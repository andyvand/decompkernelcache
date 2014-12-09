#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <math.h>

#if defined(__APPLE__)
#include <architecture/byte_order.h>
#elif defined(__GNUC__) || defined(__clang__)
inline uint32_t OSSwapInt32(uint32_t data)
{
    __asm__ ("bswap   %0" : "+r" (data));

    return data;
}
#elif defined(_MSC_VER) && (defined(__i386__) || defined(_M_IX86) || defined(_X86_)) /* MSVC x86 (32-Bit) */
static __inline uint32_t OSSwapInt32(uint32_t data)
{
    __asm
	{
		push eax
		mov eax, data
		bswap eax
		mov data, eax
		pop eax
	};

    return data;
}
#else /* Generic */
#define OSSwapInt32(x) \
((((x) & 0xff) << 24) |	\
 (((x) & 0xff00) << 8) |	\
 (((x) & 0xff0000) >> 8) |	\
 (((x) & 0xff000000) >> 24))
#endif /* Type of swap */

#include "lzvn.h"

#define FAT_MAGIC	0xcafebabe
#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */

#ifndef _MSC_VER
#define PACK_GNU __attribute__((aligned(1)))
#else /* GNUC/CLANG */
#define PACK_GNU
#endif /* PACK_DEF */

#ifdef _MSC_VER
#pragma pack(1)
#endif
typedef struct fat_header {
	uint32_t	magic;		/* FAT_MAGIC */
	uint32_t	nfat_arch;	/* number of structs that follow */
} fat_header_t PACK_GNU;
#ifdef _MSC_VER
#pragma pack()
#endif

typedef int32_t cpu_type_t;
typedef int32_t cpu_subtype_t;

#ifdef _MSC_VER
#pragma pack(1)
#endif
typedef struct fat_arch {
	cpu_type_t	cputype;	/* cpu specifier (int) */
	cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
	uint32_t	offset;		/* file offset to this object file */
	uint32_t	size;		/* size of this object file */
	uint32_t	align;		/* alignment as a power of 2 */
} fat_arch_t PACK_GNU;
#ifdef _MSC_VER
#pragma pack()
#endif

#define PLATFORM_NAME_LEN  (64)
#define ROOT_PATH_LEN     (256)

// prelinkVersion value >= 1 means KASLR supported
#ifdef _MSC_VER
#pragma pack(1)
#endif
typedef struct prelinked_kernel_header {
    uint32_t  signature;
    uint32_t  compressType;
    uint32_t  adler32;
    uint32_t  uncompressedSize;
    uint32_t  compressedSize;
    uint32_t  prelinkVersion;
    uint32_t  reserved[10];
    char      platformName[PLATFORM_NAME_LEN]; // unused
    char      rootPath[ROOT_PATH_LEN];         // unused
} PrelinkedKernelHeader PACK_GNU;

typedef struct platform_info {
    char platformName[PLATFORM_NAME_LEN];
    char rootPath[ROOT_PATH_LEN];
} PlatformInfo PACK_GNU;
#ifdef _MSC_VER
#pragma pack()
#endif

void Usage(char *name)
{
    printf("AnV LZVN/LZSS kernel cache decompressor V1.8\n");
    printf("Usage: %s <infile> <outfile>\n\n", name);
    printf("Copyright (C) 2014 AnV Software\n");
}

uint32_t local_adler32(uint8_t *buffer, int32_t length)
{
    int32_t cnt = 0;
    uint32_t result = 0;
    uint32_t lowHalf = 1;
    uint32_t highHalf = 0;
    
    for (cnt = 0; cnt < length; cnt++) {
        if ((cnt % 5000) == 0) {
            lowHalf  %= 65521L;
            highHalf %= 65521L;
        }
        
        lowHalf += buffer[cnt];
        highHalf += lowHalf;
    }
    
    lowHalf  %= 65521L;
    highHalf %= 65521L;

    result = (highHalf << 16) | lowHalf;

    return result;
}

#define N         4096  /* size of ring buffer - must be power of 2 */
#define F         18    /* upper limit for match_length */
#define THRESHOLD 2     /* encode string into position and length */

int decompress_lzss(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srclen)
{
    /* ring buffer of size N, with extra F-1 bytes to aid string comparison */
    uint8_t text_buf[N + F - 1];
    uint8_t * dststart = dst;
    const uint8_t * dstend = dst + dstlen;
    const uint8_t * srcend = src + srclen;
    int  i, j, k, r, c;
    unsigned int flags;
    
    dst = dststart;
    for (i = 0; i < N - F; i++)
        text_buf[i] = ' ';
    r = N - F;
    flags = 0;
    for ( ; ; ) {
        if (((flags >>= 1) & 0x100) == 0) {
            if (src < srcend) c = *src++; else break;
            flags = c | 0xFF00;  /* uses higher byte cleverly */
        }   /* to count eight */
        if (flags & 1) {
            if (src < srcend) c = *src++; else break;
            if (dst < dstend) *dst++ = c; else break;
            text_buf[r++] = c;
            r &= (N - 1);
        } else {
            if (src < srcend) i = *src++; else break;
            if (src < srcend) j = *src++; else break;
            i |= ((j & 0xF0) << 4);
            j  =  (j & 0x0F) + THRESHOLD;
            for (k = 0; k <= j; k++) {
                c = text_buf[(i + k) & (N - 1)];
                if (dst < dstend) *dst++ = c; else break;
                text_buf[r++] = c;
                r &= (N - 1);
            }
        }
    }
    
    return (int)(dst - dststart);
}

int main(int argc, char **argv)
{
    FILE *f = NULL;
    unsigned long actuallen = 0;
    unsigned char *buffer = NULL;
    unsigned long buflen = 0;
    PrelinkedKernelHeader *prelinkfile;
    fat_header_t *fathdr;
    fat_arch_t *fatarch;
    unsigned char *combuffer = NULL;
    unsigned long combuflen = 0;
    unsigned char *uncombuffer = NULL;
    unsigned long uncombuflen = 0;
    uint32_t adler32_cv = 0;
	uint32_t adler32_ck = 0;
	unsigned int ac = 0;
	int rv = 0;
  
    if (argc != 3)
    {
        Usage(argv[0]);

        return 1;
    }

#if __STDC_WANT_SECURE_LIB__
	fopen_s(&f, argv[1], "rb");
#else
    f = fopen(argv[1], "rb");
#endif

    if (f == NULL)
    {
        printf("ERROR: Could not open file %s for reading!\n", argv[1]);

        return -1;
    }

    fseek(f,0,SEEK_END);
	buflen = ftell(f);
	fseek(f,0,SEEK_SET);

    buffer = malloc(buflen);

    if (buffer == NULL)
    {
        printf("ERROR: Memory allocation error while allocating file input buffer\n");

        if (f)
        {
            fclose(f);
        }

        return -2;
    }
    
#if __STDC_WANT_SECURE_LIB__
    actuallen = (unsigned long)fread_s(buffer, buflen, 1, buflen, f);
#else /* OTHER */
    actuallen = (unsigned long)fread(buffer, 1, buflen, f);
#endif /* READ FUNCTION */

    if (f)
    {
        fclose(f);
    }

    if (actuallen != buflen)
    {
        printf("ERROR: Read too few bytes from file %s, %lu bytes wanted but %lu bytes read!\n", argv[1], buflen, actuallen);

        if (buffer)
        {
            free(buffer);
        }

        return -3;
    }

    fathdr = (fat_header_t *)buffer;
    if (fathdr->magic == FAT_CIGAM)
    {
        ac = 1;
        fatarch = (fat_arch_t *)(buffer + sizeof(fat_header_t));
        prelinkfile = (PrelinkedKernelHeader *)((unsigned char *)buffer + OSSwapInt32(fatarch->offset));

        while ((ac < OSSwapInt32(fathdr->nfat_arch)) && (prelinkfile->signature != 0x706D6F63))
        {
            fatarch = (fat_arch_t *)((unsigned char *)fatarch + sizeof(fat_arch_t));
            prelinkfile = (PrelinkedKernelHeader *)(buffer + OSSwapInt32(fatarch->offset));

            ++ac;
        }
    } else {
        fathdr = NULL;

        prelinkfile = (PrelinkedKernelHeader *)buffer;
    }

    if (prelinkfile->signature != 0x706D6F63)
    {
        printf("ERROR: %s is not a comressed kernel cache... not handling (Found 0x%x)\n", argv[1], prelinkfile->signature);

        if (buffer)
        {
            free(buffer);
        }
        
        return -4;
    }

    if ((prelinkfile->compressType != 0x6E767A6C) && (prelinkfile->compressType != 0x73737A6C))
    {
        printf("ERROR: %s is not an LZVN/LZSS compressed kernel cache... not handling (Found 0x%x)\n", argv[1], prelinkfile->compressType);

        if (buffer)
        {
            free(buffer);
        }

        return -5;
    }

    combuflen = OSSwapInt32(prelinkfile->compressedSize);
    uncombuflen = OSSwapInt32(prelinkfile->uncompressedSize);

    if ((combuflen == 0) || (uncombuflen == 0))
    {
        printf("ERROR: invalid compressed/uncompressed size found: uncompressed=%lu, compressed=%lu\n", uncombuflen, combuflen);
        
        if (buffer)
        {
            free(buffer);
        }
        
        return -6;
    }

    printf("%s: Initial compressed size -> %lu, Reported uncompressed size -> %lu\n", argv[1], combuflen, uncombuflen);

    combuffer = (unsigned char *)prelinkfile + sizeof(PrelinkedKernelHeader);
    uncombuffer = malloc(uncombuflen);

    if (uncombuffer == NULL)
    {
        printf("ERROR: Could not allocate memory for decompression buffer!\n");

        if (buffer)
        {
            free(buffer);
        }

        return -7;
    }

    if (prelinkfile->compressType == 0x73737A6C)
    {
        rv = decompress_lzss(uncombuffer, uncombuflen, combuffer, combuflen);
    } else {
        rv = (int)lzvn_decode(uncombuffer, (size_t)uncombuflen, combuffer, (size_t)combuflen);
    }

	adler32_ck = OSSwapInt32(prelinkfile->adler32);

    if (buffer)
    {
        free(buffer);
    }

    printf("%s: Actual decompressed size -> %d\n", argv[2], rv);

    if (uncombuflen != (unsigned long)rv)
    {
        printf("ERROR: Actual decompressed size is not expected size (%lu is not %d)\n", uncombuflen, rv);

        if (uncombuffer)
        {
            free(uncombuffer);
        }

        return -8;
    }

	adler32_cv = local_adler32(uncombuffer, uncombuflen);

    if (adler32_cv != adler32_ck)
    {
        printf("ERROR: Checksum (adler32) mismatch (0x%.8X != 0x%.8X)\n", adler32_cv, adler32_ck);

        if (uncombuffer)
        {
            free(uncombuffer);
        }

        return -9;
    }

    printf("Decompressed kernel cache adler32 checksum value -> 0x%.8X\n", adler32_cv);

#if __STDC_WANT_SECURE_LIB__
	fopen_s(&f, argv[2], "wb");
#else
    f = fopen (argv[2], "wb");
#endif

    if (f == NULL)
    {
        printf("ERROR: Couldn't open file %s for writing!\n", argv[2]);

        if (uncombuffer)
        {
            free(uncombuffer);
        }

        return -10;
    }

    actuallen = (unsigned long)fwrite(uncombuffer, 1, uncombuflen, f);

    free(uncombuffer);

    if (f)
    {
        fclose(f);
    }

    if (actuallen != uncombuflen)
    {
        printf("ERROR: Actual written decompressed file %s size incorrect, wanted %lu but wrote %lu\n", argv[2], uncombuflen, actuallen);

        return -11;
    }

	return 0;
}
