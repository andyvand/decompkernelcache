##
#
# AnV LZVN/LZSS kernel cache decompressor V1.0
#
# Intel 64-bit (x86_64) version
#
##

PREFIX=/usr

# NASM=nasm
# AR=ar
# RANLIB=ranlib
CC=clang -I/usr/include
INSTALL=install
ARFLAGS=cru
CFLAGS=-arch i386 -arch x86_64 -O3
ASFLAGS=$(CFLAGS)

all: decompkernelcache

# .asm.o:
#	$(NASM) -o $@ -f macho64 $<

# .s.o:
#	$(CC) $(ASFLAGS) -c $< -o $@

# .S.o:
#	$(CC) $(ASFLAGS) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

lzvndec.o: lzvndec.c

#liblzvn.a: lzvndec.o
#	$(AR) $(ARFLAGS) $@ lzvndec.o
#	$(RANLIB) liblzvn.a

decompkernelcache: decompkernelcache.o lzvndec.o
	$(CC) $(CFLAGS) -o $@ decompkernelcache.o lzvndec.o # -L. -llzvn

clean:
	rm -f *.o decompkernelcache

install: decompkernelcache lzvn.h # liblzvn.a
	$(INSTALL) decompkernelcache $(PREFIX)/bin
#	$(INSTALL) liblzvn.a $(PREFIX)/lib
#	$(INSTALL) lzvn.h $(PREFIX)/include
