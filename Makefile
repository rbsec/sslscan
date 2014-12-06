# set gcc as default if CC is not set
ifndef CC
  CC=gcc
endif

GIT_VERSION = $(shell git describe --tags --always --dirty=-wip)

# Ugly hack to get version if git isn't installed
ifeq ($(GIT_VERSION),)
  GIT_VERSION = $(shell grep -E -o -m 1 "[0-9]+\.[0-9]+\.[0-9]+" Changelog)
endif

SRCS      = sslscan.c
BINPATH   = /usr/bin/
MANPATH   = /usr/share/man/

WARNINGS  = -Wall -Wformat=2
DEFINES   = -DVERSION=\"$(GIT_VERSION)\"

# for dynamic linkung
LDFLAGS   = -L/usr/local/ssl/lib/ -L/usr/local/opt/openssl/lib
CFLAGS    = -I/usr/local/ssl/include/ -I/usr/local/ssl/include/openssl/ -I/usr/local/opt/openssl/include
LIBS      = -lssl -lcrypto

# for static linking
ifeq ($(STATIC_BUILD), TRUE)
PWD          = $(shell pwd)/openssl
LDFLAGS      = -L${PWD}/
CFLAGS       = -I${PWD}/include/ -I${PWD}/
LIBS         = -lssl -lcrypto -ldl
GIT_VERSION  = $(shell git describe --tags --always --dirty=-wip)-static
endif

.PHONY: sslscan clean

all: sslscan

sslscan: $(SRCS)
	$(CC) -o $@ ${WARNINGS} ${LDFLAGS} ${CFLAGS} ${DEFINES} ${SRCS} ${LIBS}

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

openssl/Makefile:
	[ -d openssl -a -d openssl/.git ] && true || git clone https://github.com/openssl/openssl ./openssl && cd ./openssl && git checkout OpenSSL_1_0_1-stable

openssl/libcrypto.a: openssl/Makefile
	cd ./openssl; ./config no-shares
	$(MAKE) -C openssl depend
	$(MAKE) -C openssl all
	$(MAKE) -C openssl test

static: openssl/libcrypto.a
	$(MAKE) sslscan STATIC_BUILD=TRUE

clean:
	[ -d openssl -a -d openssl/.git ] && ( cd ./openssl; git clean -fx )
	rm -f sslscan
