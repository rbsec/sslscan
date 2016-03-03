# set gcc as default if CC is not set
ifndef CC
  CC=gcc
endif

GIT_VERSION = $(shell git describe --tags --always --dirty=-wip)

# Ugly hack to get version if git isn't installed
ifeq ($(GIT_VERSION),)
  GIT_VERSION = $(shell grep -E -o -m 1 "[0-9]+\.[0-9]+\.[0-9]+" Changelog)
endif

# Detect OS
OS := $(shell uname)

SRCS      = sslscan.c
PREFIX    = /usr
BINDIR    = $(PREFIX)/bin
MANDIR    = $(PREFIX)/share/man
MAN1DIR   = $(MANDIR)/man1

WARNINGS  = -Wall -Wformat=2
DEFINES   = -DVERSION=\"$(GIT_VERSION)\"

# for dynamic linking
LIBS      = -lssl -lcrypto

# for static linking
ifeq ($(STATIC_BUILD), TRUE)
PWD          = $(shell pwd)/openssl
LDFLAGS      += -L${PWD}/
CFLAGS       += -I${PWD}/include/ -I${PWD}/
LIBS         = -lssl -lcrypto -ldl
GIT_VERSION  := $(GIT_VERSION)-static
else
# for dynamic linking
LDFLAGS   += -L/usr/local/ssl/lib/ -L/usr/local/opt/openssl/lib
CFLAGS    += -I/usr/local/ssl/include/ -I/usr/local/ssl/include/openssl/ -I/usr/local/opt/openssl/include
endif

.PHONY: all sslscan clean install uninstall static opensslpull

all: sslscan
	@echo
	@echo "==========="
	@echo "| WARNING |"
	@echo "==========="
	@echo
	@echo "Building against system OpenSSL. Legacy protocol checks may not be possible."
	@echo "It is recommended that you statically build sslscan with  \`make static\`."
	@echo

sslscan: $(SRCS)
	$(CC) -o $@ ${WARNINGS} ${LDFLAGS} ${CFLAGS} ${CPPFLAGS} ${DEFINES} ${SRCS} ${LIBS}

install: sslscan
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MAN1DIR)
	cp sslscan $(DESTDIR)$(BINDIR)
	cp sslscan.1 $(DESTDIR)$(MAN1DIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sslscan
	rm -f $(DESTDIR)$(MAN1DIR)/sslscan.1

.openssl.is.fresh: opensslpull
	true
opensslpull:
	if [ -d openssl -a -d openssl/.git ]; then \
		cd ./openssl && git checkout OpenSSL_1_0_2-stable && git pull | grep -q "Already up-to-date." && [ -e ../.openssl.is.fresh ] || touch ../.openssl.is.fresh ; \
	else \
		git clone https://github.com/openssl/openssl ./openssl && cd ./openssl && git checkout OpenSSL_1_0_2-stable && touch ../.openssl.is.fresh ; \
	fi
	sed -i 's/# if 0/# if 1/g' openssl/ssl/s2_lib.c

# Need to build OpenSSL differently on OSX
ifeq ($(OS), Darwin)
openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./Configure darwin64-x86_64-cc
# Any other *NIX platform
else
openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./config no-shares enable-weak-ssl-ciphers enable-ssl2
endif

openssl/libcrypto.a: openssl/Makefile
	$(MAKE) -C openssl depend
	$(MAKE) -C openssl all
	$(MAKE) -C openssl test

static: openssl/libcrypto.a
	$(MAKE) sslscan STATIC_BUILD=TRUE

clean:
	if [ -d openssl -a -d openssl/.git ]; then ( cd ./openssl; git clean -fx ); fi;
	rm -f sslscan
	rm -f .openssl.is.fresh
