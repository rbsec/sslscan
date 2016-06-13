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
ifneq ($(OS), FreeBSD)
	LIBS += -ldl
endif

# for static linking
ifeq ($(STATIC_BUILD), TRUE)
PWD          = $(shell pwd)/openssl
LDFLAGS      += -L${PWD}/
CFLAGS       += -I${PWD}/include/ -I${PWD}/
LIBS         = -lssl -lcrypto -lz
ifneq ($(OS), FreeBSD)
	LIBS += -ldl
endif
GIT_VERSION  := $(GIT_VERSION)-static
else
# for dynamic linking
LDFLAGS   += -L/usr/local/lib -L/usr/local/ssl/lib -L/usr/local/opt/openssl/lib -L/opt/local/lib
CFLAGS    += -I/usr/local/include -I/usr/local/ssl/include -I/usr/local/ssl/include/openssl -I/usr/local/opt/openssl/include -I/opt/local/include -I/opt/local/include/openssl
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

install:
	@if [ ! -f sslscan ] ; then \
		echo "\n=========\n| ERROR |\n========="; \
		echo "Before installing you need to build sslscan with either \`make\` or \`make static\`\n"; \
		exit 1; \
	fi
ifeq ($(OS), Darwin)
	install -d $(DESTDIR)$(BINDIR)/;
	install sslscan $(DESTDIR)$(BINDIR)/sslscan;
	install -d $(DESTDIR)$(MAN1DIR)/;
	install sslscan.1 $(DESTDIR)$(MAN1DIR)/sslscan.1;
else
	install -D sslscan $(DESTDIR)$(BINDIR)/sslscan;
	install -D sslscan.1 $(DESTDIR)$(MAN1DIR)/sslscan.1;
endif

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sslscan
	rm -f $(DESTDIR)$(MAN1DIR)/sslscan.1

.openssl.is.fresh: opensslpull
	true
opensslpull:
	if [ -d openssl -a -d openssl/.git ]; then \
		cd ./openssl && git checkout OpenSSL_1_0_2-stable && git pull | grep -q "Already up-to-date." && [ -e ../.openssl.is.fresh ] || touch ../.openssl.is.fresh ; \
	else \
		git clone --depth 1 -b OpenSSL_1_0_2-stable https://github.com/openssl/openssl ./openssl && cd ./openssl && touch ../.openssl.is.fresh ; \
	fi
	# Re-enable SSLv2 EXPORT ciphers
	sed -i.bak 's/# if 0/# if 1/g' openssl/ssl/s2_lib.c
	rm openssl/ssl/s2_lib.c.bak
	# Re-enable weak (<1024 bit) DH keys
	sed -i.bak 's/dh_size < [0-9]\+/dh_size < 512/g' openssl/ssl/s3_clnt.c
	rm openssl/ssl/s3_clnt.c.bak
	# Break the weak DH key test so OpenSSL compiles
	sed -i.bak 's/dhe512/zzz/g' openssl/test/testssl
	rm openssl/test/testssl.bak

# Need to build OpenSSL differently on OSX
ifeq ($(OS), Darwin)
openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./Configure enable-ssl2 enable-weak-ssl-ciphers zlib darwin64-x86_64-cc
# Any other *NIX platform
else
openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./config no-shares enable-weak-ssl-ciphers enable-ssl2 zlib
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
