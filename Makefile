# set gcc as default if CC is not set

GIT_VERSION = $(shell git describe --tags --always --dirty=-wip)

# Ugly hack to get version if git isn't installed
ifeq ($(GIT_VERSION),)
  GIT_VERSION = $(shell grep -E -o -m 1 "[0-9]+\.[0-9]+\.[0-9]+" Changelog)
endif

# Detect OS
OS := $(shell uname)

# Handle different version of Make
ifeq ($(OS), SunOS)
	ifndef $(CC)
		CC=gcc
	endif
	ifndef $(PREFIX)
		PREFIX = /usr
	endif
else
	CC ?= gcc
	PREFIX ?= /usr
endif

SRCS      = sslscan.c
BINDIR    = $(PREFIX)/bin
MANDIR    = $(PREFIX)/share/man
MAN1DIR   = $(MANDIR)/man1

WARNINGS  = -Wall -Wformat=2 -Wformat-security
DEFINES   = -DVERSION=\"$(GIT_VERSION)\"

# for dynamic linking
LIBS      = -lssl -lcrypto
ifneq ($(OS), FreeBSD)
	LIBS += -ldl
endif
ifeq ($(OS), SunOS)
	CFLAGS += -m64
	LIBS   += -lsocket -lnsl
endif

# Enable checks for buffer overflows, add stack protectors, generate position
# independent code, mark the relocation table read-only, and mark the global
# offset table read-only.
CFLAGS  += -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE

# Don't enable some hardening flags on OS X because it uses an old version of Clang
ifneq ($(OS), Darwin)
ifneq ($(OS), SunOS)
# Cygwin's linker does not support -z option.
ifneq ($(findstring CYGWIN,$(OS)),CYGWIN)
	LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now
endif
endif
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
ifeq ($(OS), SunOS)
	LIBS += -lsocket -lnsl
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
		git clone --depth 1 -b OpenSSL_1_0_2-stable https://github.com/PeterMosmans/openssl ./openssl && cd ./openssl && touch ../.openssl.is.fresh ; \
	fi

# Need to build OpenSSL differently on OSX
ifeq ($(OS), Darwin)
openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./Configure -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC enable-ssl2 enable-weak-ssl-ciphers zlib darwin64-x86_64-cc
# Any other *NIX platform
else
openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./config -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC no-shares enable-weak-ssl-ciphers enable-ssl2 zlib
endif

openssl/libcrypto.a: openssl/Makefile
	$(MAKE) -C openssl depend
	$(MAKE) -C openssl all
	$(MAKE) -C openssl test

static: openssl/libcrypto.a
	$(MAKE) sslscan STATIC_BUILD=TRUE

clean:
	if [ -d openssl ]; then ( rm -rf openssl ); fi;
	rm -f sslscan
	rm -f .openssl.is.fresh
