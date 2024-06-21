# set gcc as default if CC is not set

GIT_VERSION = $(shell git describe --tags --always --dirty=-wip)

# Ugly hack to get version if git isn't installed
ifeq ($(GIT_VERSION),)
  GIT_VERSION = $(shell grep -E -o -m 1 "[0-9]+\.[0-9]+\.[0-9]+" Changelog)
endif

# Detect OS
OS := $(shell uname)
ARCH := $(shell uname -m)

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

WARNINGS  = -Wall -Wformat=2 -Wformat-security -Wno-deprecated-declarations
DEFINES   = -DVERSION=\"$(GIT_VERSION)\"

# for dynamic linking
LIBS      = -lssl -lcrypto
ifneq ($(OS), FreeBSD)
ifneq ($(findstring MINGW64,$(OS)),MINGW64)
	LIBS += -ldl
else
	LIBS += -lwsock32 -lWs2_32
endif
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
ifneq ($(findstring CYGWIN,$(OS)),CYGWIN)
ifneq ($(findstring MINGW64,$(OS)),MINGW64)
	LDFLAGS += -pie -z relro -z now
else
	LDFLAGS += -pie
endif
endif
endif
endif

# Force C11 mode to fix the build on very old version of GCC
CFLAGS += -std=gnu11

# for static linking
ifeq ($(STATIC_BUILD), TRUE)
PWD          = $(shell pwd)/openssl
LDFLAGS      += -L${PWD}/
CFLAGS       += -I${PWD}/include/ -I${PWD}/
ifeq ($(OS), Darwin)
LIBS	     = ./openssl/libssl.a ./openssl/libcrypto.a -lz -lpthread
else
LIBS         = -lssl -lcrypto -lz -lpthread
endif
ifneq ($(OS), FreeBSD)
ifneq ($(findstring CYGWIN,$(OS)),CYGWIN)
	LIBS += -ldl
endif
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

# Find the number of processors on the system (used in -j option in building OpenSSL).
# Uses /usr/bin/nproc if available, otherwise defaults to 1.
NUM_PROCS = 1
ifneq (,$(wildcard /usr/bin/nproc))
	NUM_PROCS = `/usr/bin/nproc --all`
endif
ifeq ($(OS), Darwin)
	NUM_PROCS = `sysctl -n hw.ncpu`
endif

.PHONY: all sslscan clean realclean install uninstall static opensslpull

all: sslscan
	@echo
	@echo "==========="
	@echo "| WARNING |"
	@echo "==========="
	@echo
	@echo "Building against system OpenSSL. Compression and other checks may not be possible."
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
		cd ./openssl && git checkout `git ls-remote https://github.com/openssl/openssl | grep -Eo '(openssl-3\.0\.[0-9]+)' | sort --version-sort | tail -n 1` && git pull | grep -q "Already up to date." && [ -e ../.openssl.is.fresh ] || touch ../.openssl.is.fresh ; \
	else \
	git clone --depth 1 -b `git ls-remote https://github.com/openssl/openssl | grep -Eo '(openssl-3\.0\.[0-9]+)' | sort -V | tail -n 1` https://github.com/openssl/openssl ./openssl && cd ./openssl && touch ../.openssl.is.fresh ; \
	fi

openssl/Makefile: .openssl.is.fresh
	cd ./openssl; ./Configure -v -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC no-shared enable-weak-ssl-ciphers zlib

openssl/libcrypto.a: openssl/Makefile
	$(MAKE) -j $(NUM_PROCS) -C openssl depend
	$(MAKE) -j $(NUM_PROCS) -C openssl build_libs
#	$(MAKE) -j $(NUM_PROCS) -C openssl test # Disabled because this takes 45+ minutes for OpenSSL v1.1.1.

static: openssl/libcrypto.a
	$(MAKE) -j $(NUM_PROCS) sslscan STATIC_BUILD=TRUE

docker:
	docker build -t sslscan:sslscan .

test:	static
	./docker_test.sh

clean:
	rm -f sslscan

realclean: clean
	if [ -d openssl ]; then ( rm -rf openssl ); fi;
	rm -f .openssl.is.fresh
