SRCS = sslscan.c
BINPATH = /usr/bin/
MANPATH = /usr/share/man/
CFLAGS=-I/usr/local/ssl/include/ -I/usr/local/ssl/include/openssl/
LDFLAGS=-L/usr/local/ssl/lib/

all:
	gcc -Wall ${LDFLAGS} ${SRCS} ${CFLAGS} -lssl -lcrypto -o sslscan

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

clean:
	rm -f sslscan
