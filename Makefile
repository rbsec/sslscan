SRCS = sslscan.c
BINPATH = /usr/bin/
MANPATH = /usr/share/man/
CFLAGS=-I/usr/local/ssl/include/ -I/usr/local/ssl/include/openssl/
LDFLAGS=-L/usr/local/ssl/lib/

all:
	gcc -o sslscan -g -Wall $(CFLAGS) $(LDFLAGS) -lssl -lcrypto $(SRCS)

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

clean:
	rm -f sslscan

newopenssl:
	gcc -o sslscan -g -Wall -I /tmp/openssl-1.0.0a/ -L /tmp/openssl-1.0.0a/ sslscan.c /tmp/openssl-1.0.0a/libssl.a /tmp/openssl-1.0.0a/libcrypto.a

demo: all
	LD_LIBRARY_PATH=/usr/local/ssl/lib ./sslscan --renegotiation encrypted.google.com
