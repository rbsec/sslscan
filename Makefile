SRCS = sslscan.c
BINPATH = /usr/bin/
MANPATH = /usr/share/man/

all:
	gcc -g -Wall -lcrypto -lssl -o sslscan $(SRCS) $(LDFLAGS) $(CFLAGS)

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

clean:
	rm -f sslscan

newopenssl:
	gcc -o sslscan -g -Wall -I /tmp/openssl-0.9.8o/ -L /tmp/openssl-0.9.8o/ sslscan.c /tmp/openssl-0.9.8o/libssl.a /tmp/openssl-0.9.8o/libcrypto.a
