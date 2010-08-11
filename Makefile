SRCS = sslscan.c
BINPATH = /usr/bin/
MANPATH = /usr/share/man/

all:
	gcc -g -Wall -lssl -o sslscan $(SRCS) $(LDFLAGS) $(CFLAGS)

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

clean:
	rm -f sslscan
