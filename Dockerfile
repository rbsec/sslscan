FROM alpine:latest

RUN apk update
RUN apk add gcc make ca-certificates git libc-dev linux-headers openssl perl zlib-dev

RUN update-ca-certificates
ADD . builddir
RUN cd builddir; make static; cp /builddir/sslscan /usr/local/bin

ENTRYPOINT ["sslscan"]
