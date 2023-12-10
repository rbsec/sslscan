FROM alpine:latest as builder

# Ensure no packages are cached before we try to do an update.
RUN apk cache clean 2> /dev/null || exit 0

RUN apk update && apk add gcc make ca-certificates git libc-dev linux-headers openssl perl zlib-dev
RUN update-ca-certificates

ADD . builddir

# Make a static build of sslscan, then strip it of debugging symbols.
RUN cd builddir && make static
RUN strip --strip-all /builddir/sslscan

# Print the output of ldd so we can see what dynamic libraries that sslscan is still dependent upon.
RUN echo "ldd output:" && ldd /builddir/sslscan
RUN echo "ls -al output:" && ls -al /builddir/sslscan


# Start with an empty container for our final build.
FROM scratch

# Copy over the sslscan executable from the intermediate build container, along with the dynamic libraries it is dependent upon (see output of ldd, above).
COPY --from=builder /builddir/sslscan /sslscan
COPY --from=builder /lib/libz.so.1 /lib/libz.so.1
COPY --from=builder /lib/ld-musl-*.so.1 /lib/

# Drop root privileges.
USER 65535:65535

ENTRYPOINT ["/sslscan"]
