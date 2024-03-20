FROM alpine:3.17.2 as builder

# hadolint ignore=DL3018
RUN apk add --no-cache gcc make ca-certificates git libc-dev linux-headers openssl perl zlib-dev && update-ca-certificates

COPY . /builddir

# Make a static build of sslscan, then strip it of debugging symbols.
WORKDIR /builddir
ARG TARGETARCH
RUN archwrapper="" && \
    if [ "$TARGETARCH" = "386" ] ; then archwrapper="linux32" ; fi && \
    $archwrapper make static && strip --strip-all sslscan && \
    echo "ldd output:" && ldd sslscan && echo "ls -al output:" && ls -al sslscan # Print the output of ldd so we can see what dynamic libraries that sslscan is still dependent upon.

# Start with an empty container for our final build.
FROM scratch

# Copy over the sslscan executable from the intermediate build container, along with the dynamic libraries it is dependent upon (see output of ldd, above).
COPY --from=builder /builddir/sslscan /sslscan
COPY --from=builder /lib/libz.so.1 /lib/libz.so.1
COPY --from=builder /lib/ld-musl-*.so.1 /lib/

# Drop root privileges.
USER 65535:65535

ENTRYPOINT ["/sslscan"]
