# This is the Dockerfile to build the test image (which contains target servers to check sslscan's output against).

FROM ubuntu:24.04 AS builder

COPY build_test_apps.sh /build/build_test_apps.sh

# Update base image and install prerequisites for building.
RUN apt update; apt install -y build-essential zlib1g zlib1g-dev nettle-dev git wget m4 pkg-config python3 python3-pip python3-virtualenv python3-venv

# Build all applications.
RUN /bin/bash /build/build_test_apps.sh


# Starting from a fresh image, copy over the built applications from the prior stage.
FROM ubuntu:24.04

COPY --from=builder /build/libhogweed.so.5 /usr/lib/libhogweed.so.5
COPY --from=builder /build/libnettle.so.7 /usr/lib/libnettle.so.7

COPY --from=builder /build/gnutls-cli-v3.6.11.1 /gnutls-3.6.11.1/gnutls-cli
COPY --from=builder /build/gnutls-serv-v3.6.11.1 /gnutls-3.6.11.1/gnutls-serv

COPY --from=builder /build/gnutls-cli-v3.8.9 /gnutls-3.8.9/gnutls-cli
COPY --from=builder /build/gnutls-serv-v3.8.9 /gnutls-3.8.9/gnutls-serv

COPY --from=builder /build/openssl_prog_v1.0.0 /openssl_v1.0.0/openssl
COPY --from=builder /build/openssl_prog_v1.0.2 /openssl_v1.0.2/openssl
COPY --from=builder /build/openssl_prog_v1.1.1 /openssl_v1.1.1/openssl
COPY --from=builder /build/openssl_prog_v3.5.0 /openssl_v3.5.0/openssl

COPY --from=builder /build/mbedtls_ssl_server2_v3.6.3.1 /mbedtls_v3.6.3.1/ssl_server2

# Copy certificates, keys, and DH parameters.
COPY *.pem /etc/ssl/
COPY *.crt /etc/ssl/

# This config file seems to tell GnuTLS to not allow TLSv1.0 or TLSv1.1, which we need for testing.
RUN rm -f /etc/gnutls/config

EXPOSE 443
