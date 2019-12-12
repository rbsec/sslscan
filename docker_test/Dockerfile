FROM ubuntu:18.04

COPY openssl_prog_v1.0.0 /openssl_v1.0.0/openssl
COPY openssl_prog_v1.0.2 /openssl_v1.0.2/openssl
COPY openssl_prog_v1.1.1 /openssl_v1.1.1/openssl

# Copy certificates, keys, and DH parameters.
COPY *.pem /etc/ssl/
COPY *.crt /etc/ssl/

# Copy nginx site configurations & modules.
COPY nginx_site_client_cert_required /etc/nginx/sites-available/
COPY nginx_test9.conf /etc/nginx/

# Install nginx for some tests.
# Install strace for potential debugging, and rsyslog to enable system log gathering.
RUN apt update 2> /dev/null
RUN apt install -y nginx strace rsyslog 2> /dev/null
RUN apt clean 2> /dev/null

EXPOSE 443
