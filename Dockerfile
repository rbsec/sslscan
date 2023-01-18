FROM ubuntu:18.04

# Install nginx for some tests.
# Install strace for potential debugging, and rsyslog to enable system log gathering.
RUN apt-get update 
RUN apt-get install -y  ca-certificates build-essential git zlib1g-dev openssl 
RUN apt-get clean 

RUN update-ca-certificates
ADD . builddir 
RUN cd builddir; make static; cp /builddir/sslscan /usr/local/bin

ENTRYPOINT ["sslscan"]

EXPOSE 443
