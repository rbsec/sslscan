# sslscan2

An alpha build of sslscan 2 has been merged into master. If you want the old code,
the tag [1.11.13-rbsec](https://github.com/rbsec/sslscan/releases/tag/1.11.13-rbsec) was the last release in that branch.

The main changes in sslscan2 is a major rewrite of the backend scanning code,
which means that it is no longer reliant on the version of OpenSSL for many checks.
This means that it is possible to support legacy protocols (SSLv2 and SSLv3), as well
as supporting TLSv1.3 - regardless of the version of OpenSSL that it has been compiled against.

This has been made possible largely by the work of [jtesta](https://github.com/jtesta), who has been
responsible for most of the backend rewrite.

Other key changes include:

* Enumeration of server key exchange groups.
* Enumeration of server signature algorithms.
* SSLv2 and SSLv3 protocol support it scanned, but individual ciphers are not.
* A test suite is included using Docker, to verify that sslscan is functionality correctly.

There are likely to be bugs in this version, so please report any that you encounter.

# README

[![Build Status](https://travis-ci.org/rbsec/sslscan.svg?branch=master)](https://travis-ci.org/rbsec/sslscan)

This is a fork of ioerror's version of sslscan (the original readme of which is included below).
Key changes are as follows:

* Highlight SSLv2 and SSLv3 ciphers in output.
* Highlight CBC ciphers on SSLv3 (POODLE).
* Highlight 3DES and RC4 ciphers in output.
* Highlight PFS+GCM ciphers as good in output.
* Highlight NULL (0 bit), weak (<40 bit) and medium (40 < n <= 56) ciphers in output.
* Highlight anonymous (ADH and AECDH) ciphers in output (purple).
* Hide certificate information by default (display with `--get-certificate`).
* Hide rejected ciphers by default (display with `--failed`).
* Added TLSv1.1, TLSv1.2 and TLSv1.3 support.
* Supports IPv6  (can be forced with `--ipv6`).
* Check for TLS compression (CRIME, disable with `--no-compression`).
* Disable cipher suite checking `--no-ciphersuites`.
* Disable coloured output `--no-colour`.
* Removed undocumented -p output option.
* Added check for OpenSSL HeartBleed (CVE-2014-0160, disable with `--no-heartbleed`).
* Flag certificates signed with MD5 or SHA-1, or with short (<2048 bit) RSA keys.
* Support scanning RDP servers with `--rdp` (credit skettler).
* Added option to specify socket timeout.
* Added option for static compilation (credit dmke).
* Added `--sleep` option to pause between requests.
* Disable output for anything than specified checks `--no-preferred`.
* Determine the list of CAs acceptable for client certificates `--show-client-cas`.
* Experimental build support on OS X (credit MikeSchroll).
* Flag some self-signed SSL certificates.
* Experimental Windows support (credit jtesta).
* Display EC curve names and DHE key lengths with OpenSSL >= 1.0.2 `--no-cipher-details`.
* Flag weak DHE keys with OpenSSL >= 1.0.2 `--cipher-details`.
* Flag expired certificates.
* Flag TLSv1.0 ciphers in output as weak.
* Experimental OS X support (static building only).
* Support for scanning PostgreSQL servers (credit nuxi).
* Check for TLS Fallback SCSV support.
* Added StartTLS support for LDAP `--starttls-ldap`.
* Added SNI support `--sni-name` (credit Ken).
* Support STARTTLS for MySQL (credit bk2017).
* Check for supported key exchange groups.
* Check for supported server signature algorithms.

### Building on Debian

It is possible to ignore the OpenSSL system installation and ship your own
version. Although this results in a more resource-heavy `sslscan` binary
(file size, memory consumption, etc.), this allows some additional checks
such as TLS compression.

To compile your own OpenSSL version, you'll probably need to install the
OpenSSL build dependencies (and enable the `deb-src` repos in your apt config):

    apt-get install build-essential git zlib1g-dev
    apt-get build-dep openssl

then run

    make static

which will clone the [OpenSSL repository](https://github.com/openssl/openssl),
and configure/compile/test OpenSSL prior to compiling `sslscan`.

**Please note:** Out of the box, OpenSSL cannot compiled with `clang` without
further customization (which is not done by the provided `Makefile`).
For more information on this, see [Modifying Build Settings](http://wiki.openssl.org/index.php/Compilation_and_Installation#Modifying_Build_Settings)
in the OpenSSL wiki.

You can verify whether you have a statically linked OpenSSL version, if

    ./sslscan --version

looks a bit like

        1.x.y-...-static
        OpenSSL 1.0.2-chacha xx XXX xxxx

(pay attention to the `-static` suffix and the `1.0.2-chacha` OpenSSL version).

### Building on Windows

Thanks to a patch by jtesta, sslscan can now be compiled on Windows. This can
either be done natively or by cross-compiling from Linux. See INSTALL for
instructions.

Note that sslscan was originally written for Linux, and has not been extensively
tested on Windows. As such, the Windows version should be considered experimental.

Pre-build cross-compiled Windows binaries are available on the [GitHub Releases Page](https://github.com/rbsec/sslscan/releases).

### Building on OS X
There is experimental support for statically building on OS X, however this
should be considered unsupported. You may need to install any dependencies
required to compile OpenSSL from source on OS X. Once you have, just run:

    make static

# Original (ioerror) README
This is a fork of sslscan.c to better support STARTTLS.

The original home page of sslscan is:

    http://www.titania.co.uk

sslscan was originally written by:

    Ian Ventura-Whiting

The current home page of this fork (until upstream merges a finished patch) is:

    http://www.github.com/ioerror/sslscan

Most of the pre-TLS protocol setup was inspired by the OpenSSL s_client.c
program. The goal of this fork is to eventually merge with the original
project after the STARTTLS setup is polished.

Some of the OpenSSL setup code was borrowed from The Tor Project's Tor program.
Thus it is likely proper to comply with the BSD license by saying:
    Copyright (c) 2007-2010, The Tor Project, Inc.
