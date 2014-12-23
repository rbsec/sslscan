# README
This is a fork of ioerror's version of sslscan (the original readme of which is included below). Changes are as follows:

* Highlight SSLv2 and SSLv3 ciphers in output.
* Highlight CBC ciphers on SSLv3 (POODLE)
* Highlight RC4 ciphers in output.
* Highlight GCM ciphers as good in output.
* Highlight NULL (0 bit), weak (<40 bit) and medium (40 < n <= 56) ciphers in output.
* Highlight anonymous (ADH and AECDH) ciphers in output (purple).
* Hide certificate information by default (display with --get-certificate).
* Hide rejected ciphers by default (display with --failed).
* Added TLSv1.1 and TLSv1.2 support (merged from twwbond/sslscan).
* Compiles if OpenSSL does not support SSLv2 ciphers (merged from digineo/sslscan).
* Supports IPv6 hostnames (can be forced with --ipv6).
* Check for TLS compression (CRIME, disable with --no-compression).
* Disable cipher suite checking (--no-ciphersuites).
* Disable coloured output (--no-colour).
* Removed undocumented -p output option.
* Added check for OpenSSL HeartBleed (CVE-2014-0160, disable with --no-heartbleed).
* Flag certificates signed with MD5 or SHA-1, or with short (<2048 bit) RSA keys.
* Support scanning RDP servers with --rdp (credit skettler).
* Added option to specify socket timeout.
* Added option for static compilation (credit dmke).
* Added --sleep option to pause between requests.
* Experimental build support on OSX (credit MikeSchroll)

### OpenSSL issues

#### Building on Debian/Kali

Note that many modern distros (including Kali) ship with a version of OpenSSL
that disables support for SSLv2 ciphers. If `sslscan` is compiled on one of
these distros, it will not be able to detect SSLv2.

This issue can be resolved by rebuilding OpenSSL from source after removing
the patch that disables SSLv2 support.

The `build_openssl_debian.sh` script automates this process for Debian systems.
It has been tested on Debian Squeeze/Wheezy and Kali; it may work on other
Debian based distros, but has not been tested. The built version of OpenSSL
will be installed using `dpkg`.

If it is not possible to rebuild OpenSSL, `sslscan` will still compile
(thanks to a patch from [digineo/sslscan](https://github.com/digineo/sslscan),
based on the debian patch). However, a warning will be displayed in the
output to notify the user that SSLv2 ciphers will not be detected.

#### Statically linking a custom OpenSSL build

It is possible to ignore the OpenSSL system installation and ship your own
version. Although this results in a more resource-heavy `sslscan` binary
(file size, memory consumption, etc.), this allows to enable both SSLv2 and
SSLv3 ciphers. In comparison to the aforementioned method of repackaging the
Debian build, this custom OpenSSL build won't affect other tools on the same
system, as they would use the version packaged by the distro's maintainers.

To compile your own OpenSSL version, you'll probably need to install the
OpenSSL build dependencies:

    apt-get install build-essentials git
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
        OpenSSL 1.1.0-dev xx XXX xxxx

(pay attention to the `-static` suffix and the `1.1.0-dev` OpenSSL version).


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
