# README
This is a fork of ioerror's version of sslscan (the original readme of which is included below). Changes are as follows:

* Highlight SSLv2 ciphers in output.
* Highlight RC4 ciphers in output.
* Highlight weak (<40 bit) and medium (40 < n <= 56) ciphers in output.
* Hide certificate information by default (display with --get-certificate).
* Hide rejected ciphers by default (display with --failed).
* Added TLSv1.1 and TLSv1.2 support (merged from twwbond/sslscan).
* Compiles if OpenSSL does not support SSLv2 ciphers (merged from digineo/sslscan).
* Supports IPv6 hostnames (can be forced with --ipv6).
* Check for TLS compression (CRIME, disable with --no-compression)

#### Building on Kali
Note that many modern distros (including Kali) ship with a version of OpenSSL that disables support for SSLv2 ciphers. If sslscan is compiled on one of these distros, it will not be able to detect SSLv2.

This issue can be resolved by rebuilding OpenSSL from source after removing the patch that disables SSLv2 support. See the following article for details:

http://blog.opensecurityresearch.com/2013/05/fixing-sslv2-support-in-kali-linux.html

If it is not possible to rebuild OpenSSL, sslscan will still compile (thanks to a patch from digineo/sslscan, based on the debian patch). However, a warning will be displayed in the output to notify the user that SSLv2 ciphers will not be detected.


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
