/***************************************************************************
 *   sslscan - A SSL cipher scanning tool                                  *
 *   Copyright 2007-2009 by Ian Ventura-Whiting (Fizz)                     *
 *   fizz@titania.co.uk                                                    *
 *   Copyright 2010 by Michael Boman (michael@michaelboman.org)            *
 *   Copyleft 2010 by Jacob Appelbaum <jacob@appelbaum.net>                *
 *   Copyleft 2013 by rbsec <robin@rbsec.net>                              *
 *   Copyleft 2014 by Julian Kornberger <jk+github@digineo.de>             *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 *   In addition, as a special exception, the copyright holders give       *
 *   permission to link the code of portions of this program with the      *
 *   OpenSSL library under certain conditions as described in each         *
 *   individual source file, and distribute linked combinations            *
 *   including the two.                                                    *
 *   You must obey the GNU General Public License in all respects          *
 *   for all of the code used other than OpenSSL.  If you modify           *
 *   file(s) with this exception, you may extend this exception to your    *
 *   version of the file(s), but you are not obligated to do so.  If you   *
 *   do not wish to do so, delete this exception statement from your       *
 *   version.  If you delete this exception statement from all source      *
 *   files in the program, then also delete it here.                       *
 ***************************************************************************/

#ifndef HAVE_SSLSCAN_H_
#define HAVE_SSLSCAN_H_

// Defines...
#define false 0
#define true 1

#define mode_help 0
#define mode_version 1
#define mode_single 2
#define mode_multiple 3

#define BUFFERSIZE 1024

#define ssl_all 0
#define ssl_v2 1
#define ssl_v3 2
#define tls_all 3
#define tls_v10 4
#define tls_v11 5
#define tls_v12 6

// Macros for various outputs
#define printf_error(format, ...)   fprintf(stderr, format, ##__VA_ARGS__)
#define printf_xml(format, ...)     if (options->xmlOutput) fprintf(options->xmlOutput, format, ##__VA_ARGS__)
#define printf_verbose(format, ...) if (options->verbose) printf(format, ##__VA_ARGS__)

// Colour Console Output...
#if !defined(__WIN32__)
// Always better to do "const char RESET[] = " because it saves relocation records.
const char *RESET = "[0m";            // DEFAULT
const char *COL_RED = "[31m";
const char *COL_YELLOW = "[33m";
const char *COL_BLUE = "[1;34m";
const char *COL_GREEN = "[32m";
const char *COL_PURPLE = "[35m";
const char *COL_RED_BG = "[41m";
#else
const char *RESET = "";
const char *COL_RED = "";
const char *COL_YELLOW = "";
const char *COL_BLUE = "";
const char *COL_GREEN = "";
const char *COL_PURPLE = "";
const char *COL_RED_BG = "";
#endif


const char *program_banner = "                   _\n"
                             "           ___ ___| |___  ___ __ _ _ __\n"
                             "          / __/ __| / __|/ __/ _` | '_ \\\n"
                             "          \\__ \\__ \\ \\__ \\ (_| (_| | | | |\n"
                             "          |___/___/_|___/\\___\\__,_|_| |_|\n\n";

struct sslCipher
{
    // Cipher Properties...
    const char *name;
    char *version;
    int bits;
    char description[512];
    const SSL_METHOD *sslMethod;
    struct sslCipher *next;
};

struct sslCheckOptions
{
    // Program Options...
    char host[512];
    int port;
    int noFailed;
    int showCertificate;
    int checkCertificate;
    int showClientCiphers;
    int ciphersuites;
    int reneg;
    int compression;
    int heartbleed;
    int starttls_ftp;
    int starttls_imap;
    int starttls_pop3;
    int starttls_smtp;
    int starttls_xmpp;
    int sslVersion;
    int targets;
    int sslbugs;
    int http;
    int rdp;
    int verbose;
    int ipv4;
    int ipv6;

    // File Handles...
    FILE *xmlOutput;

    // TCP Connection Variables...
    struct hostent *hostStruct;
    struct sockaddr_in serverAddress;
    struct sockaddr_in6 serverAddress6;
    struct timeval timeout;
    struct timespec sleep;

    // SSL Variables...
    SSL_CTX *ctx;
    struct sslCipher *ciphers;
    char *clientCertsFile;
    char *privateKeyFile;
    char *privateKeyPassword;
};

// store renegotiation test data
struct renegotiationOutput
{
    int supported;
    int secure;
};

/* We redefine these so that we can run correctly even if the vendor gives us
 * a version of OpenSSL that does not match its header files.  (Apple: I am
 * looking at you.)
 */
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#    define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x00040000L
#endif
#ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#    define SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x0010
#endif

// Utilities
int fileExists(char *);
void readLine(FILE *, char *, int);
ssize_t sendString(int, const char[]);
int readOrLogAndClose(int, void *, size_t, const struct sslCheckOptions *);
const char *printableSslMethod(const SSL_METHOD *);
static int password_callback(char *, int, int, void *);

int tcpConnect(struct sslCheckOptions *);
int populateCipherList(struct sslCheckOptions *, const SSL_METHOD *);

// Tests
void tls_reneg_init(struct sslCheckOptions *);
int outputRenegotiation(struct sslCheckOptions *, struct renegotiationOutput *);
struct renegotiationOutput *newRenegotiationOutput(void);
int freeRenegotiationOutput(struct renegotiationOutput *);

int testCompression(struct sslCheckOptions *, const SSL_METHOD *);
int testRenegotiation(struct sslCheckOptions *, const SSL_METHOD *);
int testHeartbleed(struct sslCheckOptions *, const SSL_METHOD *);
int testCipher(struct sslCheckOptions *, struct sslCipher *);
int testHost(struct sslCheckOptions *);

int loadCerts(struct sslCheckOptions *);
int defaultCipher(struct sslCheckOptions *, const SSL_METHOD *);
int checkCertificate(struct sslCheckOptions *);
int showCertificate(struct sslCheckOptions *);

#endif

/* vim :set ts=4 sw=4 sts=4 et : */
