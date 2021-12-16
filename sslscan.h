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

#include "missing_ciphersuites.h"

// Defines...
#define false 0
#define true 1

#define mode_help 0
#define mode_version 1
#define mode_single 2
#define mode_multiple 3

#define BUFFERSIZE 1024

// For options.sslVersion field.
#define ssl_all 0
#define ssl_v2 1
#define ssl_v3 2
#define tls_all 3
#define tls_v10 4
#define tls_v11 5
#define tls_v12 6
#define tls_v13 7

// For functions that take a tls_version argument.
#define TLSv1_0 0
#define TLSv1_1 1
#define TLSv1_2 2
#define TLSv1_3 3

/* We must maintain our own list of TLSv1.3-specific ciphersuites here, because SSL_CTX_get_ciphers() will *always* return TLSv1.2 ciphersuites, even when SSL_CTX_set_min_proto_version() and SSL_CTX_set_max_proto_version() are used.  This is confirmed by an OpenSSL developer here: https://github.com/openssl/openssl/issues/7196#issuecomment-420575202 */
#define TLSV13_CIPHERSUITES "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"

/* Cipherlist for TLSv1.2 and below that corresponds to all available ciphersuites. */
#define CIPHERSUITE_LIST_ALL "ALL:COMPLEMENTOFALL"

// Macros for various outputs
#define printf(format, ...)         if (!xml_to_stdout) fprintf(stdout, format, ##__VA_ARGS__)
#define printf_xml(format, ...)     if (options->xmlOutput) fprintf(options->xmlOutput, format, ##__VA_ARGS__)
#define printf_verbose(format, ...) if (options->verbose) printf(format, ##__VA_ARGS__)

#define printf_error(format, ...) \
    if (!xml_to_stdout) fprintf(stderr, "%sERROR: " format "%s\n", COL_RED, ##__VA_ARGS__, RESET); \
    printf_xml("  <error><![CDATA[" format "]]></error>\n", ##__VA_ARGS__)

/* Calls close() on a file descriptor, then sets it to zero to prevent accidental re-use. */
#define CLOSE(fd) { if ((fd) != -1) { close((fd)); (fd) = -1; } }

/* Calls free() on a pointer, then explicitly sets it to NULL to avoid use-after-free. */
#define FREE(ptr) { free((ptr)); (ptr) = NULL; }

/* Frees an SSL pointer, and explicitly sets it to NULL to avoid use-after-free. */
#define FREE_SSL(ssl) { if ((ssl) != NULL) { SSL_free((ssl)); (ssl) = NULL; } }

/* Frees a SSL_CTX pointer, and explicitly sets it to NULL to avoid use-after-free. */
#define FREE_CTX(ctx) { if ((ctx) != NULL) { SSL_CTX_free((ctx)); (ctx) = NULL; } }

// Colour Console Output...
// Always better to do "const char RESET[] = " because it saves relocation records.
// Default colours were hard to read on Windows, so use lighter ones
#ifdef _WIN32
char *RESET = "[0m";            // DEFAULT
char *COL_RED = "[91m";
char *COL_YELLOW = "[93m";
char *COL_BLUE = "[1;36m";
char *COL_GREEN = "[92m";
char *COL_PURPLE = "[95m";
char *COL_GREY = "[1;30m";
char *COL_RED_BG = "[41m";
#else
char *RESET = "[0m";            // DEFAULT
char *COL_RED = "[31m";
char *COL_YELLOW = "[33m";
char *COL_BLUE = "[1;34m";
char *COL_GREEN = "[32m";
char *COL_PURPLE = "[35m";
char *COL_GREY = "[1;30m";
char *COL_RED_BG = "[41m";
#endif

#ifdef _WIN32
    #define SLEEPMS(ms) Sleep(ms);
#else
    #define SLEEPMS(ms) do {                    \
        struct timeval wait = { 0, ms*1000 };   \
        select(0, NULL, NULL, NULL, &wait);     \
    } while(0)
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
    const char *version;
    int bits;
    char description[512];
    const SSL_METHOD *sslMethod;
    struct sslCipher *next;
};

struct sslCheckOptions
{
    // Program Options...
    char host[512];
    char sniname[512];
    int sni_set;
    char addrstr[INET6_ADDRSTRLEN];
    int port;
    int showCertificate;
    int checkCertificate;
    int showTrustedCAs;
    int showClientCiphers;
    int showCipherIds;
    int showTimes;
    int ciphersuites;
    int reneg;
    int fallback;
    int compression;
    int heartbleed;
    int groups;
    int signature_algorithms;
    int starttls_ftp;
    int starttls_imap;
    int starttls_irc;
    int starttls_ldap;
    int starttls_pop3;
    int starttls_smtp;
    int starttls_mysql;
    int starttls_xmpp;
    int starttls_psql;
    int xmpp_server;
    int sslVersion;
    int targets;
    int sslbugs;
    int rdp;
    int verbose;
    int cipher_details;
    int ipv4;
    int ipv6;
    int ocspStatus;
    int ianaNames;
    char cipherstring[65536];

    // File Handles...
    FILE *xmlOutput;

    // TCP Connection Variables...
    short h_addrtype;
    struct sockaddr_in serverAddress;
    struct sockaddr_in6 serverAddress6;
    struct timeval timeout;
    int connect_timeout;
    unsigned int sleep;

    // SSL Variables...
    SSL_CTX *ctx;
    struct sslCipher *ciphers;
    char *clientCertsFile;
    char *privateKeyFile;
    char *privateKeyPassword;

    // TLS versions supported by the server.
    unsigned int tls10_supported;
    unsigned int tls11_supported;
    unsigned int tls12_supported;
    unsigned int tls13_supported;
};

// store renegotiation test data
struct renegotiationOutput
{
    int supported;
    int secure;
};

/* For OCSP processing.  Taken from crypto/ocsp/ocsp_local.h in OpenSSL, which does not seem to be normally exposed externally. */
struct ocsp_response_st {
    ASN1_ENUMERATED *responseStatus;
    OCSP_RESPBYTES *responseBytes;
};

struct ocsp_resp_bytes_st {
    ASN1_OBJECT *responseType;
    ASN1_OCTET_STRING *response;
};

struct ocsp_responder_id_st {
    int type;
    union {
        X509_NAME *byName;
        ASN1_OCTET_STRING *byKey;
    } value;
};
typedef struct ocsp_responder_id_st OCSP_RESPID;

struct ocsp_response_data_st {
    ASN1_INTEGER *version;
    OCSP_RESPID responderId;
    ASN1_GENERALIZEDTIME *producedAt;
    STACK_OF(OCSP_SINGLERESP) *responses;
    STACK_OF(X509_EXTENSION) *responseExtensions;
};
typedef struct ocsp_response_data_st OCSP_RESPDATA;

struct ocsp_basic_response_st {
    OCSP_RESPDATA tbsResponseData;
    X509_ALGOR signatureAlgorithm;
    ASN1_BIT_STRING *signature;
    STACK_OF(X509) *certs;
};

struct ocsp_single_response_st {
    OCSP_CERTID *certId;
    OCSP_CERTSTATUS *certStatus;
    ASN1_GENERALIZEDTIME *thisUpdate;
    ASN1_GENERALIZEDTIME *nextUpdate;
    STACK_OF(X509_EXTENSION) *singleExtensions;
};

struct ocsp_cert_status_st {
    int type;
    union {
        ASN1_NULL *good;
        OCSP_REVOKEDINFO *revoked;
        ASN1_NULL *unknown;
    } value;
};

struct ocsp_revoked_info_st {
    ASN1_GENERALIZEDTIME *revocationTime;
    ASN1_ENUMERATED *revocationReason;
};

struct ocsp_cert_id_st {
    X509_ALGOR hashAlgorithm;
    ASN1_OCTET_STRING issuerNameHash;
    ASN1_OCTET_STRING issuerKeyHash;
    ASN1_INTEGER serialNumber;
};

#define BS_DEFAULT_NEW_SIZE 256 /* The starting size of the buffer when bs_new() is used. */
struct _bs {
  unsigned char *buf;
  size_t size;  /* The size of the allocated buffer. */
  size_t len;   /* The number of bytes currently in the buffer. */
};
typedef struct _bs bs; /* Stands for 'byte string'. */

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
void bs_new(bs **);
void bs_new_size(bs **, size_t);
void bs_free(bs **);
void bs_append_bytes(bs *, unsigned char *, size_t);
void bs_append_uint32_t(bs *, uint32_t);
void bs_append_ushort(bs *, unsigned short);
void bs_append_bs(bs *, bs *);
size_t bs_get_len(bs *);
size_t bs_get_size(bs *);
unsigned char *bs_get_bytes(bs *);
unsigned char bs_get_byte(bs *, size_t);
void bs_set_byte(bs *, size_t, unsigned char);
void bs_set_ushort(bs *b, size_t offset, unsigned short length);
int bs_read_socket(bs *b, int s, size_t num_bytes);
unsigned int checkIfTLSVersionIsSupported(struct sslCheckOptions *options, unsigned int tls_version);
SSL_CTX *CTX_new(const SSL_METHOD *method);
int fileExists(char *);
void findMissingCiphers();
char *getPrintableTLSName(unsigned int tls_version);
bs *getServerHello(int s);
bs *makeCiphersuiteListAll(unsigned int tls_version);
bs *makeCiphersuiteListTLS13All();
bs *makeCiphersuiteListMissing(unsigned int tls_version);
bs *makeClientHello(struct sslCheckOptions *options, unsigned int version, bs *ciphersuite_list, bs *tls_extensions);
bs *makeTLSExtensions(struct sslCheckOptions *options, unsigned int include_signature_algorithms);
void markFoundCiphersuite(unsigned short server_cipher_id, unsigned int tls_version);
int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent);
static int ocsp_resp_cb(SSL *s, void *arg);
void readLine(FILE *, char *, int);
int readOrLogAndClose(int, void *, size_t, const struct sslCheckOptions *);
char *resolveCipherID(unsigned short cipher_id, int *cipher_bits);
static int password_callback(char *, int, int, void *);
const char *printableSslMethod(const SSL_METHOD *);
ssize_t sendString(int, const char[]);
int ssl_print_tmp_key(struct sslCheckOptions *, SSL *s);
void tlsExtensionAddDefaultKeyShare(bs *tls_extensions);
void tlsExtensionAddTLSv1_3(bs *tls_extensions);
void tlsExtensionUpdateLength(bs *tls_extensions);
int tcpConnect(struct sslCheckOptions *);

// Tests
void tls_reneg_init(struct sslCheckOptions *);
int outputRenegotiation(struct sslCheckOptions *, struct renegotiationOutput *);
struct renegotiationOutput *newRenegotiationOutput(void);
int freeRenegotiationOutput(struct renegotiationOutput *);

int testCompression(struct sslCheckOptions *, const SSL_METHOD *);
int testRenegotiation(struct sslCheckOptions *, const SSL_METHOD *);
#ifdef SSL_MODE_SEND_FALLBACK_SCSV
int testfallback(struct sslCheckOptions *, const SSL_METHOD *);
#endif
int testHeartbleed(struct sslCheckOptions *, const SSL_METHOD *);
int testSupportedGroups(struct sslCheckOptions *options);
int testSignatureAlgorithms(struct sslCheckOptions *options);
int testCipher(struct sslCheckOptions *, const SSL_METHOD *);
int testMissingCiphers(struct sslCheckOptions *options, unsigned int version);
int testProtocolCiphers(struct sslCheckOptions *, const SSL_METHOD *);
int testConnection(struct sslCheckOptions *);
int testHost(struct sslCheckOptions *);
int loadCerts(struct sslCheckOptions *);
int checkCertificateProtocols(struct sslCheckOptions *, const SSL_METHOD *);
int checkCertificate(struct sslCheckOptions *, const SSL_METHOD *);
int showCertificate(struct sslCheckOptions *);

int runSSLv2Test(struct sslCheckOptions *options);
int runSSLv3Test(struct sslCheckOptions *options);
#endif

/* vim :set ts=4 sw=4 sts=4 et : */
