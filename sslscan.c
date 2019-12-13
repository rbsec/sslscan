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

#define _GNU_SOURCE

// Includes...
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define VC_EXTRALEAN
  #define _WIN32_WINNT 0x0501
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <stdint.h>
  #ifdef _MSC_VER
    // For access().
    #include <io.h>

    // Flag for access() call.
    #define R_OK 4

    // access() happens to be deprecated, so use the secure version instead.
    #define access _access_s

    // There is no snprintf(), but _snprintf() instead.
    #define snprintf _snprintf

    // Calling close() on a socket descriptor instead of closesocket() causes
    // a crash!
    #define close closesocket

    // Visual Studio doesn't have ssize_t...
    typedef int ssize_t;
  #else
    void *memmem(const void *haystack_start, size_t haystack_len, const void *needle, size_t needle_len);
    /* Taken from https://sourceforge.net/p/mingw/bugs/_discuss/thread/ec0291f1/93ae/attachment/patchset-wrapped.diff:*/
    #define timersub(a, b, result) \
    do { \
        (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
        (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
        if ((result)->tv_usec < 0) { \
            --(result)->tv_sec; \
            (result)->tv_usec += 1000000L; \
        } \
    } while (0)
 
    #ifdef BUILD_32BIT
      #include "win32bit-compat.h"
    #endif
  #endif

  const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

  #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
    #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
  #endif
#else
  #include <netdb.h>
  #include <sys/socket.h>
  #include <sys/select.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#ifdef __linux__
    #include <arpa/inet.h>
#endif
#ifndef OPENSSL_NO_COMP
  #include <openssl/comp.h>
#endif

// If we're not compiling with Visual Studio, include unistd.h.  VS
// doesn't have this header.
#ifndef _MSC_VER
  #include <unistd.h>
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <netinet/in.h>
#endif

/* Format specifier for printing a size_t. */
#ifdef _WIN32
  #define SIZE_T_FMT PRIu64
#else
  #define SIZE_T_FMT "zu"
#endif

#include "sslscan.h"

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error "OpenSSL v1.1.1 or later is required!"
#endif

/* Borrowed from tortls.c to dance with OpenSSL on many platforms, with
 * many versions and releases of OpenSSL. */
/** Does the run-time openssl version look like we need
 * SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_op = 0;

/** Does the run-time openssl version look like we need
 * SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_flag = 0;

/** Does output xml to stdout? */
static int xml_to_stdout = 0;

#if OPENSSL_VERSION_NUMBER < 0x1000100L
unsigned long SSL_CIPHER_get_id(const SSL_CIPHER* cipher) { return cipher->id; }
#endif

const SSL_METHOD *TLSv1_3_client_method(void)
{
    return TLS_client_method();
}

const SSL_METHOD *TLSv1_3_method(void)
{
    return TLS_method();
}

/* Callback set through SSL_set_security_callback() and SSL_CTX_set_security_callback().  Allows all weak algorithms. */
static int security_callback_allow_all(const SSL *s, const SSL_CTX *ctx, int op, int bits, int nid, void *other, void *ex) {
  return 1;
}

/* Creates an SSL_CTX using SSL_CTX_new(), sets the security level to 0, and sets the permissive security callback on it.  Free with FREE_CTX(). */
SSL_CTX *new_CTX(const SSL_METHOD *method) {
  SSL_CTX *ret = SSL_CTX_new(method);
  SSL_CTX_set_security_level(ret, 0);
  SSL_CTX_set_security_callback(ret, security_callback_allow_all);
  return ret;
}

/* Creates an SSL object using SSL_new(), sets the security level to 0, and sets the permissive security callback on it.  Free with FREE_SSL(). */
SSL *new_SSL(SSL_CTX *ctx) {
  SSL *ret = SSL_new(ctx);
  SSL_set_security_level(ret, 0);
  SSL_set_security_callback(ret, security_callback_allow_all);
  return ret;
}

// Adds Ciphers to the Cipher List structure
int populateCipherList(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    int returnCode = true;
    struct sslCipher *sslCipherPointer;
    int tempInt;
    int loop;
    // STACK_OF is a sign that you should be using C++ :)
    STACK_OF(SSL_CIPHER) *cipherList;
    SSL *ssl = NULL;
    options->ctx = new_CTX(sslMethod);
    if (options->ctx == NULL) {
        printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        return false;
    }
    SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL);
    ssl = new_SSL(options->ctx);
    if (ssl == NULL) {
        printf_error("%sERROR: Could not create SSL object.%s\n", COL_RED, RESET);
        FREE_CTX(options->ctx);
        return false;
    }
    cipherList = SSL_get_ciphers(ssl);
    // Create Cipher Struct Entries...
    for (loop = 0; loop < sk_SSL_CIPHER_num(cipherList); loop++)
    {
        if (options->ciphers == 0)
        {
            options->ciphers = malloc(sizeof(struct sslCipher));
            sslCipherPointer = options->ciphers;
        }
        else
        {
            sslCipherPointer = options->ciphers;
            while (sslCipherPointer->next != 0)
                sslCipherPointer = sslCipherPointer->next;
            sslCipherPointer->next = malloc(sizeof(struct sslCipher));
            sslCipherPointer = sslCipherPointer->next;
        }
        // Init
        memset(sslCipherPointer, 0, sizeof(struct sslCipher));
        // Add cipher information...
        sslCipherPointer->sslMethod = sslMethod;
        sslCipherPointer->name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(cipherList, loop));
        sslCipherPointer->version = SSL_CIPHER_get_version(sk_SSL_CIPHER_value(cipherList, loop));
        SSL_CIPHER_description(sk_SSL_CIPHER_value(cipherList, loop), sslCipherPointer->description, sizeof(sslCipherPointer->description) - 1);
        sslCipherPointer->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(cipherList, loop), &tempInt);
    }
    FREE_SSL(ssl);
    FREE_CTX(options->ctx);
    return returnCode;
}

// File Exists
int fileExists(char *fileName)
{
    return access(fileName, R_OK) == 0;
}

// Read a line from the input...
void readLine(FILE *input, char *lineFromFile, int maxSize)
{
    // Variables...
    int stripPointer;

    // Read line from file...
    fgets(lineFromFile, maxSize, input);

    // Clear the end-of-line stuff...
    stripPointer = strlen(lineFromFile) -1;
    while (stripPointer >= 0 && ((lineFromFile[stripPointer] == '\r') || (lineFromFile[stripPointer] == '\n') || (lineFromFile[stripPointer] == ' ')))
    {
        lineFromFile[stripPointer] = 0;
        stripPointer--;
    }
}


int readOrLogAndClose(int fd, void* buffer, size_t len, const struct sslCheckOptions *options)
{
    ssize_t n;

    if (len < 2)
        return 1;

    n = recv(fd, buffer, len - 1, 0);

    if (n < 0 && errno != 11) {
        printf_error("%s    ERROR: error reading from %s:%d: %s%s\n", COL_RED, options->host, options->port, strerror(errno), RESET);
        close(fd);
        return 0;
    } else if (n == 0) {
        printf_error("%s    ERROR: unexpected EOF reading from %s:%d%s\n", COL_RED, options->host, options->port, RESET);
        close(fd);
        return 0;
    } else {
        ((unsigned char *)buffer)[n] = 0;
    }

    return 1;
}

// Write a null-terminated string to a socket
ssize_t sendString(int sockfd, const char str[])
{
    return send(sockfd, str, strlen(str), 0);
}

// Create a TCP socket
int tcpConnect(struct sslCheckOptions *options)
{
    //Sleep if required
    if (options->sleep > 0)
    {
        SLEEPMS(options->sleep);
    }
    
    // Variables...
    int socketDescriptor;
    int tlsStarted = 0;
    char buffer[BUFFERSIZE];
    int status;

    // Create Socket
    if (options->h_addrtype == AF_INET)
    {
        socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    }
    else    // IPv6
    {
        socketDescriptor = socket(AF_INET6, SOCK_STREAM, 0);
    }

    if(socketDescriptor < 0)
    {
        printf_error("%s    ERROR: Could not open a socket.%s\n", COL_RED, RESET);
        return 0;
    }

    // Set socket timeout
#ifdef _WIN32
    // Windows isn't looking for a timeval struct like in UNIX; it wants a timeout in a DWORD represented in milliseconds...
    DWORD timeout = (options->timeout.tv_sec * 1000) + (options->timeout.tv_usec / 1000);
    setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
#else
    setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, (char *)&options->timeout,sizeof(struct timeval));
#endif

    // Connect
    if (options->h_addrtype == AF_INET)
    {
        status = connect(socketDescriptor, (struct sockaddr *) &options->serverAddress, sizeof(options->serverAddress));
    }
    else    // IPv6
    {
        status = connect(socketDescriptor, (struct sockaddr *) &options->serverAddress6, sizeof(options->serverAddress6));
    }

    if(status < 0)
    {
        printf_error("%sERROR: Could not open a connection to host %s (%s) on port %d.%s\n", COL_RED, options->host, options->addrstr, options->port, RESET);
        close(socketDescriptor);
        return 0;
    }

    // If STARTTLS is required...
    if (options->starttls_smtp == true && tlsStarted == false)
    {
        tlsStarted = 1;
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;

        if (strncmp(buffer, "220", 3) != 0)
        {
            close(socketDescriptor);
            printf("%s    ERROR: The host %s on port %d did not appear to be an SMTP service.%s\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }
        sendString(socketDescriptor, "EHLO example.org\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        if (strncmp(buffer, "250", 3) != 0)
        {
            close(socketDescriptor);
            printf("%s    ERROR: The SMTP service on %s port %d did not respond with status 250 to our HELO.%s\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }
        sendString(socketDescriptor, "STARTTLS\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        if (strncmp(buffer, "220", 3) != 0)
        {
            close(socketDescriptor);
            printf("%s    ERROR: The SMTP service on %s port %d did not appear to support STARTTLS.%s\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }
    }

    if (options->starttls_mysql == true && tlsStarted == false)
    {
        tlsStarted = 1;
        // Taken from https://github.com/tetlowgm/sslscan/blob/master/sslscan.c

        const char mysqlssl[] = { 0x20, 0x00, 0x00, 0x01, 0x85, 0xae, 0x7f, 0x00, 
            0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00};

        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        send(socketDescriptor, mysqlssl, sizeof(mysqlssl), 0);
    }

    // We could use an XML parser but frankly it seems like a security disaster
    if (options->starttls_xmpp == true && tlsStarted == false)
    {
        /* This is so ghetto, you cannot release it! */
        char xmpp_setup[1024]; // options->host is 512 bytes long
        /* XXX: TODO - options->host isn't always the host you want to test
           eg:
           talk.google.com actually expects gmail.com, not talk.google.com
           jabber.ccc.de expects jabber.ccc.de

           It may be useful to provide a commandline switch to provide the
           expected hostname.
        */
        // Server to server handshake
        if (options->xmpp_server)
        {
            if (snprintf(xmpp_setup, sizeof(xmpp_setup), "<?xml version='1.0' ?>\r\n"
                        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='%s' version='1.0'>\r\n", options->host) >= sizeof(xmpp_setup)) {
                printf("(internal error: xmpp_setup buffer too small)\n");
                abort();
            }
        }
        // Client to server handshake (default)
        else
        {
            if (snprintf(xmpp_setup, sizeof(xmpp_setup), "<?xml version='1.0' ?>\r\n"
                        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\r\n", options->host) >= sizeof(xmpp_setup)) {
                printf("(internal error: xmpp_setup buffer too small)\n");
                abort();
            }
        }
        tlsStarted = 1;
        sendString(socketDescriptor, xmpp_setup);
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;

        printf_verbose("Server reported: %s\nAttempting to STARTTLS\n", buffer);

        sendString(socketDescriptor, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;

        /* We're looking for something like:
        <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'
        If we find the end of the stream features before we find tls, we may
        not have STARTTLS support. */
        if (strstr(buffer, "urn:ietf:params:xml:ns:xmpp-tls")) {
            printf_verbose("It appears that xmpp-tls was detected.\n");
        } else if (strstr(buffer, "/stream:features")) {
            printf_verbose("It appears that xmpp-tls was not detected.\n");
        }

        if (options->verbose)
            printf("Server reported: %s\n", buffer);

        if (strstr(buffer, "<proceed"))
        {
            printf_verbose("It appears that xmpp-tls is ready for TLS.\n");
        }
        else
        {
            if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
                return 0;
        }

        printf_verbose("Server reported: %s\n", buffer);

    }

    // Setup a POP3 STARTTLS socket
    if (options->starttls_pop3 == true && tlsStarted == false)
    {
        tlsStarted = 1;
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        printf_verbose("Server reported: %s\n", buffer);

        sendString(socketDescriptor, "STLS\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        // We probably want to confirm that we see something like:
        // '+OK Begin SSL/TLS negotiation now.'
        // Or
        // '+OK Begin TLS negotiation, mate'
        if (strstr(buffer, "+OK Begin")) {
            printf_verbose("It appears that the POP3 server is ready for TLS.\n");
        }
        printf_verbose("Server reported: %s\n", buffer);
    }

    // Setup an IMAP STARTTLS socket
    if (options->starttls_imap == true && tlsStarted == false)
    {
        tlsStarted = 1;
        memset(buffer, 0, BUFFERSIZE);

        // Fetch the IMAP banner
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        printf_verbose("Server banner: %s\n", buffer);

        // Attempt to STARTTLS
        sendString(socketDescriptor, ". STARTTLS\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;

        if (strstr(buffer, ". OK") || strstr(buffer, " . OK")){
            printf_verbose("STARTLS IMAP setup complete.\nServer reported: %s\n", buffer);
        } else{
            printf_verbose("STARTLS IMAP setup not complete.\nServer reported: %s\n", buffer);
        }
    }

    if (options->starttls_irc == true && tlsStarted == false)
    {
        tlsStarted = 1;
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        printf_verbose("Server reported: %s\n", buffer);

        // Attempt to STARTTLS
        sendString(socketDescriptor, "STARTTLS\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;

        if (strstr(buffer, " 670 ") || strstr(buffer, ":STARTTLS successful")) {
            printf_verbose("STARTLS IRC setup complete.\nServer reported %s\n", buffer);
        } else {
            printf_verbose("STARTLS IRC setup not complete.\nServer reported %s\n", buffer);
        }
    }

    // Setup a LDAP STARTTLS socket
    if (options->starttls_ldap == true && tlsStarted == false)
    {
        tlsStarted = 1;
        memset(buffer, 0, BUFFERSIZE);
        char starttls[] = {'0', 0x1d, 0x02, 0x01, 0x01, 'w', 0x18, 0x80, 0x16,
            '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.',
            '1', '4', '6', '6', '.', '2', '0', '0', '3', '7'};
        char ok[] = "1.3.6.1.4.1.1466.20037";
        char unsupported[] = "unsupported extended operation";

        // Send TLS
        send(socketDescriptor, starttls, sizeof(starttls), 0);
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;

#ifdef __USE_GNU
        if (memmem(buffer, BUFFERSIZE, ok, sizeof(ok))) {
#else
        if (strnstr(buffer, ok, BUFFERSIZE)) {
#endif
            printf_verbose("STARTLS LDAP setup complete.\n");
        }
#ifdef __USE_GNU
        else if (memmem(buffer, BUFFERSIZE, unsupported, sizeof(unsupported))) {
#else
        else if (strnstr(buffer, unsupported, BUFFERSIZE)) {
#endif
            printf_error("%sSTARTLS LDAP connection to %s:%d failed with '%s'.%s\n",
                         COL_RED, options->host, options->port, unsupported, RESET);
            return 0;
        } else {
            printf_error("%sSTARTLS LDAP connection to %s:%d failed with unknown error.%s\n",
                         COL_RED, options->host, options->port, RESET);
            return 0;
        }
    }

    // Setup a FTP STARTTLS socket
    if (options->starttls_ftp == true && tlsStarted == false)
    {
        tlsStarted = 1;

        // Fetch the server banner
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        printf_verbose("Server banner: %s\n", buffer);

        // Send TLS request
        sendString(socketDescriptor, "AUTH TLS\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        if (strstr(buffer, "234 AUTH TLS successful")) {
            printf_verbose("STARTLS FTP setup complete.\n");
        } else {
            printf_verbose("STARTLS FTP setup possibly not complete.\n");
        }
        printf_verbose("Server reported: %s\n", buffer);
    }

    if (options->starttls_psql == true && tlsStarted == false)
    {
        unsigned char buffer;

        tlsStarted = 1;

        // Send SSLRequest packet
        send(socketDescriptor, "\x00\x00\x00\x08\x04\xd2\x16\x2f", 8, 0);

        // Read reply byte
        if (1 != recv(socketDescriptor, &buffer, 1, 0)) {
            printf_error("%s    ERROR: unexpected EOF reading from %s:%d%s\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }

        if (buffer != 'S') {
            printf_error("%s    ERROR: server at %s:%d%s rejected TLS startup\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }
    }

    // Setup an RDP socket with preamble
    // Borrowed from https://labs.portcullis.co.uk/tools/ssl-cipher-suite-enum/
    if (options->rdp == true && tlsStarted == false)
    {
        unsigned char buffer[32768];
        size_t readlen;

        tlsStarted = 1;

        // Send RDP preamble
        send(socketDescriptor, "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00", 19, 0);

        // Read reply header
        if (4 != recv(socketDescriptor, buffer, 4, 0)) {
            printf_error("%s    ERROR: unexpected EOF reading from %s:%d%s\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }

        // Calculate remaining bytes (and check for overflows)
        readlen = ((buffer[2] & 0x7f) << 8) + buffer[3] - 4;
        if (readlen > sizeof(buffer)) {
            printf_error("%s    ERROR: unexpected data from %s:%d%s\n", COL_RED, options->host, options->port, RESET);
            return 0;

        }

        // Read reply data
        if (readlen != recv(socketDescriptor, buffer, readlen, 0)) {
            printf_error("%s    ERROR: unexpected EOF reading from %s:%d%s\n", COL_RED, options->host, options->port, RESET);
            return 0;
        }
    }

    // Return
    return socketDescriptor;
}

// Private Key Password Callback...
static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    strncpy(buf, (char *)userdata, size);
    // I don't know the semantics of these arguments, but it looks like this
    // could go badly wrong if userdata is too long.
    buf[strlen(userdata)] = 0;
    return strlen(userdata);
}

// Load client certificates/private keys...
int loadCerts(struct sslCheckOptions *options)
{
    // Variables...
    int status = 1;
    PKCS12 *pk12 = NULL;
    FILE *pk12File = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *ca = NULL;

    // Configure PKey password...
    if (options->privateKeyPassword != 0)
    {
        SSL_CTX_set_default_passwd_cb_userdata(options->ctx, (void *)options->privateKeyPassword);
        SSL_CTX_set_default_passwd_cb(options->ctx, password_callback);
    }

    // Separate Certs and PKey Files...
    if ((options->clientCertsFile != 0) && (options->privateKeyFile != 0))
    {
        // Load Cert...
        if (!SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_PEM))
        {
            if (!SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_ASN1))
            {
                if (!SSL_CTX_use_certificate_chain_file(options->ctx, options->clientCertsFile))
                {
                    printf("%s    Could not configure certificate(s).%s\n", COL_RED, RESET);
                    status = 0;
                }
            }
        }

        // Load PKey...
        if (status != 0)
        {
            if (!SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM))
            {
                if (!SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1))
                {
                    // Why would the more specific functions succeed if the generic functions failed?
                    // -- I'm guessing that the original author was hopeful? - io
                    if (!SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM))
                    {
                        if (!SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1))
                        {
                            printf("%s    Could not configure private key.%s\n", COL_RED, RESET);
                            status = 0;
                        }
                    }
                }
            }
        }
    }

    // PKCS Cert and PKey File...
    else if (options->privateKeyFile != 0)
    {
        pk12File = fopen(options->privateKeyFile, "rb");
        if (pk12File != NULL)
        {
            pk12 = d2i_PKCS12_fp(pk12File, NULL);
            if (!pk12)
            {
                status = 0;
                printf("%s    Could not read PKCS#12 file.%s\n", COL_RED, RESET);
            }
            else
            {
                if (!PKCS12_parse(pk12, options->privateKeyPassword, &pkey, &cert, &ca))
                {
                    status = 0;
                    printf("%s    Error parsing PKCS#12. Are you sure that password was correct?%s\n", COL_RED, RESET);
                }
                else
                {
                    if (!SSL_CTX_use_certificate(options->ctx, cert))
                    {
                        status = 0;
                        printf("%s    Could not configure certificate.%s\n", COL_RED, RESET);
                    }
                    if (!SSL_CTX_use_PrivateKey(options->ctx, pkey))
                    {
                        status = 0;
                        printf("%s    Could not configure private key.%s\n", COL_RED, RESET);
                    }
                }
                PKCS12_free(pk12);
            }
            fclose(pk12File);
        }
        else
        {
            printf("%s    Could not open PKCS#12 file.%s\n", COL_RED, RESET);
            status = 0;
        }
    }

    // Check Cert/Key...
    if (status != 0)
    {
        if (!SSL_CTX_check_private_key(options->ctx))
        {
            printf("%s    Private key does not match certificate.%s\n", COL_RED, RESET);
            return false;
        }
        else
            return true;
    }
    else
        return false;
}


// Test renegotiation
int outputRenegotiation( struct sslCheckOptions *options, struct renegotiationOutput *outputData)
{

    printf_xml("  <renegotiation supported=\"%d\" secure=\"%d\" />\n",
        outputData->supported, outputData->secure);

    if (outputData->secure)
    {
        printf("%sSecure%s session renegotiation supported\n\n", COL_GREEN, RESET);
    }
    else if (outputData->supported)
    {
        printf("%sInsecure%s session renegotiation supported\n\n", COL_RED, RESET);
    }
    else
    {
       printf("Session renegotiation %snot supported%s\n\n", COL_GREEN, RESET);
    }

    return true;
}

struct renegotiationOutput * newRenegotiationOutput( void )
{
    struct renegotiationOutput *myRenOut;
    myRenOut = calloc(1,sizeof(struct renegotiationOutput));
    return( myRenOut );
}

int freeRenegotiationOutput( struct renegotiationOutput *myRenOut )
{
    if ( myRenOut != NULL) {
        free(myRenOut);
    }
    return true;
}

void tls_reneg_init(struct sslCheckOptions *options)
{
    /* Borrowed from tortls.c to dance with OpenSSL on many platforms, with
     * many versions and release of OpenSSL. */
    SSL_library_init();
    SSL_load_error_strings();

    long version = SSLeay();
    if (version >= 0x009080c0L && version < 0x009080d0L) {
        printf_verbose("OpenSSL %s looks like version 0.9.8l; I will try SSL3_FLAGS to enable renegotiation.\n",
            SSLeay_version(SSLEAY_VERSION));
        use_unsafe_renegotiation_flag = 1;
        use_unsafe_renegotiation_op = 1;
    } else if (version >= 0x009080d0L) {
        printf_verbose("OpenSSL %s looks like version 0.9.8m or later; "
            "I will try SSL_OP to enable renegotiation\n",
        SSLeay_version(SSLEAY_VERSION));
        use_unsafe_renegotiation_op = 1;
    } else if (version < 0x009080c0L) {
        printf_verbose("OpenSSL %s [%lx] looks like it's older than "
            "0.9.8l, but some vendors have backported 0.9.8l's "
            "renegotiation code to earlier versions, and some have "
            "backported the code from 0.9.8m or 0.9.8n.  I'll set both "
            "SSL3_FLAGS and SSL_OP just to be safe.\n",
            SSLeay_version(SSLEAY_VERSION), version);
        use_unsafe_renegotiation_flag = 1;
        use_unsafe_renegotiation_op = 1;
    } else {
        printf_verbose("OpenSSL %s has version %lx\n",
            SSLeay_version(SSLEAY_VERSION), version);
    }

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  SSL_CTX_set_options(options->ctx,
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
}

// Check if the server supports compression
int testCompression(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    SSL_SESSION *session;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        options->ctx = new_CTX(sslMethod);
        tls_reneg_init(options);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                    // Make sure we can connect to insecure servers
                    // OpenSSL is going to change the default at a later date
                    SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
#endif

#ifdef SSL_OP_NO_COMPRESSION
                    // Make sure to clear the no compression flag
                    SSL_clear_options(ssl, SSL_OP_NO_COMPRESSION);
#endif

                   if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // This enables TLS SNI
                        SSL_set_tlsext_host_name(ssl, options->sniname);
#endif

                        // Connect SSL over socket
                        SSL_connect(ssl);

                        session = SSL_get_session(ssl);

#ifndef OPENSSL_NO_COMP
                        // Make sure zlib is actually present
                        if (sk_SSL_COMP_num(SSL_COMP_get_compression_methods()) != 0)
                        {
                            printf_xml("  <compression supported=\"%d\" />\n",
                                SSL_SESSION_get_compress_id(session));

                            if (SSL_SESSION_get_compress_id(session) == 0)
                            {
                                printf("Compression %sdisabled%s\n\n", COL_GREEN, RESET);
                            }
                            else
                            {
                                printf("Compression %senabled%s (CRIME)\n\n", COL_RED, RESET);
                            }
                        }
                        else
#endif
                        {
                            printf("%sOpenSSL version does not support compression%s\n", COL_RED, RESET);
                            printf("%sRebuild with zlib1g-dev package for zlib support%s\n\n", COL_RED, RESET);
                        }

                        // Disconnect SSL over socket
                        SSL_shutdown(ssl);

                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf_error("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf_error("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }
            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("%sERROR: Could not connect.%s\n", COL_RED, RESET);
        status = false;
        exit(status);
    }

    return status;
}

#ifdef SSL_MODE_SEND_FALLBACK_SCSV
// Check for TLS_FALLBACK_SCSV
int testFallback(struct sslCheckOptions *options,  const SSL_METHOD *sslMethod)
{
    // Variables...
    int status = true;
    int downgraded = true;
    int connStatus = false;
    int socketDescriptor = 0;
    int sslversion;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    const SSL_METHOD *secondMethod;

    // Function gets called a second time with downgraded protocol
    if (!sslMethod)
    {
        sslMethod = SSLv23_method();
        downgraded = false;
    }

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        options->ctx = new_CTX(sslMethod);
        tls_reneg_init(options);
        if (options->ctx != NULL)
        {
            if (downgraded)
            {
                SSL_CTX_set_mode(options->ctx, SSL_MODE_SEND_FALLBACK_SCSV);
            }
            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                    // Make sure we can connect to insecure servers
                    // OpenSSL is going to change the default at a later date
                    SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
#endif

#ifdef SSL_OP_NO_COMPRESSION
                    // Make sure to clear the no compression flag
                    SSL_clear_options(ssl, SSL_OP_NO_COMPRESSION);
#endif

                   if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // This enables TLS SNI
                        SSL_set_tlsext_host_name(ssl, options->sniname);
#endif

                        // Connect SSL over socket
                        connStatus = SSL_connect(ssl);
                        if (connStatus > 0)
                        {
                            if (!downgraded)
                            {
                                sslversion = SSL_version(ssl);
                                if (sslversion == TLS1_3_VERSION)
                                {
                                    secondMethod = TLSv1_2_client_method();
                                }
                                else if (sslversion == TLS1_2_VERSION)
                                {
				  secondMethod = TLSv1_1_client_method();
                                }
				else if (sslversion == TLS1_VERSION)
				{
				  secondMethod = TLSv1_client_method();
				}
				else if (sslversion == TLS1_VERSION)
				{
				  printf("Server only supports TLSv1.0");
				  status = false;
				}
				else
				{
				  printf("Server doesn't support TLS - skipping TLS Fallback SCSV check\n\n");
				  status = false;
				}
                            }
                            else
                            {
                                printf("Server %sdoes not%s support TLS Fallback SCSV\n\n", COL_RED, RESET);
                            }
                        }
                        else
                        {
                            if (downgraded)
                            {
                                if (SSL_get_error(ssl, connStatus == 1))
                                {
                                    ERR_get_error();
                                    if (SSL_get_error(ssl, connStatus == 6))
                                    {
                                        printf("Server %ssupports%s TLS Fallback SCSV\n\n", COL_GREEN, RESET);
                                        status = false;
                                    }
                                }
                            }
                            else
                            {
                                printf("%sConnection failed%s - unable to determine TLS Fallback SCSV support\n\n",
                                        COL_YELLOW, RESET);
                                status = false;
                            }
                        }

                        // Disconnect SSL over socket
                        SSL_shutdown(ssl);

                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf_error("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf_error("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }
            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("%sERROR: Could not connect.%s\n", COL_RED, RESET);
        status = false;
        exit(status);
    }

    // Call function again with downgraded protocol
    if (status && !downgraded)
    {
        testFallback(options, secondMethod);
    }
    return status;
}
#endif


// Check if the server supports renegotiation
int testRenegotiation(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int cipherStatus;
    int status = true;
    //int secure = false;
    int socketDescriptor = 0;
    int res;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    struct renegotiationOutput *renOut = newRenegotiationOutput();

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {

        // Setup Context Object...
        options->ctx = new_CTX(sslMethod);
        tls_reneg_init(options);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                    // Make sure we can connect to insecure servers
                    // OpenSSL is going to change the default at a later date
                    SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
#endif

                   if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // This enables TLS SNI
                        // Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
                        // TLS Virtual-hosting requires that the server present the correct
                        // certificate; to do this, the ServerNameIndication TLS extension is used.
                        // If TLS is negotiated, and OpenSSL is recent enough that it might have
                        // support, and support was enabled when OpenSSL was built, mutt supports
                        // sending the hostname we think we're connecting to, so a server can send
                        // back the correct certificate.
                        // NB: finding a server which uses this for IMAP is problematic, so this is
                        // untested.  Please report success or failure!  However, this code change
                        // has worked fine in other projects to which the contributor has added it,
                        // or HTTP usage.
                        SSL_set_tlsext_host_name(ssl, options->sniname);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);

                      /* Yes, we know what we are doing here.  No, we do not treat a renegotiation
                       * as authenticating any earlier-received data. */
/*                      if (use_unsafe_renegotiation_flag) {
                        printf_verbose("use_unsafe_renegotiation_flag\n");
			SSL_CTX_set_options(ssl,SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
			SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION??
                      } */
                      if (use_unsafe_renegotiation_op) {
                        printf_verbose("use_unsafe_renegotiation_op\n");
                        SSL_set_options(ssl,
                                        SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
                      }


                        if (cipherStatus == 1)
                        {

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                            // SSL_get_secure_renegotiation_support() appeared first in OpenSSL 0.9.8m
                            printf_verbose("Attempting secure_renegotiation_support()\n");
                            renOut->secure = SSL_get_secure_renegotiation_support(ssl);
                            if( renOut->secure )
                            {
                                // If it supports secure renegotiations,
                                // it should have renegotiation support in general
                                renOut->supported = true;
                                status = true;
                            }
                            else
                            {
#endif
                                // We can't assume that just because the secure renegotiation
                                // support failed the server doesn't support insecure renegotiations

                                // assume ssl is connected and error free up to here
                                //setBlocking(ssl); // this is unnecessary if it is already blocking
                                printf_verbose("Attempting SSL_renegotiate(ssl)\n");
                                SSL_renegotiate(ssl); // Ask to renegotiate the connection
                                // This hangs when an 'encrypted alert' is sent by the server
                                printf_verbose("Attempting SSL_do_handshake(ssl)\n");
                                SSL_do_handshake(ssl); // Send renegotiation request to server //TODO :: XXX hanging here

                                if (SSL_get_state(ssl) == TLS_ST_OK)
                                {
                                    res = SSL_do_handshake(ssl); // Send renegotiation request to server
                                    if( res != 1 )
                                    {
                                        printf_error("\n\nSSL_do_handshake() call failed\n");
                                    }
                                    if (SSL_get_state(ssl) == TLS_ST_OK)
                                    {
                                        /* our renegotiation is complete */
                                        renOut->supported = true;
                                        status = true;
                                    } else {
                                        renOut->supported = false;
                                        status = false;
                                        printf_error("\n\nFailed to complete renegotiation\n");
                                    }
                                } else {
                                    status = false;
                                    renOut->secure = false;
                                }
#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                            }
#endif
                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        renOut->supported = false;
                        printf_error("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                renOut->supported = false;
                printf_error("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }
            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            renOut->supported = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("%sERROR: Could not connect.%s\n", COL_RED, RESET);
        renOut->supported = false;
        status = false;
        freeRenegotiationOutput( renOut );
        exit(status);
    }
    outputRenegotiation(options, renOut);
    freeRenegotiationOutput( renOut );

    return status;

}

const char* printableSslMethod(const SSL_METHOD *sslMethod)
{
    if (sslMethod == TLSv1_client_method())
        return "TLSv1.0";
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    if (sslMethod == TLSv1_1_client_method())
        return "TLSv1.1";
    if (sslMethod == TLSv1_2_client_method())
        return "TLSv1.2";
#endif
    if (sslMethod == TLSv1_3_client_method())
        return "TLSv1.3";
    return "unknown SSL_METHOD";
}

// Test for Heartbleed
int testHeartbleed(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int status = true;
    int socketDescriptor = 0;

    // Connect to host
    socketDescriptor = tcpConnect(options);


    if (socketDescriptor != 0)
    {

        // Credit to Jared Stafford (jspenguin@jspenguin.org)
        char hello[] = {0x16,0x03,0x01,0x00,0xdc,0x01,0x00,0x00,0xd8,0x03,0x00,0x53,0x43,0x5b,0x90,0x9d,0x9b,0x72,0x0b,0xbc,0x0c,0xbc,0x2b,0x92,0xa8,0x48,0x97,0xcf,0xbd,0x39,0x04,0xcc,0x16,0x0a,0x85,0x03,0x90,0x9f,0x77,0x04,0x33,0xd4,0xde,0x00,0x00,0x66,0xc0,0x14,0xc0,0x0a,0xc0,0x22,0xc0,0x21,0x00,0x39,0x00,0x38,0x00,0x88,0x00,0x87,0xc0,0x0f,0xc0,0x05,0x00,0x35,0x00,0x84,0xc0,0x12,0xc0,0x08,0xc0,0x1c,0xc0,0x1b,0x00,0x16,0x00,0x13,0xc0,0x0d,0xc0,0x03,0x00,0x0a,0xc0,0x13,0xc0,0x09,0xc0,0x1f,0xc0,0x1e,0x00,0x33,0x00,0x32,0x00,0x9a,0x00,0x99,0x00,0x45,0x00,0x44,0xc0,0x0e,0xc0,0x04,0x00,0x2f,0x00,0x96,0x00,0x41,0xc0,0x11,0xc0,0x07,0xc0,0x0c,0xc0,0x02,0x00,0x05,0x00,0x04,0x00,0x15,0x00,0x12,0x00,0x09,0x00,0x14,0x00,0x11,0x00,0x08,0x00,0x06,0x00,0x03,0x00,0xff,0x01,0x00,0x00,0x49,0x00,0x0b,0x00,0x04,0x03,0x00,0x01,0x02,0x00,0x0a,0x00,0x34,0x00,0x32,0x00,0x0e,0x00,0x0d,0x00,0x19,0x00,0x0b,0x00,0x0c,0x00,0x18,0x00,0x09,0x00,0x0a,0x00,0x16,0x00,0x17,0x00,0x08,0x00,0x06,0x00,0x07,0x00,0x14,0x00,0x15,0x00,0x04,0x00,0x05,0x00,0x12,0x00,0x13,0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x0f,0x00,0x10,0x00,0x11,0x00,0x23,0x00,0x00,0x00,0x0f,0x00,0x01,0x01};

        if (sslMethod == TLSv1_client_method())
        {
            hello[10] = 0x01;
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if (sslMethod == TLSv1_1_client_method())
        {
            hello[10] = 0x02;
        }
        else if (sslMethod == TLSv1_2_client_method())
        {
            hello[10] = 0x03;
        }
#endif
        else if (sslMethod == TLSv1_3_client_method())
        {
            hello[10] = 0x03;
        }
        if (send(socketDescriptor, hello, sizeof(hello), 0) <= 0) {
            printf_error("send() failed: %s\n", strerror(errno));
            exit(1);
        }

        // Send the heartbeat
        char hb[8] = {0x18,0x03,0x00,0x00,0x03,0x01,0x40,0x00};
        if (sslMethod == TLSv1_client_method())
        {
            hb[2] = 0x01;
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if (sslMethod == TLSv1_1_client_method())
        {
            hb[2] = 0x02;
        }
        else if (sslMethod == TLSv1_2_client_method())
        {
            hb[2] = 0x03;
        }
#endif
        else if (sslMethod == TLSv1_3_client_method())
        {
            hb[2] = 0x03;
        }
        if (send(socketDescriptor, hb, sizeof(hb), 0) <= 0) {
            printf_error("send() failed: %s\n", strerror(errno));
            exit(1);
        }

        char hbbuf[65536];

        while(1)
        {
            memset(hbbuf, 0, sizeof(hbbuf));

            // Read 5 byte header
            int readResult = recv(socketDescriptor, hbbuf, 5, 0);
            if (readResult <= 0)
            {
                break;
            }

            char typ = hbbuf[0];

            // Combine 2 bytes to get payload length
            uint16_t ln = hbbuf[4] | hbbuf[3] << 8;

            // Debugging
/*
            uint16_t ver = hbbuf[2] | hbbuf[1] << 8;
            printf("%hhX %hhX %hhX %hhX %hhX - %d %d %d\n", hbbuf[0], hbbuf[1], hbbuf[2], hbbuf[3], hbbuf[4], typ, ver, ln);
*/
            memset(hbbuf, 0, sizeof(hbbuf));

            // Read rest of record
            readResult = recv(socketDescriptor, hbbuf, ln, 0);
            if (readResult <= 0)
            {
                break;
            }

            // Server returned error
            if (typ == 21)
            {
                break;
            }
            // Successful response
            else if (typ == 24 && ln > 3)
            {
                printf("%svulnerable%s to heartbleed\n", COL_RED, RESET);
                printf_xml("  <heartbleed sslversion=\"%s\" vulnerable=\"1\" />\n", printableSslMethod(sslMethod));
                close(socketDescriptor);
                return status;
            }
        }
        printf("%snot vulnerable%s to heartbleed\n", COL_GREEN, RESET);
        printf_xml("  <heartbleed sslversion=\"%s\" vulnerable=\"0\" />\n", printableSslMethod(sslMethod));

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("%sERROR: Could not connect.%s\n", COL_RED, RESET);
        status = false;
        printf("dying");
        exit(status);
    }

    return status;
}


int ssl_print_tmp_key(struct sslCheckOptions *options, SSL *s)
{
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(LIBRESSL_VERSION_NUMBER)
    EVP_PKEY *key;
    if (!SSL_get_server_tmp_key(s, &key))
        return 1;
    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        if (EVP_PKEY_bits(key) <= 768)
        {
            printf(" RSA %s%d%s bits", COL_RED, EVP_PKEY_bits(key), RESET);
        }
        else if (EVP_PKEY_bits(key) <= 1024)
        {
            printf(" RSA %s%d%s bits", COL_YELLOW, EVP_PKEY_bits(key), RESET);
        }
        else
        {
            printf(" RSA %d bits", EVP_PKEY_bits(key));
        }
        break;

    case EVP_PKEY_DH:
        if (EVP_PKEY_bits(key) <= 768)
        {
            printf(" DHE %s%d%s bits", COL_RED, EVP_PKEY_bits(key), RESET);
        }
        else if (EVP_PKEY_bits(key) <= 1024)
        {
            printf(" DHE %s%d%s bits", COL_YELLOW, EVP_PKEY_bits(key), RESET);
        }
        else
        {
            printf(" DHE %d bits", EVP_PKEY_bits(key));
        }
        printf_xml(" dhebits=\"%d\"", EVP_PKEY_bits(key));
        break;
    case EVP_PKEY_EC:
        {
            EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
            int nid;
            const char *cname;
            nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            EC_KEY_free(ec);
            cname = EC_curve_nid2nist(nid);
            if (!cname)
                cname = OBJ_nid2sn(nid);
            printf(" Curve %s DHE %d", cname, EVP_PKEY_bits(key));
            printf_xml(" curve=\"%s\" ecdhebits=\"%d\"", cname, EVP_PKEY_bits(key));
        }
	break;
    case EVP_PKEY_X25519:
      printf(" Curve %s25519%s DHE %d", COL_GREEN, RESET, EVP_PKEY_bits(key));
      printf_xml(" curve=\"25519\" ecdhebits=\"%d\"", EVP_PKEY_bits(key));
      break;
    case EVP_PKEY_X448:
      printf(" Curve %s448%s DHE %d", COL_GREEN, RESET, EVP_PKEY_bits(key));
      printf_xml(" curve=\"448\" ecdhebits=\"%d\"", EVP_PKEY_bits(key));
      break;
    default:
      printf(" %sUnknown ID (%d)%s", COL_YELLOW, EVP_PKEY_id(key), RESET);
    }
    EVP_PKEY_free(key);
    return 1;
#endif
    return 0;
}

int setCipherSuite(struct sslCheckOptions *options, const SSL_METHOD *sslMethod, const char *str)
{
  if(strlen(str)>0)
  {
    if(sslMethod==TLSv1_3_client_method())
    {
      return(SSL_CTX_set_ciphersuites(options->ctx,str));
    }
    else
    {
      return(SSL_CTX_set_cipher_list(options->ctx,str));
    }
  }
  return 0;
}

char *cipherRemove(char *str, const char *sub) {
    char *p, *q, *r;
    if ((q = r = strstr(str, sub)) != NULL) {
        size_t len = strlen(sub)+1;
        if(q != str)
        {
          q--;
          r--;
        }
        while ((r = strstr(p = r + len, sub)) != NULL) {
            while (p < r)
                *q++ = *p++;
        }
        while ((*q++ = *p++) != '\0')
            continue;
    }
    return str;
}

/* Outputs an accepted cipher to the console and XML file. */
void outputCipher(struct sslCheckOptions *options, SSL *ssl, const char *cleanSslMethod, uint32_t cipherid, const char *ciphername, int cipherbits, int cipher_accepted, unsigned int milliseconds_elapsed, char *http_code) {
  char hexCipherId[8] = {0};
  unsigned int tempInt = 0;


  printf_xml("  <cipher status=\"");
  if (cipher_accepted) {
    if (strcmp(options->cipherstring, CIPHERSUITE_LIST_ALL) && strcmp(options->cipherstring, TLSV13_CIPHERSUITES)) {
      printf_xml("accepted\"");
      printf("Accepted  ");
    }
    else {
      printf_xml("preferred\"");
      printf("%sPreferred%s ", COL_GREEN, RESET);
    }

    if (options->http == true) {
      printf("%s", http_code);
      printf_xml(" http=\"%s\"", http_code);
    }

    printf_xml(" sslversion=\"%s\"", cleanSslMethod);
    if (strcmp(cleanSslMethod, "TLSv1.0") == 0) {
      printf("%sTLSv1.0%s  ", COL_YELLOW, RESET);
    } else
      printf("%s  ", cleanSslMethod);

    if (cipherbits < 10)
      tempInt = 2;
    else if (cipherbits < 100)
      tempInt = 1;

    if (cipherbits == -1) { /* When missing ciphers are tested, and we don't have a reasonable guess. */
      printf("%s??%s bits  ", COL_YELLOW, RESET);
    } else if (cipherbits == 0) {
      printf("%s%d%s bits  ", COL_RED_BG, cipherbits, RESET);
    } else if (cipherbits >= 112) {
      printf("%s%d%s bits  ", COL_GREEN, cipherbits, RESET);
    } else if (cipherbits > 56) {
      printf("%s%d%s bits  ", COL_YELLOW, cipherbits, RESET);
    } else
      printf("%s%d%s bits  ", COL_RED, cipherbits, RESET);

    while (tempInt != 0) {
      tempInt--;
      printf(" ");
    }

    snprintf(hexCipherId, sizeof(hexCipherId) - 1, "0x%04X", cipherid);
    if (options->showCipherIds == true)
      printf("%8s ", hexCipherId);

    printf_xml(" bits=\"%d\" cipher=\"%s\" id=\"%s\"", cipherbits, ciphername, hexCipherId);
    if (strstr(ciphername, "NULL")) {
      printf("%s%-29s%s", COL_RED_BG, ciphername, RESET);
    } else if (strstr(ciphername, "ADH") || strstr(ciphername, "AECDH") || strstr(ciphername, "_anon_")) {
      printf("%s%-29s%s", COL_PURPLE, ciphername, RESET);
    } else if (strstr(ciphername, "EXP")) {
      printf("%s%-29s%s", COL_RED, ciphername, RESET);
    } else if (strstr(ciphername, "RC4") || strstr(ciphername, "DES")) {
      printf("%s%-29s%s", COL_YELLOW, ciphername, RESET);
    } else if (strstr(ciphername, "_SM4_")) { /* Developed by Chinese government */
      printf("%s%-29s%s", COL_YELLOW, ciphername, RESET);
    } else if (strstr(ciphername, "_GOSTR341112_")) { /* Developed by Russian government */
      printf("%s%-29s%s", COL_YELLOW, ciphername, RESET);
    } else if ((strstr(ciphername, "CHACHA20") || (strstr(ciphername, "GCM"))) && strstr(ciphername, "DHE")) {
      printf("%s%-29s%s", COL_GREEN, ciphername, RESET);
    } else {
      printf("%-29s", ciphername);
    }

    if ((options->cipher_details == true) && (ssl != NULL))
      ssl_print_tmp_key(options, ssl);

    // Timing
    if (options->showTimes) {
      printf(" %s%ums%s", COL_GREY, milliseconds_elapsed, RESET);
      printf_xml(" time=\"%u\"", milliseconds_elapsed);
    }

    printf("\n");
  }

  printf_xml(" />\n");
}

// Test a cipher...
int testCipher(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    char requestBuffer[256];
    char buffer[64];
    char http_code[64];
    int resultSize = 0;
    int cipherbits = -1;
    uint32_t cipherid = 0;
    const SSL_CIPHER *sslCipherPointer = NULL;
    const char *cleanSslMethod = printableSslMethod(sslMethod);
    const char *ciphername = NULL;
    struct timeval tval_start = {0};
    unsigned int milliseconds_elapsed = 0;


    memset(requestBuffer, 0, sizeof(requestBuffer));
    memset(buffer, 0, sizeof(buffer));
    memset(http_code, 0, sizeof(http_code));

    if (options->showTimes)
    {
        gettimeofday(&tval_start, NULL);
    }

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        if (setCipherSuite(options, sslMethod, options->cipherstring))
        {
            // Create SSL object...
            ssl = new_SSL(options->ctx);
            if (ssl != NULL)
            {
                // Connect socket and BIO
                cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                // Connect SSL and BIO
                SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

                // This enables TLS SNI
                SSL_set_tlsext_host_name (ssl, options->sniname);

                // Connect SSL over socket
                cipherStatus = SSL_connect(ssl);

                sslCipherPointer = SSL_get_current_cipher(ssl);
                cipherbits = SSL_CIPHER_get_bits(sslCipherPointer, NULL);

                if (cipherStatus == 0)
                {
                    return false;
                }
                else if (cipherStatus != 1)
                {
                    printf_verbose("SSL_get_error(ssl, cipherStatus) said: %d\n", SSL_get_error(ssl, cipherStatus));
                    return false;
                }

                cipherid = SSL_CIPHER_get_id(sslCipherPointer);
                cipherid = cipherid & 0x00ffffff;  // remove first byte which is the version (0x03 for TLSv1/SSLv3)

                if (cipherStatus == 1)
                {
                    if (options->http == true)
                    {
                        // Create request buffer...
                        snprintf(requestBuffer, sizeof(requestBuffer) - 1, "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n", options->host);

                        // HTTP Get...
                        SSL_write(ssl, requestBuffer, strlen(requestBuffer));
                        memset(buffer, 0, sizeof(buffer));
                        resultSize = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        if (resultSize > 9)
                        {
                            int loop = 0;
                            for (loop = 9; (loop < sizeof(buffer) - 1) && (buffer[loop] != 0) && (buffer[loop] != '\r') && (buffer[loop] != '\n'); loop++)
                            { }
                            buffer[loop] = 0;

                            strncpy(http_code, buffer + 9, sizeof(http_code) - 1);
                            loop = strlen(buffer + 9);
                            while (loop < 17)
                            {
                                loop++;
                                strncat(http_code, " ", sizeof(http_code) - 1);
                            }

                        }
                        else
                        {
                            // Output HTTP code...
                            strncpy(http_code, "                 ", sizeof(http_code) - 1);
                        }
                    }
                }

                ciphername = SSL_CIPHER_get_name(sslCipherPointer);

		// Timing
		if (options->showTimes) {
		  struct timeval tval_end = {0}, tval_elapsed = {0};

		  gettimeofday(&tval_end, NULL);
		  timersub(&tval_end, &tval_start, &tval_elapsed);
		  milliseconds_elapsed = tval_elapsed.tv_sec * 1000 + (int)tval_elapsed.tv_usec / 1000;
		}

                outputCipher(options, ssl, cleanSslMethod, cipherid, ciphername, cipherbits, (cipherStatus == 1), milliseconds_elapsed, http_code);

                // Disconnect SSL over socket
                if (cipherStatus == 1)
                {
                    const char *usedcipher = SSL_get_cipher_name(ssl);
                    if(sslMethod==TLSv1_3_client_method())
                    { // Remove cipher from TLSv1.3 list
                      cipherRemove(options->cipherstring, usedcipher);
                    }
                    else
                    {
                      strncat(options->cipherstring, ":!", 2);
                      strncat(options->cipherstring, usedcipher, strlen(usedcipher));
                    }
                    SSL_shutdown(ssl);
                }

                // Free SSL object
                FREE_SSL(ssl);
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
            }
        }
        else
        {
            status = false;
        }

        // Disconnect from host
        CLOSE(socketDescriptor);
    }

    // Could not connect
    else
        status = false;


    return status;
}

int checkCertificateProtocol(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    int status = true;
    // Setup Context Object...
    options->ctx = new_CTX(sslMethod);
    if (options->ctx != NULL)
    {
        // SSL implementation bugs/workaround
        if (options->sslbugs)
            SSL_CTX_set_options(options->ctx, SSL_OP_ALL | 0);
        else
            SSL_CTX_set_options(options->ctx, 0);

        // Load Certs if required...
        if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
            status = loadCerts(options);

        // Check the certificate
        status = checkCertificate(options, sslMethod);
    }

    // Error Creating Context Object
    else
    {
        printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        status = false;
    }
    return status;
}

// Report certificate weaknesses (key length and signing algorithm)
int checkCertificate(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    int keyBits;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    BIO *stdoutBIO = NULL;
    BIO *fileBIO = NULL;
    X509 *x509Cert = NULL;
    EVP_PKEY *publicKey = NULL;
    char certAlgorithm[80];
    X509_EXTENSION *extension = NULL;
    const X509_ALGOR *palg = NULL;
    const ASN1_OBJECT *paobj = NULL;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        options->ctx = new_CTX(sslMethod);
        if (options->ctx != NULL)
        {

            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);
                    if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
                        // TLS Virtual-hosting requires that the server present the correct
                        // certificate; to do this, the ServerNameIndication TLS extension is used.
                        // If TLS is negotiated, and OpenSSL is recent enough that it might have
                        // support, and support was enabled when OpenSSL was built, mutt supports
                        // sending the hostname we think we're connecting to, so a server can send
                        // back the correct certificate.
                        // NB: finding a server which uses this for IMAP is problematic, so this is
                        // untested.  Please report success or failure!  However, this code change
                        // has worked fine in other projects to which the contributor has added it,
                        // or HTTP usage.
                        SSL_set_tlsext_host_name (ssl, options->sniname);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus == 1)
                        {
                            // Setup BIO's
                            if (!xml_to_stdout) {
                                stdoutBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
                            }
                            if (options->xmlOutput)
                            {
                                fileBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(fileBIO, options->xmlOutput, BIO_NOCLOSE);
                            }

                            // Get Certificate...
                            printf("\n  %sSSL Certificate:%s\n", COL_BLUE, RESET);
                            printf_xml("  <certificate>\n");
                            x509Cert = SSL_get_peer_certificate(ssl);
                            if (x509Cert != NULL)
                            {
                                // Cert Serial No. - Code adapted from OpenSSL's crypto/asn1/t_x509.c
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL))
                                {
                                    BIO *bp;
                                    bp = BIO_new_fp(stdout, BIO_NOCLOSE);
                                    if (options->xmlOutput)

                                    if(NULL != bp)
                                        BIO_free(bp);
                                    // We don't free the xml_bp because it will be used in the future
                                }

                                // Signature Algo...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME))
                                {
                                    printf("Signature Algorithm: ");
                                    X509_get0_signature(NULL, &palg, x509Cert);
                                    X509_ALGOR_get0(&paobj, NULL, NULL, palg);
                                    OBJ_obj2txt(certAlgorithm, sizeof(certAlgorithm), paobj, 0);
                                    strtok(certAlgorithm, "\n");
                                    if (strstr(certAlgorithm, "md5") || strstr(certAlgorithm, "sha1"))
                                    {
                                        printf("%s%s%s\n", COL_RED, certAlgorithm, RESET);
                                    }
                                    else if (strstr(certAlgorithm, "sha512") || strstr(certAlgorithm, "sha256"))
                                    {
                                        printf("%s%s%s\n", COL_GREEN, certAlgorithm, RESET);
                                    }
                                    else
                                    {
                                        printf("%s\n", certAlgorithm);
                                    }

                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <signature-algorithm>");
                                        X509_signature_print(fileBIO, palg, NULL);
                                        printf_xml("</signature-algorithm>\n");
                                    }
                                }

                                // Public Key...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY))
                                {
                                    publicKey = X509_get_pubkey(x509Cert);
                                    if (publicKey == NULL)
                                    {
                                        printf("Public Key: Could not load\n");
                                        printf_xml("   <pk error=\"true\" />\n");
                                    }
                                    else
                                    {
										keyBits=EVP_PKEY_bits(publicKey);
                                        switch (EVP_PKEY_id(publicKey))
                                        {
                                            case EVP_PKEY_RSA:
                                                if (EVP_PKEY_get1_RSA(publicKey)!=NULL)
                                                {
                                                    if (keyBits < 2048 )
                                                    {
                                                        printf("RSA Key Strength:    %s%d%s\n", COL_RED, keyBits, RESET);
                                                    }
                                                    else if (keyBits >= 4096 )
                                                    {
                                                        printf("RSA Key Strength:    %s%d%s\n", COL_GREEN, keyBits, RESET);
                                                    }
                                                    else
                                                    {
                                                        printf("RSA Key Strength:    %d\n", keyBits);
                                                    }

                                                    printf_xml("   <pk error=\"false\" type=\"RSA\" bits=\"%d\" />\n", keyBits);
                                                }
                                                else
                                                {
                                                    printf("    RSA Public Key: NULL\n");
                                                }
                                                printf("\n");
                                                break;
                                            case EVP_PKEY_DSA:
                                                if (EVP_PKEY_get1_DSA(publicKey)!=NULL)
                                                {
                                                    // TODO - display key strength
                                                    printf_xml("   <pk error=\"false\" type=\"DSA\" />\n");
                                                    /* DSA_print(stdoutBIO, publicKey->pkey.dsa, 6); */
                                                }
                                                else
                                                {
                                                    printf("    DSA Public Key: NULL\n");
                                                }
                                                break;
                                            case EVP_PKEY_EC:
                                                if (EVP_PKEY_get1_EC_KEY(publicKey))
                                                {
                                                    // TODO - display key strength
                                                    printf_xml("   <pk error=\"false\" type=\"EC\" />\n");
                                                    /* EC_KEY_print(stdoutBIO, publicKey->pkey.ec, 6); */
                                                }
                                                else
                                                {
                                                    printf("    EC Public Key: NULL\n");
                                                }
                                                break;
                                            default:
                                                printf("    Public Key: Unknown\n");
                                                printf_xml("   <pk error=\"true\" type=\"unknown\" />\n");
                                                break;
                                        }

                                        EVP_PKEY_free(publicKey);
                                    }
                                }

                                // SSL Certificate Issuer...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER))
                                {
                                    int cnindex;
                                    X509_NAME *subj;
                                    X509_NAME_ENTRY *e;
                                    ASN1_STRING *d;
                                    const char *subject;
                                    const char *issuer;
                                    
                                    // Get SSL cert CN
                                    cnindex = -1;
                                    subj = X509_get_subject_name(x509Cert);
                                    cnindex = X509_NAME_get_index_by_NID(subj, NID_commonName, cnindex);

                                    // SSL cert doesn't have a CN, so just print whole thing
                                    if (cnindex == -1)
                                    {
                                        subject = (char *) X509_NAME_oneline(X509_get_subject_name(x509Cert), NULL, 0);
                                        printf("Subject:  %s\n", subject);
                                        printf_xml("   <subject><![CDATA[%s]]></subject>\n", subject);

                                    }
                                    else
                                    {
                                        e = X509_NAME_get_entry(subj, cnindex);
                                        d = X509_NAME_ENTRY_get_data(e);
                                        subject = (char *) ASN1_STRING_data(d);
                                        printf("Subject:  %s\n", subject);
                                        printf_xml("   <subject><![CDATA[%s]]></subject>\n", subject);
                                    }

                                    // Get certificate altnames if supported
                                    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
                                    {
                                        if (sk_X509_EXTENSION_num(X509_get0_extensions(x509Cert)) > 0)
                                        {
                                            cnindex = X509_get_ext_by_NID (x509Cert, NID_subject_alt_name, -1);
                                            if (cnindex != -1)
                                            {
                                                extension = X509v3_get_ext(X509_get0_extensions(x509Cert),cnindex);

                                                printf("Altnames: ");
                                                if (!X509V3_EXT_print(stdoutBIO, extension, X509_FLAG_COMPAT, 0))
                                                {
						    ASN1_STRING_print(stdoutBIO, X509_EXTENSION_get_data(extension));
                                                }
                                                if (options->xmlOutput)
                                                {
                                                    printf_xml("   <altnames><![CDATA[");
                                                    if (!X509V3_EXT_print(fileBIO, extension, X509_FLAG_COMPAT, 0))
						        ASN1_STRING_print(fileBIO, X509_EXTENSION_get_data(extension));
                                                }
                                                printf_xml("]]></altnames>\n");
                                                printf("\n");
                                            }
                                        }
                                    }

                                    // Get SSL cert issuer
                                    cnindex = -1;
                                    subj = X509_get_issuer_name(x509Cert);
                                    cnindex = X509_NAME_get_index_by_NID(subj, NID_commonName, cnindex);

                                    // Issuer cert doesn't have a CN, so just print whole thing
                                    if (cnindex == -1)
                                    {
                                        char *issuer = X509_NAME_oneline(X509_get_issuer_name(x509Cert), NULL, 0);
                                        printf("Issuer:   %s", issuer);
                                    printf_xml("   <issuer><![CDATA[%s]]></issuer>\n", issuer);

                                    }
                                    else
                                    {
                                        e = X509_NAME_get_entry(subj, cnindex);
                                        d = X509_NAME_ENTRY_get_data(e);
                                        issuer = (char *) ASN1_STRING_data(d);

                                        // If issuer is same as hostname we scanned or is *, flag as self-signed
                                        if (
                                                strcmp(issuer, options->host) == 0
                                                || strcmp(issuer, subject) == 0
                                                || strcmp(issuer, "*") == 0
                                           )
                                        {
                                            printf("Issuer:   %s%s%s\n", COL_RED, issuer, RESET);
                                            printf_xml("   <issuer><![CDATA[%s]]></issuer>\n", issuer);
                                            printf_xml("   <self-signed>true</self-signed>\n");

                                        }
                                        else
                                        {
                                            printf("Issuer:   %s\n", issuer);
                                            printf_xml("   <issuer><![CDATA[%s]]></issuer>\n", issuer);
                                            printf_xml("   <self-signed>false</self-signed>\n");
                                        }
                                    }
                                }

                                // Check for certificate expiration
                                time_t *ptime;
                                int timediff;
                                ptime = NULL;

                                printf("\nNot valid before: ");
                                timediff = X509_cmp_time(X509_get_notBefore(x509Cert), ptime);
                                // Certificate isn't valid yet
                                if (timediff > 0)
                                {
                                    printf("%s", COL_RED);
                                }
                                else
                                {
                                    printf("%s", COL_GREEN);
                                }
                                ASN1_TIME_print(stdoutBIO, X509_get_notBefore(x509Cert));
                                printf("%s", RESET);

                                if (options->xmlOutput) {
                                    printf_xml("   <not-valid-before>");
                                    ASN1_TIME_print(fileBIO, X509_get_notBefore(x509Cert));
                                    printf_xml("</not-valid-before>\n");
                                }

                                printf("\nNot valid after:  ");
                                timediff = X509_cmp_time(X509_get_notAfter(x509Cert), ptime);
                                // Certificate has expired
                                if (timediff < 0)
                                {
                                    printf("%s", COL_RED);
                                }
                                else
                                {
                                    printf("%s", COL_GREEN);
                                }
                                ASN1_TIME_print(stdoutBIO, X509_get_notAfter(x509Cert));
                                printf("%s", RESET);
                                if (options->xmlOutput) {
                                    printf_xml("   <not-valid-after>");
                                    ASN1_TIME_print(fileBIO, X509_get_notAfter(x509Cert));
                                    printf_xml("</not-valid-after>\n");
                                    if (timediff < 0)
                                    {
                                        printf_xml("   <expired>true</expired>\n");
                                    }
                                    else
                                    {
                                        printf_xml("   <expired>false</expired>\n");
                                    }
                                }
                                printf("\n");

                                // Free X509 Certificate...
                                X509_free(x509Cert);
                                // This is abusing status a bit, but means that we'll only get the cert once
                                status = false;
                            }

                            else {
                                printf("    Unable to parse certificate\n");
                            }

                            printf_xml("  </certificate>\n");

                            // Free BIO
                            BIO_free(stdoutBIO);
                            if (options->xmlOutput)
                                BIO_free(fileBIO);

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }
                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf("%s    ERROR: Could not create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could not set cipher.%s\n", COL_RED, RESET);
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}

// Request a stapled OCSP request from the server.
int ocspRequest(struct sslCheckOptions *options)
{
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    BIO *stdoutBIO = NULL;
    BIO *fileBIO = NULL;
    const SSL_METHOD *sslMethod = NULL;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        if( options->sslVersion == ssl_v2 || options->sslVersion == ssl_v3) {
            printf_verbose("sslMethod = SSLv23_method()");
            sslMethod = SSLv23_method();
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if( options->sslVersion == tls_v11) {
            printf_verbose("sslMethod = TLSv1_1_method()");
            sslMethod = TLSv1_1_method();
        }
        else if( options->sslVersion == tls_v12) {
            printf_verbose("sslMethod = TLSv1_2_method()");
            sslMethod = TLSv1_2_method();
        }
#endif
        else if( options->sslVersion == tls_v13) {
            printf_verbose("sslMethod = TLSv1_3_method()");
            sslMethod = TLSv1_3_method();
        }
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specify TLS version\n");
            sslMethod = TLSv1_method();
        }
        options->ctx = new_CTX(sslMethod);
        if (options->ctx != NULL)
        {

            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);
                    if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
                        // TLS Virtual-hosting requires that the server present the correct
                        // certificate; to do this, the ServerNameIndication TLS extension is used.
                        // If TLS is negotiated, and OpenSSL is recent enough that it might have
                        // support, and support was enabled when OpenSSL was built, mutt supports
                        // sending the hostname we think we're connecting to, so a server can send
                        // back the correct certificate.
                        // NB: finding a server which uses this for IMAP is problematic, so this is
                        // untested.  Please report success or failure!  However, this code change
                        // has worked fine in other projects to which the contributor has added it,
                        // or HTTP usage.
                        SSL_set_tlsext_host_name (ssl, options->sniname);
#endif
						SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
						SSL_CTX_set_tlsext_status_cb(options->ctx, ocsp_resp_cb);
                        
						// Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus == 1)
                        {
                            // Setup BIO's
                            if (!xml_to_stdout) {
                                stdoutBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
                            }
                            if (options->xmlOutput)
                            {
                                fileBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(fileBIO, options->xmlOutput, BIO_NOCLOSE);
                            }

                            // Free BIO
                            BIO_free(stdoutBIO);
                            if (options->xmlOutput)
                                BIO_free(fileBIO);

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }
                        else
                        {
                            printf("\n%sFailed to connect to get OCSP status.%s\n", COL_RED, RESET);
                            printf("Most likely cause is server not supporting %s, try manually specifying version\n", printableSslMethod(sslMethod));
                        }
                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf("%s    ERROR: Could not create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could not set cipher.%s\n", COL_RED, RESET);
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}

static int ocsp_resp_cb(SSL *s, void *unused) {
    const unsigned char *p = NULL;
    int len = 0;
    OCSP_RESPONSE *o = NULL;
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    int i = 0;
    long l = 0;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = NULL;


    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    if (p == NULL) {
        BIO_puts(bp, "No OCSP response recieved.\n\n");
        goto err;
    }

    o = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (o == NULL) {
        BIO_puts(bp, "OCSP response parse error\n");
        BIO_dump_indent(bp, (char *)p, len, 4);
        goto err;
    }

    rb = o->responseBytes;
    l = ASN1_ENUMERATED_get(o->responseStatus);
    if (BIO_printf(bp, "OCSP Response Status: %s (0x%lx)\n",
                   OCSP_response_status_str(l), l) <= 0)
        goto err;
    if (rb == NULL)
        return 1;
    if (BIO_puts(bp, "Response Type: ") <= 0)
        goto err;
    if (i2a_ASN1_OBJECT(bp, rb->responseType) <= 0)
        goto err;
    if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
        BIO_puts(bp, " (unknown response type)\n");
        return 1;
    }

    if ((br = OCSP_response_get1_basic(o)) == NULL)
        goto err;
    rd = &br->tbsResponseData;
    l = ASN1_INTEGER_get(rd->version);
    if (BIO_printf(bp, "\nVersion: %lu (0x%lx)\n", l + 1, l) <= 0)
        goto err;
    if (BIO_puts(bp, "Responder Id: ") <= 0)
        goto err;

    rid = &rd->responderId;
    switch (rid->type) {
    case V_OCSP_RESPID_NAME:
        X509_NAME_print_ex(bp, rid->value.byName, 0, XN_FLAG_ONELINE);
        break;
    case V_OCSP_RESPID_KEY:
        i2a_ASN1_STRING(bp, rid->value.byKey, 0);
        break;
    }

    if (BIO_printf(bp, "\nProduced At: ") <= 0)
        goto err;
    if (!ASN1_GENERALIZEDTIME_print(bp, rd->producedAt))
        goto err;
    if (BIO_printf(bp, "\nResponses:\n") <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
        if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
            continue;
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        cid = single->certId;
        if (ocsp_certid_print(bp, cid, 4) <= 0)
            goto err;
        cst = single->certStatus;
        if (BIO_puts(bp, "    Cert Status: ") <= 0)
            goto err;
        if (cst->type == V_OCSP_CERTSTATUS_GOOD) {
          if (BIO_printf(bp, "%s%s%s", COL_GREEN, OCSP_cert_status_str(cst->type), RESET) <= 0)
                goto err;
	} else if (cst->type == V_OCSP_CERTSTATUS_REVOKED) {
            if (BIO_printf(bp, "%s%s%s", COL_RED, OCSP_cert_status_str(cst->type), RESET) <= 0)
                goto err;
            rev = cst->value.revoked;
            if (BIO_printf(bp, "\n    Revocation Time: ") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp, rev->revocationTime))
                goto err;
            if (rev->revocationReason) {
                l = ASN1_ENUMERATED_get(rev->revocationReason);
                if (BIO_printf(bp,
                               "\n    Revocation Reason: %s (0x%lx)",
                               OCSP_crl_reason_str(l), l) <= 0)
                    goto err;
            }
        } else {
	  if (BIO_printf(bp, "%s%s%s", COL_YELLOW, OCSP_cert_status_str(cst->type), RESET) <= 0)
	    goto err;
	}
        if (BIO_printf(bp, "\n    This Update: ") <= 0)
            goto err;
        if (!ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate))
            goto err;
        if (single->nextUpdate) {
            if (BIO_printf(bp, "\n    Next Update: ") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp, single->nextUpdate))
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;

        if (!X509V3_extensions_print(bp,
                                     "Response Single Extensions",
                                     single->singleExtensions, 0, 4))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    /*
    if (!X509V3_extensions_print(bp, "Response Extensions",
                                 rd->responseExtensions, 0, 4))
        goto err;
    if (X509_signature_print(bp, &br->signatureAlgorithm, br->signature) <= 0)
        goto err;

    for (i = 0; i < sk_X509_num(br->certs); i++) {
        X509_print(bp, sk_X509_value(br->certs, i));
        PEM_write_bio_X509(bp, sk_X509_value(br->certs, i));
    }
    */
 err:
  if (o != NULL) { OCSP_RESPONSE_free(o); o = NULL; }
  BIO_free(bp);
  return 1;
}

int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent)
{
    BIO_printf(bp, "%*sCertificate ID:\n", indent, "");
    indent += 2;
    BIO_printf(bp, "%*sHash Algorithm: ", indent, "");
    i2a_ASN1_OBJECT(bp, a->hashAlgorithm.algorithm);
    BIO_printf(bp, "\n%*sIssuer Name Hash: ", indent, "");
    i2a_ASN1_STRING(bp, &a->issuerNameHash, 0);
    BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
    i2a_ASN1_STRING(bp, &a->issuerKeyHash, 0);
    BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
    i2a_ASN1_INTEGER(bp, &a->serialNumber);
    BIO_printf(bp, "\n");
    return 1;
}

// Print out the full certificate
int showCertificate(struct sslCheckOptions *options)
{
    // Variables...
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    BIO *stdoutBIO = NULL;
    BIO *fileBIO = NULL;
    X509 *x509Cert = NULL;
    EVP_PKEY *publicKey = NULL;
    const SSL_METHOD *sslMethod = NULL;
    ASN1_OBJECT *asn1Object = NULL;
    X509_EXTENSION *extension = NULL;
    char buffer[1024];
    long tempLong = 0;
    int tempInt = 0;
    int tempInt2 = 0;
    long verifyError = 0;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {

        // Setup Context Object...
        if( options->sslVersion == ssl_v2 || options->sslVersion == ssl_v3) {
            printf_verbose("sslMethod = SSLv23_method()");
            sslMethod = SSLv23_method();
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if( options->sslVersion == tls_v11) {
            printf_verbose("sslMethod = TLSv1_1_method()");
            sslMethod = TLSv1_1_method();
        }
        else if( options->sslVersion == tls_v12) {
            printf_verbose("sslMethod = TLSv1_2_method()");
            sslMethod = TLSv1_2_method();
        }
        else if( options->sslVersion == tls_v13) {
            printf_verbose("sslMethod = TLSv1_3_method()");
            sslMethod = TLSv1_3_method();
        }
#endif
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specificy TLS version\n");
            sslMethod = TLSv1_method();
        }
        options->ctx = new_CTX(sslMethod);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);
                    if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
                        // TLS Virtual-hosting requires that the server present the correct
                        // certificate; to do this, the ServerNameIndication TLS extension is used.
                        // If TLS is negotiated, and OpenSSL is recent enough that it might have
                        // support, and support was enabled when OpenSSL was built, mutt supports
                        // sending the hostname we think we're connecting to, so a server can send
                        // back the correct certificate.
                        // NB: finding a server which uses this for IMAP is problematic, so this is
                        // untested.  Please report success or failure!  However, this code change
                        // has worked fine in other projects to which the contributor has added it,
                        // or HTTP usage.
                        SSL_set_tlsext_host_name (ssl, options->sniname);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus == 1)
                        {
                            // Setup BIO's
                            if (!xml_to_stdout) {
                                stdoutBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
                            }
                            if (options->xmlOutput)
                            {
                                fileBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(fileBIO, options->xmlOutput, BIO_NOCLOSE);
                            }

                            // Get Certificate...
                            printf("\n  %sSSL Certificate:%s\n", COL_BLUE, RESET);
                            printf_xml("  <certificate>\n");
                            x509Cert = SSL_get_peer_certificate(ssl);
                            if (x509Cert != NULL)
                            {

                                // Print a base64 blob version of the cert
                                printf("    Certificate blob:\n");
                                PEM_write_bio_X509(stdoutBIO,x509Cert);
                                if (options->xmlOutput)
                                {
                                    printf_xml("   <certificate-blob>\n");
                                    PEM_write_bio_X509(fileBIO,x509Cert);
                                    printf_xml("   </certificate-blob>\n");
                                }

                                //SSL_set_verify(ssl, SSL_VERIFY_NONE|SSL_VERIFY_CLIENT_ONCE, NULL);

				//X509_print_ex(bp, x509Cert, 0, 0);

                                // Cert Version
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VERSION))
                                {
                                    tempLong = X509_get_version(x509Cert);
                                    printf("    Version: %lu\n", tempLong);
                                    printf_xml("   <version>%lu</version>\n", tempLong);
                                }

                                // Cert Serial No. - Code adapted from OpenSSL's crypto/asn1/t_x509.c
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL))
                                {
                                    ASN1_INTEGER *bs;
                                    BIO *bp;
                                    BIO *xml_bp;
                                    bp = BIO_new_fp(stdout, BIO_NOCLOSE);
                                    if (options->xmlOutput)
                                        xml_bp = BIO_new_fp(options->xmlOutput, BIO_NOCLOSE);
                                    long l;
                                    int i;
                                    const char *neg;
                                    bs=X509_get_serialNumber(x509Cert);

                                    if (BIO_write(bp,"    Serial Number:",18) <= 0)
                                        return(1);

                                    if (bs->length <= 4)
                                    {
                                        l=ASN1_INTEGER_get(bs);
                                        if (l < 0)
                                        {
                                            l= -l;
                                            neg="-";
                                        }
                                        else
                                            neg="";
                                        if (BIO_printf(bp," %s%lu (%s0x%lx)\n",neg,l,neg,l) <= 0)
                                            return(1);
                                        if (options->xmlOutput)
                                            if (BIO_printf(xml_bp,"   <serial>%s%lu (%s0x%lx)</serial>\n",neg,l,neg,l) <= 0)
                                                return(1);
                                    }
                                    else
                                    {
                                        neg=(bs->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
                                        if (BIO_printf(bp,"%1s%s","",neg) <= 0)
                                            return(1);

                                        if (options->xmlOutput)
                                            if (BIO_printf(xml_bp,"   <serial>") <= 0)
                                                return(1);

                                        for (i=0; i<bs->length; i++)
                                        {
                                            if (BIO_printf(bp,"%02x%c",bs->data[i],
                                                        ((i+1 == bs->length)?'\n':':')) <= 0)
                                                return(1);
                                            if (options->xmlOutput) {
                                                if (i+1 == bs->length)
                                                {
                                                    if (BIO_printf(xml_bp,"%02x",bs->data[i]) <= 0)
                                                        return(1);
                                                }
                                                else
                                                {
                                                    if (BIO_printf(xml_bp,"%02x%c",bs->data[i], ':') <= 0)
                                                        return(1);
                                                }
                                            }
                                        }

                                        if (options->xmlOutput)
                                            if (BIO_printf(xml_bp,"</serial>\n") <= 0)
                                                return(1);

                                    }
                                    if(NULL != bp)
                                        BIO_free(bp);
                                    // We don't free the xml_bp because it will be used in the future
                                }

                                // Signature Algo...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME))
                                {
				    X509_signature_print(stdoutBIO, X509_get0_tbs_sigalg(x509Cert), NULL);
/*                                    printf("    Signature Algorithm: ");
                                    i2a_ASN1_OBJECT(stdoutBIO, X509_get0_tbs_sigalg(x509Cert));
                                    printf("\n");
*/
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <signature-algorithm>");
                                        X509_signature_print(fileBIO, X509_get0_tbs_sigalg(x509Cert), NULL);
                                        printf_xml("</signature-algorithm>\n");
                                    }
                                }

                                // SSL Certificate Issuer...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER))
                                {
                                    X509_NAME_oneline(X509_get_issuer_name(x509Cert), buffer, sizeof(buffer) - 1);
                                    printf("    Issuer: %s\n", buffer);
                                    printf_xml("   <issuer><![CDATA[%s]]></issuer>\n", buffer);
                                }

                                // Validity...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY))
                                {
                                    printf("    Not valid before: ");
                                    ASN1_TIME_print(stdoutBIO, X509_get_notBefore(x509Cert));
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <not-valid-before>");
                                        ASN1_TIME_print(fileBIO, X509_get_notBefore(x509Cert));
                                        printf_xml("</not-valid-before>\n");
                                    }
                                    printf("\n    Not valid after: ");
                                    ASN1_TIME_print(stdoutBIO, X509_get_notAfter(x509Cert));
                                    printf("\n");
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <not-valid-after>");
                                        ASN1_TIME_print(fileBIO, X509_get_notAfter(x509Cert));
                                        printf_xml("</not-valid-after>\n");
                                    }
                                }

                                // SSL Certificate Subject...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SUBJECT))
                                {
                                    X509_NAME_oneline(X509_get_subject_name(x509Cert), buffer, sizeof(buffer) - 1);
                                    printf("    Subject: %s\n", buffer);
                                    printf_xml("   <subject><![CDATA[%s]]></subject>\n", buffer);
                                }

                                // Public Key Algo...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY))
                                {
                                    printf("    Public Key Algorithm: ");
                                   ASN1_OBJECT *xpoid = NULL;
                                    i2a_ASN1_OBJECT(stdoutBIO, xpoid);
                                    printf("\n");
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <pk-algorithm>");
                                        i2a_ASN1_OBJECT(fileBIO, xpoid);
                                        printf_xml("</pk-algorithm>\n");
                                    }

                                    // Public Key...
                                    publicKey = X509_get_pubkey(x509Cert);
                                    if (publicKey == NULL)
                                    {
                                        printf("    Public Key: Could not load\n");
                                        printf_xml("   <pk error=\"true\" />\n");
                                    }
                                    else
                                    {
                                        switch (EVP_PKEY_id(publicKey))
                                        {
                                            case EVP_PKEY_RSA:
                                                if (EVP_PKEY_get1_RSA(publicKey)!=NULL)
                                                {
                                                    printf("    RSA Public Key: (%d bit)\n", EVP_PKEY_bits(publicKey));
                                                    printf_xml("   <pk error=\"false\" type=\"RSA\" bits=\"%d\">\n", EVP_PKEY_bits(publicKey));
                                                    RSA_print(stdoutBIO, EVP_PKEY_get1_RSA(publicKey), 6);
                                                    if (options->xmlOutput)
                                                    {
                                                        RSA_print(fileBIO, EVP_PKEY_get1_RSA(publicKey), 4);
                                                        printf_xml("   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    RSA Public Key: NULL\n");
                                                }
                                                break;
                                            case EVP_PKEY_DSA:
                                                if (EVP_PKEY_get1_DSA(publicKey)!=NULL)
                                                {
                                                    printf("    DSA Public Key:\n");
                                                    printf_xml("   <pk error=\"false\" type=\"DSA\">\n");
                                                    DSA_print(stdoutBIO, EVP_PKEY_get1_DSA(publicKey), 6);
                                                    if (options->xmlOutput)
                                                    {
                                                        DSA_print(fileBIO, EVP_PKEY_get1_DSA(publicKey), 4);
                                                        printf_xml("   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    DSA Public Key: NULL\n");
                                                }
                                                break;
                                            case EVP_PKEY_EC:
                                                if (EVP_PKEY_get1_EC_KEY(publicKey)!=NULL)
                                                {
                                                    printf("    EC Public Key:\n");
                                                    printf_xml("   <pk error=\"false\" type=\"EC\">\n");
                                                    EC_KEY_print(stdoutBIO, EVP_PKEY_get1_EC_KEY(publicKey), 6);
                                                    if (options->xmlOutput)
                                                    {
                                                        EC_KEY_print(fileBIO, EVP_PKEY_get1_EC_KEY(publicKey), 4);
                                                        printf_xml("   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    EC Public Key: NULL\n");
                                                }
                                                break;
                                            default:
                                                printf("    Public Key: Unknown\n");
                                                printf_xml("   <pk error=\"true\" type=\"unknown\" />\n");
                                                break;
                                        }

                                        EVP_PKEY_free(publicKey);
                                    }
                                }

                                // X509 v3...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
                                {
                                    if (sk_X509_EXTENSION_num(X509_get0_extensions(x509Cert)) > 0)
                                    {
                                        printf("    X509v3 Extensions:\n");
                                        printf_xml("   <X509v3-Extensions>\n");
                                        for (tempInt = 0; tempInt < sk_X509_EXTENSION_num(X509_get0_extensions(x509Cert)); tempInt++)
                                        {
                                            // Get Extension...
                                            extension = sk_X509_EXTENSION_value(X509_get0_extensions(x509Cert), tempInt);

                                            // Print Extension name...
                                            printf("      ");
                                            asn1Object = X509_EXTENSION_get_object(extension);
                                            i2a_ASN1_OBJECT(stdoutBIO, asn1Object);
                                            tempInt2 = X509_EXTENSION_get_critical(extension);
                                            BIO_printf(stdoutBIO, ": %s\n", tempInt2 ? "critical" : "");
                                            if (options->xmlOutput)
                                            {
                                                printf_xml("    <extension name=\"");
                                                i2a_ASN1_OBJECT(fileBIO, asn1Object);
                                                BIO_printf(fileBIO, "\"%s><![CDATA[", tempInt2 ? " level=\"critical\"" : "");
                                            }

                                            // Print Extension value...
                                            if (!X509V3_EXT_print(stdoutBIO, extension, X509_FLAG_COMPAT, 8))
                                            {
                                                printf("        ");
						ASN1_STRING_print(stdoutBIO, X509_EXTENSION_get_data(extension));
                                            }
                                            if (options->xmlOutput)
                                            {
                                                if (!X509V3_EXT_print(fileBIO, extension, X509_FLAG_COMPAT, 0))
						    ASN1_STRING_print(stdoutBIO, X509_EXTENSION_get_data(extension));
                                                printf_xml("]]></extension>\n");
                                            }
                                            printf("\n");
                                        }
                                        printf_xml("   </X509v3-Extensions>\n");
                                    }
                                }

                                // Verify Certificate...
                                printf("  Verify Certificate:\n");
                                verifyError = SSL_get_verify_result(ssl);
                                if (verifyError == X509_V_OK)
                                {
                                    printf("    Certificate passed verification\n");
                                }
                                else
                                {
                                    printf("    %s\n", X509_verify_cert_error_string(verifyError));
                                }

                                // Free X509 Certificate...
                                X509_free(x509Cert);
                            }

                            else {
                                printf("    Unable to parse certificate\n");
                            }

                            printf_xml("  </certificate>\n");

                            // Free BIO
                            BIO_free(stdoutBIO);
                            if (options->xmlOutput)
                                BIO_free(fileBIO);

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}


// Print out the list of trusted CAs
int showTrustedCAs(struct sslCheckOptions *options)
{
    // Variables...
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    BIO *stdoutBIO = NULL;
    BIO *fileBIO = NULL;
    const SSL_METHOD *sslMethod = NULL;
    char buffer[1024];
    int tempInt = 0;
    STACK_OF(X509_NAME) *sk2;
    X509_NAME *xn;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {

        // Setup Context Object...
        if( options->sslVersion == ssl_v2 || options->sslVersion == ssl_v3) {
            printf_verbose("sslMethod = SSLv23_method()");
            sslMethod = SSLv23_method();
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if( options->sslVersion == tls_v11) {
            printf_verbose("sslMethod = TLSv1_1_method()");
            sslMethod = TLSv1_1_method();
        }
        else if( options->sslVersion == tls_v12) {
            printf_verbose("sslMethod = TLSv1_2_method()");
            sslMethod = TLSv1_2_method();
        }
        else if( options->sslVersion == tls_v13) {
            printf_verbose("sslMethod = TLSv1_3_method()");
            sslMethod = TLSv1_3_method();
        }
#endif
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specificy TLS version\n");
            sslMethod = TLSv1_method();
        }
        options->ctx = new_CTX(sslMethod);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL) != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = new_SSL(options->ctx);
                    if (ssl != NULL)
                    {
                        // Connect socket and BIO
                        cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                        // Connect SSL and BIO
                        SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                        // Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
                        // TLS Virtual-hosting requires that the server present the correct
                        // certificate; to do this, the ServerNameIndication TLS extension is used.
                        // If TLS is negotiated, and OpenSSL is recent enough that it might have
                        // support, and support was enabled when OpenSSL was built, mutt supports
                        // sending the hostname we think we're connecting to, so a server can send
                        // back the correct certificate.
                        // NB: finding a server which uses this for IMAP is problematic, so this is
                        // untested.  Please report success or failure!  However, this code change
                        // has worked fine in other projects to which the contributor has added it,
                        // or HTTP usage.
                        SSL_set_tlsext_host_name (ssl, options->sniname);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus >= 0)
                        {
                            // Setup BIO's
                            if (!xml_to_stdout) {
                                stdoutBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
                            }
                            if (options->xmlOutput)
                            {
                                fileBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(fileBIO, options->xmlOutput, BIO_NOCLOSE);
                            }

                            printf("\n  %sAcceptable client certificate CA names:%s\n", COL_BLUE, RESET);
                            sk2=SSL_get_client_CA_list(ssl);
                            if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0))
                            {
                                for (tempInt=0; tempInt<sk_X509_NAME_num(sk2); tempInt++)
                                {
                                    xn=sk_X509_NAME_value(sk2,tempInt);
                                    X509_NAME_oneline(xn,buffer,sizeof(buffer));
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("  <ca>\n");
                                        BIO_printf(fileBIO, "%s", buffer);
                                        BIO_printf(fileBIO, "\n");
                                        printf_xml("  </ca>\n");
                                    }
                                    printf("%s", buffer);
                                    printf("\n");
                                }
                            }
                            else
                            {
                                printf("%sNone defined (any)%s\n", COL_YELLOW, RESET);
                            }

                            // Free BIO
                            BIO_free(stdoutBIO);
                            if (options->xmlOutput)
                                BIO_free(fileBIO);

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}

int testConnection(struct sslCheckOptions *options)
{
    // Variables...
    int socketDescriptor = 0;
    struct addrinfo *ai;
    struct addrinfo *addrinfoResult = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    // Resolve Host Name
    if (options->ipv4 && options->ipv6)
    {
       // If both IPv4 and IPv6 are enabled, we restrict nothing in the
       // results (i.e.: we'll accept either type of address).
    }
    else if (options->ipv4)  // Only IPv4 is acceptable...
    {
        hints.ai_family = AF_INET;
    }
    else if (options->ipv6)  // Only IPv6 is acceptable...
    {
        hints.ai_family = AF_INET6;
        printf("Trying %sIPv6%s lookup\n\n", COL_GREEN, RESET);
    }

    // Perform the actual lookup.
    if (getaddrinfo(options->host, NULL, &hints, &addrinfoResult) != 0)
    {
        printf("%sERROR: Could not resolve hostname %s.%s\n", COL_RED, options->host, RESET);
        return false;
    }

    // Configure Server Address and Port
    for (ai = addrinfoResult; ai != NULL; ai = ai->ai_next)
    {
        if (ai->ai_family == AF_INET6)
        {
            options->serverAddress6.sin6_family = ai->ai_family;
            memcpy((char *) &options->serverAddress6, ai->ai_addr, ai->ai_addrlen);
            options->serverAddress6.sin6_port = htons(options->port);
            inet_ntop(ai->ai_family, &options->serverAddress6.sin6_addr, options->addrstr, sizeof(options->addrstr));
        }
        else
        {
            options->serverAddress.sin_family = ai->ai_family;
            memcpy((char *) &options->serverAddress, ai->ai_addr, ai->ai_addrlen);
            options->serverAddress.sin_port = htons(options->port);
            inet_ntop(ai->ai_family, &options->serverAddress.sin_addr, options->addrstr, sizeof(options->addrstr));
        }
        options->h_addrtype = ai->ai_family;

        socketDescriptor = tcpConnect(options);
        if (socketDescriptor != 0)
        {
            close(socketDescriptor);
            freeaddrinfo(addrinfoResult); addrinfoResult = NULL;
            printf("%sConnected to %s%s\n\n", COL_GREEN, options->addrstr, RESET);
            return true;
        }
    }
    freeaddrinfo(addrinfoResult); addrinfoResult = NULL;
    return false;
}

int testProtocolCiphers(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    int status;
    status = true;

    if (sslMethod == TLSv1_3_client_method())
      strncpy(options->cipherstring, TLSV13_CIPHERSUITES, sizeof(options->cipherstring));
    else
      strncpy(options->cipherstring, CIPHERSUITE_LIST_ALL, sizeof(options->cipherstring));

    // Loop until the server won't accept any more ciphers
    while (status == true)
    {
        // Setup Context Object...
        options->ctx = new_CTX(sslMethod);
        if (options->ctx != NULL)
        {
            // SSL implementation bugs/workaround
            if (options->sslbugs)
                SSL_CTX_set_options(options->ctx, SSL_OP_ALL | 0);
            else
                SSL_CTX_set_options(options->ctx, 0);

            // minimal protocol version 
            if (sslMethod == TLSv1_3_client_method())
                SSL_CTX_set_min_proto_version(options->ctx, TLS1_3_VERSION);

            // Load Certs if required...
            if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                status = loadCerts(options);

            // Test the cipher
            if (status == true)
                status = testCipher(options, sslMethod);

            // Free CTX Object
            FREE_CTX(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
            return false;
        }
    }

    /* Test the missing ciphersuites. */
    if (sslMethod != TLSv1_3_client_method()) {
      int version = 0;
      if (sslMethod == TLSv1_1_client_method())
	version = 1;
      else if (sslMethod == TLSv1_2_client_method())
	version = 2;

      testMissingCiphers(options, version);
    }
    return true;
}

// Test a single host and port for ciphers...
int testHost(struct sslCheckOptions *options)
{
    // Variables...
    struct sslCipher *sslCipherPointer = NULL;
    int status = true;
    
    // XML Output...
    printf_xml(" <ssltest host=\"%s\" sniname=\"%s\" port=\"%d\">\n", options->host, options->sniname, options->port);

    // Verbose warning about STARTTLS and SSLv3
    if (options->sslVersion == ssl_v3 || options->sslVersion == ssl_all)
    {
        printf_verbose("Some servers will fail to response to SSLv3 ciphers over STARTTLS\nIf your scan hangs, try using the --tlsall option\n\n");
    }

    printf("Testing SSL server %s%s%s on port %s%d%s using SNI name %s%s%s\n\n", COL_GREEN, options->host, RESET,
            COL_GREEN, options->port, RESET, COL_GREEN, options->sniname, RESET);

    if (options->showClientCiphers == true)
    {
        // Build a list of ciphers...
        switch (options->sslVersion)
        {
            case ssl_all:
                populateCipherList(options, TLSv1_3_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                populateCipherList(options, TLSv1_2_client_method());
                populateCipherList(options, TLSv1_1_client_method());
#endif
                populateCipherList(options, TLSv1_client_method());
                break;
            case tls_all:
                populateCipherList(options, TLSv1_3_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                populateCipherList(options, TLSv1_2_client_method());
                populateCipherList(options, TLSv1_1_client_method());
#endif
                populateCipherList(options, TLSv1_client_method());
                break;
            case tls_v13:
                populateCipherList(options, TLSv1_3_client_method());
                break;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            case tls_v12:
                populateCipherList(options, TLSv1_2_client_method());
                break;
            case tls_v11:
                populateCipherList(options, TLSv1_1_client_method());
                break;
#endif
            case tls_v10:
                populateCipherList(options, TLSv1_client_method());
                break;
        }
        printf("\n  %sOpenSSL-Supported Client Cipher(s):%s\n", COL_BLUE, RESET);
        sslCipherPointer = options->ciphers;
        while ((sslCipherPointer != 0) && (status == true))
        {
            printf("    %s\n",sslCipherPointer->name);
            printf_xml("  <client-cipher cipher=\"%s\" provider=\"openssl\" />\n", sslCipherPointer->name);

            sslCipherPointer = sslCipherPointer->next;
        }
        printf("\n  %sDirectly-Supported Client Cipher(s):%s\n", COL_BLUE, RESET);
        for (int i = 0; i < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); i++) {
            printf("    %s\n", missing_ciphersuites[i].protocol_name);
            printf_xml("  <client-cipher cipher=\"%s\" provider=\"sslscan\" />\n", missing_ciphersuites[i].protocol_name);
        }
        printf("\n");
    }
    if (status == true && options->fallback )
    {
        printf("  %sTLS Fallback SCSV:%s\n", COL_BLUE, RESET);
#ifdef SSL_MODE_SEND_FALLBACK_SCSV
        testFallback(options, NULL);
#else
        printf("%sOpenSSL version does not support SCSV fallback%s\n\n", COL_RED, RESET);

#endif
    }
    if (status == true && options->reneg )
    {
        printf("  %sTLS renegotiation:%s\n", COL_BLUE, RESET);
        testRenegotiation(options, TLSv1_client_method());
    }

    if (status == true && options->compression )
    {
        printf("  %sTLS Compression:%s\n", COL_BLUE, RESET);
        testCompression(options, TLSv1_client_method());
    }

    if (status == true && options->heartbleed )
    {
        printf("  %sHeartbleed:%s\n", COL_BLUE, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v13)
        {
            printf("TLS 1.3 ");
            status = testHeartbleed(options, TLSv1_3_client_method());
        }
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v12)
        {
            printf("TLS 1.2 ");
            status = testHeartbleed(options, TLSv1_2_client_method());
        }
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v11)
        {
            printf("TLS 1.1 ");
            status = testHeartbleed(options, TLSv1_1_client_method());
        }
#endif
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v10)
        {
            printf("TLS 1.0 ");
            status = testHeartbleed(options, TLSv1_client_method());
        }
        if( options->sslVersion == ssl_v2 || options->sslVersion == ssl_v3)
        {
            printf("%sAll TLS protocols disabled, cannot check for heartbleed.\n%s", COL_RED, RESET);
        }
            printf("\n");
    }

	// Print OCSP response
	if (status == true && options->ocspStatus == true)
	{
		printf("  %sOCSP Stapling Request:%s\n", COL_BLUE, RESET);
#if OPENSSL_VERSION_NUMBER > 0x00908000L && !defined(OPENSSL_NO_TLSEXT)
		status = ocspRequest(options);
#endif
	}

    if (options->ciphersuites)
    {
        printf("  %sSSL Protocols:%s\n", COL_BLUE, RESET);

        // Check if SSLv2 is enabled.
        if ((options->sslVersion == ssl_all) || (options->sslVersion == ssl_v2)) {
            if (runSSLv2Test(options)) {
                printf("SSLv2 is %senabled%s\n", COL_RED, RESET);
                printf_xml("  <ssl protocol_version=\"2\" enabled=\"1\" />\n");
            } else {
                printf("SSLv2 is %snot enabled%s\n", COL_GREEN, RESET);
                printf_xml("  <ssl protocol_version=\"2\" enabled=\"0\" />\n");
            }
        }

        // Check if SSLv3 is enabled.
        if ((options->sslVersion == ssl_all) || (options->sslVersion == ssl_v3)) {
            if (runSSLv3Test(options)) {
                printf("SSLv3 is %senabled%s\n", COL_RED, RESET);
                printf_xml("  <ssl protocol_version=\"3\" enabled=\"1\" />\n");
            } else {
                printf("SSLv3 is %snot enabled%s\n", COL_GREEN, RESET);
                printf_xml("  <ssl protocol_version=\"3\" enabled=\"0\" />\n");
            }
        }
        printf("\n");

        // Test supported ciphers...
        printf("  %sSupported Server Cipher(s):%s\n", COL_BLUE, RESET);
        switch (options->sslVersion)
        {
            case ssl_all:
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_3_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_2_client_method());
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_1_client_method());
#endif
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_client_method());
                break;
            case tls_all:
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_3_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_2_client_method());
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_1_client_method());
#endif
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_client_method());
                break;
            case tls_v10:
                status = testProtocolCiphers(options, TLSv1_client_method());
                break;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            case tls_v11:
                status = testProtocolCiphers(options, TLSv1_1_client_method());
                break;
            case tls_v12:
                status = testProtocolCiphers(options, TLSv1_2_client_method());
                break;
            case tls_v13:
                status = testProtocolCiphers(options, TLSv1_3_client_method());
                break;
#endif
        }
    }

    // Enumerate key exchange groups.
    if (options->groups)
	testSupportedGroups(options);

    // Print certificate
    if (status == true && options->showCertificate == true)
    {
        status = showCertificate(options);
    }

    // Show weak certificate signing algorithm or key strength
    if (status == true && options->checkCertificate == true)
    {
        if (status != false)
            status = checkCertificateProtocol(options, TLSv1_3_client_method());
        if (status != false)
            status = checkCertificateProtocol(options, TLSv1_2_client_method());
        if (status != false)
            status = checkCertificateProtocol(options, TLSv1_1_client_method());
        if (status != false)
            status = checkCertificateProtocol(options, TLSv1_client_method());
        if (status != false)
            printf("Certificate information cannot be enumerated through SSLv2 nor SSLv3.\n\n");
    }

    // Print client auth trusted CAs
    if (options->showTrustedCAs == true)
    {
        status = showTrustedCAs(options);
    }

    // XML Output...
    printf_xml(" </ssltest>\n");

    // Return status...
    return status;
}


int main(int argc, char *argv[])
{
    // Variables...
    struct sslCheckOptions options;
    struct sslCipher *sslCipherPointer;
    int argLoop;
    int tempInt;
    int maxSize;
    int xmlArg;
    int mode = mode_help;
    int msec;
    FILE *targetsFile;
    char line[1024];
#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    HANDLE hConsole;
    DWORD consoleMode;
#endif

    // Init...
    memset(&options, 0, sizeof(struct sslCheckOptions));
    options.port = 0;
    xmlArg = 0;
    strncpy(options.host, "127.0.0.1", 10);
    options.showCertificate = false;
    options.showTrustedCAs = false;
    options.checkCertificate = true;
    options.showClientCiphers = false;
    options.showCipherIds = false;
    options.showTimes = false;
    options.ciphersuites = true;
    options.reneg = true;
    options.fallback = true;
    options.compression = true;
    options.heartbleed = true;
    options.groups = true;
    options.starttls_ftp = false;
    options.starttls_imap = false;
    options.starttls_irc = false;
    options.starttls_ldap = false;
    options.starttls_pop3 = false;
    options.starttls_smtp = false;
    options.starttls_mysql = false;
    options.starttls_xmpp = false;
    options.starttls_psql = false;
    options.xmpp_server = false;
    options.verbose = false;
    options.cipher_details = true;
    options.ipv4 = true;
    options.ipv6 = true;
    options.ocspStatus = false;

    // Default socket timeout 3s
    options.timeout.tv_sec = 3;
    options.timeout.tv_usec = 0;
    options.sleep = 0;

    options.sslVersion = ssl_all;

#ifdef _WIN32
    /* Attempt to enable console colors.  This succeeds in Windows 10.  For other
     * OSes, color is disabled. */
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if ((hConsole == INVALID_HANDLE_VALUE) || (!GetConsoleMode(hConsole, &consoleMode)) || (!SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))) {
        RESET = "";
        COL_RED = "";
        COL_YELLOW = "";
        COL_BLUE = "";
        COL_GREEN = "";
        COL_PURPLE = "";
        COL_GREY = "";
        COL_RED_BG = "";
    }

    /* Initialize networking library. */
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        printf_error("WSAStartup failed: %d\n", err);
        return -1;
    }
#endif
    SSL_library_init();


    // Get program parameters
    for (argLoop = 1; argLoop < argc; argLoop++)
    {
        // Help
        if ((strcmp("--help", argv[argLoop]) == 0) || (strcmp("-h", argv[argLoop]) == 0))
            mode = mode_help;

        // targets
        else if ((strncmp("--targets=", argv[argLoop], 10) == 0) && (strlen(argv[argLoop]) > 10))
        {
            mode = mode_multiple;
            options.targets = argLoop;
        }

        // Show certificate
        else if (strcmp("--show-certificate", argv[argLoop]) == 0)
            options.showCertificate = true;

        // Don't check certificate strength
        else if (strcmp("--no-check-certificate", argv[argLoop]) == 0)
            options.checkCertificate = false;

        // Show supported client ciphers
        else if (strcmp("--show-ciphers", argv[argLoop]) == 0)
            options.showClientCiphers = true;

        // Show ciphers ids
        else if (strcmp("--show-cipher-ids", argv[argLoop]) == 0)
        {
            options.showCipherIds = true;
        }

        // Show handshake times
        else if (strcmp("--show-times", argv[argLoop]) == 0)
        {
            options.showTimes = true;
        }

        // Show client auth trusted CAs
        else if (strcmp("--show-client-cas", argv[argLoop]) == 0)
            options.showTrustedCAs = true;

        // Version
        else if (strcmp("--version", argv[argLoop]) == 0)
            mode = mode_version;

        // XML Output
        else if (strncmp("--xml=", argv[argLoop], 6) == 0)
            xmlArg = argLoop;

        // Verbose
        else if (strcmp("--verbose", argv[argLoop]) == 0)
            options.verbose = true;

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        // Cipher details (curve names and EDH key lengths)
        else if (strcmp("--no-cipher-details", argv[argLoop]) == 0)
            options.cipher_details = false;
#endif

        // Disable coloured output
        else if ((strcmp("--no-colour", argv[argLoop]) == 0) || (strcmp("--no-color", argv[argLoop]) == 0))
        {
            RESET = "";
            COL_RED = "";
            COL_YELLOW = "";
            COL_BLUE = "";
            COL_GREEN = "";
            COL_PURPLE = "";
            COL_RED_BG = "";
            COL_GREY = "";
        }

        // Client Certificates
        else if (strncmp("--certs=", argv[argLoop], 8) == 0)
            options.clientCertsFile = argv[argLoop] +8;

        // Private Key File
        else if (strncmp("--pk=", argv[argLoop], 5) == 0)
            options.privateKeyFile = argv[argLoop] +5;

        // Private Key Password
        else if (strncmp("--pkpass=", argv[argLoop], 9) == 0)
            options.privateKeyPassword = argv[argLoop] +9;

        // Should we check for supported cipher suites
        else if (strcmp("--no-ciphersuites", argv[argLoop]) == 0)
            options.ciphersuites = false;

        // Should we check for TLS Falback SCSV?
        else if (strcmp("--no-fallback", argv[argLoop]) == 0)
            options.fallback = false;

        // Should we check for TLS renegotiation?
        else if (strcmp("--no-renegotiation", argv[argLoop]) == 0)
            options.reneg = false;

        // Should we check for TLS Compression
        else if (strcmp("--no-compression", argv[argLoop]) == 0)
            options.compression = false;

        // Should we check for Heartbleed (CVE-2014-0160)
        else if (strcmp("--no-heartbleed", argv[argLoop]) == 0)
            options.heartbleed = false;

	// Should we check for key exchange groups?
	else if (strcmp("--no-groups", argv[argLoop]) == 0)
            options.groups = false;

        // StartTLS... FTP
        else if (strcmp("--starttls-ftp", argv[argLoop]) == 0)
            options.starttls_ftp = true;

        // StartTLS... IMAP
        else if (strcmp("--starttls-imap", argv[argLoop]) == 0)
            options.starttls_imap = true;

        else if (strcmp("--starttls-irc", argv[argLoop]) == 0)
            options.starttls_irc = true;

        // StartTLS... LDAP
        else if (strcmp("--starttls-ldap", argv[argLoop]) == 0)
            options.starttls_ldap = true;

        // StartTLS... POP3
        else if (strcmp("--starttls-pop3", argv[argLoop]) == 0)
            options.starttls_pop3 = true;

        // StartTLS... SMTP
        else if (strcmp("--starttls-smtp", argv[argLoop]) == 0)
            options.starttls_smtp = true;

        // StartTLS... MYSQL
        else if (strcmp("--starttls-mysql", argv[argLoop]) == 0)
            options.starttls_mysql = true;

        // StartTLS... XMPP
        else if (strcmp("--starttls-xmpp", argv[argLoop]) == 0)
            options.starttls_xmpp = true;

        // StartTLS... PostgreSQL
        else if (strcmp("--starttls-psql", argv[argLoop]) == 0)
            options.starttls_psql = true;

        // SSL v2 only...
        else if (strcmp("--ssl2", argv[argLoop]) == 0)
            options.sslVersion = ssl_v2;

        // SSL v3 only...
        else if (strcmp("--ssl3", argv[argLoop]) == 0)
            options.sslVersion = ssl_v3;

        // TLS v1 only...
        else if (strcmp("--tls10", argv[argLoop]) == 0)
            options.sslVersion = tls_v10;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        // TLS v11 only...
        else if (strcmp("--tls11", argv[argLoop]) == 0)
            options.sslVersion = tls_v11;

        // TLS v12 only...
        else if (strcmp("--tls12", argv[argLoop]) == 0)
            options.sslVersion = tls_v12;
        // TLS v13 only...
        else if (strcmp("--tls13", argv[argLoop]) == 0)
            options.sslVersion = tls_v13;
#endif
        // TLS (all versions)...
        else if (strcmp("--tlsall", argv[argLoop]) == 0)
            options.sslVersion = tls_all;

        // Use a server-to-server XMPP handshake
        else if (strcmp("--xmpp-server", argv[argLoop]) == 0)
            options.xmpp_server = true;

        // SSL Bugs...
        else if (strcmp("--bugs", argv[argLoop]) == 0)
            options.sslbugs = 1;

        // Socket Timeout
        else if (strncmp("--timeout=", argv[argLoop], 10) == 0)
            options.timeout.tv_sec = atoi(argv[argLoop] + 10);

        // Sleep between requests (ms)
        else if (strncmp("--sleep=", argv[argLoop], 8) == 0)
        {
            msec = atoi(argv[argLoop] + 8);
            if (msec >= 0) {
                options.sleep = msec;
            }
        }

        // SSL HTTP Get...
        else if (strcmp("--http", argv[argLoop]) == 0)
            options.http = 1;

        // RDP Preamble...
        else if (strcmp("--rdp", argv[argLoop]) == 0)
            options.rdp = 1;

        // IPv4 only
        else if ((strcmp("--ipv4", argv[argLoop]) == 0) || (strcmp("-4", argv[argLoop]) == 0))
            options.ipv6 = false;

        // IPv6 only
        else if ((strcmp("--ipv6", argv[argLoop]) == 0) || (strcmp("-6", argv[argLoop]) == 0))
            options.ipv4 = false;

        else if (strcmp("--ocsp", argv[argLoop]) == 0)
            options.ocspStatus = true;

        // SNI name
        else if (strncmp("--sni-name=", argv[argLoop], 11) == 0)
            strncpy(options.sniname, argv[argLoop]+11, strlen(argv[argLoop])-11);

		else if (strcmp("--ocsp", argv[argLoop]) == 0)
			options.ocspStatus = true;


        // Host (maybe port too)...
        else if (argLoop + 1 == argc)
        {
            mode = mode_single;

            // Get host...
            // IPv6 [] address parsing by DinoTools/phibos
            tempInt = 0;
            char *hostString = argv[argLoop];

            maxSize = strlen(hostString);

            if (strncmp((char*)hostString, "https://", 8) == 0)
            {
                // Strip https:// from the start of the hostname
                memmove(hostString, hostString + 8, (maxSize - 8));
                memset(hostString + (maxSize - 8), 0, 8);
                maxSize = strlen(hostString);
            }

            int squareBrackets = false;
            if (hostString[0] == '[')
            {
                squareBrackets = true;
                // skip the square bracket
                hostString++;
            }

            while ((hostString[tempInt] != 0) && ((squareBrackets == true && hostString[tempInt] != ']')
                        || (squareBrackets == false && hostString[tempInt] != ':')))
            {
                tempInt++;
            }

            if (squareBrackets == true && hostString[tempInt] == ']')
            {
                hostString[tempInt] = 0;
                if (tempInt < maxSize && hostString[tempInt + 1] == ':')
                {
                    tempInt++;
                    hostString[tempInt] = 0;
                }
            }
            else
            {
                hostString[tempInt] = 0;
            }
            strncpy(options.host, hostString, sizeof(options.host) -1);

            // No SNI name passed on command line
            if (strlen(options.sniname) == 0)
            {
                strncpy(options.sniname, options.host, sizeof(options.host));
            }

            // Get port (if it exists)...
            tempInt++;
            if (tempInt < maxSize)
            {
                errno = 0;
                options.port = strtol((hostString + tempInt), NULL, 10);
                if (options.port < 1 || options.port > 65535)
                {
                    printf("\n%sInvalid port specified%s\n\n", COL_RED, RESET);
                    exit(1);
                }
            }
            else if (options.port == 0) {
                if (options.starttls_ftp)
                    options.port = 21;
                else if (options.starttls_imap)
                    options.port = 143;
                else if (options.starttls_irc)
                    options.port = 6667;
                else if (options.starttls_ldap)
                    options.port = 389;
                else if (options.starttls_pop3)
                    options.port = 110;
                else if (options.starttls_smtp)
                    options.port = 25;
                else if (options.starttls_mysql)
                    options.port = 3306;
                else if (options.starttls_xmpp)
                    options.port = 5222;
                else if (options.starttls_psql)
                    options.port = 5432;
                else if (options.rdp)
                    options.port = 3389;
                else
                    options.port = 443;
            }
        }

        // Not too sure what the user is doing...
        else
            mode = mode_help;
    }

    // Open XML file output...
    if ((xmlArg > 0) && (mode != mode_help))
    {
        if (strcmp(argv[xmlArg] + 6, "-") == 0)
        {
            options.xmlOutput = stdout;
            xml_to_stdout = 1;
        }
        else
        {
            options.xmlOutput = fopen(argv[xmlArg] + 6, "w");
            if (options.xmlOutput == NULL)
            {
                printf_error("%sERROR: Could not open XML output file %s.%s\n", COL_RED, argv[xmlArg] + 6, RESET);
                exit(0);
            }
        }

        // Output file header...
        fprintf(options.xmlOutput, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document title=\"SSLScan Results\" version=\"%s\" web=\"http://github.com/rbsec/sslscan\">\n", VERSION);
    }

    // Build the list of ciphers missing from OpenSSL.
    findMissingCiphers();

    switch (mode)
    {
        case mode_version:
            printf("%s\t\t%s\n\t\t%s\n%s", COL_BLUE, VERSION,
                    SSLeay_version(SSLEAY_VERSION), RESET);
#if OPENSSL_VERSION_NUMBER < 0x10001000L
            printf("\t\t%sOpenSSL version does not support TLSv1.1%s\n", COL_RED, RESET);
            printf("\t\t%sTLSv1.1 ciphers will not be detected%s\n", COL_RED, RESET);
            printf("\t\t%sOpenSSL version does not support TLSv1.2%s\n", COL_RED, RESET);
            printf("\t\t%sTLSv1.2 ciphers will not be detected%s\n", COL_RED, RESET);
#endif
            break;

        case mode_help:
            // Program version banner...
            printf("%s%s%s\n", COL_BLUE, program_banner, RESET);
            printf("%s\t\t%s\n\t\t%s\n%s", COL_BLUE, VERSION,
                    SSLeay_version(SSLEAY_VERSION), RESET);
#ifdef OPENSSL_NO_SSL2
            printf("%sOpenSSL version does not support SSLv2%s\n", COL_RED, RESET);
            printf("%sSSLv2 ciphers will not be detected%s\n\n", COL_RED, RESET);
#endif
            printf("%sCommand:%s\n", COL_BLUE, RESET);
            printf("  %s%s [Options] [host:port | host]%s\n\n", COL_GREEN, argv[0], RESET);
            printf("%sOptions:%s\n", COL_BLUE, RESET);
            printf("  %s--targets=<file>%s     A file containing a list of hosts to check.\n", COL_GREEN, RESET);
            printf("                       Hosts can  be supplied  with ports (host:port)\n");
            printf("  %s--sni-name=<name>%s    Hostname for SNI\n", COL_GREEN, RESET);
            printf("  %s--ipv4, -4%s           Only use IPv4\n", COL_GREEN, RESET);
            printf("  %s--ipv6, -6%s           Only use IPv6\n", COL_GREEN, RESET);
            printf("  %s--show-certificate%s   Show full certificate information\n", COL_GREEN, RESET);
            printf("  %s--no-check-certificate%s  Don't warn about weak certificate algorithm or keys\n", COL_GREEN, RESET);
            printf("  %s--show-client-cas%s    Show trusted CAs for TLS client auth\n", COL_GREEN, RESET);
            printf("  %s--show-ciphers%s       Show supported client ciphers\n", COL_GREEN, RESET);
            printf("  %s--show-cipher-ids%s    Show cipher ids\n", COL_GREEN, RESET);
            printf("  %s--show-times%s         Show handhake times in milliseconds\n", COL_GREEN, RESET);
            printf("  %s--ssl2%s               Only check SSLv2 ciphers\n", COL_GREEN, RESET);
            printf("  %s--ssl3%s               Only check SSLv3 ciphers\n", COL_GREEN, RESET);
            printf("  %s--tls10%s              Only check TLSv1.0 ciphers\n", COL_GREEN, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            printf("  %s--tls11%s              Only check TLSv1.1 ciphers\n", COL_GREEN, RESET);
            printf("  %s--tls12%s              Only check TLSv1.2 ciphers\n", COL_GREEN, RESET);
            printf("  %s--tls13%s              Only check TLSv1.3 ciphers\n", COL_GREEN, RESET);
#endif
            printf("  %s--tlsall%s             Only check TLS ciphers (all versions)\n", COL_GREEN, RESET);
            printf("  %s--ocsp%s               Request OCSP response from server\n", COL_GREEN, RESET);
            printf("  %s--pk=<file>%s          A file containing the private key or a PKCS#12 file\n", COL_GREEN, RESET);
            printf("                       containing a private key/certificate pair\n");
            printf("  %s--pkpass=<password>%s  The password for the private  key or PKCS#12 file\n", COL_GREEN, RESET);
            printf("  %s--certs=<file>%s       A file containing PEM/ASN1 formatted client certificates\n", COL_GREEN, RESET);
            printf("  %s--no-ciphersuites%s    Do not check for supported ciphersuites\n", COL_GREEN, RESET);
#ifdef SSL_MODE_SEND_FALLBACK_SCSV
            printf("  %s--no-fallback%s        Do not check for TLS Fallback SCSV\n", COL_GREEN, RESET);
#endif
            printf("  %s--no-renegotiation%s   Do not check for TLS renegotiation\n", COL_GREEN, RESET);
            printf("  %s--no-compression%s     Do not check for TLS compression (CRIME)\n", COL_GREEN, RESET);
            printf("  %s--no-heartbleed%s      Do not check for OpenSSL Heartbleed (CVE-2014-0160)\n", COL_GREEN, RESET);
            printf("  %s--no-groups%s          Do not enumerate key exchange groups\n", COL_GREEN, RESET);
            printf("  %s--starttls-ftp%s       STARTTLS setup for FTP\n", COL_GREEN, RESET);
            printf("  %s--starttls-imap%s      STARTTLS setup for IMAP\n", COL_GREEN, RESET);
            printf("  %s--starttls-irc%s       STARTTLS setup for IRC\n", COL_GREEN, RESET);
            printf("  %s--starttls-ldap%s      STARTTLS setup for LDAP\n", COL_GREEN, RESET);
            printf("  %s--starttls-pop3%s      STARTTLS setup for POP3\n", COL_GREEN, RESET);
            printf("  %s--starttls-smtp%s      STARTTLS setup for SMTP\n", COL_GREEN, RESET);
            printf("  %s--starttls-mysql%s     STARTTLS setup for MYSQL\n", COL_GREEN, RESET);
            printf("  %s--starttls-xmpp%s      STARTTLS setup for XMPP\n", COL_GREEN, RESET);
            printf("  %s--starttls-psql%s      STARTTLS setup for PostgreSQL\n", COL_GREEN, RESET);
            printf("  %s--xmpp-server%s        Use a server-to-server XMPP handshake\n", COL_GREEN, RESET);
            printf("  %s--http%s               Test a HTTP connection\n", COL_GREEN, RESET);
            printf("  %s--rdp%s                Send RDP preamble before starting scan\n", COL_GREEN, RESET);
            printf("  %s--bugs%s               Enable SSL implementation bug work-arounds\n", COL_GREEN, RESET);
            printf("  %s--timeout=<sec>%s      Set socket timeout. Default is 3s\n", COL_GREEN, RESET);
            printf("  %s--sleep=<msec>%s       Pause between connection request. Default is disabled\n", COL_GREEN, RESET);
            printf("  %s--xml=<file>%s         Output results to an XML file\n", COL_GREEN, RESET);
            printf("                       <file> can be -, which means stdout\n");
            printf("  %s--version%s            Display the program version\n", COL_GREEN, RESET);
            printf("  %s--verbose%s            Display verbose output\n", COL_GREEN, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
            printf("  %s--no-cipher-details%s  Disable EC curve names and EDH/RSA key lengths output\n", COL_GREEN, RESET);
#endif
            printf("  %s--no-colour%s          Disable coloured output\n", COL_GREEN, RESET);
            printf("  %s--help%s               Display the  help text  you are  now reading\n\n", COL_GREEN, RESET);
            printf("%sExample:%s\n", COL_BLUE, RESET);
            printf("  %s%s 127.0.0.1%s\n", COL_GREEN, argv[0], RESET);
            printf("  %s%s [::1]%s\n\n", COL_GREEN, argv[0], RESET);
            break;

        // Check a single host/port ciphers...
        case mode_single:
        case mode_multiple:
            printf("Version: %s%s%s\n%s\n%s\n", COL_GREEN, VERSION, RESET,
                    SSLeay_version(SSLEAY_VERSION), RESET);
#if OPENSSL_VERSION_NUMBER < 0x10001000L
            printf("\t\t%sOpenSSL version does not support TLSv1.1%s\n", COL_RED, RESET);
            printf("\t\t%sTLSv1.1 ciphers will not be detected%s\n", COL_RED, RESET);
            printf("\t\t%sOpenSSL version does not support TLSv1.2%s\n", COL_RED, RESET);
            printf("\t\t%sTLSv1.2 ciphers will not be detected%s\n", COL_RED, RESET);
#endif

            //SSLeay_add_all_algorithms();
            ERR_load_crypto_strings();

            // Do the testing...
            if (mode == mode_single)
            {
                if (testConnection(&options))
                {
                    testHost(&options);
                }
            }
            else
            {
                if (fileExists(argv[options.targets] + 10) == true)
                {
                    // Open targets file...
                    targetsFile = fopen(argv[options.targets] + 10, "r");
                    if (targetsFile == NULL)
                        printf_error("%sERROR: Could not open targets file %s.%s\n", COL_RED, argv[options.targets] + 10, RESET);
                    else
                    {
                        readLine(targetsFile, line, sizeof(line));
                        while (feof(targetsFile) == 0)
                        {
                            if (strlen(line) != 0)
                            {
                                // Get host...
                                tempInt = 0;
                                while ((line[tempInt] != 0) && (line[tempInt] != ':'))
                                    tempInt++;
                                line[tempInt] = 0;
                                strncpy(options.host, line, sizeof(options.host) -1);

                                // Get port (if it exists)...
                                tempInt++;
                                if (strlen(line + tempInt) > 0)
                                {
                                    int port;
                                    port = atoi(line + tempInt);
                                    // Invalid port
                                    if (port == 0)
                                    {
                                        printf_error("%sERROR: Invalid port specified.%s", COL_RED, RESET);
                                        exit(1);
                                    }
                                    else
                                    {
                                        options.port = port;
                                    }
                                }
                                // Otherwise assume 443
                                else
                                {
                                    options.port = 443;
                                }

                                // Test the host...
                                if (testConnection(&options))
                                {
                                    testHost(&options);
                                }
                                printf("\n\n");
                            }
                            readLine(targetsFile, line, sizeof(line));
                        }
                    }
                }
                else
                    printf_error("%sERROR: Targets file %s does not exist.%s\n", COL_RED, argv[options.targets] + 10, RESET);
            }

            // Free Structures
            while (options.ciphers != 0)
            {
                sslCipherPointer = options.ciphers->next;
                free(options.ciphers);
                options.ciphers = sslCipherPointer;
            }
            break;
    }

    // Close XML file, if required...
    if ((xmlArg > 0) && (mode != mode_help))
    {
        fprintf(options.xmlOutput, "</document>\n");
        fclose(options.xmlOutput);
    }

    return 0;
}

int runSSLv2Test(struct sslCheckOptions *options) {
  int ret = false, s = 0;
  char sslv2_client_hello[] = {
    0x80,
    0x34, /* Length: 52 */
    0x01, /* Handshake Message Type: Client Hello */
    0x00, 0x02, /* Version: SSL 2.0 */
    0x00, 0x1b, /* Cipher Spec Length: 27 */
    0x00, 0x00, /* Session ID Length: 0 */
    0x00, 0x10, /* Challenge Length: 16 */
    0x05, 0x00, 0x80, /* SSL2_IDEA_128_CBC_WITH_MD5 */
    0x03, 0x00, 0x80, /* SSL2_RC2_128_CBC_WITH_MD5 */
    0x01, 0x00, 0x80, /* SSL2_RC4_128_WITH_MD5 */
    0x07, 0x00, 0xc0, /* SSL2_DES_192_EDE3_CBC_WITH_MD5 */
    0x08, 0x00, 0x80, /* SSL2_RC4_64_WITH_MD5 */
    0x06, 0x00, 0x40, /* SSL2_DES_64_CBC_WITH_MD5 */
    0x04, 0x00, 0x80, /* SSL2_RC2_128_CBC_EXPORT40_WITH_MD5 */
    0x02, 0x00, 0x80, /* SSL2_RC4_128_EXPORT40_WITH_MD5 */
    0x00, 0x00, 0x00, /* TLS_NULL_WITH_NULL_NULL */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f /* Challenge */
  };
  char response[8] = {0};

  /* Create a socket to the target. */
  s = tcpConnect(options);

  /* If a connection could not be made, return false. */
  if (s == 0)
    return false;

  /* Send the SSLv2 Client Hello packet. */
  if (send(s, sslv2_client_hello, sizeof(sslv2_client_hello), 0) <= 0) {
    printf_error("send() failed: %s\n", strerror(errno));
    exit(1);
  }

  /* Read a small amount of the response. */
  if (recv(s, response, sizeof(response), 0) != sizeof(response))
    goto done; /* Returns false. */

  /* If the Handshake Message Type is Server Hello (0x04) and the Version is SSL 2.0
   * (0x00, 0x02), we confirm that this is SSL v2. */
  if ((response[2] == 0x04) && (response[5] == 0x00) && (response[6] == 0x02))
    ret = true;

 done:
  close(s);
  return ret;
}

int runSSLv3Test(struct sslCheckOptions *options) {
  int ret = false, s = 0;
  uint32_t timestamp = 0;
  unsigned char timestamp_bytes[4] = {0};
  char sslv3_client_hello_1[] = {
    0x16, /* Content Type: Handshake (22) */
    0x03, 0x00, /* Version SSL 3.0 */
    0x00, 0xe8, /* Length: 232 */
    0x01, /* Handshake Type: Client Hello */
    0x00, 0x00, 0xe4, /* Length: 228 */
    0x03, 0x00, /* Version: SSL 3.0 */
  };

  char sslv3_client_hello_2[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, /* Random bytes */
    0x00, /* Session ID Length */
    0x00, 0xbc, /* Cipher Suites Length: 188 */
    0xc0, 0x14, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    0xc0, 0x0a, /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    0x00, 0x39, /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    0x00, 0x38, /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    0x00, 0x37, /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    0x00, 0x36, /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    0x00, 0x88, /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    0x00, 0x87, /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    0x00, 0x86, /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    0x00, 0x85, /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    0xc0, 0x19, /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    0x00, 0x3a, /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    0x00, 0x89, /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    0xc0, 0x0f, /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    0xc0, 0x05, /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    0x00, 0x35, /* TLS_RSA_WITH_AES_256_CBC_SHA */
    0x00, 0x84, /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    0x00, 0x95, /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    0xc0, 0x13, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    0xc0, 0x09, /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    0x00, 0x33, /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    0x00, 0x32, /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    0x00, 0x31, /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    0x00, 0x30, /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    0x00, 0x9a, /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
    0x00, 0x99, /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    0x00, 0x98, /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    0x00, 0x97, /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    0x00, 0x45, /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    0x00, 0x44, /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    0x00, 0x43, /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    0x00, 0x42, /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    0xc0, 0x18, /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    0x00, 0x34, /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    0x00, 0x9b, /* TLS_DH_anon_WITH_SEED_CBC_SHA */
    0x00, 0x46, /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    0xc0, 0x0e, /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    0xc0, 0x04, /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    0x00, 0x2f, /* TLS_RSA_WITH_AES_128_CBC_SHA */
    0x00, 0x96, /* TLS_RSA_WITH_SEED_CBC_SHA */
    0x00, 0x41, /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    0x00, 0x07, /* TLS_RSA_WITH_IDEA_CBC_SHA */
    0x00, 0x94, /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    0xc0, 0x11, /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    0xc0, 0x07, /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    0x00, 0x66, /* TLS_DHE_DSS_WITH_RC4_128_SHA */
    0xc0, 0x16, /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    0x00, 0x18, /* TLS_DH_anon_WITH_RC4_128_MD5 */
    0xc0, 0x0c, /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    0xc0, 0x02, /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    0x00, 0x05, /* TLS_RSA_WITH_RC4_128_SHA */
    0x00, 0x04, /* TLS_RSA_WITH_RC4_128_MD5 */
    0x00, 0x92, /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    0xc0, 0x12, /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    0xc0, 0x08, /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x16, /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x13, /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x10, /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x0d, /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    0xc0, 0x17, /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x1b, /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    0xc0, 0x0d, /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    0xc0, 0x03, /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x0a, /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x93, /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    0x00, 0x63, /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    0x00, 0x15, /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    0x00, 0x12, /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    0x00, 0x0f, /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    0x00, 0x0c, /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    0x00, 0x1a, /* TLS_DH_anon_WITH_DES_CBC_SHA */
    0x00, 0x62, /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    0x00, 0x09, /* TLS_RSA_WITH_DES_CBC_SHA */
    0x00, 0x61, /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
    0x00, 0x65, /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
    0x00, 0x64, /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    0x00, 0x60, /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    0x00, 0x14, /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    0x00, 0x11, /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    0x00, 0x0e, /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    0x00, 0x0b, /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    0x00, 0x19, /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    0x00, 0x08, /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    0x00, 0x06, /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    0x00, 0x17, /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    0x00, 0x03, /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    0xc0, 0x10, /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    0xc0, 0x06, /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    0xc0, 0x15, /* TLS_ECDH_anon_WITH_NULL_SHA */
    0xc0, 0x0b, /* TLS_ECDH_RSA_WITH_NULL_SHA */
    0xc0, 0x01, /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    0x00, 0x02, /* TLS_RSA_WITH_NULL_SHA */
    0x00, 0x01, /* TLS_RSA_WITH_NULL_MD5 */
    0x00, 0xff, /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
    0x02, /* Compression Methods Length: 2 */
    0x01, 0x00, /* DEFLATE, none */
  };
  char response[16] = {0};

  /* Create a socket to the target. */
  s = tcpConnect(options);

  /* If a connection could not be made, return false. */
  if (s == 0)
    return false;

  /* Send the SSLv3 Client Hello packet. */
  if (send(s, sslv3_client_hello_1, sizeof(sslv3_client_hello_1), 0) <= 0) {
    printf_error("send() failed: %s\n", strerror(errno));
    exit(1);
  }

  timestamp = htonl(time(NULL)); /* Current time stamp. */
  timestamp_bytes[0] = timestamp & 0xff;
  timestamp_bytes[1] = (timestamp >> 8) & 0xff;
  timestamp_bytes[2] = (timestamp >> 16) & 0xff;
  timestamp_bytes[3] = (timestamp >> 24) & 0xff;

  if (send(s, timestamp_bytes, sizeof(timestamp_bytes), 0) <= 0) {
    printf_error("send() failed: %s\n", strerror(errno));
    exit(1);
  }

  if (send(s, sslv3_client_hello_2, sizeof(sslv3_client_hello_2), 0) <= 0) {
    printf_error("send() failed: %s\n", strerror(errno));
    exit(1);
  }

  /* Read a small amount of the response. */
  if (recv(s, response, sizeof(response), 0) != sizeof(response))
    goto done; /* Returns false. */

  /* Examine response. */
  if ((response[0] == 0x16) && /* Content Type is Handshake (22) */
      (response[1] == 0x03) && (response[2] == 0x00) && /* Version is SSL 3.0 */
      (response[5] == 0x02) && /* Handshake Type is Server Hello (2) */
      (response[9] == 0x03) && (response[10] == 0x00)) /* Version is SSL 3.0 (again) */
    ret = true;

 done:
  close(s);
  return ret;
}

/* Compares the list of supported ciphersuites by OpenSSL with the complete list of ciphersuites from IANA.  Marks the matches so they are not re-tested again later. */
void findMissingCiphers() {
  STACK_OF(SSL_CIPHER) *cipherList = NULL;
  const SSL_CIPHER *cipher = NULL;
  unsigned int tls_version = 0;
  uint32_t id = 0;
  const SSL_METHOD *sslMethods[] = { TLSv1_client_method(), TLSv1_1_client_method(), TLSv1_2_client_method() };
  unsigned int tls_versions[] = { V1_0, V1_1, V1_2 };

  /* For each TLS version (not including v1.3)... */
  for (int m = 0; m < (sizeof(sslMethods) / sizeof(const SSL_METHOD *)); m++) {
    tls_version = tls_versions[m];
    SSL_CTX *ctx = new_CTX(sslMethods[m]);
    SSL_CTX_set_cipher_list(ctx, CIPHERSUITE_LIST_ALL);
    cipherList = SSL_CTX_get_ciphers(ctx);

    /* Loop through all OpenSSL ciphers... */
    for (int i = 0; i < sk_SSL_CIPHER_num(cipherList); i++) {
      cipher = sk_SSL_CIPHER_value(cipherList, i);
      id = SSL_CIPHER_get_protocol_id(cipher);

      /* Using the cipher ID, find the match in the IANA list. */
      for (int j = 0; j < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); j++) {
	if ((missing_ciphersuites[j].id == id) && (missing_ciphersuites[j].check_tls_versions & tls_version)) {
	  /* Turn off the flag for this version of TLS. */
	  missing_ciphersuites[j].check_tls_versions &= ~tls_version;
	}
      }
    }

    FREE_CTX(ctx);
  }
}

/* Appends an array of bytes (in 'bytes') of length 'bytes_len' to an array (in 'buffer').  The current size of 'buffer' is given in 'buf_size'.  The current number of bytes used in the buffer is given in 'buf_len'.  If the caller tries to append bytes that the current buffer cannot hold, the buffer will be automatically re-sized and the bytes are safely appended.  The extended buffer region is zeroed. */
#define OVERFLOW_MESSAGE "Cannot lengthen buffer without overflowing length!\n"
void buffer_append_bytes(unsigned char **buffer, size_t *buf_size, size_t *buf_len, unsigned char *bytes, size_t bytes_len) {
  size_t new_len = *buf_len + bytes_len;

  if (buffer == NULL)
    return;

  /* Ensure that the new length does not cause an integer overflow. */
  if ((new_len < *buf_len) || (new_len < bytes_len)) {
    fprintf(stderr, OVERFLOW_MESSAGE);
    exit(-1);
  }

  /* If the buffer needs re-sizing... */
  if (new_len > *buf_size) {

    /* Double the size of the buffer until it is larger than what we need right now. */
    while (new_len > *buf_size) {
      /* Ensure we don't overflow the length. */
      if ((size_t)(*buf_len * 2) < *buf_len) {
        fprintf(stderr, OVERFLOW_MESSAGE);
        exit(-1);
      }
      *buf_size = *buf_size * 2;
    }

    /* Extend the buffer's size. */
    *buffer = realloc(*buffer, *buf_size);
    if (*buffer == NULL) {
      fprintf(stderr, "Failed to resize buffer.\n");
      exit(-1);
    }

    /* Zero out the extended buffer region; leave the existing bytes intact. */
    memset(*buffer + *buf_len, 0, *buf_size - *buf_len);
  }

  /* Copy the new bytes into the buffer right after the existing bytes. */
  memcpy(*buffer + *buf_len, bytes, bytes_len);

  /* Update the number of used bytes in the buffer. */
  *buf_len = new_len;
}

/* Convert an unsigned short to network-order, then append it to the buffer.  See documentation for buffer_append_bytes() for description of other arguments. */
void buffer_append_ushort(unsigned char **buffer, size_t *buf_size, size_t *buf_len, unsigned short s) {
  unsigned short network_short = htons(s);
  buffer_append_bytes(buffer, buf_size, buf_len, (unsigned char *)&network_short, sizeof(unsigned short));
}

/* Append a uint32_t to the buffer.  See documentation for buffer_append_bytes() for description of other arguments. */
void buffer_append_uint32_t(unsigned char **buffer, size_t *buf_size, size_t *buf_len, uint32_t i) {
  buffer_append_bytes(buffer, buf_size, buf_len, (unsigned char *)&i, sizeof(uint32_t));
}

/* Sets the 'ciphersuite_list' arg to a buffer (which must be free()'ed) of ciphersuites for a given TLS version, and sets the 'ciphersuite_list_len' arg to the number of bytes in 'ciphersuite_list'.  When 'type' is CIPHERSUITES_MISSING, then a list of all ciphersuites missing in OpenSSL is returned.  When set to CIPHERSUITES_TLSV1_3_ALL, all TLSv1.3 ciphersuites are returned only. */
#define CIPHERSUITES_MISSING 0
#define CIPHERSUITES_TLSV1_3_ALL 1
void makeCiphersuiteList(unsigned char **ciphersuite_list, size_t *ciphersuite_list_len, unsigned int tls_version, unsigned int type) {
  size_t ciphersuite_list_size = 1024;


  // Make the buffer much smaller if we're just returning the list of 5 TLSv1.3 ciphers.
  if (type == CIPHERSUITES_TLSV1_3_ALL)
    ciphersuite_list_size = 16;

  *ciphersuite_list = calloc(ciphersuite_list_size, sizeof(unsigned char));
  if (*ciphersuite_list == NULL) {
    fprintf(stderr, "Failed to create buffer for ciphersuite list.\n");
    exit(-1);
  }
  *ciphersuite_list_len = 0;

  if (type == CIPHERSUITES_MISSING) {
    if (tls_version == 0)
      tls_version = V1_0;
    else if (tls_version == 1)
      tls_version = V1_1;
    else if (tls_version == 2)
      tls_version = V1_2;

    for (int i = 0; i < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); i++) {
      /* Append only those that OpenSSL does not cover, and those that were not already accepted through a previous run. */
      if ((missing_ciphersuites[i].check_tls_versions & tls_version) && ((missing_ciphersuites[i].accepted_tls_versions & tls_version) == 0)) {
	buffer_append_ushort(ciphersuite_list, &ciphersuite_list_size, ciphersuite_list_len, missing_ciphersuites[i].id);
      }
    }
  } else if (type == CIPHERSUITES_TLSV1_3_ALL) {
    buffer_append_bytes(ciphersuite_list, &ciphersuite_list_size, ciphersuite_list_len, (unsigned char []) {
      0x13, 0x01, // TLS_AES_128_GCM_SHA256
      0x13, 0x02, // TLS_AES_256_GCM_SHA384
      0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
      0x13, 0x04, // TLS_AES_128_CCM_SHA256
      0x13, 0x05, // TLS_AES_128_CCM_8_SHA256
    }, 10);
  }
}

/* Marks a ciphersuite as found so that it is not re-tested again. */
void markFoundCiphersuite(unsigned short server_cipher_id, unsigned int tls_version) {
  if (tls_version == 0)
    tls_version = V1_0;
  else if (tls_version == 1)
    tls_version = V1_1;
  else if (tls_version == 2)
    tls_version = V1_2;

  for (int i = 0; i < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); i++) {
    if (missing_ciphersuites[i].id == server_cipher_id) {
      missing_ciphersuites[i].accepted_tls_versions |= tls_version;
      break;
    }
  }
}

/* Resolves an IANA cipher ID to its IANA name.  Sets the cipher_bits argument to the cipher strength (or to -1 if unknown).  Returns "UNKNOWN_CIPHER if cipher ID is not found. */
char *resolveCipherID(unsigned short cipher_id, int *cipher_bits) {
  for (int i = 0; i < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); i++) {
    if (missing_ciphersuites[i].id == cipher_id) {
      *cipher_bits = missing_ciphersuites[i].bits;
      return missing_ciphersuites[i].protocol_name;
    }
  }
  *cipher_bits = -1;
  return "UNKNOWN_CIPHER";
}

/* Sets a length field in a TLS packet at the specified offset. */
void setTLSLength(unsigned char *buf, unsigned int offset, unsigned int length) {
  uint16_t u = htons(length);
  memcpy(buf + offset, &u, sizeof(u));
}

/* Creates a basic set of TLS extensions, including SNI, ec_point_formats, Session Ticket TLS, and signature_algorithms. */
unsigned char *makeTLSExtensions(size_t *tls_extensions_size, size_t *tls_extensions_len, struct sslCheckOptions *options) {
  unsigned char *tls_extensions = NULL;


  *tls_extensions_size = 64;
  tls_extensions = calloc(*tls_extensions_size, sizeof(unsigned char));
  if (tls_extensions == NULL) {
    fprintf(stderr, "Failed to allocate buffers for TLS extensions.\n");
    exit(-1);
  }
  *tls_extensions_len = 0;

  /* Add the length of the extensions (to be filled in later). */
  buffer_append_ushort(&tls_extensions, tls_extensions_size, tls_extensions_len, 0);

  /* Extension: server name */
  uint16_t sni_length = strlen(options->sniname);
  uint16_t sni_list_length = sni_length + 3;
  uint16_t extension_length = sni_list_length + 2;

  buffer_append_ushort(&tls_extensions, tls_extensions_size, tls_extensions_len, 0x0000); /* Extension: server_name */
  buffer_append_ushort(&tls_extensions, tls_extensions_size, tls_extensions_len, extension_length);
  buffer_append_ushort(&tls_extensions, tls_extensions_size, tls_extensions_len, sni_list_length);
  buffer_append_bytes(&tls_extensions, tls_extensions_size, tls_extensions_len, (unsigned char []) { 0x00 /* Server Name Type: host_name */ }, 1);
  buffer_append_ushort(&tls_extensions, tls_extensions_size, tls_extensions_len, sni_length); /* The length of the hostname. */
  buffer_append_bytes(&tls_extensions, tls_extensions_size, tls_extensions_len, (unsigned char *)options->sniname, sni_length); /* The hostname itself. */

  /* Extension: ec_point_formats */
  buffer_append_bytes(&tls_extensions, tls_extensions_size, tls_extensions_len, (unsigned char []) {
    0x00, 0x0b, // Extension: ec_point_formats (11)
    0x00, 0x04, // Extension Length (4)
    0x03, // EC Point Formats Length (3)
    0x00, // Uncompressed
    0x01, // ansiX962_compressed_prime
    0x02, // ansiX962_compressed_char2
  }, 8);

  /* Extension: SessionTicket TLS */
  buffer_append_bytes(&tls_extensions, tls_extensions_size, tls_extensions_len, (unsigned char []) {
    0x00, 0x23, // Extension: SessionTicket TLS (35)
    0x00, 0x00, // Extension Length (0)
  }, 4);

  /* Extension: signature_algorithms */
  buffer_append_bytes(&tls_extensions, tls_extensions_size, tls_extensions_len, (unsigned char []) {
    0x00, 0x0d, // Extension: signature_algorithms (13)
    0x00, 0x1e, // Extension Length (30)
    0x00, 0x1c, // Signature Hash Algorithms Length (28)
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x06, 0x03, // ecdsa_secp521r1_sha512
    0x08, 0x07, // ed25519
    0x08, 0x08, // ed448
    0x08, 0x09, // rsa_pss_pss_sha256
    0x08, 0x0a, // rsa_pss_pss_sha384
    0x08, 0x0b, // rsa_pss_pss_sha512
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x01, // rsa_pkcs1_sha384
    0x06, 0x01, // rsa_pkcs1_sha512
  }, 34);

  /* Set the extension length. */
  setTLSLength(tls_extensions, 0, *tls_extensions_len - 2);
  return tls_extensions;
}

/* Adds the TLS supported_versions extension, set to TLSv1.3 only. */
void tlsExtensionAddTLSv1_3(unsigned char **tls_extensions, size_t *tls_extensions_size, size_t *tls_extensions_len) {
  buffer_append_bytes(tls_extensions, tls_extensions_size, tls_extensions_len, (unsigned char []) {
      0x00, 0x2b, // supported_versions (43)
      0x00, 0x03, // Length
      0x02,       // Supported Versions Length
      0x03, 0x04, // Supported Version: TLS v1.3
  }, 7);
  setTLSLength(*tls_extensions, 0, *tls_extensions_len - 2);
}

/* From socket s, reads a ServerHello from the network.  Returns an unsigned char array on success (which the caller must free()), or NULL on failure. */
unsigned char *getServerHello(int s, size_t *server_hello_len) {
  unsigned char *server_hello = NULL;
  unsigned char initial5[8] = {0};  // The initial 5 bytes of the packet.


  /* Read the first 5 bytes to get the Content Type, Version, and Length fields. */
  int bytes_read = 0, n = 0;
  while (bytes_read < 5) {
    n = recv(s, initial5 + bytes_read, 5 - bytes_read, 0);
    if (n <= 0) {
      if ((errno != 0) && (errno != ECONNRESET))
	printf_error("recv() failed while reading Server Hello: %d (%s)\n", errno, strerror(errno));
      goto err;
    }
    bytes_read += n;
  }
  *server_hello_len = bytes_read;

  /* Ensure that the Content Type is Handshake (22). */
  if (initial5[0] != 0x16)
    goto err;

  /* Get the length of the Server Hello record. */
  unsigned short packet_len = (initial5[3] << 8) | initial5[4];

  server_hello = calloc(packet_len + sizeof(initial5), sizeof(unsigned char));
  if (server_hello == NULL) {
    fprintf(stderr, "Failed to create buffer for Server Hello.\n");
    exit(-1);
  }

  /* Copy the initial 5 bytes into the beginning of the buffer. */
  memcpy(server_hello, initial5, *server_hello_len);

  /* Read in the Server Hello record. */
  bytes_read = 0;
  while (bytes_read < packet_len) {
    n = recv(s, server_hello + *server_hello_len + bytes_read, packet_len - bytes_read, 0);
    if (n <= 0) {
      if ((errno != 0) && (errno != ECONNRESET))
	printf_error("recv() failed while reading Server Hello: %d (%s)\n", errno, strerror(errno));
      goto err;
    }
    bytes_read += n;
  }
  *server_hello_len += bytes_read;

  /* Ensure that the Handshake Type is Server Hello (2). */
  if (server_hello[5] != 0x02)
    goto err;

  return server_hello;

 err:
  FREE(server_hello);
  *server_hello_len = 0;
  return NULL;
}

/* Returns a buffer (which the caller must free()) containing a TLS Client Hello message.  The number of bytes is stored in 'client_hello_len'.  'version' is set to 0 for TLSv1.0, 1 for TLSv1.1, 2, for TLSv1.2, and 3 for TLSv1.3.  The specified ciphersuite list and TLS extensions will be included.  */
unsigned char *makeClientHello(size_t *client_hello_len, struct sslCheckOptions *options, unsigned int version, unsigned char *ciphersuite_list, size_t ciphersuite_list_len, unsigned char *tls_extensions, size_t tls_extensions_len) {
  unsigned char *client_hello = NULL;
  size_t client_hello_size = 1024;
  unsigned int tls_record_version_low_byte = 1, tls_handshake_version_low_byte = 1;
  time_t time_now = time(NULL);


  /* For TLSv1.0, 1.1, and 1.2, the TLS Record version and Handshake version are the same (and what they should be).  For TLSv1.3, the TLS Record claims to be TLSv1.0 and the Handshake claims to be TLSv1.2; this is for compatibility of buggy middleware that most implementations follow. */
  if (version < 3) {
    tls_record_version_low_byte += version;
    tls_handshake_version_low_byte += version;
  } else {
    tls_record_version_low_byte = 1;
    tls_handshake_version_low_byte = 3;
  }

  /* Allocate buffers for the Client Hello and TLS extensions. */
  client_hello = calloc(client_hello_size, sizeof(unsigned char));
  if (client_hello == NULL) {
    fprintf(stderr, "Failed to allocate buffer for ClientHello.\n");
    exit(-1);
  }
  *client_hello_len = 0;

  /* Build the TLSv1 Record with the ClientHello message. */
  buffer_append_bytes(&client_hello, &client_hello_size, client_hello_len, (unsigned char []) {
    0x16,       // Content Type: Handshake (22)
    0x03, (unsigned char)tls_record_version_low_byte, // Version: TLS 1.x
    0x00, 0x00, // Length (to be filled in later)
    0x01,       // Handshake Type: Client Hello
    0x00, 0x00, 0x00, // Length (to be filled in later)
    0x03, (unsigned char)tls_handshake_version_low_byte, // Version: TLS 1.x
  }, 11);

  /* "Random" 32 bytes. */
  uint32_t rand = htonl(time_now);
  buffer_append_uint32_t(&client_hello, &client_hello_size, client_hello_len, rand); /* The first 4 bytes is the timestamp. */

  for (int i = 1; i < 8; i++) {
    rand = rand + (time_now ^ (uint32_t)((~(i + 0) << 24) | (~(i + 1) << 16) | (~(i + 2) << 8) | (~(i + 3) << 0)));
    buffer_append_uint32_t(&client_hello, &client_hello_size, client_hello_len, rand);
  }

  /* Session ID Length: 0 */
  buffer_append_bytes(&client_hello, &client_hello_size, client_hello_len, (unsigned char []) { 0x00 }, 1);

  /* Add the length (in bytes) of the ciphersuites list to the Client Hello. */
  buffer_append_ushort(&client_hello, &client_hello_size, client_hello_len, ciphersuite_list_len);

  /* Add the ciphersuite list. */
  buffer_append_bytes(&client_hello, &client_hello_size, client_hello_len, ciphersuite_list, ciphersuite_list_len);

  /* Add the compression options. */
  buffer_append_bytes(&client_hello, &client_hello_size, client_hello_len, (unsigned char []) {
    0x01, // Compression Methods Length (1)
    0x00  // Compression Method: null (0)
  }, 2);

  /* Add the extensions to the Client Hello. */
  buffer_append_bytes(&client_hello, &client_hello_size, client_hello_len, tls_extensions, tls_extensions_len);

  /* Set the length of the Client Hello. */
  client_hello[6] = 0;
  setTLSLength(client_hello, 7, *client_hello_len - 9);

  /* Set the length of the Record Layer. */
  setTLSLength(client_hello, 3, *client_hello_len - 5);
  return client_hello;
}

/* Checks all ciphersuites that OpenSSL does not support.  When version is 0, TLSv1.0 is tested.  When set to 1, TLSv1.1 is tested.  When set to 2, TLSv1.2 is tested. */
int testMissingCiphers(struct sslCheckOptions *options, unsigned int version) {
  int ret = false, s = 0;
  unsigned char *ciphersuite_list = NULL, *client_hello = NULL, *server_hello = NULL, *tls_extensions = NULL;
  unsigned int tls_version_low_byte = 1;
  char *tls_printable_name = "TLSv1.0";


  tls_version_low_byte += version;

  if (version == 1)
    tls_printable_name = "TLSv1.1";
  else if (version == 2)
    tls_printable_name = "TLSv1.2";

  /* Continue until a Server Hello isn't received. */
  while (1) {
    int cipher_bits = -1;
    size_t client_hello_len = 0, ciphersuite_list_len = 0, tls_extensions_size = 256, tls_extensions_len = 0;
    unsigned char *client_hello = NULL, *tls_extensions = NULL;
    char *cipher_name = NULL;
    struct timeval tval_start = {0}, tval_end = {0}, tval_elapsed = {0};


    gettimeofday(&tval_start, NULL);

    tls_extensions = makeTLSExtensions(&tls_extensions_size, &tls_extensions_len, options);

    /* Extension: supported_groups */
    buffer_append_bytes(&tls_extensions, &tls_extensions_size, &tls_extensions_len, (unsigned char []) {
      0x00, 0x0a, // Extension: supported_groups (10)
      0x00, 0x1c, // Extension Length (28)
      0x00, 0x1a, // Supported Groups List Length (26)
      0x00, 0x17, // secp256r1
      0x00, 0x19, // secp521r1
      0x00, 0x1c, // brainpoolP512r1
      0x00, 0x1b, // brainpoolP384r1
      0x00, 0x18, // secp384r1
      0x00, 0x1a, // brainpoolP256r1
      0x00, 0x16, // secp256k1
      0x00, 0x0e, // sect571r1
      0x00, 0x0d, // sect571k1
      0x00, 0x0b, // sect409k1
      0x00, 0x0c, // sect409r1
      0x00, 0x09, // sect283k1
      0x00, 0x0a, // sect283r1
    }, 32);

    setTLSLength(tls_extensions, 0, tls_extensions_len - 2);

    /* Construct the list of all ciphersuites not implemented by OpenSSL. */
    makeCiphersuiteList(&ciphersuite_list, &ciphersuite_list_len, version, CIPHERSUITES_MISSING);

    client_hello = makeClientHello(&client_hello_len, options, version, ciphersuite_list, ciphersuite_list_len, tls_extensions, tls_extensions_len);

    FREE(ciphersuite_list);
    ciphersuite_list_len = 0;

    FREE(tls_extensions);
    tls_extensions_size = 0;
    tls_extensions_len = 0;

    /* Now connect to the target server. */
    s = tcpConnect(options);
    if (s == 0)
      goto done;

    /* Send the Client Hello message. */
    if (send(s, client_hello, client_hello_len, 0) <= 0) {
      printf_error("send() failed while sending Client Hello: %d (%s)\n", errno, strerror(errno));
      goto done; /* Returns false. */
    }
    FREE(client_hello);
    client_hello_len = 0;

    size_t server_hello_len = 0;
    server_hello = getServerHello(s, &server_hello_len);

    /* If we don't receive a proper Server Hello message, or its too short, abort.  We need to reach at least the session ID field (offset 44). */
    if ((server_hello == NULL) || (server_hello_len < 44))
      goto done;

    /* Close the socket, since we're done reading. */
    CLOSE(s);

    /* Check that the TLS version returned is what we sent earlier. */
    if ((server_hello[1] != 0x03) || (server_hello[2] != (unsigned char)tls_version_low_byte))
      goto done;

    /* At this point, the test is considered a success, even if the server rejects our Client Hello. */
    ret = true;

    /* Get the length of the session ID.  We must jump over this to reach the ciphersuite selected by the server. */
    unsigned int session_id_len = server_hello[43];

    /* Its impossible for one byte to overflow an unsigned int (on any modern hardware), but still... */
    if ((session_id_len + 43 + 2 + 1) < session_id_len) {
      fprintf(stderr, "Error: potential integer overflow averted (%d).\n", session_id_len);
      exit(-1);
    }

    /* Check that the session ID length wouldn't put us past our buffer boundary. */
    if ((session_id_len + 43 + 2 + 1) > server_hello_len) {
      fprintf(stderr, "Error: size of server_hello (%"SIZE_T_FMT") is not large enough to reach cipher suite (%u).\n", sizeof(server_hello), session_id_len + 43 + 2);
      exit(-1);
    }

    /* Extract the cipher ID. */
    unsigned short cipher_id = (server_hello[session_id_len + 43 + 1] << 8) | server_hello[session_id_len + 43 + 2];

    FREE(server_hello);
    server_hello_len = 0;

    /* Mark this cipher ID as supported by the server, so when we loop again, the next ciphersuite list doesn't include it. */
    markFoundCiphersuite(cipher_id, version);

    /* Get the IANA name and cipher bit strength (maybe -1 when unknown). */
    cipher_name = resolveCipherID(cipher_id, &cipher_bits);

    /* Get the number of milliseconds that have elapsed. */
    gettimeofday(&tval_end, NULL);
    timersub(&tval_end, &tval_start, &tval_elapsed);
    unsigned int milliseconds_elapsed = tval_elapsed.tv_sec * 1000 + (int)tval_elapsed.tv_usec / 1000;

    /* Output the cipher information. */
    outputCipher(options, NULL, tls_printable_name, cipher_id, cipher_name, cipher_bits, 1, milliseconds_elapsed, "");
  }

 done:
  CLOSE(s);
  FREE(ciphersuite_list);
  FREE(tls_extensions);
  FREE(client_hello);
  FREE(server_hello);
  return ret;
}

/* Enumerates all the group key exchanges for TLSv1.3.  This could potentially be adapted to support TLSv1.0 - v1.2. */
int testSupportedGroups(struct sslCheckOptions *options) {
  int ret = true;

  struct group_key_exchange {
    uint16_t group_id;
    char *group_name;
    unsigned int group_bit_strength; /* The bit strength equivalent of this group. */
    char *color;
    int nid;               /* NID for group, or -1 for X25519/X448. */
    unsigned int nid_type; /* One of the NID_TYPE_* flags. */
    uint16_t key_exchange_len;
  };

  /* Bit strength of DHE 2048 and 3072-bit moduli is taken directly from NIST SP 800-57 pt.1, rev4., pg. 53; DHE 4096, 6144, and 8192 are estimated using that document. */
#define COL_PLAIN ""
#define NID_TYPE_NA 0    /* Not Applicable (i.e.: X25519/X448) */
#define NID_TYPE_ECDHE 1 /* For P-256/384-521. */
#define NID_TYPE_DHE 2   /* For ffdhe* */
  struct group_key_exchange group_key_exchanges[] = {
    {0x001d, "X25519", 128, COL_GREEN, -1, NID_TYPE_NA, 32},
    {0x001e, "X448", 224, COL_GREEN, -1, NID_TYPE_NA, 56},

    {0x0017, "secp256r1 [P-256]", 128, COL_PLAIN, NID_X9_62_prime256v1, NID_TYPE_ECDHE, 0},
    {0x0018, "secp384r1 [P-384]", 192, COL_PLAIN, NID_secp384r1, NID_TYPE_ECDHE, 0},
    {0x0019, "secp521r1 [P-521]", 256, COL_PLAIN, NID_secp521r1, NID_TYPE_ECDHE, 0},

    {0x0100, "ffdhe2048", 112, COL_PLAIN, NID_ffdhe2048, NID_TYPE_DHE, 256},
    {0x0101, "ffdhe3072", 128, COL_PLAIN, NID_ffdhe3072, NID_TYPE_DHE, 384},
    {0x0102, "ffdhe4096", 150, COL_PLAIN, NID_ffdhe4096, NID_TYPE_DHE, 512},
    {0x0103, "ffdhe6144", 175, COL_PLAIN, NID_ffdhe6144, NID_TYPE_DHE, 768},
    {0x0104, "ffdhe8192", 192, COL_PLAIN, NID_ffdhe8192, NID_TYPE_DHE, 1024},
  };

  unsigned int printed_header = 0;
  int s = 0;
  unsigned char *client_hello = NULL, *ciphersuite_list = NULL, *tls_extensions = NULL, *server_hello = NULL, *key_exchange = NULL;
  size_t client_hello_len = 0, tls_extensions_size = 0, tls_extensions_len = 0, ciphersuite_list_len = 0, server_hello_len = 0, key_exchange_len = 0;


  /* Get all TLSv1.3 ciphersuites. */
  makeCiphersuiteList(&ciphersuite_list, &ciphersuite_list_len, 3, CIPHERSUITES_TLSV1_3_ALL);

  /* For each key exchange group... */
  for (int i = 0; i < (sizeof(group_key_exchanges) / sizeof(struct group_key_exchange)); i++) {
    uint16_t group_id = group_key_exchanges[i].group_id;
    char *group_name = group_key_exchanges[i].group_name;
    char *color = group_key_exchanges[i].color;
    unsigned int group_bit_strength = group_key_exchanges[i].group_bit_strength;
    int nid = group_key_exchanges[i].nid;
    unsigned nid_type = group_key_exchanges[i].nid_type;
    key_exchange_len = group_key_exchanges[i].key_exchange_len;

    /* This will hold the key exchange data that we send to the server. */
    key_exchange = calloc(key_exchange_len, sizeof(unsigned char));
    if (key_exchange == NULL) {
      fprintf(stderr, "Failed to create buffer for key exchange.\n");
      exit(-1);
    }

    /* Generate the right type of key exchange data. */
    if (nid_type == NID_TYPE_NA) {

      /* Generate "random" data.  X25519 and X448 public keys have no discernible structure. */
      srand(time(NULL) ^ 0xdeadbeef);
      for (int j = 0; j < key_exchange_len; j++)
	key_exchange[j] = rand();

    } else if (nid_type == NID_TYPE_ECDHE) {
      /* Free the buffer, since we will dynamically get the size we need and create a new one. */
      FREE(key_exchange); key_exchange_len = 0;

      /* Generate the ECDHE key. */
      EC_KEY *key = EC_KEY_new_by_curve_name(nid);
      if ((key == NULL) || (EC_KEY_generate_key(key) != 1)) {
	EC_KEY_free(key); key = NULL;
        fprintf(stderr, "Failed to generate ECDHE key for nid %d\n", nid);
        continue;
      }

      /* Allocate a *new* byte array and put the key into it. */
      unsigned char *kex_buf = NULL;
      key_exchange_len = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &kex_buf, NULL);
      if (kex_buf == NULL) {
	EC_KEY_free(key); key = NULL;
	fprintf(stderr, "Failed to obtain ECDHE public key bytes.\n");
	continue;
      }

      /* The byte array created above needs to be freed with OPENSSL_free(), not free().  To simplify the code, we will copy the bytes to our own array and call OPENSSL_free() immediately. */
      key_exchange = calloc(key_exchange_len, sizeof(unsigned char));
      if (key_exchange == NULL) {
	fprintf(stderr, "Failed to create buffer for key exchange.\n");
	exit(-1);
      }
      memcpy(key_exchange, kex_buf, key_exchange_len);
      OPENSSL_free(kex_buf); kex_buf = NULL;
      EC_KEY_free(key); key = NULL;

    } else if (nid_type == NID_TYPE_DHE) {

      /* The value (Y) for FFDHE group must be 1 < Y < p - 1 (see RFC7919).  Furthermore, GnuTLS checks that Y ^ q mod p == 1 (see GnuTLS v3.6.11.1, lib/nettle/pk.c:291).  The easiest way to do this seems to be to actually generate real DH public keys. */
      DH *dh = DH_new_by_nid(nid);
      if (!DH_generate_key(dh)) {
	FREE(key_exchange);
	fprintf(stderr, "Failed to generate DH key for nid %d\n", nid);
	continue;
      }

      /* Export the public key to our byte array. */
      const BIGNUM *pub_key = NULL;
      DH_get0_key(dh, &pub_key, NULL);
      if (!BN_bn2binpad(pub_key, key_exchange, key_exchange_len)) {
	FREE(key_exchange);
	fprintf(stderr, "Failed to get DH key for nid %d\n", nid);
	continue;
      }

    } else {
      /* Use the provided value, since it must be a specific format. */
      //memcpy(key_exchange, group_key_exchanges[i].key_exchange, key_exchange_len);
      fprintf(stderr, "Error: unknown NID_TYPE in struct: %d\n", nid_type);
      exit(-1);
    }

    /* Make generic TLS extensions (with SNI, accepted EC point formats, etc). */
    tls_extensions = makeTLSExtensions(&tls_extensions_size, &tls_extensions_len, options);

    /* Add the supported_versions extension to signify we are using TLS v1.3. */
    tlsExtensionAddTLSv1_3(&tls_extensions, &tls_extensions_size, &tls_extensions_len);

    /* Add the supported_groups extension.  Only add the one group we are testing for. */
    buffer_append_bytes(&tls_extensions, &tls_extensions_size, &tls_extensions_len, (unsigned char []) {
      0x00, 0x0a, // Extension Type: supported_groups (10)
      0x00, 0x04, // Extension Length (4)
      0x00, 0x02, // Supported Groups List Length (2)
    }, 6);
    buffer_append_ushort(&tls_extensions, &tls_extensions_size, &tls_extensions_len, group_id);

    /* Add the key_share extension for the current group type. */
    buffer_append_bytes(&tls_extensions, &tls_extensions_size, &tls_extensions_len, (unsigned char []) { 0x00, 0x33 }, 2); // Extension Type: key_share (51)
    buffer_append_ushort(&tls_extensions, &tls_extensions_size, &tls_extensions_len, key_exchange_len + 6); // Extension Length
    buffer_append_ushort(&tls_extensions, &tls_extensions_size, &tls_extensions_len, key_exchange_len + 4); // Client Key Share Length
    buffer_append_ushort(&tls_extensions, &tls_extensions_size, &tls_extensions_len, group_id); // Group ID.
    buffer_append_ushort(&tls_extensions, &tls_extensions_size, &tls_extensions_len, key_exchange_len); // Key Exchange Length
    buffer_append_bytes(&tls_extensions, &tls_extensions_size, &tls_extensions_len, key_exchange, key_exchange_len); // Key Exchange

    FREE(key_exchange);
    key_exchange_len = 0;

    /* Update the TLS extensions length since we manually added to it. */
    setTLSLength(tls_extensions, 0, tls_extensions_len - 2);

    client_hello = makeClientHello(&client_hello_len, options, 3, ciphersuite_list, ciphersuite_list_len, tls_extensions, tls_extensions_len);

    FREE(tls_extensions);
    tls_extensions_size = 0;
    tls_extensions_len = 0;

    /* Now connect to the target server. */
    s = tcpConnect(options);
    if (s == 0) {
      ret = false;
      goto done;
    }

    /* Send the Client Hello message. */
    if (send(s, client_hello, client_hello_len, 0) <= 0) {
      printf_error("send() failed while sending Client Hello: %d (%s)\n", errno, strerror(errno));
      ret = false;
      goto done;
    }
    FREE(client_hello);
    client_hello_len = 0;

    server_hello = getServerHello(s, &server_hello_len);
    CLOSE(s);

    /* This group is not supported. */
    if (server_hello == NULL)
      continue;

    FREE(server_hello);
    server_hello_len = 0;

    if (!printed_header) {
      printf("\n  %sServer Key Exchange Group(s):%s\n", COL_BLUE, RESET);
      printed_header = 1;
    }
    printf("%s%s%s (%d bits)\n", color, group_name, RESET, group_bit_strength);
    printf_xml("  <group sslversion=\"TLSv1.3\" bits=\"%d\" name=\"%s\" />\n", group_bit_strength, group_name);
  }

 done:
  CLOSE(s);
  FREE(ciphersuite_list);
  ciphersuite_list_len = 0;

  FREE(tls_extensions);
  tls_extensions_size = 0;
  tls_extensions_len = 0;

  FREE(client_hello);
  client_hello_len = 0;

  FREE(server_hello);
  server_hello_len = 0;
  return ret;
}

/* MinGW doesn't have a memmem() implementation. */
#ifdef _WIN32

/* Implementation taken from: https://sourceforge.net/p/mingw/msys2-runtime/ci/f21dc72d306bd98e55a08461a9530c4b0ce1dffe/tree/newlib/libc/string/memmem.c#l80 */
/* Copyright (C) 2008 Eric Blake
 * Permission to use, copy, modify, and distribute this software
 * is freely granted, provided that this notice is preserved.*/
void *memmem(const void *haystack_start, size_t haystack_len, const void *needle, size_t needle_len) {
  const unsigned char *haystack = (const unsigned char *) haystack_start;
  //const unsigned char *needle = (const unsigned char *) needle_start;

  if (needle_len == 0)
    return (void *)haystack;

  while (needle_len <= haystack_len)
    {
      if (!memcmp (haystack, needle, needle_len))
        return (void *) haystack;
      haystack++;
      haystack_len--;
    }
  return NULL;
}
#endif

/* vim :set ts=4 sw=4 sts=4 et : */
