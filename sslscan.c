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

#include "sslscan.h"

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

// Helper function to recv from socket until EOF or an error
static ssize_t recvall(int sockfd, void *buf, size_t len, int flags)
{
    size_t remaining = len;
    char *bufptr = buf;
    do
    {
        ssize_t actual = recv(sockfd, bufptr, remaining, flags);
        if (actual <= 0) // premature eof or an error?
        {
            return actual;
        }
        bufptr += actual;
        remaining -= actual;
    } while (remaining != 0);
    return (ssize_t) len;
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
    options->ctx = SSL_CTX_new(sslMethod);
    if (options->ctx == NULL) {
        printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        return false;
    }
    SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL");
    ssl = SSL_new(options->ctx);
    if (ssl == NULL) {
        printf_error("%sERROR: Could not create SSL object.%s\n", COL_RED, RESET);
        SSL_CTX_free(options->ctx);
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
    SSL_free(ssl);
    SSL_CTX_free(options->ctx);
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

    n = recvall(fd, buffer, len - 1, 0);

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
        if (1 != recvall(socketDescriptor, &buffer, 1, 0)) {
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
        if (4 != recvall(socketDescriptor, buffer, 4, 0)) {
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
        if (readlen != recvall(socketDescriptor, buffer, readlen, 0)) {
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
    SSL_SESSION session;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        options->ctx = SSL_CTX_new(sslMethod);
        tls_reneg_init(options);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);

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

                        session = *SSL_get_session(ssl);

#ifndef OPENSSL_NO_COMP
                        // Make sure zlib is actually present
                        if (COMP_zlib()->type != NID_undef)
                        {
                            printf_xml("  <compression supported=\"%d\" />\n",
                                session.compress_meth);

                            if (session.compress_meth == 0)
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
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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
        options->ctx = SSL_CTX_new(sslMethod);
        tls_reneg_init(options);
        if (options->ctx != NULL)
        {
            if (downgraded)
            {
                SSL_CTX_set_mode(options->ctx, SSL_MODE_SEND_FALLBACK_SCSV);
            }
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);

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
                        if (connStatus)
                        {
                            if (!downgraded)
                            {
                                sslversion = SSL_version(ssl);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                                if (sslversion == TLS1_2_VERSION)
                                {
                                    secondMethod = TLSv1_1_client_method();
                                }
                                else if (sslversion == TLS1_1_VERSION)
                                {
                                    secondMethod = TLSv1_client_method();
                                } else
#endif
                                if (sslversion == TLS1_VERSION)
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
                                printf_xml("  <fallback supported=\"0\" />\n");
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
                                        printf_xml("  <fallback supported=\"1\" />\n");
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
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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
        options->ctx = SSL_CTX_new(sslMethod);
        tls_reneg_init(options);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);

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
                      if (use_unsafe_renegotiation_flag) {
                        printf_verbose("use_unsafe_renegotiation_flag\n");
                        ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
                      }
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

                                if (SSL_get_state(ssl) == SSL_ST_OK)
                                {
                                    res = SSL_do_handshake(ssl); // Send renegotiation request to server
                                    if( res != 1 )
                                    {
                                        printf_error("\n\nSSL_do_handshake() call failed\n");
                                    }
                                    if (SSL_get_state(ssl) == SSL_ST_OK)
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
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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
#ifndef OPENSSL_NO_SSL2
    if (sslMethod == SSLv2_client_method())
        return "SSLv2";
#endif
#ifndef OPENSSL_NO_SSL3
    if (sslMethod == SSLv3_client_method())
        return "SSLv3";
#endif
    if (sslMethod == TLSv1_client_method())
        return "TLSv1.0";
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    if (sslMethod == TLSv1_1_client_method())
        return "TLSv1.1";
    if (sslMethod == TLSv1_2_client_method())
        return "TLSv1.2";
#endif
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
        if (send(socketDescriptor, hb, sizeof(hb), 0) <= 0) {
            printf_error("send() failed: %s\n", strerror(errno));
            exit(1);
        }

        char hbbuf[65536];

        while(1)
        {
            memset(hbbuf, 0, sizeof(hbbuf));

            // Read 5 byte header
            int readResult = recvall(socketDescriptor, hbbuf, 5, 0);
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
            readResult = recvall(socketDescriptor, hbbuf, ln, 0);
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
#ifndef OPENSSL_NO_EC
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
#endif
    }
    EVP_PKEY_free(key);
    return 1;
#endif
    return 0;
}


// Test a cipher...
int testCipher(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int cipherStatus;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    BIO *stdoutBIO = NULL;
    int tempInt;
    char requestBuffer[200];
    char buffer[50];
    char hexCipherId[10];
    int resultSize = 0;
    int cipherbits;
    uint32_t cipherid;
    const SSL_CIPHER *sslCipherPointer;
    const char *cleanSslMethod = printableSslMethod(sslMethod);
    struct timeval tval_start, tval_end, tval_elapsed;
    if (options->showTimes)
    {
        gettimeofday(&tval_start, NULL);
    }



    // Create request buffer...
    memset(requestBuffer, 0, 200);
    snprintf(requestBuffer, 199, "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n", options->host);

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        if (SSL_CTX_set_cipher_list(options->ctx, options->cipherstring) != 0)
        {

            // Create SSL object...
            ssl = SSL_new(options->ctx);


            if (ssl != NULL)
            {
                // Connect socket and BIO
                cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

                // Connect SSL and BIO
                SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                // This enables TLS SNI
                SSL_set_tlsext_host_name (ssl, options->sniname);
#endif

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

                // Show Cipher Status
                printf_xml("  <cipher status=\"");
                if (cipherStatus == 1)
                {
                    if (strcmp(options->cipherstring, "ALL:eNULL"))
                    {
                        printf_xml("accepted\"");
                        printf("Accepted  ");
                    }
                    else
                    {
                        printf_xml("preferred\"");
                        printf("%sPreferred%s ", COL_GREEN, RESET);
                    }
                    if (options->http == true)
                    {

                        // Stdout BIO...
                        if (!xml_to_stdout) {
                            stdoutBIO = BIO_new(BIO_s_file());
                            BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
                        }

                        // HTTP Get...
                        SSL_write(ssl, requestBuffer, sizeof(requestBuffer));
                        memset(buffer ,0 , 50);
                        resultSize = SSL_read(ssl, buffer, 49);
                        if (resultSize > 9)
                        {
                            int loop = 0;
                            for (loop = 9; (loop < 49) && (buffer[loop] != 0) && (buffer[loop] != '\r') && (buffer[loop] != '\n'); loop++)
                            { }
                            buffer[loop] = 0;

                            // Output HTTP code...
                            printf("%s", buffer + 9);
                            loop = strlen(buffer + 9);
                            while (loop < 17)
                            {
                                loop++;
                                printf(" ");
                            }
                            printf_xml(" http=\"%s\"", buffer + 9);
                        }
                        else
                        {
                            // Output HTTP code...
                            printf("                 ");
                        }
                    }
                }
                printf_xml(" sslversion=\"%s\"", cleanSslMethod);
#ifndef OPENSSL_NO_SSL2
                if (strcmp(cleanSslMethod, "SSLv2") == 0)
                {
                    printf("%sSSLv2%s    ", COL_RED, RESET);
                }
                else
#endif
#ifndef OPENSSL_NO_SSL3
                    if (strcmp(cleanSslMethod, "SSLv3") == 0)
                    {
                        printf("%sSSLv3%s    ", COL_RED, RESET);
                    }
                    else
#endif
                        if (strcmp(cleanSslMethod, "TLSv1.0") == 0)
                        {
                            printf("%sTLSv1.0%s  ", COL_YELLOW, RESET);
                        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                        else 
                        {
                            printf("%s  ", cleanSslMethod);
                        }
#endif
                if (cipherbits < 10)
                    tempInt = 2;
                else if (cipherbits < 100)
                    tempInt = 1;
                else
                    tempInt = 0;
                if (cipherbits == 0)
                {
                    printf("%s%d%s bits  ", COL_RED_BG, cipherbits, RESET);
                }
                else if (cipherbits >= 112)
                {
                    printf("%s%d%s bits  ", COL_GREEN, cipherbits, RESET);
                }
                else if (cipherbits > 56)
                {
                    printf("%s%d%s bits  ", COL_YELLOW, cipherbits, RESET);
                }
                else
                {
                    printf("%s%d%s bits  ", COL_RED, cipherbits, RESET);
                }
                while (tempInt != 0)
                {
                    tempInt--;
                    printf(" ");
                }

                sprintf(hexCipherId, "0x%X", cipherid);

                if (options->showCipherIds == true)
                {
                    printf("%8s ", hexCipherId);
                }

                printf_xml(" bits=\"%d\" cipher=\"%s\" id=\"%s\"", cipherbits, sslCipherPointer->name, hexCipherId);
                if (strstr(sslCipherPointer->name, "NULL"))
                {
                    printf("%s%-29s%s", COL_RED_BG, sslCipherPointer->name, RESET);
                }
                else if (strstr(sslCipherPointer->name, "ADH") || strstr(sslCipherPointer->name, "AECDH"))
                {
                    printf("%s%-29s%s", COL_PURPLE, sslCipherPointer->name, RESET);
                }
                else if (strstr(sslCipherPointer->name, "EXP"))
                {
                    printf("%s%-29s%s", COL_RED, sslCipherPointer->name, RESET);
                }
                else if (strstr(sslCipherPointer->name, "RC4") || strstr(sslCipherPointer->name, "DES"))
                {
                    printf("%s%-29s%s", COL_YELLOW, sslCipherPointer->name, RESET);
                }
                else if ((strstr(sslCipherPointer->name, "CHACHA20") || (strstr(sslCipherPointer->name, "GCM")))
                        && strstr(sslCipherPointer->name, "DHE"))
                {
                    printf("%s%-29s%s", COL_GREEN, sslCipherPointer->name, RESET);
                }
                else
                {
                    printf("%-29s", sslCipherPointer->name);
                }

                if (options->cipher_details == true)
                {
                    ssl_print_tmp_key(options, ssl);
                }
                // Timing
                if (options->showTimes)
                {
                    int msec;
                    gettimeofday(&tval_end, NULL);
                    timersub(&tval_end, &tval_start, &tval_elapsed);
                    msec = tval_elapsed.tv_sec * 1000 + (int)tval_elapsed.tv_usec/1000;
                    printf("%s %dms%s", COL_GREY, msec, RESET);
                    printf_xml(" time=\"%d\"", msec);
                }

                printf("\n");
                printf_xml(" />\n");

                // Disconnect SSL over socket
                if (cipherStatus == 1)
                {
                    strncat(options->cipherstring, ":!", 2);
                    strncat(options->cipherstring, SSL_get_cipher_name(ssl), strlen(SSL_get_cipher_name(ssl)));
                    SSL_shutdown(ssl);
                }

                // Free SSL object
                SSL_free(ssl);
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
        close(socketDescriptor);
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
    options->ctx = SSL_CTX_new(sslMethod);
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

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {

            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);
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
                                    i2t_ASN1_OBJECT(certAlgorithm, sizeof(certAlgorithm), x509Cert->cert_info->signature->algorithm);
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
                                        i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->signature->algorithm);
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
                                        switch (publicKey->type)
                                        {
                                            case EVP_PKEY_RSA:
                                                if (publicKey->pkey.rsa)
                                                {
                                                    keyBits = BN_num_bits(publicKey->pkey.rsa->n);
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

                                                    printf_xml("   <pk error=\"false\" type=\"RSA\" bits=\"%d\" />\n", BN_num_bits(publicKey->pkey.rsa->n));
                                                }
                                                else
                                                {
                                                    printf("    RSA Public Key: NULL\n");
                                                }
                                                printf("\n");
                                                break;
                                            case EVP_PKEY_DSA:
                                                if (publicKey->pkey.dsa)
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
                                                if (publicKey->pkey.ec)
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
                                        if (sk_X509_EXTENSION_num(x509Cert->cert_info->extensions) > 0)
                                        {
                                            cnindex = X509_get_ext_by_NID (x509Cert, NID_subject_alt_name, -1);
                                            if (cnindex != -1)
                                            {
                                                extension = X509v3_get_ext(x509Cert->cert_info->extensions,cnindex);

                                                printf("Altnames: ");
                                                if (!X509V3_EXT_print(stdoutBIO, extension, X509_FLAG_COMPAT, 0))
                                                {
                                                    M_ASN1_OCTET_STRING_print(stdoutBIO, extension->value);
                                                }
                                                if (options->xmlOutput)
                                                {
                                                    printf_xml("   <altnames><![CDATA[");
                                                    if (!X509V3_EXT_print(fileBIO, extension, X509_FLAG_COMPAT, 0))
                                                        M_ASN1_OCTET_STRING_print(fileBIO, extension->value);
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
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specify TLS version\n");
            sslMethod = TLSv1_method();
        }
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {

            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);
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
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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

static int ocsp_resp_cb(SSL *s, void *arg)
{
	const unsigned char *p;
	int len;
	OCSP_RESPONSE *rsp;
	len = SSL_get_tlsext_status_ocsp_resp(s, &p);
	if (!p) {
		printf("No OCSP response sent\n\n");
		return 1;
	}
	rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
	if (!rsp){
		printf("OCSP response parse error\n");
		return 0;
	}

	BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
    int i = 0;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = rsp->responseBytes;

	//Pretty print response status
	l = ASN1_ENUMERATED_get(rsp->responseStatus);
	if (BIO_printf(bio_out, "OCSP Response Status: %s (0x%lx)\n",
				   OCSP_response_status_str(l), l) <= 0)
		goto err;

	//Check for null response bytes
	if (rb == NULL)
		return 1;
	i = ASN1_STRING_length(rb->response);
	if ((br = OCSP_response_get1_basic(rsp)) == NULL)
		goto err;
	rd = br->tbsResponseData;
	l = ASN1_INTEGER_get(rd->version);

	//Pretty print responder id
	if(BIO_puts(bio_out, "Responder Id: ") <= 0)
		goto err;
	rid = rd->responderId;
	switch (rid->type){
	case V_OCSP_RESPID_NAME:
		X509_NAME_print_ex(bio_out, rid->value.byName, 0, XN_FLAG_ONELINE);
		break;
	case V_OCSP_RESPID_KEY:
		i2a_ASN1_STRING(bio_out, rid->value.byKey, V_ASN1_OCTET_STRING);
		break;
	}

	if(BIO_printf(bio_out, "\nProduced At: ") <= 0)
		goto err;
	if (!ASN1_GENERALIZEDTIME_print(bio_out, rd->producedAt))
		goto err;
	if (BIO_printf(bio_out, "\nResponses:\n") <= 0)
		goto err;
	for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++)
	{
       if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
            continue;
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        cid = single->certId;
        if (ocsp_certid_print(bio_out, cid, 4) <= 0)
            goto err;
        cst = single->certStatus;
        if (cst->type == V_OCSP_CERTSTATUS_GOOD)
        {
            if (BIO_printf(bio_out, "Cert Status: %s%s%s\n\n",
                           COL_GREEN, OCSP_cert_status_str(cst->type), RESET) <= 0)
                goto err;
        }
        else if (cst->type == V_OCSP_CERTSTATUS_UNKNOWN)
        {
            if (BIO_printf(bio_out, "Cert Status: %s%s%s\n\n",
                           COL_YELLOW, OCSP_cert_status_str(cst->type), RESET) <= 0)
                goto err;
        }
        else
        {
            rev = cst->value.revoked;
            if (BIO_printf(bio_out, "\nRevocation Time: \n\n") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bio_out, rev->revocationTime))
                goto err;
            if (rev->revocationReason) {
                l = ASN1_ENUMERATED_get(rev->revocationReason);
                if (BIO_printf(bio_out,
                               "\nRevocation Reason: %s (0x%lx)\n\n",
                               OCSP_crl_reason_str(l), l) <= 0)
                    goto err;
            }
        }
	}
	err:
		OCSP_RESPONSE_free(rsp);
    return 1;
	
}

int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent)
{
    BIO_printf(bp, "%*sHash Algorithm: ", indent, "");
    i2a_ASN1_OBJECT(bp, a->hashAlgorithm->algorithm);
    BIO_printf(bp, "\n%*sIssuer Name Hash: ", indent, "");
    i2a_ASN1_STRING(bp, a->issuerNameHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
    i2a_ASN1_STRING(bp, a->issuerKeyHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
    i2a_ASN1_INTEGER(bp, a->serialNumber);
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
#endif
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specify TLS version\n");
            sslMethod = TLSv1_method();
        }
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);
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
                                    printf("    Signature Algorithm: ");
                                    i2a_ASN1_OBJECT(stdoutBIO, x509Cert->cert_info->signature->algorithm);
                                    printf("\n");
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <signature-algorithm>");
                                        i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->signature->algorithm);
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
                                    i2a_ASN1_OBJECT(stdoutBIO, x509Cert->cert_info->key->algor->algorithm);
                                    printf("\n");
                                    if (options->xmlOutput)
                                    {
                                        printf_xml("   <pk-algorithm>");
                                        i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->key->algor->algorithm);
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
                                        switch (publicKey->type)
                                        {
                                            case EVP_PKEY_RSA:
                                                if (publicKey->pkey.rsa)
                                                {
                                                    printf("    RSA Public Key: (%d bit)\n", BN_num_bits(publicKey->pkey.rsa->n));
                                                    printf_xml("   <pk error=\"false\" type=\"RSA\" bits=\"%d\">\n", BN_num_bits(publicKey->pkey.rsa->n));
                                                    RSA_print(stdoutBIO, publicKey->pkey.rsa, 6);
                                                    if (options->xmlOutput)
                                                    {
                                                        RSA_print(fileBIO, publicKey->pkey.rsa, 4);
                                                        printf_xml("   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    RSA Public Key: NULL\n");
                                                }
                                                break;
                                            case EVP_PKEY_DSA:
                                                if (publicKey->pkey.dsa)
                                                {
                                                    printf("    DSA Public Key:\n");
                                                    printf_xml("   <pk error=\"false\" type=\"DSA\">\n");
                                                    DSA_print(stdoutBIO, publicKey->pkey.dsa, 6);
                                                    if (options->xmlOutput)
                                                    {
                                                        DSA_print(fileBIO, publicKey->pkey.dsa, 4);
                                                        printf_xml("   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    DSA Public Key: NULL\n");
                                                }
                                                break;
                                            case EVP_PKEY_EC:
                                                if (publicKey->pkey.ec)
                                                {
                                                    printf("    EC Public Key:\n");
                                                    printf_xml("   <pk error=\"false\" type=\"EC\">\n");
                                                    EC_KEY_print(stdoutBIO, publicKey->pkey.ec, 6);
                                                    if (options->xmlOutput)
                                                    {
                                                        EC_KEY_print(fileBIO, publicKey->pkey.ec, 4);
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
                                    if (sk_X509_EXTENSION_num(x509Cert->cert_info->extensions) > 0)
                                    {
                                        printf("    X509v3 Extensions:\n");
                                        printf_xml("   <X509v3-Extensions>\n");
                                        for (tempInt = 0; tempInt < sk_X509_EXTENSION_num(x509Cert->cert_info->extensions); tempInt++)
                                        {
                                            // Get Extension...
                                            extension = sk_X509_EXTENSION_value(x509Cert->cert_info->extensions, tempInt);

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
                                                M_ASN1_OCTET_STRING_print(stdoutBIO, extension->value);
                                            }
                                            if (options->xmlOutput)
                                            {
                                                if (!X509V3_EXT_print(fileBIO, extension, X509_FLAG_COMPAT, 0))
                                                    M_ASN1_OCTET_STRING_print(fileBIO, extension->value);
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
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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
#endif
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specify TLS version\n");
            sslMethod = TLSv1_method();
        }
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {
                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);
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

                            sk2=SSL_get_client_CA_list(ssl);
                            if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0))
                            {
                                printf("\n  %sAcceptable client certificate CA names:%s\n", COL_BLUE, RESET);
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

                            // Free BIO
                            BIO_free(stdoutBIO);
                            if (options->xmlOutput)
                                BIO_free(fileBIO);

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        SSL_free(ssl);
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
            SSL_CTX_free(options->ctx);
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
    strncpy(options->cipherstring, "ALL:eNULL", 10);

    // Loop until the server won't accept any more ciphers
    while (status == true)
    {
        // Setup Context Object...
        options->ctx = SSL_CTX_new(sslMethod);
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

            // Test the cipher
            if (status == true)
                status = testCipher(options, sslMethod);

            // Free CTX Object
            SSL_CTX_free(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
            return false;
        }
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
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                populateCipherList(options, TLSv1_2_client_method());
                populateCipherList(options, TLSv1_1_client_method());
#endif
                populateCipherList(options, TLSv1_client_method());
#ifndef OPENSSL_NO_SSL3
                populateCipherList(options, SSLv3_client_method());
#endif
#ifndef OPENSSL_NO_SSL2
                populateCipherList(options, SSLv2_client_method());
#endif
                break;
            case tls_all:
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                populateCipherList(options, TLSv1_2_client_method());
                populateCipherList(options, TLSv1_1_client_method());
#endif
                populateCipherList(options, TLSv1_client_method());
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
#ifndef OPENSSL_NO_SSL3
            case ssl_v3:
                populateCipherList(options, SSLv3_client_method());
                break;
#endif
#ifndef OPENSSL_NO_SSL2
            case ssl_v2:
                populateCipherList(options, SSLv2_client_method());
                break;
#endif
        }
        printf("\n  %sSupported Client Cipher(s):%s\n", COL_BLUE, RESET);
        sslCipherPointer = options->ciphers;
        while ((sslCipherPointer != 0) && (status == true))
        {
            printf("    %s\n",sslCipherPointer->name);
            printf_xml("  <client-cipher cipher=\"%s\" />\n", sslCipherPointer->name);

            sslCipherPointer = sslCipherPointer->next;
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
        // Test supported ciphers...
        printf("  %sSupported Server Cipher(s):%s\n", COL_BLUE, RESET);
        switch (options->sslVersion)
        {
            case ssl_all:
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_2_client_method());
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_1_client_method());
#endif
                if (status != false)
                    status = testProtocolCiphers(options, TLSv1_client_method());
#ifndef OPENSSL_NO_SSL3
                if (status != false)
                    status = testProtocolCiphers(options, SSLv3_client_method());
#endif
#ifndef OPENSSL_NO_SSL2
                if (status != false)
                    status = testProtocolCiphers(options, SSLv2_client_method());
#endif
                break;
#ifndef OPENSSL_NO_SSL2
            case ssl_v2:
                status = testProtocolCiphers(options, SSLv2_client_method());
                break;
#endif
#ifndef OPENSSL_NO_SSL3
            case ssl_v3:
                status = testProtocolCiphers(options, SSLv3_client_method());
                break;
#endif
            case tls_all:
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
#endif
        }
    }

    // Print certificate
    if (status == true && options->showCertificate == true)
    {
        status = showCertificate(options);
    }

    // Show weak certificate signing algorithm or key strength
    if (status == true && options->checkCertificate == true)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        if (status != false)
            {
            status = checkCertificateProtocol(options, TLSv1_2_client_method());
            }
        if (status != false)
            status = checkCertificateProtocol(options, TLSv1_1_client_method());
#endif
        if (status != false)
            status = checkCertificateProtocol(options, TLSv1_client_method());
#ifndef OPENSSL_NO_SSL3
        if (status != false)
            status = checkCertificateProtocol(options, SSLv3_client_method());
#endif
#ifndef OPENSSL_NO_SSL2
        if (status != false)
            status = checkCertificateProtocol(options, SSLv2_client_method());
#endif
    }

    // Print client auth trusted CAs
    if (status == true && options->showTrustedCAs == true)
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

#ifndef OPENSSL_NO_SSL2
        // SSL v2 only...
        else if (strcmp("--ssl2", argv[argLoop]) == 0)
            options.sslVersion = ssl_v2;
#endif
#ifndef OPENSSL_NO_SSL3
        // SSL v3 only...
        else if (strcmp("--ssl3", argv[argLoop]) == 0)
            options.sslVersion = ssl_v3;
#endif
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

    switch (mode)
    {
        case mode_version:
            printf("%s\t\t%s\n\t\t%s\n%s", COL_BLUE, VERSION,
                    SSLeay_version(SSLEAY_VERSION), RESET);
#ifdef OPENSSL_NO_SSL2
            printf("\t\t%sOpenSSL version does not support SSLv2%s\n", COL_RED, RESET);
            printf("\t\t%sSSLv2 ciphers will not be detected%s\n", COL_RED, RESET);
#endif
#ifdef OPENSSL_NO_SSL3
            printf("\t\t%sOpenSSL version does not support SSLv3%s\n", COL_RED, RESET);
            printf("\t\t%sSSLv3 ciphers will not be detected%s\n", COL_RED, RESET);
#endif
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
#ifdef OPENSSL_NO_SSL3
            printf("%sOpenSSL version does not support SSLv3%s\n", COL_RED, RESET);
            printf("%sSSLv3 ciphers will not be detected%s\n", COL_RED, RESET);
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
#ifndef OPENSSL_NO_SSL2
            printf("  %s--ssl2%s               Only check SSLv2 ciphers\n", COL_GREEN, RESET);
#endif
#ifndef OPENSSL_NO_SSL3
            printf("  %s--ssl3%s               Only check SSLv3 ciphers\n", COL_GREEN, RESET);
#endif
            printf("  %s--tls10%s              Only check TLSv1.0 ciphers\n", COL_GREEN, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            printf("  %s--tls11%s              Only check TLSv1.1 ciphers\n", COL_GREEN, RESET);
            printf("  %s--tls12%s              Only check TLSv1.2 ciphers\n", COL_GREEN, RESET);
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
#ifdef OPENSSL_NO_SSL2
            printf("%sOpenSSL version does not support SSLv2%s\n", COL_RED, RESET);
            printf("%sSSLv2 ciphers will not be detected%s\n\n", COL_RED, RESET);
#endif
#ifdef OPENSSL_NO_SSL3
            printf("%sOpenSSL version does not support SSLv3%s\n", COL_RED, RESET);
            printf("%sSSLv3 ciphers will not be detected%s\n", COL_RED, RESET);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10001000L
            printf("\t\t%sOpenSSL version does not support TLSv1.1%s\n", COL_RED, RESET);
            printf("\t\t%sTLSv1.1 ciphers will not be detected%s\n", COL_RED, RESET);
            printf("\t\t%sOpenSSL version does not support TLSv1.2%s\n", COL_RED, RESET);
            printf("\t\t%sTLSv1.2 ciphers will not be detected%s\n", COL_RED, RESET);
#endif

            SSLeay_add_all_algorithms();
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
