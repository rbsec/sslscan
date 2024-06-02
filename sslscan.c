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
  #include <winbase.h>
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
  #include <fcntl.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <openssl/ec.h>
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

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

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
  SSL_CTX_set_quiet_shutdown(ret, 1);
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
        printf_error("Could not create CTX object.");
        return false;
    }
    SSL_CTX_set_cipher_list(options->ctx, CIPHERSUITE_LIST_ALL);
    ssl = new_SSL(options->ctx);
    if (ssl == NULL) {
        printf_error("Could not create SSL object.");
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
        printf_error("Error reading from %s:%d: %s", options->host, options->port, strerror(errno));
        close(fd);
        return 0;
    } else if (n == 0) {
        printf_error("Unexpected EOF reading from %s:%d", options->host, options->port);
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

char *sock_strerror(int err)
{
#ifdef _WIN32
    static char msg[255];

    msg[0] = '\0';

    if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msg, sizeof(msg), NULL) == 0 || msg[0] == '\0')
    {
        sprintf(msg, "Error code %d", err);
    }

    return msg;
#else
    return strerror(err);
#endif
}

int tcpConnectSocket(int socket, struct sslCheckOptions *options, char *error, int errlen)
{
    int status = -1, flags, errn = 0, len;
    fd_set rset, wset, eset;
    struct timeval tval;

#ifdef _WIN32
#define INPROGRESS  WSAEWOULDBLOCK
#define sock_errno WSAGetLastError()
    flags = 1;

    if ((status = ioctlsocket(socket, FIONBIO, (u_long *)&flags)) != 0)
    {
        snprintf(error, errlen, "ioctlsocket: %s", sock_strerror(sock_errno));
        return status;
    }
#else
#define INPROGRESS  EINPROGRESS
#define sock_errno errno
    if ((flags = fcntl(socket, F_GETFL, 0)) < 0)
    {
        snprintf(error, errlen, "fcntl getfl: %s", sock_strerror(sock_errno));
        return status;
    }

    if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        snprintf(error, errlen, "fcntl setfl: %s", sock_strerror(sock_errno));
        return status;
    }
#endif

    // Connect
    if (options->h_addrtype == AF_INET)
    {
        status = connect(socket, (struct sockaddr *)&options->serverAddress, sizeof(options->serverAddress));
    }
    else    // IPv6
    {
        status = connect(socket, (struct sockaddr *)&options->serverAddress6, sizeof(options->serverAddress6));
    }

    if (status < 0 && sock_errno != INPROGRESS)
    {
        snprintf(error, errlen, "connect: %s", sock_strerror(sock_errno));
        return status;
    }

    // connect() completed immediately
    if (status == 0)
        return status;

    FD_ZERO(&rset);
    FD_SET(socket, &rset);
    wset = eset = rset;
    tval.tv_sec = options->connect_timeout;
    tval.tv_usec = 0;

    if ((status = select(socket + 1, &rset, &wset, &eset, &tval)) == 0)
    {
        snprintf(error, errlen, "connect: Timed out");
        return -1;
    }
    else if (status < 0)
    {
        snprintf(error, errlen, "connect: select: %s", sock_strerror(sock_errno));
        return status;
    }

    if (FD_ISSET(socket, &rset) || FD_ISSET(socket, &wset) || FD_ISSET(socket, &eset))
    {
        len = sizeof(errn);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)&errn, (socklen_t *)&len) < 0)
        {
            snprintf(error, errlen, "connect: getsockopt: %s", sock_strerror(errn));
            return -1;
        }
    }

    if (errn)
    {
        snprintf(error, errlen, "connect: %s", sock_strerror(errn));
        return -1;
    }

#ifdef _WIN32
    flags = 0;

    if ((status = ioctlsocket(socket, FIONBIO, (u_long *)&flags)) != NO_ERROR)
    {
        snprintf(error, errlen, "ioctlsocket: %s", sock_strerror(sock_errno));
        return -1;
    }
#else
    if (fcntl(socket, F_SETFL, flags) < 0)
    {
        snprintf(error, errlen, "fcntl setfl: %s", sock_strerror(sock_errno));
        return -1;
    }
#endif

    return status;
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
    char buffer[BUFFERSIZE], errmsg[BUFFERSIZE];
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
        printf_error("Could not open a socket.");
        return 0;
    }

    // Set socket timeout
#ifdef _WIN32
    // Windows isn't looking for a timeval struct like in UNIX; it wants a timeout in a DWORD represented in milliseconds...
    DWORD timeout = (options->timeout.tv_sec * 1000) + (options->timeout.tv_usec / 1000);
    setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(socketDescriptor, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
#else
    setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, (char *)&options->timeout, sizeof(struct timeval));
    setsockopt(socketDescriptor, SOL_SOCKET, SO_SNDTIMEO, (char *)&options->timeout, sizeof(struct timeval));
#endif

    status = tcpConnectSocket(socketDescriptor, options, errmsg, BUFFERSIZE);

    if(status < 0)
    {
        printf_error("Could not open a connection to host %s (%s) on port %d (%s).", options->host, options->addrstr,
                options->port, errmsg);
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
            printf_error("The host %s on port %d did not appear to be an SMTP service.", options->host, options->port);
            return 0;
        }
        sendString(socketDescriptor, "EHLO example.org\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        if (strncmp(buffer, "250", 3) != 0)
        {
            close(socketDescriptor);
            printf_error("The SMTP service on %s port %d did not respond with status 250 to our HELO.", options->host, options->port);
            return 0;
        }
        sendString(socketDescriptor, "STARTTLS\r\n");
        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        if (strncmp(buffer, "220", 3) != 0)
        {
            close(socketDescriptor);
            printf_error("The SMTP service on %s port %d did not appear to support STARTTLS.", options->host, options->port);
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

        if (memmem(buffer, BUFFERSIZE, ok, strlen(ok))) {
            printf_verbose("STARTLS LDAP setup complete.\n");
        }
        else if (strstr(buffer, unsupported)) {
            printf_error("STARTLS LDAP connection to %s:%d failed with '%s'.",
                         options->host, options->port, unsupported);
            return 0;
        } else {
            printf_error("STARTLS LDAP connection to %s:%d failed with unknown error.",
                         options->host, options->port);
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
            printf_error("Unexpected EOF reading from %s:%d", options->host, options->port);
            return 0;
        }

        if (buffer != 'S') {
            printf_error("Server at %s:%d rejected TLS startup", options->host, options->port);
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
            printf_error("Unexpected EOF reading from %s:%d", options->host, options->port);
            return 0;
        }

        // Calculate remaining bytes (and check for overflows)
        readlen = ((buffer[2] & 0x7f) << 8) + buffer[3] - 4;
        if (readlen > sizeof(buffer)) {
            printf_error("Unexpected data from %s:%d", options->host, options->port);
            return 0;

        }

        // Read reply data
        if (readlen != recv(socketDescriptor, buffer, readlen, 0)) {
            printf_error("Unexpected EOF reading from %s:%d", options->host, options->port);
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
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                printf_error("Could not set cipher.");
            }
            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("Could not create CTX object.");
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("Could not connect.");
        exit(1);
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
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                printf_error("Could not set cipher.");
            }
            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("Could not create CTX object.");
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("Could not connect.");
        exit(1);
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
                                        printf_error("SSL_do_handshake() call failed");
                                    }
                                    if (SSL_get_state(ssl) == TLS_ST_OK)
                                    {
                                        /* our renegotiation is complete */
                                        renOut->supported = true;
                                        status = true;
                                    } else {
                                        renOut->supported = false;
                                        status = false;
                                        printf_error("Failed to complete renegotiation");
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
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                renOut->supported = false;
                printf_error("Could not set cipher.");
            }
            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            renOut->supported = false;
            printf_error("Could not create CTX object.");
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        printf_error("Could not connect.");
        renOut->supported = false;
        freeRenegotiationOutput( renOut );
        exit(1);
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
            printf_error("send() failed: %s", strerror(errno));
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
            printf_error("send() failed: %s", strerror(errno));
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
        printf_error("Could not connect.");
        printf("dying");
        exit(1);
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
void outputCipher(struct sslCheckOptions *options, SSL *ssl, const char *cleanSslMethod, uint32_t cipherid, const char *ciphername, int cipherbits, int cipher_accepted, unsigned int milliseconds_elapsed) {
  char hexCipherId[8] = {0};
  char *strength;
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

    printf_xml(" sslversion=\"%s\"", cleanSslMethod);
    if (strcmp(cleanSslMethod, "TLSv1.3") == 0) {
      printf("%sTLSv1.3%s  ", COL_GREEN, RESET);
    }
    else if (strcmp(cleanSslMethod, "TLSv1.1") == 0) {
      printf("%sTLSv1.1%s  ", COL_YELLOW, RESET);
    }
    else if (strcmp(cleanSslMethod, "TLSv1.0") == 0) {
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
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_RED_BG, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_RED_BG, ciphername, RESET);
        }
        strength = "null";
    } else if (strstr(ciphername, "ADH") || strstr(ciphername, "AECDH") || strstr(ciphername, "_anon_")) {
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_PURPLE, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_PURPLE, ciphername, RESET);
        }
        strength = "anonymous";
    } else if (strstr(ciphername, "EXP")) {
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_RED, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_RED, ciphername, RESET);
        }
        strength = "weak";
    } else if (strstr(ciphername, "RC4") || strstr(ciphername, "DES")) {
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_YELLOW, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_YELLOW, ciphername, RESET);
        }
        strength = "medium";
    } else if (strstr(ciphername, "_SM4_")) { /* Developed by Chinese government */
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_YELLOW, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_YELLOW, ciphername, RESET);
        }
        strength = "medium";
    } else if (strstr(ciphername, "_GOSTR341112_")) { /* Developed by Russian government */
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_YELLOW, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_YELLOW, ciphername, RESET);
        }
        strength = "medium";
    } else if ((strstr(ciphername, "CHACHA20") || (strstr(ciphername, "GCM"))) && (strstr(ciphername, "DHE") || (strcmp(cleanSslMethod, "TLSv1.3") == 0))) {
        if (options->ianaNames) {
            printf("%s%-45s%s", COL_GREEN, ciphername, RESET);
        }
        else {
            printf("%s%-29s%s", COL_GREEN, ciphername, RESET);
        }
        strength = "strong";
    } else {
        if (options->ianaNames) {
            printf("%-45s", ciphername);
        }
        else {
            printf("%-29s", ciphername);
        }
        strength = "acceptable";
    }
    printf_xml(" strength=\"%s\"", strength);

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
    int cipherbits = -1;
    uint32_t cipherid = 0;
    const SSL_CIPHER *sslCipherPointer = NULL;
    const char *cleanSslMethod = printableSslMethod(sslMethod);
    const char *ciphername = NULL;
    struct timeval tval_start = {0};
    unsigned int milliseconds_elapsed = 0;


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

                // Against some servers, this is required for a successful SSL_connect(), below.
                SSL_set_options(ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

                // Connect SSL over socket
                cipherStatus = SSL_connect(ssl);
                printf_verbose("SSL_connect() returned: %d\n", cipherStatus);

                sslCipherPointer = SSL_get_current_cipher(ssl);
                if (sslCipherPointer == NULL) {
                  printf_verbose("SSL_get_current_cipher() returned NULL; this indicates that the server did not choose a cipher from our list (%s)\n", options->cipherstring);
                  SSL_shutdown(ssl);
                  FREE_SSL(ssl);
                  CLOSE(socketDescriptor);
                  return false;
                }

                cipherbits = SSL_CIPHER_get_bits(sslCipherPointer, NULL);
                cipherid = SSL_CIPHER_get_id(sslCipherPointer);
                cipherid = cipherid & 0x00ffffff;  // remove first byte which is the version (0x03 for TLSv1/SSLv3)

                if (options->ianaNames)
                {
                    ciphername = SSL_CIPHER_standard_name(sslCipherPointer);
                }
                else
                {
                    ciphername = SSL_CIPHER_get_name(sslCipherPointer);
                }
                

		// Timing
		if (options->showTimes) {
		  struct timeval tval_end = {0}, tval_elapsed = {0};

		  gettimeofday(&tval_end, NULL);
		  timersub(&tval_end, &tval_start, &tval_elapsed);
		  milliseconds_elapsed = tval_elapsed.tv_sec * 1000 + (int)tval_elapsed.tv_usec / 1000;
		}

                outputCipher(options, ssl, cleanSslMethod, cipherid, ciphername, cipherbits, 1, milliseconds_elapsed);

                // Disconnect SSL over socket
                const char *usedcipher = SSL_get_cipher_name(ssl);
                if(sslMethod == TLSv1_3_client_method())
                  cipherRemove(options->cipherstring, usedcipher);  // Remove cipher from TLSv1.3 list
                else {
                  // Using strcat rather than strncat to avoid a warning from GCC
                  strcat(options->cipherstring, ":!");
                  strncat(options->cipherstring, usedcipher, strlen(usedcipher));
                }
                SSL_shutdown(ssl);

                // Free SSL object
                FREE_SSL(ssl);
            }
            else
            {
                status = false;
                printf_error("Could not create SSL object.");
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
        printf_error("Could not create CTX object.");
        status = false;
    }
    return status;
}

// Report certificate weaknesses (key length and signing algorithm)
int checkCertificate(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
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

                        // Against some servers, this is required for a successful SSL_connect(), below.
                        SSL_set_options(ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

                        // Connect SSL over socket
                        SSL_connect(ssl);
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
                        x509Cert = SSL_get_peer_certificate(ssl);
                        if (x509Cert != NULL)
                        {
                            printf("\n  %sSSL Certificate:%s\n", COL_BLUE, RESET);
                            printf_xml("  <certificate type=\"short\">\n");
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
                                    printf_xml("   <signature-algorithm>%s</signature-algorithm>\n", certAlgorithm);
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
                                                else if (keyBits >= 3072 )
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
                                            {
                                                EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(publicKey);
                                                if (ec_key != NULL)
                                                {
                                                    // We divide by two to get the symmetric key strength equivalent; this
                                                    // ensures consistency with the Server Key Exchange Group section.
                                                    int keyBits = EVP_PKEY_bits(publicKey) / 2;
                                                    const char *ec_group_name = OBJ_nid2sn(EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key)));
                                                    char *color = "";


                                                    if (keyBits < 112)
                                                        color = COL_RED;
                                                    else if (keyBits < 128)
                                                        color = COL_YELLOW;

                                                    printf("ECC Curve Name:      %s\n", ec_group_name);
                                                    printf("ECC Key Strength:    %s%d%s\n\n", color, keyBits, RESET);
                                                    printf_xml("   <pk error=\"false\" type=\"EC\" curve_name=\"%s\" bits=\"%d\" />\n", ec_group_name, keyBits);
                                                    EC_KEY_free(ec_key); ec_key = NULL;
                                                }
                                                else
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
                                    char *color = "";
                                    int self_signed = 0;

                                    if ((subject != NULL) && (strcmp(subject, issuer) == 0)) {
                                        color = COL_RED;
                                        self_signed = 1;
                                    }
                                    printf("%sIssuer:   %s%s", color, issuer, RESET);
                                    printf_xml("   <issuer><![CDATA[%s]]></issuer>\n", issuer);

                                    if (self_signed) {
                                        printf_xml("   <self-signed>true</self-signed>\n");
                                    }
                                    else {
                                        printf_xml("   <self-signed>false</self-signed>\n");
                                    }
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
                                if (timediff > 0)
                                {
                                    printf_xml("   <not-yet-valid>true</not-yet-valid>\n");
                                }
                                else
                                {
                                    printf_xml("   <not-yet-valid>false</not-yet-valid>\n");
                                }
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

                            printf_xml("  </certificate>\n");
                        }

                        else {
                            printf("    Unable to parse certificate\n");
                        }

                        // Free BIO
                        BIO_free(stdoutBIO);
                        if (options->xmlOutput)
                            BIO_free(fileBIO);

                        // Disconnect SSL over socket
                        SSL_shutdown(ssl);
                        // Free SSL object
                        FREE_SSL(ssl);
                    }
                    else
                    {
                        status = false;
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                printf_error("Could not set cipher.");
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("Could not create CTX object.");
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
            printf_verbose("sslMethod = TLS_method()\n");
            sslMethod = TLS_method();
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
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                printf_error("Could not set cipher.");
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("Could not create CTX object.");
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
        BIO_puts(bp, "No OCSP response received.\n\n");
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
            printf_verbose("sslMethod = TLS_method()\n");
            sslMethod = TLS_method();
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

                            // Get certificate(s) chain
                            STACK_OF(X509) *certificatesChain;

                            if (options->showCertificates == true)
                            {
                                certificatesChain = SSL_get_peer_cert_chain(ssl);   
                            }
                            else
                            {                                
                                X509 *peerCertificate = SSL_get_peer_certificate(ssl);
                                certificatesChain = sk_X509_new_null();
                                sk_X509_push(certificatesChain, peerCertificate);
                            }

                            for (int cert_index = 0; cert_index < sk_X509_num(certificatesChain); cert_index++)
                            {
                                // Get Certificate...
                                printf("\n  %sSSL Certificate: %s\n", COL_BLUE, RESET);
                                printf_xml("  <certificate type=\"full\">\n");

                                x509Cert = sk_X509_value(certificatesChain, cert_index);

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

                                    // SSL_set_verify(ssl, SSL_VERIFY_NONE|SSL_VERIFY_CLIENT_ONCE, NULL);

                                    // X509_print_ex(bp, x509Cert, 0, 0);

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
                                    printf("  Verify m:\n");
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

                                else
                                {
                                    printf("    Unable to parse certificate\n");
                                }

                                printf_xml("  </certificate>\n");
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
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                printf_error("Could not set cipher.");
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("Could not create CTX object.");
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
            printf_verbose("sslMethod = TLS_method()\n");
            sslMethod = TLS_method();
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
                        printf_error("Could not create SSL object.");
                    }
                }
            }
            else
            {
                status = false;
                printf_error("Could not set cipher.");
            }

            // Free CTX Object
            FREE_CTX(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf_error("Could not create CTX object.");
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
        printf_error("Could not resolve hostname %s.", options->host);
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
            printf_error("Could not create CTX object.");
            return false;
        }
    }

    /* Test the missing ciphersuites. */
    if (sslMethod != TLSv1_3_client_method()) {
      int tls_version = TLSv1_0;
      if (sslMethod == TLSv1_1_client_method())
	tls_version = TLSv1_1;
      else if (sslMethod == TLSv1_2_client_method())
	tls_version = TLSv1_2;

      testMissingCiphers(options, tls_version);
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

    printf("  %sSSL/TLS Protocols:%s\n", COL_BLUE, RESET);

    // Check if SSLv2 is enabled.
    if ((options->sslVersion == ssl_all) || (options->sslVersion == ssl_v2)) {
      if (runSSLv2Test(options)) {
        printf("SSLv2     %senabled%s\n", COL_RED, RESET);
        printf_xml("  <protocol type=\"ssl\" version=\"2\" enabled=\"1\" />\n");
      } else {
        printf("SSLv2     %sdisabled%s\n", COL_GREEN, RESET);
        printf_xml("  <protocol type=\"ssl\" version=\"2\" enabled=\"0\" />\n");
      }
    }

    // Check if SSLv3 is enabled.
    if ((options->sslVersion == ssl_all) || (options->sslVersion == ssl_v3)) {
      if (runSSLv3Test(options)) {
	printf("SSLv3     %senabled%s\n", COL_RED, RESET);
	printf_xml("  <protocol type=\"ssl\" version=\"3\" enabled=\"1\" />\n");
      } else {
	printf("SSLv3     %sdisabled%s\n", COL_GREEN, RESET);
	printf_xml("  <protocol type=\"ssl\" version=\"3\" enabled=\"0\" />\n");
      }
    }

    /* Test if TLSv1.0 through TLSv1.3 is supported.  This allows us to skip unnecessary tests later.  Print status of each protocol when verbose flag is set. */
    if ((options->sslVersion == ssl_all) || (options->sslVersion == tls_all) || (options->sslVersion == tls_v10)) {
      if ((options->tls10_supported = checkIfTLSVersionIsSupported(options, TLSv1_0))) {
	printf("TLSv1.0   %senabled%s\n", COL_YELLOW, RESET);
	printf_xml("  <protocol type=\"tls\" version=\"1.0\" enabled=\"1\" />\n");
      } else {
	printf("TLSv1.0   %sdisabled%s\n", COL_GREEN, RESET);
	printf_xml("  <protocol type=\"tls\" version=\"1.0\" enabled=\"0\" />\n");
      }
    }

    if ((options->sslVersion == ssl_all) || (options->sslVersion == tls_all) || (options->sslVersion == tls_v11)) {
      if ((options->tls11_supported = checkIfTLSVersionIsSupported(options, TLSv1_1))) {
	printf("TLSv1.1   %senabled%s\n", COL_YELLOW, RESET);
	printf_xml("  <protocol type=\"tls\" version=\"1.1\" enabled=\"1\" />\n");
      } else {
	printf("TLSv1.1   %sdisabled%s\n", COL_GREEN, RESET);
	printf_xml("  <protocol type=\"tls\" version=\"1.1\" enabled=\"0\" />\n");
      }
    }

    if ((options->sslVersion == ssl_all) || (options->sslVersion == tls_all) || (options->sslVersion == tls_v12)) {
      if ((options->tls12_supported = checkIfTLSVersionIsSupported(options, TLSv1_2))) {
	printf("TLSv1.2   enabled\n");
	printf_xml("  <protocol type=\"tls\" version=\"1.2\" enabled=\"1\" />\n");
      } else {
	printf("TLSv1.2   disabled\n");
	printf_xml("  <protocol type=\"tls\" version=\"1.2\" enabled=\"0\" />\n");
      }
    }

    if ((options->sslVersion == ssl_all) || (options->sslVersion == tls_all) || (options->sslVersion == tls_v13)) {
      if ((options->tls13_supported = checkIfTLSVersionIsSupported(options, TLSv1_3))) {
	printf("TLSv1.3   %senabled%s\n", COL_GREEN, RESET);
	printf_xml("  <protocol type=\"tls\" version=\"1.3\" enabled=\"1\" />\n");
      } else {
	printf("TLSv1.3   %sdisabled%s\n", COL_YELLOW, RESET);
	printf_xml("  <protocol type=\"tls\" version=\"1.3\" enabled=\"0\" />\n");
      }
    }
    printf("\n");

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
        if ((options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v13) && options->tls13_supported)
        {
            printf("TLSv1.3 ");
            status = testHeartbleed(options, TLSv1_3_client_method());
        }
        if ((options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v12) && options->tls12_supported)
        {
            printf("TLSv1.2 ");
            status = testHeartbleed(options, TLSv1_2_client_method());
        }
        if ((options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v11) && options->tls11_supported)
        {
            printf("TLSv1.1 ");
            status = testHeartbleed(options, TLSv1_1_client_method());
        }
#endif
        if ((options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v10) && options->tls10_supported)
        {
            printf("TLSv1.0 ");
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
            case tls_all:
                if ((status != false) && options->tls13_supported)
                    status = testProtocolCiphers(options, TLSv1_3_client_method());
                if ((status != false) && options->tls12_supported)
                    status = testProtocolCiphers(options, TLSv1_2_client_method());
                if ((status != false) && options->tls11_supported)
                    status = testProtocolCiphers(options, TLSv1_1_client_method());
                if ((status != false) && options->tls10_supported)
                    status = testProtocolCiphers(options, TLSv1_client_method());
                break;
            case tls_v10:
                if ((status != false) && options->tls10_supported)
                    status = testProtocolCiphers(options, TLSv1_client_method());
                break;
            case tls_v11:
                if ((status != false) && options->tls11_supported)
                    status = testProtocolCiphers(options, TLSv1_1_client_method());
                break;
            case tls_v12:
                if ((status != false) && options->tls12_supported)
                    status = testProtocolCiphers(options, TLSv1_2_client_method());
                break;
            case tls_v13:
                if ((status != false) && options->tls13_supported)
                    status = testProtocolCiphers(options, TLSv1_3_client_method());
                break;
        }
    }

    // Enumerate key exchange groups.
    if (options->groups)
        testSupportedGroups(options);

    // Enumerate signature algorithms.
    if (options->signature_algorithms)
        testSignatureAlgorithms(options);

    // Certificate checks
    if (status == true && (options->showCertificate == true || options->checkCertificate == true))
    {
        printf_xml(" <certificates>\n");

        // Full certificate details
        if (status == true && (options->showCertificate == true || options->showCertificates == true))
        {
            status = showCertificate(options);
        }

        // Default certificate details
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
                printf("Certificate information cannot be retrieved.\n\n");
        }
        printf_xml(" </certificates>\n");
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
    struct sslCheckOptions sslOptions;
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
    unsigned int enable_colors;
#endif

    // Init...
    memset(&sslOptions, 0, sizeof(struct sslCheckOptions));
    sslOptions.port = 0;
    xmlArg = 0;
    strncpy(sslOptions.host, "127.0.0.1", 10);
    sslOptions.showCertificate = false;
    sslOptions.showTrustedCAs = false;
    sslOptions.checkCertificate = true;
    sslOptions.showClientCiphers = false;
    sslOptions.showCipherIds = false;
    sslOptions.showTimes = false;
    sslOptions.ciphersuites = true;
    sslOptions.reneg = true;
    sslOptions.fallback = true;
    sslOptions.compression = true;
    sslOptions.heartbleed = true;
    sslOptions.groups = true;
    sslOptions.signature_algorithms = false;
    sslOptions.starttls_ftp = false;
    sslOptions.starttls_imap = false;
    sslOptions.starttls_irc = false;
    sslOptions.starttls_ldap = false;
    sslOptions.starttls_pop3 = false;
    sslOptions.starttls_smtp = false;
    sslOptions.starttls_mysql = false;
    sslOptions.starttls_xmpp = false;
    sslOptions.starttls_psql = false;
    sslOptions.xmpp_server = false;
    sslOptions.verbose = false;
    sslOptions.cipher_details = true;
    sslOptions.ipv4 = true;
    sslOptions.ipv6 = true;
    sslOptions.ocspStatus = false;

    // Default socket timeout 3s
    sslOptions.timeout.tv_sec = 3;
    sslOptions.timeout.tv_usec = 0;
    // Default connect timeout 75s
    sslOptions.connect_timeout = 75;
    sslOptions.sleep = 0;

    sslOptions.sslVersion = ssl_all;

    struct sslCheckOptions *options = &sslOptions;

#ifdef _WIN32
    /* Attempt to enable console colors.  This succeeds in Windows 10.  For other
     * OSes, color is disabled. */
    enable_colors = 1;
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    /* Cygwin's terminal is re-directed, so GetConsoleMode() fails on it.  So we'll try to get a direct handle in that case. */
    if (!GetConsoleMode(hConsole, &consoleMode)) {
      hConsole = CreateFile("CONIN$", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

      /* Also, Cygwin appears to do full buffering of output, so the program seems to hang until its fully complete, then the output gets dumped all at once.  To be more responsive, we'll force line buffering at 80 bytes (the default terminal width). */
      setvbuf(stdout, NULL, _IOLBF, 80);

      /* If we still can't get console information, then disable colors. */
      if (!GetConsoleMode(hConsole, &consoleMode))
	enable_colors = 0;
    }

    /* Some terminals already have colors enabled, and somehow don't like being set. */
    if (enable_colors && ((consoleMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0)) {
      if (!SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
	enable_colors = 0;
    }

    if (!enable_colors) {
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
        printf_error("WSAStartup failed: %d", err);
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
            options->targets = argLoop;
        }

        // Show certificate (only one)
        else if (strcmp("--show-certificate", argv[argLoop]) == 0)
            options->showCertificate = true;

        // Show certificates (all)
        else if (strcmp("--show-certificates", argv[argLoop]) == 0)
            options->showCertificates = true;

        // Don't check certificate strength
        else if (strcmp("--no-check-certificate", argv[argLoop]) == 0)
            options->checkCertificate = false;

        // Show supported client ciphers
        else if (strcmp("--show-ciphers", argv[argLoop]) == 0)
            options->showClientCiphers = true;

        // Show ciphers ids
        else if (strcmp("--show-cipher-ids", argv[argLoop]) == 0)
        {
            options->showCipherIds = true;
        }

        // Show handshake times
        else if (strcmp("--show-times", argv[argLoop]) == 0)
        {
            options->showTimes = true;
        }

        // Show client auth trusted CAs
        else if (strcmp("--show-client-cas", argv[argLoop]) == 0)
            options->showTrustedCAs = true;

        // Version
        else if (strcmp("--version", argv[argLoop]) == 0)
            mode = mode_version;

        // XML Output
        else if (strncmp("--xml=", argv[argLoop], 6) == 0)
            xmlArg = argLoop;

        // Verbose
        else if (strcmp("--verbose", argv[argLoop]) == 0)
            options->verbose = true;

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        // Cipher details (curve names and EDH key lengths)
        else if (strcmp("--no-cipher-details", argv[argLoop]) == 0)
            options->cipher_details = false;
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
            options->clientCertsFile = argv[argLoop] +8;

        // Private Key File
        else if (strncmp("--pk=", argv[argLoop], 5) == 0)
            options->privateKeyFile = argv[argLoop] +5;

        // Private Key Password
        else if (strncmp("--pkpass=", argv[argLoop], 9) == 0)
            options->privateKeyPassword = argv[argLoop] +9;

        // Should we check for supported cipher suites
        else if (strcmp("--no-ciphersuites", argv[argLoop]) == 0)
            options->ciphersuites = false;

        // Should we check for TLS Falback SCSV?
        else if (strcmp("--no-fallback", argv[argLoop]) == 0)
            options->fallback = false;

        // Should we check for TLS renegotiation?
        else if (strcmp("--no-renegotiation", argv[argLoop]) == 0)
            options->reneg = false;

        // Should we check for TLS Compression
        else if (strcmp("--no-compression", argv[argLoop]) == 0)
            options->compression = false;

        // Should we check for Heartbleed (CVE-2014-0160)
        else if (strcmp("--no-heartbleed", argv[argLoop]) == 0)
            options->heartbleed = false;

        // Should we check for key exchange groups?
        else if (strcmp("--no-groups", argv[argLoop]) == 0)
            options->groups = false;

        // Should we check for signature algorithms?
        else if (strcmp("--show-sigs", argv[argLoop]) == 0)
            options->signature_algorithms = true;

        // Show IANA/RFC cipher names in output
        else if (strcmp("--iana-names", argv[argLoop]) == 0)
            options->ianaNames = true;

        // StartTLS... FTP
        else if (strcmp("--starttls-ftp", argv[argLoop]) == 0)
            options->starttls_ftp = true;

        // StartTLS... IMAP
        else if (strcmp("--starttls-imap", argv[argLoop]) == 0)
            options->starttls_imap = true;

        else if (strcmp("--starttls-irc", argv[argLoop]) == 0)
            options->starttls_irc = true;

        // StartTLS... LDAP
        else if (strcmp("--starttls-ldap", argv[argLoop]) == 0)
            options->starttls_ldap = true;

        // StartTLS... POP3
        else if (strcmp("--starttls-pop3", argv[argLoop]) == 0)
            options->starttls_pop3 = true;

        // StartTLS... SMTP
        else if (strcmp("--starttls-smtp", argv[argLoop]) == 0)
            options->starttls_smtp = true;

        // StartTLS... MYSQL
        else if (strcmp("--starttls-mysql", argv[argLoop]) == 0)
            options->starttls_mysql = true;

        // StartTLS... XMPP
        else if (strcmp("--starttls-xmpp", argv[argLoop]) == 0)
            options->starttls_xmpp = true;

        // StartTLS... PostgreSQL
        else if (strcmp("--starttls-psql", argv[argLoop]) == 0)
            options->starttls_psql = true;

        // SSL v2 only...
        else if (strcmp("--ssl2", argv[argLoop]) == 0)
            options->sslVersion = ssl_v2;

        // SSL v3 only...
        else if (strcmp("--ssl3", argv[argLoop]) == 0)
            options->sslVersion = ssl_v3;

        // TLS v1 only...
        else if (strcmp("--tls10", argv[argLoop]) == 0)
            options->sslVersion = tls_v10;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        // TLS v11 only...
        else if (strcmp("--tls11", argv[argLoop]) == 0)
            options->sslVersion = tls_v11;

        // TLS v12 only...
        else if (strcmp("--tls12", argv[argLoop]) == 0)
            options->sslVersion = tls_v12;
        // TLS v13 only...
        else if (strcmp("--tls13", argv[argLoop]) == 0)
            options->sslVersion = tls_v13;
#endif
        // TLS (all versions)...
        else if (strcmp("--tlsall", argv[argLoop]) == 0)
            options->sslVersion = tls_all;

        // Use a server-to-server XMPP handshake
        else if (strcmp("--xmpp-server", argv[argLoop]) == 0)
            options->xmpp_server = true;

        // SSL Bugs...
        else if (strcmp("--bugs", argv[argLoop]) == 0)
            options->sslbugs = 1;

        // Socket Timeout (both send and receive)
        else if (strncmp("--timeout=", argv[argLoop], 10) == 0)
            options->timeout.tv_sec = atoi(argv[argLoop] + 10);

        // Connect Timeout
        else if (strncmp("--connect-timeout=", argv[argLoop], 18) == 0)
            options->connect_timeout = atoi(argv[argLoop] + 18);

        // Sleep between requests (ms)
        else if (strncmp("--sleep=", argv[argLoop], 8) == 0)
        {
            msec = atoi(argv[argLoop] + 8);
            if (msec >= 0) {
                options->sleep = msec;
            }
        }

        // RDP Preamble...
        else if (strcmp("--rdp", argv[argLoop]) == 0)
            options->rdp = 1;

        // IPv4 only
        else if ((strcmp("--ipv4", argv[argLoop]) == 0) || (strcmp("-4", argv[argLoop]) == 0))
            options->ipv6 = false;

        // IPv6 only
        else if ((strcmp("--ipv6", argv[argLoop]) == 0) || (strcmp("-6", argv[argLoop]) == 0))
            options->ipv4 = false;

        // Check OCSP response
        else if (strcmp("--ocsp", argv[argLoop]) == 0)
            options->ocspStatus = true;

        // SNI name
        else if (strncmp("--sni-name=", argv[argLoop], 11) == 0)
        {
            strncpy(options->sniname, argv[argLoop]+11, strlen(argv[argLoop])-11);
            options->sni_set = 1;
        }


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
                        || (squareBrackets == false && hostString[tempInt] != ':' && hostString[tempInt] != '/')))
            {
                tempInt++;
            }

            if (squareBrackets == true && hostString[tempInt] == ']')
            {
                hostString[tempInt] = 0;
                if (tempInt < maxSize && (hostString[tempInt + 1] == ':' || hostString[tempInt + 1] == '/'))
                {
                    tempInt++;
                    hostString[tempInt] = 0;
                }
            }
            else
            {
                hostString[tempInt] = 0;
            }
            strncpy(options->host, hostString, sizeof(options->host) -1);

            // No SNI name passed on command line
            if (!options->sni_set)
            {
                strncpy(options->sniname, options->host, sizeof(options->host) -1);
            }

            // Get port (if it exists)...
            tempInt++;
            if (tempInt < maxSize)
            {
                errno = 0;
                options->port = strtol((hostString + tempInt), NULL, 10);
                if (options->port < 1 || options->port > 65535)
                {
                    printf_error("Invalid target specified.");
                    exit(1);
                }
            }
            else if (options->port == 0) {
                if (options->starttls_ftp)
                    options->port = 21;
                else if (options->starttls_imap)
                    options->port = 143;
                else if (options->starttls_irc)
                    options->port = 6667;
                else if (options->starttls_ldap)
                    options->port = 389;
                else if (options->starttls_pop3)
                    options->port = 110;
                else if (options->starttls_smtp)
                    options->port = 25;
                else if (options->starttls_mysql)
                    options->port = 3306;
                else if (options->starttls_xmpp)
                    options->port = 5222;
                else if (options->starttls_psql)
                    options->port = 5432;
                else if (options->rdp)
                    options->port = 3389;
                else
                    options->port = 443;
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
            options->xmlOutput = stdout;
            xml_to_stdout = 1;
        }
        else
        {
            options->xmlOutput = fopen(argv[xmlArg] + 6, "w");
            if (options->xmlOutput == NULL)
            {
                printf_error("Could not open XML output file %s.", argv[xmlArg] + 6);
                exit(0);
            }
        }

        // Output file header...
        fprintf(options->xmlOutput, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document title=\"SSLScan Results\" version=\"%s\" web=\"http://github.com/rbsec/sslscan\">\n", VERSION);
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
            printf("%s\t\t%s\n\t\t%s\n%s\n\n", COL_BLUE, VERSION,
                    SSLeay_version(SSLEAY_VERSION), RESET);
            printf("%sCommand:%s\n", COL_BLUE, RESET);
            printf("  %s%s [options] [host:port | host]%s\n\n", COL_GREEN, argv[0], RESET);
            printf("%sOptions:%s\n", COL_BLUE, RESET);
            printf("  %s--targets=<file>%s     A file containing a list of hosts to check.\n", COL_GREEN, RESET);
            printf("                       Hosts can  be supplied  with ports (host:port)\n");
            printf("  %s--sni-name=<name>%s    Hostname for SNI\n", COL_GREEN, RESET);
            printf("  %s--ipv4, -4%s           Only use IPv4\n", COL_GREEN, RESET);
            printf("  %s--ipv6, -6%s           Only use IPv6\n", COL_GREEN, RESET);
            printf("\n");
            printf("  %s--show-certificate%s   Show full certificate information\n", COL_GREEN, RESET);
            printf("  %s--show-certificates%s  Show chain full certificates information\n", COL_GREEN, RESET);
            printf("  %s--show-client-cas%s    Show trusted CAs for TLS client auth\n", COL_GREEN, RESET);
            printf("  %s--no-check-certificate%s  Don't warn about weak certificate algorithm or keys\n", COL_GREEN, RESET);
            printf("  %s--ocsp%s               Request OCSP response from server\n", COL_GREEN, RESET);
            printf("  %s--pk=<file>%s          A file containing the private key or a PKCS#12 file\n", COL_GREEN, RESET);
            printf("                       containing a private key/certificate pair\n");
            printf("  %s--pkpass=<password>%s  The password for the private  key or PKCS#12 file\n", COL_GREEN, RESET);
            printf("  %s--certs=<file>%s       A file containing PEM/ASN1 formatted client certificates\n", COL_GREEN, RESET);
            printf("\n");
            printf("  %s--ssl2%s               Only check if SSLv2 is enabled\n", COL_GREEN, RESET);
            printf("  %s--ssl3%s               Only check if SSLv3 is enabled\n", COL_GREEN, RESET);
            printf("  %s--tls10%s              Only check TLSv1.0 ciphers\n", COL_GREEN, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            printf("  %s--tls11%s              Only check TLSv1.1 ciphers\n", COL_GREEN, RESET);
            printf("  %s--tls12%s              Only check TLSv1.2 ciphers\n", COL_GREEN, RESET);
            printf("  %s--tls13%s              Only check TLSv1.3 ciphers\n", COL_GREEN, RESET);
#endif
            printf("  %s--tlsall%s             Only check TLS ciphers (all versions)\n", COL_GREEN, RESET);
            printf("  %s--show-ciphers%s       Show supported client ciphers\n", COL_GREEN, RESET);
            printf("  %s--show-cipher-ids%s    Show cipher ids\n", COL_GREEN, RESET);
            printf("  %s--iana-names%s         Use IANA/RFC cipher names rather than OpenSSL ones\n", COL_GREEN, RESET);
            printf("  %s--show-times%s         Show handhake times in milliseconds\n", COL_GREEN, RESET);
            printf("\n");
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
            printf("  %s--no-cipher-details%s  Disable EC curve names and EDH/RSA key lengths output\n", COL_GREEN, RESET);
#endif
            printf("  %s--no-ciphersuites%s    Do not check for supported ciphersuites\n", COL_GREEN, RESET);
            printf("  %s--no-compression%s     Do not check for TLS compression (CRIME)\n", COL_GREEN, RESET);
#ifdef SSL_MODE_SEND_FALLBACK_SCSV
            printf("  %s--no-fallback%s        Do not check for TLS Fallback SCSV\n", COL_GREEN, RESET);
#endif
            printf("  %s--no-groups%s          Do not enumerate key exchange groups\n", COL_GREEN, RESET);
            printf("  %s--no-heartbleed%s      Do not check for OpenSSL Heartbleed (CVE-2014-0160)\n", COL_GREEN, RESET);
            printf("  %s--no-renegotiation%s   Do not check for TLS renegotiation\n", COL_GREEN, RESET);
            printf("  %s--show-sigs%s          Enumerate signature algorithms\n", COL_GREEN, RESET);
            printf("\n");
            printf("  %s--starttls-ftp%s       STARTTLS setup for FTP\n", COL_GREEN, RESET);
            printf("  %s--starttls-imap%s      STARTTLS setup for IMAP\n", COL_GREEN, RESET);
            printf("  %s--starttls-irc%s       STARTTLS setup for IRC\n", COL_GREEN, RESET);
            printf("  %s--starttls-ldap%s      STARTTLS setup for LDAP\n", COL_GREEN, RESET);
            printf("  %s--starttls-mysql%s     STARTTLS setup for MYSQL\n", COL_GREEN, RESET);
            printf("  %s--starttls-pop3%s      STARTTLS setup for POP3\n", COL_GREEN, RESET);
            printf("  %s--starttls-psql%s      STARTTLS setup for PostgreSQL\n", COL_GREEN, RESET);
            printf("  %s--starttls-smtp%s      STARTTLS setup for SMTP\n", COL_GREEN, RESET);
            printf("  %s--starttls-xmpp%s      STARTTLS setup for XMPP\n", COL_GREEN, RESET);
            printf("  %s--xmpp-server%s        Use a server-to-server XMPP handshake\n", COL_GREEN, RESET);
            printf("  %s--rdp%s                Send RDP preamble before starting scan\n", COL_GREEN, RESET);
            printf("\n");
            printf("  %s--bugs%s               Enable SSL implementation bug work-arounds\n", COL_GREEN, RESET);
            printf("  %s--no-colour%s          Disable coloured output\n", COL_GREEN, RESET);
            printf("  %s--sleep=<msec>%s       Pause between connection request. Default is disabled\n", COL_GREEN, RESET);
            printf("  %s--timeout=<sec>%s      Set socket timeout. Default is 3s\n", COL_GREEN, RESET);
            printf("  %s--connect-timeout=<sec>%s  Set connect timeout. Default is 75s\n", COL_GREEN, RESET);
            printf("  %s--verbose%s            Display verbose output\n", COL_GREEN, RESET);
            printf("  %s--version%s            Display the program version\n", COL_GREEN, RESET);
            printf("  %s--xml=<file>%s         Output results to an XML file. Use - for STDOUT.\n", COL_GREEN, RESET);
            printf("  %s--help%s               Display the help text you are now reading\n\n", COL_GREEN, RESET);
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
                if (testConnection(options))
                {
                    testHost(options);
                }
            }
            else
            {
                if (fileExists(argv[options->targets] + 10) == true)
                {
                    // Open targets file...
                    targetsFile = fopen(argv[options->targets] + 10, "r");
                    if (targetsFile == NULL)
                    {
                        printf_error("Could not open targets file %s.", argv[options->targets] + 10);
                    }
                    else
                    {
                        readLine(targetsFile, line, sizeof(line));
                        while (feof(targetsFile) == 0)
                        {
                            if (strlen(line) != 0)
                            {
                                // Strip https:// from the start of the hostname
                                if (strncmp(line, "https://", 8) == 0)
                                {
                                    memmove(line, line + 8, (strlen(line) - 8));
                                    memset(line + (strlen(line) - 8), 0, 8);
                                }
                                // Get host...
                                tempInt = 0;
                                while ((line[tempInt] != 0) && (line[tempInt] != ':'))
                                    tempInt++;
                                line[tempInt] = 0;
                                strncpy(options->host, line, sizeof(options->host) -1);

                                if (!options->sni_set)
                                {
                                    strncpy(options->sniname, options->host, sizeof(options->host) -1);
                                }

                                // Get port (if it exists)...
                                tempInt++;
                                if (strlen(line + tempInt) > 0)
                                {
                                    int port;
                                    port = atoi(line + tempInt);
                                    // Invalid port
                                    if (port == 0)
                                    {
                                        printf_error("Invalid port specified.");
                                        exit(1);
                                    }
                                    else
                                    {
                                        options->port = port;
                                    }
                                }
                                // Otherwise assume 443
                                else
                                {
                                    options->port = 443;
                                }

                                // Test the host...
                                if (testConnection(options))
                                {
                                    testHost(options);
                                }
                                printf("\n\n");
                            }
                            readLine(targetsFile, line, sizeof(line));
                        }
                    }
                }
                else
                    printf_error("Targets file %s does not exist.", argv[options->targets] + 10);
            }

            // Free Structures
            while (options->ciphers != 0)
            {
                sslCipherPointer = options->ciphers->next;
                free(options->ciphers);
                options->ciphers = sslCipherPointer;
            }
            break;
    }

    // Close XML file, if required...
    if ((xmlArg > 0) && (mode != mode_help))
    {
        fprintf(options->xmlOutput, "</document>\n");
        fclose(options->xmlOutput);
    }

    return 0;
}

int runSSLv2Test(struct sslCheckOptions *options) {
  int ret = false, s = -1;
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
    printf_error("send() failed: %s", strerror(errno));
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
  int ret = false, s = -1;
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
    printf_error("send() failed: %s", strerror(errno));
    exit(1);
  }

  timestamp = htonl(time(NULL)); /* Current time stamp. */
  timestamp_bytes[0] = timestamp & 0xff;
  timestamp_bytes[1] = (timestamp >> 8) & 0xff;
  timestamp_bytes[2] = (timestamp >> 16) & 0xff;
  timestamp_bytes[3] = (timestamp >> 24) & 0xff;

  if (send(s, timestamp_bytes, sizeof(timestamp_bytes), 0) <= 0) {
    printf_error("send() failed: %s", strerror(errno));
    exit(1);
  }

  if (send(s, sslv3_client_hello_2, sizeof(sslv3_client_hello_2), 0) <= 0) {
    printf_error("send() failed: %s", strerror(errno));
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

/* Creates a new byte string of size BS_DEFAULT_NEW_SIZE.  Caller must eventually free it with bs_free().  The caller MUST initialize the pointer to NULL, otherwise the heap will be corrupted. */
void bs_new(bs **b) {
  bs_new_size(b, BS_DEFAULT_NEW_SIZE);
}

/* Creates a new byte string with the specified initial size (or BS_DEFAULT_NEW_SIZE if 0).  Caller must eventually free it with bs_free(). The caller MUST initialize the pointer to NULL, otherwise the heap will be corrupted. */
void bs_new_size(bs **b, size_t new_size) {
  if (b == NULL) {
    fprintf(stderr, "Error: bs_new*() given NULL pointer!\n");
    exit(-1);
  }

  /* If this byte string was already initialized, silently free it, then continue on. */
  if (*b != NULL)
    bs_free(b);

  if (new_size == 0)
    new_size = BS_DEFAULT_NEW_SIZE;

  *b = calloc(1, sizeof(bs));
  if (*b == NULL) {
    fprintf(stderr, "bs_new_size(): failed to allocate new buffer.\n");
    exit(-1);
  }

  (*b)->buf = calloc(new_size, sizeof(unsigned char));
  if ((*b)->buf == NULL) {
    fprintf(stderr, "bs_new_size(): failed to allocate new buffer.\n");
    exit(-1);
  }

  (*b)->size = new_size;
  (*b)->len = 0;
}

/* De-allocates a byte string.  May be safely called multiple times.  Furthermore, bs_free(NULL) does nothing. */
void bs_free(bs **b) {
  if ((b == NULL) || (*b == NULL))
    return;

  free((*b)->buf);
  (*b)->buf = NULL;

  (*b)->size = 0;
  (*b)->len = 0;
  free(*b);
  *b = NULL;
}

/* Appends an array of bytes to this byte string.  The byte string is automatically re-sized if necessary. */
#define OVERFLOW_MESSAGE "Cannot lengthen buffer without overflowing length!\n"
void bs_append_bytes(bs *b, unsigned char *bytes, size_t bytes_len) {
  size_t new_len = 0, b_len = 0, b_size = 0;

  if ((b == NULL) || (bytes == NULL) || (bytes_len == 0))
    return;

  b_len = b->len;
  b_size = b->size;
  new_len = b_len + bytes_len;

  /* Ensure that the new length does not cause an integer overflow. */
  if ((new_len < b_len) || (new_len < bytes_len)) {
    fprintf(stderr, OVERFLOW_MESSAGE);
    exit(-1);
  }

  /* If the buffer needs re-sizing... */
  if (new_len > b_size) {
    /* Double the size of the buffer until it is larger than what we need right now. */
    while (new_len > b_size) {
      /* Ensure we don't overflow the length. */
      if ((b_len * 2) < b_len) {
        fprintf(stderr, OVERFLOW_MESSAGE);
        exit(-1);
      }
      b_size = b_size * 2;
    }

    /* Extend the buffer's size. */
    b->buf = realloc(b->buf, b_size);
    if (b->buf == NULL) {
      fprintf(stderr, "Failed to resize buffer.\n");
      exit(-1);
    }
    b->size = b_size;

    /* Zero out the extended buffer region; leave the existing bytes intact. */
    memset(b->buf + b_len, 0, b_size - b_len);
  }

  /* Copy the new bytes into the buffer right after the existing bytes. */
  memcpy(b->buf + b_len, bytes, bytes_len);

  /* Update the number of used bytes in the buffer. */
  b->len = new_len;
}

/* Appends a uint32_t to the byte string. */
void bs_append_uint32_t(bs *b, uint32_t u) {
  bs_append_bytes(b, (unsigned char *)&u, sizeof(uint32_t));
}

/* Converts an unsigned short to network-order, then appends it to the byte string. */
void bs_append_ushort(bs *b, unsigned short us) {
  uint16_t u16 = htons(us);
  bs_append_bytes(b, (unsigned char *)&u16, sizeof(uint16_t));
}

/* Appends one byte string (src) to another (dst). */
void bs_append_bs(bs *dst, bs *src) {
  if (src == NULL)
    return;

  bs_append_bytes(dst, src->buf, src->len);
}

/* Returns the number of bytes in this byte string. */
size_t bs_get_len(bs *b) {
  if (b == NULL)
    return 0;

  return b->len;
}

/* Returns the number of bytes allocated in the underlying byte string. */
size_t bs_get_size(bs *b) {
  if (b == NULL)
    return 0;

  return b->size;
}

/* Gets the bytes of this byte string.  The caller must _never_ free it directly themselves. */
unsigned char *bs_get_bytes(bs *b) {
  if (b == NULL)
    return NULL;

  return b->buf;
}

/* Gets a single byte from the offset position.  Performs safety checks that the read will not overflow.  Returns 0 if out of bounds.  */
unsigned char bs_get_byte(bs *b, size_t offset) {
  if ((b == NULL) || (offset >= b->len))
    return 0;

  return b->buf[offset];
}

/* Gets a single byte from the offset position.  Performs safety checks that the read will not overflow. */
void bs_set_byte(bs *b, size_t offset, unsigned char byte) {
  if ((b == NULL) || (offset >= b->len))
    return;

  b->buf[offset] = byte;
}

/* Sets a length field in a TLS packet at the specified offset. */
void bs_set_ushort(bs *b, size_t offset, unsigned short length) {
  uint16_t u = htons(length);

  bs_set_byte(b, offset, (unsigned char)u);
  bs_set_byte(b, offset + 1, (unsigned char)(u >> 8));
}

/* Reads the specified number of bytes from socket s into byte string b.  Returns 0 on success, or errno on error. */
int bs_read_socket(bs *b, int s, size_t num_bytes) {
  int ret = -1, n = 0;
  unsigned int i = 0;
  size_t old_len = 0, bytes_read = 0;

  if (b == NULL)
    return -1;

  /* Append num_bytes to the byte string to ensure that the underlying buffer is resized appropriately.  Then reset the length. */
  old_len = b->len;
  for (; i < (num_bytes / sizeof(uint32_t)) + 1; i++)
    bs_append_uint32_t(b, 0);

  b->len = old_len;

  /* Read in num_bytes from the socket and store it in the underlying buffer. */
  bytes_read = 0;
  while (bytes_read < num_bytes) {
    n = recv(s, b->buf + b->len + bytes_read, num_bytes - bytes_read, 0);
    if (n <= 0) {
      if ((errno != 0) && (errno != ECONNRESET))
        ret = errno;

      b->len += bytes_read;
      goto err;
    }
    bytes_read += n;
  }
  b->len += bytes_read;
  ret = 0;

err:
  return ret;
}


/* Internal function.  Use  bs_append_x25519_pubkey() and bs_append_x448_pubkey() instead. */
void __bs_append_xstar_pubkey(bs *b, unsigned int gen_x25519) {
  unsigned char public_key[64] = {0};  /* X25519 requires 32 bytes minimum, and X448 requires 56 bytes minimum. */
  size_t public_key_len = sizeof(public_key);
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;


  /* Create an X25519 or X448 key depending on which is requested. */
  if (gen_x25519)
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  else
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);

  /* Create the private and public keys, and append the raw public key to the byte string. */
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_keygen(pctx, &pkey);
  EVP_PKEY_get_raw_public_key(pkey, public_key, &public_key_len);
  bs_append_bytes(b, public_key, public_key_len);

  EVP_PKEY_free(pkey);  pkey = NULL;
  EVP_PKEY_CTX_free(pctx);  pctx = NULL;
}


/* Generates a random x25519 public key and appends it to the byte string. */
void bs_append_x25519_pubkey(bs *b) {
  __bs_append_xstar_pubkey(b, 1);
}


/* Generates a random x448 public key and appends it to the byte string. */
void bs_append_x448_pubkey(bs *b) {
  __bs_append_xstar_pubkey(b, 0);
}


/* Returns true if the ServerHello response contains TLSv1.3 in its supported_versions extension. */
unsigned int checkSupportedVersionsExtensionForTLS13(bs *server_hello) {

  unsigned int handshake_record_len = bs_get_byte(server_hello, 3) << 8 | bs_get_byte(server_hello, 4);

  /* The Server Hello *record* passed into this function can have multiple handshake protocols inside.  We need to find the Server Hello *handshake protocol*, specifically, since that contains the extensions we need to parse. */
  unsigned int handshake_record_ptr = 5;
  while (handshake_record_ptr < handshake_record_len) {
    unsigned int handshake_protocol_type = bs_get_byte(server_hello, handshake_record_ptr);
    unsigned int handshake_protocol_len = bs_get_byte(server_hello, handshake_record_ptr + 1) << 16 | bs_get_byte(server_hello, handshake_record_ptr + 2) << 8 | bs_get_byte(server_hello, handshake_record_ptr + 3);

    /* We found the Server Hello handshake protocol entry... */
    if (handshake_protocol_type == 2) {

      /* The session ID field is variable, so we need to find its length first so we can skip over it and get to the extensions section. */
      unsigned int session_id_len = (unsigned int)bs_get_byte(server_hello, handshake_record_ptr + 5 + 32 + 1);

      /* Get the length of all the extensions. */
      unsigned int extensions_len_offset = handshake_record_ptr + 5 + 32 + 1 + session_id_len + 4;
      unsigned int extensions_len = bs_get_byte(server_hello, extensions_len_offset) << 8 | bs_get_byte(server_hello, extensions_len_offset + 1);

      /* Loop through each extension. */
      unsigned int extensions_base_offset = extensions_len_offset + 2;
      unsigned int extensions_offset = 0;
      while (extensions_offset < extensions_len) {

	/* Get the extension type and length. */
	unsigned int extension_type = bs_get_byte(server_hello, extensions_base_offset + extensions_offset) << 8 | bs_get_byte(server_hello, extensions_base_offset + extensions_offset + 1);
	unsigned int extension_len = bs_get_byte(server_hello, extensions_base_offset + extensions_offset + 2) << 8 | bs_get_byte(server_hello, extensions_base_offset + extensions_offset + 3);

	/* The supported_version extension is type 43. */
	if (extension_type == 43) {

	  /* The length of this extension should be divisible by 2, since the TLS versions are each 2 bytes. */
	  if ((extension_len % 2) != 0) {
	    fprintf(stderr, "Error in %s: extension length for supported_versions is not even!: %u\n", __func__, extension_len);
	    return 0;
	  }

	  /* Loop through all the TLS versions in the supported_versions extension.  Each version uses two bytes. */
	  for (int i = 0; i < extension_len; i += 2) {
	    unsigned int tls_high_byte = (unsigned int)bs_get_byte(server_hello, extensions_base_offset + extensions_offset + 4 + i);
	    unsigned int tls_low_byte = (unsigned int)bs_get_byte(server_hello, extensions_base_offset + extensions_offset + 5 + i);

	    /* If we find TLS version 0x0304 in the supported_versions extension, then the server supports TLSv1.3! */
	    if ((tls_high_byte == 3) && (tls_low_byte == 4))
	      return 1;
	  }
	}

	extensions_offset += (4 + extension_len);
      }

      /* We already found the Server Hello protocol handshake and looked through all the extensions.  If we reached here, then there's no point in continuing. */
      return 0;
    }

    handshake_record_ptr += (4 + handshake_protocol_len);
  }

  return 0;
}


/* Returns true if a specific TLS version is supported by the server. */
unsigned int checkIfTLSVersionIsSupported(struct sslCheckOptions *options, unsigned int tls_version) {
  bs *tls_extensions = NULL, *ciphersuite_list = NULL, *client_hello = NULL, *server_hello = NULL;
  int ret = false, s = -1;


  tls_extensions = makeTLSExtensions(options, 1);
  if (tls_version == TLSv1_3) {
    /* Extension: supported_groups */
    bs_append_bytes(tls_extensions, (unsigned char []) {
      0x00, 0x0a, // Extension: supported_groups (10)
      0x00, 0x16, // Extension Length (22)
      0x00, 0x14, // Supported Groups List Length (20)
      0x00, 0x17, // secp256r1
      0x00, 0x19, // secp521r1
      0x00, 0x18, // secp384r1
      0x00, 0x1d, // X25519
      0x00, 0x1e, // X448
      0x01, 0x00, // FFDHE2048
      0x01, 0x01, // FFDHE3072
      0x01, 0x02, // FFDHE4096
      0x01, 0x03, // FFDHE6144
      0x01, 0x04, // FFDHE8192
    }, 26);

    /* Add key share for X25519. */
    tlsExtensionAddDefaultKeyShare(tls_extensions);

    /* Explicitly mark that this is a TLSv1.3 Client Hello. */
    tlsExtensionAddTLSv1_3(tls_extensions);

    /* Update the length of the extensions. */
    tlsExtensionUpdateLength(tls_extensions);
  } else {
    /* Extension: supported_groups */
    bs_append_bytes(tls_extensions, (unsigned char []) {
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

    /* Update the length of the extensions. */
    tlsExtensionUpdateLength(tls_extensions);
  }

  ciphersuite_list = makeCiphersuiteListAll(tls_version);
  client_hello = makeClientHello(options, tls_version, ciphersuite_list, tls_extensions);
  bs_free(&ciphersuite_list);
  bs_free(&tls_extensions);

  /* Now connect to the target server. */
  s = tcpConnect(options);
  if (s == 0)
    goto done;

  /* Send the Client Hello message. */
  if (send(s, bs_get_bytes(client_hello), bs_get_len(client_hello), 0) <= 0) {
    printf_error("send() failed while sending Client Hello: %d (%s)", errno, strerror(errno));
    goto done; /* Returns false. */
  }
  bs_free(&client_hello);

  server_hello = getServerHello(s);

  /* If we don't receive a proper Server Hello message, then this TLS version is not supported. */
  if (server_hello == NULL)
    goto done;

  unsigned int expected_tls_version_low = tls_version + 1;
  if (tls_version == TLSv1_3)
    expected_tls_version_low = 3;

  /* Get the server's TLS version and compare it with what we sent. */
  unsigned int server_tls_version_high = bs_get_byte(server_hello, 9);
  unsigned int server_tls_version_low = bs_get_byte(server_hello, 10);
  if ((server_tls_version_high != 3) || (server_tls_version_low != expected_tls_version_low))
    goto done;

  /* TLSv1.3's ServerHello will be tagged as TLSv1.2 in the header, but will include v1.3 in the supported_versions extension.  Some servers (like Windows Server 2019), when only supporting v1.2, will still respond with a ServerHello to our v1.3 Client Hello.  So to eliminate false positives, we need to check the supported_versions extension and ensure v1.3 is listed there. */
  if ((tls_version == TLSv1_3) && (!checkSupportedVersionsExtensionForTLS13(server_hello)))
    goto done;

  /* A valid Server Hello was returned, so this TLS version is supported. */
  ret = true;

 done:
  CLOSE(s);
  bs_free(&ciphersuite_list);
  bs_free(&tls_extensions);
  bs_free(&client_hello);
  bs_free(&server_hello);
  return ret;
}

/* Given a TLSv1_? constant, return its printable string representation. */
char *getPrintableTLSName(unsigned int tls_version) {
  switch (tls_version) {
  case TLSv1_0:
    return "TLSv1.0";
  case TLSv1_1:
    return "TLSv1.1";
  case TLSv1_2:
    return "TLSv1.2";
  case TLSv1_3:
    return "TLSv1.3";
  default:
    return "Unknown";
  }
}

/* Returns a byte string of all TLSv1.3 cipher suites.  The caller must eventually call bs_free() on it. */
bs *makeCiphersuiteListTLS13All() {
  bs *ciphersuite_list = NULL;

  bs_new_size(&ciphersuite_list, 16);
  bs_append_bytes(ciphersuite_list, (unsigned char []) {
    0x13, 0x01, // TLS_AES_128_GCM_SHA256
    0x13, 0x02, // TLS_AES_256_GCM_SHA384
    0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    0x13, 0x04, // TLS_AES_128_CCM_SHA256
    0x13, 0x05, // TLS_AES_128_CCM_8_SHA256
  }, 10);

  return ciphersuite_list;
}


/* Returns a byte string with a list of all ciphersuites registered by IANA. */
bs *makeCiphersuiteListAll(unsigned int tls_version) {
  bs *ciphersuite_list = NULL;

  /* If its TLSv1.3, return the smaller v1.3-specific list. */
  if (tls_version == TLSv1_3)
    return makeCiphersuiteListTLS13All();

  bs_new_size(&ciphersuite_list, 1024);

  for (int i = 0; i < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); i++) {
    if (!strstr(missing_ciphersuites[i].protocol_name, "PRIVATE_CIPHER_"))
      bs_append_ushort(ciphersuite_list, missing_ciphersuites[i].id);
  }

  /* Append TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff), otherwise some servers will reject the connection outright. */
  bs_append_ushort(ciphersuite_list, 255);

  return ciphersuite_list;
}


/* Returns a byte string with a list of all missing ciphersuites for a given TLS version (TLSv1_? constant) .*/
bs *makeCiphersuiteListMissing(unsigned int tls_version) {
  bs *ciphersuite_list = NULL;

  bs_new_size(&ciphersuite_list, 1024);

  if (tls_version == TLSv1_0)
    tls_version = V1_0;
  else if (tls_version == TLSv1_1)
    tls_version = V1_1;
  else if (tls_version == TLSv1_2)
    tls_version = V1_2;

  for (int i = 0; i < (sizeof(missing_ciphersuites) / sizeof(struct missing_ciphersuite)); i++) {
    /* Append only those that OpenSSL does not cover, and those that were not already accepted through a previous run. */
    if ((missing_ciphersuites[i].check_tls_versions & tls_version) && ((missing_ciphersuites[i].accepted_tls_versions & tls_version) == 0)) {
      bs_append_ushort(ciphersuite_list, missing_ciphersuites[i].id);
    }
  }

  return ciphersuite_list;
}

/* Marks a ciphersuite as found so that it is not re-tested again. */
void markFoundCiphersuite(unsigned short server_cipher_id, unsigned int tls_version) {
  if (tls_version == TLSv1_0)
    tls_version = V1_0;
  else if (tls_version == TLSv1_1)
    tls_version = V1_1;
  else if (tls_version == TLSv1_2)
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

/* Creates a basic set of TLS extensions, including SNI, ec_point_formats, Session Ticket TLS, and signature_algorithms. */
bs *makeTLSExtensions(struct sslCheckOptions *options, unsigned int include_signature_algorithms) {
  bs *tls_extensions = NULL;

  bs_new_size(&tls_extensions, 64);

  /* Add the length of the extensions (to be filled in later). */
  bs_append_ushort(tls_extensions, 0);

  /* Extension: server name */
  uint16_t sni_length = strlen(options->sniname);
  uint16_t sni_list_length = sni_length + 3;
  uint16_t extension_length = sni_list_length + 2;

  bs_append_ushort(tls_extensions, 0x0000); /* Extension: server_name */
  bs_append_ushort(tls_extensions, extension_length);
  bs_append_ushort(tls_extensions, sni_list_length);
  bs_append_bytes(tls_extensions, (unsigned char []) { 0x00 /* Server Name Type: host_name */ }, 1);
  bs_append_ushort(tls_extensions, sni_length); /* The length of the hostname. */
  bs_append_bytes(tls_extensions, (unsigned char *)options->sniname, sni_length); /* The hostname itself. */

  /* Extension: ec_point_formats */
  bs_append_bytes(tls_extensions, (unsigned char []) {
    0x00, 0x0b, // Extension: ec_point_formats (11)
    0x00, 0x04, // Extension Length (4)
    0x03, // EC Point Formats Length (3)
    0x00, // Uncompressed
    0x01, // ansiX962_compressed_prime
    0x02, // ansiX962_compressed_char2
  }, 8);

  /* Extension: SessionTicket TLS */
  bs_append_bytes(tls_extensions, (unsigned char []) {
    0x00, 0x23, // Extension: SessionTicket TLS (35)
    0x00, 0x00, // Extension Length (0)
  }, 4);

  if (include_signature_algorithms) {
    /* Extension: signature_algorithms */
    bs_append_bytes(tls_extensions, (unsigned char []) {
      0x00, 0x0d, // Extension: signature_algorithms (13)
      0x00, 0x30, // Extension Length (48)
      0x00, 0x2e, // Signature Hash Algorithms Length (46)
      0x08, 0x04, // rsa_pss_rsae_sha256
      0x08, 0x05, // rsa_pss_rsae_sha384
      0x08, 0x06, // rsa_pss_rsae_sha512
      0x08, 0x07, // ed25519
      0x08, 0x08, // ed448
      0x08, 0x09, // rsa_pss_pss_sha256
      0x08, 0x0a, // rsa_pss_pss_sha384
      0x08, 0x0b, // rsa_pss_pss_sha512
      0x06, 0x01, // rsa_pkcs1_sha512
      0x06, 0x02, // SHA512 DSA
      0x06, 0x03, // ecdsa_secp521r1_sha512
      0x05, 0x01, // rsa_pkcs1_sha384
      0x05, 0x02, // SHA384 DSA
      0x05, 0x03, // ecdsa_secp384r1_sha384
      0x04, 0x01, // rsa_pkcs1_sha256"
      0x04, 0x02, // SHA256 DSA
      0x04, 0x03, // ecdsa_secp256r1_sha256
      0x03, 0x01, // SHA224 ECDSA
      0x03, 0x02, // SHA224 DSA
      0x03, 0x03, // SHA224 ECDSA
      0x02, 0x01, // rsa_pkcs1_sha1
      0x02, 0x02, // SHA1 DSA
      0x02, 0x03, // ecdsa_sha1
    }, 52);
  }

  /* Set the extension length. */
  tlsExtensionUpdateLength(tls_extensions);
  return tls_extensions;
}

/* Adds the TLS supported_versions extension, set to TLSv1.3 only. */
void tlsExtensionAddTLSv1_3(bs *tls_extensions) {
  bs_append_bytes(tls_extensions, (unsigned char []) {
      0x00, 0x2b, // supported_versions (43)
      0x00, 0x03, // Length
      0x02,       // Supported Versions Length
      0x03, 0x04, // Supported Version: TLS v1.3
  }, 7);
  tlsExtensionUpdateLength(tls_extensions);
}

/* Adds default key_share extension. */
void tlsExtensionAddDefaultKeyShare(bs *tls_extensions) {

  bs_append_bytes(tls_extensions, (unsigned char []) {
    0x00, 0x33, // key_share (51)
    0x00, 0x26, // Length (38)
    0x00, 0x24, // Key Share List Length (36)
    0x00, 0x1d, // Group ID (X25519)
    0x00, 0x20, // Key Exchange Length (32)
  }, 10);

  /* Append a random X25519 public key. */
  bs_append_x25519_pubkey(tls_extensions);

  /* Update the length of the extensions. */
  tlsExtensionUpdateLength(tls_extensions);
}

/* Retrieves a TLS Handshake record, or returns NULL on error. */
bs *getTLSHandshakeRecord(int s) {
  bs *tls_record = NULL;
  bs_new_size(&tls_record, 512);

  /* Read in the first 5 bytes to get the length of the rest of the record. */
  int err = bs_read_socket(tls_record, s, 5);
  if (err != 0)
    goto err;

  /* Ensure that the Content Type is Handshake (22). */
  if (bs_get_byte(tls_record, 0) != 0x16)
    goto err;

  /* Get the length of the record. */
  unsigned short packet_len = (bs_get_byte(tls_record, 3) << 8) | bs_get_byte(tls_record, 4);

  /* Read in the rest of the record. */
  err = bs_read_socket(tls_record, s, packet_len);
  if (err != 0)
    goto err;

  return tls_record;

 err:
  bs_free(&tls_record);
  return NULL;
}

/* Update the length of the TLS extensions. */
void tlsExtensionUpdateLength(bs *tls_extensions) {
  bs_set_ushort(tls_extensions, 0, bs_get_len(tls_extensions) - 2);
}

/* From socket s, reads a ServerHello from the network.  Returns a byte string on success (which the caller must bs_free()), or NULL on failure. */
bs *getServerHello(int s) {
  bs *server_hello = getTLSHandshakeRecord(s);

  if (server_hello == NULL)
    goto err;

  /* Ensure that the Handshake Type is Server Hello (2). */
  if (bs_get_byte(server_hello, 5) != 0x02)
    goto err;

  return server_hello;

 err:
  bs_free(&server_hello);
  return NULL;
}

/* Returns a byte string (which the caller must later bs_free()) containing a TLS Client Hello message.  The 'tls_version' must be one of the TLSv1_? constants.  The specified ciphersuite list and TLS extensions will be included.  */
bs *makeClientHello(struct sslCheckOptions *options, unsigned int tls_version, bs *ciphersuite_list, bs *tls_extensions) {
  bs *client_hello = NULL;
  unsigned int tls_record_version_low_byte = 1, tls_handshake_version_low_byte = 1;
  time_t time_now = time(NULL);


  /* For TLSv1.0, 1.1, and 1.2, the TLS Record version and Handshake version are the same (and what they should be).  For TLSv1.3, the TLS Record claims to be TLSv1.0 and the Handshake claims to be TLSv1.2; this is for compatibility of buggy middleware that most implementations follow. */
  if (tls_version < TLSv1_3) {
    tls_record_version_low_byte += tls_version;
    tls_handshake_version_low_byte += tls_version;
  } else {
    tls_record_version_low_byte = 1;
    tls_handshake_version_low_byte = 3;
  }

  /* Allocate byte string for the Client Hello and TLS extensions. */
  bs_new_size(&client_hello, 1024);

  /* Build the TLSv1 Record with the ClientHello message. */
  bs_append_bytes(client_hello, (unsigned char []) {
    0x16,       // Content Type: Handshake (22)
    0x03, (unsigned char)tls_record_version_low_byte, // Version: TLS 1.x
    0x00, 0x00, // Length (to be filled in later)
    0x01,       // Handshake Type: Client Hello
    0x00, 0x00, 0x00, // Length (to be filled in later)
    0x03, (unsigned char)tls_handshake_version_low_byte, // Version: TLS 1.x
  }, 11);

  /* "Random" 32 bytes. */
  uint32_t rand = htonl(time_now);
  bs_append_uint32_t(client_hello, rand); /* The first 4 bytes is the timestamp. */

  for (int i = 1; i < 8; i++) {
    rand = rand + (time_now ^ (uint32_t)((~(i + 0) << 24) | (~(i + 1) << 16) | (~(i + 2) << 8) | (~(i + 3) << 0)));
    bs_append_uint32_t(client_hello, rand);
  }

  /* Session ID Length: 32 */
  bs_append_bytes(client_hello, (unsigned char []) { 32 }, 1);

  /* A "random" 32-byte session ID. */
  for (int i = 0; i < 8; i++) {
    rand += (time_now ^ (uint32_t)((~(i + 0) << 24) | (~(i + 1) << 16) | (~(i + 2) << 8) | (~(i + 3) << 0)));
    bs_append_uint32_t(client_hello, rand);
  }

  /* Add the length (in bytes) of the ciphersuites list to the Client Hello. */
  bs_append_ushort(client_hello, bs_get_len(ciphersuite_list));

  /* Add the ciphersuite list. */
  bs_append_bs(client_hello, ciphersuite_list);

  /* Add the compression options. */
  bs_append_bytes(client_hello, (unsigned char []) {
    0x01, // Compression Methods Length (1)
    0x00  // Compression Method: null (0)
  }, 2);

  /* Add the extensions to the Client Hello. */
  bs_append_bs(client_hello, tls_extensions);

  /* Set the length of the Client Hello. */
  bs_set_byte(client_hello, 6, 0);
  bs_set_ushort(client_hello, 7, bs_get_len(client_hello) - 9);

  /* Set the length of the Record Layer. */
  bs_set_ushort(client_hello, 3, bs_get_len(client_hello) - 5);
  return client_hello;
}

/* Checks all ciphersuites that OpenSSL does not support.  When version is 0, TLSv1.0 is tested.  When set to 1, TLSv1.1 is tested.  When set to 2, TLSv1.2 is tested. */
int testMissingCiphers(struct sslCheckOptions *options, unsigned int tls_version) {
  int ret = false, s = -1, valid_cipher_id = false;
  unsigned int tls_version_low_byte = 1;
  char *tls_printable_name = getPrintableTLSName(tls_version);
  bs *client_hello = NULL, *server_hello = NULL, *ciphersuite_list = NULL, *tls_extensions = NULL;


  tls_version_low_byte += tls_version;

  /* Continue until a Server Hello isn't received. */
  while (1) {
    int cipher_bits = -1;
    char *cipher_name = NULL;
    struct timeval tval_start = {0}, tval_end = {0}, tval_elapsed = {0};


    gettimeofday(&tval_start, NULL);

    tls_extensions = makeTLSExtensions(options, 1);

    /* Extension: supported_groups */
    bs_append_bytes(tls_extensions, (unsigned char []) {
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

    tlsExtensionUpdateLength(tls_extensions);

    /* Construct the list of all ciphersuites not implemented by OpenSSL. */
    ciphersuite_list = makeCiphersuiteListMissing(tls_version);

    client_hello = makeClientHello(options, tls_version, ciphersuite_list, tls_extensions);
    bs_free(&tls_extensions);

    /* Now connect to the target server. */
    s = tcpConnect(options);
    if (s == 0)
      goto done;

    /* Send the Client Hello message. */
    if (send(s, bs_get_bytes(client_hello), bs_get_len(client_hello), 0) <= 0) {
      printf_error("send() failed while sending Client Hello: %d (%s)", errno, strerror(errno));
      goto done; /* Returns false. */
    }
    bs_free(&client_hello);

    server_hello = getServerHello(s);

    /* If we don't receive a proper Server Hello message, or its too short, abort.  We need to reach at least the session ID field (offset 44). */
    if ((server_hello == NULL) || (bs_get_len(server_hello) < 44))
      goto done;

    /* Close the socket, since we're done reading. */
    CLOSE(s);

    /* Check that the TLS version returned is what we sent earlier. */
    if ((bs_get_byte(server_hello, 1) != 0x03) || (bs_get_byte(server_hello, 2) != (unsigned char)tls_version_low_byte))
      goto done;

    /* At this point, the test is considered a success, even if the server rejects our Client Hello. */
    ret = true;

    /* Get the length of the session ID.  We must jump over this to reach the ciphersuite selected by the server. */
    unsigned int session_id_len = bs_get_byte(server_hello, 43);

    /* Its impossible for one byte to overflow an unsigned int (on any modern hardware), but still... */
    if ((session_id_len + 43 + 2 + 1) < session_id_len) {
      fprintf(stderr, "Error: potential integer overflow averted (%d).\n", session_id_len);
      exit(-1);
    }

    /* Check that the session ID length wouldn't put us past our buffer boundary. */
    if ((session_id_len + 43 + 2 + 1) > bs_get_len(server_hello)) {
      fprintf(stderr, "Error: size of server_hello (%"SIZE_T_FMT") is not large enough to reach cipher suite (%u).\n", sizeof(server_hello), session_id_len + 43 + 2);
      exit(-1);
    }

    /* Extract the cipher ID. */
    unsigned char cipher_id_byte1 = bs_get_byte(server_hello, session_id_len + 43 + 1);
    unsigned char cipher_id_byte2 = bs_get_byte(server_hello, session_id_len + 43 + 2);
    unsigned short cipher_id = (cipher_id_byte1 << 8) | cipher_id_byte2;

    bs_free(&server_hello);

    /* Check that the server returned a cipher ID that we requested.  Some servers
     * will return a cipher ID that we didn't request when our ciphersuite list
     * doesn't match anything (this likely violates the spec, but real servers in the
     * wild do this sometimes, so we have to handle it).  When this happens, we
     * conclude that the server does not accept any of the ciphers, so we're done. */
    valid_cipher_id = false;
    for (int i = 0; i < (bs_get_len(ciphersuite_list) / 2) && (valid_cipher_id == false); i++) {
      if ((bs_get_byte(ciphersuite_list, i * 2) == cipher_id_byte1) &&
          (bs_get_byte(ciphersuite_list, (i * 2) + 1) == cipher_id_byte2))
        valid_cipher_id = true;
    }

    if (valid_cipher_id == false)
      goto done;

    bs_free(&ciphersuite_list);

    /* Mark this cipher ID as supported by the server, so when we loop again, the next ciphersuite list doesn't include it. */
    markFoundCiphersuite(cipher_id, tls_version);

    /* Get the IANA name and cipher bit strength (maybe -1 when unknown). */
    cipher_name = resolveCipherID(cipher_id, &cipher_bits);

    /* Get the number of milliseconds that have elapsed. */
    gettimeofday(&tval_end, NULL);
    timersub(&tval_end, &tval_start, &tval_elapsed);
    unsigned int milliseconds_elapsed = tval_elapsed.tv_sec * 1000 + (int)tval_elapsed.tv_usec / 1000;

    /* Output the cipher information. */
    outputCipher(options, NULL, tls_printable_name, cipher_id, cipher_name, cipher_bits, 1, milliseconds_elapsed);
  }

 done:
  CLOSE(s);
  bs_free(&ciphersuite_list);
  bs_free(&tls_extensions);
  bs_free(&client_hello);
  bs_free(&server_hello);
  return ret;
}

/* Enumerates all the group key exchanges supported by the server.  Tests the highest supported protocol between TLSv1.0 and v1.2, along with TLSv1.3 (if enabled). */
int testSupportedGroups(struct sslCheckOptions *options) {
  int ret = true, s = -1;
  unsigned int printed_header = 0;
  int test_versions[2] = {-1, -1};
  bs *client_hello = NULL, *ciphersuite_list = NULL, *tls_extensions = NULL, *tls_record = NULL, *key_exchange = NULL;

  struct group_key_exchange {
    uint16_t group_id;
    char *group_name;
    unsigned int group_bit_strength; /* The bit strength equivalent of this group. */
    char *color;
    int nid;               /* NID for group, or -1 for X25519/X448. */
    unsigned int nid_type; /* One of the NID_TYPE_* flags. */
    uint16_t key_exchange_len;
  };


  /* Auto-generated by ./tools/iana_tls_supported_groups_parser.py on December 24, 2019. */
#define COL_PLAIN ""
#define NID_TYPE_UNUSED 0
#define NID_TYPE_ECDHE 1 /* For ECDHE curves (sec*, P-256/384-521) */
#define NID_TYPE_DHE 2   /* For ffdhe* */
#define NID_TYPE_X25519 3
#define NID_TYPE_X448 4
  /* Bit strength of DHE 2048 and 3072-bit moduli is taken directly from NIST SP 800-57 pt.1, rev4., pg. 53; DHE 4096, 6144, and 8192 are estimated using that document. */
  struct group_key_exchange group_key_exchanges[] = {
    {0x0001, "sect163k1", 81, COL_RED, NID_sect163k1, NID_TYPE_ECDHE, 0},
    {0x0002, "sect163r1", 81, COL_RED, NID_sect163r1, NID_TYPE_ECDHE, 0},
    {0x0003, "sect163r2", 81, COL_RED, NID_sect163r2, NID_TYPE_ECDHE, 0},
    {0x0004, "sect193r1", 96, COL_RED, NID_sect193r1, NID_TYPE_ECDHE, 0},
    {0x0005, "sect193r2", 96, COL_RED, NID_sect193r2, NID_TYPE_ECDHE, 0},
    {0x0006, "sect233k1", 116, COL_PLAIN, NID_sect233k1, NID_TYPE_ECDHE, 0},
    {0x0007, "sect233r1", 116, COL_PLAIN, NID_sect233r1, NID_TYPE_ECDHE, 0},
    {0x0008, "sect239k1", 119, COL_PLAIN, NID_sect239k1, NID_TYPE_ECDHE, 0},
    {0x0009, "sect283k1", 141, COL_PLAIN, NID_sect283k1, NID_TYPE_ECDHE, 0},
    {0x000a, "sect283r1", 141, COL_PLAIN, NID_sect283r1, NID_TYPE_ECDHE, 0},
    {0x000b, "sect409k1", 204, COL_PLAIN, NID_sect409k1, NID_TYPE_ECDHE, 0},
    {0x000c, "sect409r1", 204, COL_PLAIN, NID_sect409r1, NID_TYPE_ECDHE, 0},
    {0x000d, "sect571k1", 285, COL_PLAIN, NID_sect571k1, NID_TYPE_ECDHE, 0},
    {0x000e, "sect571r1", 285, COL_PLAIN, NID_sect571r1, NID_TYPE_ECDHE, 0},
    {0x000f, "secp160k1", 80, COL_RED, NID_secp160k1, NID_TYPE_ECDHE, 0},
    {0x0010, "secp160r1", 80, COL_RED, NID_secp160r1, NID_TYPE_ECDHE, 0},
    {0x0011, "secp160r2", 80, COL_RED, NID_secp160r2, NID_TYPE_ECDHE, 0},
    {0x0012, "secp192k1", 96, COL_RED, NID_secp192k1, NID_TYPE_ECDHE, 0},
    {0x0013, "secp192r1", 96, COL_RED, NID_X9_62_prime192v1, NID_TYPE_ECDHE, 0},
    {0x0014, "secp224k1", 112, COL_PLAIN, NID_secp224k1, NID_TYPE_ECDHE, 0},
    {0x0015, "secp224r1", 112, COL_PLAIN, NID_secp224r1, NID_TYPE_ECDHE, 0},
    {0x0016, "secp256k1", 128, COL_GREEN, NID_secp256k1, NID_TYPE_ECDHE, 0},
    {0x0017, "secp256r1 (NIST P-256)", 128, COL_PLAIN, NID_X9_62_prime256v1, NID_TYPE_ECDHE, 0},
    {0x0018, "secp384r1 (NIST P-384)", 192, COL_PLAIN, NID_secp384r1, NID_TYPE_ECDHE, 0},
    {0x0019, "secp521r1 (NIST P-521)", 260, COL_PLAIN, NID_secp521r1, NID_TYPE_ECDHE, 0},
    {0x001a, "brainpoolP256r1", 128, COL_PLAIN, NID_brainpoolP256r1, NID_TYPE_ECDHE, 0},
    {0x001b, "brainpoolP384r1", 192, COL_PLAIN, NID_brainpoolP384r1, NID_TYPE_ECDHE, 0},
    {0x001c, "brainpoolP512r1", 256, COL_PLAIN, NID_brainpoolP512r1, NID_TYPE_ECDHE, 0},
    {0x001d, "x25519", 128, COL_GREEN, -1, NID_TYPE_X25519, 32},
    {0x001e, "x448", 224, COL_GREEN, -1, NID_TYPE_X448, 56},
    {0x0100, "ffdhe2048", 112, COL_PLAIN, NID_ffdhe2048, NID_TYPE_DHE, 256},
    {0x0101, "ffdhe3072", 128, COL_PLAIN, NID_ffdhe3072, NID_TYPE_DHE, 384},
    {0x0102, "ffdhe4096", 150, COL_PLAIN, NID_ffdhe4096, NID_TYPE_DHE, 512},
    {0x0103, "ffdhe6144", 175, COL_PLAIN, NID_ffdhe6144, NID_TYPE_DHE, 768},
    {0x0104, "ffdhe8192", 192, COL_PLAIN, NID_ffdhe8192, NID_TYPE_DHE, 1024},
  };


  /* If TLSv1.3 is supported, test it first. */
  unsigned int index = 0;
  if (options->tls13_supported) {
    test_versions[index] = TLSv1_3;
    index++;
  }

  /* For TLSv1.2 and below, test the highest protocol version supported. */
  if (options->tls12_supported)
    test_versions[index] = TLSv1_2;
  else if (options->tls11_supported)
    test_versions[index] = TLSv1_1;
  else if (options->tls10_supported)
    test_versions[index] = TLSv1_0;

  /* Loop through the one or two TLS versions to test. */
  for (index = 0; index < (sizeof(test_versions) / sizeof(int)); index++) {
    int tls_version = test_versions[index];

    /* If there's only one version to test... */
    if (tls_version == -1)
      break;

    if (tls_version == TLSv1_3)
      ciphersuite_list = makeCiphersuiteListAll(tls_version);
    else {
      /* For some reason, with TLSv1.2 (and maybe below), passing all ciphersuites causes false negatives.  So we use a string of bytes sniffed from an OpenSSL client connection. */
      bs_new(&ciphersuite_list);
      bs_append_bytes(ciphersuite_list, (unsigned char []) { 0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0xa5, 0x00, 0xa3, 0x00, 0xa1, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x6a, 0x00, 0x69, 0x00, 0x68, 0x00, 0x39, 0x00, 0x38, 0x00, 0x37, 0x00, 0x36, 0x00, 0x88, 0x00, 0x87, 0x00, 0x86, 0x00, 0x85, 0xc0, 0x32, 0xc0, 0x2e, 0xc0, 0x2a, 0xc0, 0x26, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x9d, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0xa4, 0x00, 0xa2, 0x00, 0xa0, 0x00, 0x9e, 0x00, 0x67, 0x00, 0x40, 0x00, 0x3f, 0x00, 0x3e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x31, 0x00, 0x30, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x98, 0x00, 0x97, 0x00, 0x45, 0x00, 0x44, 0x00, 0x43, 0x00, 0x42, 0xc0, 0x31, 0xc0, 0x2d, 0xc0, 0x29, 0xc0, 0x25, 0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x13, 0x00, 0x10, 0x00, 0x0d, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0x00, 0xff }, 170);
    }

    /* For each key exchange group... */
    for (int i = 0; i < (sizeof(group_key_exchanges) / sizeof(struct group_key_exchange)); i++) {
      uint16_t group_id = group_key_exchanges[i].group_id;
      char *group_name = group_key_exchanges[i].group_name;
      char *color = group_key_exchanges[i].color;
      unsigned int group_bit_strength = group_key_exchanges[i].group_bit_strength;
      int nid = group_key_exchanges[i].nid;
      unsigned nid_type = group_key_exchanges[i].nid_type;
      uint16_t key_exchange_len = group_key_exchanges[i].key_exchange_len;

      /* This will hold the key exchange data that we send to the server. */
      bs_new_size(&key_exchange, key_exchange_len);

      /* Generate the right type of key exchange data. */
      if (nid_type == NID_TYPE_X25519)
	bs_append_x25519_pubkey(key_exchange);
      else if (nid_type == NID_TYPE_X448)
        bs_append_x448_pubkey(key_exchange);
      else if (nid_type == NID_TYPE_ECDHE) {

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

        bs_append_bytes(key_exchange, kex_buf, key_exchange_len);
        OPENSSL_free(kex_buf); kex_buf = NULL;
        EC_KEY_free(key); key = NULL;

      } else if (nid_type == NID_TYPE_DHE) {

        /* The value (Y) for FFDHE group must be 1 < Y < p - 1 (see RFC7919).  Furthermore, GnuTLS checks that Y ^ q mod p == 1 (see GnuTLS v3.6.11.1, lib/nettle/pk.c:291).  The easiest way to do this seems to be to actually generate real DH public keys. */
        DH *dh = DH_new_by_nid(nid);
        if (!DH_generate_key(dh)) {
          bs_free(&key_exchange);
          fprintf(stderr, "Failed to generate DH key for nid %d\n", nid);
          continue;
        }

        /* Make array to read in DH public key. */
        unsigned int bytes_len = key_exchange_len;
        unsigned char *bytes = calloc(bytes_len, sizeof(unsigned char));
        if (bytes == NULL) {
          fprintf(stderr, "Failed to allocate buffer for key.\n");
          exit(-1);
        }

        /* Export the public key to our array. */
        const BIGNUM *pub_key = NULL;
        DH_get0_key(dh, &pub_key, NULL);
        if (!BN_bn2binpad(pub_key, bytes, bytes_len)) {
          bs_free(&key_exchange);
          fprintf(stderr, "Failed to get DH key for nid %d\n", nid);
          continue;
        }

        /* Add the bytes to our byte string. */
        bs_append_bytes(key_exchange, bytes, bytes_len);
        FREE(bytes);  bytes_len = 0;

      } else {
        /* Use the provided value, since it must be a specific format. */
        fprintf(stderr, "Error: unknown NID_TYPE in struct: %d\n", nid_type);
        exit(-1);
      }

      /* Make generic TLS extensions (with SNI, accepted EC point formats, etc). */
      tls_extensions = makeTLSExtensions(options, 1);

      /* Add the supported_versions extension to signify we are using TLS v1.3. */
      if (tls_version == TLSv1_3)
        tlsExtensionAddTLSv1_3(tls_extensions);

      /* Add the supported_groups extension.  Only add the one group we are testing for. */
      bs_append_bytes(tls_extensions, (unsigned char []) {
        0x00, 0x0a, // Extension Type: supported_groups (10)
        0x00, 0x04, // Extension Length (4)
        0x00, 0x02, // Supported Groups List Length (2)
      }, 6);
      bs_append_ushort(tls_extensions, group_id);

      /* Only add the key_share extension if we're using TLS v1.3. */
      if (tls_version == TLSv1_3) {
        /* Add the key_share extension for the current group type. */
        bs_append_bytes(tls_extensions, (unsigned char []) { 0x00, 0x33 }, 2); // Extension Type: key_share (51)
        bs_append_ushort(tls_extensions, bs_get_len(key_exchange) + 6); // Extension Length
        bs_append_ushort(tls_extensions, bs_get_len(key_exchange) + 4); // Client Key Share Length
        bs_append_ushort(tls_extensions, group_id); // Group ID.
        bs_append_ushort(tls_extensions, bs_get_len(key_exchange)); // Key Exchange Length
        bs_append_bs(tls_extensions, key_exchange); // Key Exchange
      }
      bs_free(&key_exchange);

      /* Update the TLS extensions length since we manually added to it. */
      tlsExtensionUpdateLength(tls_extensions);

      /* Create the Client Hello buffer using the ciphersuite list and TLS extensions. */
      client_hello = makeClientHello(options, tls_version, ciphersuite_list, tls_extensions);

      /* Free the TLS extensions since we're done with them.  Note: we don't free the ciphersuite_list because we'll need them on the next loop. */
      bs_free(&tls_extensions);

      CLOSE(s); /* In case the last loop left the socket open. */

      /* Now connect to the target server. */
      s = tcpConnect(options);
      if (s == 0) {
        ret = false;
        goto done;
      }

      /* Send the Client Hello message. */
      if (send(s, bs_get_bytes(client_hello), bs_get_len(client_hello), 0) <= 0) {
        printf_error("send() failed while sending Client Hello: %d (%s)", errno, strerror(errno));
        ret = false;
        goto done;
      }
      bs_free(&client_hello);

      tls_record = getServerHello(s);

      /* This group is definitely not supported. */
      if (tls_record == NULL) {
        CLOSE(s);
        continue;
      }

      /* For TLSv1.2 and below, we need to examine the Server Key Exchange record. */
      if (tls_version < TLSv1_3) {
	unsigned int handshake_type = 0;
	unsigned int handshake_type_offset = 5;
	uint32_t handshake_len = 0;

	/* Loop through all the handshake protocols inside this TLS record.  Some implementations only include one (such as OpenSSL), and others include several (such as Windows Server 2022). */
        while (tls_record != NULL) {

	  handshake_type = bs_get_byte(tls_record, handshake_type_offset);

	  /* Handshake type 12 is a Server Key Exchange.  This may have the group information we need, so we can stop searching. */
	  if (handshake_type == 12) {
            break;
	  /* Handshake type 14 is a Server Hello Done.  If we reach this before finding a Server Key Exchange, we know the server does not support this group. */
	  } else if (handshake_type == 14) {
            bs_free(&tls_record);
            CLOSE(s);
            continue;
          }

	  /* The handshake length is strangely only three bytes... */
	  handshake_len = bs_get_byte(tls_record, handshake_type_offset + 1) << 16;
	  handshake_len |= bs_get_byte(tls_record, handshake_type_offset + 2) << 8;
	  handshake_len |= bs_get_byte(tls_record, handshake_type_offset + 3) << 0;

	  /* If we processed all handshake messages in this TLS record, read the next record. */
	  if (tls_record->len < handshake_len + handshake_type_offset) {
	    bs_free(&tls_record);
	    tls_record = getTLSHandshakeRecord(s);
	    handshake_type_offset = 5;
	  } else
	    handshake_type_offset += (handshake_len + 4);

        }

        /* Error, so skip this group. */
        if (tls_record == NULL) {
          bs_free(&tls_record);
          CLOSE(s);
          continue;
        }

        /* If this Server Key Exchange does not have a named_curve (3) field, skip this group. */
        if (bs_get_byte(tls_record, handshake_type_offset + 4) != 3) {
          bs_free(&tls_record);
          CLOSE(s);
          continue;
        }

        /* Check that the named_curve result is the group we requested. */
        uint16_t server_group_id = bs_get_byte(tls_record, handshake_type_offset + 5) << 8 | bs_get_byte(tls_record, handshake_type_offset + 6);
        if (server_group_id != group_id) {
          bs_free(&tls_record);
          CLOSE(s);
          continue;
        }
      }

      bs_free(&tls_record);
      CLOSE(s);

      if (!printed_header) {
        printf("\n  %sServer Key Exchange Group(s):%s\n", COL_BLUE, RESET);
        printed_header = 1;
      }

      char *bits_color = RESET;
      if (group_bit_strength < 112)
        bits_color = COL_RED;
      else
        bits_color = COL_GREEN;

      char *printable_TLS_name = getPrintableTLSName(tls_version);
      printf("%s  %s%d%s bits  %s%s%s\n", printable_TLS_name, bits_color, group_bit_strength, RESET, color, group_name, RESET);
      printf_xml("  <group sslversion=\"%s\" bits=\"%d\" name=\"%s\" id=\"0x%04x\" />\n", printable_TLS_name, group_bit_strength, group_name, group_id);
    }
  }

 done:
  CLOSE(s);
  bs_free(&ciphersuite_list);
  bs_free(&tls_extensions);
  bs_free(&client_hello);
  bs_free(&tls_record);
  return ret;
}

/* Enumerates all the signature algorithms supported by the server. */
int testSignatureAlgorithms(struct sslCheckOptions *options) {

  struct signature_algorithm {
    uint16_t sig_id;
    char *sig_name;
    char *color;
  };

#define COL_PLAIN ""
#define BOGUS_SIG_ALG_ID 0xfdff /* Last un-assigned ID. */
  struct signature_algorithm signature_algorithms[] = {
    {BOGUS_SIG_ALG_ID, "bogus", COL_RED}, /* Tests if the server is accepting all. */
    {0x0001, "rsa_pkcs1_nohash", COL_RED},
    {0x0002, "dsa_nohash", COL_RED},
    {0x0003, "ecdsa_nohash", COL_RED},
    {0x0101, "rsa_pkcs1_md5", COL_RED},
    {0x0102, "dsa_md5", COL_RED},
    {0x0103, "ecdsa_md5", COL_RED},
    {0x0201, "rsa_pkcs1_sha1", COL_RED},
    {0x0202, "dsa_sha1", COL_RED},
    {0x0203, "ecdsa_sha1", COL_RED},
    {0x0301, "rsa_pkcs1_sha224", COL_YELLOW},
    {0x0302, "dsa_sha224", COL_RED},
    {0x0303, "ecdsa_sha224", COL_YELLOW},
    {0x0401, "rsa_pkcs1_sha256", COL_PLAIN},
    {0x0402, "dsa_sha256", COL_RED},
    {0x0403, "ecdsa_secp256r1_sha256", COL_PLAIN},
    {0x0501, "rsa_pkcs1_sha384", COL_PLAIN},
    {0x0502, "dsa_sha384", COL_RED},
    {0x0503, "ecdsa_secp384r1_sha384", COL_PLAIN},
    {0x0601, "rsa_pkcs1_sha512", COL_PLAIN},
    {0x0602, "dsa_sha512", COL_RED},
    {0x0603, "ecdsa_secp521r1_sha512", COL_PLAIN},
    {0x0804, "rsa_pss_rsae_sha256", COL_PLAIN},
    {0x0805, "rsa_pss_rsae_sha384", COL_PLAIN},
    {0x0806, "rsa_pss_rsae_sha512", COL_PLAIN},
    {0x0807, "ed25519", COL_GREEN},
    {0x0808, "ed448", COL_GREEN},
    {0x0809, "rsa_pss_pss_sha256", COL_PLAIN},
    {0x080a, "rsa_pss_pss_sha384", COL_PLAIN},
    {0x080b, "rsa_pss_pss_sha512", COL_PLAIN},
  };

  unsigned int printed_header = 0;
  int ret = true, s = -1;
  int test_versions[2] = {-1, -1};
  bs *client_hello = NULL, *ciphersuite_list = NULL, *tls_extensions = NULL, *server_hello = NULL;

  /* If TLSv1.3 is supported, test it first. */
  unsigned int index = 0;
  if (options->tls13_supported) {
    test_versions[index] = TLSv1_3;
    index++;
  }

  /* For TLSv1.2 and below, test the highest protocol version supported. */
  if (options->tls12_supported)
    test_versions[index] = TLSv1_2;
  else if (options->tls11_supported)
    test_versions[index] = TLSv1_1;
  else if (options->tls10_supported)
    test_versions[index] = TLSv1_0;

  /* Loop through the one or two TLS versions to test. */
  for (index = 0; index < (sizeof(test_versions) / sizeof(int)); index++) {
    int tls_version = test_versions[index];

    /* If there's only one version to test... */
    if (tls_version == -1)
      break;

    if (tls_version == TLSv1_3) {
      /* Get all TLSv1.3 ciphersuites. */
      ciphersuite_list = makeCiphersuiteListTLS13All();
    } else
      ciphersuite_list = makeCiphersuiteListAll(tls_version);


    /* For each signature algorithm... */
    for (int i = 0; i < (sizeof(signature_algorithms) / sizeof(struct signature_algorithm)); i++) {
      uint16_t sig_id = signature_algorithms[i].sig_id;
      char *sig_name = signature_algorithms[i].sig_name;
      char *color = signature_algorithms[i].color;


      /* Make generic TLS extensions (with SNI, accepted EC point formats, etc). */
      tls_extensions = makeTLSExtensions(options, 0);

      if (tls_version == TLSv1_3) {
        /* Extension: supported_groups */
        bs_append_bytes(tls_extensions, (unsigned char []) {
          0x00, 0x0a, // Extension: supported_groups (10)
          0x00, 0x16, // Extension Length (22)
          0x00, 0x14, // Supported Groups List Length (20)
          0x00, 0x17, // secp256r1
          0x00, 0x19, // secp521r1
          0x00, 0x18, // secp384r1
          0x00, 0x1d, // X25519
          0x00, 0x1e, // X448
          0x01, 0x00, // FFDHE2048
          0x01, 0x01, // FFDHE3072
          0x01, 0x02, // FFDHE4096
          0x01, 0x03, // FFDHE6144
          0x01, 0x04, // FFDHE8192
        }, 26);

        /* Add key shares for X25519. */
        tlsExtensionAddDefaultKeyShare(tls_extensions);

        /* Add the supported_versions extension to signify we are using TLS v1.3. */
        tlsExtensionAddTLSv1_3(tls_extensions);
      }

      /* Add the signature_algorithms extension.  Only add the one group we are testing for. */
      bs_append_bytes(tls_extensions, (unsigned char []) {
        0x00, 0x0d, // Extension Type: signature_algorithms (13)
        0x00, 0x04, // Extension Length (4)
        0x00, 0x02, // Signature Hash Algorithms List Length (2)
      }, 6);
      bs_append_ushort(tls_extensions, sig_id);

      /* Update the TLS extensions length since we manually added to it. */
      tlsExtensionUpdateLength(tls_extensions);

      /* Create the Client Hello buffer using the ciphersuite list and TLS extensions. */
      client_hello = makeClientHello(options, tls_version, ciphersuite_list, tls_extensions);

      /* Free the TLS extensions since we're done with them.  Note: we don't free the ciphersuite_list because we'll need them on the next loop. */
      bs_free(&tls_extensions);

      /* Now connect to the target server. */
      s = tcpConnect(options);
      if (s == 0) {
        ret = false;
        goto done;
      }

      /* Send the Client Hello message. */
      if (send(s, bs_get_bytes(client_hello), bs_get_len(client_hello), 0) <= 0) {
        printf_error("send() failed while sending Client Hello: %d (%s)", errno, strerror(errno));
        ret = false;
        goto done;
      }
      bs_free(&client_hello);

      server_hello = getServerHello(s);
      CLOSE(s);

      /* This signature algorithm is not supported. */
      if (server_hello == NULL)
        continue;

      bs_free(&server_hello);

      if (!printed_header) {
        printf("\n  %sServer Signature Algorithm(s):%s\n", COL_BLUE, RESET);
        printed_header = 1;
      }

      /* If the server accepted our bogus signature ID, then we can conclude that it will accept all of them (and not test any further).  Some servers in the wild do this for some reason... */
      if (sig_id == BOGUS_SIG_ALG_ID) {
        printf("%s%s  Server accepts all signature algorithms.%s\n", getPrintableTLSName(tls_version), COL_RED, RESET);
        printf_xml("  <connection-signature-algorithm sslversion=\"%s\" name=\"ANY\" id=\"0xfdff\" />\n", getPrintableTLSName(tls_version));
        break;
      } else {
        printf("%s  %s%s%s\n", getPrintableTLSName(tls_version), color, sig_name, RESET);
        printf_xml("  <connection-signature-algorithm sslversion=\"%s\" name=\"%s\" id=\"0x%04x\" />\n", getPrintableTLSName(tls_version), sig_name, sig_id);
      }
    }
  }

 done:
  CLOSE(s);
  bs_free(&ciphersuite_list);
  bs_free(&tls_extensions);
  bs_free(&client_hello);
  bs_free(&server_hello);
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
