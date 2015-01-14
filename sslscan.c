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

// Includes...
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define VC_EXTRALEAN
  #define _WIN32_WINNT 0x0501
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <stdint.h>
  #if defined(WONKY_LINUX_MINGW) || defined(_MSC_VER)
    // The 32-bit Linux MinGW doesn't have a definition for
    // this timespec struct, and neither does Visual Studio.
    // This is a workaround.
    #include <time.h>
    struct timespec {
      time_t tv_sec;
      long tv_nsec;
    };
  #endif
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
  #endif
#else
  #include <netdb.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef __FreeBSD__
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

    n = recv(fd, buffer, len - 1, 0);

    if (n < 0) {
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
    if (options->sleep.tv_sec)
    {
#ifdef _WIN32
        Sleep(options->sleep.tv_sec * 1000);
#else
        nanosleep(&options->sleep, NULL);
#endif
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
        printf_error("%s    ERROR: Could not open a connection to host %s on port %d.%s\n", COL_RED, options->host, options->port, RESET);
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
        if (snprintf(xmpp_setup, sizeof(xmpp_setup), "<?xml version='1.0' ?>\r\n"
               "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\r\n", options->host) >= sizeof(xmpp_setup)) {
            printf("(internal error: xmpp_setup buffer too small)\n");
            abort();
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

        if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
            return 0;
        if (strstr(buffer, "<proceed"))
            printf_verbose("It appears that xmpp-tls is ready for TLS.\n");

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

    // Seperate Certs and PKey Files...
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
            printf("%s    Prvate key does not match certificate.%s\n", COL_RED, RESET);
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
        printf("%sSecure%s session renegotiation supported\n", COL_GREEN, RESET);
    else if (outputData->supported)
        printf("%sInsecure%s session renegotiation supported\n", COL_RED, RESET);
    else
       printf("Session renegotiation %snot supported%s\n", COL_GREEN, RESET);

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
        printf_verbose("OpenSSL %s looks like version 0.9.8l; I will try SSL3_FLAGS to enable renegotation.\n",
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

    tls_reneg_init(options);

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
                        SSL_set_tlsext_host_name(ssl, options->host);
#endif

                        // Connect SSL over socket
                        SSL_connect(ssl);

                        session = *SSL_get_session(ssl);

                        printf_xml("  <compression supported=\"%d\" />\n",
                            session.compress_meth);

                        if (session.compress_meth == 0)
                        {
                            printf("Compression %sdisabled%s\n", COL_GREEN, RESET);
                        }
                        else
                        {
                            printf("Compression %senabled%s (CRIME)\n", COL_RED, RESET);
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

    tls_reneg_init(options);

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
                        SSL_set_tlsext_host_name(ssl, options->host);
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
                            printf_verbose("Attempting secure_renegotiation_support()");
                            renOut->secure = SSL_get_secure_renegotiation_support(ssl);
                            if( renOut->secure )
                            {
                                // If it supports secure renegotiations,
                                // it should have renegotioation support in general
                                renOut->supported = true;
                                status = true;
                            }
                            else
                            {
#endif
                                // We can't assume that just because the secure renegotiation
                                // support failed the server doesn't support insecure renegotiations·

                                // assume ssl is connected and error free up to here
                                //setBlocking(ssl); // this is unnecessary if it is already blocking·
                                printf_verbose("Attempting SSL_renegotiate(ssl)\n");
                                SSL_renegotiate(ssl); // Ask to renegotiate the connection
                                // This hangs when an 'encrypted alert' is sent by the server
                                printf_verbose("Attempting SSL_do_handshake(ssl)\n");
                                SSL_do_handshake(ssl); // Send renegotiation request to server //TODO :: XXX hanging here

                                if (ssl->state == SSL_ST_OK)
                                {
                                    res = SSL_do_handshake(ssl); // Send renegotiation request to server
                                    if( res != 1 )
                                    {
                                        printf_error("\n\nSSL_do_handshake() call failed\n");
                                    }
                                    if (ssl->state == SSL_ST_OK)
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
        char hello[] = {0x16,0x03,0x02,0x00,0xdc,0x01,0x00,0x00,0xd8,0x03,0x02,0x53,0x43,0x5b,0x90,0x9d,0x9b,0x72,0x0b,0xbc,0x0c,0xbc,0x2b,0x92,0xa8,0x48,0x97,0xcf,0xbd,0x39,0x04,0xcc,0x16,0x0a,0x85,0x03,0x90,0x9f,0x77,0x04,0x33,0xd4,0xde,0x00,0x00,0x66,0xc0,0x14,0xc0,0x0a,0xc0,0x22,0xc0,0x21,0x00,0x39,0x00,0x38,0x00,0x88,0x00,0x87,0xc0,0x0f,0xc0,0x05,0x00,0x35,0x00,0x84,0xc0,0x12,0xc0,0x08,0xc0,0x1c,0xc0,0x1b,0x00,0x16,0x00,0x13,0xc0,0x0d,0xc0,0x03,0x00,0x0a,0xc0,0x13,0xc0,0x09,0xc0,0x1f,0xc0,0x1e,0x00,0x33,0x00,0x32,0x00,0x9a,0x00,0x99,0x00,0x45,0x00,0x44,0xc0,0x0e,0xc0,0x04,0x00,0x2f,0x00,0x96,0x00,0x41,0xc0,0x11,0xc0,0x07,0xc0,0x0c,0xc0,0x02,0x00,0x05,0x00,0x04,0x00,0x15,0x00,0x12,0x00,0x09,0x00,0x14,0x00,0x11,0x00,0x08,0x00,0x06,0x00,0x03,0x00,0xff,0x01,0x00,0x00,0x49,0x00,0x0b,0x00,0x04,0x03,0x00,0x01,0x02,0x00,0x0a,0x00,0x34,0x00,0x32,0x00,0x0e,0x00,0x0d,0x00,0x19,0x00,0x0b,0x00,0x0c,0x00,0x18,0x00,0x09,0x00,0x0a,0x00,0x16,0x00,0x17,0x00,0x08,0x00,0x06,0x00,0x07,0x00,0x14,0x00,0x15,0x00,0x04,0x00,0x05,0x00,0x12,0x00,0x13,0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x0f,0x00,0x10,0x00,0x11,0x00,0x23,0x00,0x00,0x00,0x0f,0x00,0x01,0x01};

        if (send(socketDescriptor, hello, sizeof(hello), 0) <= 0) { 
            printf_error("send() failed: %s\n", strerror(errno));
            exit(1);
        }

        // Send the heartbeat
        char hb[8] = {0x18,0x03,0x02,0x00,0x03,0x01,0x40,0x00};
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
            // Sucessful response
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



// Test a cipher...
int testCipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer)
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
    int resultSize = 0;
    const char *sslMethod = printableSslMethod(sslCipherPointer->sslMethod);

    // Create request buffer...
    memset(requestBuffer, 0, 200);
    snprintf(requestBuffer, 199, "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n", options->host);

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        if (SSL_CTX_set_cipher_list(options->ctx, sslCipherPointer->name) != 0)
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
                SSL_set_tlsext_host_name (ssl, options->host);
#endif

                // Connect SSL over socket
                cipherStatus = SSL_connect(ssl);

                // Show Cipher Status
                if (!((options->noFailed == true) && (cipherStatus != 1)))
                {
                    printf_xml("  <cipher status=\"");
                    if (cipherStatus == 1)
                    {
                        printf_xml("accepted\"");
                        if (options->noFailed == false)
                        {
                            printf("%sAccepted%s  ", COL_GREEN, RESET);
                        }
                        else
                        {
                            printf("Accepted  ");
                        }
                        if (options->http == true)
                        {

                            // Stdout BIO...
                            stdoutBIO = BIO_new(BIO_s_file());
                            BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);

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
                    else if (cipherStatus == 0)
                    {
                        printf_xml("rejected\"");
                        if (options->http == true)
                        {
                            printf("Rejected  N/A              ");
                        }
                        else
                        {
                            printf("Rejected  ");
                        }
                    }
                    else
                    {
                        printf_verbose("SSL_get_error(ssl, cipherStatus) said: %d\n", SSL_get_error(ssl, cipherStatus));
                        printf_xml("failed\"");
                        if (options->http == true)
                        {
                            printf("Failed    N/A              ");
                        }
                        else
                        {
                            printf("Failed    ");
                        }
                    }
                    printf_xml(" sslversion=\"%s\"", sslMethod);
#ifndef OPENSSL_NO_SSL2
                    if (sslCipherPointer->sslMethod == SSLv2_client_method())
                    {
                        printf("%sSSLv2%s    ", COL_RED, RESET);
                    }
                    else
#endif
#ifndef OPENSSL_NO_SSL3
                    if (sslCipherPointer->sslMethod == SSLv3_client_method())
                    {
                        printf("%sSSLv3%s    ", COL_RED, RESET);
                    }
                    else
#endif
                    if (sslCipherPointer->sslMethod == TLSv1_client_method())
                    {
                        printf("TLSv1.0  ");
                    }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                    else if (sslCipherPointer->sslMethod == TLSv1_1_client_method())
                    {
                        printf("TLSv1.1  ");
                    }
                    else if (sslCipherPointer->sslMethod == TLSv1_2_client_method())
                    {
                        printf("TLSv1.2  ");
                    }
#endif
                    if (sslCipherPointer->bits < 10)
                        tempInt = 2;
                    else if (sslCipherPointer->bits < 100)
                        tempInt = 1;
                    else
                        tempInt = 0;
                    if (sslCipherPointer->bits == 0)
                    {
                        printf("%s%d%s bits  ", COL_RED_BG, sslCipherPointer->bits, RESET);
                    }
                    else if (sslCipherPointer->bits > 56)
                    {
                        printf("%s%d%s bits  ", COL_GREEN, sslCipherPointer->bits, RESET);
                    }
                    else if (sslCipherPointer->bits > 40)
                    {
                        printf("%s%d%s bits  ", COL_YELLOW, sslCipherPointer->bits, RESET);
                    }
                    else
                    {
                        printf("%s%d%s bits  ", COL_RED, sslCipherPointer->bits, RESET);
                    }
                    while (tempInt != 0)
                    {
                        tempInt--;
                        printf(" ");
                    }
                    printf_xml(" bits=\"%d\" cipher=\"%s\" />\n", sslCipherPointer->bits, sslCipherPointer->name);
                    if (strstr(sslCipherPointer->name, "NULL"))
                    {
                        printf("%s%s%s\n", COL_RED_BG, sslCipherPointer->name, RESET);
                    }
                    else if (strstr(sslCipherPointer->name, "ADH") || strstr(sslCipherPointer->name, "AECDH"))
                    {
                        printf("%s%s%s\n", COL_PURPLE, sslCipherPointer->name, RESET);
                    }
                    else if (strstr(sslCipherPointer->name, "EXP") || (sslCipherPointer->sslMethod == SSLv3_client_method() && !strstr(sslCipherPointer->name, "RC4")))
                    {
                        printf("%s%s%s\n", COL_RED, sslCipherPointer->name, RESET);
                    }
                    else if (strstr(sslCipherPointer->name, "RC4"))
                    {
                        printf("%s%s%s\n", COL_YELLOW, sslCipherPointer->name, RESET);
                    }
                    else if (strstr(sslCipherPointer->name, "GCM"))
                    {
                        printf("%s%s%s\n", COL_GREEN, sslCipherPointer->name, RESET);
                    }
                    else
                    {
                        printf("%s\n", sslCipherPointer->name);
                    }
                }

                // Disconnect SSL over socket
                if (cipherStatus == 1)
                    SSL_shutdown(ssl);

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
            printf("%s    ERROR: Could set cipher %s.%s\n", COL_RED, sslCipherPointer->name, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}


// Test for preferred ciphers
int defaultCipher(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int cipherStatus;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    int tempInt;
    int tempInt2;

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
                        // TLS SNI
                        SSL_set_tlsext_host_name (ssl, options->host);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus == 1)
                        {
#ifndef OPENSSL_NO_SSL2
                            if (sslMethod == SSLv2_client_method())
                            {
                                printf_xml("  <defaultcipher sslversion=\"SSLv2\" bits=\"");
                                printf("%sSSLv2%s    ", COL_RED, RESET);
                            }
                            else
#endif
                            if (sslMethod == SSLv3_client_method())
                            {
                                printf_xml("  <defaultcipher sslversion=\"SSLv3\" bits=\"");
                                printf("%sSSLv3%s    ", COL_RED, RESET);
                            }
                            else if (sslMethod == TLSv1_client_method())
                            {
                                printf_xml("  <defaultcipher sslversion=\"TLSv1\" bits=\"");
                                printf("TLSv1.0  ");
                            }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                            else if (sslMethod == TLSv1_1_client_method())
                            {
                                printf_xml("  <defaultcipher sslversion=\"TLSv1.1\" bits=\"");
                                printf("TLSv1.1  ");
                            }
                            else if (sslMethod == TLSv1_2_client_method())
                            {
                                printf_xml("  <defaultcipher sslversion=\"TLSv1.2\" bits=\"");
                                printf("TLSv1.2  ");
                            }
#endif
                            if (SSL_get_cipher_bits(ssl, &tempInt2) < 10)
                                tempInt = 2;
                            else if (SSL_get_cipher_bits(ssl, &tempInt2) < 100)
                                tempInt = 1;
                            else
                                tempInt = 0;
                                //Bit ugly
                            int tempbits = SSL_get_cipher_bits(ssl, &tempInt2);
                            if (tempbits > 56)
                            {
                                printf("%s%d%s bits  ", COL_GREEN, tempbits, RESET);
                            }
                            else if (tempbits > 40)
                            {
                                printf("%s%d%s bits  ", COL_YELLOW, tempbits, RESET);
                            }
                            else
                            {
                                printf("%s%d%s bits  ", COL_RED, tempbits, RESET);
                            }

                            while (tempInt != 0)
                            {
                                tempInt--;
                                printf(" ");
                            }
                            printf_xml("%d\" cipher=\"%s\" />\n", SSL_get_cipher_bits(ssl, &tempInt2), SSL_get_cipher_name(ssl));
                            if (strstr(SSL_get_cipher_name(ssl), "EXP") || (sslMethod == SSLv3_client_method() && strstr(SSL_get_cipher_name(ssl), "CBC")))
                            {
                                printf("%s%s%s\n", COL_RED, SSL_get_cipher_name(ssl), RESET);
                            }
                            else if (strstr(SSL_get_cipher_name(ssl), "RC4"))
                            {
                                printf("%s%s%s\n", COL_YELLOW, SSL_get_cipher_name(ssl), RESET);
                            }
                            else if (strstr(SSL_get_cipher_name(ssl), "GCM"))
                            {
                                printf("%s%s%s\n", COL_GREEN, SSL_get_cipher_name(ssl), RESET);
                            }
                            else
                            {
                                printf("%s\n", SSL_get_cipher_name(ssl));
                            }

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

// Report certificate weaknesses (key length and signing algorithm)
int checkCertificate(struct sslCheckOptions *options)
{
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
    char certAlgorithm[80];
    int keyBits;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        // Setup Context Object...
        if( options->sslVersion == ssl_v2 || options->sslVersion == ssl_v3) {
            printf_verbose("sslMethod = SSLv23_method()");
            sslMethod = SSLv23_method();
        }
        else if( options->sslVersion == tls_v11) {
            printf_verbose("sslMethod = TLSv1_1_method()");
            sslMethod = TLSv1_1_method();
        }
        else if( options->sslVersion == tls_v12) {
            printf_verbose("sslMethod = TLSv1_2_method()");
            sslMethod = TLSv1_2_method();
        }
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specificy TLS version\n");
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
                        SSL_set_tlsext_host_name (ssl, options->host);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus == 1)
                        {
                            // Setup BIO's
                            stdoutBIO = BIO_new(BIO_s_file());
                            BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
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
                                    if (strstr(certAlgorithm, "md5"))
                                    {
                                        printf("%s%s%s\n", COL_RED, certAlgorithm, RESET);
                                    }
                                    else if (strstr(certAlgorithm, "sha1"))
                                    {
                                        printf("%s%s%s\n", COL_YELLOW, certAlgorithm, RESET);
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
                                                        printf("RSA Key Strength: %s%d%s\n", COL_RED, keyBits, RESET);
                                                    }
                                                    else if (keyBits >= 4096 )
                                                    {
                                                        printf("RSA Key Strength: %s%d%s\n", COL_GREEN, keyBits, RESET);
                                                    }
                                                    else
                                                    {
                                                        printf("RSA Key Strength: %d\n", keyBits);
                                                    }

                                                    printf_xml("   <pk error=\"false\" type=\"RSA\" bits=\"%d\" />\n", BN_num_bits(publicKey->pkey.rsa->n));
                                                }
                                                else
                                                {
                                                    printf("    RSA Public Key: NULL\n");
                                                }
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
                                        char *subject = X509_NAME_oneline(X509_get_subject_name(x509Cert), NULL, 0);
                                        printf("Subject: %s", subject);

                                    }
                                    else
                                    {
                                        e = X509_NAME_get_entry(subj, cnindex);
                                        d = X509_NAME_ENTRY_get_data(e);
                                        subject = (char *) ASN1_STRING_data(d);
                                        printf("Subject: %s\n", subject);
                                    }
                                    
                                    // Get SSL cert issuer
                                    cnindex = -1;
                                    subj = X509_get_issuer_name(x509Cert);
                                    cnindex = X509_NAME_get_index_by_NID(subj, NID_commonName, cnindex);
                                    
                                    // Issuer cert doesn't have a CN, so just print whole thing
                                    if (cnindex == -1)
                                    {
                                        char *issuer = X509_NAME_oneline(X509_get_issuer_name(x509Cert), NULL, 0);
                                        printf("Issuer:  %s", issuer);

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
                                            printf("Issuer:  %s%s%s\n", COL_RED, issuer, RESET);

                                        }
                                        else
                                        {
                                            printf("Issuer:  %s\n", issuer);
                                        }
                                    }
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
                        else
                        {
                            printf("\n%sFailed to connect to get certificate.%s\n", COL_RED, RESET);
                            printf("Most likley cause is server not supporting TLSv1.0, try manually specifying version");
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
        else if( options->sslVersion == tls_v11) {
            printf_verbose("sslMethod = TLSv1_1_method()");
            sslMethod = TLSv1_1_method();
        }
        else if( options->sslVersion == tls_v12) {
            printf_verbose("sslMethod = TLSv1_2_method()");
            sslMethod = TLSv1_2_method();
        }
        else {
            printf_verbose("sslMethod = TLSv1_method()\n");
            printf_verbose("If server doesn't support TLSv1.0, manually specificy TLS version\n");
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
                        SSL_set_tlsext_host_name (ssl, options->host);
#endif

                        // Connect SSL over socket
                        cipherStatus = SSL_connect(ssl);
                        if (cipherStatus == 1)
                        {
                            // Setup BIO's
                            stdoutBIO = BIO_new(BIO_s_file());
                            BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
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
                                    printf_xml("   <issuer>%s</issuer>\n", buffer);
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
                                    printf_xml("   <subject>%s</subject>\n", buffer);
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
                                                BIO_printf(fileBIO, "\"%s>", tempInt2 ? " level=\"critical\"" : "");
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
                                                printf_xml("</extension>\n");
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
                                    printf("    Certificate passed verification\n");
                                else
                                    printf("    %s\n", X509_verify_cert_error_string(verifyError));

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


// Test a single host and port for ciphers...
int testHost(struct sslCheckOptions *options)
{
    // Variables...
    struct sslCipher *sslCipherPointer = NULL;
    int status = true;
    struct addrinfo *addrinfoResult = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));

    // Resolve Host Name
    options->h_addrtype = 0;
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
    if (addrinfoResult->ai_family == AF_INET6)
    {
        options->serverAddress6.sin6_family = addrinfoResult->ai_family;
        memcpy((char *) &options->serverAddress6, addrinfoResult->ai_addr, addrinfoResult->ai_addrlen);
        options->serverAddress6.sin6_port = htons(options->port);
    }
    else
    {
        options->serverAddress.sin_family = addrinfoResult->ai_family;
        memcpy((char *) &options->serverAddress, addrinfoResult->ai_addr, addrinfoResult->ai_addrlen);
        options->serverAddress.sin_port = htons(options->port);
    }
    options->h_addrtype = addrinfoResult->ai_family;
    freeaddrinfo(addrinfoResult); addrinfoResult = NULL;

    // XML Output...
    printf_xml(" <ssltest host=\"%s\" port=\"%d\">\n", options->host, options->port);

    // Verbose warning about STARTTLS and SSLv3
    if (options->sslVersion == ssl_v3 || options->sslVersion == ssl_all)
    {
        printf_verbose("Some servers will fail to response to SSLv3 ciphers over STARTTLS\nIf your scan hangs, try using the --tlsall option\n\n");
    }

    // Test renegotiation
    printf("Testing SSL server %s%s%s on port %s%d%s\n\n", COL_GREEN, options->host, RESET, COL_GREEN, options->port, RESET);

    sslCipherPointer = options->ciphers;

    if (options->showClientCiphers == true)
    {
        printf("\n  %sSupported Client Cipher(s):%s\n", COL_BLUE, RESET);
        while ((sslCipherPointer != 0) && (status == true))
        {
            printf("    %s\n",sslCipherPointer->name);
            printf_xml(" <client-cipher cipher=\"%s\">\n", sslCipherPointer->name);

            sslCipherPointer = sslCipherPointer->next;
        }
    }
    if (status == true && options->reneg )
    {
        printf("  %sTLS renegotiation:%s\n", COL_BLUE, RESET);
        testRenegotiation(options, TLSv1_client_method());
    }

    if (status == true && options->compression )
    {
        printf("\n  %sTLS Compression:%s\n", COL_BLUE, RESET);
        testCompression(options, TLSv1_client_method());
    }

    if (status == true && options->heartbleed )
    {
        printf("\n  %sHeartbleed:%s\n", COL_BLUE, RESET);
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v10)
        {
            printf("TLS 1.0 ");
            status = testHeartbleed(options, TLSv1_client_method());
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v11)
        {
            printf("TLS 1.1 ");
            status = testHeartbleed(options, TLSv1_1_client_method());
        }
        if( options->sslVersion == ssl_all || options->sslVersion == tls_all || options->sslVersion == tls_v12)
        {
            printf("TLS 1.2 ");
            status = testHeartbleed(options, TLSv1_2_client_method());
        }
#endif
        if( options->sslVersion == ssl_v2 || options->sslVersion == ssl_v3)
        {
            printf("%sAll TLS protocols disabled, cannot check for heartbleed.\n%s", COL_RED, RESET);
        }
            printf("\n");
    }

    if (options->ciphersuites)
    {
        // Test supported ciphers...
        printf("  %sSupported Server Cipher(s):%s\n", COL_BLUE, RESET);
        sslCipherPointer = options->ciphers;
        while ((sslCipherPointer != 0) && (status == true))
        {

            // Setup Context Object...
            options->ctx = SSL_CTX_new(sslCipherPointer->sslMethod);
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


                // Test
                if (status == true)
                    status = testCipher(options, sslCipherPointer);

                // Free CTX Object
                SSL_CTX_free(options->ctx);
            }

            // Error Creating Context Object
            else
            {
                status = false;
                printf_error("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
            }

            sslCipherPointer = sslCipherPointer->next;

        }
        printf("\n");
    }
    if (status == true)
    {
        // Test preferred ciphers...
        printf("  %sPreferred Server Cipher(s):%s\n", COL_BLUE, RESET);
        switch (options->sslVersion)
        {
            case ssl_all:
#ifndef OPENSSL_NO_SSL2
                status = defaultCipher(options, SSLv2_client_method());
#endif
#ifndef OPENSSL_NO_SSL3
                if (status != false)
                    status = defaultCipher(options, SSLv3_client_method());
#endif
                if (status != false)
                    status = defaultCipher(options, TLSv1_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                if (status != false)
                    status = defaultCipher(options, TLSv1_1_client_method());
                if (status != false)
                    status = defaultCipher(options, TLSv1_2_client_method());
#endif
                break;
#ifndef OPENSSL_NO_SSL2
            case ssl_v2:
                status = defaultCipher(options, SSLv2_client_method());
                break;
#endif
#ifndef OPENSSL_NO_SSL3
            case ssl_v3:
                status = defaultCipher(options, SSLv3_client_method());
                break;
#endif
            case tls_all:
                if (status != false)
                    status = defaultCipher(options, TLSv1_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                if (status != false)
                    status = defaultCipher(options, TLSv1_1_client_method());
                if (status != false)
                    status = defaultCipher(options, TLSv1_2_client_method());
#endif
                break;
            case tls_v10:
                status = defaultCipher(options, TLSv1_client_method());
                break;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            case tls_v11:
                status = defaultCipher(options, TLSv1_1_client_method());
                break;
            case tls_v12:
                status = defaultCipher(options, TLSv1_2_client_method());
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
        status = checkCertificate(options);
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
#endif

    // Init...
    memset(&options, 0, sizeof(struct sslCheckOptions));
    options.port = 0;
    xmlArg = 0;
    strcpy(options.host, "127.0.0.1");
    options.noFailed = true;
    options.showCertificate = false;
    options.checkCertificate = true;
    options.showClientCiphers = false;
    options.ciphersuites = true;
    options.reneg = true;
    options.compression = true;
    options.heartbleed = true;
    options.starttls_ftp = false;
    options.starttls_imap = false;
    options.starttls_pop3 = false;
    options.starttls_smtp = false;
    options.starttls_xmpp = false;
    options.verbose = false;
    options.ipv4 = true;
    options.ipv6 = true;

    // Default socket timeout 3s
    options.timeout.tv_sec = 3;
    options.timeout.tv_usec = 0;

    options.sslVersion = ssl_all;

#ifdef _WIN32
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

        // Show unsupported ciphers
        else if (strcmp("--failed", argv[argLoop]) == 0)
            options.noFailed = false;

        // Show certificate
        else if (strcmp("--show-certificate", argv[argLoop]) == 0)
            options.showCertificate = true;

        // Don't check certificate strength
        else if (strcmp("--no-check-certificate", argv[argLoop]) == 0)
            options.checkCertificate = false;

        // Show supported client ciphers
        else if (strcmp("--show-ciphers", argv[argLoop]) == 0)
            options.showClientCiphers = true;

        // Version
        else if (strcmp("--version", argv[argLoop]) == 0)
            mode = mode_version;

        // XML Output
        else if (strncmp("--xml=", argv[argLoop], 6) == 0)
            xmlArg = argLoop;

        // Verbose
        else if (strcmp("--verbose", argv[argLoop]) == 0)
            options.verbose = true;

        // Disable coloured output
        else if ((strcmp("--no-colour", argv[argLoop]) == 0) || (strcmp("--no-color", argv[argLoop]) == 0))
        {
            RESET = "";
            COL_RED = "";
            COL_YELLOW = "";
            COL_BLUE = "";
            COL_GREEN = "";
            COL_PURPLE = "";
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

        // StartTLS... POP3
        else if (strcmp("--starttls-pop3", argv[argLoop]) == 0)
            options.starttls_pop3 = true;

        // StartTLS... SMTP
        else if (strcmp("--starttls-smtp", argv[argLoop]) == 0)
            options.starttls_smtp = true;

        // StartTLS... XMPP
        else if (strcmp("--starttls-xmpp", argv[argLoop]) == 0)
            options.starttls_xmpp = true;
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
            options.sleep.tv_sec = msec / 1000;
            options.sleep.tv_nsec = (msec - (options.sleep.tv_sec * 1000)) * 1000000;
        }

        // SSL HTTP Get...
        else if (strcmp("--http", argv[argLoop]) == 0)
            options.http = 1;

        // RDP Preamble...
        else if (strcmp("--rdp", argv[argLoop]) == 0)
            options.rdp = 1;

        // IPv4 only
        else if (strcmp("--ipv4", argv[argLoop]) == 0)
            options.ipv6 = false;

        // IPv6 only
        else if (strcmp("--ipv6", argv[argLoop]) == 0)
            options.ipv4 = false;

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

            while ((hostString[tempInt] != 0) && ((squareBrackets == true && hostString[tempInt] != ']') || (squareBrackets == false && hostString[tempInt] != ':')))
                tempInt++;

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
                    hostString[tempInt] = 0;

            strncpy(options.host, hostString, sizeof(options.host) -1);

            // Get port (if it exists)...
            tempInt++;
            if (tempInt < maxSize - 1)
                options.port = atoi(hostString + tempInt);
            else if (options.port == 0) {
                if (options.starttls_ftp)
                    options.port = 21;
                if (options.starttls_imap)
                    options.port = 143;
                if (options.starttls_pop3)
                    options.port = 110;
                if (options.starttls_smtp)
                    options.port = 25;
                if (options.starttls_xmpp)
                    options.port = 5222;
                if (options.rdp)
                    options.port = 3389;
                if (options.port == 0)
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
        options.xmlOutput = fopen(argv[xmlArg] + 6, "w");
        if (options.xmlOutput == NULL)
        {
            printf_error("%sERROR: Could not open XML output file %s.%s\n", COL_RED, argv[xmlArg] + 6, RESET);
            exit(0);
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
            printf("  %s--ipv4%s               Only use IPv4\n", COL_GREEN, RESET);
            printf("  %s--ipv6%s               Only use IPv6\n", COL_GREEN, RESET);
            printf("  %s--failed%s             Show unsupported ciphers.\n", COL_GREEN, RESET);
            printf("  %s--show-certificate%s   Show full certificate information.\n", COL_GREEN, RESET);
            printf("  %s--no-check-certificate%s      Don't warn about weak certificate algorithm or keys.\n", COL_GREEN, RESET);
            printf("  %s--show-ciphers%s       Show supported client ciphers.\n", COL_GREEN, RESET);
#ifndef OPENSSL_NO_SSL2
            printf("  %s--ssl2%s               Only check SSLv2 ciphers.\n", COL_GREEN, RESET);
#endif
#ifndef OPENSSL_NO_SSL3
            printf("  %s--ssl3%s               Only check SSLv3 ciphers.\n", COL_GREEN, RESET);
#endif
            printf("  %s--tls10%s              Only check TLSv1.0 ciphers.\n", COL_GREEN, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
            printf("  %s--tls11%s              Only check TLSv1.1 ciphers.\n", COL_GREEN, RESET);
            printf("  %s--tls12%s              Only check TLSv1.2 ciphers.\n", COL_GREEN, RESET);
#endif
            printf("  %s--tlsall%s             Only check TLS ciphers (all versions).\n", COL_GREEN, RESET);
            printf("  %s--pk=<file>%s          A file containing the private key or a PKCS#12 file\n", COL_GREEN, RESET);
            printf("                       containing a private key/certificate pair\n");
            printf("  %s--pkpass=<password>%s  The password for the private  key or PKCS#12 file\n", COL_GREEN, RESET);
            printf("  %s--certs=<file>%s       A file containing PEM/ASN1 formatted client certificates\n", COL_GREEN, RESET);
            printf("  %s--no-ciphersuites%s    Only check for supported SSL/TLS versions, not ciphers\n", COL_GREEN, RESET);
            printf("  %s--no-renegotiation%s   Do not check for TLS renegotiation\n", COL_GREEN, RESET);
            printf("  %s--no-compression%s     Do not check for TLS compression (CRIME)\n", COL_GREEN, RESET);
            printf("  %s--no-heartbleed%s      Do not check for OpenSSL Heartbleed (CVE-2014-0160)\n", COL_GREEN, RESET);
            printf("  %s--starttls-ftp%s       STARTTLS setup for FTP\n", COL_GREEN, RESET);
            printf("  %s--starttls-imap%s      STARTTLS setup for IMAP\n", COL_GREEN, RESET);
            printf("  %s--starttls-pop3%s      STARTTLS setup for POP3\n", COL_GREEN, RESET);
            printf("  %s--starttls-smtp%s      STARTTLS setup for SMTP\n", COL_GREEN, RESET);
            printf("  %s--starttls-xmpp%s      STARTTLS setup for XMPP\n", COL_GREEN, RESET);
            printf("  %s--http%s               Test a HTTP connection.\n", COL_GREEN, RESET);
            printf("  %s--rdp%s                Send RDP preamble before starting scan.\n", COL_GREEN, RESET);
            printf("  %s--bugs%s               Enable SSL implementation bug work-arounds\n", COL_GREEN, RESET);
            printf("  %s--timeout=<sec>%s      Set socket timeout. Default is 3s.\n", COL_GREEN, RESET);
            printf("  %s--sleep=<msec>%s       Pause between connection request. Default is disabled.\n", COL_GREEN, RESET);
            printf("  %s--xml=<file>%s         Output results to an XML file.\n", COL_GREEN, RESET);
            printf("  %s--version%s            Display the program version.\n", COL_GREEN, RESET);
            printf("  %s--verbose%s            Display verbose output.\n", COL_GREEN, RESET);
            printf("  %s--no-colour%s          Disable coloured output.\n", COL_GREEN, RESET);
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

            // Build a list of ciphers...
            switch (options.sslVersion)
            {
                case ssl_all:
#ifndef OPENSSL_NO_SSL2
                    populateCipherList(&options, SSLv2_client_method());
#endif
#ifndef OPENSSL_NO_SSL3
                    populateCipherList(&options, SSLv3_client_method());
#endif
                    populateCipherList(&options, TLSv1_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                    populateCipherList(&options, TLSv1_1_client_method());
                    populateCipherList(&options, TLSv1_2_client_method());
#endif
                    break;
#ifndef OPENSSL_NO_SSL2
                case ssl_v2:
                    populateCipherList(&options, SSLv2_client_method());
                    break;
#endif
#ifndef OPENSSL_NO_SSL3
                case ssl_v3:
                    populateCipherList(&options, SSLv3_client_method());
                    break;
#endif
                case tls_all:
                    populateCipherList(&options, TLSv1_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                    populateCipherList(&options, TLSv1_1_client_method());
                    populateCipherList(&options, TLSv1_2_client_method());
#endif
                    break;
                case tls_v10:
                    populateCipherList(&options, TLSv1_client_method());
                    break;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                case tls_v11:
                    populateCipherList(&options, TLSv1_1_client_method());
                    break;
                case tls_v12:
                    populateCipherList(&options, TLSv1_2_client_method());
                    break;
#endif
             }

            // Do the testing...
            if (mode == mode_single)
                testHost(&options);
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
                                    options.port = atoi(line + tempInt);
                                }
                                // Otherwise assume 443
                                else
                                {
                                    options.port = 443;
                                }

                                // Test the host...
                                testHost(&options);
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

/* vim :set ts=4 sw=4 sts=4 et : */
