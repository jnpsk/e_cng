#include <stdio.h>
#include <string.h>

#include <WS2tcpip.h>
#include <Windows.h>
#include <WinCrypt.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/x509.h>

#include "confparser.h"

CONFIG glob_config = {
    0,
    "certs\\ca_rsa.pem",
    "certs\\ca_ecdsa.pem",
    "engine\\cng.dll",
    NULL,
    "localhostServerRSA",
    "localhostServerECDSA",
    0, 0, 0, 0
};

// #define LOG_PATH "server.log"
void trace(char *format, ...)
{
    BIO *out;

    #ifdef LOG_PATH
        out = BIO_new_file(LOG_PATH, "a+");
    #else
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
    #endif

    if (out == NULL) exit(666);

    va_list argptr;
    /* Gets arguments passed after format (i.e. ...) */
    va_start(argptr, format);
    
    BIO_vprintf(out, format, argptr);
    BIO_free(out);
    
    va_end(argptr);
}

/* WINDOWS create socket
 * copied form microsoft docs
 * https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-server-application 
 */
SOCKET create_socket(const char* port)
{
    WSADATA wsaData;

    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        trace("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    // Creating a Socket for the Server
    struct addrinfo *result = NULL, hints;

    ZeroMemory(&hints, sizeof (hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the local address and port to be used by the server
    iResult = getaddrinfo(NULL, port, &hints, &result);
    if (iResult != 0) {
        trace("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections
    SOCKET ListenSocket = INVALID_SOCKET;
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        trace("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Bind Socket
    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        trace("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    // Listening on a Socket
    if ( listen( ListenSocket, SOMAXCONN ) == SOCKET_ERROR ) {
        trace( "Listen failed with error: %ld\n", WSAGetLastError() );
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    return ListenSocket;
}

/* Find certificate in windows certificate store
 * based on subject name and convert it to
 * OpenSSL structure */
X509* get_cert_from_winstore(const char *id, const char* storename) {

    HCERTSTORE winStore;
    PCCERT_CONTEXT winCert;
    X509 *osslCert;

    winStore = CertOpenSystemStoreA(0, storename);
    if (!winStore) {
        trace("[ERROR] Windows Store '%s' could not be opened\n", storename);
        return 0;
    }

    winCert = CertFindCertificateInStore(winStore, X509_ASN_ENCODING, 0,
                                         CERT_FIND_SUBJECT_STR_A, id, NULL);
    if (!winCert) {
        trace("[ERROR] Cert containing subject name '%s' does not exist\n", id);
        CertCloseStore(winStore, 0);
        return 0;
    }

    osslCert = d2i_X509(NULL, &(winCert->pbCertEncoded), winCert->cbCertEncoded);
    if (!osslCert) {
        trace("[ERROR] WinCert could not be converted to X509\n");
        CertCloseStore(winStore, 0);
        CertFreeCertificateContext(winCert);
        return NULL;
    }

    CertFreeCertificateContext(winCert);
    CertCloseStore(winStore, 0);
    return osslCert;
}

/* Load Engine and set it for default operations */
ENGINE *load_engine(const char *so_path)
{
    /**
     *  ENGINE_by_id(id) can be used too
     *    although it requires to store dll to
     *    specific location.
     */
    ENGINE_load_dynamic();
    ENGINE *engine = ENGINE_by_id("dynamic");
    if(!engine) {
        trace("[ERROR] Engine 'dynamic' not available.\n");
        return NULL;
    }

    ENGINE_ctrl_cmd_string(engine, "SO_PATH", so_path, 0);
    if (ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0) != 1) {
        trace("[WARNING] Engine '%s' was NOT loaded\n", so_path);
        return NULL;
    }

    if(!engine) {
        trace("[ERROR] Engine not available.\n");
        return NULL;
    }

    if(!ENGINE_init(engine)) {
        trace("[ERROR] Engine could not be initted.\n");
        ENGINE_free(engine);
        return 0;
    }
    
    /* Enable debugging tracing 
     * Example of two methods */
    ENGINE_ctrl_cmd_string(engine, "debug_file", "server.log", 0);
    ENGINE_ctrl_cmd(engine, "debug_level", 2, NULL, NULL, 0);

    /* Set engines supported methods as default */
    if(!ENGINE_set_default(engine, ENGINE_METHOD_ALL))
        trace("[WARNING] Could not set engine methods as default\n");

    trace("[INFO] Engine '%s' loaded: %s\n", ENGINE_get_id(engine), ENGINE_get_name(engine));
    return engine;
}

int set_context(SSL_CTX *ctx, ENGINE *engine)
{
    if (!ctx || !engine) {
        trace("[ERROR] Unable to init SSL context");
        return 0;
    }

    
    /* Set certs and keys */
    const char* rsa_cert_id = glob_config.server_rsa_cert;

    X509* rsa_cert = get_cert_from_winstore(rsa_cert_id, "MY");
    if (!rsa_cert) {
        trace("[ERROR] Cert with id '%s' could not be obtained\n", rsa_cert_id);
        return 0;
    }
    SSL_CTX_use_certificate(ctx, rsa_cert);

    EVP_PKEY *rsa_pkey = ENGINE_load_private_key(engine, rsa_cert_id, UI_OpenSSL(), NULL);
    if(!rsa_pkey) {
        trace("[ERROR] Key with id '%s' could not be obtained\n", rsa_cert_id);
        return 0;
    }

    if(SSL_CTX_use_PrivateKey(ctx, rsa_pkey) != 1) {
        trace("[ERROR] SSL_CTX_use_PrivateKey() failed\n");
        return 0;
    }

    if (strcmp("cng", ENGINE_get_id(engine)) == 0) {
        const char* ecdsa_cert_id = glob_config.server_ecdsa_cert;
        X509* ecdsa_cert = get_cert_from_winstore(ecdsa_cert_id, "MY");
        if (!ecdsa_cert) {
            trace("[ERROR] Cert with id '%s' could not be obtained\n", ecdsa_cert_id);
            return 0;
        }

        SSL_CTX_set_ecdh_auto(ctx, 1);
        SSL_CTX_use_certificate(ctx, ecdsa_cert);

        EVP_PKEY *ecdsa_pkey = ENGINE_load_private_key(engine, ecdsa_cert_id, UI_OpenSSL(), NULL);
        if(!ecdsa_pkey) {
            trace("[ERROR] Key with id '%s' could not be obtained\n", ecdsa_cert_id);
            return 0;
        }

        if(SSL_CTX_use_PrivateKey(ctx, ecdsa_pkey) != 1) {
            trace("[ERROR] SSL_CTX_use_PrivateKey() failed\n");
            return 0;
        }
    }

    if (glob_config.cert_request == 1) {
        /* Verify client */
        if (SSL_CTX_load_verify_locations(ctx, glob_config.rsa_ca_path, NULL) != 1) {
            trace("[ERROR] SSL_CTX_load_verify_locations(): '%s' could not be loaded\n", glob_config.rsa_ca_path);
            return 0;
        }

        if (SSL_CTX_load_verify_locations(ctx, glob_config.ecdsa_ca_path, NULL) != 1) {
            trace("[ERROR] SSL_CTX_load_verify_locations(): '%s' could not be loaded\n", glob_config.ecdsa_ca_path);
            return 0;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        STACK_OF(X509_NAME) *cert = SSL_load_client_CA_file(glob_config.rsa_ca_path);
        SSL_add_file_cert_subjects_to_stack(cert, glob_config.ecdsa_ca_path);
        SSL_CTX_set_client_CA_list(ctx, cert);

    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    

    return 1;
}

int main(int argc, char const *argv[])
{
    if (argc > 1)
        get_config(&glob_config, argv[1]);

    /** Init libssl
     * Loads required EVP_MD and EVP_CIPHER */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

    ENGINE *engine = load_engine(glob_config.server_engine_path);

    /* Create socket */
    SOCKET sock = create_socket("27015");

    /* Set SSL context */
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (set_context(ctx, engine) <= 0)
        return -1;
   
    const char *reply = "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 14\r\n\r\n"
                        "To bude dobry.\r\n";

    int ret;
    /* Handle connections */
    // while(1) { /* It's better to exit immediately after one connection for testing purpose */
        struct sockaddr_in addr;
        int cl_len = sizeof(addr);
        SSL *ssl;

        trace("- - - Waiting for a new client - - -\n");
        /* Permit an incoming connection attempt on a socket */
        int client = accept(sock, (struct sockaddr*)&addr, &cl_len);
        if (client < 0) {
            trace("[ERROR] Unable to accept connection\n");
            return -2;
        }

        /* Get connection handler */
        ssl = SSL_new(ctx);
        /* Redirect I/O fh to socket */
        SSL_set_fd(ssl, client);

        /* Make handshake and send message if successfull */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stdout);
            trace("[ERROR] Unable to establish connection\n");
            return -3;
        } else {
            trace("[INFO] Sending message to the client\n");
            ret = SSL_write(ssl, reply, strlen(reply));
            if (ret <= 0) {
                trace("[ERROR] SSL_write() write operation was not successful reason: %d", SSL_get_error(ssl, ret));
            }
        }

        if (glob_config.cert_request == 1) {
            X509* clientCert = SSL_get_peer_certificate(ssl);
            if (!clientCert)
                trace("[WARNING] Client did not provide certificate\n");
            else {
                trace("[DEBUG] Client cert subject: %s\n", X509_NAME_oneline(X509_get_subject_name(clientCert), 0, 0));
                trace("[DEBUG] Client cert issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(clientCert), 0, 0));  
            }
        }     

        /* Close notify, do not wait for ACK */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        trace("[INFO] Client was terminated\n");
    // }

    /* Free socket */
    closesocket(sock);
    SSL_CTX_free(ctx);

    /* Free libssl */
    ERR_free_strings();
    EVP_cleanup();

    /* Free engine */
    ENGINE_finish(engine);
    ENGINE_free(engine);

    return 0;
}
