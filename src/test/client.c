#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/x509.h>

#include <windows.h>
#include <wincrypt.h>

#include "confparser.h"

CONFIG glob_config = {
    TLS1_2_VERSION,
    "certs\\ca_rsa.pem",
    "certs\\ca_ecdsa.pem",
    NULL,
    "engine\\cng.dll",
    NULL,
    NULL,
    0, 0, 0, 0
};

/* Specify host and port */
#define HOST_NAME "127.0.0.1"
#define HOST_PORT "27015"

// #define LOG_PATH "client.log"
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

/* Load and init engine from so_path */
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
    ENGINE_ctrl_cmd_string(engine, "debug_file", "client.log", 0);
    ENGINE_ctrl_cmd(engine, "debug_level", 2, NULL, NULL, 0);

    /* Set engines supported methods as default */
    if(!ENGINE_set_default(engine, ENGINE_METHOD_ALL))
        trace("[WARNING] Could not set engine methods as default\n");

    trace("[INFO] Engine '%s' loaded: %s\n", ENGINE_get_id(engine), ENGINE_get_name(engine));
    return engine;
}

/**
 * CertificateRequest callback
 * it uses engine to search for acceptable CAs
 * x509 and pkey will be automatically installed into ssl */
int client_cert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{   
    STACK_OF(X509_NAME) *ca_list = SSL_get0_peer_CA_list(ssl);
    if (sk_X509_NAME_num(ca_list) <= 0) {
        trace("[WARNING] Server haven't specified acceptable CAs\n");
        return 0;
    }

    trace("[DEBUG] Acceptable CAs specified by server:\n");
    for(int i = 0; i < sk_X509_NAME_num(ca_list); ++i)
        trace("\t%d. %s\n", i, X509_NAME_oneline(sk_X509_NAME_value(ca_list, i), 0, 0));

    X509 *pcert;
    EVP_PKEY *ppkey;
    STACK_OF(X509) *pother;

    ENGINE *engine = load_engine(glob_config.client_engine_path);
    ENGINE_load_ssl_client_cert(engine, ssl, ca_list,
                                &pcert, &ppkey, &pother,
                                UI_OpenSSL(), NULL);

    trace("[DEBUG] Chosen client certificate:\n");
    trace("\tSubject: %s\n", X509_NAME_oneline(X509_get_subject_name(pcert), 0, 0));
    trace("\tIssuer:  %s\n", X509_NAME_oneline(X509_get_issuer_name(pcert), 0, 0)); 

    *x509 = pcert;
    *pkey = ppkey;
    
    return 1;
}

/* Create SSL_CTX and optionally set restrictions based on #defines */
int set_context(SSL_CTX *ctx)
{
    /* Create and set SSL_CTX supporting MAX_SSL_VERSION tops. */
    if (!ctx) {
        trace("[ERROR] Unable to init SSL context\n");
        return 0;
    }

    /* Set upper limit for TLS_VERSION */
    if (SSL_CTX_set_max_proto_version(ctx, glob_config.tls_version) != 1) {
        trace("[ERROR] Unable to limit TLS_VERSION\n");
        return 0;
    }

    /* Set paths to CA certs */
    if (SSL_CTX_load_verify_locations(ctx, glob_config.rsa_ca_path, NULL) != 1) {
        trace("[ERROR] SSL_CTX_load_verify_locations(): %s could not be loaded\n", glob_config.rsa_ca_path);
	    return 0;
    }

    if (SSL_CTX_load_verify_locations(ctx, glob_config.ecdsa_ca_path, NULL) != 1) {
        trace("[ERROR] SSL_CTX_load_verify_locations(): %s could not be loaded\n", glob_config.ecdsa_ca_path);
	    return 0;
    }

    if (glob_config.rsa_only == 1) {
        /* Limit ciphers to RSA only, this cant be set on TLS 1.3 */
        if (glob_config.tls_version == 0 && SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) != 1) {
            perror("[ERROR] Unable to init SSL context");
            ERR_print_errors_fp(stderr);
            return 0;
        }

        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA") == 0) {
            trace("[ERROR] SSL_CTX_set_cipher_list(): RSA cipher list could not be set\n");
            return 0;
        }
    }

    if (glob_config.ecdsa_only == 1) {
        /* Limit ciphers to ECDSA only, this cant be set on TLS 1.3 */
        if (glob_config.tls_version == 0 && SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) != 1) {
            perror("[ERROR] Unable to init SSL context");
            ERR_print_errors_fp(stderr);
            return 0;
        }

        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA") == 0) {
            trace("[ERROR] SSL_CTX_set_cipher_list(): ECDSA cipher list could not be set\n");
            return 0;
        }
    }

    if (glob_config.no_pss == 1) {
        /* Limit signature algorithm, so RSA_PSS could not be used */
        if (SSL_CTX_set1_sigalgs_list(ctx, "ECDSA+SHA256:RSA+SHA256") == 0) {
            trace("[ERROR] SSL_CTX_set1_sigalgs_list(): SIGALGs list could not be set\n");
            return 0;
        }
    }

    /* Verify server cert, end if fail */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_client_cert_cb(ctx, client_cert_cb); /*Used only when CertificateRequest*/

    return 1;
}

/* Print Subject and Issuer information about server certificate */
int print_server_cert(SSL* ssl)
{
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return 0;

    trace("Server cert Subject: %s\n", X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
    trace("Server cert Issuer:  %s\n", X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));

    X509_free(cert);
    return 1;
}

/* Print negotiated cipher suite and TLS version */
void print_negotiated(SSL* ssl)
{
    trace("Used encryption: %s\n", SSL_get_cipher(ssl));
    trace("Used SSL version: %s\n", SSL_get_version(ssl));
}

int main(int argc, char const *argv[])
{
    if (argc > 1)
        get_config(&glob_config, argv[1]);

    /** Init libssl
     * Loads required EVP_MD and EVP_CIPHER, ERR_strings */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

    BIO *web = NULL;
    SSL *ssl = NULL;
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    
    if (set_context(ctx) <= 0) {
        trace("[ERROR] set_context(): Can't set SSL_CTX\n");
        return -1;
    }

    /* Create SSL BIO representing new connection based on ctx */
    web = BIO_new_ssl_connect(ctx);
    if (!web) {
        trace("[ERROR] BIO_new_ssl_connect(): Can't obtain SSL BIO\n");
        return -2;
    }
    
    /* Set hostname, always returns 1 */
    BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);

    /* Get SSL pointer; can apply standard libssl functions later */
    BIO_get_ssl(web, &ssl);
    if (!ssl) {
        trace("[ERROR] BIO_get_ssl(): Can't locate SSL pointer\n");
        return -3;
    }

    /* Connect to server */
    if (BIO_do_connect(web) <= 0) {
        ERR_print_errors_fp(stdout);
        trace("[ERROR] BIO_do_connect(): Can't connect to server\n");
        return -4;
    }

    /* Establish the connection */
    if (BIO_do_handshake(web) <= 0) {
        trace("[ERROR] BIO_do_handshake(): Error during handshake\n");
        return -5;
    }

    trace("\nConnection:\n");
    /* Get connection info */
    print_negotiated(ssl);
    if (print_server_cert(ssl) <= 0) {
        trace("[ERROR] No server certificate provided\n");
    }

    /* Send something to the server, UNUSED */
    // BIO_puts(web, "GET / HTTP/1.1\r\n");

    /* Finally receive a message */
    int len = 0;
    char buff[1024];

    while(1) {
        len = BIO_read(web, buff, sizeof(buff)-1);
        if (len <= 0) break;
        buff[len] = '\0';
        trace("%s", buff);
    }

    BIO_free_all(web);
    SSL_CTX_free(ctx);

    /* Cleanup libssl */
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
