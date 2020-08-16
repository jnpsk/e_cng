#ifdef _WIN32
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0600 /*VISTA*/
    #endif /*_WIN32_WINNT*/

    #include <windows.h>
    #include <bcrypt.h> /*CNG*/
    #include <ncrypt.h> /*CNG*/
    #include <wincrypt.h> /*Cert Store Functions*/

    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    #include <malloc.h>

    #include <openssl/crypto.h>

    #ifndef OPENSSL_NO_CAPIENG

        #include <openssl/buffer.h>
        #include <openssl/x509.h>
        #include <openssl/evp.h>
        #include <openssl/bn.h>
        #include <openssl/rsa.h>
        #include <openssl/ec.h>
    
        /* Weak test if cryptoAPI libraries is in shape, compatilibity tested only on OSSL >= 1.1 */
        #if defined(BCRYPT_PUBLIC_KEY_BLOB) && \
            defined(CERT_STORE_PROV_SYSTEM_A) && \
            OPENSSL_VERSION_NUMBER > 0x10100000
            # define __COMPILE_CAPIENG
        #endif/* CERT_KEY_PROV_INFO_PROP_ID */
    #endif /* OPENSSL_NO_CAPIENG */
#endif /*_WIN32*/

#ifdef __COMPILE_CAPIENG

static const char *engine_cng_id = "cng";
static const char *engine_cng_name = "Cryptography API: Next Generation ENGINE";


/* default storename */

# include <openssl/engine.h>
# include <openssl/pem.h>
# include <openssl/x509v3.h>

/************************************************************
 *    ENGINE INNER STRUCTURES
 ************************************************************/
/* Include headers for CNGerr */
# include "e_cng_err.h"
# include "e_cng_err.c"

/* Unique integers used within structures for the lifetime of the program */
static int engine_cng_idx = -1;

/* Dialog windows utilities */
static int cert_select_simple(ENGINE *e, SSL *ssl, STACK_OF(X509) *certs);
# ifdef OPENSSL_CNGENG_DIALOG
static int cert_select_dialog(ENGINE *e, SSL *ssl, STACK_OF(X509) *certs);
# endif
typedef PCCERT_CONTEXT(WINAPI *CERTDLG)(HCERTSTORE, HWND, LPCWSTR,
                                        LPCWSTR, DWORD, DWORD, void *);
typedef HWND(WINAPI *GETCONSWIN)(void);

/* CNG engine context */
typedef struct CNG_CTX_st CNG_CTX;
struct CNG_CTX_st {
    /* File for cng_trace output */
    char *debug_file;

    /* Debug level */
    int debug_level;
    #define CNG_DBG_TRACE  2 /*cng_trace messages will be printed*/
    #define CNG_DBG_ERROR  1 /*cng_trace messages will be ignored, as it is lower than CNG_DBG_TRACE*/

    /* Name of used Cert Store */ 
    #define DEFAULT_STORENAME "MY"
    LPSTR storename;

    /**
     * System store flags
     * Combined using bitwise-OR
     * see https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
     */
    DWORD store_flags;

    /* CNG inner flags to specify certificate dumping style in cng_dump_cert*/
    DWORD dump_flags;
    #define CNG_DMP_SUMMARY        1    /* Issuer and serial name */
    #define CNG_DMP_FNAME          2    /* Friendly name */
    #define CNG_DMP_FULL           4    /* Full X509_print dump */
    #define CNG_DMP_PEM            8    /* Dump PEM format certificate */

    int lookup_method;
    #define CNG_LU_SUBJ_SUBSTR     1  /* Substring of subject */
    #define CNG_LU_ISSU_SUBSTR     2  /* Substring of issuer */    
    #define CNG_LU_FNAME           3  /* Friendly name */
    #define CNG_LU_CONTNAME        4  /* Name of key in KSP */

    int list_method;
    #define CNG_LIST_ALL           1  /* List every cert from store */
    #define CNG_LIST_HAS_PKEY      2  /* List certs that have a private key */

    LPCWSTR ksp_name;
    DWORD keyspec;
    DWORD keyflag;

    /* Used in cng_load_ssl_client_cert() */
    int (*client_cert_select) (ENGINE *e, SSL *ssl, STACK_OF(X509) *certs);
    CERTDLG certselectdlg;
    GETCONSWIN getconswindow;
};

/* Clean CNG context structure */
static void cng_ctx_free(CNG_CTX *ctx)
{
    if (!ctx)
        return;
    OPENSSL_free(ctx->debug_file);
    OPENSSL_free(ctx->storename);
    OPENSSL_free(ctx);
} 

/* CNG certificate context */
typedef struct CNG_KEY_st CNG_KEY;
struct CNG_KEY_st {
    NCRYPT_KEY_HANDLE key;
    PCCERT_CONTEXT cert;
    // DWORD keyspec;
};

/* Clean CNG key structure */
void cng_free_key(CNG_KEY *key) {
    if (!key)
        return;
    NCryptFreeObject(key->key);
    if (key->cert)
        CertFreeCertificateContext(key->cert);
    OPENSSL_free(key);
}

/**
 * Initialize a CNG_CTX structure
 * @return Pointer to new CNG_CTX structure or NULL on error
 */
static CNG_CTX *cng_ctx_new(void)
{
    CNG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if(!ctx) {
        CNGerr(CNG_F_CNG_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->debug_file = NULL;
    
    /* Set default flags */
    ctx->store_flags = CERT_STORE_OPEN_EXISTING_FLAG | /* Open existing store, fails if does not exist */
                       CERT_STORE_READONLY_FLAG | /* Open in read-only mode, trying to change results an error */
                       CERT_SYSTEM_STORE_CURRENT_USER; /* Specify registry location of system store:
                                                        * HKEY_CURRENT_USER - Software - Microsoft - SystemCertificates */

    ctx->dump_flags = CNG_DMP_SUMMARY | CNG_DMP_FNAME; /* Issuer, Serial and Friendly name */
    ctx->list_method = CNG_LIST_ALL;
    ctx->lookup_method = CNG_LU_SUBJ_SUBSTR;

    /* KSP */
    ctx->ksp_name = MS_KEY_STORAGE_PROVIDER; /*Microsoft Software Key Storage Provider*/
    ctx->keyspec = AT_KEYEXCHANGE;
    ctx->keyflag = 0; /*Use only local user keys*/

    ctx->client_cert_select = cert_select_simple; /*Select first*/

    return ctx;
}

/**
 * Logging tool
 * Get data from ... argument and pass them into BIO
 * @see <stdarg.h>
 * @param ctx Engine inner structure
 * @param format Formatted message to print
 * @param ... Variables to print in formatted message
 */
static void cng_trace(CNG_CTX *ctx, char *format, ...)
{
    BIO *out;

    if (!ctx || (ctx->debug_level < CNG_DBG_TRACE) || (!ctx->debug_file))
        return;

    out = BIO_new_file(ctx->debug_file, "a+");
    if (out == NULL) {
        CNGerr(CNG_F_CNG_TRACE, CNG_R_FILE_OPEN_ERROR);
        return;
    }
    
    va_list argptr;
    /* Gets arguments passed after format (i.e. ...) */
    va_start(argptr, format);
    
    BIO_vprintf(out, format, argptr);
    BIO_free(out);
    
    va_end(argptr);
}

/**
 * Adds an error code to the thread's error queue
 * Can be obtained using ERR_print_errors_fp(stderr);
 */
static void cng_adderror(DWORD err)
{
    char errstr[10];
    BIO_snprintf(errstr, 10, "%lX", err);
    ERR_add_error_data(2, "Error code=0x", errstr);
}

/**
 * Retrieves the calling thread's last-error code value
 * and pass it to cng_adderror().
 * Used after Windows functions
 */
static void cng_addlasterror(void)
{
    cng_adderror(GetLastError());
}

/**
 * Convert unicode wide string to ascii string
 * @param wstr - pointer to wide, null terminated string
 * @return pointer to char string
 */
static char* wide2ascii(LPCWSTR wstr)
{
    if (!wstr)
        return NULL;

    char* str;
    DWORD len;

    /** WideCharToMultiByte
     *      CP_ACP - use system default Windows ANSI code page for conversion
     *      conversion type flags, not used
     *      wstr - pointer to unicode wide string to convert
     *      len - size of wstr; -1 if null-terminated
     *      pointer to a buffer that recives converted string
     *      number of bytes in that buffer
     *      ... and additional conversion info for default characters
     *    returns required size of buffer
     */
    
    /* First dry run to obtain required buffer size */
    len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);

    if (len == 0) {
        CNGerr(CNG_F_WIDE2ASCII, CNG_R_WIN32_ERROR);
        return NULL;
    }

    str = OPENSSL_malloc(len);
    if (!str) {
        CNGerr(CNG_F_WIDE2ASCII, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL)) {
        OPENSSL_free(str);
        CNGerr(CNG_F_WIDE2ASCII, CNG_R_WIN32_ERROR);
        return NULL;
    }

    return str;
}

LPWSTR ascii2wide(const char* str)
{
    if (!str)
        return NULL;

    LPWSTR wstr;
    DWORD len;

    /* First dry run to obtain required buffer size */
    len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (len == 0) {
        CNGerr(CNG_F_ASCII2WIDE, CNG_R_WIN32_ERROR);
        return NULL;
    }

    wstr = OPENSSL_malloc(len * sizeof(WCHAR));
    if (!wstr) {
        CNGerr(CNG_F_ASCII2WIDE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len)) {
        OPENSSL_free(wstr);
        CNGerr(CNG_F_ASCII2WIDE, CNG_R_WIN32_ERROR);
        return NULL;
    }

    return wstr;
}
/************************************************************
 *  CERTIFICATES HANDLING
 *   - Certificate Store Functions are not part of CryptoAPI,
 *     but share header file Wincrypt.h
 ************************************************************/

/**
 * Get friendly name specified for certificate
 * @param ctx Engine inner structure
 * @param cert Certificate handler
 * @return File name
 */ 
static char* cng_cert_get_fname(CNG_CTX *ctx, PCCERT_CONTEXT cert)
{
    DWORD len;

    /** CertGetCertificateContextProperty
     *      pointer to CERT_CONTEXT
     *      property to retrive
     *      pointer to a buffer where requested data will be stored
     *      pointer to a DWORD that specifies size of buffer
     *    returns True or ErrorCode
     */ 

    /* Dry run to define len parameter */
    if (!CertGetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, NULL, &len)) {
        /**
         * Function returns error codes
         *      - ERROR_MORE_DATA (can not happen in this case as no buffer provided);
         *      - CRYPT_E_NOT_FOUND when property does not exist
         */
        cng_trace(ctx, "[DEBUG] Certificate probably does not have a friendly name\n");
        return NULL;
    }

    LPWSTR wfname = OPENSSL_malloc(len);
    if (!wfname) {
        CNGerr(CNG_F_CNG_CTRL, ERR_R_MALLOC_FAILURE);
        cng_trace(ctx, "[ERROR] Could not allocate memory for friendly name\n");
        return NULL;
    }

    if (!CertGetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, wfname, &len)) {
        CNGerr(CNG_F_CNG_CTRL, CNG_R_ERROR_GETTING_FRIENDLY_NAME);
        cng_addlasterror();
        cng_trace(ctx, "[ERROR] Unexpected error while getting friendly name\n");
        OPENSSL_free(wfname);
        return NULL;
    }

    /* BIO_printf can not handle wide string */
    char *fname = wide2ascii(wfname);
    OPENSSL_free(wfname);
    return fname;
}

/**
 * Print certificate info
 * @param ctx Engine inner structure
 * @param out Output handler for printing
 * @param cert Certificate handler
 */
static void cng_dump_cert(CNG_CTX *ctx, BIO *out, PCCERT_CONTEXT cert)
{
    DWORD flags = ctx->dump_flags;
    
    /**
     * Should print Friendly name?
     * As friendly name isn't part of X.509 format, use Cert Store Functions to get it
     */
    if (flags & CNG_DMP_FNAME) {
        char* fname = cng_cert_get_fname(ctx, cert);
        if (fname) {
            BIO_printf(out, "  Friendly Name: '%ls'\n", fname);
            OPENSSL_free(fname);
        } else {
            BIO_printf(out, "  <No Friendly Name>\n");
        }
    }

    /** d2i_X509
     * Convert ASN.1/DER encoded cert into OpenSSL object
     *      - Pointer to returned X509 structure
     *      - Pointer to a buffer to decode
     *      - Size of the buffer
     *   returns pointer to returned X509 structure
     */
    const unsigned char *p = cert->pbCertEncoded; /* cast to const char */
    X509 *x509_cert = d2i_X509(NULL, &p, cert->cbCertEncoded);
    if (!x509_cert) {
        BIO_printf(out, "  <Can't parse certificate>\n");
    }
    
    /* Should print Subject name & Issuer Name? */
    if (flags & CNG_DMP_SUMMARY) {
        BIO_printf(out, "  Subject: ");
        X509_NAME_print_ex(out, X509_get_subject_name(x509_cert), 0, XN_FLAG_ONELINE);
        BIO_printf(out, "\n  Issuer: ");
        X509_NAME_print_ex(out, X509_get_issuer_name(x509_cert), 0, XN_FLAG_ONELINE);
        BIO_printf(out, "\n");
    }

    /* Should print full dump? */
    if (flags & CNG_DMP_FULL)
        X509_print(out, x509_cert);
    
    /* Should dump PEM format? */
    if (flags & CNG_DMP_PEM)
        PEM_write_bio_X509(out, x509_cert);

    X509_free(x509_cert);
}

/**
 * Open Certificate Store
 * @param ctx Engine inner structure
 * @param storename Name of store to open
 * @return CertStore handler
 */
static HCERTSTORE cng_open_store(CNG_CTX *ctx, char *storename)
{
    if (!storename)
        storename = ctx->storename ? ctx->storename : DEFAULT_STORENAME;
    cng_trace(ctx, "[INFO] Opening certificate store '%s'\n", storename);

    /**
     * Store handler
     * CertOpenStore params:
     *   - System store with certificates, CRLs, and CTLs as provider type
     *   - Encoding type, used only with some provider types
     *   - Use default HCRYPTPROV 
     *   - Controls of general characteristics of the certificate store
     *   - System store name
     */
    HCERTSTORE hstore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, ctx->store_flags, storename);
    if (!hstore) {
        CNGerr(CNG_F_CNG_OPEN_STORE, CNG_R_ERROR_OPENING_STORE);
        cng_addlasterror();
        cng_trace(ctx, "[ERROR] Certificate store '%s' could not be opened\n", storename);
    }

    return hstore;
}

/**
 * Print info about certificates stored in Cert Store
 * Storename is DEFAULT_STORENAME by default, or ctx->storename if specified
 * @param ctx Engine inner structure
 * @param out Output print handler for cert dump
 * @return 1 if OK else 0
 */
int cng_list_certs(CNG_CTX *ctx, BIO *out)
{
    char *storename = ctx->storename ? ctx->storename : DEFAULT_STORENAME;    
    cng_trace(ctx, "[INFO] Listing certificates for store '%s'\n", storename);

    /*Certstore Handler*/
    HCERTSTORE hstore = cng_open_store(ctx, storename);
    if (!hstore)
        return 0;

    /*Representation of a certificate*/
    PCCERT_CONTEXT cert = NULL;
    int i;

    switch(ctx->list_method) {
        case CNG_LIST_ALL:
            for (i = 0;; i++) {
                /*Retrieves next certificate in store*/
                cert = CertEnumCertificatesInStore(hstore, cert);
                if (!cert)
                    break;
                
                BIO_printf(out, "Certificate %d:\n", i);
                cng_dump_cert(ctx, out, cert);
            }
            break;
        
        case CNG_LIST_HAS_PKEY:
            for (i = 0;; i++) {
                cert = CertFindCertificateInStore(hstore, X509_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, cert);
                if (!cert)
                    break;
                
                BIO_printf(out, "Certificate %d:\n", i);
                cng_dump_cert(ctx, out, cert);
            }
            break;

        default:
            BIO_printf(out, "Unknown list method %d:\n", ctx->list_method);
            return 0;
    }

    
    if (!CertCloseStore(hstore, 0)) {
        cng_trace(ctx, "[WARNING] Certificate store '%s' could not be closed\n", storename);
    }
    cng_trace(ctx, "[INFO] Number of certificates dumped from '%s': %d\n", storename, i);
    return 1;
}

/**
 * Find cert using CNG_CTX.lookup_method matching 'id' string as substring
 * @param ctx Engine inner structure
 * @param id Substring to match
 * @return matching PCCERT_CONTEXT or NULL
 */
static PCCERT_CONTEXT cng_find_cert(CNG_CTX *ctx, const char *id)
{
    char *storename = ctx->storename ? ctx->storename : DEFAULT_STORENAME;

    /*Certstore Handler*/
    HCERTSTORE hstore = cng_open_store(ctx, storename);
    if (!hstore)
        return 0;

    /** CertFindCertificateInStore(
     *      Cert store handler
     *      Certificate encoding type
     *      Search criteria modificator, mostly not used
     *      Type of search
     *      Data used for search
     *      Pointer to last CERT_CONTEXT returned by this function; NULL if first call)
     *   returns pointer to CERT_CONTEXT or NULL
     */

    PCCERT_CONTEXT ret;
    switch (ctx->lookup_method)
    {
        case CNG_LU_SUBJ_SUBSTR:
            ret = CertFindCertificateInStore(hstore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, id, NULL);
            break;
        
        case CNG_LU_ISSU_SUBSTR:
            ret = CertFindCertificateInStore(hstore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR, id, NULL);
            break;

        case CNG_LU_FNAME:
            PCCERT_CONTEXT cert = NULL;
            char *fname = NULL;
            int match;

            for (;;) {
                cert = CertEnumCertificatesInStore(hstore, cert);
                if (!cert) {
                    CertCloseStore(hstore, 0);
                    return NULL;
                }
                fname = cng_cert_get_fname(ctx, cert);
                if (fname) {
                    if (strcmp(fname, id))
                        match = 0;
                    else
                        match = 1;
                    OPENSSL_free(fname);
                    if (match) {
                        CertCloseStore(hstore, 0);
                        return cert;
                    }
                }
            }
        
        default:
            return NULL;
    }

    if (!CertCloseStore(hstore, 0)) {
        cng_trace(ctx, "[WARNING] Certificate store '%s' could not be closed\n", storename);
    }

    return ret;
}

/************************************************************
 *  KSP HANDLING
 ************************************************************/
/**
 * List all available KSPs
 * This is only runned by engine ctrl_cmd
*/
static int cng_list_ksps(CNG_CTX *ctx, BIO *out)
{
    DWORD cnt;
    NCryptProviderName *list;
    SECURITY_STATUS status;

    if ((status = NCryptEnumStorageProviders(&cnt, &list, NCRYPT_SILENT_FLAG)) != ERROR_SUCCESS) {
        cng_addlasterror();
        CNGerr(CNG_F_CNG_LIST_KSPS, CNG_R_ERROR_ENUM_KSP);
        cng_trace(ctx, "[ERROR] Error while getting KSP list using NCryptEnumStorageProviders: returned 0x%x\n", status);
        return 0;
    }

    char *name, *comment; 

    BIO_printf(out, "Available KSPs:\n");
    for (size_t i = 0; i < cnt; ++i) {
        name = wide2ascii(list[i].pszName);
        comment = wide2ascii(list[i].pszComment);
        BIO_printf(out, " %d. %s\n", i+1, name);
        BIO_printf(out, "    desc: %s\n", comment);
        OPENSSL_free(name); OPENSSL_free(comment);
    }
    NCryptFreeBuffer(list);
    return 1;
}

static CNG_KEY *cng_key_from_ksp(CNG_CTX *ctx, const char *id) 
{
    NCRYPT_PROV_HANDLE ksp;
    CNG_KEY *key;
    SECURITY_STATUS status;

    if ((status = NCryptOpenStorageProvider(&ksp, ctx->ksp_name, 0)) != ERROR_SUCCESS) {
        cng_addlasterror();
        CNGerr(CNG_F_CNG_KEY_FROM_KSP, CNG_R_UNKNOWN_KSP);
        cng_trace(ctx, "[ERROR] Error while getting KSP using NCryptOpenStorageProvider: returned 0x%x\n", status);
        return NULL;
    }

    key = OPENSSL_malloc(sizeof(*key));
    if (!key) {
        CNGerr(CNG_F_CNG_KEY_FROM_KSP, ERR_R_MALLOC_FAILURE);
        cng_trace(ctx, "[ERROR] Error in malloc\n");
        NCryptFreeObject(ksp);
        return NULL;
    }

    LPCWSTR key_name = ascii2wide(id);
    status = NCryptOpenKey(ksp, &(key->key), key_name, ctx->keyspec, ctx->keyflag);
    OPENSSL_free(key_name);

    if (status == NTE_BAD_KEYSET) {
        cng_addlasterror();
        CNGerr(CNG_F_CNG_KEY_FROM_KSP, CNG_R_CANT_FIND_KEY);
        cng_trace(ctx, "[ERROR] Specified key name '%s' was not found\n", id);
        NCryptFreeObject(ksp);
        return NULL;
    } else if (status != ERROR_SUCCESS) {
        cng_addlasterror();
        CNGerr(CNG_F_CNG_KEY_FROM_KSP, CNG_R_CANT_OPEN_KEY);
        cng_trace(ctx, "[ERROR] Error while getting key from KSP using NCryptOpenKey: returned 0x%x\n", status);
        NCryptFreeObject(ksp);
        return NULL;
    }

    NCryptFreeObject(ksp);
    return key;
}

static int cng_list_keys(CNG_CTX *ctx, BIO *out)
{
    NCRYPT_PROV_HANDLE ksp;
    NCryptKeyName *key;

    SECURITY_STATUS status;

    if ((status = NCryptOpenStorageProvider(&ksp, ctx->ksp_name, 0)) != ERROR_SUCCESS) {
        cng_addlasterror();
        CNGerr(CNG_F_CNG_LIST_KEYS, CNG_R_UNKNOWN_KSP);
        cng_trace(ctx, "[ERROR] Error while getting KSP using NCryptOpenStorageProvider: returned 0x%x\n", status);
        return 0;
    }

    char* tmpstr = wide2ascii(ctx->ksp_name);
    BIO_printf(out, "Enumerating keys in %s:\n", tmpstr);
    OPENSSL_free(tmpstr);

    PVOID state = NULL;
    int cnt = 0;

    status = NCryptEnumKeys(ksp, NULL, &key, &state, ctx->keyflag);
    while (status == ERROR_SUCCESS) {
        ++cnt;
        tmpstr = wide2ascii(key->pszName);
        BIO_printf(out, " %d. Name: %s\n", cnt, tmpstr);
        OPENSSL_free(tmpstr);
        tmpstr = wide2ascii(key->pszAlgid);
        BIO_printf(out, "    AlgId: %s\n", tmpstr);
        OPENSSL_free(tmpstr);

        if (key->dwLegacyKeySpec == AT_KEYEXCHANGE)
            BIO_printf(out, "    KeySpec: AT_KEYEXCHANGE\n");
        else if (key->dwLegacyKeySpec == AT_SIGNATURE)
            BIO_printf(out, "    KeySpec: AT_SIGNATURE\n");
        else
            BIO_printf(out, "    KeySpec: <NONE>\n");

        NCryptFreeBuffer(key); 
        status = NCryptEnumKeys(ksp, NULL, &key, &state, ctx->keyflag);
    }

    NCryptFreeObject(ksp);
    return 1;
}

/************************************************************
 *  RSA METHODS
 ************************************************************/
/*RSA METHOD structure for binding specifc RSA implementation*/
static RSA_METHOD *cng_rsa_method = NULL;
static int rsa_cng_idx = -1;

/**
 * Convert OpenSSL padding id into NCRYPT id
 * @param padding OpenSSL padding id
 * @return Ncrypt padding id or 0 if not supported
 */
static DWORD osslPad2cngPad(int padding) {
    switch (padding) {
        case RSA_NO_PADDING:
            return NCRYPT_NO_PADDING_FLAG;
        
        case RSA_PKCS1_PADDING:
            return NCRYPT_PAD_PKCS1_FLAG;

        case RSA_PKCS1_OAEP_PADDING:
            /** 
             * Although OAEP encrypt/decrypt is labeled as unsupported, engine supports it as 
             * RSA_PKEY_METHOD prepare OAEP parameters before calling RSA_encrypt or RSA_decrypt with RSA_NO_PADDING padding.
             * See rsa_pmeth.c */
        default:
            return 0;
    }
}

/**
 * According to RSA_private_(encrypt|decrypt) man3, functions should be used for signing.
 * Since EVP_PKEY_RSA calls these methods for encrypting and decrypting, engine ignores this recommendation now for now.
 * For signing there is implemented EVP_PKEY_sign method, which override RSA_sign calls and satisfies these recommendation.
 * In OpenSSL 3.0 RSA_methods probably will be deprecated and EVP_PKEY_methods should be used instead.
 */

/**
 * Function is called by EVP_PKEY_RSA method, when RSA_encrypt is used.
 * @param flen Length of from buffer
 * @param from Buffer with data to encrypt
 * @param to Buffer that recives ciphertext
 * @param rsa Structure holding RSA inner data  
 * @param padding Padding for RSA encrypt
 */
static int cng_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    CNG_KEY *cng_key = RSA_get_ex_data(rsa, rsa_cng_idx);
    CNG_CTX *cng_ctx = ENGINE_get_ex_data(RSA_get0_engine(rsa), engine_cng_idx);

    cng_trace(cng_ctx, "[INFO] Called cng_rsa_priv_enc()\n");

    DWORD pad = osslPad2cngPad(padding);
    if (pad == 0) {
        cng_trace(cng_ctx, "[ERROR] OpenSSL padding %d is not supported\n", padding);
        CNGerr(CNG_F_CNG_RSA_PRIV_ENC, CNG_R_UNSUPPORTED_PADDING);
        return -1;
    }

    DWORD len;
    /* info used only with oaep */
    if (NCryptEncrypt(cng_key->key, (PBYTE)from, (DWORD)flen, NULL, to, flen, &len, pad) != ERROR_SUCCESS) {
        cng_trace(cng_ctx, "[ERROR] Error while encrypting\n");
        CNGerr(CNG_F_CNG_RSA_PRIV_ENC, CNG_R_DECRYPT_ERROR);
        cng_addlasterror();
        return -1;
    }
    return len;
}

/**
 * Function is called by EVP_PKEY_RSA method, when RSA_decrypt is used.
 * @param flen Length of from buffer
 * @param from Buffer with data to encrypt
 * @param to Buffer that recives ciphertext
 * @param rsa Structure holding RSA inner data  
 * @param padding Padding for RSA decrypt
 */
static int cng_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    CNG_KEY *cng_key = RSA_get_ex_data(rsa, rsa_cng_idx);
    CNG_CTX *cng_ctx = ENGINE_get_ex_data(RSA_get0_engine(rsa), engine_cng_idx);

    cng_trace(cng_ctx, "[INFO] Called cng_rsa_priv_dec()\n");

    DWORD pad = osslPad2cngPad(padding);
    if (pad == 0) {
        cng_trace(cng_ctx, "[ERROR] OpenSSL padding %d is not supported\n", padding);
        CNGerr(CNG_F_CNG_RSA_PRIV_DEC, CNG_R_UNSUPPORTED_PADDING);
        return -1;
    }

    DWORD len;
    if (NCryptDecrypt(cng_key->key, (PBYTE)from, (DWORD)flen, NULL, to, flen, &len, pad) != ERROR_SUCCESS) {
        cng_trace(cng_ctx, "[ERROR] Error while decrypting\n");
        CNGerr(CNG_F_CNG_RSA_PRIV_DEC, CNG_R_DECRYPT_ERROR);
        cng_addlasterror();
        return -1;
    }
    return flen;
}

/**
 * Clean & free
 */
static int cng_rsa_free(RSA *rsa)
{
    CNG_KEY *cng_key = RSA_get_ex_data(rsa, rsa_cng_idx);
    cng_free_key(cng_key);
    RSA_set_ex_data(rsa, rsa_cng_idx, NULL);
    return 1;
}

/* EVP_PKEY METHOD; RSA_PKEY override */
 
#include <crypto/evp.h>

static EVP_PKEY_METHOD *cng_evp_rsa_method = NULL;

/**
 * EVP_PKEY_sign method. Use CNG to sign passed hash.
 * @param ctx EVP_PKEY inner structure
 * @param sig pointer to a buffer that revies signature
 * @param siglen recives length of signature
 * @param tbs buffer with hashed message
 * @param tbslen length of tbs buffer
 * @return 1 if success, else N<=0
 */
static int cng_rsa_sign(EVP_PKEY_CTX *ctx,
                        unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    RSA *rsa = ctx->pkey->pkey.rsa;
    CNG_CTX *cng_ctx = ENGINE_get_ex_data(RSA_get0_engine(rsa), engine_cng_idx);
    cng_trace(cng_ctx, "[DEBUG] Called cng_rsa_sign()\n");
    
    CNG_KEY *cng_key = RSA_get_ex_data(rsa, rsa_cng_idx);
    if (!cng_key) {
        cng_trace(cng_ctx, "[ERROR] Can't get key\n");
        CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_CANT_GET_KEY);
        return -1;
    }

    /* Get used hash algorithm */
    EVP_MD *hash = NULL;
    if (EVP_PKEY_CTX_get_signature_md(ctx, &hash) <= 0) {
        cng_trace(cng_ctx, "[ERROR] EVP_PKEY_CTX_get_signature_md() failed\n");
        CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_UNEXPECTED);
        return -1;
    }

    if (tbslen != (size_t)EVP_MD_size(hash)) {
        cng_trace(cng_ctx, "[ERROR] Digest length differ: passed 'tbslen' is %u but should be %d\n", tbslen, EVP_MD_size(hash));
        CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_INVALID_DIGEST_LENGTH);
        return -1;
    }

    /* Convert OpenSSL signature NID into CNG AlgID */
    LPCWSTR hashAlgId;
    switch (EVP_MD_type(hash)) {
        case NID_sha256:
            hashAlgId = BCRYPT_SHA256_ALGORITHM;
            break;

        case NID_sha384:
            hashAlgId = BCRYPT_SHA384_ALGORITHM;
            break;

        case NID_sha512:
            hashAlgId = BCRYPT_SHA512_ALGORITHM;
            break;

        case NID_sha1:
            hashAlgId = BCRYPT_SHA1_ALGORITHM;
            break;

        case NID_md5:
            hashAlgId = BCRYPT_MD5_ALGORITHM;
            break;

        /**
         * Acording to RFC 4346 F1.5 pg.78 (and so RFC 2246 F1.5 pg.72)
         * "TLS uses hash functions very conservatively.  Where possible, both MD5 and SHA are used in tandem"
         * This type of hash algorithm is not listed in standard CNG Algorithms
         */
        case NID_md5_sha1:
            cng_trace(cng_ctx, "[ERROR] NID_md5_sha1 is not supported by CNG\n");
        default:
            cng_trace(cng_ctx, "[ERROR] Unsupported NID %d\n", EVP_MD_type(hash));
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_UNSUPPORTED_ALGORITHM_NID);
            hashAlgId = NULL;
            return -1;
    }

    int padding = 0;
    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
        cng_trace(cng_ctx, "[ERROR] EVP_PKEY_CTX_get_rsa_padding() failed\n");
        CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_UNEXPECTED);
        return -1;
    }

    /**
     * Finally sign hash depending on used padding
     */
    DWORD slen;
    SECURITY_STATUS status;
    if (padding == RSA_PKCS1_PSS_PADDING) {
        /** 
         * OpenSSL supports different mask function and hash function, CNG NCryptSignHash do not - they must be same.
         * According to RFC 8017 8.1, pg.33 - "It is RECOMMENDED that the mask generation function be based on the same hash function"
         * So just check that they are same.
         * */
        EVP_MD *mgf1Hash = NULL;
        if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1Hash) <= 0) {
            cng_trace(cng_ctx, "[WARNING] EVP_PKEY_CTX_get_rsa_mgf1_md() failed, using hash function as MGF1\n");
            mgf1Hash = hash;
        }
        if (EVP_MD_type(mgf1Hash) != EVP_MD_type(hash)) {
            cng_trace(cng_ctx, "[ERROR] MGF1 and hash function do not match. This is not supported by CNG\n");
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_UNSUPPORTED_MGF);
            return -1;
        }

        int saltlen;
        if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen) <= 0) {
            cng_trace(cng_ctx, "[WARNING] EVP_PKEY_CTX_get_rsa_pss_saltlen() failed, using RSA_PSS_SALTLEN_DIGEST as default\n");
            saltlen = RSA_PSS_SALTLEN_DIGEST;
        }

        /** Salt length
         * RSA_PSS_SALTLEN_DIGEST (-1): Salt length equals hash len
         * RSA_PSS_SALTLEN_MAX_SIGN (-2): Salt length is maximized
         * RSA_PSS_SALTLEN_MAX (-3): Salt length is maximized (on signing)
         */

        if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
            saltlen = (int)tbslen;
        } else if (saltlen == RSA_PSS_SALTLEN_MAX_SIGN) {
            saltlen = RSA_PSS_SALTLEN_MAX;
        } else if (saltlen < RSA_PSS_SALTLEN_MAX) {
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_SLEN_CHECK_FAILED);
            cng_trace(cng_ctx, "Unknown meaning of salt length value %d\n", saltlen);
        }

        /* See crypto/rsa/rsa_pss.c in OpenSSL project */
        int modLen = RSA_size(rsa);
        if ((RSA_bits(rsa) & 0x7) == 0)
            --modLen;

        if (modLen < (int)tbslen + 2) {
            cng_trace(cng_ctx, "[ERROR] Data are too large for key size\n");
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        }

        if (saltlen == RSA_PSS_SALTLEN_MAX) {
            saltlen = modLen - tbslen - 2;
        } else if (saltlen > modLen - (int)tbslen - 2) {
            cng_trace(cng_ctx, "[ERROR] Data are too large for key size\n");
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        }

        cng_trace(cng_ctx, "[INFO] Signing hash with PSS padding, hashAlgId: %s; saltLen: %d; tbslen: %u\n", wide2ascii(hashAlgId), saltlen, tbslen);
        BCRYPT_PSS_PADDING_INFO PSSPaddingInfo = {hashAlgId, saltlen};
        slen = RSA_size(rsa);
        if ((status = NCryptSignHash(cng_key->key, &PSSPaddingInfo, (PBYTE)tbs, (DWORD)tbslen, sig, slen, &slen, BCRYPT_PAD_PSS)) != ERROR_SUCCESS) {
            cng_trace(cng_ctx, "[ERROR] Error while signing hash using NCryptSignHash: returned 0x%x\n", status);
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_ERROR_SIGNING_HASH);
            cng_addlasterror();
            return -1;
        }

    } else if (padding == RSA_PKCS1_PADDING) {
        cng_trace(cng_ctx, "[INFO] Signing hash with PKCS1 padding, hashAlgId: %s; tbslen: %u\n", wide2ascii(hashAlgId), tbslen);
        BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo = {hashAlgId};
        slen = RSA_size(rsa);
        if ((status = NCryptSignHash(cng_key->key, &PKCS1PaddingInfo, (PBYTE)tbs, (DWORD)tbslen, sig, slen, &slen, BCRYPT_PAD_PKCS1)) != ERROR_SUCCESS) {
            cng_trace(cng_ctx, "[ERROR] Error while signing hash using NCryptSignHash: returned 0x%x\n", status);
            CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_ERROR_SIGNING_HASH);
            cng_addlasterror();
            return -1;
        }
    } else {
        cng_trace(cng_ctx, "[ERROR] Unsupported padding type %d\n", padding);
        CNGerr(CNG_F_CNG_PKEY_RSA_SIGN, CNG_R_UNSUPPORTED_PADDING);
        return -1;
    }

    *siglen = slen;
    return 1;
}


/************************************************************
 *  ECDSA METHODS
 ************************************************************/
# ifndef OPENSSL_NO_EC
static EC_KEY_METHOD *cng_ec_key_method = NULL;
static int ec_key_cng_idx = -1;

/**
 * Sign hashed message in dgst having length dgst_len using ECDSA key
 * @param dgst Digest to sign
 * @param dgst_len Length of digest to sign
 * @param in_kinv k^-1; not used
 * @param in_r not used
 * @param eckey EC_KEY structure
 * @return ECDSA_SIG ECDSA signature structure or NULL if error
 */
static ECDSA_SIG* cng_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                                     const BIGNUM *in_kinv, const BIGNUM* in_r, EC_KEY *eckey)
{
    CNG_KEY *cng_key = EC_KEY_get_ex_data(eckey, ec_key_cng_idx);
    if (!cng_key) {
        CNGerr(CNG_F_CNG_ECDSA_SIGN_KEY, CNG_R_UNEXPECTED);
        return NULL;
    }
   
    ECDSA_SIG *ecdsaSig = NULL;
    DWORD siglen;
    NCryptSignHash(cng_key->key, NULL, (PBYTE)dgst, (DWORD)dgst_len, NULL, 0, &siglen, 0);
    
    PBYTE signature = OPENSSL_malloc(siglen);
    if (!signature) {
        CNGerr(CNG_F_CNG_ECDSA_SIGN_KEY, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    NCryptSignHash(cng_key->key, NULL, (PBYTE)dgst, (DWORD)dgst_len, signature, siglen, &siglen, 0);
    /* Returned signature is concatenation of r and s, both with same length */
    DWORD rLen = siglen/2; /*signature = [r|s]*/
    BIGNUM *r = BN_bin2bn(signature, rLen, NULL);
    BIGNUM *s = BN_bin2bn(signature + rLen, rLen, NULL);
    if (!r || !s) {
        CNGerr(CNG_F_CNG_ECDSA_SIGN_KEY, CNG_R_ECDSA_SIGN_ERROR);
        return NULL;
    }

    ecdsaSig = ECDSA_SIG_new();
    if (!ecdsaSig) {
        CNGerr(CNG_F_CNG_ECDSA_SIGN_KEY, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(signature);
        BN_free(r);
        BN_free(s);
        return NULL;
    }
    ECDSA_SIG_set0(ecdsaSig, r, s);

    return ecdsaSig;
}

/**
 * There isn't support for generic magic number for all ECC Blobs until Windows 10 1507,
 * so every possible magic number must be tested now.
 * @param magic Magic number to test
 * @return OpenSSL curve NID if magic is ECC blob, else 0
 */
int is_ecc(int magic)
{
    typedef struct magicToNid_st {
        int magic;
        int nid;
    } magicToNid;

    magicToNid eccPublicMagics[] = {
        {BCRYPT_ECDH_PUBLIC_P256_MAGIC, NID_X9_62_prime256v1},
        {BCRYPT_ECDH_PUBLIC_P384_MAGIC, NID_secp384r1},
        {BCRYPT_ECDH_PUBLIC_P521_MAGIC, NID_secp521r1},
        {BCRYPT_ECDSA_PUBLIC_P256_MAGIC, NID_X9_62_prime256v1},
        {BCRYPT_ECDSA_PUBLIC_P384_MAGIC, NID_secp384r1},
        {BCRYPT_ECDSA_PUBLIC_P521_MAGIC, NID_secp521r1}};

    size_t size = sizeof(eccPublicMagics)/sizeof(eccPublicMagics[0]);
    for (size_t i = 0; i < size; i++)
        if (magic == eccPublicMagics[i].magic)
            return eccPublicMagics[i].nid;
    
    return 0;
}

# endif /* OPENSSL_NO_EC */

/************************************************************
 *  KEY LOAD
 ************************************************************/

/**
 * From PCCERT_CONTEXT acquire key into CNG_KEY.key
 * @param CNG_CTX Engine inner structure
 * @param PCCERT_CONTEXT Certificate context for which key will be obtained
 */
static CNG_KEY *cng_get_cert_key(CNG_CTX *ctx, PCCERT_CONTEXT cert)
{
    CNG_KEY *key = OPENSSL_malloc(sizeof(*key));
    if (!key) {
        CNGerr(CNG_F_CNG_GET_CERT_KEY, ERR_R_MALLOC_FAILURE);
        return NULL;
    }


    BOOL callerFree;
    DWORD keySpec;
    /** CryptAcquireCertificatePrivateKey
     *      address of PCCERT_CONTEXT 
     *      obtain the key by using CNG and do not display any UI
     *      parameters for specific flags
     *      NCryptKeyHandle that recives acquired key
     *      keySpec should be CERT_NCRYPT_KEY_SPEC, as ONLY_NCRYPT flag is used
     *      recives bool - If TRUE, the caller is responsible for releasing the handle
     */
    if (!CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &key->key, &keySpec, &callerFree)) {
        cng_trace(ctx, "[ERROR] Can not acquire key from certificate\n");
        CNGerr(CNG_F_CNG_GET_CERT_KEY, CNG_R_CRYPTACQUIREPRIVKEY_ERROR);
        cng_addlasterror();
        OPENSSL_free(key);
        return NULL;
    }
    
    if(keySpec != CERT_NCRYPT_KEY_SPEC) {
        cng_trace(ctx, "[WARNING] keySpec should be CERT_NCRYPT_KEY_SPEC\n");
    }

    return key;
}

/**
 * Find certificate using CNG_CTX->lookup_method that match id.
 * Then get its key. CNG_CTX->storename is used.
 * @param ctx Engine inner structure
 * @param id Parameter for lookup_method
 */
CNG_KEY* cng_find_key(CNG_CTX *ctx, const char *id)
{
    CNG_KEY *key = NULL;

    switch (ctx->lookup_method) {
        case CNG_LU_SUBJ_SUBSTR:
        case CNG_LU_ISSU_SUBSTR:
        case CNG_LU_FNAME:
            PCCERT_CONTEXT cert = cng_find_cert(ctx, id);
            if (!cert) {
                cng_trace(ctx, "[ERROR] No cert match specified criteria '%s'\n", id);
                return NULL;
            }
            
            key = cng_get_cert_key(ctx, cert);
            CertFreeCertificateContext(cert);
            return key;
        
        case CNG_LU_CONTNAME:
            key = cng_key_from_ksp(ctx, id);
            return key;

        default:
            cng_trace(ctx, "[ERROR] Unsupported lookup method '%d'\n", ctx->lookup_method);
            return NULL;
    }
    
}


/**
 * Create EVP_PKEY structure from initialized CNG_KEY
 * Supported algorithms
 *      - RSA
 *      - EC, ECDSA, ECDH
 * @param eng ENGINE structure
 * @param key CNG_KEY containing key handler
 * @return *EVP_PKEY with a lowlevel key represetnation and privkey handler in its exdata
 */
static EVP_PKEY* cng_get_pkey(ENGINE *eng, CNG_KEY *key)
{
    CNG_CTX *ctx = ENGINE_get_ex_data(eng, engine_cng_idx);

    EVP_PKEY* pkey = NULL;
    DWORD len = 0;

    RSA *rsa = NULL;
    EC_KEY *ec = NULL;
    int curveNid = 0;

    if (FAILED(NCryptExportKey(key->key, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL, NULL, 0, &len, 0))) {
        cng_trace(ctx, "[ERROR] First call of NCryptExportKey failed, can't obtain length\n");
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_PUBKEY_EXPORT_LENGTH_ERROR);
        cng_addlasterror();
        return NULL;
    }

    unsigned char *blob = OPENSSL_malloc(len);
    if (!blob)
        goto memerr;

    if (FAILED(NCryptExportKey(key->key, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL, blob, len, &len, 0))) {
        cng_trace(ctx, "[ERROR] Second call of NCryptExportKey failed, can't obtain key blob\n");
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_PUBKEY_EXPORT_ERROR);
        cng_addlasterror();
        goto err;
    }
    
    BCRYPT_KEY_BLOB *keyBlob = (BCRYPT_KEY_BLOB*)blob;
    if (keyBlob->Magic == BCRYPT_RSAPUBLIC_MAGIC) {
        cng_trace(ctx, "[INFO] Using RSA key\n");
        BCRYPT_RSAKEY_BLOB *rsaBlob = (BCRYPT_RSAKEY_BLOB*)keyBlob;
        BIGNUM *e = NULL;
        BIGNUM *n = NULL;
        
        ULONG offset = sizeof(BCRYPT_RSAKEY_BLOB);
        e = BN_bin2bn(blob + offset, rsaBlob->cbPublicExp, NULL);
        offset += rsaBlob->cbPublicExp;
        n = BN_bin2bn(blob + offset, rsaBlob->cbModulus, NULL);

        rsa = RSA_new_method((ENGINE*)eng);

        if (!e || !n || !rsa) {
            cng_trace(ctx, "[ERROR] e, n or rsa memerr\n");
            BN_free(e);
            BN_free(n);
            goto memerr;
        }

        RSA_set0_key(rsa, n, e, NULL);
        RSA_set_ex_data(rsa, rsa_cng_idx, key);
        
        pkey = EVP_PKEY_new();
        if (pkey == NULL) {
            cng_trace(ctx, "[ERROR] EVP_PKEY could not be allocated\n");
            goto memerr;
        }

        EVP_PKEY_assign_RSA(pkey, rsa);
        rsa = NULL;
  # ifndef OPENSSL_NO_EC
    } else if ((curveNid = is_ecc(keyBlob->Magic)) != 0) {
        cng_trace(ctx, "[INFO] Using ECC key\n");
        BCRYPT_ECCKEY_BLOB *eccBlob = (BCRYPT_ECCKEY_BLOB*)keyBlob;
        BIGNUM *x = NULL;
        BIGNUM *y = NULL;

        ULONG offset = sizeof(BCRYPT_ECCKEY_BLOB);
        x = BN_bin2bn((PBYTE)eccBlob + offset, eccBlob->cbKey, NULL);
        offset += eccBlob->cbKey;
        y = BN_bin2bn((PBYTE)eccBlob + offset, eccBlob->cbKey, NULL);

        ec = EC_KEY_new_by_curve_name(curveNid);

        if (!x || !y || !ec) {
            cng_trace(ctx, "[ERROR] x, y or ec memerr\n");
            BN_free(x);
            BN_free(y);
            goto memerr;
        }
        
        EC_KEY_set_public_key_affine_coordinates(ec, x, y);
        EC_KEY_set_ex_data(ec, ec_key_cng_idx, key);

        pkey = EVP_PKEY_new();
        if (pkey == NULL) {
            cng_trace(ctx, "[ERROR] EVP_PKEY could not be allocated\n");
            goto memerr;
        }

        EVP_PKEY_assign_EC_KEY(pkey, ec);
        ec = NULL;
  # endif /* OPENSSL_NO_EC */
    } else {
        cng_trace(ctx, "[ERROR] Public key blob with Magic number 0x%x is not supported\n", keyBlob->Magic);
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM);
        goto err;
    }
    return pkey;

err:
    OPENSSL_free(blob);
    return pkey;

    memerr:
        CNGerr(CNG_F_CNG_GET_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
}

/*******************************************************************
 *  CLIENT SSL CERT MANIPULATION
 *    - Implementation of functions used in cng_load_ssl_client_cert
 *******************************************************************/
static int cert_cng_idx = -1;

/**
 * Check if issuer name of @cert match any of names in @ca_dn 
 * @param ca_dn stack of issuer names
 * @param cert X509 struct containing cert data
 * @return 1 if match, else 0
 */
static int cert_issuer_match(STACK_OF(X509_NAME) *ca_dn, X509 *cert)
{
    int i;
    X509_NAME *cert_name;

    /* Special case: empty list = match anything */
    if (sk_X509_NAME_num(ca_dn) <= 0)
        return 1;

    /* Compare every CA name with cert name */
    for (i = 0; i < sk_X509_NAME_num(ca_dn); ++i) {
        cert_name = sk_X509_NAME_value(ca_dn, i);
        if (!X509_NAME_cmp(cert_name, X509_get_issuer_name(cert)))
            return 1;
    }
    return 0;
}

/**
 * Simple selection method
 * always returns 0 which means first cert in certs stack
 */
static int cert_select_simple(ENGINE *e, SSL *ssl, STACK_OF(X509) *certs)
{
    return 0;
}

/**
 * Similar to e_capi
 * https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/engines/e_capi.c
 * Opens dialog window for certificate selection
 */
# ifdef OPENSSL_CNGENG_DIALOG
/*
 * More complex cert selection function, using standard function
 * CryptUIDlgSelectCertificateFromStore() to produce a dialog box.
 */

/*
 * Definitions which are in cryptuiapi.h but this is not present in older
 * versions of headers.
 */
#  ifndef CRYPTUI_SELECT_LOCATION_COLUMN
#   define CRYPTUI_SELECT_LOCATION_COLUMN                   0x000000010
#   define CRYPTUI_SELECT_INTENDEDUSE_COLUMN                0x000000004
#  endif

#  define dlg_title L"OpenSSL Application SSL Client Certificate Selection"
#  define dlg_prompt L"Select a certificate to use for authentication"
#  define dlg_columns      CRYPTUI_SELECT_LOCATION_COLUMN \
                        |CRYPTUI_SELECT_INTENDEDUSE_COLUMN

/** Returns number of cert in certs stack, that was chosen by user
 * in dialog windows */
static int cert_select_dialog(ENGINE *e, SSL *ssl, STACK_OF(X509) *certs)
{
    X509 *x;
    HCERTSTORE dstore;
    PCCERT_CONTEXT cert;
    CNG_CTX *ctx;
    CNG_KEY *key;
    HWND hwnd;
    int i, idx = -1;
    if (sk_X509_num(certs) == 1)
        return 0;
    ctx = ENGINE_get_ex_data(e, engine_cng_idx);

    /* Create an in memory store of certificates */
    dstore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                           CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!dstore) {
        CNGerr(CNG_F_CERT_SELECT_DIALOG, CNG_R_ERROR_CREATING_STORE);
        cng_addlasterror();
        goto err;
    }
    /* Add all certificates to store */
    for (i = 0; i < sk_X509_num(certs); i++) {
        x = sk_X509_value(certs, i);
        key = X509_get_ex_data(x, cert_cng_idx);

        if (!CertAddCertificateContextToStore(dstore, key->cert,
                                              CERT_STORE_ADD_NEW, NULL)) {
            CNGerr(CNG_F_CERT_SELECT_DIALOG, CNG_R_ERROR_ADDING_CERT);
            cng_addlasterror();
            goto err;
        }

    }
    hwnd = GetForegroundWindow();
    if (!hwnd)
        hwnd = GetActiveWindow();
    if (!hwnd && ctx->getconswindow)
        hwnd = ctx->getconswindow();
    /* Call dialog to select one */
    cert = ctx->certselectdlg(dstore, hwnd, dlg_title, dlg_prompt,
                              dlg_columns, 0, NULL);

    /* Find matching cert from list */
    if (cert) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            x = sk_X509_value(certs, i);
            key = X509_get_ex_data(x, cert_cng_idx);
            if (CertCompareCertificate
                (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->pCertInfo,
                 key->cert->pCertInfo)) {
                idx = i;
                break;
            }
        }
    }

 err:
    if (dstore)
        CertCloseStore(dstore, 0);
    return idx;

}
# endif

/************************************************************
 *  ENGINE FRAMEWORK FUNCTIONS
 *    - Implementation of functions binned in bind_cng()
 ************************************************************/

/**
 * Definitions for ctrl() commands handle
 */
#define CNG_CMD_DEBUG_LEVEL            (ENGINE_CMD_BASE)
#define CNG_CMD_DEBUG_FILE             (ENGINE_CMD_BASE + 1)

#define CNG_CMD_LIST_CERTS             (ENGINE_CMD_BASE + 2)
#define CNG_CMD_LIST_METHOD            (ENGINE_CMD_BASE + 3)
#define CNG_CMD_LOOKUP_CERT            (ENGINE_CMD_BASE + 4)
#define CNG_CMD_LOOKUP_METHOD          (ENGINE_CMD_BASE + 5)
#define CNG_CMD_DUMP_FLAGS             (ENGINE_CMD_BASE + 6)

#define CNG_CMD_STORE_NAME             (ENGINE_CMD_BASE + 7)
#define CNG_CMD_STORE_FLAGS            (ENGINE_CMD_BASE + 8)

#define CNG_CMD_LIST_KSPS              (ENGINE_CMD_BASE + 9)
#define CNG_CMD_KSP_NAME               (ENGINE_CMD_BASE + 10)
#define CNG_CMD_KEYSPEC                (ENGINE_CMD_BASE + 11)
#define CNG_CMD_KEY_FLAG               (ENGINE_CMD_BASE + 12)
#define CNG_CMD_LIST_KEYS              (ENGINE_CMD_BASE + 13)

/**
 * Array of ENGINE_CMD_DEFN struct = {cmd_num, cmd_name, cmd_description, cmd_input}
 * Must be in cmd_num increasing order
 */
static const ENGINE_CMD_DEFN cng_cmd_defns[] = {
    {CNG_CMD_DEBUG_LEVEL, "debug_level", "Set debug level: <NUM>\n\t1=errors;\n\t2=trace;", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_DEBUG_FILE, "debug_file", "Set debugging filename: <PATH>", ENGINE_CMD_FLAG_STRING},
    {CNG_CMD_LIST_CERTS, "list_certs", "List certificates in store", ENGINE_CMD_FLAG_NO_INPUT},
    {CNG_CMD_LIST_METHOD, "list_method", "Set certificate list method: <NUM> (default is 1)\n\t1 = All;\n\t2 = Has private key;", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_LOOKUP_CERT, "lookup_cert", "Lookup and output certificates: <STRING>", ENGINE_CMD_FLAG_STRING},
    {CNG_CMD_LOOKUP_METHOD, "lookup_method", "Set certificate lookup method: <NUM>\n\t1 = Subject substring;\n\t2 = Issuer substring\n\t3 = Friendly name;\n\t4 = Container name", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_DUMP_FLAGS, "dump_flags", "Set certificate dump flags: <NUM> (default is 3)\n\t1 = Issuer and Serial name;\n\t2 = Friendly name;\n\t4 = Full X.509 printout;\n\t8 = PEM format certificate;", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_STORE_NAME, "store_name", "Certificate store name: <NAME> (default is 'MY')", ENGINE_CMD_FLAG_STRING},
    {CNG_CMD_STORE_FLAGS, "store_flags", "Certificate store flags: <NUM>\n\t1 = System store;", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_LIST_KSPS, "list_ksps", "List all KSPs", ENGINE_CMD_FLAG_NO_INPUT},
    {CNG_CMD_KSP_NAME, "ksp_name", "Set KSP name: <NAME> (default is Microsoft Software Key Storage Provider)", ENGINE_CMD_FLAG_STRING},
    {CNG_CMD_KEYSPEC, "keyspec", "Set keyspec: <NUM> (default is AT_KEYEXCHANGE)\n\t0 = None;\n\t1=AT_KEYEXCHANGE;\n\t2=AT_SIGNATURE", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_KEY_FLAG, "keyflag", "Set keyflag: <NUM> (default is local user)\n\t0=Use local user keys;\n\t1=Use machine keys", ENGINE_CMD_FLAG_NUMERIC},
    {CNG_CMD_LIST_KEYS, "list_keys", "List all keys in KSPs\n", ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};


/**
 * Specify EVP_PKEY_METHOD according to nid 
 *  When calling cng_pkey_meths(e, NULL, &pnids, 0)
 *       framework wants a list of supported nids to pnids
 *       returns number of nids or -1 for error
 *  When calling cng_pkey_mehts(e, &pmeth, NULL, nid)
 *       framework wants EVP_PKEY_METHOD for specified nid
 *       returns 1 on success else 0
 */
static int cng_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **pnids, int nid)
{
    /* EVP_RSA_PSS is not usually called
     * This EVP_PKEY_RSA supports PSS */
    static int rnid[] = {
        EVP_PKEY_RSA,
        0
    };
    if (!pmeth) {
        /* Pass list and number of supported nids */
        *pnids = rnid;
        return 1;
    }
    switch (nid) {
        /* EVP_PKEY_METHOD is used only to override EVP_PKEY_RSA sign */
        case EVP_PKEY_RSA:
            *pmeth = cng_evp_rsa_method;
            return 1;
        
        default:
            *pmeth = NULL;
            return 0;
    }
}

/**
 * Engine function for loading key.
 * Find key using lookup_method that match key_id criteria and transform it into EVP_PKEY
 * @return EVP_PKEY or NULL
 */
static EVP_PKEY *cng_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    CNG_CTX *ctx;
    CNG_KEY *key;
    EVP_PKEY *ret;
    
    ctx = ENGINE_get_ex_data(e, engine_cng_idx);

    if (!ctx) {
        cng_trace(ctx, "[ERROR] Cant get engine context\n");
        CNGerr(CNG_F_CNG_LOAD_PRIVKEY, CNG_R_CANT_FIND_CNG_CONTEXT);
        return NULL;
    }

    key = cng_find_key(ctx, key_id);

    if (!key) {
        cng_trace(ctx, "[ERROR] Cant find key\n");
        CNGerr(CNG_F_CNG_LOAD_PRIVKEY, CNG_R_CANT_FIND_KEY);
        return NULL;
    }

    ret = cng_get_pkey(e, key);

    if (!ret) {
        cng_trace(ctx, "[ERROR] Key couldnt be transformed into EVP_PKEY\n");
        CNGerr(CNG_F_CNG_LOAD_PRIVKEY, CNG_R_CANT_CREATE_PKEY);
        cng_free_key(key);
        return NULL;
    }

    return ret;
}


/**
 * This takes list of CA names and returns certificate with EVP_PKEY
 * that is issued by any of passed authorities.
 * pother, ui_method and callback_data are not used.
 */
static int cng_load_ssl_client_cert(ENGINE *e, SSL *ssl, STACK_OF(X509_NAME) *ca_dn, 
                                    X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                    UI_METHOD *ui_method, void *callback_data)
{
    STACK_OF(X509) *match_certs = NULL;
    HCERTSTORE hstore;
    PCCERT_CONTEXT cert = NULL, tmp_cert = NULL;
    X509 *x509;
    const unsigned char *len;
    CNG_KEY *key;
    CNG_CTX *ctx = ENGINE_get_ex_data(e, engine_cng_idx);

    int i, cert_idx;


    const char* storename = ctx->storename;
    if (!storename) storename = DEFAULT_STORENAME;

    hstore = cng_open_store(ctx, storename);
    if (!hstore) return 0;

    /* Enumerate hstore and collect matches in ca_dn*/
    for (i = 0;; ++i) {
        cert = CertEnumCertificatesInStore(hstore, cert);
        if (!cert) break;

        len = cert->pbCertEncoded;
        x509 = d2i_X509(NULL, &len, cert->cbCertEncoded);
        if (!x509) {
            cng_trace(ctx, "Certificate no.%d could not be parsed", i);
            continue;
        }

        /* Check if cert in CA list AND
         * - The EKU extension must be absent or include the "web client authentication" OID.
         * - keyUsage must be absent or it must have the digitalSignature bit set.
         * - Netscape certificate type must be absent or it must have the SSL client bit set. */
        if (cert_issuer_match(ca_dn, x509) && X509_check_purpose(x509, X509_PURPOSE_SSL_CLIENT, 0)) {
            key = cng_get_cert_key(ctx, cert);
            if (!key) {
                X509_free(x509);
                continue;
            }

            /* Got matching cert and key; add key as x509 exdata */
            tmp_cert = CertDuplicateCertificateContext(cert);
            key->cert = tmp_cert;
            X509_set_ex_data(x509, cert_cng_idx, key);

            if (!match_certs)
                match_certs = sk_X509_new_null();
            sk_X509_push(match_certs, x509);
        } else {
            X509_free(x509);
        }
    }

    if (cert) CertFreeCertificateContext(cert);
    if (hstore) CertCloseStore(hstore, 0);

    /* No match found */
    if (!match_certs) return 0;

    /* There is at least one certificate that match
     * if engine was compiled with OPENSSL_CNGENG_DIALOG, then window showes up
     * by default first cert is used. */
    cert_idx = ctx->client_cert_select(e, ssl, match_certs);

    /* Set the selected certificate and free rest */
    for (i = 0; i < sk_X509_num(match_certs); i++) {
        x509 = sk_X509_value(match_certs, i);
        if (i == cert_idx)
            *pcert = x509;
        else {
            key = X509_get_ex_data(x509, cert_cng_idx);
            cng_free_key(key);
            X509_free(x509);
        }
    }

    sk_X509_free(match_certs);
    if (!*pcert) return 0;

    /* Setup key for selected certificate */
    key = X509_get_ex_data(*pcert, cert_cng_idx);
    *pkey = cng_get_pkey(e, key);
    X509_set_ex_data(*pcert, cert_cng_idx, NULL);
    return 1;
}

/**
 * Bind specific functions implementation and set CNG_CTX.
 * RSA, DSA
 * @param e Engine structure
 * @return 1 if OK, else 0
 */
static int cng_init(ENGINE *e)
{
    if (engine_cng_idx < 0) {
        /* CRYPTO_get_ex_new_index(argl, argp are arguments for callbacks; 
                                   following callbacks are called when: new, duplicate, free)*/
        engine_cng_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (engine_cng_idx < 0) {
            CNGerr(CNG_F_CNG_INIT, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        /* Index used for x509 exdata in cng_load_ssl_client_cert() */
        cert_cng_idx = X509_get_ex_new_index(0, NULL, NULL, NULL, 0);


        /* RSA Setup*/

        /* Override default EVP_PKEY_RSA method */
        /* Copy existing EVP_PKEY_RSA method. See rsa_pmeth.c */
        const EVP_PKEY_METHOD *ossl_pkey_method = EVP_PKEY_meth_find(EVP_PKEY_RSA);
        if (!ossl_pkey_method)
            return 0;

        /* Get default sign init method */
        int (*psign_init)(EVP_PKEY_CTX *);
        EVP_PKEY_meth_get_sign(ossl_pkey_method, &psign_init, NULL);

        /* Override sign method */
        EVP_PKEY_meth_copy(cng_evp_rsa_method, ossl_pkey_method);
        EVP_PKEY_meth_set_sign(cng_evp_rsa_method, psign_init, cng_rsa_sign);

        /* Deallocate ossl_pkey_method */
        EVP_PKEY_meth_free(ossl_pkey_method);

        /* Define RSA_methods */
        rsa_cng_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
        const RSA_METHOD *ossl_rsa_meth = RSA_PKCS1_OpenSSL(); /*OpenSSL methods implementation*/
        if (   !RSA_meth_set_pub_enc(cng_rsa_method, RSA_meth_get_pub_enc(ossl_rsa_meth))
            || !RSA_meth_set_pub_dec(cng_rsa_method, RSA_meth_get_pub_dec(ossl_rsa_meth))
            || !RSA_meth_set_mod_exp(cng_rsa_method, RSA_meth_get_mod_exp(ossl_rsa_meth))
            || !RSA_meth_set_bn_mod_exp(cng_rsa_method, RSA_meth_get_bn_mod_exp(ossl_rsa_meth))
            || !RSA_meth_set_priv_enc(cng_rsa_method, cng_rsa_priv_enc)
            || !RSA_meth_set_priv_dec(cng_rsa_method, cng_rsa_priv_dec)
            || !RSA_meth_set_finish(cng_rsa_method, cng_rsa_free)) {
                CNGerr(CNG_F_CNG_INIT, ERR_R_MALLOC_FAILURE);
                return 0;
            }

        /* ECDSA Setup */
        #ifndef OPENSSL_NO_EC
            ec_key_cng_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
            const EC_KEY_METHOD *ossl_ec_key_meth = EC_KEY_OpenSSL();
            int (*sign)(int, const unsigned char*, int, unsigned char*,
                            unsigned int*, const BIGNUM*, const BIGNUM*, EC_KEY*) = NULL;

            EC_KEY_METHOD_get_sign(ossl_ec_key_meth, &sign, NULL, NULL);
            /* Override do_sign only */
            EC_KEY_METHOD_set_sign(cng_ec_key_method, sign, NULL, cng_ecdsa_sign_sig);
        #endif /* OPENSSL_NO_EC */

        /************************************************************
         *  DSA METHODS
         *      - From OpenSSL 1.1.0 and above ciphersuites for TLSv1.2 and below based on DSA are no longer available by default
         *      - DSA certificates are no longer allowed in TLSv1.3
         *   => DSA IS NOT IMPLEMENTED
         ************************************************************/
    }

    CNG_CTX *ctx = cng_ctx_new();
    if (!ctx) {
        CNGerr(CNG_F_CNG_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    } 

    ENGINE_set_ex_data(e, engine_cng_idx, ctx);

    /* By default cert_select_simple is used
     * OPENSS_CNGENG_DIALOG flag enables dialog window for user
     * to choose between certificates in cng_load_ssl_client_cert() */
    # ifdef OPENSSL_CNGENG_DIALOG
    {
        HMODULE cryptui = LoadLibrary(TEXT("CRYPTUI.DLL"));
        HMODULE kernel = GetModuleHandle(TEXT("KERNEL32.DLL"));
        if (cryptui)
            ctx->certselectdlg =
                (CERTDLG) GetProcAddress(cryptui,
                                         "CryptUIDlgSelectCertificateFromStore");
        if (kernel)
            ctx->getconswindow =
                (GETCONSWIN) GetProcAddress(kernel, "GetConsoleWindow");
        if (cryptui && !OPENSSL_isservice())
            ctx->client_cert_select = cert_select_dialog;
    }
    # endif
    
    return 1;
}

/**
 * Release functional references
 * @param e Engine structure
 */
static int cng_finish(ENGINE *e)
{
    CNG_CTX *ctx = ENGINE_get_ex_data(e, engine_cng_idx);
    cng_ctx_free(ctx);
    ENGINE_set_ex_data(e, engine_cng_idx, NULL);
    return 1;
}

/**
 * Release structural references
 * @param e Engine structure
 */
static int cng_destroy(ENGINE *e)
{
    RSA_meth_free(cng_rsa_method);
    cng_rsa_method = NULL;
# ifndef OPENSSL_NO_EC
    EC_KEY_METHOD_free(cng_ec_key_method);
    cng_ec_key_method = NULL;
# endif
    ERR_unload_CNG_strings();
    return 1;
}

/**
 * ENGINE_CMD_DEFN commands control handler.
 * @param e Engine structure
 * @param cmd ENGINE_CMD_DEFN.cmd_num
 * @param ipf Additional arguments
 * @return 1 if OK, else 0
 */ 
static int cng_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    CNG_CTX *ctx;
    BIO *out;
    
    LPSTR tmpstr;
    
    /*if engine is not initted*/
    if (engine_cng_idx == -1) {
        CNGerr(CNG_F_CNG_CTRL, CNG_R_ENGINE_NOT_INITIALIZED);
        return 0;
    }

    ctx = ENGINE_get_ex_data(e, engine_cng_idx);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    switch (cmd) {
        case CNG_CMD_DEBUG_LEVEL:
            ctx->debug_level = (int)i;
            cng_trace(ctx, "[INFO] Setting debug level to %d\n", ctx->debug_level);
            break;

        case CNG_CMD_DEBUG_FILE:
            tmpstr = OPENSSL_strdup(p);
            if (tmpstr != NULL) {
                ctx->debug_file = tmpstr;
                cng_trace(ctx, "[INFO] Setting debug file to %s\n", ctx->debug_file);
            } else {
                cng_trace(ctx, "[ERROR] Path to debug file is not specified\n");
                CNGerr(CNG_F_CNG_CTRL, ERR_R_MALLOC_FAILURE);
                ret = 0;
            }
            break;
        
        case CNG_CMD_LIST_CERTS:
            ret = cng_list_certs(ctx, out);
            break;
        
        case CNG_CMD_LIST_METHOD:
            if (i < 1 || i > 2) {
                CNGerr(CNG_F_CNG_CTRL, CNG_R_INVALID_METHOD);
                BIO_printf(out, "Unknown list method %ld\n", i);
                cng_trace(ctx, "[ERROR] Unknown list method %ld\n", i);
                ret = 0;
                break;
            }
            ctx->list_method = i;
            break;
        
        case CNG_CMD_LOOKUP_CERT:
            PCCERT_CONTEXT cert = cng_find_cert(ctx, p);
            if(!cert) {
                BIO_printf(out, "No certificate for specified search criteria\n");
                break;
            }
            cng_dump_cert(ctx, out, cert);
            CertFreeCertificateContext(cert);
            break;

        case CNG_CMD_LOOKUP_METHOD:
            if (i < 1 || i > 4) {
                CNGerr(CNG_F_CNG_CTRL, CNG_R_INVALID_METHOD);
                cng_trace(ctx, "[ERROR] Unknown lookup method %ld (valid: 1,2,3,4)\n", i);
                BIO_free(out);
                return 0;
            }
            ctx->lookup_method = i;
            break;
        
        case CNG_CMD_DUMP_FLAGS:
            ctx->dump_flags = (DWORD)i;
            cng_trace(ctx, "[INFO] Setting certs dump flag to %lu\n", ctx->dump_flags);
            break;

        case CNG_CMD_STORE_NAME:
            tmpstr = OPENSSL_strdup(p);
            if (tmpstr != NULL) {
                OPENSSL_free(ctx->storename);
                ctx->storename = tmpstr;
                cng_trace(ctx, "Setting store name to %s\n", ctx->storename);
            } else {
                CNGerr(CNG_F_CNG_CTRL, ERR_R_MALLOC_FAILURE);
                cng_trace(ctx, "[ERROR] Certificate store name is not specified\n");
                ret = 0;
            }
            break;
        
        case CNG_CMD_STORE_FLAGS:
            if (i & 1) {
                ctx->store_flags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
                ctx->store_flags &= ~CERT_SYSTEM_STORE_CURRENT_USER;
            } else {
                ctx->store_flags |= CERT_SYSTEM_STORE_CURRENT_USER;
                ctx->store_flags &= ~CERT_SYSTEM_STORE_LOCAL_MACHINE;
            }
            cng_trace(ctx, "Setting flags to %d\n", i);
            break;
        
        case CNG_CMD_LIST_KSPS:
            ret = cng_list_ksps(ctx, out);
            break;

        case CNG_CMD_KSP_NAME:
            ctx->ksp_name = ascii2wide(p);
            if (ctx->ksp_name) {
                cng_trace(ctx, "Setting KSP name to %s\n", p);
            } else {
                cng_trace(ctx, "KSP name could not be set\n");
                return 0;
            }
            break;
            

        case CNG_CMD_KEYSPEC:
            if (i == 0) {
                ctx->keyspec = 0;
                cng_trace(ctx, "None keyspec used\n");
            } else if (i == 1) {
                ctx->keyspec = AT_KEYEXCHANGE;
                cng_trace(ctx, "Setting keyspec as AT_KEYEXCHANGE\n");
            } else if (i == 2) {
                ctx->keyflag = AT_SIGNATURE;
                cng_trace(ctx, "Setting keyspec as AT_SIGNATURE\n\n");
            } else {
                cng_trace(ctx, "No such keyspec; 0=none, 1=exchange, 2=signature\n");
                return 0;
            }
            break;

        case CNG_CMD_KEY_FLAG:
            if (i == 0) {
                ctx->keyflag = 0;
                cng_trace(ctx, "Only current user keys will be used\n");
            } else if (i == 1) {
                ctx->keyflag = NCRYPT_MACHINE_KEY_FLAG;
                cng_trace(ctx, "Keys for the local computer will be used\n");
            } else {
                cng_trace(ctx, "No such keyflag; 0=user, 1=machine\n");
                return 0;
            }
            break;      

        case CNG_CMD_LIST_KEYS:
            ret = cng_list_keys(ctx, out);
            break;

        default:
            cng_trace(ctx, "Unknown command\n");
            return 0;
    }

    BIO_free(out);
    return ret;
}

/**
 * Set ENGINE structure, bind functions
 * Called from bind_helper()
 * @param e Engine structure
 * @return 1 if OK, else 0
 */
static int bind_cng(ENGINE *e)
{   
    cng_evp_rsa_method = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
    if (!cng_evp_rsa_method)
        return 0; 
    
    cng_rsa_method = RSA_meth_new("Cryptography API: Next Generation RSA method", 0);
    if (!cng_rsa_method)
        goto memerr;

    if (   !ENGINE_set_id(e, engine_cng_id)
        || !ENGINE_set_name(e, engine_cng_name)
        || !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) /* Do not register methods as part of ENGINE_register_all_complete() */
        || !ENGINE_set_init_function(e, cng_init)
        || !ENGINE_set_finish_function(e, cng_finish)
        || !ENGINE_set_destroy_function(e, cng_destroy)
        || !ENGINE_set_RSA(e, cng_rsa_method)
        || !ENGINE_set_load_privkey_function(e, cng_load_privkey)
        || !ENGINE_set_cmd_defns(e, cng_cmd_defns)
        || !ENGINE_set_pkey_meths(e, cng_pkey_meths)
        || !ENGINE_set_ctrl_function(e, cng_ctrl)
        || !ENGINE_set_load_ssl_client_cert_function(e, cng_load_ssl_client_cert)) {
            goto memerr;
        }

    ERR_load_CNG_strings();
    #ifndef OPENSSL_NO_EC
        cng_ec_key_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    
        if (!cng_ec_key_method)
            goto memerr;

        if (!ENGINE_set_EC(e, cng_ec_key_method))
            goto memerr;
    #endif /* OPENSSL_NO_EC */
    return 1;
    
    memerr:
        EVP_PKEY_meth_free(cng_evp_rsa_method);
        cng_evp_rsa_method = NULL;
        RSA_meth_free(cng_rsa_method);
        cng_rsa_method = NULL;
    # ifdef OPENSSL_NO_EC
        EC_KEY_METHOD_free(cng_ec_key_method);
        cng_ec_key_method = NULL;
    # endif
        return 0;

}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE

/**
 * Runs automatically on engine dynamic load
 * @param e Engine structure
 * @param id Unique name of engine
 * @return 1 if OK, else 0
 */
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_cng_id) != 0))
        return 0;

    if (!bind_cng(e)) {
        return 0;
    }
    return 1;
}

/**
 * Engine must-have for dynamic load
 */
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

# else /* OPENSSL_NO_DYNAMIC_ENGINE */

/*Engine is not loaded through 'dynamic' engine*/
static ENGINE *engine_cng(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_cng(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_cng_int(void)
{
    ENGINE *toadd = engine_cng();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


# endif /* OPENSSL_NO_DYNAMIC_ENGINE */

#else /* !__COMPILE_CAPIENG */
    # include <openssl/engine.h>
    # ifndef OPENSSL_NO_DYNAMIC_ENGINE
        OPENSSL_EXPORT
        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns);
        OPENSSL_EXPORT
        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { return 0; }
        IMPLEMENT_DYNAMIC_CHECK_FN()
    # else /* !OPENSSL_NO_DYNAMIC_ENGINE */
        void engine_load_cng_int(void);
        void engine_load_cng_int(void) {}
    # endif /* OPENSSL_NO_DYNAMIC_ENGINE */

#endif /* __COMPILE_CAPIENG */

