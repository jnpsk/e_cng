#include <openssl/err.h>
#include "e_cng_err.h"

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA CNG_str_functs[] = {
    {ERR_PACK(0, CNG_F_CNG_INIT, 0), "cng_init"},
    {ERR_PACK(0, CNG_F_CNG_CTX_NEW, 0), "capi_ctx_new"},
    {ERR_PACK(0, CNG_F_CNG_TRACE, 0), "cng_trace"},
    {ERR_PACK(0, CNG_F_CNG_CTRL, 0), "cng_ctrl"},
    {ERR_PACK(0, CNG_F_CNG_OPEN_STORE, 0), "cng_open_store"},
    {ERR_PACK(0, CNG_F_CNG_CERT_GET_FNAME, 0), "cng_cert_get_fname"},
    {ERR_PACK(0, CNG_F_WIDE2ASCII, 0), "wide2ascii"},
    {ERR_PACK(0, CNG_F_CNG_LOAD_PRIVKEY, 0), "cng_load_privkey"},
    {ERR_PACK(0, CNG_F_CNG_PKEY_RSA_SIGN, 0), "cng_rsa_sign"},
    {ERR_PACK(0, CNG_F_CNG_GET_PKEY, 0), "cng_get_pkey"},
    {ERR_PACK(0, CNG_F_CERT_SELECT_DIALOG, 0), "cert_select_dialog"},
    {ERR_PACK(0, CNG_F_CNG_RSA_PRIV_DEC, 0), "cng_rsa_priv_dec"},
    {ERR_PACK(0, CNG_F_CNG_RSA_PRIV_ENC, 0), "cng_rsa_priv_enc"},
    {ERR_PACK(0, CNG_F_CNG_DSA_DO_SIGN, 0), "cng_dsa_do_sign"},
    {ERR_PACK(0, CNG_F_CNG_GET_CERT_KEY, 0), "cng_get_cert_key"},
    {ERR_PACK(0, CNG_F_CNG_ECDSA_SIGN_KEY, 0), "cng_ecdsa_sign_sig"},
    {ERR_PACK(0, CNG_F_CNG_LIST_KEYS, 0), "cng_list_keys"},
    {ERR_PACK(0, CNG_F_CNG_LIST_KSPS, 0), "cng_list_ksps"},
    {ERR_PACK(0, CNG_F_CNG_KEY_FROM_KSP, 0), "cng_key_from_ksp"},
    {ERR_PACK(0, CNG_F_ASCII2WIDE, 0), "ascii2wide"},
    {0, NULL}
};

static ERR_STRING_DATA CNG_str_reasons[] = {
    {ERR_PACK(0, 0, CNG_R_FILE_OPEN_ERROR), "file open error"},
    {ERR_PACK(0, 0, CNG_R_ENGINE_NOT_INITIALIZED), "engine not initialized"},
    {ERR_PACK(0, 0, CNG_R_ERROR_ADDING_CERT), "error adding cert"},
    {ERR_PACK(0, 0, CNG_R_ERROR_CREATING_STORE), "error creating store"},
    {ERR_PACK(0, 0, CNG_R_ERROR_OPENING_STORE), "error opening store"},
    {ERR_PACK(0, 0, CNG_R_ERROR_GETTING_FRIENDLY_NAME), "error getting friendly name"},
    {ERR_PACK(0, 0, CNG_R_INVALID_METHOD), "invalid lookup method"},
    {ERR_PACK(0, 0, CNG_R_WIN32_ERROR), "win32 error"},
    {ERR_PACK(0, 0, CNG_R_CANT_FIND_CNG_CONTEXT), "cant find cng context"},
    {ERR_PACK(0, 0, CNG_R_CANT_GET_KEY), "cant get key"},
    {ERR_PACK(0, 0, CNG_R_UNEXPECTED), "function call returned unexpected code"},
    {ERR_PACK(0, 0, CNG_R_INVALID_DIGEST_LENGTH), "expected and passed hash length differ"},
    {ERR_PACK(0, 0, CNG_R_UNSUPPORTED_ALGORITHM_NID), "unsupported algorithm nid"},
    {ERR_PACK(0, 0, CNG_R_ERROR_SIGNING_HASH), "error signing hash"},
    {ERR_PACK(0, 0, CNG_R_UNSUPPORTED_PADDING), "unsupported padding"},
    {ERR_PACK(0, 0, CNG_R_DATA_TOO_LARGE_FOR_KEY_SIZE), "data too large for key size"},
    {ERR_PACK(0, 0, CNG_R_UNSUPPORTED_MGF), "unsupported MGF1"},
    {ERR_PACK(0, 0, CNG_R_SLEN_CHECK_FAILED), "salt length has invalid value"},
    {ERR_PACK(0, 0, CNG_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM), "unsupported public key algorithm"},
    {ERR_PACK(0, 0, CNG_R_PUBKEY_EXPORT_LENGTH_ERROR), "pubkey export length error"},
    {ERR_PACK(0, 0, CNG_R_PUBKEY_EXPORT_ERROR), "pubkey export error"},
    {ERR_PACK(0, 0, CNG_R_DECRYPT_ERROR), "decrypt error"},
    {ERR_PACK(0, 0, CNG_R_ENCRYPT_ERROR), "encrypt error"},
    {ERR_PACK(0, 0, CNG_R_FUNCTION_NOT_SUPPORTED), "function not supported"},
    {ERR_PACK(0, 0, CNG_R_CRYPTACQUIREPRIVKEY_ERROR), "cryptacquireprivatekey error"},
    {ERR_PACK(0, 0, CNG_R_CANT_FIND_KEY), "key not found"},
    {ERR_PACK(0, 0, CNG_R_CANT_CREATE_PKEY), "cant create evp_pkey"},
    {ERR_PACK(0, 0, CNG_R_ECDSA_SIGN_ERROR), "cant obtain r or s from ecdsa sign"},
    {ERR_PACK(0, 0, CNG_R_UNKNOWN_KSP), "specified KSP could not be opened"},
    {ERR_PACK(0, 0, CNG_R_ERROR_ENUM_KSP), "error while enumerating KSPs"},
    {ERR_PACK(0, 0, CNG_R_CANT_OPEN_KEY), "error while getting key from KSP"},
    {0, NULL}
};

#endif /*OPENSSL_NO_ERR*/


static int lib_code = 0;
static int error_loaded = 0;

static int ERR_load_CNG_strings(void)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();

    if (!error_loaded) {
        #ifndef OPENSSL_NO_ERR
            ERR_load_strings(lib_code, CNG_str_functs);
            ERR_load_strings(lib_code, CNG_str_reasons);
        #endif
        error_loaded = 1;
    }
    return 1;
}

static void ERR_unload_CNG_strings(void)
{
    if (error_loaded) {
        #ifndef OPENSSL_NO_ERR
            ERR_unload_strings(lib_code, CNG_str_functs);
            ERR_unload_strings(lib_code, CNG_str_reasons);
        #endif
        error_loaded = 0;
    }
}

static void ERR_CNG_error(int function, int reason, char *file, int line)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();
    
    ERR_PUT_error(lib_code, function, reason, file, line);
}