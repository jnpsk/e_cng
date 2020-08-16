
#ifndef OSSL_ENGINES_E_CNG_ERR_H

# define OSSL_ENGINES_E_CNG_ERR_H
# define CNGerr(f, r) ERR_CNG_error((f), (r), OPENSSL_FILE, OPENSSL_LINE)


/**
 * CNG function codes.
 */
# define CNG_F_CNG_CERT_GET_FNAME                       99
# define CNG_F_CNG_CTRL                                 100
# define CNG_F_CNG_CTX_NEW                              101
# define CNG_F_CNG_INIT                                 106
# define CNG_F_CNG_LIST_KEYS                            107
# define CNG_F_CNG_LOAD_PRIVKEY                         108
# define CNG_F_CNG_OPEN_STORE                           109
# define CNG_F_CNG_RSA_PRIV_DEC                         110
# define CNG_F_CNG_RSA_PRIV_ENC                         111
# define CNG_F_CNG_PKEY_RSA_SIGN                        112
# define CNG_F_WIDE2ASCII                               113
# define CNG_F_CNG_DSA_DO_SIGN                          114
# define CNG_F_CNG_GET_PKEY                             115
# define CNG_F_CERT_SELECT_DIALOG                       117
# define CNG_F_CNG_TRACE                                118
# define CNG_F_CNG_GET_CERT_KEY                         120
# define CNG_F_CNG_ECDSA_SIGN_KEY                       121
# define CNG_F_CNG_LIST_KSPS                            122
# define CNG_F_CNG_KEY_FROM_KSP                         123
# define CNG_F_ASCII2WIDE                               124


/**
 * CNG reason codes.
 */
# define CNG_R_CANT_FIND_CNG_CONTEXT                    101
# define CNG_R_CANT_GET_KEY                             102
# define CNG_R_CRYPTACQUIREPRIVKEY_ERROR                104
# define CNG_R_DECRYPT_ERROR                            106
# define CNG_R_ENGINE_NOT_INITIALIZED                   107
# define CNG_R_ERROR_ADDING_CERT                        109
# define CNG_R_ERROR_CREATING_STORE                     110
# define CNG_R_ERROR_GETTING_FRIENDLY_NAME              111
# define CNG_R_ERROR_OPENING_STORE                      113
# define CNG_R_ERROR_SIGNING_HASH                       114
# define CNG_R_FILE_OPEN_ERROR                          115
# define CNG_R_FUNCTION_NOT_SUPPORTED                   116
# define CNG_R_INVALID_METHOD                           120
# define CNG_R_PUBKEY_EXPORT_ERROR                      123
# define CNG_R_PUBKEY_EXPORT_LENGTH_ERROR               124
# define CNG_R_UNSUPPORTED_ALGORITHM_NID                126
# define CNG_R_UNSUPPORTED_PADDING                      127
# define CNG_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM         128
# define CNG_R_WIN32_ERROR                              129
# define CNG_R_INVALID_DIGEST_LENGTH                    143
# define CNG_R_DATA_TOO_LARGE_FOR_KEY_SIZE              150
# define CNG_R_UNSUPPORTED_MGF                          151
# define CNG_R_SLEN_CHECK_FAILED                        152
# define CNG_R_ENCRYPT_ERROR                            156
# define CNG_R_CANT_FIND_KEY                            157
# define CNG_R_CANT_CREATE_PKEY                         158
# define CNG_R_ECDSA_SIGN_ERROR                         159
# define CNG_R_UNKNOWN_KSP                              160
# define CNG_R_ERROR_ENUM_KSP                           161
# define CNG_R_CANT_OPEN_KEY                            163
# define CNG_R_UNEXPECTED                               666

#endif /*OSSL_ENGINES_E_CNG_ERR_H*/