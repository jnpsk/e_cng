#ifndef CONFPARSER_H
#define CONFPARSER_H
#pragma warning(disable : 4996)

typedef struct config_st {
    int tls_version;
    char *rsa_ca_path;
    char *ecdsa_ca_path;
    char *server_engine_path;
    char *client_engine_path;
    char *server_rsa_cert;
    char *server_ecdsa_cert;
    int ecdsa_only;
    int rsa_only;
    int no_pss;
    int cert_request;
} CONFIG;

int get_config(CONFIG *conf, const char* filename);
#endif