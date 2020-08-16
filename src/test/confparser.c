#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include "confparser.h"

void strip(char **str)
{
    while (isspace(**str) || **str == '"') ++*str;

    char* end = *str + strlen(*str);
    while (isspace(*(end-1)) || *(end-1) == '"') --end;
    *end = '\0';
}

int assign(CONFIG* conf, const char* key, const char* value)
{
    if (strcmp(key, "MAX_TLS_VERSION") == 0) {
        if (strcmp(value, "1.0") == 0) conf->tls_version = TLS1_VERSION;    
        else if (strcmp(value, "1.1") == 0) conf->tls_version = TLS1_1_VERSION;
        else if (strcmp(value, "1.2") == 0) conf->tls_version = TLS1_2_VERSION;
        else if (strcmp(value, "1.3") == 0) conf->tls_version = 0;
        else {
            printf("[ERROR] Unsupported tls version '%s'\n", value);
            return 0;
        }
        return 1;

    } else if (strcmp(key, "RSA_CA_PATH") == 0) {
        conf->rsa_ca_path = strdup(value);
    } else if (strcmp(key, "ECDSA_CA_PATH") == 0) {
        conf->ecdsa_ca_path = strdup(value);
    } else if (strcmp(key, "SERVER_ENGINE_PATH") == 0) {
        conf->server_engine_path = strdup(value);
    } else if (strcmp(key, "CLIENT_ENGINE_PATH") == 0) {
        conf->client_engine_path = strdup(value);
    } else if (strcmp(key, "SERVER_RSA_CERT") == 0) {
        conf->server_rsa_cert = strdup(value);
    } else if (strcmp(key, "SERVER_ECDSA_CERT") == 0) {
        conf->server_ecdsa_cert = strdup(value);
    } else if (strcmp(key, "ECDSA_ONLY") == 0) {
        conf->ecdsa_only = 1;
    } else if (strcmp(key, "RSA_ONLY") == 0) {
        conf->rsa_only = 1;
    } else if (strcmp(key, "NO_RSA_PSS") == 0) {
        conf->no_pss = 1;
    } else if (strcmp(key, "CERT_REQUEST") == 0) {
        conf->cert_request = 1;
    } else {
        printf("[WARNING] Key '%s' does not exist\n", key);
        return 0;
    }

    return 1;
}

int get_config(CONFIG* conf, const char* filename)
{
    char line[256];    
    FILE *file;  

    file = fopen(filename, "r"); 
    
    if (file==NULL) {
        printf("[Error] Can't open file '%s'.\n", filename);
        return 0;
    }

    char* key;
    char* val;

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '\n') continue;
 
        key = line;
        val = strchr(line, '=');
        if (!val) continue;
        *val++ = '\0';

        strip(&val);
        strip(&key);

        if (key[0] == '#') continue;

        assign(conf, key, val);
    }
    return 1;
}