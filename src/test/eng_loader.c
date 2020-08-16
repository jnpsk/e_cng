#include <stdio.h>
#include <openssl/engine.h>

void print_ctrls(ENGINE *e)
{
    if(!ENGINE_ctrl(e, ENGINE_CTRL_HAS_CTRL_FUNCTION, 0, NULL, NULL)) {
        printf("[INFO] Engine has no controls\n");
        return;
    }

    printf("ENGINE COMMANDS:\n");
    char name[50], desc[200];
    long cmd_num = ENGINE_ctrl(e, ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, NULL, NULL);
    while(cmd_num > 0) {
        ENGINE_ctrl(e, ENGINE_CTRL_GET_NAME_FROM_CMD, cmd_num, name, NULL);
        printf("%s:\n", name);
        ENGINE_ctrl(e, ENGINE_CTRL_GET_DESC_FROM_CMD, cmd_num, desc, NULL);
        printf(" - %s\n", desc);
        cmd_num = ENGINE_ctrl(e, ENGINE_CTRL_GET_NEXT_CMD_TYPE, cmd_num, NULL, NULL);
    }
    printf("\n");
}


int main(int argc, char const *argv[])
{
    if (argc < 2) {
        printf("Specify engine's dll path, please");
        return -1;
    }

    printf("[INFO] Bind engine\n");
    ENGINE_load_dynamic();
    ENGINE *engine = ENGINE_by_id("dynamic");
    if (!engine) {
        printf("[ERROR] No such engine.\n");
        return 1;
    }

    ENGINE_ctrl_cmd_string(engine, "SO_PATH", argv[1], 0);
    if (ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0) != 1) {
        printf("[WARNING] Engine '%s' was NOT loaded\n", argv[1]);
        return 1;
    }

    printf("[INFO] Engine '%s' loaded: %s\n", ENGINE_get_id(engine), ENGINE_get_name(engine));

    printf("[INFO] Print controls\n");
    print_ctrls(engine);

    printf("[INFO] Init engine\n");
    if (!ENGINE_init(engine)) {
        printf("[ERROR] Engine could not be initted.\n");
        ENGINE_free(engine);
        return 1;
    }

    printf("[INFO] Set log file\n");
    if (!ENGINE_ctrl_cmd_string(engine, "debug_file", "cng_trace.log", 0)) {
        printf("[WARNING] Cannot set debug file for engine.\n");
        ENGINE_free(engine);
        return 1;
    }

    printf("[INFO] Set debug level\n");
    if (!ENGINE_ctrl_cmd(engine, "debug_level", 2, NULL, NULL, 0)) {
        printf("[WARNING] Cannot set debug level for engine\n");
        ENGINE_free(engine);
        return 1;
    }

    /* Has effect with cng only */
    ENGINE_ctrl_cmd_string(engine, "list_ksps", NULL, 1);
    ENGINE_ctrl_cmd_string(engine, "list_keys", NULL, 1);

    /*Has effect with capi only*/
    ENGINE_ctrl_cmd_string(engine, "list_csps", NULL, 1);
    ENGINE_ctrl_cmd_string(engine, "list_containers", NULL, 1);

    printf("[INFO] List certs in certstore\n");
    if (!ENGINE_ctrl_cmd_string(engine, "list_certs", NULL, 0)) {
        ERR_print_errors_fp(stderr);
        printf("[WARNING] Cannot list certs.\n");
        ENGINE_free(engine);
        return 1;
    }

    printf("[INFO] Find cert containing '27'\n");
    if (!ENGINE_ctrl_cmd_string(engine, "lookup_cert", "localhost", 0)) {
        printf("[WARNING] Lookup failed\n");
        ENGINE_free(engine);
        return 1;
    }

    ENGINE_free(engine);
    return 0;
}

