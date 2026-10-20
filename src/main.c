#include "cipherdns/core.h"
#include "cipherdns/doctor.h"
#include <stdio.h>
#include <string.h>
#ifndef CDNS_VERSION
#define CDNS_VERSION "0.2.1"
#endif
static void usage(void) {
    puts("CipherDNS " CDNS_VERSION
         "\nUsage:\n  cipherdns server|client -c FILE [--once]\n  cipherdns keygen [-o FILE]\n  "
         "cipherdns configtest -c FILE\n  cipherdns doctor -c FILE [--json] [--provider-read]\n  "
         "cipherdns --version\n  cipherdns --help");
}
int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage();
        return 0;
    }
    if (!strcmp(argv[1], "--version")) {
        puts("CipherDNS " CDNS_VERSION);
        return 0;
    }
    if (cdns_platform_init()) {
        fputs("platform initialization failed\n", stderr);
        return 1;
    }
    int rc = 1;
    if (!strcmp(argv[1], "keygen")) {
        const char *path = "aes.key";
        if (argc == 4 && !strcmp(argv[2], "-o"))
            path = argv[3];
        else if (argc != 2) {
            usage();
            goto done;
        }
        if (cdns_keygen(path))
            fputs("key generation failed (existing files are never overwritten)\n", stderr);
        else {
            puts("32-byte AES key created; distribute through a secure local channel.");
            rc = 0;
        }
        goto done;
    }
    const char *path = NULL;
    int once = 0, json = 0, provider_read = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc && !path)
            path = argv[++i];
        else if (!strcmp(argv[i], "--once") && !once)
            once = 1;
        else if (!strcmp(argv[i], "--json") && !json)
            json = 1;
        else if (!strcmp(argv[i], "--provider-read") && !provider_read)
            provider_read = 1;
        else {
            usage();
            rc = 2;
            goto done;
        }
    }
    if (!path || (strcmp(argv[1], "server") && strcmp(argv[1], "client") &&
                  strcmp(argv[1], "configtest") && strcmp(argv[1], "doctor"))) {
        usage();
        rc = 2;
        goto done;
    }
    if (!strcmp(argv[1], "doctor")) {
        if (once) {
            usage();
            rc = 2;
            goto done;
        }
        rc = cdns_doctor_run(path, json, provider_read, stdout);
        goto done;
    }
    if (json || provider_read || (!strcmp(argv[1], "configtest") && once)) {
        usage();
        rc = 2;
        goto done;
    }
    cdns_config c;
    char err[256];
    unsigned char key[32] = {0};
    if (cdns_config_load(path, &c, err, sizeof(err))) {
        cdns_log("ERROR", "%s", err);
        cdns_zero(&c, sizeof(c));
        goto done;
    }
    if (!strcmp(argv[1], "configtest")) {
        puts("Configuration and local key/credential permissions are valid.");
        rc = 0;
    } else if (strcmp(argv[1], c.mode))
        cdns_log("ERROR", "command mode differs from common.mode");
    else if (cdns_key_load(c.key_file, key))
        cdns_log("ERROR", "cannot read AES key");
#ifdef CDNS_SERVER
    else if (!strcmp(c.mode, "server"))
        rc = cdns_server_run(&c, key, once);
#endif
#ifdef CDNS_CLIENT
    else if (!strcmp(c.mode, "client"))
        rc = cdns_client_run(&c, key, once);
#endif
    cdns_zero(key, sizeof(key));
    cdns_zero(&c, sizeof(c));
done:
    cdns_platform_cleanup();
    return rc;
}
