#include "cipherdns/core.h"
#include "cipherdns/provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deliberately not a unit-test assertion: every guard remains active in Release.
 * Only configuration paths and explicit ownership acknowledgement use env vars.
 * Secret values are read using the normal private-file configuration loader. */
static const char *setting(const char *provider, const char *suffix) {
    char name[128];
    const char *upper = !strcmp(provider, "cloudflare") ? "CLOUDFLARE"
                        : !strcmp(provider, "aliyun")   ? "ALIYUN"
                                                        : "DNSPOD";
    const char *value;
    snprintf(name, sizeof(name), "CIPHERDNS_INTEGRATION_%s_%s", upper, suffix);
    value = getenv(name);
    if (value && *value)
        return value;
    snprintf(name, sizeof(name), "CIPHERDNS_INTEGRATION_%s", suffix);
    return getenv(name);
}
static int dedicated_name(const char *domain) {
    const char prefix[] = "_cipherdns-it-";
    size_t n = sizeof(prefix) - 1;
    if (strncmp(domain, prefix, n) || strlen(domain) < n + 34)
        return 0;
    for (size_t i = n; i < n + 32; ++i)
        if (!((domain[i] >= '0' && domain[i] <= '9') || (domain[i] >= 'a' && domain[i] <= 'f')))
            return 0;
    return domain[n + 32] == '.';
}
static int verify(const cdns_config *c, const char *txt, const unsigned char key[32],
                  const cdns_address *address, char id[128]) {
    cdns_config bounded = *c;
    char err[CDNS_ERROR_MAX];
    bounded.api_deadline_ms = cdns_mono_ms() + 60000;
    for (;;) {
        cdns_provider_record rec;
        cdns_address decoded;
        cdns_provider_result result = cdns_provider_read(&bounded, &rec, err, sizeof(err));
        if (result && !cdns_provider_retryable(result)) {
            fprintf(stderr, "FAIL read-only verification: %s\n", err);
            cdns_zero(&bounded, sizeof(bounded));
            return 1;
        }
        if (!result && rec.exists) {
            if (*id && strcmp(id, rec.id)) {
                fputs("FAIL record ID changed; stop and inspect the dedicated test name\n", stderr);
                cdns_zero(&bounded, sizeof(bounded));
                return 1;
            }
            if (!strcmp(rec.value, txt) && rec.ttl == c->ttl &&
                !cdns_decrypt(key, rec.value, &decoded) && cdns_address_equal(&decoded, address)) {
                snprintf(id, 128, "%s", rec.id);
                cdns_zero(&bounded, sizeof(bounded));
                return 0;
            }
        }
        if (cdns_stopping() || cdns_mono_ms() + 5000 >= bounded.api_deadline_ms) {
            fputs("FAIL provider list did not show the expected value within 60 seconds\n", stderr);
            cdns_zero(&bounded, sizeof(bounded));
            return 1;
        }
        cdns_sleep_ms(5000);
    }
}
int main(int argc, char **argv) {
    cdns_config config;
    cdns_provider_record rec;
    cdns_address first = {"192.0.2.1", "2001:db8::1", 7000}, second = first;
    unsigned char key[32] = {0};
    char text[256], next[256], err[CDNS_ERROR_MAX], id[128] = "";
    const char *path, *domain, *confirm;
    int rc = 1, initialized = 0, wrote = 0;
    if (argc != 2 ||
        (strcmp(argv[1], "cloudflare") && strcmp(argv[1], "aliyun") && strcmp(argv[1], "dnspod")))
        return 1;
    path = setting(argv[1], "CONFIG");
    domain = setting(argv[1], "DOMAIN");
    confirm = setting(argv[1], "CONFIRM");
    if (!path || !*path || !domain || !*domain || !confirm || !*confirm) {
        puts(
            "SKIP: real provider acceptance PENDING; explicit CONFIG, DOMAIN and CONFIRM required");
        return 77;
    }
    if (!dedicated_name(domain) || strcmp(domain, confirm)) {
        fputs("FAIL dedicated test name or ownership confirmation invalid; no requests sent\n",
              stderr);
        return 1;
    }
    if (cdns_private_file(path) || cdns_config_load(path, &config, err, sizeof(err))) {
        fputs("FAIL private integration configuration/key/credentials; no requests sent\n", stderr);
        cdns_zero(&config, sizeof(config));
        return 1;
    }
    if (strcmp(config.mode, "server") || strcmp(config.provider, argv[1]) ||
        strcmp(config.domain, domain)) {
        fputs("FAIL configuration provider/domain mismatch; no requests sent\n", stderr);
        goto done;
    }
    if (cdns_key_load(config.key_file, key) || cdns_platform_init()) {
        fputs("FAIL platform/key initialization; no requests sent\n", stderr);
        goto done;
    }
    initialized = 1;
    if (cdns_provider_read(&config, &rec, err, sizeof(err))) {
        fprintf(stderr, "FAIL initial read-only discovery: %s\n", err);
        goto done;
    }
    if (rec.exists) {
        fputs("FAIL test name already has TXT; refused to overwrite it\n", stderr);
        goto done;
    }
    if (cdns_encrypt(key, &first, text)) {
        fputs("FAIL test ciphertext creation\n", stderr);
        goto done;
    }
    wrote = 1; /* A transport error can occur after provider acceptance. */
    if (cdns_provider_sync_guarded(&config, text, "", err, sizeof(err))) {
        fprintf(stderr, "FAIL create: %s\n", err);
        goto done;
    }
    if (verify(&config, text, key, &first, id))
        goto done;
    puts("PASS create and read-only provider value/decrypt verification");
    strcpy(second.ipv4, "192.0.2.2");
    strcpy(second.ipv6, "2001:db8::2");
    if (cdns_encrypt(key, &second, next))
        goto done;
    if (cdns_provider_sync_guarded(&config, next, id, err, sizeof(err))) {
        fprintf(stderr, "FAIL update: %s\n", err);
        goto done;
    }
    if (verify(&config, next, key, &second, id))
        goto done;
    puts("PASS update of same owned record ID and read-only provider value/decrypt verification");
    if (cdns_provider_sync_guarded(&config, next, id, err, sizeof(err))) {
        fprintf(stderr, "FAIL unchanged sync: %s\n", err);
        goto done;
    }
    if (verify(&config, next, key, &second, id))
        goto done;
    puts("PASS repeated identical ciphertext; no-write optimization is asserted by offline HTTP "
         "mocks");
    puts("PENDING recursive/authoritative DNS propagation must be checked separately after TTL");
    rc = 0;
done:
    if (wrote)
        fprintf(
            stderr,
            "TEST RECORD RETAINED: %s TXT; record ID %s; verify ownership and remove manually\n",
            config.domain, *id ? id : "unknown (check provider console)");
    cdns_zero(key, sizeof(key));
    cdns_zero(&config, sizeof(config));
    if (initialized)
        cdns_platform_cleanup();
    return rc;
}
