#include "cipherdns/core.h"
#include "cipherdns/provider.h"
#include <stdio.h>
#include <string.h>
int cdns_server_step(const cdns_config *c, const unsigned char key[32], cdns_address *synced,
                     int *has_synced, const cdns_address *observed, char *err, size_t cap) {
    cdns_address next;
    cdns_address_merge(&next, observed, synced);
    if (cdns_address_valid(&next)) {
        snprintf(err, cap, "no valid address available");
        return CDNS_PROVIDER_INVALID;
    }
    if (*has_synced && cdns_address_equal(&next, synced))
        return 0;
    cdns_config bounded = *c;
    if (!bounded.update_timeout)
        bounded.update_timeout = 30;
    bounded.api_deadline_ms = cdns_mono_ms() + (uint64_t)bounded.update_timeout * 1000;
    if (c->api_deadline_ms && c->api_deadline_ms < bounded.api_deadline_ms)
        bounded.api_deadline_ms = c->api_deadline_ms;
    cdns_provider_record record;
    cdns_provider_result result = cdns_provider_read(&bounded, &record, err, cap);
    if (result != CDNS_PROVIDER_OK)
        goto done;
    if (record.exists) {
        cdns_address published;
        if (cdns_decrypt(key, record.value, &published)) {
            snprintf(err, cap,
                     "existing TXT does not authenticate with this key; inspect ownership or "
                     "choose a dedicated name");
            result = CDNS_PROVIDER_CONFLICT;
            goto done;
        }
        if (!*has_synced)
            cdns_address_merge(&next, observed, &published);
        if (cdns_address_equal(&next, &published) && record.ttl == c->ttl)
            goto accepted;
    }
    char text[256];
    if (cdns_encrypt(key, &next, text)) {
        snprintf(err, cap, "encryption failed");
        result = CDNS_PROVIDER_REJECTED;
        goto done;
    }
    result = cdns_provider_sync_guarded(&bounded, text, record.exists ? record.id : "", err, cap);
    if (result != CDNS_PROVIDER_OK)
        goto done;
accepted:
    *synced = next;
    *has_synced = 1;
done:
    cdns_zero(&bounded, sizeof(bounded));
    return result == CDNS_PROVIDER_OK ? 1 : result;
}
unsigned cdns_server_retry_delay(unsigned failures) {
    if (!failures)
        return 0;
    if (failures >= 10)
        return 300000;
    unsigned delay = 1000u << (failures - 1);
    return delay > 300000 ? 300000 : delay;
}
int cdns_server_run(const cdns_config *c, const unsigned char key[32], int once) {
    cdns_address synced = {0};
    int has_synced = 0;
    unsigned failures = 0;
    while (!cdns_stopping()) {
        cdns_address observed;
        char err[256];
        int rc = -1;
        if (cdns_ip_detect(c, &observed))
            cdns_log("WARN", "no eligible address detected; retaining last successful state");
        else {
            for (unsigned attempt = 0; attempt <= c->retries && !cdns_stopping(); attempt++) {
                rc = cdns_server_step(c, key, &synced, &has_synced, &observed, err, sizeof(err));
                if (rc >= 0) {
                    failures = 0;
                    break;
                }
                if (rc != CDNS_PROVIDER_RETRY && rc != CDNS_PROVIDER_RATE_LIMIT) {
                    cdns_log("ERROR",
                             "DNS update rejected: %s; fix configuration/permissions and restart",
                             err);
                    return 1;
                }
                if (failures < 10)
                    failures++;
                cdns_log("WARN", "DNS update failed: %s (attempt %u/%u)", err, attempt + 1,
                         c->retries + 1);
                if (attempt < c->retries)
                    cdns_sleep_ms(cdns_server_retry_delay(failures));
            }
            if (rc > 0)
                cdns_log("INFO", "provider state synchronized; resolver caches may still "
                                 "contain the previous value");
        }
        if (once)
            return rc >= 0 ? 0 : 1;
        unsigned interval = c->check_interval * 1000u;
        unsigned backoff = cdns_server_retry_delay(failures);
        cdns_sleep_ms(backoff > interval ? backoff : interval);
    }
    return 0;
}
