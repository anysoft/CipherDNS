#include "cipherdns/core.h"
#include "cipherdns/provider.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static int calls, fail, recover_after, reads, existing;
static char existing_text[256];
cdns_provider_result cdns_provider_read(const cdns_config *c, cdns_provider_record *r, char *err,
                                        size_t cap) {
    reads++;
    memset(r, 0, sizeof(*r));
    if (fail) {
        snprintf(err, cap, "mock read failure");
        return (cdns_provider_result)fail;
    }
    r->exists = existing;
    r->ttl = c->ttl;
    strcpy(r->id, "testrecord");
    strcpy(r->value, existing_text);
    return CDNS_PROVIDER_OK;
}
cdns_provider_result cdns_provider_sync_guarded(const cdns_config *c, const char *text,
                                                const char *id, char *err, size_t cap) {
    assert(!strcmp(id, existing ? "testrecord" : ""));
    (void)c;
    (void)text;
    calls++;
    if (fail || recover_after) {
        snprintf(err, cap, "mock network failure");
        if (recover_after) {
            recover_after--;
            return CDNS_PROVIDER_RETRY;
        }
        return (cdns_provider_result)fail;
    }
    return 0;
}
int main(void) {
    unsigned char key[32] = {0};
    cdns_config c = {0};
    cdns_address synced = {0}, seen = {"203.0.113.1", "2001:db8::1", 7000};
    int has = 0;
    char err[256];
    assert(cdns_platform_init() == 0);
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) == 1 && calls == 1 &&
           has);
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) == 0 && calls == 1);
    strcpy(seen.ipv4, "203.0.113.2");
    seen.ipv6[0] = 0;
    fail = CDNS_PROVIDER_RETRY;
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) < 0 && calls == 1);
    assert(!strcmp(synced.ipv4, "203.0.113.1") && !strcmp(synced.ipv6, "2001:db8::1"));
    fail = 0;
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) == 1 && calls == 2);
    assert(!strcmp(synced.ipv4, "203.0.113.2") && !strcmp(synced.ipv6, "2001:db8::1"));
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) == 0 && calls == 2);
    has = 0;
    existing = 1;
    strcpy(existing_text, "unrelated TXT");
    int writes = calls;
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) ==
               CDNS_PROVIDER_CONFLICT &&
           calls == writes);
    cdns_address published = {"203.0.113.2", "2001:db8::2", 7000};
    assert(cdns_encrypt(key, &published, existing_text) == 0);
    assert(cdns_server_step(&c, key, &synced, &has, &seen, err, sizeof(err)) == 1 &&
           calls == writes);
    assert(!strcmp(synced.ipv6, "2001:db8::2"));
    existing = 0;
    assert(cdns_server_retry_delay(0) == 0 && cdns_server_retry_delay(1) == 1000);
    assert(cdns_server_retry_delay(9) == 256000 && cdns_server_retry_delay(10) == 300000);
    assert(cdns_server_retry_delay(1000000) == 300000);
#ifndef _WIN32
    strcpy(c.ip_source, "command");
    strcpy(c.ip_family, "both");
    strcpy(c.ipv6_strategy, "lowest");
    c.command_timeout = 2;
    c.port = 7000;
    strcpy(c.command, "printf '10.1.2.3 2001:db8::123\\n'");
    assert(cdns_ip_detect(&c, &seen) == 0);
    assert(!seen.ipv4[0] && !strcmp(seen.ipv6, "2001:db8::123"));
    c.allow_private_ipv4 = 1;
    assert(cdns_ip_detect(&c, &seen) == 0);
    assert(!strcmp(seen.ipv4, "10.1.2.3"));
    strcpy(c.command, "printf 'invalid\\n'");
    assert(cdns_ip_detect(&c, &seen) != 0);
    strcpy(c.command, "printf '203.0.113.5\\n'");
    c.retries = 5;
    c.check_interval = 1;
    calls = 0;
    fail = CDNS_PROVIDER_DENIED;
    int before_reads = reads;
    uint64_t start = cdns_mono_ms();
    assert(cdns_server_run(&c, key, 1) == 1);
    assert(calls == 0 && reads == before_reads + 1 && cdns_mono_ms() - start < 1000);
    calls = 0;
    fail = 0;
    recover_after = 1;
    c.retries = 1;
    assert(cdns_server_run(&c, key, 1) == 0 && calls == 2);
#endif
    cdns_platform_cleanup();
    puts("server state/recovery tests passed");
    return 0;
}
