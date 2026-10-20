#include "cipherdns/client.h"
#include "cipherdns/dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *err, size_t cap, const char *message) {
    if (err && cap)
        snprintf(err, cap, "%s", message);
    return -1;
}
static int save_state(const cdns_config *c, const unsigned char key[32],
                      const cdns_client_state *s) {
    char txt[256], contents[1024];
    int n;
    if (!s->has_applied || cdns_encrypt(key, &s->applied, txt))
        return -1;
    n = snprintf(contents, sizeof contents, "CipherDNS-state-v1\n%s\n%s\n", c->domain, txt);
    if (n < 0 || (size_t)n >= sizeof contents)
        return -1;
    return cdns_atomic_write(c->state_file, contents, (size_t)n);
}
int cdns_client_load(const cdns_config *c, const unsigned char key[32], cdns_client_state *s) {
    FILE *file;
    char buffer[1024], expected[512], *txt, *newline;
    size_t got, prefix_len;
    int n;
    if (!c || !key || !s)
        return -1;
    memset(s, 0, sizeof *s);
    if (cdns_private_file(c->state_file))
        return -1;
    file = fopen(c->state_file, "rb");
    if (!file)
        return -1;
    got = fread(buffer, 1, sizeof buffer - 1, file);
    if (ferror(file) || !feof(file)) {
        fclose(file);
        return -1;
    }
    if (fclose(file) || memchr(buffer, 0, got))
        return -1;
    buffer[got] = 0;
    n = snprintf(expected, sizeof expected, "CipherDNS-state-v1\n%s\n", c->domain);
    if (n < 0 || (size_t)n >= sizeof expected)
        return -1;
    prefix_len = (size_t)n;
    if (got <= prefix_len || memcmp(buffer, expected, prefix_len))
        return -1;
    txt = buffer + prefix_len;
    newline = strchr(txt, '\n');
    if (newline) {
        if (newline[1])
            return -1;
        *newline = 0;
    }
    if (strlen(txt) > CDNS_TEXT_MAX || cdns_decrypt(key, txt, &s->applied))
        return -1;
    s->has_applied = 1;
    return 0;
}

static int connectivity(const cdns_config *c, const cdns_address *a) {
    const char *first, *second;
    unsigned port = c->check_port ? c->check_port : a->port;
    if (!strcmp(c->prefer_family, "ipv4")) {
        first = a->ipv4;
        second = a->ipv6;
    } else {
        first = a->ipv6;
        second = a->ipv4;
    }
    if (*first && !cdns_tcp_probe(first, port, c->check_timeout))
        return 1;
    if (*second && !cdns_tcp_probe(second, port, c->check_timeout))
        return 1;
    return 0;
}
int cdns_client_step(const cdns_config *c, const unsigned char key[32], cdns_client_state *s,
                     const char *txt, char *err, size_t cap) {
    cdns_address address;
    int changed, recovered = 0, trigger;
    uint64_t now;
    char json[256];
    if (err && cap)
        err[0] = 0;
    if (!c || !key || !s)
        return fail(err, cap, "invalid client state");
    if (!txt) {
        /* DNS recovery is independent from committing an already successful
         * Hook. Retry a transient cache-write failure even while DNS is down. */
        if (s->cache_dirty && s->has_applied && !save_state(c, key, s))
            s->cache_dirty = 0;
        return fail(err, cap, "DNS TXT query failed; keeping last valid state");
    }
    if (cdns_decrypt(key, txt, &address))
        return fail(err, cap, "TXT authentication or address validation failed");
    s->observed = address;
    s->has_observed = 1;
    if (c->check_connectivity) {
        int reachable = connectivity(c, &address);
        recovered = s->connectivity_known && !s->reachable && reachable;
        if (!s->connectivity_known || s->reachable != reachable)
            cdns_log("INFO", "service connectivity: %s", reachable ? "reachable" : "unreachable");
        s->reachable = reachable;
        s->connectivity_known = 1;
    }
    changed = !s->has_applied || !cdns_address_equal(&address, &s->applied);
    trigger = changed || s->retry_hook || (recovered && c->hook_on_recovery);
    if (recovered && c->hook_on_recovery)
        s->retry_hook = 1;
    if (!trigger) {
        if (s->cache_dirty) {
            if (save_state(c, key, s))
                return fail(err, cap, "cannot persist applied state; will retry cache write");
            s->cache_dirty = 0;
        }
        return 0;
    }
    now = cdns_mono_ms();
    if (s->attempted_hook && now - s->last_hook_ms < (uint64_t)c->hook_min_interval * 1000)
        return 0;
    if (cdns_address_json(&address, json, sizeof json) ||
        cdns_atomic_write(c->current_file, json, strlen(json)))
        return fail(err, cap, "cannot write hook JSON; applied state retained");
    s->attempted_hook = 1;
    s->last_hook_ms = now;
    if (cdns_hook(c->hook, c->current_file, c->hook_timeout)) {
        s->retry_hook = 1;
        return fail(err, cap, "hook failed or timed out; pending address will be retried");
    }
    s->applied = address;
    s->has_applied = 1;
    s->retry_hook = 0;
    s->cache_dirty = 1;
    if (save_state(c, key, s))
        return fail(err, cap, "hook succeeded but cache write failed; will retry cache write");
    s->cache_dirty = 0;
    cdns_log("INFO", "client hook applied successfully");
    return 0;
}

int cdns_client_run(const cdns_config *c, const unsigned char key[32], int once) {
    cdns_client_state state;
    char lock_path[CDNS_PATH_MAX + 8], txt[256], err[CDNS_ERROR_MAX];
    int result = 0, n;
    if (!c || !key)
        return -1;
    n = snprintf(lock_path, sizeof lock_path, "%s.lock", c->state_file);
    if (n < 0 || (size_t)n >= sizeof lock_path || cdns_lock(lock_path)) {
        cdns_log("ERROR", "cannot acquire client state lock");
        return -1;
    }
    if (!cdns_client_load(c, key, &state))
        cdns_log("INFO", "restored applied client state");
    do {
        int lookup = cdns_dns_lookup(c->domain, c->dns_timeout, txt);
        result = cdns_client_step(c, key, &state, lookup ? NULL : txt, err, sizeof err);
        if (result)
            cdns_log("WARN", "%s", err);
        if (!once)
            cdns_sleep_ms(c->poll_interval * 1000);
    } while (!once && !cdns_stopping());
    cdns_unlock();
    return once ? result : 0;
}
