#include "cipherdns/core.h"
#include "ini.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <limits.h>
typedef struct {
    const char *section, *key;
    size_t offset, size;
    unsigned min, max;
    int kind;
} field;
#define S(s, k, f) {s, k, offsetof(cdns_config, f), sizeof(((cdns_config *)0)->f), 0, 0, 0}
#define N(s, k, f, lo, hi) {s, k, offsetof(cdns_config, f), 0, lo, hi, 1}
#define B(s, k, f) {s, k, offsetof(cdns_config, f), 0, 0, 1, 2}
static const field fields[] = {S("common", "mode", mode),
                               S("common", "domain", domain),
                               S("common", "key_file", key_file),
                               S("server", "ip_family", ip_family),
                               S("server", "ip_source", ip_source),
                               S("server", "interface", interface_name),
                               S("server", "command", command),
                               S("server", "ipv6_strategy", ipv6_strategy),
                               B("server", "allow_ula", allow_ula),
                               B("server", "allow_private_ipv4", allow_private_ipv4),
                               N("server", "check_interval", check_interval, 1, 86400),
                               N("server", "command_timeout", command_timeout, 1, 300),
                               N("server", "port", port, 1, 65535),
                               S("dns", "provider", provider),
                               S("dns", "credentials_file", credentials_file),
                               S("dns", "ca_file", ca_file),
                               S("dns", "zone", zone),
                               S("dns", "rr", rr),
                               N("dns", "ttl", ttl, 1, 86400),
                               N("dns", "connect_timeout", connect_timeout, 1, 300),
                               N("dns", "read_timeout", read_timeout, 1, 300),
                               N("dns", "update_timeout", update_timeout, 1, 900),
                               N("dns", "retries", retries, 0, 5),
                               N("client", "poll_interval", poll_interval, 1, 86400),
                               N("client", "dns_timeout", dns_timeout, 1, 60),
                               N("client", "check_port", check_port, 1, 65535),
                               N("client", "check_timeout", check_timeout, 1, 60),
                               N("client", "hook_timeout", hook_timeout, 1, 3600),
                               N("client", "hook_min_interval", hook_min_interval, 0, 86400),
                               S("client", "prefer_family", prefer_family),
                               S("client", "hook", hook),
                               S("client", "state_file", state_file),
                               S("client", "current_file", current_file),
                               B("client", "check_connectivity", check_connectivity),
                               B("client", "hook_on_recovery", hook_on_recovery)};
#ifdef CDNS_SERVER
static const field credentials[] = {S("", "token", token),
                                    S("", "zone_id", zone_id),
                                    S("", "access_key_id", access_key_id),
                                    S("", "access_key_secret", access_key_secret),
                                    S("", "secret_id", secret_id),
                                    S("", "secret_key", secret_key)};
#endif
typedef struct {
    cdns_config *c;
    const field *f;
    size_t count;
    uint64_t seen;
} parse_ctx;
static int handler(void *user, const char *section, const char *name, const char *value) {
    parse_ctx *p = user;
    for (size_t i = 0; i < p->count; i++)
        if (!strcmp(section, p->f[i].section) && !strcmp(name, p->f[i].key)) {
            if (p->seen & (UINT64_C(1) << i))
                return 0;
            p->seen |= UINT64_C(1) << i;
            for (const unsigned char *s = (const unsigned char *)value; *s; s++)
                if (*s < 32 || *s == 127)
                    return 0;
            char *dest = (char *)p->c + p->f[i].offset;
            if (p->f[i].kind == 0) {
                size_t n = strlen(value);
                if (!n || n >= p->f[i].size)
                    return 0;
                memcpy(dest, value, n + 1);
            } else if (p->f[i].kind == 2) {
                int b;
                if (!strcmp(value, "true"))
                    b = 1;
                else if (!strcmp(value, "false"))
                    b = 0;
                else
                    return 0;
                memcpy(dest, &b, sizeof(b));
            } else {
                if (!*value)
                    return 0;
                unsigned long n = 0;
                for (const char *s = value; *s; s++) {
                    if (*s < '0' || *s > '9' || n > (UINT_MAX - (unsigned)(*s - '0')) / 10)
                        return 0;
                    n = n * 10 + (unsigned)(*s - '0');
                }
                if (n < p->f[i].min || n > p->f[i].max)
                    return 0;
                unsigned v = (unsigned)n;
                memcpy(dest, &v, sizeof(v));
            }
            return 1;
        }
    return 0;
}
static int absolute(const char *s) {
#ifdef _WIN32
    return (isalpha((unsigned char)s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) ||
           (s[0] == '\\' && s[1] == '\\');
#else
    return s[0] == '/';
#endif
}
static int domain(char *s, int rr) {
    size_t n = strlen(s);
    if (n && s[n - 1] == '.')
        s[--n] = 0;
    if (!n || n > 253)
        return -1;
    if (rr && !strcmp(s, "@"))
        return 0;
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (!label || label > 63 || s[i - 1] == '-')
                return -1;
            label = 0;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-') ||
            (!label && c == '-'))
            return -1;
        s[i] = (char)tolower(c);
        label++;
    }
    return label && label <= 63 && s[n - 1] != '-' ? 0 : -1;
}
static int fail(char *err, size_t cap, const char *s) {
    snprintf(err, cap, "%s", s);
    return -1;
}
int cdns_config_parse(const char *path, cdns_config *c, char *err, size_t cap) {
    memset(c, 0, sizeof(*c));
    strcpy(c->ip_family, "both");
    strcpy(c->ip_source, "auto");
    strcpy(c->ipv6_strategy, "lowest");
    strcpy(c->prefer_family, "ipv6");
    c->check_interval = 30;
    c->command_timeout = 5;
    c->port = 7000;
    c->ttl = 60;
    c->connect_timeout = 10;
    c->read_timeout = 10;
    c->update_timeout = 30;
    c->retries = 2;
    c->poll_interval = 60;
    c->dns_timeout = 5;
    c->check_port = 7000;
    c->check_timeout = 3;
    c->hook_timeout = 30;
    c->hook_min_interval = 10;
#ifdef _WIN32
    strcpy(c->state_file, "C:\\ProgramData\\CipherDNS\\applied.json");
    strcpy(c->current_file, "C:\\ProgramData\\CipherDNS\\current.json");
#else
    strcpy(c->state_file, "/var/lib/cipherdns/applied.json");
    strcpy(c->current_file, "/run/cipherdns/current.json");
#endif
    parse_ctx ctx = {c, fields, sizeof(fields) / sizeof(fields[0]), 0};
    int rc = ini_parse(path, handler, &ctx);
    if (rc) {
        if (rc > 0)
            snprintf(err, cap, "invalid, unknown or duplicate configuration key at line %d", rc);
        else
            snprintf(err, cap, "cannot read configuration file");
        return -1;
    }
    if (strcmp(c->mode, "server") && strcmp(c->mode, "client"))
        return fail(err, cap, "common.mode must be server or client");
    if (domain(c->domain, 0) || !absolute(c->key_file))
        return fail(err, cap, "valid domain and absolute key_file required");
    if (!strcmp(c->mode, "server")) {
#ifndef CDNS_SERVER
        return fail(err, cap, "server mode is excluded from this build");
#else
        if (strcmp(c->ip_family, "ipv4") && strcmp(c->ip_family, "ipv6") &&
            strcmp(c->ip_family, "both"))
            return fail(err, cap, "invalid server.ip_family");
        if (strcmp(c->ip_source, "auto") && strcmp(c->ip_source, "interface") &&
            strcmp(c->ip_source, "command"))
            return fail(err, cap, "invalid server.ip_source");
        if (!strcmp(c->ip_source, "interface") && !c->interface_name[0])
            return fail(err, cap, "server.interface required");
        if (!strcmp(c->ip_source, "command") && !c->command[0])
            return fail(err, cap, "server.command required");
        if (strcmp(c->ipv6_strategy, "lowest") && strcmp(c->ipv6_strategy, "highest"))
            return fail(err, cap, "ipv6_strategy must be lowest or highest");
        if (strcmp(c->provider, "cloudflare") && strcmp(c->provider, "aliyun") &&
            strcmp(c->provider, "dnspod"))
            return fail(err, cap, "dns.provider must be cloudflare, aliyun or dnspod");
        if (!absolute(c->credentials_file))
            return fail(err, cap, "credentials_file must be absolute");
        if (c->ca_file[0] && !absolute(c->ca_file))
            return fail(err, cap, "ca_file must be absolute");
        if (!strcmp(c->provider, "cloudflare")) {
            if (c->ttl != 1 && c->ttl < 60)
                return fail(err, cap, "Cloudflare ttl must be 1 or at least 60");
        } else {
            if (domain(c->zone, 0))
                return fail(err, cap, "dns.zone required for aliyun/dnspod");
            if (!c->rr[0]) {
                size_t d = strlen(c->domain), z = strlen(c->zone);
                if (!strcmp(c->domain, c->zone))
                    strcpy(c->rr, "@");
                else if (d > z + 1 && c->domain[d - z - 1] == '.' &&
                         !strcmp(c->domain + d - z, c->zone)) {
                    memcpy(c->rr, c->domain, d - z - 1);
                    c->rr[d - z - 1] = 0;
                } else
                    return fail(err, cap, "domain must belong to dns.zone");
            }
            if (domain(c->rr, 1))
                return fail(err, cap, "invalid dns.rr");
            char fqdn[512];
            if (!strcmp(c->rr, "@"))
                snprintf(fqdn, sizeof(fqdn), "%s", c->zone);
            else
                snprintf(fqdn, sizeof(fqdn), "%s.%s", c->rr, c->zone);
            if (strcmp(fqdn, c->domain))
                return fail(err, cap, "dns.rr + zone must equal common.domain");
        }
#endif
    } else {
#ifndef CDNS_CLIENT
        return fail(err, cap, "client mode is excluded from this build");
#else
        if (strcmp(c->prefer_family, "ipv4") && strcmp(c->prefer_family, "ipv6"))
            return fail(err, cap, "client.prefer_family must be ipv4 or ipv6");
        if (!absolute(c->hook) || !absolute(c->state_file) || !absolute(c->current_file) ||
            !strcmp(c->state_file, c->current_file))
            return fail(err, cap,
                        "absolute hook/state_file/current_file paths required; state and current "
                        "must differ");
#endif
    }
    return 0;
}
#ifdef CDNS_SERVER
int cdns_credentials_load(cdns_config *c, char *err, size_t cap) {
    if (cdns_private_file(c->credentials_file))
        return fail(err, cap, "credentials_file must be private and owned by the running user");
    parse_ctx ctx = {c, credentials, sizeof(credentials) / sizeof(credentials[0]), 0};
    if (ini_parse(c->credentials_file, handler, &ctx))
        return fail(err, cap, "invalid credentials file (unknown/duplicate key or invalid value)");
    if (!strcmp(c->provider, "cloudflare")) {
        if (!c->token[0] || !c->zone_id[0])
            return fail(err, cap, "Cloudflare token and zone_id required");
        for (const char *p = c->zone_id; *p; p++)
            if (!isalnum((unsigned char)*p))
                return fail(err, cap, "invalid Cloudflare zone_id");
    } else if (!strcmp(c->provider, "aliyun")) {
        if (!c->access_key_id[0] || !c->access_key_secret[0])
            return fail(err, cap, "Alibaba access_key_id/access_key_secret required");
    } else if (!strcmp(c->provider, "dnspod")) {
        if (!c->secret_id[0] || !c->secret_key[0])
            return fail(err, cap, "DNSPod secret_id/secret_key required");
    } else
        return fail(err, cap, "unknown provider");
    return 0;
}
#endif
int cdns_config_load(const char *path, cdns_config *c, char *err, size_t cap) {
    if (cdns_config_parse(path, c, err, cap))
        return -1;
#ifdef CDNS_SERVER
    if (!strcmp(c->mode, "server") && cdns_credentials_load(c, err, cap))
        return -1;
#endif
    unsigned char key[32];
    if (cdns_key_load(c->key_file, key))
        return fail(err, cap,
                    "key_file must contain exactly 32 binary bytes and be private to its owner");
    cdns_zero(key, 32);
    return 0;
}
