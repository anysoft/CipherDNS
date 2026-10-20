#include "cipherdns/doctor.h"
#ifdef CDNS_SERVER
#include "cipherdns/http.h"
#include "cipherdns/provider.h"
#include "mbedtls/x509.h"
#endif
#ifdef CDNS_CLIENT
#include "cipherdns/dns.h"
#endif
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
typedef enum { PASS, WARN, FAIL, SKIP } status;
typedef struct {
    const char *name;
    status state;
    char detail[192];
} check;
typedef struct {
    check checks[24];
    size_t count;
    unsigned failures;
    const char *mode;
} report;
static void add(report *r, const char *name, status state, const char *detail) {
    if (r->count >= sizeof(r->checks) / sizeof(r->checks[0]))
        return;
    check *c = &r->checks[r->count++];
    c->name = name;
    c->state = state;
    snprintf(c->detail, sizeof(c->detail), "%s", detail);
    if (state == FAIL)
        r->failures++;
}
static void quoted(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', f);
            fputc(*p, f);
        } else if (*p < 32 || *p >= 127)
            fprintf(f, "\\u%04x", (unsigned)*p);
        else
            fputc(*p, f);
    }
    fputc('"', f);
}
static const char *os(void) {
#ifdef _WIN32
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "POSIX";
#endif
}
static const char *cpu(void) {
#if defined(__aarch64__) || defined(_M_ARM64)
    return "ARM64";
#elif defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__arm__) || defined(_M_ARM)
    return "ARM";
#elif defined(__mips__)
    return "MIPS";
#else
    return "unknown";
#endif
}
static const char *compiler(void) {
#ifdef __clang_version__
    return "Clang " __clang_version__;
#elif defined(__VERSION__)
    return "GCC " __VERSION__;
#elif defined(_MSC_VER)
    return "MSVC";
#else
    return "C11 compiler";
#endif
}
static int finish(report *r, int json, FILE *out) {
    static const char *states[] = {"PASS", "WARN", "FAIL", "SKIP"};
    if (json) {
        fputs("{\"version\":", out);
        quoted(out, CDNS_VERSION);
        fputs(",\"os\":", out);
        quoted(out, os());
        fputs(",\"cpu\":", out);
        quoted(out, cpu());
        fputs(",\"compiler\":", out);
        quoted(out, compiler());
        fputs(",\"mode\":", out);
        quoted(out, r->mode);
        fputs(",\"checks\":[", out);
        for (size_t i = 0; i < r->count; i++) {
            check *c = &r->checks[i];
            if (i)
                fputc(',', out);
            fputs("{\"name\":", out);
            quoted(out, c->name);
            fputs(",\"status\":", out);
            quoted(out, states[c->state]);
            fputs(",\"message\":", out);
            quoted(out, c->detail);
            fputc('}', out);
        }
        fprintf(out, "],\"failures\":%u}\n", r->failures);
    } else {
        fprintf(out, "CipherDNS Doctor %s\n%s / %s / %s\nMode: %s\n\n", CDNS_VERSION, os(), cpu(),
                compiler(), r->mode);
        for (size_t i = 0; i < r->count; i++) {
            check *c = &r->checks[i];
            fprintf(out, "[%s] %s: %s\n", c->state == PASS ? "OK" : states[c->state], c->name,
                    c->detail);
        }
    }
    return r->failures ? 1 : 0;
}
#ifdef CDNS_CLIENT
static int writable_parent(const char *path) {
    char temporary[CDNS_PATH_MAX + 64];
    size_t end = 0;
    for (size_t i = 0; path[i]; i++)
        if (path[i] == '/'
#ifdef _WIN32
            || path[i] == '\\'
#endif
        )
            end = i + 1;
    if (!end || end >= CDNS_PATH_MAX)
        return -1;
    memcpy(temporary, path, end);
    unsigned char nonce[8];
    if (cdns_random(nonce, sizeof(nonce)))
        return -1;
    snprintf(temporary + end, sizeof(temporary) - end,
             ".cipherdns-doctor-%02x%02x%02x%02x%02x%02x%02x%02x", nonce[0], nonce[1], nonce[2],
             nonce[3], nonce[4], nonce[5], nonce[6], nonce[7]);
    static const char data[] = "CipherDNS diagnostic write probe\n";
    if (cdns_private_create(temporary, data, sizeof(data) - 1))
        return -1;
    return remove(temporary) == 0 ? 0 : -1;
}
static int hook_available(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        return -1;
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fclose(f);
    return 0;
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0 ? 0 : -1;
#endif
}
static void client_checks(report *r, const cdns_config *c, const unsigned char key[32],
                          int key_ok) {
    add(r, "State Directory", writable_parent(c->state_file) ? FAIL : PASS,
        "private create/remove probe in cache directory");
    add(r, "Current JSON Directory", writable_parent(c->current_file) ? FAIL : PASS,
        "private create/remove probe in hook input directory");
    add(r, "Hook Path", hook_available(c->hook) ? FAIL : PASS,
        "check existence and executable access; Hook is never run");
    char txt[256];
    if (cdns_dns_lookup(c->domain, c->dns_timeout, txt)) {
        add(r, "DNS Resolver / TXT", FAIL,
            "bounded TXT query failed, or no unique CD1 record; check resolver and DNS records");
        add(r, "AES-GCM", SKIP, "no usable TXT record");
        return;
    }
    add(r, "DNS Resolver / TXT", PASS, "system resolver returned exactly one CD1 TXT payload");
    unsigned char binary[52];
    size_t n = 0;
    if (strncmp(txt, "CD1:", 4) || cdns_base64_decode(txt + 4, binary, sizeof(binary), &n) ||
        n != sizeof(binary)) {
        add(r, "Base64", FAIL, "invalid canonical Base64 or version-1 envelope length");
        return;
    }
    add(r, "Base64", PASS, "canonical version-1 envelope length");
    cdns_address address;
    if (!key_ok) {
        add(r, "AES-GCM", SKIP, "local AES Key unavailable");
        return;
    }
    if (cdns_decrypt(key, txt, &address)) {
        add(r, "AES-GCM", FAIL, "authentication or address validation failed; no Hook executed");
        return;
    }
    add(r, "AES-GCM", PASS, "authenticated and address-validated; no Hook executed");
    char addresses[128];
    snprintf(addresses, sizeof(addresses), "IPv4=%s IPv6=%s port=%u", address.ipv4, address.ipv6,
             address.port);
    add(r, "Addresses", PASS, addresses);
    if (!c->check_connectivity) {
        add(r, "TCP Probe", SKIP, "enable client.check_connectivity to probe service port");
        return;
    }
    const char *first = !strcmp(c->prefer_family, "ipv4") ? address.ipv4 : address.ipv6;
    const char *second = !strcmp(c->prefer_family, "ipv4") ? address.ipv6 : address.ipv4;
    unsigned port = c->check_port ? c->check_port : address.port;
    int ok = (*first && !cdns_tcp_probe(first, port, c->check_timeout)) ||
             (*second && !cdns_tcp_probe(second, port, c->check_timeout));
    add(r, "TCP Probe", ok ? PASS : WARN,
        ok ? "service port reachable"
           : "service port unreachable; valid address remains available");
}
#endif
#ifdef CDNS_SERVER
static void server_checks(report *r, cdns_config *c, int provider_read) {
    char err[256];
    int credentials_ok = cdns_credentials_load(c, err, sizeof(err)) == 0;
    add(r, "Provider Credentials", credentials_ok ? PASS : FAIL,
        credentials_ok ? "private file, required credential fields validated" : err);
    if (!strcmp(c->ip_source, "command"))
        add(r, "IP Detection", SKIP, "configured local command is not run by read-only doctor");
    else {
        cdns_address address;
        if (cdns_ip_detect(c, &address))
            add(r, "IP Detection", WARN,
                "no eligible address; check selected interface, global scope and address policy");
        else {
            char message[160];
            snprintf(message, sizeof(message), "IPv4=%s IPv6=%s", address.ipv4, address.ipv6);
            add(r, "IP Detection", PASS, message);
        }
    }
    char source[160];
    if (c->interface_name[0])
        snprintf(source, sizeof(source), "interface=%.120s", c->interface_name);
    else
        snprintf(source, sizeof(source), "%s", c->ip_source);
    add(r, "IP Source", PASS, source);
    add(r, "State Directory", SKIP,
        "Server keeps its last successful state in memory; no cache directory is required");
    if (c->ca_file[0]) {
        FILE *ca = fopen(c->ca_file, "rb");
        add(r, "CA File Access", ca ? PASS : FAIL,
            ca ? "explicit CA file readable" : "explicit CA file unreadable");
        if (ca)
            fclose(ca);
    }
    const char *host = !strcmp(c->provider, "cloudflare") ? "api.cloudflare.com"
                       : !strcmp(c->provider, "aliyun")   ? "alidns.aliyuncs.com"
                                                          : "dnspod.tencentcloudapi.com";
    cdns_http_probe_result probe;
    int result = cdns_http_probe(c, host, &probe, err, sizeof(err));
    add(r, "DNS Resolver", probe.resolved ? PASS : FAIL,
        probe.resolved ? "provider hostname resolved"
                       : "provider name resolution failed or timed out");
    add(r, "TCP 443",
        probe.connected  ? PASS
        : probe.resolved ? FAIL
                         : SKIP,
        probe.connected ? "provider connection established" : "provider connection unavailable");
    add(r, "CA Bundle",
        probe.ca_loaded   ? PASS
        : probe.connected ? FAIL
                          : SKIP,
        probe.ca_loaded ? "trusted roots loaded"
                        : "unable to load CA or network precondition failed");
    if (!result) {
        add(r, "HTTPS TLS", PASS, "TLS 1.2 handshake with SNI completed");
        add(r, "Certificate Chain", PASS, "trusted chain verified");
        add(r, "Certificate Hostname", PASS, "hostname verified");
    } else {
        add(r, "HTTPS TLS", probe.connected && probe.ca_loaded ? FAIL : SKIP,
            "handshake not completed; check clock, CA, connectivity and TLS support");
        add(r, "Certificate Chain",
            probe.certificate_checked && (probe.verify_flags & ~MBEDTLS_X509_BADCERT_CN_MISMATCH)
                ? FAIL
                : SKIP,
            "certificate verification did not complete successfully");
        add(r, "Certificate Hostname",
            probe.certificate_checked && (probe.verify_flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
                ? FAIL
                : SKIP,
            "hostname verification did not complete successfully");
    }
    if (!provider_read)
        add(r, "Provider Authentication", SKIP,
            "use --provider-read for an authenticated read-only API request");
    else if (!credentials_ok || result)
        add(r, "Provider Authentication", SKIP, "local credentials or verified TLS unavailable");
    else {
        cdns_provider_record record;
        cdns_provider_result rc = cdns_provider_read(c, &record, err, sizeof(err));
        add(r, "Provider Authentication", rc == CDNS_PROVIDER_OK ? PASS : FAIL,
            rc == CDNS_PROVIDER_OK ? "read-only API discovery accepted" : err);
        if (rc == CDNS_PROVIDER_OK)
            add(r, "Provider TXT", record.exists ? PASS : WARN,
                record.exists ? "unique TXT record exists"
                              : "no TXT record; doctor will not create it");
    }
}
#endif
int cdns_doctor_run(const char *path, int json, int provider_read, FILE *output) {
    report r = {0};
    r.mode = "unknown";
    cdns_config c;
    char err[256];
    if (cdns_config_parse(path, &c, err, sizeof(err))) {
        add(&r, "Config", FAIL, err);
        cdns_zero(&c, sizeof(c));
        return finish(&r, json, output);
    }
    r.mode = !strcmp(c.mode, "server") ? "server" : "client";
    add(&r, "Config", PASS, "configuration exists and schema is valid");
    unsigned char key[32] = {0};
    int key_ok = cdns_key_load(c.key_file, key) == 0;
    add(&r, "AES Key", key_ok ? PASS : FAIL,
        key_ok ? "private 32-byte key readable"
               : "key unreadable, wrong length, ownership or permissions");
    time_t now = time(NULL);
    add(&r, "System Time",
        now >= (time_t)1704067200 && (uint64_t)now < UINT64_C(4133980800) ? PASS : WARN,
        "TLS and signed APIs require accurate UTC; verify RTC/NTP");
#ifdef CDNS_SERVER
    if (!strcmp(c.mode, "server"))
        server_checks(&r, &c, provider_read);
#else
    (void)provider_read;
#endif
#ifdef CDNS_CLIENT
    if (!strcmp(c.mode, "client"))
        client_checks(&r, &c, key, key_ok);
#endif
    add(&r, "DNS TTL / Cache", WARN,
        "provider acceptance and recursive DNS visibility are independent; cached records may be "
        "older");
    cdns_zero(key, sizeof(key));
    cdns_zero(&c, sizeof(c));
    return finish(&r, json, output);
}
