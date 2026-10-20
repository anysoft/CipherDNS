#include "cipherdns/doctor.h"
#include "cipherdns/json.h"
#ifdef CDNS_SERVER
#include "cipherdns/http.h"
#include "cipherdns/provider.h"
#endif
#ifdef CDNS_CLIENT
#include "cipherdns/dns.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif
static unsigned char aes_key[32];
static unsigned probe_calls, read_calls, lookup_calls;
static int tls_failure, lookup_failure, wrong_cipher;
#ifdef CDNS_SERVER
int cdns_http_probe(const cdns_config *c, const char *host, cdns_http_probe_result *r, char *err,
                    size_t cap) {
    (void)c;
    assert(!strcmp(host, "api.cloudflare.com"));
    probe_calls++;
    memset(r, 0, sizeof(*r));
    r->resolved = 1;
    r->connected = 1;
    r->ca_loaded = !tls_failure;
    if (tls_failure) {
        snprintf(err, cap, "no CA");
        return -1;
    }
    r->tls_ready = 1;
    r->certificate_checked = 1;
    return 0;
}
int cdns_ip_detect(const cdns_config *c, cdns_address *a) {
    (void)c;
    *a = (cdns_address){"203.0.113.10", "2001:db8::10", 7000};
    return 0;
}
cdns_provider_result cdns_provider_read(const cdns_config *c, cdns_provider_record *r, char *err,
                                        size_t cap) {
    (void)c;
    (void)err;
    (void)cap;
    read_calls++;
    memset(r, 0, sizeof(*r));
    r->exists = 1;
    return CDNS_PROVIDER_OK;
}
#endif
#ifdef CDNS_CLIENT
int cdns_dns_lookup(const char *domain, unsigned timeout, char out[256]) {
    (void)timeout;
    assert(!strcmp(domain, "home.example.com"));
    lookup_calls++;
    if (lookup_failure)
        return -1;
    if (wrong_cipher) {
        strcpy(out, "CD1:invalid!");
        return 0;
    }
    cdns_address a = {"203.0.113.10", "2001:db8::10", 7000};
    return cdns_encrypt(aes_key, &a, out);
}
#endif
static int run(const char *path, int json, int read, char out[16384]) {
    FILE *f = tmpfile();
    assert(f);
    int rc = cdns_doctor_run(path, json, read, f);
    assert(fflush(f) == 0);
    rewind(f);
    size_t n = fread(out, 1, 16383, f);
    assert(!ferror(f));
    out[n] = 0;
    fclose(f);
    assert(!strstr(out, "do-not-log-this-token"));
    return rc;
}
int main(void) {
    char base[1024], path[1100], keypath[1100], credpath[1100], hook[1100], cache[1100],
        current[1100], config[8192], out[16384];
#ifdef _WIN32
    char tmp[1024], temp[1024];
    assert(GetTempPathA(sizeof(tmp), tmp));
    assert(GetTempFileNameA(tmp, "cdd", 0, temp));
    assert(DeleteFileA(temp));
    assert(CreateDirectoryA(temp, NULL));
    strcpy(base, temp);
#else
    strcpy(base, "/tmp/cipherdns-doctor-XXXXXX");
    assert(mkdtemp(base));
#endif
    assert(cdns_platform_init() == 0);
    snprintf(path, sizeof(path), "%s/test.ini", base);
    snprintf(keypath, sizeof(keypath), "%s/aes.key", base);
    snprintf(credpath, sizeof(credpath), "%s/credentials.ini", base);
    snprintf(hook, sizeof(hook), "%s/hook.sh", base);
    snprintf(cache, sizeof(cache), "%s/cache", base);
    snprintf(current, sizeof(current), "%s/current.json", base);
    assert(cdns_keygen(keypath) == 0 && cdns_key_load(keypath, aes_key) == 0);
    assert(cdns_atomic_write(hook, "#!/bin/sh\nexit 123\n", 19) == 0);
#ifndef _WIN32
    assert(chmod(hook, 0700) == 0);
#endif
    assert(run(path, 1, 0, out) == 1);
    cdns_json j;
    assert(cdns_json_parse(&j, out) == 0);
#ifdef CDNS_CLIENT
    snprintf(config, sizeof(config),
             "[common]\nmode=client\ndomain=home.example.com\nkey_file=%s\n[client]\nhook=%"
             "s\nstate_file=%s\ncurrent_file=%s\n",
             keypath, hook, cache, current);
    assert(cdns_atomic_write(path, config, strlen(config)) == 0);
    assert(run(path, 1, 0, out) == 0 && lookup_calls == 1);
    assert(cdns_json_parse(&j, out) == 0);
    assert(strstr(out, "\"name\":\"AES-GCM\",\"status\":\"PASS\""));
    assert(strstr(out, "\"name\":\"Hook Path\",\"status\":\"PASS\""));
    /* The configured Hook exits 123: doctor succeeding proves it never executes it. */
    FILE *f = fopen(cache, "rb");
    assert(!f);
    f = fopen(current, "rb");
    assert(!f);
    wrong_cipher = 1;
    assert(run(path, 1, 0, out) == 1);
    assert(strstr(out, "invalid canonical Base64"));
    wrong_cipher = 0;
    lookup_failure = 1;
    assert(run(path, 0, 0, out) == 1);
    assert(strstr(out, "[FAIL] DNS Resolver / TXT"));
    lookup_failure = 0;
    assert(cdns_atomic_write(keypath, "short", 5) == 0);
    assert(run(path, 1, 0, out) == 1);
    assert(strstr(out, "\"name\":\"Config\",\"status\":\"PASS\""));
    assert(strstr(out, "\"name\":\"AES Key\",\"status\":\"FAIL\""));
    remove(keypath);
    assert(cdns_keygen(keypath) == 0 && cdns_key_load(keypath, aes_key) == 0);
#endif
#ifdef CDNS_SERVER
    const char *secret = "token=do-not-log-this-token\nzone_id=abcdef123\n";
    assert(cdns_atomic_write(credpath, secret, strlen(secret)) == 0);
    snprintf(config, sizeof(config),
             "[common]\nmode=server\ndomain=home.example.com\nkey_file=%s\n[server]\nip_source="
             "command\ncommand=exit 123\n[dns]\nprovider=cloudflare\ncredentials_file=%s\n",
             keypath, credpath);
    assert(cdns_atomic_write(path, config, strlen(config)) == 0);
    assert(run(path, 1, 0, out) == 0 && probe_calls == 1 && read_calls == 0);
    assert(strstr(out, "\"name\":\"IP Detection\",\"status\":\"SKIP\""));
    assert(run(path, 0, 1, out) == 0 && read_calls == 1);
    assert(strstr(out, "[OK] Provider Authentication"));
    tls_failure = 1;
    assert(run(path, 1, 1, out) == 1 && read_calls == 1);
    tls_failure = 0;
    remove(credpath);
#endif
    (void)tls_failure;
    (void)lookup_failure;
    (void)wrong_cipher;
    (void)probe_calls;
    (void)read_calls;
    (void)lookup_calls;
    remove(path);
    remove(keypath);
    remove(hook);
#ifdef _WIN32
    assert(RemoveDirectoryA(base));
#else
    assert(rmdir(base) == 0);
#endif
    cdns_zero(aes_key, sizeof(aes_key));
    cdns_platform_cleanup();
    puts("doctor read-only, JSON, diagnostics and redaction tests passed");
    return 0;
}
