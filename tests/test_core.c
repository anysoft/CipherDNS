#include "cipherdns/core.h"
#include "cipherdns/json.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#define test_pid GetCurrentProcessId()
#else
#include <unistd.h>
#include <sys/stat.h>
#define test_pid ((unsigned)getpid())
#endif
static void crypto_tests(void) {
    unsigned char key[32] = {0}, wrong[32] = {1};
    char a[256], b[256];
    cdns_address in = {"203.0.113.10", "2001:db8::100", 7000}, out = {0}, unchanged;
    /* Captured from the unchanged v0.1.0 library with a zero test key. */
    const char *v01 =
        "CD1:kvhv0aJOQy6fCgcB9wddfiuLZPXp3Ygters45KBHZVyXzgaXQv0a79s2hd5I/+te9QiuTg==";
    assert(cdns_decrypt(key, v01, &out) == 0 && cdns_address_equal(&in, &out));
    assert(cdns_encrypt(key, &in, a) == 0);
    assert(strlen(a) == 76);
    assert(cdns_decrypt(key, a, &out) == 0);
    assert(cdns_address_equal(&in, &out));
    assert(cdns_encrypt(key, &in, b) == 0);
    assert(strcmp(a, b) != 0);
    unchanged = out;
    assert(cdns_decrypt(wrong, a, &out) != 0);
    assert(cdns_address_equal(&out, &unchanged));
    a[22] = a[22] == 'A' ? 'B' : 'A';
    assert(cdns_decrypt(key, a, &out) != 0);
    assert(cdns_decrypt(key, "CD1:!!!!", &out) != 0);
    for (unsigned i = 0; i < 128; i++) {
        assert(cdns_random(key, 32) == 0);
        assert(cdns_encrypt(key, &in, a) == 0);
        assert(cdns_decrypt(key, a, &out) == 0);
        assert(cdns_address_equal(&in, &out));
    }
    in.ipv4[0] = 0;
    assert(cdns_encrypt(key, &in, a) == 0);
    assert(cdns_decrypt(key, a, &out) == 0);
    assert(!out.ipv4[0]);
    in.ipv6[0] = 0;
    assert(cdns_encrypt(key, &in, a) != 0);
}
static void data_tests(void) {
    char out[100];
    unsigned char raw[100];
    size_t n;
    assert(cdns_base64_encode((const unsigned char *)"hello", 5, out, sizeof(out)) == 0);
    assert(!strcmp(out, "aGVsbG8="));
    assert(cdns_base64_decode(out, raw, sizeof(raw), &n) == 0 && n == 5 &&
           !memcmp(raw, "hello", 5));
    assert(cdns_base64_decode("aGVs bG8=", raw, sizeof(raw), &n) != 0);
    assert(cdns_base64_decode("Zh==", raw, sizeof(raw), &n) != 0); /* noncanonical padding bits */
    assert(cdns_base64_decode("aGVsbG8", raw, sizeof(raw), &n) != 0);
    cdns_address a, b = {"203.0.113.2", "2001:db8::1", 1};
    assert(cdns_address_parse(
               "{\"v\":1,\"ipv4\":\"203.0.113.2\",\"ipv6\":\"2001:0DB8:0:0::1\",\"port\":1}", &a) ==
           0);
    assert(cdns_address_equal(&a, &b));
    assert(cdns_address_json(&a, out, sizeof(out)) == 0);
    assert(cdns_address_parse(out, &a) == 0);
    assert(cdns_address_parse("{\"ipv4\":\"127.0.0.1\",\"ipv6\":\"\",\"port\":1}", &a) != 0);
    assert(cdns_address_parse("{\"ipv4\":\"\",\"ipv6\":\"fe80::1\",\"port\":1}", &a) != 0);
    assert(cdns_address_parse("{\"ipv4\":\"1.2.3.4\",\"ipv6\":\"\",\"port\":65536}", &a) != 0);
    cdns_address seen = {"203.0.113.4", "", 1};
    cdns_address_merge(&a, &seen, &b);
    assert(!strcmp(a.ipv6, b.ipv6));
    assert(!strcmp(a.ipv4, seen.ipv4));
    cdns_json j;
    assert(cdns_json_parse(&j, "{\"a\":1 \"b\":2}") != 0);
    assert(cdns_json_parse(&j, "{} {}") != 0);
    assert(cdns_json_parse(&j, "{\"a\": [1,{\"b\":2}],\"c\":true}") == 0);
    assert(cdns_json_eq(&j, cdns_json_get(&j, 0, "c"), "true"));
    assert(cdns_json_parse(&j, "[1,]") != 0);
    assert(cdns_json_parse(&j, "{\"a\":01}") != 0);
    assert(cdns_json_parse(&j, "{\"a\":1,\"a\":2}") != 0);
    assert(cdns_json_parse(&j, "{\"a\":1,\"\\u0061\":2}") != 0);
    const char *seed = "{\"a\":[{\"escaped\":\"\\u0061\\\\\\\"\"},1.2e-3,true,null]}";
    char truncated[128];
    for (size_t i = 0; i < strlen(seed); i++) {
        memcpy(truncated, seed, i);
        truncated[i] = 0;
        assert(cdns_json_parse(&j, truncated) != 0);
    }
}
static void file_config_tests(void) {
    char keyfile[1024], configfile[1024], credsfile[1032], err[256], config[4096];
#ifdef _WIN32
    char base[900];
    assert(GetTempPathA(sizeof(base), base));
    snprintf(keyfile, sizeof(keyfile), "%scipherdns-core-%u.key", base, (unsigned)test_pid);
    snprintf(configfile, sizeof(configfile), "%scipherdns-core-%u.ini", base, (unsigned)test_pid);
#else
    snprintf(keyfile, sizeof(keyfile), "/tmp/cipherdns-core-%u.key", test_pid);
    snprintf(configfile, sizeof(configfile), "/tmp/cipherdns-core-%u.ini", test_pid);
#endif
    assert(cdns_keygen(keyfile) == 0);
    assert(cdns_keygen(keyfile) != 0);
    unsigned char key[32];
    assert(cdns_key_load(keyfile, key) == 0);
#ifndef _WIN32
    assert(chmod(keyfile, 0644) == 0);
    assert(cdns_key_load(keyfile, key) != 0);
    assert(chmod(keyfile, 0600) == 0);
#endif
    assert(cdns_atomic_write(configfile, "first", 5) == 0);
    assert(cdns_atomic_write(configfile, "next", 4) == 0);
    FILE *f = fopen(configfile, "rb");
    assert(f);
    char buf[10] = {0};
    assert(fread(buf, 1, 10, f) == 4);
    fclose(f);
    assert(!strcmp(buf, "next"));
    cdns_config c;
    snprintf(config, sizeof(config), "[common]\nmode=bogus\ndomain=home.example.com\nkey_file=%s\n",
             keyfile);
    assert(cdns_atomic_write(configfile, config, strlen(config)) == 0);
    assert(cdns_config_load(configfile, &c, err, sizeof(err)) != 0);
    snprintf(
        config, sizeof(config),
        "[common]\nmode=client\ndomain=home.example.com\nkey_file=%s\n[client]\npoll_interval=0\n",
        keyfile);
    assert(cdns_atomic_write(configfile, config, strlen(config)) == 0);
    assert(cdns_config_load(configfile, &c, err, sizeof(err)) != 0);
    snprintf(config, sizeof(config),
             "[common]\nmode=client\nmode=client\ndomain=home.example.com\nkey_file=%s\n", keyfile);
    assert(cdns_atomic_write(configfile, config, strlen(config)) == 0);
    assert(cdns_config_load(configfile, &c, err, sizeof(err)) != 0);
#ifdef CDNS_CLIENT
    snprintf(config, sizeof(config),
             "[common]\nmode=client\ndomain=HOME.example.com.\nkey_file=%s\n[client]\nhook=%s\n",
             keyfile, keyfile);
    assert(cdns_atomic_write(configfile, config, strlen(config)) == 0);
    assert(cdns_config_load(configfile, &c, err, sizeof(err)) == 0);
    assert(!strcmp(c.domain, "home.example.com") && c.poll_interval == 60 && c.dns_timeout == 5);
#endif
#ifdef CDNS_SERVER
    snprintf(credsfile, sizeof(credsfile), "%s.ini", keyfile);
    const char *secrets = "token=test-token\nzone_id=abcd1234\naccess_key_id=test-id\naccess_key_"
                          "secret=test-secret\nsecret_id=test-id\nsecret_key=test-key\n";
    assert(cdns_atomic_write(credsfile, secrets, strlen(secrets)) == 0);
    const char *providers[] = {"cloudflare", "aliyun", "dnspod"};
    for (unsigned i = 0; i < 3; i++) {
        snprintf(config, sizeof(config),
                 "[common]\nmode=server\ndomain=home.example.com\nkey_file=%s\n[dns]\nprovider=%"
                 "s\ncredentials_file=%s\nzone=example.com\n",
                 keyfile, providers[i], credsfile);
        assert(cdns_atomic_write(configfile, config, strlen(config)) == 0);
        assert(cdns_config_load(configfile, &c, err, sizeof(err)) == 0);
        if (i)
            assert(!strcmp(c.rr, "home"));
    }
    remove(credsfile);
#else
    (void)credsfile;
#endif
    remove(keyfile);
    remove(configfile);
    cdns_zero(key, sizeof(key));
    cdns_zero(&c, sizeof(c));
}
int main(void) {
    assert(cdns_platform_init() == 0);
    crypto_tests();
    data_tests();
    file_config_tests();
    cdns_platform_cleanup();
    puts("core tests passed");
    return 0;
}
