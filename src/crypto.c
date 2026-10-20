#include "cipherdns/core.h"
#include "cipherdns/json.h"
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif
void cdns_zero(void *p, size_t n) {
    mbedtls_platform_zeroize(p, n);
}
int cdns_random(void *out, size_t n) {
#ifdef _WIN32
    if (n > 0xffffffffu)
        return -1;
    return BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    size_t pos = 0;
    while (pos < n) {
        ssize_t z = read(fd, (unsigned char *)out + pos, n - pos);
        if (z < 0 && errno == EINTR)
            continue;
        if (z <= 0) {
            close(fd);
            return -1;
        }
        pos += (size_t)z;
    }
    close(fd);
    return 0;
#endif
}
int cdns_base64_encode(const unsigned char *in, size_t n, char *out, size_t cap) {
    size_t z = 0;
    return mbedtls_base64_encode((unsigned char *)out, cap, &z, in, n) == 0 ? 0 : -1;
}
int cdns_base64_decode(const char *in, unsigned char *out, size_t cap, size_t *n) {
    size_t len = strlen(in);
    if (!len || len % 4 || len > 1024)
        return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '+' || c == '/' || c == '='))
            return -1;
    }
    if (mbedtls_base64_decode(out, cap, n, (const unsigned char *)in, len))
        return -1;
    char canonical[1025];
    if (cdns_base64_encode(out, *n, canonical, sizeof(canonical)) || strcmp(canonical, in))
        return -1;
    return 0;
}
int cdns_key_load(const char *path, unsigned char key[32]) {
    if (cdns_private_file(path))
        return -1;
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    unsigned char tmp[33];
    size_t n = fread(tmp, 1, sizeof(tmp), f);
    int ok = !ferror(f) && n == 32;
    fclose(f);
    if (ok)
        memcpy(key, tmp, 32);
    cdns_zero(tmp, sizeof(tmp));
    return ok ? 0 : -1;
}
int cdns_keygen(const char *path) {
    unsigned char key[32];
    if (cdns_random(key, 32))
        return -1;
#ifdef _WIN32
    int rc = cdns_private_create(path, key, 32);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    int rc = -1;
    if (fd >= 0) {
        size_t pos = 0;
        while (pos < 32) {
            ssize_t n = write(fd, key + pos, 32 - pos);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            pos += (size_t)n;
        }
        if (pos == 32 && fsync(fd) == 0)
            rc = 0;
        if (close(fd))
            rc = -1;
        if (rc)
            unlink(path);
    }
#endif
    cdns_zero(key, 32);
    return rc;
}
int cdns_address_valid(cdns_address *a) {
    unsigned char raw[16];
    char normalized[46];
    if (a->port > 65535 || (!a->ipv4[0] && !a->ipv6[0]))
        return -1;
    if (a->ipv4[0]) {
        if (inet_pton(AF_INET, a->ipv4, raw) != 1 ||
            !inet_ntop(AF_INET, raw, normalized, sizeof(normalized)))
            return -1;
        if (raw[0] == 0 || raw[0] == 127 || raw[0] >= 224)
            return -1;
        strcpy(a->ipv4, normalized);
    }
    if (a->ipv6[0]) {
        static const unsigned char zero[16] = {0};
        if (inet_pton(AF_INET6, a->ipv6, raw) != 1 ||
            !inet_ntop(AF_INET6, raw, normalized, sizeof(normalized)))
            return -1;
        if (!memcmp(raw, zero, 15) && (raw[15] == 0 || raw[15] == 1))
            return -1;
        if (raw[0] == 0xff || (raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80) ||
            (!memcmp(raw, zero, 10) && raw[10] == 0xff && raw[11] == 0xff))
            return -1;
        strcpy(a->ipv6, normalized);
    }
    return 0;
}
int cdns_address_equal(const cdns_address *a, const cdns_address *b) {
    return !strcmp(a->ipv4, b->ipv4) && !strcmp(a->ipv6, b->ipv6) && a->port == b->port;
}
int cdns_address_json(const cdns_address *a, char *out, size_t cap) {
    cdns_address tmp = *a;
    if (cdns_address_valid(&tmp))
        return -1;
    int n = snprintf(out, cap, "{\"v\":1,\"ipv4\":\"%s\",\"ipv6\":\"%s\",\"port\":%u}\n", tmp.ipv4,
                     tmp.ipv6, tmp.port);
    return n >= 0 && (size_t)n < cap ? 0 : -1;
}
int cdns_address_parse(const char *json, cdns_address *a) {
    cdns_json j;
    cdns_address b = {0};
    unsigned long long port;
    int v;
    if (cdns_json_parse(&j, json) || j.tokens[0].type != JSMN_OBJECT)
        return -1;
    v = cdns_json_get(&j, 0, "v");
    if (v >= 0 && !cdns_json_eq(&j, v, "1"))
        return -1;
    if (cdns_json_string(&j, cdns_json_get(&j, 0, "ipv4"), b.ipv4, sizeof(b.ipv4)) ||
        cdns_json_string(&j, cdns_json_get(&j, 0, "ipv6"), b.ipv6, sizeof(b.ipv6)) ||
        cdns_json_uint(&j, cdns_json_get(&j, 0, "port"), &port) || port > 65535)
        return -1;
    b.port = (unsigned)port;
    if (cdns_address_valid(&b))
        return -1;
    *a = b;
    return 0;
}
int cdns_encrypt(const unsigned char key[32], const cdns_address *a, char out[256]) {
    unsigned char plain[24] = {1, 0}, wire[52];
    cdns_address b = *a;
    if (cdns_address_valid(&b) || cdns_random(wire, 12))
        return -1;
    if (b.ipv4[0]) {
        plain[1] |= 1;
        if (inet_pton(AF_INET, b.ipv4, plain + 4) != 1)
            return -1;
    }
    if (b.ipv6[0]) {
        plain[1] |= 2;
        if (inet_pton(AF_INET6, b.ipv6, plain + 8) != 1)
            return -1;
    }
    plain[2] = (unsigned char)(b.port >> 8);
    plain[3] = (unsigned char)b.port;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    static const unsigned char aad[] = "CipherDNS/CD1";
    if (!rc)
        rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, 24, wire, 12, aad,
                                       sizeof(aad) - 1, plain, wire + 12, 16, wire + 36);
    mbedtls_gcm_free(&ctx);
    cdns_zero(plain, sizeof(plain));
    if (rc)
        return -1;
    memcpy(out, "CD1:", 4);
    rc = cdns_base64_encode(wire, sizeof(wire), out + 4, 252);
    cdns_zero(wire, sizeof(wire));
    return rc;
}
int cdns_decrypt(const unsigned char key[32], const char *txt, cdns_address *a) {
    unsigned char wire[52], plain[24];
    size_t n = 0;
    cdns_address b = {0};
    if (strlen(txt) > 255 || strncmp(txt, "CD1:", 4) ||
        cdns_base64_decode(txt + 4, wire, sizeof(wire), &n) || n != 52)
        return -1;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    static const unsigned char aad[] = "CipherDNS/CD1";
    if (!rc)
        rc = mbedtls_gcm_auth_decrypt(&ctx, 24, wire, 12, aad, sizeof(aad) - 1, wire + 36, 16,
                                      wire + 12, plain);
    mbedtls_gcm_free(&ctx);
    cdns_zero(wire, sizeof(wire));
    if (!rc) {
        if (plain[0] != 1 || !plain[1] || (plain[1] & ~3))
            rc = -1;
        b.port = ((unsigned)plain[2] << 8) | plain[3];
        if ((plain[1] & 1) && !inet_ntop(AF_INET, plain + 4, b.ipv4, sizeof(b.ipv4)))
            rc = -1;
        if ((plain[1] & 2) && !inet_ntop(AF_INET6, plain + 8, b.ipv6, sizeof(b.ipv6)))
            rc = -1;
        if (!rc)
            rc = cdns_address_valid(&b);
    }
    cdns_zero(plain, sizeof(plain));
    if (!rc)
        *a = b;
    return rc ? -1 : 0;
}
void cdns_address_merge(cdns_address *out, const cdns_address *seen, const cdns_address *previous) {
    cdns_address result = *seen;
    if (!result.ipv4[0])
        memcpy(result.ipv4, previous->ipv4, sizeof(result.ipv4));
    if (!result.ipv6[0])
        memcpy(result.ipv6, previous->ipv6, sizeof(result.ipv6));
    *out = result;
}
