#include "cipherdns/provider.h"
#include "cipherdns/http.h"
#include "cipherdns/json.h"
#include "mbedtls/md.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CDNS_PROVIDER_PAGE_SIZE 100U
#define CDNS_PROVIDER_RECORD_LIMIT 10000U
typedef struct {
    const char *key, *value;
} pair;
typedef struct {
    char id[128], value[CDNS_TEXT_MAX + 1];
    unsigned ttl, count;
} record;

static int fail_as(cdns_provider_result result, char *err, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (cap)
        vsnprintf(err, cap, fmt, ap);
    va_end(ap);
    return result;
}
#define fail(err, cap, ...) fail_as(CDNS_PROVIDER_RESPONSE, err, cap, __VA_ARGS__)
static int putf(char *out, size_t cap, const char *fmt, ...) {
    int n;
    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(out, cap, fmt, ap);
    va_end(ap);
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}
static int encode(const char *s, char *out, size_t cap) {
    const char hex[] = "0123456789ABCDEF";
    size_t n = 0;
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        int plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '-' || c == '_' || c == '.' || c == '~';
        size_t need = plain ? 1 : 3;
        if (n + need >= cap)
            return -1;
        if (plain)
            out[n++] = (char)c;
        else {
            out[n++] = '%';
            out[n++] = hex[c >> 4];
            out[n++] = hex[c & 15];
        }
    }
    if (!cap)
        return -1;
    out[n] = 0;
    return 0;
}
static void hexify(const unsigned char *in, size_t n, char *out) {
    const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        out[i * 2] = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 15];
    }
    out[n * 2] = 0;
}
static int mac(mbedtls_md_type_t type, const void *key, size_t key_len, const char *message,
               unsigned char *out) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(type);
    return !md || mbedtls_md_hmac(md, key, key_len, (const unsigned char *)message, strlen(message),
                                  out)
               ? -1
               : 0;
}
static int sha256(const char *in, char out[65]) {
    unsigned char digest[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md(md, (const unsigned char *)in, strlen(in), digest))
        return -1;
    hexify(digest, sizeof(digest), out);
    return 0;
}
int cdns_aliyun_sign(const char *query, const char *secret, char *signature, size_t cap) {
    char encoded[24576], message[24584], key[258];
    unsigned char digest[20];
    int rc = -1;
    if (!query || !secret || strlen(secret) > 255 || encode(query, encoded, sizeof(encoded)) ||
        putf(message, sizeof(message), "GET&%%2F&%s", encoded) ||
        putf(key, sizeof(key), "%s&", secret))
        return -1;
    if (!mac(MBEDTLS_MD_SHA1, key, strlen(key), message, digest))
        rc = cdns_base64_encode(digest, sizeof(digest), signature, cap);
    cdns_zero(key, sizeof(key));
    cdns_zero(digest, sizeof(digest));
    return rc;
}
int cdns_tencent_authorization(const char *id, const char *secret, const char *host,
                               const char *service, uint64_t timestamp, const char *payload,
                               char *authorization, size_t cap) {
    char date[11], scope[256], canonical[1024], payload_hash[65], canonical_hash[65];
    char message[1024], key[260], signature[65];
    unsigned char kdate[32], kservice[32], ksigning[32], digest[32];
    time_t t = (time_t)timestamp;
    struct tm *utc;
    int rc = -1;
    if (!id || !secret || !host || !service || !payload || timestamp > 0x7fffffffffffffffULL ||
        t < 0 || (uint64_t)t != timestamp || strlen(secret) > 255)
        return -1;
    utc = gmtime(&t);
    if (!utc || !strftime(date, sizeof(date), "%Y-%m-%d", utc) ||
        putf(scope, sizeof(scope), "%s/%s/tc3_request", date, service) ||
        sha256(payload, payload_hash) ||
        putf(canonical, sizeof(canonical),
             "POST\n/\n\ncontent-type:application/json; "
             "charset=utf-8\nhost:%s\n\ncontent-type;host\n%s",
             host, payload_hash) ||
        sha256(canonical, canonical_hash) ||
        putf(message, sizeof(message), "TC3-HMAC-SHA256\n%llu\n%s\n%s",
             (unsigned long long)timestamp, scope, canonical_hash) ||
        putf(key, sizeof(key), "TC3%s", secret))
        return -1;
    if (!mac(MBEDTLS_MD_SHA256, key, strlen(key), date, kdate) &&
        !mac(MBEDTLS_MD_SHA256, kdate, sizeof(kdate), service, kservice) &&
        !mac(MBEDTLS_MD_SHA256, kservice, sizeof(kservice), "tc3_request", ksigning) &&
        !mac(MBEDTLS_MD_SHA256, ksigning, sizeof(ksigning), message, digest)) {
        hexify(digest, sizeof(digest), signature);
        rc = putf(authorization, cap,
                  "TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host, Signature=%s",
                  id, scope, signature);
    }
    cdns_zero(key, sizeof(key));
    cdns_zero(kdate, sizeof(kdate));
    cdns_zero(kservice, sizeof(kservice));
    cdns_zero(ksigning, sizeof(ksigning));
    cdns_zero(digest, sizeof(digest));
    return rc;
}
static int json_quote(const char *in, char *out, size_t cap) {
    size_t n = 0;
    if (cap < 3)
        return -1;
    out[n++] = '"';
    for (; *in; ++in) {
        unsigned char c = (unsigned char)*in;
        if (c < 32 || c == 127 || n + 3 >= cap)
            return -1;
        if (c == '"' || c == '\\')
            out[n++] = '\\';
        out[n++] = (char)c;
    }
    out[n++] = '"';
    out[n] = 0;
    return 0;
}
static int dns_equal(const char *a, const char *b) {
    size_t na = strlen(a), nb = strlen(b), i;
    if (na && a[na - 1] == '.')
        --na;
    if (nb && b[nb - 1] == '.')
        --nb;
    if (na != nb)
        return 0;
    for (i = 0; i < na; ++i)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    return 1;
}
/* Cloudflare uses RFC 1035 presentation character strings in API content. The
 * DNS resolver returns their concatenated bytes. Keep legacy unquoted replies
 * readable, and decode quotes only for this provider, not Aliyun/DNSPod Value. */
static int cf_text(const char *in, char *out, size_t cap) {
    size_t n = 0;
    if (*in != '"')
        return putf(out, cap, "%s", in);
    do {
        if (*in++ != '"')
            return -1;
        while (*in && *in != '"') {
            unsigned c = (unsigned char)*in++;
            if (c == '\\') {
                if (!*in)
                    return -1;
                if (in[0] >= '0' && in[0] <= '9') {
                    if (!in[1] || !in[2] || in[1] < '0' || in[1] > '9' || in[2] < '0' ||
                        in[2] > '9')
                        return -1;
                    c = (unsigned)(in[0] - '0') * 100 + (unsigned)(in[1] - '0') * 10 +
                        (unsigned)(in[2] - '0');
                    in += 3;
                } else
                    c = (unsigned char)*in++;
            }
            if (!c || c > 255 || n + 1 >= cap)
                return -1;
            out[n++] = (char)c;
        }
        if (*in++ != '"')
            return -1;
        while (*in == ' ' || *in == '\t')
            ++in;
    } while (*in);
    out[n] = 0;
    return 0;
}
static void read_record(const record *rec, cdns_provider_record *out) {
    memset(out, 0, sizeof(*out));
    out->exists = rec->count != 0;
    memcpy(out->id, rec->id, sizeof(out->id));
    memcpy(out->value, rec->value, sizeof(out->value));
    out->ttl = rec->ttl;
}
static int safe_id(const char *id) {
    const unsigned char *p = (const unsigned char *)id;
    if (!*p)
        return 0;
    for (; *p; ++p)
        if (!isalnum(*p) && *p != '-' && *p != '_')
            return 0;
    return 1;
}
static int field(const cdns_json *j, int o, const char *key, char *out, size_t cap) {
    return cdns_json_string(j, cdns_json_get(j, o, key), out, cap);
}
static int number(const cdns_json *j, int o, const char *key, unsigned long long *n) {
    return cdns_json_uint(j, cdns_json_get(j, o, key), n);
}
static int is_type(const cdns_json *j, int t, jsmntype_t type) {
    return t >= 0 && t < j->count && j->tokens[t].type == type;
}
static int starts(const char *s, const char *prefix) {
    return !strncmp(s, prefix, strlen(prefix));
}
static const char *api_category(const char *code) {
    if (starts(code, "AuthFailure") || starts(code, "InvalidAccessKeyId") ||
        starts(code, "SignatureDoesNotMatch") || starts(code, "InvalidSecurityToken") ||
        starts(code, "InvalidParameter.Login") || starts(code, "FailedOperation.Login"))
        return "AUTHENTICATION";
    if (starts(code, "Forbidden") || starts(code, "UnauthorizedOperation") ||
        starts(code, "OperationDenied") || !strcmp(code, "OperationDomain.NoPermission") ||
        !strcmp(code, "DomainRecordNotBelongToUser") ||
        !strcmp(code, "FailedOperation.NotDomainOwner"))
        return "ACCESS_DENIED";
    if (starts(code, "Throttling") || starts(code, "RequestLimitExceeded") ||
        !strcmp(code, "FailedOperation.FrequencyLimit"))
        return "RATE_LIMIT";
    if (starts(code, "InternalError") || starts(code, "InternalFailure") ||
        starts(code, "ServiceUnavailable") || starts(code, "RequestTimeout") ||
        !strcmp(code, "FailedOperation.UnknowError") ||
        !strcmp(code, "InvalidParameter.OperateFailed"))
        return "TEMPORARY_ERROR";
    if (!strcmp(code, "InvalidRecordId.NotFound") || !strcmp(code, "InvalidRecordId.NoExist") ||
        !strcmp(code, "InvalidParameter.RecordIdInvalid") ||
        !strcmp(code, "ResourceNotFound.NoDataOfRecord") ||
        !strcmp(code, "ResourceNotFound.RecordNotExist"))
        return "RECORD_NOT_FOUND";
    if (starts(code, "QuotaExceeded") || starts(code, "LimitExceeded") ||
        starts(code, "DomainRecordLimit") || starts(code, "DomainRecordExceed") ||
        starts(code, "RecordLimitExceeded"))
        return "QUOTA";
    if (starts(code, "DomainRecordDuplicate") || starts(code, "DomainRecordConflict") ||
        starts(code, "DomainRecordExist") || !strcmp(code, "InvalidParameter.DomainRecordExist"))
        return "RECORD_CONFLICT";
    if (starts(code, "Invalid") || starts(code, "MissingParameter") ||
        starts(code, "ResourceNotFound"))
        return "INVALID_ARGUMENT";
    return "API_REJECTED";
}
static cdns_provider_result category_result(const char *category) {
    if (!strcmp(category, "AUTHENTICATION"))
        return CDNS_PROVIDER_AUTH;
    if (!strcmp(category, "ACCESS_DENIED"))
        return CDNS_PROVIDER_DENIED;
    if (!strcmp(category, "RATE_LIMIT"))
        return CDNS_PROVIDER_RATE_LIMIT;
    if (!strcmp(category, "TEMPORARY_ERROR") || !strcmp(category, "TRANSPORT_ERROR"))
        return CDNS_PROVIDER_RETRY;
    if (!strcmp(category, "RECORD_NOT_FOUND"))
        return CDNS_PROVIDER_NOT_FOUND;
    if (!strcmp(category, "RECORD_CONFLICT") || !strcmp(category, "QUOTA"))
        return CDNS_PROVIDER_CONFLICT;
    if (!strcmp(category, "INVALID_ARGUMENT"))
        return CDNS_PROVIDER_INVALID;
    return CDNS_PROVIDER_REJECTED;
}
static const char *json_category(const cdns_json *j, int root) {
    char code[128];
    if (field(j, root, "Code", code, sizeof(code)))
        return "API_REJECTED";
    return api_category(code);
}
static const char *cf_category(const cdns_json *j, const char *fallback) {
    int errors = cdns_json_get(j, 0, "errors");
    unsigned long long code;
    if (!is_type(j, errors, JSMN_ARRAY) || number(j, errors + 1, "code", &code))
        return fallback;
    if (code == 10000 || code == 9109)
        return "AUTHENTICATION";
    if (code == 81057)
        return "RECORD_CONFLICT";
    if (code == 81044)
        return "RECORD_NOT_FOUND";
    return fallback;
}
/* Never propagate vendor response messages, request URLs, or credentials into errors. */
static int request(const cdns_config *c, const char *host, const char *method, const char *path,
                   const char *headers, const char *body, cdns_http_response *r, cdns_json *j,
                   char *err, size_t cap) {
    char transport_error[CDNS_ERROR_MAX];
    memset(r, 0, sizeof(*r));
    if (cdns_http_request(c, host, method, path, headers, body, r, transport_error,
                          sizeof(transport_error))) {
        cdns_http_free(r);
        return fail_as(CDNS_PROVIDER_RETRY, err, cap, "provider TRANSPORT_ERROR");
    }
    if (r->status < 200 || r->status >= 300) {
        int status = r->status;
        const char *category = status == 401                    ? "AUTHENTICATION"
                               : status == 403                  ? "ACCESS_DENIED"
                               : status == 429                  ? "RATE_LIMIT"
                               : status == 408 || status >= 500 ? "TEMPORARY_ERROR"
                               : status == 404                  ? "RECORD_NOT_FOUND"
                                                                : "HTTP_ERROR";
        /* RPC APIs also return structured machine codes with HTTP 4xx. Keep
         * categorization useful without ever reflecting a vendor message. */
        if (status != 429 && status != 408 && status < 500 && r->body &&
            !cdns_json_parse(j, r->body) && is_type(j, 0, JSMN_OBJECT)) {
            int api_error = cdns_json_get(j, cdns_json_get(j, 0, "Response"), "Error");
            if (cdns_json_get(j, 0, "Code") >= 0)
                category = json_category(j, 0);
            else if (api_error >= 0)
                category = json_category(j, api_error);
            else if (!strcmp(host, "api.cloudflare.com"))
                category = cf_category(j, category);
        }
        cdns_http_free(r);
        return fail_as(category_result(category), err, cap, "provider %s (HTTP %d)", category,
                       status);
    }
    if (!r->body || cdns_json_parse(j, r->body) || !is_type(j, 0, JSMN_OBJECT)) {
        cdns_http_free(r);
        return fail(err, cap, "provider MALFORMED_RESPONSE");
    }
    return 0;
}
static int found(record *r, const char *id, const char *value, unsigned long long ttl, char *err,
                 size_t cap) {
    if (++r->count != 1)
        return fail_as(CDNS_PROVIDER_CONFLICT, err, cap,
                       "provider AMBIGUOUS_TXT (multiple exact records)");
    if (!safe_id(id) || ttl > 604800 || putf(r->id, sizeof(r->id), "%s", id) ||
        putf(r->value, sizeof(r->value), "%s", value))
        return fail(err, cap, "provider MALFORMED_RESPONSE");
    r->ttl = (unsigned)ttl;
    return 0;
}
static int cf_call(const cdns_config *c, const char *method, const char *path, const char *body,
                   cdns_http_response *r, cdns_json *j, char *err, size_t cap) {
    char headers[1024];
    int rc;
    if (putf(headers, sizeof(headers),
             "Authorization: Bearer %s\r\nContent-Type: application/json\r\n", c->token))
        return fail(err, cap, "provider INVALID_CREDENTIAL");
    rc = request(c, "api.cloudflare.com", method, path, headers, body, r, j, err, cap);
    cdns_zero(headers, sizeof(headers));
    if (rc)
        return rc;
    if (!is_type(j, cdns_json_get(j, 0, "success"), JSMN_PRIMITIVE) ||
        !cdns_json_eq(j, cdns_json_get(j, 0, "success"), "true")) {
        const char *category = cf_category(j, "API_REJECTED");
        cdns_http_free(r);
        return fail_as(category_result(category), err, cap, "cloudflare %s", category);
    }
    return 0;
}
static int cloudflare(const cdns_config *c, const char *txt, cdns_provider_record *out,
                      const char *expected_id, char *err, size_t cap) {
    record rec = {0};
    char path[1536], encoded[768], id[128], value[1032], text[256], name[256], type[32];
    unsigned page;
    unsigned long long expected_total = 0;
    for (page = 1; page <= CDNS_PROVIDER_RECORD_LIMIT / CDNS_PROVIDER_PAGE_SIZE; ++page) {
        cdns_http_response r;
        cdns_json j;
        unsigned long long total, ttl;
        unsigned count = 0;
        int a, i, info, rc;
        if (encode(c->domain, encoded, sizeof(encoded)) ||
            putf(path, sizeof(path),
                 "/client/v4/zones/%s/dns_records?type=TXT&name.exact=%s&per_page=%u&page=%u",
                 c->zone_id, encoded, CDNS_PROVIDER_PAGE_SIZE, page))
            return fail(err, cap, "provider REQUEST_TOO_LARGE");
        if ((rc = cf_call(c, "GET", path, NULL, &r, &j, err, cap)))
            return rc;
        a = cdns_json_get(&j, 0, "result");
        info = cdns_json_get(&j, 0, "result_info");
        if (!is_type(&j, a, JSMN_ARRAY) || number(&j, info, "total_count", &total) ||
            total > CDNS_PROVIDER_RECORD_LIMIT)
            goto malformed;
        if (page > 1 && expected_total != total) {
            cdns_http_free(&r);
            return fail(err, cap, "provider INCONSISTENT_PAGINATION");
        }
        expected_total = total;
        for (i = a + 1; i < j.count && j.tokens[i].start < j.tokens[a].end;
             i = cdns_json_next(&j, i)) {
            ++count;
            if (field(&j, i, "name", name, sizeof(name)) ||
                field(&j, i, "type", type, sizeof(type)))
                goto malformed;
            if (!dns_equal(name, c->domain) || strcmp(type, "TXT"))
                continue;
            if (field(&j, i, "id", id, sizeof(id)) ||
                field(&j, i, "content", value, sizeof(value)) || number(&j, i, "ttl", &ttl) ||
                cf_text(value, text, sizeof(text)))
                goto malformed;
            if ((rc = found(&rec, id, text, ttl, err, cap))) {
                cdns_http_free(&r);
                return rc;
            }
        }
        cdns_http_free(&r);
        if (count > CDNS_PROVIDER_PAGE_SIZE ||
            (unsigned long long)(page - 1) * CDNS_PROVIDER_PAGE_SIZE + count > total)
            return fail(err, cap, "provider INCONSISTENT_PAGINATION");
        if ((unsigned long long)(page - 1) * CDNS_PROVIDER_PAGE_SIZE + count == total)
            break;
        if (count != CDNS_PROVIDER_PAGE_SIZE)
            return fail(err, cap, "provider INCOMPLETE_LIST");
        continue;
    malformed:
        cdns_http_free(&r);
        return fail(err, cap, "cloudflare MALFORMED_RESPONSE");
    }
    if (page > CDNS_PROVIDER_RECORD_LIMIT / CDNS_PROVIDER_PAGE_SIZE)
        return fail(err, cap, "provider LIST_LIMIT");
    if (out) {
        read_record(&rec, out);
        return 0;
    }
    if (expected_id && ((!*expected_id && rec.count) ||
                        (*expected_id && (!rec.count || strcmp(rec.id, expected_id)))))
        return fail_as(CDNS_PROVIDER_CONFLICT, err, cap, "provider OWNERSHIP_MISMATCH");
    if (rec.count && rec.ttl == c->ttl && !strcmp(rec.value, txt))
        return 0;
    {
        char qname[512], dnsvalue[516], qvalue[1036], body[2048];
        cdns_http_response r;
        cdns_json j;
        int a, rc;
        if (json_quote(c->domain, qname, sizeof(qname)) ||
            json_quote(txt, dnsvalue, sizeof(dnsvalue)) ||
            json_quote(dnsvalue, qvalue, sizeof(qvalue)) ||
            putf(body, sizeof(body), "{\"type\":\"TXT\",\"name\":%s,\"content\":%s,\"ttl\":%u}",
                 qname, qvalue, c->ttl) ||
            putf(path, sizeof(path), "/client/v4/zones/%s/dns_records%s%s", c->zone_id,
                 rec.count ? "/" : "", rec.count ? rec.id : ""))
            return fail(err, cap, "provider REQUEST_TOO_LARGE");
        if ((rc = cf_call(c, rec.count ? "PATCH" : "POST", path, body, &r, &j, err, cap)))
            return rc;
        a = cdns_json_get(&j, 0, "result");
        if (!is_type(&j, a, JSMN_OBJECT) || field(&j, a, "id", id, sizeof(id)) || !safe_id(id)) {
            cdns_http_free(&r);
            return fail(err, cap, "cloudflare MALFORMED_RESPONSE");
        }
        cdns_http_free(&r);
    }
    return 0;
}
static int pair_cmp(const void *a, const void *b) {
    return strcmp(((const pair *)a)->key, ((const pair *)b)->key);
}
static int ali_call(const cdns_config *c, const char *action, pair *params, size_t count,
                    cdns_http_response *r, cdns_json *j, char *err, size_t cap) {
    char query[8192] = "", path[8448], timestamp[32], nonce[33], signature[64], escaped[192];
    unsigned char random[16];
    size_t i, used = 0;
    time_t now = time(NULL);
    struct tm *utc;
    pair all[24];
    int rc;
    if (count + 8 > sizeof(all) / sizeof(all[0]) || now < 0 || !(utc = gmtime(&now)) ||
        !strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", utc) ||
        cdns_random(random, sizeof(random)))
        return fail(err, cap, "provider SIGNING_ERROR");
    hexify(random, sizeof(random), nonce);
    all[0] = (pair){"AccessKeyId", c->access_key_id};
    all[1] = (pair){"Action", action};
    all[2] = (pair){"Format", "JSON"};
    all[3] = (pair){"SignatureMethod", "HMAC-SHA1"};
    all[4] = (pair){"SignatureNonce", nonce};
    all[5] = (pair){"SignatureVersion", "1.0"};
    all[6] = (pair){"Timestamp", timestamp};
    all[7] = (pair){"Version", "2015-01-09"};
    for (i = 0; i < count; ++i)
        all[i + 8] = params[i];
    count += 8;
    qsort(all, count, sizeof(all[0]), pair_cmp);
    for (i = 0; i < count; ++i) {
        char encoded_value[2048];
        size_t n;
        if (encode(all[i].value, encoded_value, sizeof(encoded_value)) ||
            putf(query + used, sizeof(query) - used, "%s%s=%s", i ? "&" : "", all[i].key,
                 encoded_value))
            return fail(err, cap, "provider REQUEST_TOO_LARGE");
        n = strlen(query + used);
        used += n;
    }
    if (cdns_aliyun_sign(query, c->access_key_secret, signature, sizeof(signature)) ||
        encode(signature, escaped, sizeof(escaped)) ||
        putf(path, sizeof(path), "/?%s&Signature=%s", query, escaped))
        return fail(err, cap, "provider SIGNING_ERROR");
    rc = request(c, "alidns.aliyuncs.com", "GET", path, "", NULL, r, j, err, cap);
    cdns_zero(path, sizeof(path));
    cdns_zero(signature, sizeof(signature));
    if (rc)
        return rc;
    if (cdns_json_get(j, 0, "Code") >= 0) {
        const char *category = json_category(j, 0);
        cdns_http_free(r);
        return fail_as(category_result(category), err, cap, "aliyun %s", category);
    }
    return 0;
}
static int aliyun(const cdns_config *c, const char *txt, cdns_provider_record *out,
                  const char *expected_id, char *err, size_t cap) {
    record rec = {0};
    unsigned page;
    unsigned long long expected_total = 0;
    char id[128], value[256], rr[256], zone[256], type[32], status[32], line[64];
    for (page = 1; page <= CDNS_PROVIDER_RECORD_LIMIT / CDNS_PROVIDER_PAGE_SIZE; ++page) {
        cdns_http_response r;
        cdns_json j;
        unsigned count = 0;
        unsigned long long total, ttl;
        int a, i, rc;
        char page_text[16];
        pair p[5];
        snprintf(page_text, sizeof(page_text), "%u", page);
        p[0] = (pair){"SubDomain", c->domain};
        p[1] = (pair){"Type", "TXT"};
        p[2] = (pair){"PageNumber", page_text};
        p[3] = (pair){"PageSize", "100"};
        p[4] = (pair){"DomainName", c->zone};
        if ((rc = ali_call(c, "DescribeSubDomainRecords", p, 5, &r, &j, err, cap)))
            return rc;
        a = cdns_json_get(&j, cdns_json_get(&j, 0, "DomainRecords"), "Record");
        if (!is_type(&j, a, JSMN_ARRAY) || number(&j, 0, "TotalCount", &total) ||
            total > CDNS_PROVIDER_RECORD_LIMIT)
            goto malformed;
        if (page > 1 && expected_total != total) {
            cdns_http_free(&r);
            return fail(err, cap, "provider INCONSISTENT_PAGINATION");
        }
        expected_total = total;
        for (i = a + 1; i < j.count && j.tokens[i].start < j.tokens[a].end;
             i = cdns_json_next(&j, i)) {
            ++count;
            if (field(&j, i, "RR", rr, sizeof(rr)) ||
                field(&j, i, "DomainName", zone, sizeof(zone)) ||
                field(&j, i, "Type", type, sizeof(type)))
                goto malformed;
            if (!dns_equal(rr, c->rr) || !dns_equal(zone, c->zone) || strcmp(type, "TXT"))
                continue;
            if (field(&j, i, "RecordId", id, sizeof(id)) ||
                field(&j, i, "Value", value, sizeof(value)) || number(&j, i, "TTL", &ttl) ||
                field(&j, i, "Status", status, sizeof(status)) ||
                field(&j, i, "Line", line, sizeof(line)))
                goto malformed;
            if (!dns_equal(status, "ENABLE") || strcmp(line, "default")) {
                cdns_http_free(&r);
                return fail_as(CDNS_PROVIDER_CONFLICT, err, cap,
                               "aliyun UNSUPPORTED_RECORD_STATE (enable default line)");
            }
            if ((rc = found(&rec, id, value, ttl, err, cap))) {
                cdns_http_free(&r);
                return rc;
            }
        }
        cdns_http_free(&r);
        if (count > CDNS_PROVIDER_PAGE_SIZE ||
            (unsigned long long)(page - 1) * CDNS_PROVIDER_PAGE_SIZE + count > total)
            return fail(err, cap, "provider INCONSISTENT_PAGINATION");
        if ((unsigned long long)(page - 1) * CDNS_PROVIDER_PAGE_SIZE + count == total)
            break;
        if (count != CDNS_PROVIDER_PAGE_SIZE)
            return fail(err, cap, "provider INCOMPLETE_LIST");
        continue;
    malformed:
        cdns_http_free(&r);
        return fail(err, cap, "aliyun MALFORMED_RESPONSE");
    }
    if (page > CDNS_PROVIDER_RECORD_LIMIT / CDNS_PROVIDER_PAGE_SIZE)
        return fail(err, cap, "provider LIST_LIMIT");
    if (out) {
        read_record(&rec, out);
        return 0;
    }
    if (expected_id && ((!*expected_id && rec.count) ||
                        (*expected_id && (!rec.count || strcmp(rec.id, expected_id)))))
        return fail_as(CDNS_PROVIDER_CONFLICT, err, cap, "provider OWNERSHIP_MISMATCH");
    if (rec.count && rec.ttl == c->ttl && !strcmp(rec.value, txt))
        return 0;
    {
        cdns_http_response r;
        cdns_json j;
        char ttl[16];
        pair p[6];
        int rc;
        snprintf(ttl, sizeof(ttl), "%u", c->ttl);
        p[0] = rec.count ? (pair){"RecordId", rec.id} : (pair){"DomainName", c->zone};
        p[1] = (pair){"RR", c->rr};
        p[2] = (pair){"Type", "TXT"};
        p[3] = (pair){"Value", txt};
        p[4] = (pair){"TTL", ttl};
        p[5] = (pair){"Line", "default"};
        if ((rc = ali_call(c, rec.count ? "UpdateDomainRecord" : "AddDomainRecord", p, 6, &r, &j,
                           err, cap)))
            return rc;
        if (field(&j, 0, "RecordId", id, sizeof(id)) || !safe_id(id)) {
            cdns_http_free(&r);
            return fail(err, cap, "aliyun MALFORMED_RESPONSE");
        }
        cdns_http_free(&r);
    }
    return 0;
}
static int tc_call(const cdns_config *c, const char *action, const char *body,
                   cdns_http_response *r, cdns_json *j, int *root, char *err, size_t cap) {
    char auth[1024], headers[1536];
    time_t now = time(NULL);
    int rc;
    if (now < 0 ||
        cdns_tencent_authorization(c->secret_id, c->secret_key, "dnspod.tencentcloudapi.com",
                                   "dnspod", (uint64_t)now, body, auth, sizeof(auth)) ||
        putf(headers, sizeof(headers),
             "Authorization: %s\r\nContent-Type: application/json; charset=utf-8\r\n"
             "X-TC-Action: %s\r\nX-TC-Version: 2021-03-23\r\nX-TC-Timestamp: %llu\r\n",
             auth, action, (unsigned long long)now))
        return fail(err, cap, "provider SIGNING_ERROR");
    rc = request(c, "dnspod.tencentcloudapi.com", "POST", "/", headers, body, r, j, err, cap);
    cdns_zero(auth, sizeof(auth));
    cdns_zero(headers, sizeof(headers));
    if (rc)
        return rc;
    *root = cdns_json_get(j, 0, "Response");
    if (!is_type(j, *root, JSMN_OBJECT)) {
        cdns_http_free(r);
        return fail(err, cap, "tencent MALFORMED_RESPONSE");
    }
    if (cdns_json_get(j, *root, "Error") >= 0) {
        const char *category = json_category(j, cdns_json_get(j, *root, "Error"));
        cdns_http_free(r);
        return fail_as(category_result(category), err, cap, "tencent %s", category);
    }
    return 0;
}
static int tencent(const cdns_config *c, const char *txt, cdns_provider_record *out,
                   const char *expected_id, char *err, size_t cap) {
    record rec = {0};
    unsigned offset;
    unsigned long long expected_total = 0;
    char qzone[512], qrr[512], qvalue[516], body[2048], name[256], type[32], status[32], line[64],
        value[256], id[128];
    if (json_quote(c->zone, qzone, sizeof(qzone)) || json_quote(c->rr, qrr, sizeof(qrr)) ||
        (txt && json_quote(txt, qvalue, sizeof(qvalue))))
        return fail(err, cap, "provider INVALID_VALUE");
    for (offset = 0; offset < CDNS_PROVIDER_RECORD_LIMIT; offset += CDNS_PROVIDER_PAGE_SIZE) {
        cdns_http_response r;
        cdns_json j;
        int root, a, i, rc;
        unsigned count = 0;
        unsigned long long total, ttl, rid;
        /* Read the complete zone: TotalCount is documented as the total record
         * count, not an explicitly filter-scoped count. Match name/type locally. */
        if (putf(body, sizeof(body),
                 "{\"Domain\":%s,\"ErrorOnEmpty\":\"no\",\"Offset\":%u,\"Limit\":100}", qzone,
                 offset))
            return fail(err, cap, "provider REQUEST_TOO_LARGE");
        if ((rc = tc_call(c, "DescribeRecordList", body, &r, &j, &root, err, cap)))
            return rc;
        a = cdns_json_get(&j, root, "RecordList");
        if (!is_type(&j, a, JSMN_ARRAY) ||
            number(&j, cdns_json_get(&j, root, "RecordCountInfo"), "TotalCount", &total) ||
            total > CDNS_PROVIDER_RECORD_LIMIT)
            goto malformed;
        if (offset && expected_total != total) {
            cdns_http_free(&r);
            return fail(err, cap, "provider INCONSISTENT_PAGINATION");
        }
        expected_total = total;
        for (i = a + 1; i < j.count && j.tokens[i].start < j.tokens[a].end;
             i = cdns_json_next(&j, i)) {
            ++count;
            if (field(&j, i, "Name", name, sizeof(name)) ||
                field(&j, i, "Type", type, sizeof(type)))
                goto malformed;
            if (!dns_equal(name, c->rr) || strcmp(type, "TXT"))
                continue;
            if (number(&j, i, "RecordId", &rid) || !rid ||
                field(&j, i, "Value", value, sizeof(value)) || number(&j, i, "TTL", &ttl) ||
                field(&j, i, "Status", status, sizeof(status)) ||
                field(&j, i, "LineId", line, sizeof(line)))
                goto malformed;
            if (strcmp(status, "ENABLE") || strcmp(line, "0")) {
                cdns_http_free(&r);
                return fail_as(CDNS_PROVIDER_CONFLICT, err, cap,
                               "tencent UNSUPPORTED_RECORD_STATE (enable default line)");
            }
            snprintf(id, sizeof(id), "%llu", rid);
            if ((rc = found(&rec, id, value, ttl, err, cap))) {
                cdns_http_free(&r);
                return rc;
            }
        }
        cdns_http_free(&r);
        if (count > CDNS_PROVIDER_PAGE_SIZE || (unsigned long long)offset + count > total)
            return fail(err, cap, "provider INCONSISTENT_PAGINATION");
        if ((unsigned long long)offset + count == total)
            break;
        if (count != CDNS_PROVIDER_PAGE_SIZE)
            return fail(err, cap, "provider INCOMPLETE_LIST");
        continue;
    malformed:
        cdns_http_free(&r);
        return fail(err, cap, "tencent MALFORMED_RESPONSE");
    }
    if (offset >= CDNS_PROVIDER_RECORD_LIMIT)
        return fail(err, cap, "provider LIST_LIMIT");
    if (out) {
        read_record(&rec, out);
        return 0;
    }
    if (expected_id && ((!*expected_id && rec.count) ||
                        (*expected_id && (!rec.count || strcmp(rec.id, expected_id)))))
        return fail_as(CDNS_PROVIDER_CONFLICT, err, cap, "provider OWNERSHIP_MISMATCH");
    if (rec.count && rec.ttl == c->ttl && !strcmp(rec.value, txt))
        return 0;
    {
        cdns_http_response r;
        cdns_json j;
        int root, rc;
        unsigned long long rid;
        if (putf(body, sizeof(body),
                 "{\"Domain\":%s,\"SubDomain\":%s,\"RecordType\":\"TXT\","
                 "\"RecordLine\":\"默认\",\"RecordLineId\":\"0\",\"Value\":%s,\"TTL\":%u%s%s}",
                 qzone, qrr, qvalue, c->ttl, rec.count ? ",\"RecordId\":" : "",
                 rec.count ? rec.id : ""))
            return fail(err, cap, "provider REQUEST_TOO_LARGE");
        if ((rc = tc_call(c, rec.count ? "ModifyRecord" : "CreateRecord", body, &r, &j, &root, err,
                          cap)))
            return rc;
        if (number(&j, root, "RecordId", &rid) || !rid) {
            cdns_http_free(&r);
            return fail(err, cap, "tencent MALFORMED_RESPONSE");
        }
        cdns_http_free(&r);
    }
    return 0;
}
static int provider_sync_impl(const cdns_config *c, const char *txt, cdns_provider_record *out,
                              const char *expected_id, char *err, size_t cap) {
    char combined[512];
    const unsigned char *p;
    if (cap)
        err[0] = 0;
    if (!c || (!txt && !out) || (txt && (!*txt || strlen(txt) > CDNS_TEXT_MAX)) || !*c->domain ||
        !c->ttl || c->ttl > 604800)
        return fail_as(CDNS_PROVIDER_INVALID, err, cap, "provider INVALID_CONFIG");
    if (txt)
        for (p = (const unsigned char *)txt; *p; ++p)
            if (*p < 32 || *p == 127)
                return fail_as(CDNS_PROVIDER_INVALID, err, cap, "provider INVALID_VALUE");
    if (!strcmp(c->provider, "cloudflare")) {
        if (!safe_id(c->zone_id) || !*c->token || strpbrk(c->token, "\r\n"))
            return fail_as(CDNS_PROVIDER_INVALID, err, cap, "cloudflare INVALID_CREDENTIAL");
        if (c->ttl != 1 && (c->ttl < 30 || c->ttl > 86400))
            return fail_as(CDNS_PROVIDER_INVALID, err, cap, "cloudflare INVALID_TTL");
        return cloudflare(c, txt, out, expected_id, err, cap);
    }
    if (!*c->zone || !*c->rr ||
        putf(combined, sizeof(combined), !strcmp(c->rr, "@") ? "%s%s" : "%s.%s",
             !strcmp(c->rr, "@") ? "" : c->rr, c->zone) ||
        !dns_equal(combined, c->domain))
        return fail_as(CDNS_PROVIDER_INVALID, err, cap,
                       "provider INVALID_ZONE_RR (must exactly form domain)");
    if (!strcmp(c->provider, "aliyun")) {
        if (!*c->access_key_id || !*c->access_key_secret)
            return fail_as(CDNS_PROVIDER_INVALID, err, cap, "aliyun INVALID_CREDENTIAL");
        if (c->ttl > 86400)
            return fail_as(CDNS_PROVIDER_INVALID, err, cap, "aliyun INVALID_TTL");
        return aliyun(c, txt, out, expected_id, err, cap);
    }
    if (!strcmp(c->provider, "dnspod") || !strcmp(c->provider, "tencent")) {
        if (!*c->secret_id || !*c->secret_key || strpbrk(c->secret_id, "\r\n"))
            return fail_as(CDNS_PROVIDER_INVALID, err, cap, "tencent INVALID_CREDENTIAL");
        return tencent(c, txt, out, expected_id, err, cap);
    }
    return fail_as(CDNS_PROVIDER_INVALID, err, cap, "provider UNSUPPORTED_PROVIDER");
}
static cdns_provider_result provider_operation(const cdns_config *c, const char *txt,
                                               cdns_provider_record *out, const char *expected_id,
                                               char *err, size_t cap) {
    cdns_config bounded;
    int rc;
    if (out)
        memset(out, 0, sizeof(*out));
    if (!c)
        return (cdns_provider_result)fail_as(CDNS_PROVIDER_INVALID, err, cap,
                                             "provider INVALID_CONFIG");
    bounded = *c;
    bounded.api_deadline_ms =
        cdns_mono_ms() + (uint64_t)(c->update_timeout ? c->update_timeout : 30) * 1000;
    if (c->api_deadline_ms && c->api_deadline_ms < bounded.api_deadline_ms)
        bounded.api_deadline_ms = c->api_deadline_ms;
    rc = provider_sync_impl(&bounded, txt, out, expected_id, err, cap);
    cdns_zero(&bounded, sizeof(bounded));
    if (rc && out)
        memset(out, 0, sizeof(*out));
    return (cdns_provider_result)rc;
}
cdns_provider_result cdns_provider_sync(const cdns_config *c, const char *txt, char *err,
                                        size_t cap) {
    return provider_operation(c, txt, NULL, NULL, err, cap);
}
cdns_provider_result cdns_provider_read(const cdns_config *c, cdns_provider_record *out, char *err,
                                        size_t cap) {
    return provider_operation(c, NULL, out, NULL, err, cap);
}
int cdns_provider_retryable(cdns_provider_result result) {
    return result == CDNS_PROVIDER_RETRY || result == CDNS_PROVIDER_RATE_LIMIT;
}

cdns_provider_result cdns_provider_sync_guarded(const cdns_config *c, const char *txt,
                                                const char *expected_id, char *err, size_t cap) {
    if (!expected_id)
        return (cdns_provider_result)fail_as(CDNS_PROVIDER_INVALID, err, cap,
                                             "provider EXPECTED_RECORD_ID_REQUIRED");
    return provider_operation(c, txt, NULL, expected_id, err, cap);
}
