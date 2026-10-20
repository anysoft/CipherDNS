#ifndef CIPHERDNS_PROVIDER_H
#define CIPHERDNS_PROVIDER_H
#include "core.h"
typedef enum {
    CDNS_PROVIDER_OK = 0,
    CDNS_PROVIDER_RETRY = -1,
    CDNS_PROVIDER_AUTH = -2,
    CDNS_PROVIDER_DENIED = -3,
    CDNS_PROVIDER_RATE_LIMIT = -4,
    CDNS_PROVIDER_INVALID = -5,
    CDNS_PROVIDER_NOT_FOUND = -6,
    CDNS_PROVIDER_CONFLICT = -7,
    CDNS_PROVIDER_RESPONSE = -8,
    CDNS_PROVIDER_REJECTED = -9
} cdns_provider_result;
typedef struct {
    int exists;
    char id[128], value[CDNS_TEXT_MAX + 1];
    unsigned ttl;
} cdns_provider_record;
/* Reads every matching TXT record before choosing create or update. A successful
 * call means the provider accepted the desired value; DNS caches may lag. The
 * configured name must be dedicated to CipherDNS. No record deletion is used. */
cdns_provider_result cdns_provider_sync(const cdns_config *c, const char *txt, char *err,
                                        size_t cap);
/* A complete, read-only discovery. An absent TXT is OK with exists=0. Multiple
 * exact records fail, and out is cleared on failure. Values are logical DNS text,
 * without Cloudflare's presentation quotes. This never creates or updates. */
cdns_provider_result cdns_provider_read(const cdns_config *c, cdns_provider_record *out, char *err,
                                        size_t cap);
/* Integration safety guard, checked again after discovery: empty expected_id
 * permits creation only; a nonempty ID permits updating only that exact record.
 * Run one writer per dedicated name; provider APIs offer no atomic name lock. */
cdns_provider_result cdns_provider_sync_guarded(const cdns_config *c, const char *txt,
                                                const char *expected_id, char *err, size_t cap);
int cdns_provider_retryable(cdns_provider_result result);
/* Deterministic request-signing primitives, also used by offline vector tests.
 * Aliyun input is an already sorted RFC 3986 canonical query without Signature.
 * Tencent signs POST / with application/json; charset=utf-8 and host headers. */
int cdns_aliyun_sign(const char *canonical_query, const char *secret, char *signature, size_t cap);
int cdns_tencent_authorization(const char *secret_id, const char *secret_key, const char *host,
                               const char *service, uint64_t timestamp, const char *payload,
                               char *authorization, size_t cap);
#endif
