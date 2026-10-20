#ifndef CIPHERDNS_CLIENT_H
#define CIPHERDNS_CLIENT_H
#include "cipherdns/core.h"
typedef struct {
    cdns_address applied, observed;
    int has_applied, has_observed, retry_hook, cache_dirty;
    int connectivity_known, reachable, attempted_hook;
    uint64_t last_hook_ms;
} cdns_client_state;
/* Invalid, foreign-domain, foreign-key or missing cache leaves empty state. */
int cdns_client_load(const cdns_config *c, const unsigned char key[32], cdns_client_state *s);
/* A NULL TXT represents a failed lookup and preserves all address state. */
int cdns_client_step(const cdns_config *c, const unsigned char key[32], cdns_client_state *s,
                     const char *txt, char *err, size_t cap);
#endif
