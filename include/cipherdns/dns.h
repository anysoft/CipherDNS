#ifndef CIPHERDNS_DNS_H
#define CIPHERDNS_DNS_H
#include "cipherdns/core.h"
/* The sole accepted version prefix; unrelated TXT records are ignored. */
#define CDNS_TXT_PREFIX "CD1:"
int cdns_dns_txt_rdata(const unsigned char *rdata, size_t n, char out[256]);
/* Exactly one matching TXT answer is required, including through CNAMEs. */
int cdns_dns_parse_wire(const unsigned char *packet, size_t n, char out[256]);
int cdns_dns_lookup(const char *domain, unsigned timeout_s, char out[256]);
#endif
