#ifndef CIPHERDNS_HTTP_H
#define CIPHERDNS_HTTP_H
#include "core.h"
#define CDNS_HTTP_BODY_MAX 65536
typedef struct {
    int status;
    char *body;
    size_t length;
} cdns_http_response;
/* Only built for SERVER/BOTH. host is DNS name, port is fixed HTTPS 443.
   headers are internally generated, never logged. Response ownership passes to caller. */
int cdns_http_request(const cdns_config *c, const char *host, const char *method, const char *path,
                      const char *headers, const char *body, cdns_http_response *response,
                      char *err, size_t cap);
void cdns_http_free(cdns_http_response *r);
typedef struct {
    int ca_loaded, resolved, connected, tls_ready, certificate_checked;
    uint32_t verify_flags;
} cdns_http_probe_result;
/* Handshake only: no HTTP request and no credentials are sent. */
int cdns_http_probe(const cdns_config *c, const char *host, cdns_http_probe_result *result,
                    char *err, size_t cap);
/* Transport-independent framing parser, used by tests. 1=incomplete, 0=complete, -1=invalid. */
int cdns_http_parse(const unsigned char *wire, size_t n, int eof, cdns_http_response *r, char *err,
                    size_t cap);
#endif
