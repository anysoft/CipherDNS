#ifndef CIPHERDNS_JSON_H
#define CIPHERDNS_JSON_H
#include <stddef.h>
#define JSMN_HEADER
#include "jsmn.h"
#undef JSMN_HEADER
typedef struct {
    const char *text;
    jsmntok_t tokens[2048];
    int count;
} cdns_json;
int cdns_json_parse(cdns_json *j, const char *text);
int cdns_json_get(const cdns_json *j, int object, const char *key);
int cdns_json_next(const cdns_json *j, int token);
int cdns_json_string(const cdns_json *j, int token, char *out, size_t cap);
int cdns_json_eq(const cdns_json *j, int token, const char *s);
int cdns_json_uint(const cdns_json *j, int token, unsigned long long *out);
#endif
