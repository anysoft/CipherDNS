#include "jsmn.h"
#include "cipherdns/json.h"
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
/* jsmn tokenizes. Validate actual JSON grammar first (jsmn alone tolerates missing commas). */
static void ws(const char **s) {
    while (**s == ' ' || **s == '\t' || **s == '\r' || **s == '\n')
        ++*s;
}
static int str(const char **s) {
    if (*(*s)++ != '"')
        return -1;
    while (**s && **s != '"') {
        unsigned char c = (unsigned char)*(*s)++;
        if (c < 32)
            return -1;
        if (c == '\\') {
            c = (unsigned char)*(*s)++;
            if (!c)
                return -1;
            if (c == 'u') {
                for (int i = 0; i < 4; i++) {
                    if (!isxdigit((unsigned char)**s))
                        return -1;
                    ++*s;
                }
            } else if (!strchr("\"\\/bfnrt", c))
                return -1;
        }
    }
    if (**s != '"')
        return -1;
    ++*s;
    return 0;
}
static int value(const char **s, unsigned depth) {
    if (depth > 32)
        return -1;
    ws(s);
    if (**s == '"')
        return str(s);
    if (**s == '{' || **s == '[') {
        int obj = **s == '{';
        char end = obj ? '}' : ']';
        ++*s;
        ws(s);
        if (**s == end) {
            ++*s;
            return 0;
        }
        for (;;) {
            if (obj) {
                if (**s != '"' || str(s))
                    return -1;
                ws(s);
                if (*(*s)++ != ':')
                    return -1;
            }
            if (value(s, depth + 1))
                return -1;
            ws(s);
            if (**s == end) {
                ++*s;
                return 0;
            }
            if (*(*s)++ != ',')
                return -1;
            ws(s);
        }
    }
    const char *p = *s;
    const char *lit = NULL;
    if (*p == 't')
        lit = "true";
    else if (*p == 'f')
        lit = "false";
    else if (*p == 'n')
        lit = "null";
    if (lit) {
        size_t n = strlen(lit);
        if (strncmp(p, lit, n))
            return -1;
        *s += n;
        return 0;
    }
    if (*p == '-')
        p++;
    if (*p == '0')
        p++;
    else {
        if (*p < '1' || *p > '9')
            return -1;
        while (isdigit((unsigned char)*p))
            p++;
    }
    if (*p == '.') {
        p++;
        if (!isdigit((unsigned char)*p))
            return -1;
        while (isdigit((unsigned char)*p))
            p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!isdigit((unsigned char)*p))
            return -1;
        while (isdigit((unsigned char)*p))
            p++;
    }
    *s = p;
    return 0;
}
int cdns_json_parse(cdns_json *j, const char *text) {
    const char *p = text;
    jsmn_parser parser;
    if (!text || strlen(text) > 65536 || value(&p, 0))
        return -1;
    ws(&p);
    if (*p)
        return -1;
    jsmn_init(&parser);
    j->text = text;
    j->count = jsmn_parse(&parser, text, strlen(text), j->tokens, 2048);
    if (j->count <= 0)
        return -1;
    /* Duplicate keys make success/error fields ambiguous. Reject them, including
       names written with equivalent JSON escapes. API keys are bounded ASCII. */
    for (int o = 0; o < j->count; o++)
        if (j->tokens[o].type == JSMN_OBJECT) {
            for (int a = o + 1; a < j->count && j->tokens[a].start < j->tokens[o].end;) {
                char ka[256];
                if (cdns_json_string(j, a, ka, sizeof(ka)))
                    return -1;
                for (int b = o + 1; b < a;) {
                    char kb[256];
                    if (cdns_json_string(j, b, kb, sizeof(kb)) || !strcmp(ka, kb))
                        return -1;
                    b = cdns_json_next(j, b + 1);
                }
                a = cdns_json_next(j, a + 1);
            }
        }
    return 0;
}
int cdns_json_next(const cdns_json *j, int t) {
    if (t < 0 || t >= j->count)
        return j->count;
    int e = j->tokens[t].end;
    t++;
    while (t < j->count && j->tokens[t].start < e)
        t++;
    return t;
}
int cdns_json_eq(const cdns_json *j, int t, const char *s) {
    return t >= 0 && t < j->count && (size_t)(j->tokens[t].end - j->tokens[t].start) == strlen(s) &&
           !memcmp(j->text + j->tokens[t].start, s, strlen(s));
}
int cdns_json_get(const cdns_json *j, int object, const char *key) {
    if (object < 0 || object >= j->count || j->tokens[object].type != JSMN_OBJECT)
        return -1;
    int found = -1;
    for (int i = object + 1; i < j->count && j->tokens[i].start < j->tokens[object].end;) {
        int v = i + 1;
        if (v >= j->count)
            return -1;
        char decoded[256];
        if (cdns_json_string(j, i, decoded, sizeof(decoded)))
            return -1;
        if (!strcmp(decoded, key)) {
            if (found != -1)
                return -1;
            found = v;
        }
        i = cdns_json_next(j, v);
    }
    return found;
}
int cdns_json_string(const cdns_json *j, int t, char *out, size_t cap) {
    if (t < 0 || t >= j->count || j->tokens[t].type != JSMN_STRING || cap == 0)
        return -1;
    size_t n = 0;
    for (int i = j->tokens[t].start; i < j->tokens[t].end; i++) {
        unsigned char c = (unsigned char)j->text[i];
        if (c == '\\') {
            c = (unsigned char)j->text[++i];
            if (c == 'u') {
                char hex[5];
                memcpy(hex, j->text + i + 1, 4);
                hex[4] = 0;
                unsigned long v = strtoul(hex, NULL, 16);
                if (v == 0 || v > 127)
                    return -1;
                c = (unsigned char)v;
                i += 4;
            } else if (c == 'b')
                c = '\b';
            else if (c == 'f')
                c = '\f';
            else if (c == 'n')
                c = '\n';
            else if (c == 'r')
                c = '\r';
            else if (c == 't')
                c = '\t';
        }
        if (n + 1 >= cap)
            return -1;
        out[n++] = (char)c;
    }
    out[n] = 0;
    return 0;
}
int cdns_json_uint(const cdns_json *j, int t, unsigned long long *out) {
    if (t < 0 || t >= j->count || j->tokens[t].type != JSMN_PRIMITIVE)
        return -1;
    unsigned long long v = 0;
    for (int i = j->tokens[t].start; i < j->tokens[t].end; i++) {
        unsigned char c = (unsigned char)j->text[i];
        if (c < '0' || c > '9' || v > (ULLONG_MAX - (c - '0')) / 10)
            return -1;
        v = v * 10 + (c - '0');
    }
    *out = v;
    return 0;
}
