#include "cipherdns/core.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
void cdns_log(const char *level, const char *fmt, ...) {
    char stamp[32];
    time_t now = time(NULL);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
    fprintf(stderr, "%s [%s] ", stamp, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
