#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "cipherdns/dns.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
#else
#include <errno.h>
#include <poll.h>
#include <resolv.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static unsigned u16(const unsigned char *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

int cdns_dns_txt_rdata(const unsigned char *rdata, size_t n, char out[256]) {
    size_t pos = 0, used = 0;
    if (!rdata || !n || !out)
        return -1;
    while (pos < n) {
        size_t len = rdata[pos++];
        if (len > n - pos || len > CDNS_TEXT_MAX - used)
            return -1;
        if (memchr(rdata + pos, 0, len))
            return -1;
        memcpy(out + used, rdata + pos, len);
        pos += len;
        used += len;
    }
    out[used] = 0;
    return 0;
}

static int select_txt(const unsigned char *rdata, size_t n, char out[256]) {
    size_t at = 0, used = 0;
    char prefix[sizeof(CDNS_TXT_PREFIX) - 1];
    while (at < n) {
        size_t len = rdata[at++], i;
        if (len > n - at)
            return -1;
        for (i = 0; i < len && used + i < sizeof prefix; ++i)
            prefix[used + i] = (char)rdata[at + i];
        used += len;
        at += len;
    }
    if (used < sizeof prefix || memcmp(prefix, CDNS_TXT_PREFIX, sizeof prefix))
        return 0;
    return cdns_dns_txt_rdata(rdata, n, out) ? -1 : 1;
}

/* Decode compression pointers with a bounded traversal, including loop detection. */
static int name_read(const unsigned char *p, size_t n, size_t *offset, char out[254]) {
    size_t at = *offset, end = 0, used = 0, steps = 0;
    int jumped = 0;
    for (;;) {
        unsigned len;
        if (at >= n || ++steps > 256)
            return -1;
        len = p[at++];
        if ((len & 0xc0u) == 0xc0u) {
            size_t target;
            if (at >= n)
                return -1;
            target = ((size_t)(len & 0x3fu) << 8) | p[at++];
            if (target >= n)
                return -1;
            if (!jumped)
                end = at;
            jumped = 1;
            at = target;
            continue;
        }
        if (len & 0xc0u)
            return -1;
        if (!len)
            break;
        if (len > n - at || used + (used ? 1u : 0u) + len >= 254)
            return -1;
        if (used)
            out[used++] = '.';
        while (len--) {
            unsigned char ch = p[at++];
            if (!ch || ch == '.')
                return -1;
            out[used++] = (char)tolower(ch);
        }
    }
    out[used] = 0;
    *offset = jumped ? end : at;
    return 0;
}

typedef struct {
    char owner[254];
    unsigned type, class_;
    size_t at, len;
} answer;
int cdns_dns_parse_wire(const unsigned char *p, size_t n, char out[256]) {
    answer records[128];
    char query[254], canonical[254], payload[256];
    size_t at = 12;
    unsigned count, matching = 0, i, hops;
    if (!p || !out || n < 12 || !(p[2] & 0x80u) || (p[2] & 0x7au) || (p[3] & 0x0fu) ||
        u16(p + 4) != 1)
        return -1;
    count = u16(p + 6);
    if (!count || count > 128 || name_read(p, n, &at, query) || at + 4 > n || u16(p + at) != 16 ||
        u16(p + at + 2) != 1)
        return -1;
    at += 4;
    for (i = 0; i < count; ++i) {
        if (name_read(p, n, &at, records[i].owner) || at + 10 > n)
            return -1;
        records[i].type = u16(p + at);
        records[i].class_ = u16(p + at + 2);
        records[i].len = u16(p + at + 8);
        at += 10;
        records[i].at = at;
        if (records[i].len > n - at)
            return -1;
        at += records[i].len;
    }
    memcpy(canonical, query, sizeof canonical);
    for (hops = 0; hops < 16; ++hops) {
        int found = 0;
        for (i = 0; i < count; ++i)
            if (records[i].type == 5 && records[i].class_ == 1 &&
                !strcmp(records[i].owner, canonical)) {
                size_t cursor = records[i].at;
                char target[254];
                if (found || name_read(p, n, &cursor, target) ||
                    cursor != records[i].at + records[i].len)
                    return -1;
                memcpy(payload, target, strlen(target) + 1);
                found = 1;
            }
        if (!found)
            break;
        if (!strcmp(canonical, payload))
            return -1;
        memcpy(canonical, payload, strlen(payload) + 1);
    }
    if (hops == 16)
        return -1;
    for (i = 0; i < count; ++i)
        if (records[i].type == 16 && records[i].class_ == 1 &&
            !strcmp(records[i].owner, canonical)) {
            int selected = select_txt(p + records[i].at, records[i].len, payload);
            if (selected < 0)
                return -1;
            if (selected) {
                if (++matching > 1)
                    return -1;
                memcpy(out, payload, strlen(payload) + 1);
            }
        }
    return matching == 1 ? 0 : -1;
}

#ifdef _WIN32
/* MinGW SDK versions omit the Win8 request/cancel declarations. Keep local ABI
 * types from the documented Windows API and resolve those two entry points;
 * the DNS record/result structures still come from the platform SDK. */
typedef struct {
    ULONG Version;
    PCWSTR QueryName;
    WORD QueryType;
    ULONG64 QueryOptions;
    PVOID pDnsServerList;
    ULONG InterfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE pQueryCompletionCallback;
    PVOID pQueryContext;
} cdns_dns_request;
typedef struct {
    CHAR Reserved[32];
} cdns_dns_cancel;
typedef DNS_STATUS(WINAPI *cdns_query_ex_fn)(cdns_dns_request *, PDNS_QUERY_RESULT,
                                             cdns_dns_cancel *);
typedef DNS_STATUS(WINAPI *cdns_cancel_query_fn)(cdns_dns_cancel *);
typedef struct {
    LONG references;
    HANDLE event;
    DNS_QUERY_RESULT result;
    cdns_dns_cancel cancel;
    cdns_dns_request request;
    WCHAR name[254];
} query_context;
static void release_query(query_context *q) {
    if (InterlockedDecrement(&q->references) == 0) {
        if (q->result.pQueryRecords)
            DnsRecordListFree(q->result.pQueryRecords, DnsFreeRecordList);
        CloseHandle(q->event);
        free(q);
    }
}
static VOID WINAPI query_done(PVOID context, PDNS_QUERY_RESULT result) {
    query_context *q = context;
    (void)result;
    SetEvent(q->event);
    release_query(q);
}
int cdns_dns_lookup(const char *domain, unsigned timeout_s, char out[256]) {
    HMODULE module = GetModuleHandleW(L"dnsapi.dll");
    FARPROC query_proc, cancel_proc;
    cdns_query_ex_fn query_ex;
    cdns_cancel_query_fn cancel_query;
    DNS_STATUS status;
    query_context *q = calloc(1, sizeof *q);
    int rc = -1;
    unsigned matches = 0;
    if (!q || !domain || !timeout_s || !out || !module) {
        free(q);
        return -1;
    }
    query_proc = GetProcAddress(module, "DnsQueryEx");
    cancel_proc = GetProcAddress(module, "DnsCancelQuery");
    if (!query_proc || !cancel_proc) {
        free(q);
        return -1;
    }
    _Static_assert(sizeof query_ex == sizeof query_proc, "Windows function pointer size");
    _Static_assert(sizeof cancel_query == sizeof cancel_proc, "Windows function pointer size");
    memcpy(&query_ex, &query_proc, sizeof query_ex);
    memcpy(&cancel_query, &cancel_proc, sizeof cancel_query);
    q->references = 2;
    q->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!q->event ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, domain, -1, q->name, 254)) {
        if (q->event)
            CloseHandle(q->event);
        free(q);
        return -1;
    }
    q->request.Version = DNS_QUERY_REQUEST_VERSION1;
    q->request.QueryName = q->name;
    q->request.QueryType = DNS_TYPE_TEXT;
    q->request.QueryOptions = DNS_QUERY_TREAT_AS_FQDN;
    q->request.pQueryCompletionCallback = query_done;
    q->request.pQueryContext = q;
    q->result.Version = DNS_QUERY_RESULTS_VERSION1;
    status = query_ex(&q->request, &q->result, &q->cancel);
    if (status == DNS_REQUEST_PENDING) {
        uint64_t deadline = cdns_mono_ms() + (uint64_t)timeout_s * 1000;
        for (;;) {
            DWORD wait = WaitForSingleObject(q->event, 50);
            if (wait == WAIT_OBJECT_0) {
                status = q->result.QueryStatus;
                break;
            }
            if (wait == WAIT_FAILED || cdns_stopping() || cdns_mono_ms() >= deadline) {
                cancel_query(&q->cancel);
                release_query(q);
                return -1;
            }
        }
    } else
        release_query(q); /* No callback for a synchronous completion. */
    if (status == ERROR_SUCCESS) {
        PDNS_RECORDW r;
        rc = 0;
        for (r = (PDNS_RECORDW)q->result.pQueryRecords; r; r = r->pNext)
            if (r->wType == DNS_TYPE_TEXT) {
                DWORD i;
                size_t used = 0;
                char joined[256];
                int invalid = 0;
                memset(joined, 0, sizeof joined);
                for (i = 0; i < r->Data.TXT.dwStringCount; ++i) {
                    const WCHAR *s = r->Data.TXT.pStringArray[i];
                    while (*s) {
                        if (*s > 127 || used >= CDNS_TEXT_MAX)
                            invalid = 1;
                        if (used < CDNS_TEXT_MAX)
                            joined[used] = *s <= 127 ? (char)*s : '?';
                        ++used;
                        ++s;
                    }
                }
                if (!strncmp(joined, CDNS_TXT_PREFIX, sizeof(CDNS_TXT_PREFIX) - 1)) {
                    if (invalid) {
                        rc = -1;
                        break;
                    }
                    if (++matches > 1) {
                        rc = -1;
                        break;
                    }
                    memcpy(out, joined, used + 1);
                }
            }
    }
    release_query(q);
    return !rc && matches == 1 ? 0 : -1;
}
#else
int cdns_dns_lookup(const char *domain, unsigned timeout_s, char out[256]) {
    struct result {
        int status;
        char txt[256];
    } result;
    int fds[2], status, rc = -1;
    pid_t pid;
    size_t got = 0;
    uint64_t deadline;
    if (!domain || !out || !timeout_s || pipe(fds))
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (!pid) {
        unsigned char packet[65536];
        int length;
        close(fds[0]);
        memset(&result, 0, sizeof result);
        length = res_query(domain, 1, 16, packet, (int)sizeof packet);
        result.status = length > 0 && (size_t)length <= sizeof packet
                            ? cdns_dns_parse_wire(packet, (size_t)length, result.txt)
                            : -1;
        if (write(fds[1], &result, sizeof result) < 0) { /* Parent may time out. */
        }
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    deadline = cdns_mono_ms() + (uint64_t)timeout_s * 1000;
    while (got < sizeof result && !cdns_stopping()) {
        struct pollfd pfd;
        uint64_t now = cdns_mono_ms();
        int ready;
        if (now >= deadline)
            break;
        pfd.fd = fds[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        ready = poll(&pfd, 1, (int)((deadline - now) > 50 ? 50 : deadline - now));
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ready > 0) {
            ssize_t bytes = read(fds[0], (unsigned char *)&result + got, sizeof result - got);
            if (bytes < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (!bytes)
                break;
            got += (size_t)bytes;
        }
    }
    close(fds[0]);
    if (got == sizeof result && !result.status) {
        memcpy(out, result.txt, sizeof result.txt);
        rc = 0;
    }
    /* Always reap, including timeouts; the resolver cannot outlive this call. */
    if (got != sizeof result)
        kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return rc;
}
#endif
