#include "cipherdns/http.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
typedef SOCKET netfd;
#define BADFD INVALID_SOCKET
#define netclose closesocket
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
typedef int netfd;
#define BADFD (-1)
#define netclose close
#endif
#define WIRE_MAX (CDNS_HTTP_BODY_MAX * 2 + 16384)
static int error(char *err, size_t cap, const char *msg) {
    snprintf(err, cap, "%s", msg);
    return -1;
}
static int ci(const unsigned char *s, size_t n, const char *lit) {
    if (n != strlen(lit))
        return 0;
    for (size_t i = 0; i < n; i++)
        if (tolower(s[i]) != tolower((unsigned char)lit[i]))
            return 0;
    return 1;
}
static size_t line_end(const unsigned char *s, size_t start, size_t n) {
    for (size_t i = start; i + 1 < n; i++)
        if (s[i] == '\r' && s[i + 1] == '\n')
            return i;
    return SIZE_MAX;
}
static int number(const unsigned char *s, size_t n, size_t *out, unsigned base) {
    if (!n)
        return -1;
    size_t v = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned d = s[i] >= '0' && s[i] <= '9'   ? (unsigned)(s[i] - '0')
                     : s[i] >= 'a' && s[i] <= 'f' ? (unsigned)(s[i] - 'a' + 10)
                     : s[i] >= 'A' && s[i] <= 'F' ? (unsigned)(s[i] - 'A' + 10)
                                                  : base;
        if (d >= base || v > (SIZE_MAX - d) / base)
            return -1;
        v = v * base + d;
    }
    *out = v;
    return 0;
}
void cdns_http_free(cdns_http_response *r) {
    free(r->body);
    memset(r, 0, sizeof(*r));
}
int cdns_http_parse(const unsigned char *wire, size_t n, int eof, cdns_http_response *r, char *err,
                    size_t cap) {
    memset(r, 0, sizeof(*r));
    if (n > WIRE_MAX)
        return error(err, cap, "HTTP response exceeds wire limit");
    size_t end = line_end(wire, 0, n);
    if (end == SIZE_MAX)
        return eof ? error(err, cap, "truncated HTTP status") : 1;
    if (end < 12 || memcmp(wire, "HTTP/1.", 7) || (wire[7] != '0' && wire[7] != '1') ||
        wire[8] != ' ' || !isdigit(wire[9]) || !isdigit(wire[10]) || !isdigit(wire[11]) ||
        (end > 12 && wire[12] != ' '))
        return error(err, cap, "invalid HTTP status");
    int status = (wire[9] - '0') * 100 + (wire[10] - '0') * 10 + wire[11] - '0';
    if (status < 200 || status > 599)
        return error(err, cap, "unsupported HTTP status");
    size_t pos = end + 2, length = 0;
    int cl = 0, te = 0;
    for (;;) {
        end = line_end(wire, pos, n);
        if (end == SIZE_MAX)
            return n > 16384 || eof ? error(err, cap, "invalid/truncated HTTP headers") : 1;
        if (end + 2 > 16384)
            return error(err, cap, "HTTP headers exceed limit");
        if (end == pos) {
            pos += 2;
            break;
        }
        size_t colon = pos;
        while (colon < end && wire[colon] != ':')
            colon++;
        if (colon == pos || colon == end)
            return error(err, cap, "invalid HTTP header");
        for (size_t i = pos; i < colon; i++)
            if (!isalnum(wire[i]) && !strchr("!#$%&'*+-.^_`|~", wire[i]))
                return error(err, cap, "invalid HTTP header name");
        size_t v = colon + 1, e = end;
        while (v < e && (wire[v] == ' ' || wire[v] == '\t'))
            v++;
        while (e > v && (wire[e - 1] == ' ' || wire[e - 1] == '\t'))
            e--;
        for (size_t i = v; i < e; i++)
            if ((wire[i] < 32 && wire[i] != '\t') || wire[i] == 127)
                return error(err, cap, "invalid HTTP header value");
        if (ci(wire + pos, colon - pos, "content-length")) {
            if (cl++ || number(wire + v, e - v, &length, 10) || length > CDNS_HTTP_BODY_MAX)
                return error(err, cap, "invalid HTTP Content-Length");
        } else if (ci(wire + pos, colon - pos, "transfer-encoding")) {
            if (te++ || !ci(wire + v, e - v, "chunked"))
                return error(err, cap, "unsupported HTTP Transfer-Encoding");
        } else if (ci(wire + pos, colon - pos, "content-encoding") &&
                   !ci(wire + v, e - v, "identity"))
            return error(err, cap, "compressed HTTP responses unsupported");
        pos = end + 2;
    }
    if (cl && te)
        return error(err, cap, "ambiguous HTTP response framing");
    char *body = malloc(CDNS_HTTP_BODY_MAX + 1);
    if (!body)
        return error(err, cap, "out of memory");
    size_t used = 0;
    if (te) {
        for (;;) {
            end = line_end(wire, pos, n);
            if (end == SIZE_MAX)
                goto incomplete;
            size_t hexend = pos;
            while (hexend < end && wire[hexend] != ';')
                hexend++;
            size_t chunk;
            if (number(wire + pos, hexend - pos, &chunk, 16) || chunk > CDNS_HTTP_BODY_MAX - used)
                goto invalid;
            pos = end + 2;
            if (!chunk) {
                /* Trailers are framing only; they cannot replace original headers. */
                for (;;) {
                    end = line_end(wire, pos, n);
                    if (end == SIZE_MAX)
                        goto incomplete;
                    if (end == pos) {
                        pos += 2;
                        break;
                    }
                    if (end - pos > 8192)
                        goto invalid;
                    pos = end + 2;
                }
                if (pos != n)
                    goto invalid;
                break;
            }
            if (chunk > n - pos || n - pos - chunk < 2)
                goto incomplete;
            if (wire[pos + chunk] != '\r' || wire[pos + chunk + 1] != '\n')
                goto invalid;
            memcpy(body + used, wire + pos, chunk);
            used += chunk;
            pos += chunk + 2;
        }
    } else if (cl) {
        if (n - pos < length)
            goto incomplete;
        if (n - pos != length)
            goto invalid;
        used = length;
        memcpy(body, wire + pos, used);
    } else {
        if (n - pos > CDNS_HTTP_BODY_MAX)
            goto invalid;
        if (!eof)
            goto incomplete;
        used = n - pos;
        memcpy(body, wire + pos, used);
    }
    if (memchr(body, 0, used))
        goto invalid;
    body[used] = 0;
    r->status = status;
    r->body = body;
    r->length = used;
    return 0;
incomplete:
    free(body);
    return eof ? error(err, cap, "truncated HTTP body") : 1;
invalid:
    free(body);
    return error(err, cap, "invalid or oversized HTTP body");
}
static int waitfd(netfd fd, int writing, uint64_t deadline) {
#ifndef _WIN32
    if (fd < 0 || fd >= FD_SETSIZE)
        return -1;
#endif
    while (!cdns_stopping()) {
        uint64_t now = cdns_mono_ms();
        if (now >= deadline)
            return -1;
        uint64_t left = deadline - now;
        if (left > 500)
            left = 500;
        struct timeval t = {(long)(left / 1000), (long)((left % 1000) * 1000)};
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        int rc = select((int)(fd + 1), writing ? NULL : &set, writing ? &set : NULL, NULL, &t);
        if (rc > 0)
            return 0;
        if (rc < 0) {
#ifndef _WIN32
            if (errno == EINTR)
                continue;
#endif
            return -1;
        }
    }
    return -1;
}
typedef struct {
    unsigned count;
    struct sockaddr_storage addresses[8];
    unsigned lengths[8];
} resolved;
static int resolve(const char *host, resolved *r, uint64_t deadline) {
    memset(r, 0, sizeof(*r));
#ifdef _WIN32
    WCHAR name[256];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host, -1, name, 256))
        return -1;
    ADDRINFOEXW hints, *list = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    uint64_t now = cdns_mono_ms();
    if (now >= deadline)
        return -1;
    struct timeval timeout = {(long)((deadline - now) / 1000),
                              (long)(((deadline - now) % 1000) * 1000)};
    /* Wide API supports a provider timeout; ANSI API does not. */
    int rc = GetAddrInfoExW(name, L"443", NS_DNS, NULL, &hints, &list, &timeout, NULL, NULL, NULL);
    if (rc)
        return -1;
    for (ADDRINFOEXW *i = list; i && r->count < 8; i = i->ai_next)
        if (i->ai_addrlen <= sizeof(struct sockaddr_storage)) {
            memcpy(&r->addresses[r->count], i->ai_addr, i->ai_addrlen);
            r->lengths[r->count++] = (unsigned)i->ai_addrlen;
        }
    FreeAddrInfoExW(list);
#else
    int pipes[2];
    if (pipe(pipes))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipes[0]);
        close(pipes[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipes[0]);
        resolved result;
        memset(&result, 0, sizeof(result));
        struct addrinfo hints, *list = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;
        if (!getaddrinfo(host, "443", &hints, &list)) {
            for (struct addrinfo *i = list; i && result.count < 8; i = i->ai_next)
                if (i->ai_addrlen <= sizeof(struct sockaddr_storage)) {
                    memcpy(&result.addresses[result.count], i->ai_addr, i->ai_addrlen);
                    result.lengths[result.count++] = (unsigned)i->ai_addrlen;
                }
            freeaddrinfo(list);
        }
        size_t pos = 0;
        while (pos < sizeof(result)) {
            ssize_t z = write(pipes[1], (char *)&result + pos, sizeof(result) - pos);
            if (z < 0 && errno == EINTR)
                continue;
            if (z <= 0)
                break;
            pos += (size_t)z;
        }
        close(pipes[1]);
        _exit(0);
    }
    close(pipes[1]);
    size_t pos = 0;
    while (pos < sizeof(*r) && !waitfd(pipes[0], 0, deadline)) {
        ssize_t z = read(pipes[0], (char *)r + pos, sizeof(*r) - pos);
        if (z < 0 && errno == EINTR)
            continue;
        if (z <= 0)
            break;
        pos += (size_t)z;
    }
    close(pipes[0]);
    if (pos < sizeof(*r))
        kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
    if (pos != sizeof(*r))
        return -1;
#endif
    return r->count ? 0 : -1;
}
static netfd connect_host(const char *host, uint64_t deadline, cdns_http_probe_result *probe) {
    resolved r;
    if (resolve(host, &r, deadline))
        return BADFD;
    if (probe)
        probe->resolved = 1;
    for (unsigned i = 0; i < r.count; i++) {
        netfd fd = socket(r.addresses[i].ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (fd == BADFD)
            continue;
#ifdef _WIN32
        u_long nonblock = 1;
        if (ioctlsocket(fd, FIONBIO, &nonblock)) {
            netclose(fd);
            continue;
        }
#else
        if (fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
            netclose(fd);
            continue;
        }
#ifdef SO_NOSIGPIPE
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#endif
        int rc = connect(fd, (struct sockaddr *)&r.addresses[i], (int)r.lengths[i]);
        if (rc != 0) {
#ifdef _WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                netclose(fd);
                continue;
            }
#else
            if (errno != EINPROGRESS) {
                netclose(fd);
                continue;
            }
#endif
            uint64_t part = cdns_mono_ms() + 3000;
            if (part > deadline)
                part = deadline;
            if (waitfd(fd, 1, part)) {
                netclose(fd);
                continue;
            }
            int e = 0;
#ifdef _WIN32
            int len = sizeof(e);
#else
            socklen_t len = sizeof(e);
#endif
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&e, &len) || e) {
                netclose(fd);
                continue;
            }
        }
        if (probe)
            probe->connected = 1;
        return fd;
    }
    return BADFD;
}
static int tls_random(void *ctx, unsigned char *out, size_t n) {
    (void)ctx;
    return cdns_random(out, n);
}
static int tls_send(void *ctx, const unsigned char *buf, size_t n) {
    netfd fd = *(netfd *)ctx;
#ifdef MSG_NOSIGNAL
    int flags = MSG_NOSIGNAL;
#else
    int flags = 0;
#endif
    int rc = (int)send(fd, (const char *)buf, (int)n, flags);
    if (rc >= 0)
        return rc;
#ifdef _WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK)
        return MBEDTLS_ERR_SSL_WANT_WRITE;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int tls_recv(void *ctx, unsigned char *buf, size_t n) {
    int rc = (int)recv(*(netfd *)ctx, (char *)buf, (int)n, 0);
    if (rc >= 0)
        return rc;
#ifdef _WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK)
        return MBEDTLS_ERR_SSL_WANT_READ;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return MBEDTLS_ERR_SSL_WANT_READ;
#endif
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int load_ca(mbedtls_x509_crt *ca, const char *path) {
    if (path[0])
        return mbedtls_x509_crt_parse_file(ca, path) >= 0 && ca->raw.p ? 0 : -1;
#ifdef _WIN32
    HCERTSTORE store = CertOpenSystemStoreA(0, "ROOT");
    if (!store)
        return -1;
    PCCERT_CONTEXT cert = NULL;
    unsigned count = 0;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL)
        if (!mbedtls_x509_crt_parse_der(ca, cert->pbCertEncoded, cert->cbCertEncoded))
            count++;
    CertCloseStore(store, 0);
    return count ? 0 : -1;
#else
    static const char *paths[] = {"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem",
                                  "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (mbedtls_x509_crt_parse_file(ca, paths[i]) >= 0 && ca->raw.p)
            return 0;
    return -1;
#endif
}
static uint64_t minimum(uint64_t a, uint64_t b) {
    return a < b ? a : b;
}
/* Both diagnostics and API requests use exactly the same verification path. */
static int tls_open(const cdns_config *c, const char *host, mbedtls_ssl_context *ssl,
                    mbedtls_ssl_config *conf, mbedtls_x509_crt *ca, netfd *fd, uint64_t deadline,
                    cdns_http_probe_result *probe, char *err, size_t cap) {
    uint64_t start = cdns_mono_ms();
    if (start >= deadline)
        return error(err, cap, "DNS API operation timed out");
    if (probe) {
        *fd = connect_host(host, minimum(deadline, start + (uint64_t)c->connect_timeout * 1000),
                           probe);
        if (*fd == BADFD)
            return error(err, cap, "HTTPS name resolution/connect failed or timed out");
    }
    if (load_ca(ca, c->ca_file))
        return error(err, cap, "no trusted CA bundle; configure dns.ca_file");
    if (probe)
        probe->ca_loaded = 1;
    if (mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT))
        return error(err, cap, "TLS configuration failed");
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(conf, ca, NULL);
    mbedtls_ssl_conf_rng(conf, tls_random, NULL);
    if (mbedtls_ssl_setup(ssl, conf) || mbedtls_ssl_set_hostname(ssl, host))
        return error(err, cap, "TLS initialization failed");
    if (*fd == BADFD)
        *fd = connect_host(host, minimum(deadline, start + (uint64_t)c->connect_timeout * 1000),
                           NULL);
    if (*fd == BADFD)
        return error(err, cap, "HTTPS name resolution/connect failed or timed out");
    mbedtls_ssl_set_bio(ssl, fd, tls_send, tls_recv, NULL);
    int rc;
    uint64_t handshake_deadline =
        minimum(deadline, cdns_mono_ms() + (uint64_t)c->read_timeout * 1000);
    while ((rc = mbedtls_ssl_handshake(ssl)) != 0) {
        if ((rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) ||
            waitfd(*fd, rc == MBEDTLS_ERR_SSL_WANT_WRITE, handshake_deadline)) {
            if (probe && rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                probe->certificate_checked = 1;
                probe->verify_flags = mbedtls_ssl_get_verify_result(ssl);
            }
            return error(err, cap, "TLS handshake/certificate verification failed or timed out");
        }
    }
    uint32_t flags = mbedtls_ssl_get_verify_result(ssl);
    if (probe) {
        probe->certificate_checked = 1;
        probe->verify_flags = flags;
    }
    if (flags)
        return error(err, cap, "TLS certificate verification failed");
    if (probe)
        probe->tls_ready = 1;
    return 0;
}
int cdns_http_probe(const cdns_config *c, const char *host, cdns_http_probe_result *result,
                    char *err, size_t cap) {
    memset(result, 0, sizeof(*result));
    if (!host || !*host || strpbrk(host, "\r\n /:"))
        return error(err, cap, "invalid HTTPS hostname");
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);
    netfd fd = BADFD;
    uint64_t deadline = cdns_mono_ms() + (uint64_t)c->update_timeout * 1000;
    if (c->api_deadline_ms)
        deadline = minimum(deadline, c->api_deadline_ms);
    int rc = tls_open(c, host, &ssl, &conf, &ca, &fd, deadline, result, err, cap);
    if (fd != BADFD)
        netclose(fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&ca);
    return rc;
}
int cdns_http_request(const cdns_config *c, const char *host, const char *method, const char *path,
                      const char *headers, const char *body, cdns_http_response *response,
                      char *err, size_t cap) {
    memset(response, 0, sizeof(*response));
    if (!body)
        body = "";
    if (!headers)
        headers = "";
    if ((strcmp(method, "GET") && strcmp(method, "POST") && strcmp(method, "PUT") &&
         strcmp(method, "PATCH")) ||
        path[0] != '/' || strpbrk(path, "\r\n ") || strpbrk(host, "\r\n /:") ||
        strlen(body) > CDNS_HTTP_BODY_MAX)
        return error(err, cap, "invalid HTTPS request");
    size_t request_cap = strlen(path) + strlen(headers) + strlen(body) + strlen(host) + 512;
    char *request = malloc(request_cap);
    unsigned char *wire = malloc(WIRE_MAX + 1);
    if (!request || !wire) {
        free(request);
        free(wire);
        return error(err, cap, "out of memory");
    }
    int length = snprintf(request, request_cap,
                          "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: CipherDNS/" CDNS_VERSION
                          "\r\nAccept: application/json\r\nAccept-Encoding: "
                          "identity\r\nConnection: close\r\n%sContent-Length: %zu\r\n\r\n%s",
                          method, path, host, headers, strlen(body), body);
    if (length < 0 || (size_t)length >= request_cap) {
        free(request);
        free(wire);
        return error(err, cap, "HTTPS request too large");
    }
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);
    netfd fd = BADFD;
    int result = -1;
    uint64_t start = cdns_mono_ms(), deadline = start + (uint64_t)c->update_timeout * 1000;
    if (c->api_deadline_ms)
        deadline = minimum(deadline, c->api_deadline_ms);
    if (start >= deadline) {
        error(err, cap, "DNS API operation timed out");
        goto done;
    }
    if (tls_open(c, host, &ssl, &conf, &ca, &fd, deadline, NULL, err, cap))
        goto done;
    int rc;
    uint64_t idle;
    size_t pos = 0;
    while (pos < (size_t)length) {
        if (cdns_mono_ms() >= deadline) {
            error(err, cap, "HTTPS write timed out");
            goto done;
        }
        size_t chunk = (size_t)length - pos;
        if (chunk > MBEDTLS_SSL_OUT_CONTENT_LEN)
            chunk = MBEDTLS_SSL_OUT_CONTENT_LEN;
        rc = mbedtls_ssl_write(&ssl, (unsigned char *)request + pos, chunk);
        if (rc > 0) {
            pos += (size_t)rc;
            continue;
        }
        if ((rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) ||
            waitfd(fd, rc == MBEDTLS_ERR_SSL_WANT_WRITE, deadline)) {
            error(err, cap, "HTTPS write failed or timed out");
            goto done;
        }
    }
    pos = 0;
    idle = minimum(deadline, cdns_mono_ms() + (uint64_t)c->read_timeout * 1000);
    for (;;) {
        if (cdns_mono_ms() >= deadline || cdns_stopping()) {
            error(err, cap, "HTTPS response timed out");
            goto done;
        }
        if (pos == WIRE_MAX) {
            error(err, cap, "HTTP response exceeds limit");
            goto done;
        }
        rc = mbedtls_ssl_read(&ssl, wire + pos, WIRE_MAX - pos);
        if (rc > 0) {
            pos += (size_t)rc;
            idle = minimum(deadline, cdns_mono_ms() + (uint64_t)c->read_timeout * 1000);
            int parsed = cdns_http_parse(wire, pos, 0, response, err, cap);
            if (parsed < 0)
                goto done;
            if (!parsed) {
                result = 0;
                break;
            }
        } else if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            result = cdns_http_parse(wire, pos, 1, response, err, cap);
            break;
        } else if ((rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) ||
                   waitfd(fd, rc == MBEDTLS_ERR_SSL_WANT_WRITE, idle)) {
            error(err, cap, "HTTPS read failed or timed out");
            goto done;
        }
    }
done:
    if (fd != BADFD)
        netclose(fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&ca);
    cdns_zero(request, request_cap);
    free(request);
    free(wire);
    return result;
}
