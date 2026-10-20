#include "cipherdns/http.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void check(const char *wire, int eof, int expected, const char *body) {
    char err[256];
    cdns_http_response r;
    int rc = cdns_http_parse((const unsigned char *)wire, strlen(wire), eof, &r, err, sizeof(err));
    assert(rc == expected);
    if (rc == 0) {
        assert(!strcmp(r.body, body));
        cdns_http_free(&r);
    }
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--live")) {
        cdns_config c = {0};
        cdns_http_response r;
        char err[256];
        c.connect_timeout = 10;
        c.read_timeout = 10;
        c.update_timeout = 20;
        assert(cdns_platform_init() == 0);
        if (cdns_http_request(&c, "api.cloudflare.com", "GET", "/client/v4/user/tokens/verify",
                              NULL, NULL, &r, err, sizeof(err))) {
            fprintf(stderr, "live HTTPS failed: %s\n", err);
            return 1;
        }
        printf("live verified HTTPS status=%d bytes=%zu\n", r.status, r.length);
        assert(r.status >= 400 && r.status < 500);
        cdns_http_free(&r);
        strcpy(c.ca_file, "/nonexistent/cipherdns-test-ca.pem");
        assert(cdns_http_request(&c, "api.cloudflare.com", "GET", "/", NULL, NULL, &r, err,
                                 sizeof(err)) != 0);
        cdns_platform_cleanup();
        return 0;
    }
    check("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", 0, 0, "{}");
    check("HTTP/1.1 200 OK\r\nTransfer-Encoding: "
          "chunked\r\n\r\n1\r\n{\r\n1;foo=bar\r\n}\r\n0\r\n\r\n",
          0, 0, "{}");
    check("HTTP/1.1 200 OK\r\n\r\n{}", 1, 0, "{}");
    check("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}", 0, 1, NULL);
    check("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}", 1, -1, NULL);
    check("HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\n", 0, -1, NULL);
    check("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 0, -1, NULL);
    check("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}", 0, -1,
          NULL);
    check("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFFFFFF\r\n", 0,
          -1, NULL);
    const char *s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
    for (size_t i = 0; i < strlen(s); i++) {
        cdns_http_response r;
        char err[256];
        assert(cdns_http_parse((const unsigned char *)s, i, 0, &r, err, sizeof(err)) == 1);
    }
    static const unsigned char mutations[] = {0, 1, 10, 13, 32, 127, 128, 255};
    for (size_t i = 0; i < strlen(s); i++)
        for (size_t k = 0; k < sizeof(mutations); k++) {
            unsigned char copy[256];
            size_t len = strlen(s);
            memcpy(copy, s, len);
            copy[i] = mutations[k];
            cdns_http_response r;
            char err[256];
            int rc = cdns_http_parse(copy, len, 1, &r, err, sizeof(err));
            if (rc == 0)
                cdns_http_free(&r);
            else
                assert(rc == -1);
        }
    puts("HTTP framing tests passed");
    return 0;
}
