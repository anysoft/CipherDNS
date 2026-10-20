#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif
#include "cipherdns/core.h"
#include "cipherdns/client.h"
#include "cipherdns/dns.h"
#include "cipherdns/http.h"
#include "cipherdns/json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Only the HTTP boundary is replaced. Provider request/response logic, AES,
 * DNS wire TXT parsing, client state and process execution remain real. */
static char provider_txt[256];
static unsigned requests, creates, updates;
static int fail_next_write;
int cdns_http_request(const cdns_config *c, const char *host, const char *method, const char *path,
                      const char *headers, const char *body, cdns_http_response *response,
                      char *err, size_t cap) {
    char reply[2048];
    ++requests;
    assert(!strcmp(host, "api.cloudflare.com"));
    assert(strstr(path, "/client/v4/zones/test-zone/dns_records"));
    assert(strstr(headers, "Authorization: Bearer test-token\r\n"));
    if (!strcmp(method, "GET")) {
        assert(!body && strstr(path, "?type=TXT&name.exact=example.com&per_page=100&page=1"));
        if (*provider_txt)
            snprintf(reply, sizeof reply,
                     "{\"success\":true,\"result\":[{\"id\":\"record1\",\"type\":\"TXT\",\"name\":"
                     "\"example.com\",\"content\":\"%s\",\"ttl\":60}],\"result_info\":{\"total_"
                     "count\":1}}",
                     provider_txt);
        else
            snprintf(reply, sizeof reply,
                     "{\"success\":true,\"result\":[],\"result_info\":{\"total_count\":0}}");
    } else {
        cdns_json json;
        char content[256], name[254], type[8];
        assert(body && !cdns_json_parse(&json, body));
        assert(
            !cdns_json_string(&json, cdns_json_get(&json, 0, "content"), content, sizeof content));
        assert(!cdns_json_string(&json, cdns_json_get(&json, 0, "name"), name, sizeof name));
        assert(!cdns_json_string(&json, cdns_json_get(&json, 0, "type"), type, sizeof type));
        assert(!strcmp(name, c->domain) && !strcmp(type, "TXT"));
        {
            size_t n = strlen(content);
            assert(n >= 2 && content[0] == '"' && content[n - 1] == '"');
            memmove(content, content + 1, n - 2);
            content[n - 2] = 0;
        }
        assert(!strncmp(content, "CD1:", 4));
        if (fail_next_write) {
            fail_next_write = 0;
            snprintf(err, cap, "simulated network outage");
            return -1;
        }
        if (*provider_txt) {
            assert(!strcmp(method, "PATCH"));
            assert(strstr(path, "/record1"));
            ++updates;
        } else {
            assert(!strcmp(method, "POST"));
            ++creates;
        }
        snprintf(provider_txt, sizeof provider_txt, "%s", content);
        snprintf(reply, sizeof reply, "{\"success\":true,\"result\":{\"id\":\"record1\"}}");
    }
    response->length = strlen(reply);
    response->status = 200;
    response->body = malloc(response->length + 1);
    assert(response->body);
    memcpy(response->body, reply, response->length + 1);
    return 0;
}
void cdns_http_free(cdns_http_response *response) {
    free(response->body);
    memset(response, 0, sizeof *response);
}

static int dns_bridge(char out[256]) {
    unsigned char packet[512] = {0};
    static const unsigned char question[] = {7,   'e', 'x', 'a', 'm', 'p', 'l', 'e', 3,
                                             'c', 'o', 'm', 0,   0,   16,  0,   1};
    size_t n = 12, length = strlen(provider_txt), rdata;
    if (length < 4 || length > 255)
        return -1;
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[5] = 1;
    packet[7] = 1;
    memcpy(packet + n, question, sizeof question);
    n += sizeof question;
    packet[n++] = 0xc0;
    packet[n++] = 12;
    packet[n++] = 0;
    packet[n++] = 16;
    packet[n++] = 0;
    packet[n++] = 1;
    n += 4;
    rdata = length + 2;
    packet[n++] = (unsigned char)(rdata >> 8);
    packet[n++] = (unsigned char)rdata;
    /* Deliberately split the version prefix over two DNS character strings. */
    packet[n++] = 2;
    memcpy(packet + n, provider_txt, 2);
    n += 2;
    packet[n++] = (unsigned char)(length - 2);
    memcpy(packet + n, provider_txt + 2, length - 2);
    n += length - 2;
    return cdns_dns_parse_wire(packet, n, out);
}
static int hook_write(const char *path, int fail_hook) {
    const char *script;
#ifdef _WIN32
    script = fail_hook
                 ? "exit 7\n"
                 : "param([string]$StateFile)\nif (!(Test-Path -LiteralPath $StateFile)) { exit 3 "
                   "}\n[IO.File]::AppendAllText((Join-Path $PSScriptRoot 'calls'),'x')\nexit 0\n";
#else
    script = fail_hook ? "#!/bin/sh\nexit 7\n"
                       : "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ -s \"$1\" ] || exit 3\nprintf x >> "
                         "\"${0%/*}/calls\"\n";
#endif
    if (cdns_atomic_write(path, script, strlen(script)))
        return -1;
#ifndef _WIN32
    if (chmod(path, 0700))
        return -1;
#endif
    return 0;
}
static long calls(const char *path) {
    FILE *f = fopen(path, "rb");
    long n = 0;
    if (f) {
        if (!fseek(f, 0, SEEK_END))
            n = ftell(f);
        fclose(f);
    }
    return n;
}
int main(void) {
    cdns_config c = {0};
    cdns_address observed = {"203.0.113.10", "2001:db8::10", 7000}, synced = {0}, previous;
    cdns_client_state client, restart;
    unsigned char key[32] = {42};
    int has_synced = 0;
    char directory[1024], counter[1024], txt[256], corrupt[256], err[256];
    unsigned before;
#ifdef _WIN32
    char base[1024], temp[1024];
    CHECK(GetTempPathA(sizeof base, base));
    CHECK(GetTempFileNameA(base, "cde", 0, temp));
    CHECK(DeleteFileA(temp));
    CHECK(CreateDirectoryA(temp, NULL));
    snprintf(directory, sizeof directory, "%s", temp);
#else
    snprintf(directory, sizeof directory, "/tmp/cipherdns-e2e-XXXXXX");
    CHECK(mkdtemp(directory));
#endif
    CHECK(!cdns_platform_init());
    snprintf(c.domain, sizeof c.domain, "example.com");
    snprintf(c.provider, sizeof c.provider, "cloudflare");
    snprintf(c.zone_id, sizeof c.zone_id, "test-zone");
    snprintf(c.token, sizeof c.token, "test-token");
    c.ttl = 60;
    c.hook_timeout = 5;
    snprintf(c.state_file, sizeof c.state_file, "%s/state", directory);
    snprintf(c.current_file, sizeof c.current_file, "%s/current.json", directory);
#ifdef _WIN32
    snprintf(c.hook, sizeof c.hook, "%s/hook.ps1", directory);
#else
    snprintf(c.hook, sizeof c.hook, "%s/hook.sh", directory);
#endif
    snprintf(counter, sizeof counter, "%s/calls", directory);
    memset(&client, 0, sizeof client);
    CHECK(!hook_write(c.hook, 0));
    CHECK(cdns_server_step(&c, key, &synced, &has_synced, &observed, err, sizeof err) == 1);
    CHECK(has_synced && creates == 1 && updates == 0 && requests == 3);
    CHECK(!dns_bridge(txt));
    CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(calls(counter) == 1 && cdns_address_equal(&client.applied, &synced));
    before = requests;
    CHECK(!cdns_server_step(&c, key, &synced, &has_synced, &observed, err, sizeof err));
    CHECK(requests == before);
    CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(calls(counter) == 1);
    CHECK(!cdns_client_load(&c, key, &restart));
    CHECK(!cdns_client_step(&c, key, &restart, txt, err, sizeof err));
    CHECK(calls(counter) == 1);

    previous = synced;
    observed.ipv4[0] = 0;
    snprintf(observed.ipv6, sizeof observed.ipv6, "2001:db8::11");
    fail_next_write = 1;
    CHECK(cdns_server_step(&c, key, &synced, &has_synced, &observed, err, sizeof err) < 0);
    CHECK(cdns_address_equal(&synced, &previous) && creates == 1 && updates == 0);
    CHECK(!dns_bridge(txt));
    CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(calls(counter) == 1);
    CHECK(cdns_server_step(&c, key, &synced, &has_synced, &observed, err, sizeof err) == 1);
    CHECK(!strcmp(synced.ipv4, "203.0.113.10") && !strcmp(synced.ipv6, "2001:db8::11"));
    CHECK(creates == 1 && updates == 1);
    /* Provider write success does not invalidate an independent resolver cache.
     * Until the resolver returns fresh TXT, the client keeps its applied state. */
    CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(calls(counter) == 1 && cdns_address_equal(&client.applied, &previous));
    CHECK(!dns_bridge(txt));
    CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(calls(counter) == 2);
    CHECK(cdns_client_step(&c, key, &client, NULL, err, sizeof err));
    snprintf(corrupt, sizeof corrupt, "%s", txt);
    corrupt[12] = corrupt[12] == 'A' ? 'B' : 'A';
    CHECK(cdns_client_step(&c, key, &client, corrupt, err, sizeof err));
    CHECK(cdns_address_equal(&client.applied, &synced) && calls(counter) == 2);

    previous = synced;
    observed.ipv6[0] = 0;
    snprintf(observed.ipv4, sizeof observed.ipv4, "203.0.113.12");
    CHECK(cdns_server_step(&c, key, &synced, &has_synced, &observed, err, sizeof err) == 1);
    CHECK(!strcmp(synced.ipv6, previous.ipv6) && updates == 2 && creates == 1);
    CHECK(!dns_bridge(txt));
    CHECK(!hook_write(c.hook, 1));
    CHECK(cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(cdns_address_equal(&client.applied, &previous) && client.retry_hook &&
          calls(counter) == 2);
    CHECK(!cdns_client_load(&c, key, &restart));
    CHECK(cdns_address_equal(&restart.applied, &previous));
    CHECK(!hook_write(c.hook, 0));
    CHECK(!cdns_client_step(&c, key, &restart, txt, err, sizeof err));
    CHECK(cdns_address_equal(&restart.applied, &synced) && calls(counter) == 3);
    CHECK(!cdns_client_load(&c, key, &client));
    CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
    CHECK(calls(counter) == 3);
    {
        cdns_address restarted_server = {0};
        int restarted_has_synced = 0;
        unsigned writes = creates + updates;
        unsigned char foreign_key[32] = {99};
        before = requests;
        CHECK(cdns_server_step(&c, key, &restarted_server, &restarted_has_synced, &observed, err,
                               sizeof err) == 1);
        CHECK(restarted_has_synced && cdns_address_equal(&restarted_server, &synced));
        CHECK(requests == before + 1 && creates + updates == writes);
        CHECK(!cdns_client_step(&c, key, &client, txt, err, sizeof err));
        CHECK(calls(counter) == 3);
        snprintf(provider_txt, sizeof provider_txt, "administrator-owned unrelated TXT");
        restarted_has_synced = 0;
        CHECK(cdns_server_step(&c, key, &restarted_server, &restarted_has_synced, &observed, err,
                               sizeof err) < 0);
        CHECK(!restarted_has_synced && creates + updates == writes);
        CHECK(!cdns_encrypt(foreign_key, &synced, provider_txt));
        CHECK(cdns_server_step(&c, key, &restarted_server, &restarted_has_synced, &observed, err,
                               sizeof err) < 0);
        CHECK(!restarted_has_synced && creates + updates == writes);
    }
    remove(c.hook);
    remove(c.current_file);
    remove(c.state_file);
    remove(counter);
#ifdef _WIN32
    RemoveDirectoryA(directory);
#else
    rmdir(directory);
#endif
    cdns_platform_cleanup();
    puts("offline provider -> encrypted DNS -> hook/cache integration passed");
    return 0;
}
