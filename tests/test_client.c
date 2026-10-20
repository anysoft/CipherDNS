#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif
#include "cipherdns/client.h"
#include "cipherdns/dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static void put16(unsigned char *p, unsigned value) {
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}
static size_t question(unsigned char *p, unsigned answers) {
    static const unsigned char q[] = {7,   'e', 'x', 'a', 'm', 'p', 'l', 'e', 3,
                                      'c', 'o', 'm', 0,   0,   16,  0,   1};
    memset(p, 0, 1024);
    p[2] = 0x81;
    p[3] = 0x80;
    put16(p + 4, 1);
    put16(p + 6, answers);
    memcpy(p + 12, q, sizeof q);
    return 12 + sizeof q;
}
static size_t record(unsigned char *p, size_t at, unsigned type, const unsigned char *rdata,
                     size_t n) {
    p[at++] = 0xc0;
    p[at++] = 0x0c;
    put16(p + at, type);
    put16(p + at + 2, 1);
    memset(p + at + 4, 0, 4);
    put16(p + at + 8, (unsigned)n);
    at += 10;
    memcpy(p + at, rdata, n);
    return at + n;
}
static int dns_tests(void) {
    unsigned char packet[1024];
    static const unsigned char split[] = {1, 'C', 3, 'D', '1', ':', 4, 'a', 'b', 'c', '='};
    static const unsigned char unrelated[] = {5, 'h', 'e', 'l', 'l', 'o'};
    static const unsigned char broken[] = {4, 'a'};
    unsigned char lengthy[302];
    char txt[256];
    size_t n;
    CHECK(!cdns_dns_txt_rdata(split, sizeof split, txt));
    CHECK(!strcmp(txt, "CD1:abc="));
    CHECK(cdns_dns_txt_rdata(broken, sizeof broken, txt));
    n = question(packet, 2);
    n = record(packet, n, 16, unrelated, sizeof unrelated);
    n = record(packet, n, 16, split, sizeof split);
    CHECK(!cdns_dns_parse_wire(packet, n, txt));
    CHECK(!strcmp(txt, "CD1:abc="));
    CHECK(cdns_dns_parse_wire(packet, n - 1, txt));
    n = question(packet, 2);
    n = record(packet, n, 16, split, sizeof split);
    n = record(packet, n, 16, split, sizeof split);
    CHECK(cdns_dns_parse_wire(packet, n, txt));
    lengthy[0] = 255;
    memset(lengthy + 1, 'x', 255);
    lengthy[256] = 45;
    memset(lengthy + 257, 'x', 45);
    n = question(packet, 2);
    n = record(packet, n, 16, lengthy, sizeof lengthy);
    n = record(packet, n, 16, split, sizeof split);
    CHECK(!cdns_dns_parse_wire(packet, n, txt)); /* Long unrelated TXT is ignored. */
    memcpy(lengthy + 1, "CD1:", 4);
    n = question(packet, 1);
    n = record(packet, n, 16, lengthy, sizeof lengthy);
    CHECK(cdns_dns_parse_wire(packet, n, txt)); /* A payload is never truncated. */
    {
        static const unsigned char cname[] = {5, 'a', 'l', 'i', 'a', 's', 3, 'c', 'o', 'm', 0};
        size_t target, owner;
        n = question(packet, 2);
        target = n + 12;
        n = record(packet, n, 5, cname, sizeof cname);
        owner = n;
        n = record(packet, n, 16, split, sizeof split);
        packet[owner] = (unsigned char)(0xc0u | (target >> 8));
        packet[owner + 1] = (unsigned char)target;
        CHECK(!cdns_dns_parse_wire(packet, n, txt));
        CHECK(!strcmp(txt, "CD1:abc="));
    }
    n = question(packet, 1);
    n = record(packet, n, 16, unrelated, sizeof unrelated);
    CHECK(cdns_dns_parse_wire(packet, n, txt));
    packet[3] = 0x83;
    CHECK(cdns_dns_parse_wire(packet, n, txt)); /* NXDOMAIN */
    n = question(packet, 1);
    n = record(packet, n, 16, split, sizeof split);
    packet[12] = 0xc0;
    packet[13] = 12;
    CHECK(cdns_dns_parse_wire(packet, n, txt)); /* Compression loop. */
    n = question(packet, 1);
    n = record(packet, n, 16, broken, sizeof broken);
    CHECK(cdns_dns_parse_wire(packet, n, txt));
    return 0;
}
static int write_hook(const char *path, int mode) {
    const char *body;
#ifdef _WIN32
    if (mode == 2)
        body = "param([string]$StateFile)\nStart-Sleep -Seconds 10\n";
    else if (mode == 1)
        body = "param([string]$StateFile)\n[IO.File]::AppendAllText((Join-Path $PSScriptRoot "
               "'calls'),'x')\nexit 7\n";
    else
        body = "param([string]$StateFile)\nif (!(Test-Path -LiteralPath $StateFile)) { exit 3 "
               "}\n[IO.File]::AppendAllText((Join-Path $PSScriptRoot 'calls'),'x')\nexit 0\n";
#else
    if (mode == 2)
        body = "#!/bin/sh\nsleep 10\n";
    else if (mode == 1)
        body = "#!/bin/sh\nprintf x >> \"${0%/*}/calls\"\nexit 7\n";
    else
        body = "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ -s \"$1\" ] || exit 3\nprintf x >> "
               "\"${0%/*}/calls\"\n";
#endif
    if (cdns_atomic_write(path, body, strlen(body)))
        return -1;
#ifndef _WIN32
    if (chmod(path, 0700))
        return -1;
#endif
    return 0;
}
static long call_count(const char *path) {
    FILE *f = fopen(path, "rb");
    long size = 0;
    if (f) {
        if (!fseek(f, 0, SEEK_END))
            size = ftell(f);
        fclose(f);
    }
    return size;
}
static int probe_tests(void) {
    struct sockaddr_in address;
    unsigned port;
#ifdef _WIN32
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int length = sizeof address;
    CHECK(listener != INVALID_SOCKET);
#else
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    socklen_t length = sizeof address;
    CHECK(listener >= 0);
#endif
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(listener, (struct sockaddr *)&address, sizeof address));
    CHECK(!listen(listener, 1));
    CHECK(!getsockname(listener, (struct sockaddr *)&address, &length));
    port = ntohs(address.sin_port);
    CHECK(!cdns_tcp_probe("127.0.0.1", port, 1));
#ifdef _WIN32
    CHECK(!closesocket(listener));
#else
    CHECK(!close(listener));
#endif
    CHECK(cdns_tcp_probe("127.0.0.1", port, 1));
    CHECK(cdns_tcp_probe("not-a-numeric-address", port, 1));
    CHECK(cdns_tcp_probe("127.0.0.1", 0, 1));
    return 0;
}
int main(void) {
    cdns_config config, foreign;
    cdns_client_state state, restored;
    cdns_address first = {"203.0.113.10", "2001:db8::10", 7000}, second;
    unsigned char key[32] = {1}, wrong_key[32] = {2};
    char directory[CDNS_PATH_MAX], counter[CDNS_PATH_MAX], lockfile[CDNS_PATH_MAX];
    char txt[256], next[256], err[256], output[32];
    uint64_t started;
#ifdef _WIN32
    char base[CDNS_PATH_MAX], temp[CDNS_PATH_MAX];
    CHECK(GetTempPathA(sizeof base, base));
    CHECK(GetTempFileNameA(base, "cds", 0, temp));
    CHECK(DeleteFileA(temp));
    CHECK(CreateDirectoryA(temp, NULL));
    snprintf(directory, sizeof directory, "%s", temp);
#else
    snprintf(directory, sizeof directory, "/tmp/cipherdns-client-XXXXXX");
    CHECK(mkdtemp(directory));
#endif
    CHECK(!cdns_platform_init());
    CHECK(!dns_tests());
    CHECK(!probe_tests());
    memset(&config, 0, sizeof config);
    memset(&state, 0, sizeof state);
    snprintf(config.domain, sizeof config.domain, "example.com");
    snprintf(config.state_file, sizeof config.state_file, "%s/state", directory);
    /* Spaces and shell punctuation are passed literally as a single argument. */
    snprintf(config.current_file, sizeof config.current_file, "%s/current $(echo unused).json",
             directory);
#ifdef _WIN32
    snprintf(config.hook, sizeof config.hook, "%s/hook.ps1", directory);
#else
    snprintf(config.hook, sizeof config.hook, "%s/hook.sh", directory);
#endif
    snprintf(counter, sizeof counter, "%s/calls", directory);
    snprintf(lockfile, sizeof lockfile, "%s/lock", directory);
    config.hook_timeout = 5;
    config.check_timeout = 1;
    CHECK(!write_hook(config.hook, 0));
    CHECK(!cdns_encrypt(key, &first, txt));
    CHECK(cdns_client_load(&config, key, &restored));
    CHECK(!cdns_client_step(&config, key, &state, txt, err, sizeof err));
    CHECK(state.has_applied && cdns_address_equal(&state.applied, &first));
    CHECK(call_count(counter) == 1);
    CHECK(!cdns_private_file(config.state_file));
    CHECK(!cdns_client_step(&config, key, &state, txt, err, sizeof err));
    CHECK(call_count(counter) == 1);
    CHECK(!cdns_client_load(&config, key, &restored));
    CHECK(!cdns_client_step(&config, key, &restored, txt, err, sizeof err));
    CHECK(call_count(counter) == 1);
    foreign = config;
    snprintf(foreign.domain, sizeof foreign.domain, "other.example.com");
    CHECK(cdns_client_load(&foreign, key, &restored));
    CHECK(!restored.has_applied);
    CHECK(cdns_client_load(&config, wrong_key, &restored));
    CHECK(!restored.has_applied);
    CHECK(!cdns_client_load(&config, key, &restored));
    second = first;
    snprintf(second.ipv4, sizeof second.ipv4, "203.0.113.11");
    CHECK(!cdns_encrypt(key, &second, next));
    CHECK(!write_hook(config.hook, 1));
    CHECK(cdns_client_step(&config, key, &state, next, err, sizeof err));
    CHECK(state.retry_hook && cdns_address_equal(&state.applied, &first));
    CHECK(call_count(counter) == 2);
    CHECK(!cdns_client_load(&config, key, &restored));
    CHECK(cdns_address_equal(&restored.applied, &first));
    config.hook_min_interval = 60;
    CHECK(!cdns_client_step(&config, key, &state, next, err, sizeof err));
    CHECK(call_count(counter) == 2);
    config.hook_min_interval = 0;
    CHECK(!write_hook(config.hook, 0));
    CHECK(!cdns_client_step(&config, key, &state, next, err, sizeof err));
    CHECK(call_count(counter) == 3);
    CHECK(!state.retry_hook && cdns_address_equal(&state.applied, &second));
    CHECK(cdns_client_step(&config, key, &state, NULL, err, sizeof err));
    CHECK(cdns_client_step(&config, wrong_key, &state, txt, err, sizeof err));
    CHECK(cdns_client_step(&config, key, &state, "CD1:invalid!", err, sizeof err));
    CHECK(cdns_address_equal(&state.applied, &second) && call_count(counter) == 3);
    CHECK(!write_hook(config.hook, 2));
    config.hook_timeout = 1;
    started = cdns_mono_ms();
    CHECK(cdns_client_step(&config, key, &state, txt, err, sizeof err));
    CHECK(cdns_mono_ms() - started < 3000);
    CHECK(cdns_address_equal(&state.applied, &second));
    CHECK(!write_hook(config.hook, 0));
    config.hook_timeout = 5;
    foreign = config;
    snprintf(foreign.state_file, sizeof foreign.state_file, "%s/missing/state", directory);
    CHECK(cdns_client_step(&foreign, key, &state, txt, err, sizeof err));
    CHECK(state.cache_dirty && cdns_address_equal(&state.applied, &first));
    CHECK(call_count(counter) == 4);
    CHECK(cdns_client_step(&config, key, &state, NULL, err, sizeof err));
    CHECK(!state.cache_dirty && call_count(counter) == 4);
    CHECK(!cdns_client_step(&config, key, &state, txt, err, sizeof err));
    CHECK(!state.cache_dirty && call_count(counter) == 4);
    CHECK(!cdns_client_load(&config, key, &restored));
    CHECK(cdns_address_equal(&restored.applied, &first));
#ifdef _WIN32
    CHECK(!cdns_capture("echo hello", 2, output, sizeof output));
    CHECK(strstr(output, "hello"));
    CHECK(cdns_capture("exit /B 7", 2, output, sizeof output));
#else
    CHECK(!cdns_capture("printf hello", 2, output, sizeof output));
    CHECK(!strcmp(output, "hello"));
    CHECK(cdns_capture("exit 7", 2, output, sizeof output));
    CHECK(cdns_capture("printf 123456789", 2, output, 4));
    CHECK(!chmod(config.state_file, 0644));
    CHECK(cdns_private_file(config.state_file));
    CHECK(!chmod(config.state_file, 0600));
#endif
    CHECK(!cdns_lock(lockfile));
    CHECK(cdns_lock(lockfile));
#ifndef _WIN32
    {
        pid_t child = fork();
        int child_status = 0;
        CHECK(child >= 0);
        if (!child) {
            cdns_unlock();
            _exit(cdns_lock(lockfile) ? 0 : 1);
        }
        CHECK(waitpid(child, &child_status, 0) == child);
        CHECK(WIFEXITED(child_status) && !WEXITSTATUS(child_status));
    }
#endif
    cdns_unlock();
    CHECK(!cdns_lock(lockfile));
    cdns_unlock();
    remove(config.hook);
    remove(config.current_file);
    remove(config.state_file);
    remove(counter);
    remove(lockfile);
#ifdef _WIN32
    RemoveDirectoryA(directory);
#else
    rmdir(directory);
#endif
    cdns_platform_cleanup();
    puts("client, TXT, hook, timeout and cache tests passed");
    return 0;
}
