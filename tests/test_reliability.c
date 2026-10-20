#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif
#include "cipherdns/client.h"
#include "cipherdns/dns.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
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

#ifndef _WIN32
static int resolver_mode;
/* Replace only the libc resolver boundary. The production fork, deadline,
 * pipe, DNS parser, kill and waitpid paths remain under test. */
int res_query(const char *domain, int class_, int type, unsigned char *answer, int length) {
    static const unsigned char question[] = {7,   'e', 'x', 'a', 'm', 'p', 'l', 'e', 3,
                                             'c', 'o', 'm', 0,   0,   16,  0,   1};
    static const unsigned char txt[] = {8, 'C', 'D', '1', ':', 'a', 'b', 'c', '='};
    size_t at = 12;
    (void)domain;
    (void)class_;
    (void)type;
    if (resolver_mode == 1) {
        sleep(5);
        return -1;
    }
    if (resolver_mode == 2)
        return -1;
    if (resolver_mode == 3)
        return length + 1;
    if (length < 100)
        return -1;
    memset(answer, 0, 100);
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[5] = 1;
    answer[7] = 1;
    memcpy(answer + at, question, sizeof question);
    at += sizeof question;
    answer[at++] = 0xc0;
    answer[at++] = 12;
    answer[at++] = 0;
    answer[at++] = 16;
    answer[at++] = 0;
    answer[at++] = 1;
    at += 4;
    answer[at++] = 0;
    answer[at++] = sizeof txt;
    memcpy(answer + at, txt, sizeof txt);
    return (int)(at + sizeof txt);
}
#endif

static long resource_count(void) {
#ifdef _WIN32
    DWORD count = 0;
    return GetProcessHandleCount(GetCurrentProcess(), &count) ? (long)count : -1;
#else
    long limit = sysconf(_SC_OPEN_MAX), count = 0, i;
    if (limit < 0 || limit > 8192)
        limit = 8192;
    for (i = 0; i < limit; ++i)
        if (fcntl((int)i, F_GETFD) >= 0 || errno != EBADF)
            ++count;
    return count;
#endif
}
static long file_size(const char *path) {
    FILE *file = fopen(path, "rb");
    long result = 0;
    if (file) {
        if (!fseek(file, 0, SEEK_END))
            result = ftell(file);
        fclose(file);
    }
    return result;
}
static int write_hook(const char *path, int fail) {
    const char *body;
#ifdef _WIN32
    body = fail
               ? "exit 7\n"
               : "param([string]$StateFile)\nif (!(Test-Path -LiteralPath $StateFile)) { exit 3 }\n"
                 "[IO.File]::AppendAllText((Join-Path $PSScriptRoot 'calls'),'x')\n";
#else
    body = fail ? "#!/bin/sh\nexit 7\n"
                : "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ -s \"$1\" ] || exit 3\n"
                  "printf x >> \"${0%/*}/calls\"\n";
#endif
    if (cdns_atomic_write(path, body, strlen(body)))
        return -1;
#ifndef _WIN32
    if (chmod(path, 0700))
        return -1;
#endif
    return 0;
}
static int resolver_tests(void) {
#ifndef _WIN32
    char txt[256];
    unsigned i;
    int status;
    long before = resource_count();
    for (i = 0; i < 2; ++i) {
        uint64_t start = cdns_mono_ms();
        resolver_mode = 1;
        CHECK(cdns_dns_lookup("example.com", 1, txt));
        CHECK(cdns_mono_ms() - start >= 900 && cdns_mono_ms() - start < 3000);
        CHECK(waitpid(-1, &status, WNOHANG) < 0 && errno == ECHILD);
        resolver_mode = 0;
        CHECK(!cdns_dns_lookup("example.com", 1, txt));
        CHECK(!strcmp(txt, "CD1:abc="));
    }
    for (i = 0; i < 32; ++i) {
        resolver_mode = 2;
        CHECK(cdns_dns_lookup("example.com", 1, txt));
        resolver_mode = 3;
        CHECK(cdns_dns_lookup("example.com", 1, txt));
        resolver_mode = 0;
        CHECK(!cdns_dns_lookup("example.com", 1, txt));
        CHECK(waitpid(-1, &status, WNOHANG) < 0 && errno == ECHILD);
    }
    CHECK(resource_count() == before);
#else
    puts("SKIP: POSIX resolver injection/reaping checks on Windows");
#endif
    return 0;
}
int main(int argc, char **argv) {
    cdns_config c = {0};
    cdns_client_state state = {0}, restored, previous;
    unsigned char key[32] = {73};
    cdns_address address = {"203.0.113.10", "2001:db8::10", 7000};
    char directory[CDNS_PATH_MAX], calls[CDNS_PATH_MAX], txt[256], err[256], cache[1024];
    unsigned i, loops;
    long handles, expected_calls = 0;
    size_t n;
    FILE *file;
    int resource_workload = argc == 2 && !strcmp(argv[1], "--resource-workload");
    CHECK(argc == 1 || resource_workload);
#ifdef _WIN32
    char base[CDNS_PATH_MAX], temporary[CDNS_PATH_MAX];
    CHECK(GetTempPathA(sizeof base, base));
    CHECK(GetTempFileNameA(base, "cdr", 0, temporary));
    CHECK(DeleteFileA(temporary));
    CHECK(CreateDirectoryA(temporary, NULL));
    snprintf(directory, sizeof directory, "%s", temporary);
    loops = resource_workload ? 32 : 12;
#else
    snprintf(directory, sizeof directory, "/tmp/cipherdns-reliability-XXXXXX");
    CHECK(mkdtemp(directory));
    loops = resource_workload ? 256 : 64;
#endif
    CHECK(!cdns_platform_init());
    snprintf(c.domain, sizeof c.domain, "example.com");
    snprintf(c.state_file, sizeof c.state_file, "%s/state", directory);
    snprintf(c.current_file, sizeof c.current_file, "%s/current $(echo unused).json", directory);
    snprintf(calls, sizeof calls, "%s/calls", directory);
#ifdef _WIN32
    snprintf(c.hook, sizeof c.hook, "%s/hook.ps1", directory);
#else
    snprintf(c.hook, sizeof c.hook, "%s/hook.sh", directory);
#endif
    c.hook_timeout = 3;
    CHECK(!write_hook(c.hook, 0));
    if (resource_workload) {
        puts("resource phase: startup complete; idle for 3 seconds");
        fflush(stdout);
        cdns_sleep_ms(3000);
        puts("resource phase: offline client address/cache/Hook workload");
        fflush(stdout);
    } else
        CHECK(!resolver_tests());
    handles = resource_count();
    CHECK(handles > 0);
    for (i = 0; i < loops; ++i) {
        snprintf(address.ipv4, sizeof address.ipv4, "203.0.113.%u", 1 + i % 200);
        snprintf(address.ipv6, sizeof address.ipv6, "2001:db8::%x", 1 + i);
        CHECK(!cdns_encrypt(key, &address, txt));
        previous = state;
        CHECK(cdns_client_step(&c, key, &state, NULL, err, sizeof err));
        CHECK(!memcmp(&state, &previous, sizeof state));
        CHECK(cdns_client_step(&c, key, &state, "CD1:broken", err, sizeof err));
        CHECK(!memcmp(&state, &previous, sizeof state));
        if (i % 8 == 0) {
            CHECK(!write_hook(c.hook, 1));
            CHECK(cdns_client_step(&c, key, &state, txt, err, sizeof err));
            CHECK(!memcmp(&state.applied, &previous.applied, sizeof state.applied));
            CHECK(state.has_applied == previous.has_applied && state.retry_hook);
            CHECK(!write_hook(c.hook, 0));
        }
        CHECK(!cdns_client_step(&c, key, &state, txt, err, sizeof err));
        CHECK(cdns_address_equal(&state.applied, &address));
        ++expected_calls;
        CHECK(file_size(calls) == expected_calls);
        CHECK(!cdns_client_step(&c, key, &state, txt, err, sizeof err));
        CHECK(!cdns_client_load(&c, key, &restored));
        CHECK(!cdns_client_step(&c, key, &restored, txt, err, sizeof err));
        CHECK(file_size(calls) == expected_calls);
        state = restored; /* Repeat startup restoration on every address change. */
    }
    CHECK(resource_count() == handles);
    file = fopen(c.state_file, "rb");
    CHECK(file);
    n = fread(cache, 1, sizeof cache - 16, file);
    CHECK(n && feof(file) && !ferror(file));
    CHECK(!fclose(file));
    memcpy(cache + n, "\0hidden-corrupt", 15);
    CHECK(!cdns_atomic_write(c.state_file, cache, n + 15));
    CHECK(cdns_client_load(&c, key, &restored));
    CHECK(!restored.has_applied);
    CHECK(!cdns_atomic_write(c.state_file, "broken cache", 12));
    CHECK(cdns_client_load(&c, key, &restored));
    CHECK(!restored.has_applied);
    CHECK(!cdns_atomic_write(c.state_file, cache, n));
    CHECK(!cdns_client_load(&c, key, &restored));
    CHECK(!cdns_client_step(&c, key, &restored, txt, err, sizeof err));
    CHECK(file_size(calls) == expected_calls);
#ifndef _WIN32
    {
        char ready[CDNS_PATH_MAX], fifo[CDNS_PATH_MAX];
        int writer;
        const char body[] = "#!/bin/sh\n"
                            "(exec 3<>\"${0%/*}/release\"; printf ready > \"${0%/*}/ready\"; "
                            "read token <&3) &\n"
                            "while [ ! -s \"${0%/*}/ready\" ]; do sleep 0.01; done\nexit 0\n";
        snprintf(ready, sizeof ready, "%s/ready", directory);
        snprintf(fifo, sizeof fifo, "%s/release", directory);
        CHECK(!mkfifo(fifo, 0600));
        CHECK(!cdns_atomic_write(c.hook, body, strlen(body)));
        CHECK(!chmod(c.hook, 0700));
        CHECK(!cdns_hook(c.hook, c.current_file, 5));
        CHECK(!access(ready, F_OK));
        /* The leader confirms its descendant opened the FIFO before exiting.
         * Once managed cleanup returns, no reader may remain. Avoid a delayed
         * marker whose timing would depend on CI scheduling. */
        cdns_sleep_ms(50);
        writer = open(fifo, O_WRONLY | O_NONBLOCK);
        if (writer >= 0)
            close(writer);
        CHECK(writer < 0 && errno == ENXIO);
        CHECK(!remove(ready));
        CHECK(!remove(fifo));
    }
#endif
    CHECK(resource_count() == handles);
    CHECK(!remove(c.hook));
    CHECK(!remove(c.current_file));
    CHECK(!remove(c.state_file));
    CHECK(!remove(calls));
#ifdef _WIN32
    CHECK(RemoveDirectoryA(directory));
#else
    CHECK(!rmdir(directory));
#endif
    cdns_platform_cleanup();
    printf("PASS: %u address changes/restarts, duplicate suppression, failures/recovery, cache "
           "corruption; no descriptor/handle growth\n",
           loops);
    return 0;
}
