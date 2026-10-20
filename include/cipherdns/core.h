#ifndef CIPHERDNS_CORE_H
#define CIPHERDNS_CORE_H
#include <stddef.h>
#include <stdint.h>
#define CDNS_TEXT_MAX 255
#define CDNS_PATH_MAX 1024
#define CDNS_ERROR_MAX 256
typedef struct {
    char ipv4[16];
    char ipv6[46];
    unsigned port;
} cdns_address;
typedef struct {
    char mode[16], domain[254], key_file[CDNS_PATH_MAX];
    char ip_family[8], ip_source[16], interface_name[256], command[CDNS_PATH_MAX];
    char ipv6_strategy[16];
    int allow_ula, allow_private_ipv4;
    unsigned check_interval, command_timeout, port;
    char provider[16], credentials_file[CDNS_PATH_MAX], ca_file[CDNS_PATH_MAX];
    char zone[254], rr[254];
    unsigned ttl, connect_timeout, read_timeout, update_timeout, retries;
    uint64_t api_deadline_ms; /* Internal monotonic deadline for the complete provider operation. */
    char token[512], zone_id[128], access_key_id[256], access_key_secret[256];
    char secret_id[256], secret_key[256];
    unsigned poll_interval, dns_timeout, check_port, check_timeout, hook_timeout, hook_min_interval;
    char prefer_family[8], hook[CDNS_PATH_MAX], state_file[CDNS_PATH_MAX],
        current_file[CDNS_PATH_MAX];
    int check_connectivity, hook_on_recovery;
} cdns_config;
void cdns_log(const char *level, const char *fmt, ...);
int cdns_config_load(const char *path, cdns_config *c, char *err, size_t cap);
/* Schema-only parsing for doctor; no key or credential material is read. */
int cdns_config_parse(const char *path, cdns_config *c, char *err, size_t cap);
#ifdef CDNS_SERVER
int cdns_credentials_load(cdns_config *c, char *err, size_t cap);
#endif
int cdns_random(void *out, size_t n);
void cdns_zero(void *p, size_t n);
int cdns_key_load(const char *path, unsigned char key[32]);
int cdns_keygen(const char *path);
int cdns_base64_encode(const unsigned char *in, size_t n, char *out, size_t cap);
int cdns_base64_decode(const char *in, unsigned char *out, size_t cap, size_t *n);
int cdns_encrypt(const unsigned char key[32], const cdns_address *a, char out[256]);
int cdns_decrypt(const unsigned char key[32], const char *txt, cdns_address *a);
int cdns_address_parse(const char *json, cdns_address *a);
int cdns_address_json(const cdns_address *a, char *out, size_t cap);
int cdns_address_equal(const cdns_address *a, const cdns_address *b);
int cdns_address_valid(cdns_address *a);
int cdns_ip_detect(const cdns_config *c, cdns_address *a);
/* Merge independently detected families; absent observations never erase valid state. */
void cdns_address_merge(cdns_address *out, const cdns_address *observed,
                        const cdns_address *previous);
int cdns_server_step(const cdns_config *c, const unsigned char key[32], cdns_address *synced,
                     int *has_synced, const cdns_address *observed, char *err, size_t cap);
int cdns_server_run(const cdns_config *c, const unsigned char key[32], int once);
unsigned cdns_server_retry_delay(unsigned consecutive_failures);
int cdns_client_run(const cdns_config *c, const unsigned char key[32], int once);
/* Platform calls have bounded runtimes. Files are written privately via same-directory rename. */
int cdns_platform_init(void);
void cdns_platform_cleanup(void);
uint64_t cdns_mono_ms(void);
void cdns_sleep_ms(unsigned ms);
int cdns_stopping(void);
int cdns_private_file(const char *path);
int cdns_atomic_write(const char *path, const void *data, size_t n);
int cdns_private_create(const char *path, const void *data, size_t n);
int cdns_lock(const char *path);
void cdns_unlock(void);
int cdns_capture(const char *command, unsigned timeout_s, char *out, size_t cap);
int cdns_hook(const char *path, const char *json_path, unsigned timeout_s);
int cdns_tcp_probe(const char *ip, unsigned port, unsigned timeout_s);
#endif
