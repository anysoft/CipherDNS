#include "cipherdns/core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __APPLE__
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet6/in6_var.h>
#endif
#endif
static int ipv4_ok(const unsigned char *p, int allow_private) {
    if (p[0] == 0 || p[0] == 127 || p[0] >= 224 || (p[0] == 169 && p[1] == 254))
        return 0;
    if (!allow_private &&
        (p[0] == 10 || (p[0] == 172 && (p[1] >= 16 && p[1] <= 31)) ||
         (p[0] == 192 && p[1] == 168) || (p[0] == 100 && p[1] >= 64 && p[1] <= 127)))
        return 0;
    return 1;
}
static void candidate(const cdns_config *c, cdns_address *a, int family, const void *raw) {
    const unsigned char *p = raw;
    char s[46];
    if (family == AF_INET) {
        if (!strcmp(c->ip_family, "ipv6") || !ipv4_ok(p, c->allow_private_ipv4))
            return;
        if (inet_ntop(AF_INET, raw, s, sizeof(s)) && (!a->ipv4[0] || strcmp(s, a->ipv4) < 0))
            strcpy(a->ipv4, s);
    } else if (family == AF_INET6) {
        int ula = (p[0] & 0xfe) == 0xfc;
        if (!strcmp(c->ip_family, "ipv4") || (!ula && ((p[0] & 0xe0) != 0x20)) ||
            (ula && !c->allow_ula))
            return;
        if (!inet_ntop(AF_INET6, raw, s, sizeof(s)))
            return;
        unsigned char old[16];
        int have = a->ipv6[0] && inet_pton(AF_INET6, a->ipv6, old) == 1;
        int old_ula = have && ((old[0] & 0xfe) == 0xfc);
        int cmp = have ? memcmp(p, old, 16) : 0;
        if (!have || (old_ula && !ula) ||
            (old_ula == ula && (!strcmp(c->ipv6_strategy, "highest") ? cmp > 0 : cmp < 0)))
            strcpy(a->ipv6, s);
    }
}
#if !defined(_WIN32)
static int unstable6(const char *name, const struct sockaddr *addr) {
#ifdef __linux__
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
    char hex[33];
    const unsigned char *p = (const unsigned char *)&a->sin6_addr;
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", p[i]);
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f)
        return 0;
    char line[256], ip[33], iface[128];
    unsigned idx, prefix, scope, flags;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "%32s %x %x %x %x %127s", ip, &idx, &prefix, &scope, &flags, iface) == 6 &&
            !strcmp(iface, name) && !strcmp(ip, hex)) {
            fclose(f);
            return (flags & (0x01 | 0x08 | 0x20 | 0x40)) != 0;
        }
    fclose(f);
#elif defined(__APPLE__)
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    struct in6_ifreq r;
    memset(&r, 0, sizeof(r));
    snprintf(r.ifr_name, sizeof(r.ifr_name), "%s", name);
    memcpy(&r.ifr_addr, addr, sizeof(struct sockaddr_in6));
    int rc = ioctl(fd, SIOCGIFAFLAG_IN6, &r);
    close(fd);
    if (!rc)
        return (r.ifr_ifru.ifru_flags6 & (IN6_IFF_TEMPORARY | IN6_IFF_DEPRECATED |
                                          IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED)) != 0;
#else
    (void)name;
    (void)addr;
#endif
    return 0;
}
#endif
int cdns_ip_detect(const cdns_config *c, cdns_address *a) {
    memset(a, 0, sizeof(*a));
    a->port = c->port;
    if (!strcmp(c->ip_source, "command")) {
        char output[1024];
        if (cdns_capture(c->command, c->command_timeout, output, sizeof(output)))
            return -1;
        char *p = output;
        while (isspace((unsigned char)*p))
            p++;
        if (*p == '{') {
            cdns_address b;
            if (cdns_address_parse(p, &b))
                return -1;
            unsigned char raw[16];
            if (b.ipv4[0] && inet_pton(AF_INET, b.ipv4, raw) == 1)
                candidate(c, a, AF_INET, raw);
            if (b.ipv6[0] && inet_pton(AF_INET6, b.ipv6, raw) == 1)
                candidate(c, a, AF_INET6, raw);
        } else
            while (*p) {
                char *start = p;
                while (*p && !isspace((unsigned char)*p))
                    p++;
                if (*p)
                    *p++ = 0;
                unsigned char raw[16];
                if (inet_pton(AF_INET, start, raw) == 1)
                    candidate(c, a, AF_INET, raw);
                else if (inet_pton(AF_INET6, start, raw) == 1)
                    candidate(c, a, AF_INET6, raw);
                else
                    return -1;
                while (isspace((unsigned char)*p))
                    p++;
            }
    } else {
#ifdef _WIN32
        ULONG n = 16384;
        IP_ADAPTER_ADDRESSES *list = malloc(n);
        if (!list)
            return -1;
        ULONG rc = GetAdaptersAddresses(
            AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, list, &n);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            free(list);
            list = malloc(n);
            if (!list)
                return -1;
            rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, list, &n);
        }
        if (rc != NO_ERROR) {
            free(list);
            return -1;
        }
        for (IP_ADAPTER_ADDRESSES *i = list; i; i = i->Next) {
            if (i->OperStatus != IfOperStatusUp || i->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                continue;
            if (c->interface_name[0] && strcmp(c->interface_name, i->AdapterName))
                continue;
            for (IP_ADAPTER_UNICAST_ADDRESS *u = i->FirstUnicastAddress; u; u = u->Next) {
                if (u->DadState != IpDadStatePreferred || u->PreferredLifetime == 0)
                    continue;
                int family = u->Address.lpSockaddr->sa_family;
                if (family == AF_INET)
                    candidate(c, a, family,
                              &((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr);
                else if (family == AF_INET6 && u->SuffixOrigin != IpSuffixOriginRandom)
                    candidate(c, a, family,
                              &((struct sockaddr_in6 *)u->Address.lpSockaddr)->sin6_addr);
            }
        }
        free(list);
#else
        struct ifaddrs *list = NULL;
        if (getifaddrs(&list))
            return -1;
        for (struct ifaddrs *i = list; i; i = i->ifa_next) {
            if (!i->ifa_addr || !(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK))
                continue;
            if (c->interface_name[0] && strcmp(c->interface_name, i->ifa_name))
                continue;
            int family = i->ifa_addr->sa_family;
            if (family == AF_INET)
                candidate(c, a, family, &((struct sockaddr_in *)i->ifa_addr)->sin_addr);
            else if (family == AF_INET6 && !unstable6(i->ifa_name, i->ifa_addr))
                candidate(c, a, family, &((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr);
        }
        freeifaddrs(list);
#endif
    }
    return a->ipv4[0] || a->ipv6[0] ? 0 : -1;
}
