#ifndef CIPHERDNS_DOCTOR_H
#define CIPHERDNS_DOCTOR_H
#include "core.h"
#include <stdio.h>
/* Never runs a Hook, an IP source command, or a DNS mutation. provider_read is opt-in. */
int cdns_doctor_run(const char *path, int json, int provider_read, FILE *output);
#endif
