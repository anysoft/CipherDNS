#ifndef CIPHERDNS_TEST_PATH_H
#define CIPHERDNS_TEST_PATH_H

#include <stddef.h>
#include <string.h>

/* The suffix includes its separator. Inputs must not overlap the destination.
 * Check both lengths before writing so failure leaves the destination intact. */
static int cdns_test_path_join(char *out, size_t capacity, const char *directory,
                               const char *suffix) {
    size_t directory_length = strlen(directory), suffix_length = strlen(suffix);
    if (directory_length >= capacity || suffix_length >= capacity - directory_length)
        return -1;
    memcpy(out, directory, directory_length);
    memcpy(out + directory_length, suffix, suffix_length + 1);
    return 0;
}

#endif
