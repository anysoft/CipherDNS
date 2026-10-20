#ifndef CIPHERDNS_TEST_ASSERTIONS_H
#define CIPHERDNS_TEST_ASSERTIONS_H

/* Forced into test translation units before their first include. Release and
 * MinSizeRel still define NDEBUG for production; tests always execute assert().
 * Undefining it in C avoids conflicting compiler /D and /U switches on MSVC. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#endif
