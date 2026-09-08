/* Basanos — minimal host test harness. SPDX-License-Identifier: MIT */
#ifndef BASANOS_TEST_HARNESS_H
#define BASANOS_TEST_HARNESS_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int g_checks;
extern int g_fails;
extern const char *g_suite;

#define CHECK(cond) do {                                                      \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            g_fails++;                                                         \
            printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b) do {                                                   \
        long _a = (long)(a), _b = (long)(b);                                   \
        g_checks++;                                                            \
        if (_a != _b) {                                                        \
            g_fails++;                                                         \
            printf("  FAIL %s:%d  %s == %s  (%ld != %ld)\n",                   \
                   __FILE__, __LINE__, #a, #b, _a, _b);                        \
        }                                                                      \
    } while (0)

#define CHECK_STR(a, b) do {                                                  \
        g_checks++;                                                            \
        if (strcmp((a), (b)) != 0) {                                           \
            g_fails++;                                                         \
            printf("  FAIL %s:%d  \"%s\" != \"%s\"\n",                         \
                   __FILE__, __LINE__, (a), (b));                              \
        }                                                                      \
    } while (0)

#define SUITE(name) do { g_suite = name; printf("== %s\n", name); } while (0)

void suite_target(void);
void suite_engage(void);
void suite_engage_area(void);
void suite_family(void);
void suite_rbac(void);
void suite_wpa(void);
void suite_score(void);
void suite_station(void);
void suite_ie(void);
void suite_survey(void);
void suite_alarm(void);

#endif
