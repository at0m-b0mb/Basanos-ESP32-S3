/* Basanos — host test entry point. SPDX-License-Identifier: MIT */
#include "harness.h"

int g_checks = 0;
int g_fails  = 0;
const char *g_suite = "";

int main(void)
{
    printf("Basanos host tests\n\n");

    suite_target();
    suite_engage();
    suite_engage_area();
    suite_engage_clients();
    suite_engage_whole_cell();
    suite_family();
    suite_region();
    suite_region();
    suite_region();
    suite_rbac();
    suite_wpa();
    suite_score();
    suite_station();
    suite_ie();
    suite_survey();
    suite_alarm();

    printf("\n%d checks, %d failures\n", g_checks, g_fails);
    if (g_fails != 0) {
        printf("FAILED\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}
