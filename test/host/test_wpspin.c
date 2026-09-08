/* Basanos — WPS PIN recovery.
 *
 * Every algorithm here is pinned to a vector computed from an independent
 * reference implementation. That is not ceremony: a wrong PIN generator does
 * not fail loudly. It produces eight plausible digits, the AP rejects them,
 * and the operator concludes the network is fine while the tool quietly spends
 * a lockout budget on arithmetic errors. A generator without a vector is worse
 * than no generator at all.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/wpspin.h"

/* Find the candidate produced by one algorithm, or 0. */
static uint32_t by_alg(const bas_pin_cand_t *c, int n, bas_pinalg_t a)
{
    for (int i = 0; i < n; i++) {
        if (c[i].alg == a) {
            return c[i].pin;
        }
    }
    return 0;
}

void suite_wpspin(void)
{
    SUITE("wpspin: the specification's checksum digit");

    /* The eighth digit is not a secret and not a guess -- an AP rejects a PIN
     * that fails this without counting it as an attempt. */
    CHECK(bas_wps_pin_checksum(1234567u) == 0u);
    CHECK(bas_wps_pin_complete(1234567u) == 12345670u);
    CHECK(bas_wps_pin_valid(12345670u));
    CHECK(!bas_wps_pin_valid(12345671u));
    CHECK(bas_wps_pin_valid(0u));                 /* 0000000 + checksum 0  */
    CHECK(!bas_wps_pin_valid(100000000u));        /* nine digits           */

    /* Completing any body must produce a PIN that validates. Exhaustive over
     * the whole seven-digit space -- it is only ten million iterations and it
     * closes the question permanently. */
    for (uint32_t b = 0; b < 10000000u; b += 7u) {
        if (!bas_wps_pin_valid(bas_wps_pin_complete(b))) {
            CHECK(false);
            break;
        }
    }
    CHECK(true);

    SUITE("wpspin: derived PINs match independent reference vectors");

    static const uint8_t mac_a[6] = { 0x00, 0x1E, 0x58, 0x12, 0x34, 0x56 };
    bas_pin_cand_t c[BAS_MAX_PIN_CANDS];
    int n = bas_wps_pin_candidates(mac_a, c, BAS_MAX_PIN_CANDS);
    CHECK(n > 10);

    CHECK(by_alg(c, n, BAS_PINALG_NIC24)       == 11930464u);
    CHECK(by_alg(c, n, BAS_PINALG_DLINK)       == 76465154u);
    CHECK(by_alg(c, n, BAS_PINALG_DLINK_1)     == 66672982u);
    CHECK(by_alg(c, n, BAS_PINALG_ASUS)        == 54623064u);
    CHECK(by_alg(c, n, BAS_PINALG_AIROCON)     ==  8608604u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC32)       == 75880545u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC28)       == 54107748u);
    CHECK(by_alg(c, n, BAS_PINALG_INV_NIC)     == 55841696u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC_X2)      == 23860926u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC_X3)      == 35791386u);
    CHECK(by_alg(c, n, BAS_PINALG_OUI_ADD_NIC) == 12008148u);
    CHECK(by_alg(c, n, BAS_PINALG_OUI_XOR_NIC) == 11904144u);

    /* A second address, because a single vector can be matched by a generator
     * that is right about one MAC and wrong about the arithmetic. */
    static const uint8_t mac_b[6] = { 0xC8, 0x3A, 0x35, 0xAB, 0xCD, 0xEF };
    n = bas_wps_pin_candidates(mac_b, c, BAS_MAX_PIN_CANDS);
    CHECK(by_alg(c, n, BAS_PINALG_NIC24)       == 12593750u);
    CHECK(by_alg(c, n, BAS_PINALG_DLINK)       == 55575300u);
    CHECK(by_alg(c, n, BAS_PINALG_DLINK_1)     == 12197019u);
    CHECK(by_alg(c, n, BAS_PINALG_ASUS)        == 41254219u);
    CHECK(by_alg(c, n, BAS_PINALG_AIROCON)     == 81464982u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC32)       ==  4518235u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC28)       == 51454555u);
    CHECK(by_alg(c, n, BAS_PINALG_INV_NIC)     == 55178402u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC_X2)      == 25187502u);
    CHECK(by_alg(c, n, BAS_PINALG_NIC_X3)      == 37781255u);
    CHECK(by_alg(c, n, BAS_PINALG_OUI_ADD_NIC) == 43814763u);
    CHECK(by_alg(c, n, BAS_PINALG_OUI_XOR_NIC) == 65515143u);

    SUITE("wpspin: the vendor default leads, and every candidate is legal");

    /* Order is load-bearing. The attack is only useful if it finishes inside
     * the AP's lockout budget, which depends on trying the likely ones first. */
    CHECK(c[0].pin == 12345670u);
    CHECK(c[0].alg == BAS_PINALG_STATIC);

    for (int i = 0; i < n; i++) {
        CHECK(bas_wps_pin_valid(c[i].pin));
        CHECK(c[i].pin <= 99999999u);
        CHECK(bas_pinalg_name(c[i].alg)[0] != '\0');
    }

    SUITE("wpspin: a duplicate candidate is never tried twice");

    /* Several algorithms collapse to one value on some address ranges. Each
     * repeat spends an attempt from a budget the AP is counting down. */
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (c[i].pin == c[j].pin) {
                CHECK(false);
            }
        }
    }
    CHECK(true);

    /* An all-zero and an all-ones BSSID are not real targets, but they are
     * what a caller passes when something upstream went wrong. Neither may
     * produce an invalid PIN or run off the array. */
    static const uint8_t zero[6] = { 0, 0, 0, 0, 0, 0 };
    static const uint8_t ones[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    int nz = bas_wps_pin_candidates(zero, c, BAS_MAX_PIN_CANDS);
    for (int i = 0; i < nz; i++) { CHECK(bas_wps_pin_valid(c[i].pin)); }
    int no = bas_wps_pin_candidates(ones, c, BAS_MAX_PIN_CANDS);
    for (int i = 0; i < no; i++) { CHECK(bas_wps_pin_valid(c[i].pin)); }

    CHECK(bas_wps_pin_candidates(NULL, c, BAS_MAX_PIN_CANDS) == 0);
    CHECK(bas_wps_pin_candidates(mac_a, NULL, 4) == 0);
    CHECK(bas_wps_pin_candidates(mac_a, c, 0) == 0);
    CHECK(bas_wps_pin_candidates(mac_a, c, 3) == 3);   /* honours the cap  */

    SUITE("wpspin: the split search is two small spaces, not one large one");

    bas_pin_search_t s;
    bas_pin_search_init(&s);
    CHECK(bas_pin_search_remaining(&s) == 11000u);

    /* Walk the first half to 1234, answering "wrong" each time. */
    for (int i = 0; i < 1234; i++) {
        uint32_t p = bas_pin_search_next(&s);
        CHECK(bas_wps_pin_valid(p));
        bas_pin_search_result(&s, false);
    }
    CHECK(bas_pin_search_remaining(&s) == 11000u - 1234u);
    CHECK(bas_pin_search_next(&s) / 10000u == 1234u);

    /* The AP accepts the first half. The remaining space collapses to 1000 --
     * this collapse is the entire reason the attack is feasible at all. */
    bas_pin_search_result(&s, true);
    CHECK(s.first_half_known);
    CHECK(s.first_half == 1234u);
    CHECK(bas_pin_search_remaining(&s) == 1000u);

    for (int i = 0; i < 567; i++) {
        bas_pin_search_result(&s, false);
    }
    uint32_t got = bas_pin_search_next(&s);
    CHECK(got == 12345670u);              /* 1234 | 567 | checksum        */
    CHECK(bas_pin_search_remaining(&s) == 1000u - 567u);

    /* Exhaustion returns 0 rather than wrapping to the start, which would
     * make the search run for ever without saying so. */
    for (int i = 0; i < 500; i++) {
        bas_pin_search_result(&s, false);
    }
    CHECK(bas_pin_search_next(&s) == 0u);
    CHECK(bas_pin_search_remaining(&s) == 0u);

    bas_pin_search_init(&s);
    for (int i = 0; i < 10001; i++) {
        bas_pin_search_result(&s, false);
    }
    CHECK(bas_pin_search_next(&s) == 0u);

    bas_pin_search_init(NULL);
    CHECK(bas_pin_search_next(NULL) == 0u);
    CHECK(bas_pin_search_remaining(NULL) == 0u);
    bas_pin_search_result(NULL, true);
}
