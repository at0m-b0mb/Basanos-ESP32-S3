/* Basanos — scan list and target validation. SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/target.h"

static bas_ap_t mk(const char *ssid, uint8_t last, uint8_t ch, int8_t rssi, uint32_t seen)
{
    bas_ap_t a;
    memset(&a, 0, sizeof(a));
    bas_strlcpy(a.ssid, ssid, sizeof(a.ssid));
    a.bssid[0] = 0x02; a.bssid[1] = 0x11; a.bssid[2] = 0x22;
    a.bssid[3] = 0x33; a.bssid[4] = 0x44; a.bssid[5] = last;
    a.channel = ch;
    a.rssi = rssi;
    a.sec = BAS_SEC_WPA2;
    a.last_seen_ms = seen;
    a.first_seen_ms = seen;
    return a;
}

void suite_target(void)
{
    SUITE("target: scan list");

    bas_scan_t s;
    bas_scan_reset(&s);
    CHECK_EQ(s.count, 0);

    bas_ap_t a = mk("sunshine 12", 0x01, 6, -55, 1000);
    CHECK_EQ(bas_scan_observe(&s, &a), 0);
    CHECK_EQ(s.count, 1);

    /* Same BSSID again is an update, not a second entry. */
    a.rssi = -40;
    a.last_seen_ms = 2000;
    CHECK_EQ(bas_scan_observe(&s, &a), 0);
    CHECK_EQ(s.count, 1);
    CHECK_EQ(s.ap[0].rssi, -40);
    /* first_seen must survive the update — dwell time depends on it. */
    CHECK_EQ(s.ap[0].first_seen_ms, 1000);
    CHECK_EQ(s.ap[0].last_seen_ms, 2000);

    /* A second radio advertising the same SSID is a separate AP. */
    bas_ap_t b = mk("sunshine 12", 0x02, 11, -70, 2000);
    CHECK_EQ(bas_scan_observe(&s, &b), 1);
    CHECK_EQ(s.count, 2);
    CHECK_EQ(bas_scan_count_ssid(&s, "sunshine 12"), 2);

    /* find_ssid returns the strongest of the two, so the picker defaults to
     * the radio the operator is actually standing next to. */
    int idx = bas_scan_find_ssid(&s, "sunshine 12");
    CHECK_EQ(idx, 0);
    CHECK_EQ(s.ap[idx].rssi, -40);

    CHECK_EQ(bas_scan_find_ssid(&s, "not here"), -1);
    CHECK_EQ(bas_scan_count_ssid(&s, "not here"), 0);
    CHECK_EQ(bas_scan_find_ssid(&s, ""), -1);
    CHECK_EQ(bas_scan_find_ssid(&s, NULL), -1);

    SUITE("target: sort and expiry");

    bas_ap_t c = mk("other", 0x03, 1, -20, 2000);
    bas_scan_observe(&s, &c);
    bas_scan_sort_rssi(&s);
    CHECK_EQ(s.ap[0].rssi, -20);
    CHECK_EQ(s.ap[1].rssi, -40);
    CHECK_EQ(s.ap[2].rssi, -70);

    /* Anything not seen since the cutoff is gone and cannot be selected. */
    bas_scan_expire(&s, 2000);
    CHECK_EQ(s.count, 3);
    bas_scan_expire(&s, 2500);
    CHECK_EQ(s.count, 0);

    SUITE("target: overflow is reported, not silent");

    bas_scan_reset(&s);
    for (int i = 0; i < BAS_MAX_APS + 5; i++) {
        bas_ap_t x = mk("net", (uint8_t)i, 6, -60, 100);
        x.bssid[4] = (uint8_t)(i >> 8);
        x.bssid[5] = (uint8_t)i;
        bas_scan_observe(&s, &x);
    }
    CHECK_EQ(s.count, BAS_MAX_APS);
    CHECK_EQ(s.dropped, 5);

    SUITE("target: candidate validation refuses the unusable");

    bas_ap_t good = mk("sunshine 12", 0x01, 6, -55, 1000);
    CHECK_EQ(bas_ap_check(&good), BAS_OK);

    bas_ap_t zero = good;
    memset(zero.bssid, 0, 6);
    CHECK_EQ(bas_ap_check(&zero), BAS_ERR_BAD_BSSID);

    /* Broadcast and every multicast address are refused as a BSSID. This is
     * what makes "attack everything" inexpressible rather than merely absent
     * from the menu. */
    bas_ap_t bcast = good;
    memset(bcast.bssid, 0xFF, 6);
    CHECK_EQ(bas_ap_check(&bcast), BAS_ERR_BROADCAST);

    bas_ap_t mcast = good;
    mcast.bssid[0] = 0x01;
    CHECK_EQ(bas_ap_check(&mcast), BAS_ERR_BROADCAST);

    bas_ap_t ch0 = good;
    ch0.channel = 0;
    CHECK_EQ(bas_ap_check(&ch0), BAS_ERR_CHANNEL);

    bas_ap_t ch15 = good;
    ch15.channel = 15;
    CHECK_EQ(bas_ap_check(&ch15), BAS_ERR_CHANNEL);

    CHECK_EQ(bas_ap_check(NULL), BAS_ERR_ARG);

    SUITE("target: security classification");

    CHECK(bas_sec_is_open(BAS_SEC_OPEN));
    CHECK(!bas_sec_is_open(BAS_SEC_WPA2));

    /* WPA3 and WPA2-Enterprise are expected to shrug off a deauth. Transition
     * mode is NOT, because its WPA2 half is unprotected — that is the whole
     * problem with transition mode and the tool must not imply otherwise. */
    CHECK(bas_sec_likely_mfp(BAS_SEC_WPA3));
    CHECK(bas_sec_likely_mfp(BAS_SEC_WPA2_ENT));
    CHECK(!bas_sec_likely_mfp(BAS_SEC_WPA2_WPA3));
    CHECK(!bas_sec_likely_mfp(BAS_SEC_WPA2));

    CHECK_STR(bas_sec_name(BAS_SEC_WPA2), "WPA2");
    CHECK_STR(bas_sec_name(BAS_SEC_OPEN), "Open");
}
