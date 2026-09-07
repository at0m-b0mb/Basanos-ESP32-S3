/* Basanos — station enumeration. SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/station.h"

static const uint8_t AP1[6] = { 0x02,0xAA,0xBB,0xCC,0xDD,0xEE };
static const uint8_t AP2[6] = { 0x02,0xAA,0xBB,0xCC,0xDD,0x99 };

static void mac(uint8_t out[6], uint8_t first, uint8_t last)
{
    out[0] = first; out[1] = 0x11; out[2] = 0x22;
    out[3] = 0x33;  out[4] = 0x44; out[5] = last;
}

void suite_station(void)
{
    SUITE("station: sightings accumulate");

    bas_stalist_t l;
    bas_sta_reset(&l);
    CHECK_EQ(l.count, 0);

    uint8_t a[6]; mac(a, 0x06, 0x01);
    CHECK_EQ(bas_sta_observe(&l, a, AP1, -50, 1000), 0);
    CHECK_EQ(l.count, 1);
    CHECK_EQ(l.s[0].frames, 1);
    CHECK_EQ(l.s[0].first_seen_ms, 1000);

    CHECK_EQ(bas_sta_observe(&l, a, AP1, -45, 2000), 0);
    CHECK_EQ(l.count, 1);
    CHECK_EQ(l.s[0].frames, 2);
    CHECK_EQ(l.s[0].first_seen_ms, 1000);
    CHECK_EQ(l.s[0].last_seen_ms, 2000);
    CHECK_EQ(l.s[0].rssi, -45);

    SUITE("station: a group address is never a station");

    uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    uint8_t mcast[6] = { 0x01,0x00,0x5E,0x00,0x00,0x01 };
    uint8_t zero[6]  = { 0,0,0,0,0,0 };

    /* If one of these landed in the list it could be chosen in the client
     * picker, which is exactly what the engagement lock exists to prevent. */
    CHECK_EQ(bas_sta_observe(&l, bcast, AP1, -50, 3000), -1);
    CHECK_EQ(bas_sta_observe(&l, mcast, AP1, -50, 3000), -1);
    CHECK_EQ(bas_sta_observe(&l, zero,  AP1, -50, 3000), -1);
    CHECK_EQ(l.count, 1);

    /* Nor is a broadcast BSSID a real AP to attribute a station to. */
    CHECK_EQ(bas_sta_observe(&l, a, bcast, -50, 3000), -1);
    CHECK_EQ(bas_sta_observe(&l, a, zero,  -50, 3000), -1);

    /* An AP talking to itself is not a station sighting. */
    CHECK_EQ(bas_sta_observe(&l, AP1, AP1, -50, 3000), -1);
    CHECK_EQ(l.count, 1);

    SUITE("station: randomised addresses are flagged, not hidden");

    uint8_t rnd[6]; mac(rnd, 0x06, 0x02);      /* 0x06 has bit 1 set      */
    uint8_t global[6]; mac(global, 0x04, 0x03); /* bit 1 clear            */

    CHECK(bas_mac_is_randomised(rnd));
    CHECK(!bas_mac_is_randomised(global));
    CHECK(!bas_mac_is_randomised(NULL));

    bas_sta_reset(&l);
    int i1 = bas_sta_observe(&l, rnd, AP1, -50, 1000);
    int i2 = bas_sta_observe(&l, global, AP1, -60, 1000);
    CHECK(l.s[i1].randomised);
    CHECK(!l.s[i2].randomised);

    SUITE("station: per-BSSID counting and filtering");

    bas_sta_reset(&l);
    uint8_t s1[6], s2[6], s3[6];
    mac(s1, 0x04, 0x01); mac(s2, 0x04, 0x02); mac(s3, 0x04, 0x03);
    bas_sta_observe(&l, s1, AP1, -50, 1000);
    bas_sta_observe(&l, s2, AP1, -60, 1000);
    bas_sta_observe(&l, s3, AP2, -70, 1000);

    CHECK_EQ(l.count, 3);
    CHECK_EQ(bas_sta_count_for(&l, AP1), 2);
    CHECK_EQ(bas_sta_count_for(&l, AP2), 1);

    bas_sta_filter(&l, AP1);
    CHECK_EQ(l.count, 2);
    CHECK_EQ(bas_sta_count_for(&l, AP2), 0);

    SUITE("station: sort and expiry");

    bas_sta_reset(&l);
    bas_sta_observe(&l, s1, AP1, -80, 1000);
    bas_sta_observe(&l, s2, AP1, -30, 2000);
    bas_sta_observe(&l, s3, AP1, -55, 3000);
    bas_sta_sort_rssi(&l);
    CHECK_EQ(l.s[0].rssi, -30);
    CHECK_EQ(l.s[1].rssi, -55);
    CHECK_EQ(l.s[2].rssi, -80);

    bas_sta_expire(&l, 2000);
    CHECK_EQ(l.count, 2);
    bas_sta_expire(&l, 4000);
    CHECK_EQ(l.count, 0);

    SUITE("station: overflow is counted");

    bas_sta_reset(&l);
    for (int i = 0; i < BAS_MAX_STATIONS + 4; i++) {
        uint8_t m[6];
        m[0] = 0x04; m[1] = 0x11; m[2] = 0x22;
        m[3] = 0x33; m[4] = (uint8_t)(i >> 8); m[5] = (uint8_t)i;
        bas_sta_observe(&l, m, AP1, -60, 1000);
    }
    CHECK_EQ(l.count, BAS_MAX_STATIONS);
    CHECK_EQ(l.dropped, 4);

    SUITE("station: null safety");

    CHECK_EQ(bas_sta_observe(NULL, s1, AP1, -50, 0), -1);
    CHECK_EQ(bas_sta_observe(&l, NULL, AP1, -50, 0), -1);
    CHECK_EQ(bas_sta_observe(&l, s1, NULL, -50, 0), -1);
    CHECK_EQ(bas_sta_find(NULL, s1), -1);
    CHECK_EQ(bas_sta_count_for(NULL, AP1), 0);
}
