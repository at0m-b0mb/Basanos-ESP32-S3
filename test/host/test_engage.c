/* Basanos — the engagement lock.
 *
 * These are mostly negative tests. The value of this component is what it
 * refuses, so that is what gets asserted.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/engage.h"
#include "basanos/family.h"

static bas_ap_t target_sunshine(void)
{
    bas_ap_t a;
    memset(&a, 0, sizeof(a));
    bas_strlcpy(a.ssid, "sunshine 12", sizeof(a.ssid));
    a.bssid[0] = 0x02; a.bssid[1] = 0xAA; a.bssid[2] = 0xBB;
    a.bssid[3] = 0xCC; a.bssid[4] = 0xDD; a.bssid[5] = 0xEE;
    a.channel = 6;
    a.rssi = -50;
    a.sec = BAS_SEC_WPA2;
    return a;
}

void suite_engage(void)
{
    SUITE("engage: locking requires a target, a label and an operator");

    bas_engagement_t e;
    bas_ap_t t = target_sunshine();

    bas_engage_clear(&e);
    CHECK_EQ(bas_engage_check(&e, 0), BAS_ERR_NOT_LOCKED);

    CHECK_EQ(bas_engage_lock(&e, &t, "WO-4471", "kailash", 1000, BAS_TTL_DEFAULT_MS), BAS_OK);
    CHECK(e.locked);
    CHECK_STR(e.label, "WO-4471");
    CHECK_STR(e.operator_name, "kailash");
    CHECK_EQ(bas_engage_check(&e, 1000), BAS_OK);

    /* An empty or whitespace-only label is not an authorisation reference. */
    bas_engage_clear(&e);
    CHECK_EQ(bas_engage_lock(&e, &t, "", "kailash", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_NO_LABEL);
    CHECK_EQ(bas_engage_lock(&e, &t, "   ", "kailash", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_NO_LABEL);
    CHECK_EQ(bas_engage_lock(&e, &t, NULL, "kailash", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_NO_LABEL);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-1", "", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_ARG);
    CHECK(!e.locked);

    SUITE("engage: a broadcast target cannot be locked at all");

    bas_ap_t bad = t;
    memset(bad.bssid, 0xFF, 6);
    CHECK_EQ(bas_engage_lock(&e, &bad, "WO-1", "op", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_BROADCAST);

    bad = t;
    bad.bssid[0] = 0x01;           /* group bit */
    CHECK_EQ(bas_engage_lock(&e, &bad, "WO-1", "op", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_BROADCAST);

    bad = t;
    memset(bad.bssid, 0x00, 6);
    CHECK_EQ(bas_engage_lock(&e, &bad, "WO-1", "op", 1000, BAS_TTL_DEFAULT_MS), BAS_ERR_BAD_BSSID);

    SUITE("engage: the TTL is mandatory and bounded");

    CHECK_EQ(bas_engage_lock(&e, &t, "WO-1", "op", 1000, 0), BAS_ERR_ARG);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-1", "op", 1000, BAS_TTL_MIN_MS - 1u), BAS_ERR_ARG);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-1", "op", 1000, BAS_TTL_MAX_MS + 1u), BAS_ERR_ARG);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-1", "op", 1000, BAS_TTL_MIN_MS), BAS_OK);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-1", "op", 1000, BAS_TTL_MAX_MS), BAS_OK);

    SUITE("engage: expiry stops the run, not just the arming");

    bas_engage_clear(&e);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-4471", "op", 1000, 60000u), BAS_OK);
    CHECK_EQ(bas_engage_check(&e, 1000),  BAS_OK);
    CHECK_EQ(bas_engage_check(&e, 60000), BAS_OK);
    CHECK_EQ(bas_engage_check(&e, 60999), BAS_OK);
    CHECK_EQ(bas_engage_check(&e, 61000), BAS_ERR_EXPIRED);
    CHECK_EQ(bas_engage_check(&e, 90000), BAS_ERR_EXPIRED);

    CHECK_EQ(bas_engage_remaining_ms(&e, 1000),  60000);
    CHECK_EQ(bas_engage_remaining_ms(&e, 31000), 30000);
    CHECK_EQ(bas_engage_remaining_ms(&e, 61000), 0);
    CHECK_EQ(bas_engage_remaining_ms(&e, 99999), 0);

    SUITE("engage: client narrowing refuses group addresses");

    bas_engage_clear(&e);
    CHECK_EQ(bas_engage_lock(&e, &t, "WO-4471", "op", 1000, 60000u), BAS_OK);

    uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    uint8_t mcast[6] = { 0x01,0x00,0x5E,0x00,0x00,0x01 };
    uint8_t zero[6]  = { 0,0,0,0,0,0 };
    uint8_t sta[6]   = { 0x06,0x11,0x22,0x33,0x44,0x55 };

    CHECK_EQ(bas_engage_set_client(&e, bcast), BAS_ERR_BROADCAST);
    CHECK_EQ(bas_engage_set_client(&e, mcast), BAS_ERR_BROADCAST);
    CHECK_EQ(bas_engage_set_client(&e, zero),  BAS_ERR_ARG);
    CHECK(!e.has_client);

    CHECK_EQ(bas_engage_set_client(&e, sta), BAS_OK);
    CHECK(e.has_client);

    SUITE("engage: the frame gate is the last line");

    /* In scope: the client, and the AP itself. */
    CHECK_EQ(bas_engage_permits_frame(&e, sta, t.bssid, 2000), BAS_OK);
    CHECK_EQ(bas_engage_permits_frame(&e, t.bssid, t.bssid, 2000), BAS_OK);

    /* Out of scope: broadcast, another client, another BSSID. */
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, t.bssid, 2000), BAS_ERR_BROADCAST);
    CHECK_EQ(bas_engage_permits_frame(&e, mcast, t.bssid, 2000), BAS_ERR_BROADCAST);
    CHECK_EQ(bas_engage_permits_frame(&e, zero,  t.bssid, 2000), BAS_ERR_ARG);

    uint8_t other_sta[6] = { 0x06,0x99,0x99,0x99,0x99,0x99 };
    CHECK_EQ(bas_engage_permits_frame(&e, other_sta, t.bssid, 2000), BAS_ERR_NO_TARGET);

    uint8_t other_bss[6] = { 0x02,0x00,0x00,0x00,0x00,0x99 };
    CHECK_EQ(bas_engage_permits_frame(&e, sta, other_bss, 2000), BAS_ERR_NO_TARGET);

    /* Expiry is enforced at the frame gate too, not only at arm time. */
    CHECK_EQ(bas_engage_permits_frame(&e, sta, t.bssid, 61000), BAS_ERR_EXPIRED);

    SUITE("engage: without a client, only the AP is addressable");

    bas_engage_clear_client(&e);
    CHECK(!e.has_client);
    CHECK_EQ(bas_engage_permits_frame(&e, t.bssid, t.bssid, 2000), BAS_OK);
    /* Crucially NOT every client of the BSS. An un-narrowed engagement is
     * still not permission to spray the network. */
    CHECK_EQ(bas_engage_permits_frame(&e, sta, t.bssid, 2000), BAS_ERR_NO_TARGET);
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, t.bssid, 2000), BAS_ERR_BROADCAST);

    SUITE("engage: run counter");

    CHECK_EQ(e.runs, 0);
    bas_engage_note_run(&e);
    bas_engage_note_run(&e);
    CHECK_EQ(e.runs, 2);
}

void suite_engage_area(void)
{
    SUITE("engage: a label-only lock authorises work but scopes no network");

    bas_engagement_t e;
    bas_engage_clear(&e);

    CHECK_EQ(bas_engage_lock_area(&e, "", "op", 1000, 60000), BAS_ERR_NO_LABEL);
    CHECK_EQ(bas_engage_lock_area(&e, "BLE SWEEP", "op", 1000, 60000), BAS_OK);
    CHECK(e.locked);
    CHECK(!e.has_target);
    CHECK_EQ(bas_engage_check(&e, 2000), BAS_OK);

    /* Families that address nobody may run. */
    bas_plan_t p;
    bas_plan_default(&p, BAS_FAM_BLE_ADV);
    CHECK_EQ(bas_plan_validate(&p, 1, &e, 2000), BAS_OK);
    bas_plan_default(&p, BAS_FAM_PROBE_REQ);
    CHECK_EQ(bas_plan_validate(&p, 1, &e, 2000), BAS_OK);

    /* Every family that addresses a network is refused. It widens nothing. */
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, 2, &e, 2000), BAS_ERR_NO_TARGET);
    bas_plan_default(&p, BAS_FAM_EVIL_TWIN);
    CHECK_EQ(bas_plan_validate(&p, 2, &e, 2000), BAS_ERR_NO_TARGET);
    bas_plan_default(&p, BAS_FAM_PMKID);
    CHECK_EQ(bas_plan_validate(&p, 2, &e, 2000), BAS_ERR_NO_TARGET);

    /* And no frame may be addressed under it. */
    uint8_t any[6] = { 0x02,0x11,0x22,0x33,0x44,0x55 };
    CHECK_EQ(bas_engage_permits_frame(&e, any, any, 2000), BAS_ERR_NO_TARGET);

    /* There is no target to narrow to a client. */
    CHECK_EQ(bas_engage_set_client(&e, any), BAS_ERR_NO_TARGET);

    SUITE("engage: a targeted lock still sets has_target");

    bas_ap_t t;
    memset(&t, 0, sizeof(t));
    bas_strlcpy(t.ssid, "lab", sizeof(t.ssid));
    t.bssid[0] = 0x02; t.bssid[5] = 0x01;
    t.channel = 6;
    CHECK_EQ(bas_engage_lock(&e, &t, "JOB-1", "op", 1000, 60000), BAS_OK);
    CHECK(e.has_target);
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, 2, &e, 2000), BAS_OK);
}
