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
    CHECK(!(e.client_n > 0));

    CHECK_EQ(bas_engage_set_client(&e, sta), BAS_OK);
    CHECK((e.client_n > 0));

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

    bas_engage_clear_clients(&e);
    CHECK(!(e.client_n > 0));
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

void suite_engage_clients(void)
{
    SUITE("engage: a selectable set of clients, never a broadcast");

    bas_ap_t t;
    memset(&t, 0, sizeof(t));
    bas_strlcpy(t.ssid, "lab", sizeof(t.ssid));
    t.bssid[0] = 0x02; t.bssid[5] = 0xEE;
    t.channel = 6;

    bas_engagement_t e;
    bas_engage_clear(&e);
    CHECK_EQ(bas_engage_lock(&e, &t, "JOB-9", "op", 1000, 600000), BAS_OK);

    /* Nothing selected: the access point is the only destination, so an
     * un-narrowed engagement cannot spray a cell. */
    CHECK_EQ(bas_engage_dest_count(&e), 1);
    CHECK(bas_mac_eq(bas_engage_dest(&e, 0), t.bssid));
    CHECK(bas_mac_eq(bas_engage_dest(&e, 7), t.bssid));

    uint8_t a[6] = { 0x02,0x11,0x11,0x11,0x11,0x01 };
    uint8_t b[6] = { 0x02,0x22,0x22,0x22,0x22,0x02 };
    uint8_t c[6] = { 0x02,0x33,0x33,0x33,0x33,0x03 };

    CHECK_EQ(bas_engage_add_client(&e, a), BAS_OK);
    CHECK_EQ(bas_engage_add_client(&e, b), BAS_OK);
    CHECK_EQ(bas_engage_dest_count(&e), 2);
    CHECK(bas_engage_has_client(&e, a));
    CHECK(bas_engage_has_client(&e, b));
    CHECK(!bas_engage_has_client(&e, c));

    /* Adding twice is a no-op, not a duplicate destination. */
    CHECK_EQ(bas_engage_add_client(&e, a), BAS_OK);
    CHECK_EQ(bas_engage_dest_count(&e), 2);

    /* Destinations cycle, so a burst is shared rather than aimed at one. */
    CHECK(bas_mac_eq(bas_engage_dest(&e, 0), a));
    CHECK(bas_mac_eq(bas_engage_dest(&e, 1), b));
    CHECK(bas_mac_eq(bas_engage_dest(&e, 2), a));

    SUITE("engage: a group address can never enter the set");

    uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    uint8_t mcast[6] = { 0x01,0x00,0x5E,0x00,0x00,0x01 };
    uint8_t zero[6]  = { 0,0,0,0,0,0 };

    /* This is the whole reason the set exists rather than a broadcast flag. */
    CHECK_EQ(bas_engage_add_client(&e, bcast), BAS_ERR_BROADCAST);
    CHECK_EQ(bas_engage_add_client(&e, mcast), BAS_ERR_BROADCAST);
    CHECK_EQ(bas_engage_add_client(&e, zero),  BAS_ERR_ARG);
    /* The AP is already the default destination; listing it would double it. */
    CHECK_EQ(bas_engage_add_client(&e, t.bssid), BAS_ERR_ARG);
    CHECK_EQ(bas_engage_dest_count(&e), 2);

    SUITE("engage: the frame gate follows the set");

    CHECK_EQ(bas_engage_permits_frame(&e, a, t.bssid, 2000), BAS_OK);
    CHECK_EQ(bas_engage_permits_frame(&e, b, t.bssid, 2000), BAS_OK);
    CHECK_EQ(bas_engage_permits_frame(&e, t.bssid, t.bssid, 2000), BAS_OK);
    /* A client that was never selected stays untouched. */
    CHECK_EQ(bas_engage_permits_frame(&e, c, t.bssid, 2000), BAS_ERR_NO_TARGET);
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, t.bssid, 2000),
             BAS_ERR_BROADCAST);

    SUITE("engage: removing, and the bound on the set");

    CHECK_EQ(bas_engage_remove_client(&e, a), BAS_OK);
    CHECK(!bas_engage_has_client(&e, a));
    CHECK_EQ(bas_engage_dest_count(&e), 1);
    CHECK_EQ(bas_engage_remove_client(&e, a), BAS_ERR_NO_TARGET);
    CHECK_EQ(bas_engage_permits_frame(&e, a, t.bssid, 2000), BAS_ERR_NO_TARGET);

    bas_engage_clear_clients(&e);
    CHECK_EQ(bas_engage_dest_count(&e), 1);

    /* The bound is deliberate: an unbounded list quietly becomes "everyone". */
    for (int i = 0; i < BAS_MAX_CLIENTS; i++) {
        uint8_t m[6] = { 0x02, 0x44, 0x44, 0x44, 0x44, (uint8_t)i };
        CHECK_EQ(bas_engage_add_client(&e, m), BAS_OK);
    }
    uint8_t extra[6] = { 0x02,0x55,0x55,0x55,0x55,0x55 };
    CHECK_EQ(bas_engage_add_client(&e, extra), BAS_ERR_NO_SPACE);
    CHECK_EQ(bas_engage_dest_count(&e), BAS_MAX_CLIENTS);

    SUITE("engage: set_client narrows to exactly one");

    CHECK_EQ(bas_engage_set_client(&e, c), BAS_OK);
    CHECK_EQ(bas_engage_dest_count(&e), 1);
    CHECK(bas_engage_has_client(&e, c));

    /* A label-only engagement has no target, so it has no clients either. */
    bas_engagement_t area;
    bas_engage_clear(&area);
    bas_engage_lock_area(&area, "AREA", "op", 1000, 60000);
    CHECK_EQ(bas_engage_add_client(&area, a), BAS_ERR_NO_TARGET);
    CHECK_EQ(bas_engage_dest_count(&area), 0);
}

void suite_engage_whole_cell(void)
{
    SUITE("engage: the whole cell is addressable, scoped by BSSID");

    bas_ap_t t;
    memset(&t, 0, sizeof(t));
    bas_strlcpy(t.ssid, "lab", sizeof(t.ssid));
    t.bssid[0] = 0x02; t.bssid[5] = 0xEE;
    t.channel = 6;

    bas_engagement_t e;
    bas_engage_clear(&e);
    CHECK_EQ(bas_engage_lock(&e, &t, "JOB-12", "op", 1000, 600000), BAS_OK);

    uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

    /* Off by default: the whole cell is always a deliberate choice. */
    CHECK(!bas_engage_is_whole_cell(&e));
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, t.bssid, 2000),
             BAS_ERR_BROADCAST);

    CHECK_EQ(bas_engage_set_whole_cell(&e, true), BAS_OK);
    CHECK(bas_engage_is_whole_cell(&e));
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, t.bssid, 2000), BAS_OK);
    CHECK(bas_mac_eq(bas_engage_dest(&e, 0), bcast));

    SUITE("engage: a broadcast to any OTHER cell is still refused");

    /* This is the line that matters. A deauth carries the BSSID in addresses
     * 2 and 3 and only that cell's stations act on it, so the BSSID is the
     * scope. A broadcast with someone else's BSSID is the untargeted sweep,
     * and no mode enables it. */
    uint8_t other[6] = { 0x02,0x99,0x99,0x99,0x99,0x99 };
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, other, 2000),
             BAS_ERR_NO_TARGET);
    uint8_t zero_bssid[6] = { 0,0,0,0,0,0 };
    CHECK_EQ(bas_engage_permits_frame(&e, bcast, zero_bssid, 2000),
             BAS_ERR_NO_TARGET);

    SUITE("engage: whole cell and a client list are alternatives");

    uint8_t a[6] = { 0x02,0x11,0x11,0x11,0x11,0x01 };
    bas_engage_set_whole_cell(&e, false);
    CHECK_EQ(bas_engage_add_client(&e, a), BAS_OK);
    CHECK_EQ(bas_engage_dest_count(&e), 1);

    /* Choosing the cell drops the list rather than layering on it: a
     * broadcast already reaches everyone, so a list beside it would imply a
     * narrowing that is not happening. */
    CHECK_EQ(bas_engage_set_whole_cell(&e, true), BAS_OK);
    CHECK_EQ(e.client_n, 0);
    CHECK(!bas_engage_has_client(&e, a));

    SUITE("engage: no target means no cell to broadcast into");

    bas_engagement_t area;
    bas_engage_clear(&area);
    bas_engage_lock_area(&area, "AREA", "op", 1000, 60000);
    CHECK_EQ(bas_engage_set_whole_cell(&area, true), BAS_ERR_NO_TARGET);
    CHECK(!bas_engage_is_whole_cell(&area));

    bas_engagement_t unlocked;
    bas_engage_clear(&unlocked);
    CHECK_EQ(bas_engage_set_whole_cell(&unlocked, true), BAS_ERR_NOT_LOCKED);

    SUITE("engage: an expired engagement broadcasts nothing");

    CHECK_EQ(bas_engage_permits_frame(&e, bcast, t.bssid, 601000),
             BAS_ERR_EXPIRED);
}
