/* Basanos — on-device self-test. SPDX-License-Identifier: MIT */
#include "selftest.h"

#include "basanos/alarm.h"
#include "basanos/engage.h"
#include "basanos/family.h"
#include "basanos/ie.h"
#include "basanos/rbac.h"
#include "basanos/score.h"
#include "basanos/station.h"
#include "basanos/survey.h"
#include "canvas.h"
#include "rawtx.h"
#include "theme.h"

#include "esp_log.h"

#include <string.h>

static const char *TAG = "bas_selftest";

static bas_selftest_t *s_r;

static void ck(bool cond, const char *what)
{
    s_r->checks++;
    if (!cond) {
        s_r->failures++;
        ESP_LOGE(TAG, "FAIL: %s", what);
        if (s_r->first_failure[0] == '\0') {
            strncpy(s_r->first_failure, what, sizeof(s_r->first_failure) - 1u);
        }
    }
}

static bas_ap_t make_target(void)
{
    bas_ap_t t;
    memset(&t, 0, sizeof(t));
    bas_strlcpy(t.ssid, "selftest", sizeof(t.ssid));
    t.bssid[0] = 0x02; t.bssid[5] = 0xEE;
    t.channel = 6;
    t.sec = BAS_SEC_WPA2;
    return t;
}

void bas_selftest_run(bas_selftest_t *out)
{
    static bas_selftest_t r;
    memset(&r, 0, sizeof(r));
    s_r = &r;

    /* --- the targeting invariants ------------------------------------- */
    bas_ap_t t = make_target();
    ck(bas_ap_check(&t) == BAS_OK, "valid AP accepted");

    bas_ap_t bad = t;
    memset(bad.bssid, 0xFF, 6);
    ck(bas_ap_check(&bad) == BAS_ERR_BROADCAST, "broadcast BSSID refused");

    bad = t;
    bad.bssid[0] = 0x01;
    ck(bas_ap_check(&bad) == BAS_ERR_BROADCAST, "multicast BSSID refused");

    bad = t;
    memset(bad.bssid, 0, 6);
    ck(bas_ap_check(&bad) == BAS_ERR_BAD_BSSID, "zero BSSID refused");

    /* --- the engagement lock ------------------------------------------- */
    bas_engagement_t e;
    bas_engage_clear(&e);
    ck(bas_engage_check(&e, 0) == BAS_ERR_NOT_LOCKED, "unlocked refuses");
    ck(bas_engage_lock(&e, &t, "", "op", 1000, 60000) == BAS_ERR_NO_LABEL,
       "empty label refused");
    ck(bas_engage_lock(&e, &t, "ST", "op", 1000, 60000) == BAS_OK, "lock ok");
    ck(bas_engage_check(&e, 60999) == BAS_OK, "unexpired ok");
    ck(bas_engage_check(&e, 61000) == BAS_ERR_EXPIRED, "expiry enforced");

    uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    ck(bas_engage_permits_frame(&e, bcast, t.bssid, 2000) == BAS_ERR_BROADCAST,
       "frame gate refuses broadcast");
    ck(bas_engage_permits_frame(&e, t.bssid, t.bssid, 2000) == BAS_OK,
       "frame gate allows target");

    uint8_t other[6] = { 0x02,0x00,0x00,0x00,0x00,0x99 };
    ck(bas_engage_permits_frame(&e, other, t.bssid, 2000) == BAS_ERR_NO_TARGET,
       "frame gate refuses stranger");

    /* --- role gating ---------------------------------------------------- */
    bas_plan_t p;
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    ck(bas_plan_validate(&p, BAS_ROLE_VIEWER, &e, 2000) == BAS_ERR_ROLE,
       "viewer cannot transmit");
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    ck(bas_plan_validate(&p, BAS_ROLE_OPERATOR, &e, 2000) == BAS_ERR_ROLE,
       "operator cannot deauth");
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    ck(bas_plan_validate(&p, BAS_ROLE_ADMIN, &e, 2000) == BAS_OK,
       "admin may deauth in engagement");

    /* The load-bearing one. */
    bas_engagement_t none;
    bas_engage_clear(&none);
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    ck(bas_plan_validate(&p, BAS_ROLE_ADMIN, &none, 2000) == BAS_ERR_NOT_LOCKED,
       "admin without engagement cannot TX");

    bas_plan_default(&p, BAS_FAM_DEAUTH);
    p.pps = 60000; p.seconds = 60000;
    ck(bas_plan_validate(&p, BAS_ROLE_ADMIN, &e, 2000) == BAS_OK &&
       p.pps == bas_family(BAS_FAM_DEAUTH)->max_pps &&
       p.seconds == bas_family(BAS_FAM_DEAUTH)->max_seconds,
       "ceilings clamp");

    /* --- crypto, on this silicon ---------------------------------------- */
    uint8_t h[32];
    static const uint8_t abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,
        0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    bas_sha256("abc", 3, h);
    ck(memcmp(h, abc, 32) == 0, "SHA-256 vector");

    uint8_t dk[32];
    static const uint8_t pb[32] = {
        0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c,0x43,0xe7,0x22,0x52,
        0x56,0xc4,0xf8,0x37,0xa8,0x65,0x48,0xc9,0x2c,0xcc,0x35,0x48,
        0x08,0x05,0x98,0x7c,0xb7,0x0b,0xe1,0x7b
    };
    bas_pbkdf2_sha256("password", 8, "salt", 4, 1, dk, sizeof(dk));
    ck(memcmp(dk, pb, 32) == 0, "PBKDF2 vector");

    /* --- scorecard fairness --------------------------------------------- */
    bas_card_t c;
    bas_card_reset(&c);
    int idx = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    bas_card_end(&c, idx, 5000, 10);
    ck(bas_run_verdict(&c.r[idx], 7999) == BAS_VERDICT_PENDING,
       "not MISSED inside grace");
    ck(bas_run_verdict(&c.r[idx], 8000) == BAS_VERDICT_MISSED,
       "MISSED after grace");

    /* --- alarm parsing --------------------------------------------------- */
    bas_alarm_t a;
    ck(bas_alarm_parse("BASANOS-ALARM detector=X conf=50", BAS_SRC_SERIAL, &a) &&
       a.confidence == 50, "alarm parses");
    ck(!bas_alarm_parse("see BASANOS-ALARM detector=X", BAS_SRC_SERIAL, &a),
       "alarm prefix must lead");

    /* --- element parsing on hostile input -------------------------------- */
    static const uint8_t overrun[] = { 0x00, 0x40, 'a', 'b' };
    bas_posture_t po;
    bas_ie_parse(overrun, sizeof(overrun), NULL, &po);
    ck(po.truncated, "IE overrun truncates");

    /* --- station list ---------------------------------------------------- */
    bas_stalist_t sl;
    bas_sta_reset(&sl);
    ck(bas_sta_observe(&sl, bcast, t.bssid, -50, 1000) == -1,
       "broadcast is not a station");

    /* --- canvas stays inside the panel ----------------------------------- */
    static uint16_t tiny_px[16 * 16];
    bas_canvas_t tc;
    bas_canvas_init(&tc, tiny_px, 16, 16);
    bas_canvas_clear(&tc, 0);
    bas_text(&tc, 1, 1, "ok", TH_INK, 1);
    ck(tc.oob == 0u, "canvas in bounds");
    bas_text(&tc, 60, 1, "off", TH_INK, 1);
    ck(tc.oob > 0u, "canvas counts overflow");

    /* Not an invariant -- a capability. A build without the override is still
     * correct, it simply cannot run three of the families, and the interface
     * says so rather than failing them one at a time later. */
    ESP_LOGI(TAG, "%s", bas_rawtx_status());

    ESP_LOGI(TAG, "%d checks, %d failures", r.checks, r.failures);
    if (out != NULL) {
        *out = r;
    }
}

bool bas_selftest_ok(const bas_selftest_t *r)
{
    return r != NULL && r->checks > 0 && r->failures == 0;
}
