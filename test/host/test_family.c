/* Basanos — families, ceilings and the validation gate.
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/family.h"
#include "basanos/rbac.h"

#define VIEWER   0u
#define OPERATOR 1u
#define ADMIN    2u

static bas_engagement_t locked_engagement(void)
{
    bas_engagement_t e;
    bas_ap_t t;
    memset(&t, 0, sizeof(t));
    bas_strlcpy(t.ssid, "sunshine 12", sizeof(t.ssid));
    t.bssid[0] = 0x02; t.bssid[5] = 0xEE;
    t.channel = 6;
    t.sec = BAS_SEC_WPA2;
    bas_engage_clear(&e);
    bas_engage_lock(&e, &t, "WO-4471", "op", 1000, 600000u);
    return e;
}

void suite_family(void)
{
    SUITE("family: the table is complete and self-consistent");

    CHECK(bas_family(BAS_FAM__COUNT) == NULL);
    CHECK(bas_family((bas_family_t)-1) == NULL);

    for (int i = 0; i < BAS_FAM__COUNT; i++) {
        const bas_family_spec_t *s = bas_family((bas_family_t)i);
        CHECK(s != NULL);
        if (s == NULL) {
            continue;
        }
        /* Every family names a detector it exercises. A family that tests
         * nothing has no reason to be in the build. */
        CHECK(s->name != NULL && s->name[0] != '\0');
        CHECK(s->detector != NULL && s->detector[0] != '\0');
        CHECK(s->proves != NULL && s->proves[0] != '\0');
        CHECK(s->default_pps > 0);
        CHECK(s->max_pps >= s->default_pps);
        CHECK(s->max_seconds > 0);

        /* Disruptive families are admin-only, everywhere, always. */
        if (s->klass == BAS_CLASS_DISRUPTIVE) {
            CHECK_EQ(s->min_role, ADMIN);
            CHECK(s->needs_target);
        }
        /* Nothing benign may require a locked target: those families are
         * things a phone does unprompted and have no victim. */
        if (s->klass == BAS_CLASS_BENIGN) {
            CHECK(!s->needs_target);
        }
    }

    /* The integer role constants in family.c must agree with rbac.h. */
    CHECK_EQ((int)BAS_ROLE_VIEWER,   (int)VIEWER);
    CHECK_EQ((int)BAS_ROLE_OPERATOR, (int)OPERATOR);
    CHECK_EQ((int)BAS_ROLE_ADMIN,    (int)ADMIN);

    SUITE("family: role gating");

    bas_engagement_t e = locked_engagement();
    bas_plan_t p;

    /* A viewer runs nothing at all. */
    for (int i = 0; i < BAS_FAM__COUNT; i++) {
        bas_plan_default(&p, (bas_family_t)i);
        CHECK_EQ(bas_plan_validate(&p, VIEWER, &e, 2000), BAS_ERR_ROLE);
    }

    /* An operator runs benign and active, never disruptive. */
    bas_plan_default(&p, BAS_FAM_PROBE_REQ);
    CHECK_EQ(bas_plan_validate(&p, OPERATOR, &e, 2000), BAS_OK);
    bas_plan_default(&p, BAS_FAM_BEACON);
    CHECK_EQ(bas_plan_validate(&p, OPERATOR, &e, 2000), BAS_OK);
    bas_plan_default(&p, BAS_FAM_EVIL_TWIN);
    CHECK_EQ(bas_plan_validate(&p, OPERATOR, &e, 2000), BAS_OK);

    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, OPERATOR, &e, 2000), BAS_ERR_ROLE);
    bas_plan_default(&p, BAS_FAM_DISASSOC);
    CHECK_EQ(bas_plan_validate(&p, OPERATOR, &e, 2000), BAS_ERR_ROLE);
    bas_plan_default(&p, BAS_FAM_AUTH_FLOOD);
    CHECK_EQ(bas_plan_validate(&p, OPERATOR, &e, 2000), BAS_ERR_ROLE);

    /* An admin runs everything — but still only inside an engagement. */
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &e, 2000), BAS_OK);

    SUITE("family: admin without an engagement still cannot transmit");

    bas_engagement_t none;
    bas_engage_clear(&none);
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &none, 2000), BAS_ERR_NOT_LOCKED);
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, NULL, 2000), BAS_ERR_NO_TARGET);

    /* This is the property the whole design rests on: the highest role in the
     * system, with no target selected, transmits nothing. */
    bas_plan_default(&p, BAS_FAM_AUTH_FLOOD);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &none, 2000), BAS_ERR_NOT_LOCKED);

    SUITE("family: an expired engagement refuses at validate time");

    bas_engagement_t exp = locked_engagement();   /* 1000 .. 601000 */
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &exp, 600999), BAS_OK);
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &exp, 601000), BAS_ERR_EXPIRED);

    SUITE("family: ceilings clamp, never widen");

    bas_plan_default(&p, BAS_FAM_DEAUTH);
    const bas_family_spec_t *d = bas_family(BAS_FAM_DEAUTH);
    p.pps     = 60000;
    p.seconds = 60000;
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &e, 2000), BAS_OK);
    CHECK_EQ(p.pps, d->max_pps);
    CHECK_EQ(p.seconds, d->max_seconds);
    CHECK(p.clamped_pps);
    CHECK(p.clamped_secs);

    /* A modest request is left exactly as asked. */
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    p.pps = 5;
    p.seconds = 4;
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &e, 2000), BAS_OK);
    CHECK_EQ(p.pps, 5);
    CHECK_EQ(p.seconds, 4);
    CHECK(!p.clamped_pps);
    CHECK(!p.clamped_secs);
    CHECK_EQ(bas_plan_frame_budget(&p), 20);

    /* Zero means "use the default", not "emit nothing forever". */
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    p.pps = 0;
    p.seconds = 0;
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &e, 2000), BAS_OK);
    CHECK_EQ(p.pps, d->default_pps);
    CHECK_EQ(p.seconds, 1);

    SUITE("family: channel resolution and the regulatory clamp");

    bas_region_set(BAS_REGION_FCC);
    CHECK_EQ(bas_region_max_channel(), 11);
    CHECK_EQ(bas_region_check_channel(0),  BAS_ERR_CHANNEL);
    CHECK_EQ(bas_region_check_channel(1),  BAS_OK);
    CHECK_EQ(bas_region_check_channel(11), BAS_OK);
    CHECK_EQ(bas_region_check_channel(12), BAS_ERR_CHANNEL);

    bas_region_set(BAS_REGION_ETSI);
    CHECK_EQ(bas_region_max_channel(), 13);
    CHECK_EQ(bas_region_check_channel(13), BAS_OK);
    CHECK_EQ(bas_region_check_channel(14), BAS_ERR_CHANNEL);

    bas_region_set(BAS_REGION_JP);
    CHECK_EQ(bas_region_check_channel(14), BAS_OK);

    /* channel 0 in a plan means "follow the target". */
    bas_region_set(BAS_REGION_FCC);
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(p.channel, 0);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &e, 2000), BAS_OK);
    CHECK_EQ(p.channel, 6);

    /* A target outside the domain is refused rather than silently retuned. */
    bas_engagement_t far_e = locked_engagement();
    far_e.target.channel = 13;
    bas_plan_default(&p, BAS_FAM_DEAUTH);
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &far_e, 2000), BAS_ERR_CHANNEL);

    SUITE("family: invented names must be labelled as a test rig");

    CHECK(bas_family_label_ok("BASANOS-01"));
    CHECK(bas_family_label_ok(BAS_TEST_PREFIX "beacon-7"));
    CHECK(!bas_family_label_ok("Free Airport WiFi"));
    CHECK(!bas_family_label_ok("basanos-01"));   /* case matters */
    CHECK(!bas_family_label_ok(""));
    CHECK(!bas_family_label_ok(NULL));

    SUITE("family: unknown family is refused");

    memset(&p, 0, sizeof(p));
    p.fam = (bas_family_t)BAS_FAM__COUNT;
    CHECK_EQ(bas_plan_validate(&p, ADMIN, &e, 2000), BAS_ERR_UNKNOWN_FAMILY);
    CHECK_EQ(bas_plan_validate(NULL, ADMIN, &e, 2000), BAS_ERR_ARG);
}
