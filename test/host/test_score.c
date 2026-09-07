/* Basanos — the scorecard.
 *
 * The property worth protecting here is that the instrument is never unfair to
 * a detector: nothing is called MISSED before the grace window has elapsed,
 * and an alarm that arrives after the burst still counts as a catch.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/score.h"

void suite_score(void)
{
    SUITE("score: a run is PENDING while it is still emitting");

    bas_card_t c;
    bas_card_reset(&c);
    CHECK_EQ(c.count, 0);

    int r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, BAS_GRACE_DEFAULT_MS);
    CHECK_EQ(r, 0);
    CHECK_EQ(c.count, 1);
    CHECK_EQ(bas_run_verdict(&c.r[0], 1000), BAS_VERDICT_PENDING);
    CHECK_EQ(bas_run_verdict(&c.r[0], 5000), BAS_VERDICT_PENDING);
    CHECK_EQ(bas_run_latency_ms(&c.r[0]), -1);

    SUITE("score: an alarm during emission is CAUGHT");

    CHECK_EQ(bas_card_alarm(&c, 0, "Aegis", 82, 0x0F, BAS_SRC_SERIAL, 2400), BAS_OK);
    CHECK_EQ(bas_run_verdict(&c.r[0], 2400), BAS_VERDICT_CAUGHT);
    CHECK_EQ(bas_run_latency_ms(&c.r[0]), 1400);
    CHECK_STR(c.r[0].alarm_detector, "Aegis");
    CHECK_EQ(c.r[0].alarm_confidence, 82);
    CHECK_EQ(c.r[0].families_fired, 0x0F);

    /* The first alarm wins: a detector that keeps shouting earns no better
     * latency, and the moment it first spoke is not overwritten. */
    CHECK_EQ(bas_card_alarm(&c, 0, "Aegis", 99, 0x0F, BAS_SRC_SERIAL, 2900), BAS_OK);
    CHECK_EQ(bas_run_latency_ms(&c.r[0]), 1400);
    CHECK_EQ(c.r[0].alarm_confidence, 82);

    CHECK_EQ(bas_card_end(&c, 0, 4000, 300), BAS_OK);
    CHECK_EQ(c.r[0].frames_sent, 300);
    CHECK_EQ(bas_run_verdict(&c.r[0], 9000), BAS_VERDICT_CAUGHT);
    CHECK_EQ(bas_card_end(&c, 0, 4000, 300), BAS_ERR_RUN_CLOSED);

    SUITE("score: MISSED is only reached after the grace window");

    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_BEACON, 1000, 3000);
    CHECK_EQ(bas_card_end(&c, r, 5000, 100), BAS_OK);

    /* Emission ended at 5000; grace runs to 8000. */
    CHECK_EQ(bas_run_verdict(&c.r[r], 5000), BAS_VERDICT_PENDING);
    CHECK_EQ(bas_run_verdict(&c.r[r], 7999), BAS_VERDICT_PENDING);
    CHECK_EQ(bas_run_verdict(&c.r[r], 8000), BAS_VERDICT_MISSED);
    CHECK_EQ(bas_run_verdict(&c.r[r], 9999), BAS_VERDICT_MISSED);

    SUITE("score: an alarm inside the grace window is LATE, not MISSED");

    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    CHECK_EQ(bas_card_end(&c, r, 5000, 100), BAS_OK);
    CHECK_EQ(bas_card_alarm(&c, r, "Pharos", 71, 0x03, BAS_SRC_SERIAL, 6200), BAS_OK);
    CHECK_EQ(bas_run_verdict(&c.r[r], 6200), BAS_VERDICT_LATE);
    CHECK_EQ(bas_run_verdict(&c.r[r], 20000), BAS_VERDICT_LATE);
    CHECK_EQ(bas_run_latency_ms(&c.r[r]), 5200);

    SUITE("score: an alarm past the grace window belongs to something else");

    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    CHECK_EQ(bas_card_end(&c, r, 5000, 100), BAS_OK);
    /* 8001 is past end+grace. Crediting it here would invent a working
     * detector out of an alarm that belonged to the next run. */
    CHECK_EQ(bas_card_alarm(&c, r, "Aegis", 90, 0x01, BAS_SRC_SERIAL, 8001), BAS_ERR_ARG);
    CHECK(!c.r[r].alarm_seen);
    CHECK_EQ(bas_run_verdict(&c.r[r], 9000), BAS_VERDICT_MISSED);

    /* An alarm before the run started is equally not ours. */
    CHECK_EQ(bas_card_alarm(&c, r, "Aegis", 90, 0x01, BAS_SRC_SERIAL, 500), BAS_ERR_ARG);

    SUITE("score: boundaries of the grace window");

    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    bas_card_end(&c, r, 5000, 10);
    /* Exactly on the deadline still counts. */
    CHECK_EQ(bas_card_alarm(&c, r, "Argus", 60, 0x01, BAS_SRC_SERIAL, 8000), BAS_OK);
    CHECK_EQ(bas_run_verdict(&c.r[r], 8000), BAS_VERDICT_LATE);

    /* An alarm exactly at the end of emission is a catch, not a late. */
    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    bas_card_end(&c, r, 5000, 10);
    CHECK_EQ(bas_card_alarm(&c, r, "Argus", 60, 0x01, BAS_SRC_SERIAL, 5000), BAS_OK);
    CHECK_EQ(bas_run_verdict(&c.r[r], 6000), BAS_VERDICT_CAUGHT);

    SUITE("score: confidence is clamped to 100");

    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    bas_card_alarm(&c, r, "X", 250, 0, BAS_SRC_SERIAL, 1500);
    CHECK_EQ(c.r[r].alarm_confidence, 100);

    SUITE("score: tally across a session");

    bas_card_reset(&c);
    int a = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);
    bas_card_alarm(&c, a, "Aegis", 80, 0x0F, BAS_SRC_SERIAL, 2000);      /* caught, 1000ms  */
    bas_card_end(&c, a, 4000, 40);

    int b = bas_card_begin(&c, BAS_FAM_BEACON, 5000, 3000);
    bas_card_end(&c, b, 7000, 40);
    bas_card_alarm(&c, b, "Aegis", 55, 0x01, BAS_SRC_SERIAL, 8500);      /* late, 3500ms    */

    int d = bas_card_begin(&c, BAS_FAM_PROBE_REQ, 9000, 3000);
    bas_card_end(&c, d, 10000, 40);                       /* missed          */

    int e = bas_card_begin(&c, BAS_FAM_BLE_ADV, 20000, 3000);
    (void)e;                                              /* still running   */

    bas_tally_t t;
    bas_card_tally(&c, 21000, &t);
    CHECK_EQ(t.caught, 1);
    CHECK_EQ(t.late, 1);
    CHECK_EQ(t.missed, 1);
    CHECK_EQ(t.pending, 1);
    CHECK_EQ(t.best_latency_ms, 1000);
    CHECK_EQ(t.worst_latency_ms, 3500);

    SUITE("score: report line");

    char line[96];
    bas_run_line(&c.r[a], 21000, line, sizeof(line));
    CHECK(strstr(line, "Deauthentication") != NULL);
    CHECK(strstr(line, "CAUGHT") != NULL);
    CHECK(strstr(line, "Aegis") != NULL);
    CHECK(strstr(line, "1.0s") != NULL);

    bas_run_line(&c.r[d], 21000, line, sizeof(line));
    CHECK(strstr(line, "MISSED") != NULL);

    /* A tiny buffer must truncate, never overrun. */
    char tiny[8];
    bas_run_line(&c.r[a], 21000, tiny, sizeof(tiny));
    CHECK(strlen(tiny) < sizeof(tiny));

    SUITE("score: bad indices and a full card");

    CHECK_EQ(bas_card_end(&c, 99, 1000, 0), BAS_ERR_NO_RUN);
    CHECK_EQ(bas_card_end(&c, -1, 1000, 0), BAS_ERR_NO_RUN);
    CHECK_EQ(bas_card_alarm(&c, 99, "X", 10, 0, BAS_SRC_SERIAL, 1000), BAS_ERR_NO_RUN);
    CHECK_EQ(bas_card_begin(&c, (bas_family_t)999, 1000, 3000), -1);

    bas_card_reset(&c);
    for (int i = 0; i < BAS_MAX_RUNS; i++) {
        CHECK(bas_card_begin(&c, BAS_FAM_PROBE_REQ, 1000, 3000) >= 0);
    }
    CHECK_EQ(bas_card_begin(&c, BAS_FAM_PROBE_REQ, 1000, 3000), -1);

    SUITE("score: no letter grade exists");

    /* Deliberate: one run against one signal is not evidence about a detector
     * in general, and a letter would imply that it was. If someone adds a
     * bas_card_grade() later, this comment is the reason not to. */
    CHECK_STR(bas_verdict_name(BAS_VERDICT_CAUGHT), "CAUGHT");
    CHECK_STR(bas_verdict_name(BAS_VERDICT_MISSED), "MISSED");
    CHECK_STR(bas_verdict_name(BAS_VERDICT_PENDING), "PENDING");
    CHECK_STR(bas_verdict_name(BAS_VERDICT_LATE), "LATE");
}
