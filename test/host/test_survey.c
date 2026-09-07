/* Basanos — passive survey. SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/survey.h"

void suite_survey(void)
{
    SUITE("survey: frame classification from type and subtype");

    CHECK_EQ(bas_ftype_of(0, 8),  BAS_FT_BEACON);
    CHECK_EQ(bas_ftype_of(0, 4),  BAS_FT_PROBE_REQ);
    CHECK_EQ(bas_ftype_of(0, 5),  BAS_FT_PROBE_RESP);
    CHECK_EQ(bas_ftype_of(0, 11), BAS_FT_AUTH);
    CHECK_EQ(bas_ftype_of(0, 12), BAS_FT_DEAUTH);
    CHECK_EQ(bas_ftype_of(0, 10), BAS_FT_DISASSOC);
    CHECK_EQ(bas_ftype_of(0, 0),  BAS_FT_ASSOC);
    CHECK_EQ(bas_ftype_of(0, 2),  BAS_FT_ASSOC);   /* reassoc counts too  */
    CHECK_EQ(bas_ftype_of(0, 13), BAS_FT_MGMT_OTHER);
    CHECK_EQ(bas_ftype_of(1, 11), BAS_FT_CTRL);
    CHECK_EQ(bas_ftype_of(2, 0),  BAS_FT_DATA);
    CHECK_EQ(bas_ftype_of(3, 0),  BAS_FT_MGMT_OTHER);

    CHECK_STR(bas_ftype_name(BAS_FT_DEAUTH), "deauth");
    CHECK_STR(bas_ftype_name(BAS_FT__COUNT), "?");

    SUITE("survey: frame counters");

    bas_fcount_t f;
    bas_fcount_reset(&f, 1000);
    CHECK_EQ(f.total, 0);

    bas_fcount_add(&f, BAS_FT_BEACON, 128, 1100);
    bas_fcount_add(&f, BAS_FT_BEACON, 128, 1200);
    bas_fcount_add(&f, BAS_FT_DEAUTH, 26, 1300);
    CHECK_EQ(f.total, 3);
    CHECK_EQ(f.frames[BAS_FT_BEACON], 2);
    CHECK_EQ(f.frames[BAS_FT_DEAUTH], 1);
    CHECK_EQ(f.bytes, 282);

    /* An out-of-range type is dropped, not written past the array. */
    bas_fcount_add(&f, (bas_ftype_t)99, 100, 1400);
    bas_fcount_add(&f, (bas_ftype_t)-1, 100, 1400);
    CHECK_EQ(f.total, 3);

    SUITE("survey: a rate needs a window worth measuring");

    /* Three frames in 300 ms is 10/s. */
    CHECK_EQ(bas_fcount_rate_x100(&f), 1000);

    /* Two frames 3 ms apart is not "666 per second" — it is not a measurement
     * at all, and reporting a number would put a fiction on the scorecard. */
    bas_fcount_t q;
    bas_fcount_reset(&q, 1000);
    bas_fcount_add(&q, BAS_FT_BEACON, 10, 1001);
    bas_fcount_add(&q, BAS_FT_BEACON, 10, 1003);
    CHECK_EQ(bas_fcount_rate_x100(&q), 0);

    CHECK_EQ(bas_fcount_rate_x100(NULL), 0);

    SUITE("survey: channel occupancy");

    bas_chansurvey_t c;
    bas_chan_reset(&c);
    CHECK_EQ(c.peak_rssi[6], -128);

    bas_chan_note_ap(&c, 6);
    bas_chan_note_ap(&c, 6);
    bas_chan_note_ap(&c, 6);
    for (int i = 0; i < 40; i++) {
        bas_chan_note_frame(&c, 6, (int8_t)(-70 + i));
    }
    CHECK_EQ(c.aps[6], 3);
    CHECK_EQ(c.frames[6], 40);
    CHECK_EQ(c.peak_rssi[6], -31);

    /* 3 APs * 12 + 40/8 = 41 */
    CHECK_EQ(bas_chan_score(&c, 6), 41);

    /* Out-of-range channels are ignored rather than indexed. */
    bas_chan_note_ap(&c, 0);
    bas_chan_note_ap(&c, 15);
    bas_chan_note_ap(&c, 255);
    bas_chan_note_frame(&c, 0, -20);
    bas_chan_note_frame(&c, 200, -20);
    CHECK_EQ(bas_chan_score(&c, 0), 0);
    CHECK_EQ(bas_chan_score(&c, 15), 0);

    SUITE("survey: the score saturates rather than wrapping");

    bas_chansurvey_t big;
    bas_chan_reset(&big);
    for (int i = 0; i < 250; i++) {
        bas_chan_note_ap(&big, 1);
    }
    CHECK_EQ(bas_chan_score(&big, 1), 100);

    SUITE("survey: quietest channel, and refusing to guess");

    bas_chansurvey_t q2;
    bas_chan_reset(&q2);
    bas_region_set(BAS_REGION_FCC);

    /* Nothing dwelt on: the answer is "do not know", which is 0 — and the
     * caller must not read that as channel zero. */
    CHECK_EQ(bas_chan_quietest(&q2, 500), 0);

    bas_chan_note_dwell(&q2, 1, 1000);
    bas_chan_note_dwell(&q2, 6, 1000);
    bas_chan_note_dwell(&q2, 11, 1000);
    bas_chan_note_ap(&q2, 1);
    bas_chan_note_ap(&q2, 1);
    bas_chan_note_ap(&q2, 6);
    /* Channel 11 has nothing on it. */
    CHECK_EQ(bas_chan_quietest(&q2, 500), 11);

    /* A channel that was not listened to long enough is not eligible, even if
     * it looks empty — unmeasured is not the same as quiet. */
    bas_chan_note_dwell(&q2, 9, 100);
    CHECK_EQ(bas_chan_quietest(&q2, 500), 11);
    bas_chan_note_dwell(&q2, 9, 900);
    CHECK_EQ(bas_chan_quietest(&q2, 500), 9);

    SUITE("survey: the regulatory clamp bounds the search");

    bas_chansurvey_t r;
    bas_chan_reset(&r);
    for (uint8_t ch = 1; ch <= 14; ch++) {
        bas_chan_note_dwell(&r, ch, 1000);
        bas_chan_note_ap(&r, ch);
    }
    /* Channel 13 is empty but outside FCC, so it is never suggested. */
    bas_chan_reset(&r);
    for (uint8_t ch = 1; ch <= 14; ch++) {
        bas_chan_note_dwell(&r, ch, 1000);
        if (ch <= 11) {
            bas_chan_note_ap(&r, ch);
        }
    }
    bas_region_set(BAS_REGION_FCC);
    uint8_t pick = bas_chan_quietest(&r, 500);
    CHECK(pick >= 1 && pick <= 11);

    bas_region_set(BAS_REGION_ETSI);
    CHECK_EQ(bas_chan_quietest(&r, 500), 12);

    bas_region_set(BAS_REGION_FCC);

    SUITE("survey: null safety");

    bas_chan_reset(NULL);
    bas_chan_note_ap(NULL, 6);
    bas_chan_note_frame(NULL, 6, -50);
    bas_chan_note_dwell(NULL, 6, 100);
    CHECK_EQ(bas_chan_score(NULL, 6), 0);
    CHECK_EQ(bas_chan_quietest(NULL, 500), 0);
    bas_fcount_reset(NULL, 0);
    bas_fcount_add(NULL, BAS_FT_BEACON, 10, 0);
}
