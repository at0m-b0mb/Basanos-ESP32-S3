/* Basanos — alarm ingest, including hostile input from a detector's serial
 * line. A malformed line must never become a phantom catch.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/alarm.h"
#include "basanos/score.h"

void suite_alarm(void)
{
    SUITE("alarm: a well-formed line");

    bas_alarm_t a;
    CHECK(bas_alarm_parse("BASANOS-ALARM detector=Aegis conf=82 fam=0x0F",
                          BAS_SRC_SERIAL, &a));
    CHECK(a.valid);
    CHECK_STR(a.detector, "Aegis");
    CHECK_EQ(a.confidence, 82);
    CHECK_EQ(a.families, 0x0F);
    CHECK_EQ(a.source, BAS_SRC_SERIAL);

    SUITE("alarm: keys in any order, decimal or hex, extra keys ignored");

    CHECK(bas_alarm_parse("BASANOS-ALARM fam=15 conf=100 detector=Pharos",
                          BAS_SRC_NETWORK, &a));
    CHECK_STR(a.detector, "Pharos");
    CHECK_EQ(a.families, 15);
    CHECK_EQ(a.confidence, 100);

    /* An unknown key must not break an older instrument. */
    CHECK(bas_alarm_parse("BASANOS-ALARM detector=Argus rssi=-40 zone=lab conf=5",
                          BAS_SRC_SERIAL, &a));
    CHECK_STR(a.detector, "Argus");
    CHECK_EQ(a.confidence, 5);

    /* Leading whitespace and trailing newline are normal on a serial line. */
    CHECK(bas_alarm_parse("   BASANOS-ALARM detector=Aegis\r\n", BAS_SRC_SERIAL, &a));
    CHECK_STR(a.detector, "Aegis");
    CHECK_EQ(a.confidence, 0);
    CHECK_EQ(a.families, 0);

    SUITE("alarm: the prefix must start the line");

    /* A detector printing an example of the format in its own help text is
     * the realistic way a log-scraping parser invents an alarm. */
    CHECK(!bas_alarm_parse("usage: see BASANOS-ALARM detector=X for the format",
                           BAS_SRC_SERIAL, &a));
    CHECK(!a.valid);

    CHECK(!bas_alarm_parse("BASANOS-ALARMED detector=X", BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse("XBASANOS-ALARM detector=X", BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse("BASANOS-ALAR detector=X", BAS_SRC_SERIAL, &a));

    SUITE("alarm: a detector name is required");

    CHECK(!bas_alarm_parse("BASANOS-ALARM conf=90 fam=3", BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse("BASANOS-ALARM detector=", BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse("BASANOS-ALARM", BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse("", BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse(NULL, BAS_SRC_SERIAL, &a));
    CHECK(!bas_alarm_parse("BASANOS-ALARM detector=X", (bas_alarm_src_t)99, &a));

    SUITE("alarm: numbers are clamped and overflow is refused");

    CHECK(bas_alarm_parse("BASANOS-ALARM detector=X conf=250", BAS_SRC_SERIAL, &a));
    CHECK_EQ(a.confidence, 100);

    /* A crafted enormous value must not wrap into a small plausible one. */
    CHECK(bas_alarm_parse("BASANOS-ALARM detector=X conf=99999999999999999",
                          BAS_SRC_SERIAL, &a));
    CHECK_EQ(a.confidence, 0);

    /* Trailing junk is not a number. */
    CHECK(bas_alarm_parse("BASANOS-ALARM detector=X conf=42abc", BAS_SRC_SERIAL, &a));
    CHECK_EQ(a.confidence, 0);

    CHECK(bas_alarm_parse("BASANOS-ALARM detector=X conf=0x2A", BAS_SRC_SERIAL, &a));
    CHECK_EQ(a.confidence, 42);

    CHECK(bas_alarm_parse("BASANOS-ALARM detector=X fam=0x1FF", BAS_SRC_SERIAL, &a));
    CHECK_EQ(a.families, 0xFF);

    SUITE("alarm: a long detector name truncates rather than overruns");

    CHECK(bas_alarm_parse("BASANOS-ALARM detector=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                          BAS_SRC_SERIAL, &a));
    CHECK_EQ(strlen(a.detector), BAS_ALARM_NAME_MAX - 1u);

    SUITE("alarm: provenance travels with the measurement");

    CHECK_STR(bas_alarm_src_name(BAS_SRC_OPERATOR), "operator");
    CHECK_STR(bas_alarm_src_name(BAS_SRC_SERIAL), "serial");
    CHECK_STR(bas_alarm_src_name(BAS_SRC_NETWORK), "network");

    /* A human thumb and a UART are not the same measurement and must never be
     * averaged together, so the report can always tell them apart. */
    CHECK(!bas_alarm_src_is_machine(BAS_SRC_OPERATOR));
    CHECK(bas_alarm_src_is_machine(BAS_SRC_SERIAL));
    CHECK(bas_alarm_src_is_machine(BAS_SRC_NETWORK));

    SUITE("alarm: crediting a parsed line to a run");

    bas_card_t c;
    bas_card_reset(&c);
    int r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);

    bas_alarm_t good;
    CHECK(bas_alarm_parse("BASANOS-ALARM detector=Aegis conf=77 fam=0x0F",
                          BAS_SRC_SERIAL, &good));
    CHECK_EQ(bas_card_alarm_from(&c, r, &good, 2500), BAS_OK);
    CHECK_EQ(bas_run_verdict(&c.r[r], 2500), BAS_VERDICT_CAUGHT);
    CHECK_EQ(c.r[r].alarm_confidence, 77);
    CHECK_EQ(c.r[r].alarm_source, BAS_SRC_SERIAL);
    CHECK_EQ(bas_run_latency_ms(&c.r[r]), 1500);

    /* The source reaches the report line. */
    char line[128];
    bas_run_line(&c.r[r], 2500, line, sizeof(line));
    CHECK(strstr(line, "via serial") != NULL);

    SUITE("alarm: a line that failed to parse is never a catch");

    bas_card_reset(&c);
    r = bas_card_begin(&c, BAS_FAM_DEAUTH, 1000, 3000);

    bas_alarm_t bad;
    CHECK(!bas_alarm_parse("garbage from the serial port", BAS_SRC_SERIAL, &bad));
    CHECK_EQ(bas_card_alarm_from(&c, r, &bad, 2500), BAS_ERR_ARG);
    CHECK(!c.r[r].alarm_seen);
    CHECK_EQ(bas_card_alarm_from(&c, r, NULL, 2500), BAS_ERR_ARG);
    CHECK(!c.r[r].alarm_seen);

    bas_card_end(&c, r, 3000, 10);
    CHECK_EQ(bas_run_verdict(&c.r[r], 7000), BAS_VERDICT_MISSED);
}
