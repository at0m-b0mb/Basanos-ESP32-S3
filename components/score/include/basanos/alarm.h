/* Basanos — alarm ingest: how the instrument learns that a detector fired.
 *
 * This closes the measurement loop. Emitting a signal is only half of a test;
 * the other half is observing the response, and a detector under test can
 * report in three ways:
 *
 *   OPERATOR  the person watching the detector taps the screen. Works with
 *             every detector ever built, including one with no interface but
 *             a buzzer. Latency includes human reaction time, and the report
 *             says so rather than pretending otherwise.
 *   SERIAL    the detector prints a line on the UART pads. Machine timing.
 *   NETWORK   the detector posts to the instrument over Wi-Fi.
 *
 * The source travels with the alarm all the way into the report, because a
 * 300 ms latency from a wire and a 300 ms latency from a human thumb are not
 * the same measurement and must never be averaged together.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_ALARM_H
#define BASANOS_ALARM_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BAS_SRC_OPERATOR = 0,
    BAS_SRC_SERIAL,
    BAS_SRC_NETWORK,
    BAS_SRC__COUNT
} bas_alarm_src_t;

const char *bas_alarm_src_name(bas_alarm_src_t s);

/* True when this source's timing is machine-measured. The report separates
 * these from operator-reported alarms rather than mixing the two. */
bool bas_alarm_src_is_machine(bas_alarm_src_t s);

#define BAS_ALARM_NAME_MAX 24

typedef struct {
    char            detector[BAS_ALARM_NAME_MAX];
    uint8_t         confidence;     /* 0..100, clamped on parse            */
    uint8_t         families;       /* bitmask, detector-defined           */
    bas_alarm_src_t source;
    bool            valid;
} bas_alarm_t;

/* The line format a detector prints to report itself. Deliberately trivial to
 * emit from an embedded device with no JSON library:
 *
 *   BASANOS-ALARM detector=Aegis conf=82 fam=0x0F
 *
 * Keys may appear in any order. `detector` is required; `conf` defaults to 0
 * and `fam` to 0. Unknown keys are ignored so the format can grow without
 * breaking older instruments.
 *
 * Returns false and leaves `out->valid` false for anything that is not a
 * well-formed alarm line — including a line that merely contains the prefix
 * somewhere in the middle, which is how a log-scraping parser gets fooled by
 * a detector printing an example of the format in its own help text. */
bool bas_alarm_parse(const char *line, bas_alarm_src_t src, bas_alarm_t *out);

#define BAS_ALARM_PREFIX "BASANOS-ALARM"

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_ALARM_H */
