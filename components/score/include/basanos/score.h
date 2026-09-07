/* Basanos — the scorecard. This is the part that makes it an instrument.
 *
 * Every other ESP32 Wi-Fi tool answers "can I knock this over?". Basanos
 * answers "did my detector see it?" — so the run is not finished when the
 * emission stops, it is finished when the detector has had its fair chance to
 * react and either did or did not.
 *
 * The honesty rule, and the reason PENDING exists: a run is never called
 * MISSED until the grace window after the emission has fully elapsed. A
 * detector that alarms two seconds after the burst ends has caught it; an
 * instrument that scored the moment the burst stopped would call that a miss
 * and quietly slander a working detector.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_SCORE_H
#define BASANOS_SCORE_H

#include "basanos/family.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BAS_VERDICT_PENDING = 0, /* still emitting, or inside the grace window   */
    BAS_VERDICT_CAUGHT,      /* alarmed while the signal was still on air    */
    BAS_VERDICT_LATE,        /* alarmed, but only after the emission ended   */
    BAS_VERDICT_MISSED       /* grace elapsed with no alarm                  */
} bas_verdict_t;

const char *bas_verdict_name(bas_verdict_t v);

/* How long after a burst ends an alarm still counts. Detectors in this
 * catalogue use sliding windows measured in seconds; three is long enough to
 * be fair to every one of them and short enough that an operator will wait. */
#define BAS_GRACE_DEFAULT_MS 3000u

#define BAS_DETECTOR_NAME_MAX 24

typedef struct {
    bool         used;
    bas_family_t fam;
    uint32_t     emit_start_ms;
    uint32_t     emit_end_ms;      /* 0 while still running                  */
    bool         closed;
    uint32_t     grace_ms;
    uint32_t     frames_sent;

    bool         alarm_seen;
    uint32_t     alarm_ms;
    uint8_t      alarm_confidence; /* 0..100 as the detector reported it     */
    char         alarm_detector[BAS_DETECTOR_NAME_MAX];
    uint8_t      families_fired;   /* bitmask, for 4-family detectors        */
} bas_run_t;

#define BAS_MAX_RUNS 32

typedef struct {
    bas_run_t r[BAS_MAX_RUNS];
    uint8_t   count;
} bas_card_t;

void bas_card_reset(bas_card_t *c);

/* Open a run. Returns the run index, or -1 when the card is full. */
int bas_card_begin(bas_card_t *c, bas_family_t f, uint32_t now_ms, uint32_t grace_ms);

/* Close the emission window. Alarms are still accepted afterwards, for
 * grace_ms — that is the whole point. */
bas_err_t bas_card_end(bas_card_t *c, int idx, uint32_t now_ms, uint32_t frames_sent);

/* Record a detector alarm. The FIRST alarm wins: latency is measured to the
 * moment the detector first spoke, and a detector that keeps shouting does not
 * get a better score for it. Alarms outside [start, end + grace] are refused,
 * so an alarm belonging to a previous run cannot be credited to this one. */
bas_err_t bas_card_alarm(bas_card_t *c, int idx,
                         const char *detector, uint8_t confidence,
                         uint8_t families_fired, uint32_t now_ms);

bas_verdict_t bas_run_verdict(const bas_run_t *r, uint32_t now_ms);

/* Milliseconds from the start of emission to the first alarm, or -1 when the
 * detector never alarmed. Latency is measured from emission start rather than
 * from the first frame's ACK because that is the number an operator can act
 * on: "it took four seconds from when I pressed the button". */
int32_t bas_run_latency_ms(const bas_run_t *r);

typedef struct {
    int caught, late, missed, pending;
    int32_t best_latency_ms;   /* -1 when nothing was caught                */
    int32_t worst_latency_ms;
} bas_tally_t;

void bas_card_tally(const bas_card_t *c, uint32_t now_ms, bas_tally_t *out);

/* One line for the report, e.g.
 *   "DEAUTH  CAUGHT  1.4s  Aegis  conf 82"
 * Writes at most out_sz bytes and always terminates. */
void bas_run_line(const bas_run_t *r, uint32_t now_ms, char *out, size_t out_sz);

/* The instrument does not grade the detector's *design*, only this run. There
 * is deliberately no bas_card_grade() returning A+..F: one run against one
 * signal is not evidence about a detector in general, and a letter would imply
 * it was. The tally is what the device shows. */

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_SCORE_H */
