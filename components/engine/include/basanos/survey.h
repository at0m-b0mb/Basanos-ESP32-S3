/* Basanos — passive survey: what is on air, and where it is quiet.
 *
 * Two jobs. Before a run, find a channel whose baseline is known, so the
 * emission is measured against something rather than into noise. During a run,
 * count what else was on air — so "the detector was busy" becomes a number in
 * the report instead of an excuse afterwards.
 *
 * Receive only.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_SURVEY_H
#define BASANOS_SURVEY_H

#include "basanos/family.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BAS_FT_BEACON = 0,
    BAS_FT_PROBE_REQ,
    BAS_FT_PROBE_RESP,
    BAS_FT_AUTH,
    BAS_FT_ASSOC,
    BAS_FT_DEAUTH,
    BAS_FT_DISASSOC,
    BAS_FT_MGMT_OTHER,
    BAS_FT_CTRL,
    BAS_FT_DATA,
    BAS_FT__COUNT
} bas_ftype_t;

const char *bas_ftype_name(bas_ftype_t t);

/* Classify from the 802.11 frame-control field's type and subtype. */
bas_ftype_t bas_ftype_of(uint8_t fc_type, uint8_t fc_subtype);

typedef struct {
    uint32_t frames[BAS_FT__COUNT];
    uint32_t total;
    uint32_t bytes;
    uint32_t started_ms;
    uint32_t updated_ms;
} bas_fcount_t;

void bas_fcount_reset(bas_fcount_t *f, uint32_t now_ms);
void bas_fcount_add(bas_fcount_t *f, bas_ftype_t t, uint16_t bytes, uint32_t now_ms);

/* Frames per second over the counted window, x100 to keep it integer. Returns
 * 0 when the window is too short to mean anything rather than dividing by a
 * near-zero interval and reporting a spectacular fictional rate. */
uint32_t bas_fcount_rate_x100(const bas_fcount_t *f);

/* --- channel occupancy --------------------------------------------------- */

#define BAS_CH_MIN 1u
#define BAS_CH_MAX 14u
#define BAS_CH_SLOTS (BAS_CH_MAX + 1u)   /* index by channel number, 0 unused */

typedef struct {
    uint32_t frames[BAS_CH_SLOTS];
    uint8_t  aps[BAS_CH_SLOTS];
    int8_t   peak_rssi[BAS_CH_SLOTS];
    uint32_t dwell_ms[BAS_CH_SLOTS];
} bas_chansurvey_t;

void bas_chan_reset(bas_chansurvey_t *c);
void bas_chan_note_frame(bas_chansurvey_t *c, uint8_t ch, int8_t rssi);
void bas_chan_note_ap(bas_chansurvey_t *c, uint8_t ch);
void bas_chan_note_dwell(bas_chansurvey_t *c, uint8_t ch, uint32_t ms);

/* The least occupied channel inside the current regulatory domain, weighing
 * access points more heavily than frames — a channel with three APs on it is
 * busier in the way that matters than one with a chatty neighbour.
 *
 * Returns 0 when no channel has been dwelt on long enough to judge. The caller
 * must treat that as "do not know" rather than "channel zero". */
uint8_t bas_chan_quietest(const bas_chansurvey_t *c, uint32_t min_dwell_ms);

/* Occupancy score for one channel, 0..100. Used by the UI bar chart. */
uint8_t bas_chan_score(const bas_chansurvey_t *c, uint8_t ch);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_SURVEY_H */
