/* Basanos — passive survey. SPDX-License-Identifier: MIT */
#include "basanos/survey.h"

#include <string.h>

const char *bas_ftype_name(bas_ftype_t t)
{
    switch (t) {
    case BAS_FT_BEACON:     return "beacon";
    case BAS_FT_PROBE_REQ:  return "probe-req";
    case BAS_FT_PROBE_RESP: return "probe-resp";
    case BAS_FT_AUTH:       return "auth";
    case BAS_FT_ASSOC:      return "assoc";
    case BAS_FT_DEAUTH:     return "deauth";
    case BAS_FT_DISASSOC:   return "disassoc";
    case BAS_FT_MGMT_OTHER: return "mgmt";
    case BAS_FT_CTRL:       return "ctrl";
    case BAS_FT_DATA:       return "data";
    default:                return "?";
    }
}

bas_ftype_t bas_ftype_of(uint8_t fc_type, uint8_t fc_subtype)
{
    if (fc_type == 1u) {
        return BAS_FT_CTRL;
    }
    if (fc_type == 2u) {
        return BAS_FT_DATA;
    }
    if (fc_type != 0u) {
        return BAS_FT_MGMT_OTHER;
    }
    switch (fc_subtype) {
    case 0u:  return BAS_FT_ASSOC;       /* assoc request                 */
    case 1u:  return BAS_FT_ASSOC;       /* assoc response                */
    case 2u:  return BAS_FT_ASSOC;       /* reassoc request               */
    case 3u:  return BAS_FT_ASSOC;       /* reassoc response              */
    case 4u:  return BAS_FT_PROBE_REQ;
    case 5u:  return BAS_FT_PROBE_RESP;
    case 8u:  return BAS_FT_BEACON;
    case 10u: return BAS_FT_DISASSOC;
    case 11u: return BAS_FT_AUTH;
    case 12u: return BAS_FT_DEAUTH;
    default:  return BAS_FT_MGMT_OTHER;
    }
}

void bas_fcount_reset(bas_fcount_t *f, uint32_t now_ms)
{
    if (f == NULL) {
        return;
    }
    memset(f, 0, sizeof(*f));
    f->started_ms = now_ms;
    f->updated_ms = now_ms;
}

void bas_fcount_add(bas_fcount_t *f, bas_ftype_t t, uint16_t bytes, uint32_t now_ms)
{
    if (f == NULL || (int)t < 0 || t >= BAS_FT__COUNT) {
        return;
    }
    if (f->frames[t] < UINT32_MAX) {
        f->frames[t]++;
    }
    if (f->total < UINT32_MAX) {
        f->total++;
    }
    f->bytes += bytes;
    f->updated_ms = now_ms;
}

uint32_t bas_fcount_rate_x100(const bas_fcount_t *f)
{
    if (f == NULL) {
        return 0u;
    }
    uint32_t span = f->updated_ms - f->started_ms;
    /* Under a quarter second is not a measurement. Reporting a rate from a
     * 3 ms window turns two frames into "666 per second", which would be a
     * fiction the scorecard then reasons about. */
    if (span < 250u) {
        return 0u;
    }
    return (uint32_t)((uint64_t)f->total * 100000u / span);
}

/* --- channel occupancy --------------------------------------------------- */

void bas_chan_reset(bas_chansurvey_t *c)
{
    if (c == NULL) {
        return;
    }
    memset(c, 0, sizeof(*c));
    for (uint8_t i = 0; i < BAS_CH_SLOTS; i++) {
        c->peak_rssi[i] = -128;
    }
}

static bool ch_ok(uint8_t ch)
{
    return ch >= BAS_CH_MIN && ch <= BAS_CH_MAX;
}

void bas_chan_note_frame(bas_chansurvey_t *c, uint8_t ch, int8_t rssi)
{
    if (c == NULL || !ch_ok(ch)) {
        return;
    }
    if (c->frames[ch] < UINT32_MAX) {
        c->frames[ch]++;
    }
    if (rssi > c->peak_rssi[ch]) {
        c->peak_rssi[ch] = rssi;
    }
}

void bas_chan_note_ap(bas_chansurvey_t *c, uint8_t ch)
{
    if (c == NULL || !ch_ok(ch)) {
        return;
    }
    if (c->aps[ch] < 255u) {
        c->aps[ch]++;
    }
}

void bas_chan_note_dwell(bas_chansurvey_t *c, uint8_t ch, uint32_t ms)
{
    if (c == NULL || !ch_ok(ch)) {
        return;
    }
    c->dwell_ms[ch] += ms;
}

uint8_t bas_chan_score(const bas_chansurvey_t *c, uint8_t ch)
{
    if (c == NULL || !ch_ok(ch)) {
        return 0u;
    }
    /* An access point is worth more than a frame: a channel with three APs is
     * busier in the way that matters for a beacon test than one carrying a
     * neighbour's file transfer. 12 points per AP, 1 per 8 frames. */
    uint32_t s = (uint32_t)c->aps[ch] * 12u + c->frames[ch] / 8u;
    return (uint8_t)(s > 100u ? 100u : s);
}

uint8_t bas_chan_quietest(const bas_chansurvey_t *c, uint32_t min_dwell_ms)
{
    if (c == NULL) {
        return 0u;
    }
    uint8_t best = 0u;
    uint32_t best_score = 0u;
    uint8_t max_ch = bas_region_max_channel();

    for (uint8_t ch = BAS_CH_MIN; ch <= max_ch && ch <= BAS_CH_MAX; ch++) {
        /* A channel nobody listened to is not quiet, it is unmeasured. */
        if (c->dwell_ms[ch] < min_dwell_ms) {
            continue;
        }
        uint32_t s = bas_chan_score(c, ch);
        if (best == 0u || s < best_score) {
            best = ch;
            best_score = s;
        }
    }
    return best;
}
