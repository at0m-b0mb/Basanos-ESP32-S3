/* Basanos — the scorecard. SPDX-License-Identifier: MIT */
#include "basanos/score.h"

#include <string.h>
#include <stdio.h>

const char *bas_verdict_name(bas_verdict_t v)
{
    switch (v) {
    case BAS_VERDICT_PENDING: return "PENDING";
    case BAS_VERDICT_CAUGHT:  return "CAUGHT";
    case BAS_VERDICT_LATE:    return "LATE";
    case BAS_VERDICT_MISSED:  return "MISSED";
    default:                  return "?";
    }
}

void bas_card_reset(bas_card_t *c)
{
    if (c == NULL) {
        return;
    }
    memset(c, 0, sizeof(*c));
}

int bas_card_begin(bas_card_t *c, bas_family_t f, uint32_t now_ms, uint32_t grace_ms)
{
    if (c == NULL || bas_family(f) == NULL) {
        return -1;
    }
    if (c->count >= BAS_MAX_RUNS) {
        return -1;
    }
    bas_run_t *r = &c->r[c->count];
    memset(r, 0, sizeof(*r));
    r->used          = true;
    r->fam           = f;
    r->emit_start_ms = now_ms;
    r->grace_ms      = (grace_ms == 0u) ? BAS_GRACE_DEFAULT_MS : grace_ms;
    c->count++;
    return (int)(c->count - 1u);
}

static bas_run_t *run_at(bas_card_t *c, int idx)
{
    if (c == NULL || idx < 0 || idx >= (int)c->count) {
        return NULL;
    }
    if (!c->r[idx].used) {
        return NULL;
    }
    return &c->r[idx];
}

bas_err_t bas_card_end(bas_card_t *c, int idx, uint32_t now_ms, uint32_t frames_sent)
{
    bas_run_t *r = run_at(c, idx);
    if (r == NULL) {
        return BAS_ERR_NO_RUN;
    }
    if (r->closed) {
        return BAS_ERR_RUN_CLOSED;
    }
    if ((int32_t)(now_ms - r->emit_start_ms) < 0) {
        return BAS_ERR_ARG;
    }
    r->emit_end_ms = now_ms;
    r->frames_sent = frames_sent;
    r->closed      = true;
    return BAS_OK;
}

bas_err_t bas_card_alarm_from(bas_card_t *c, int idx,
                              const bas_alarm_t *a, uint32_t now_ms)
{
    if (a == NULL || !a->valid) {
        /* A line that failed to parse is not evidence of anything. Crediting
         * it would manufacture a detector that works out of a typo. */
        return BAS_ERR_ARG;
    }
    return bas_card_alarm(c, idx, a->detector, a->confidence,
                          a->families, a->source, now_ms);
}

bas_err_t bas_card_alarm(bas_card_t *c, int idx,
                         const char *detector, uint8_t confidence,
                         uint8_t families_fired, bas_alarm_src_t src,
                         uint32_t now_ms)
{
    bas_run_t *r = run_at(c, idx);
    if (r == NULL) {
        return BAS_ERR_NO_RUN;
    }

    /* The first alarm wins. A detector that keeps shouting does not earn a
     * better latency, and a second alarm must not overwrite the moment it
     * first spoke. */
    if (r->alarm_seen) {
        return BAS_OK;
    }

    if ((int32_t)(now_ms - r->emit_start_ms) < 0) {
        return BAS_ERR_ARG;
    }

    /* An alarm after the grace window belongs to something else — most likely
     * the next run. Crediting it here would invent a detector that works. */
    if (r->closed) {
        uint32_t deadline = r->emit_end_ms + r->grace_ms;
        if ((int32_t)(now_ms - deadline) > 0) {
            return BAS_ERR_ARG;
        }
    }

    r->alarm_seen       = true;
    r->alarm_ms         = now_ms;
    r->alarm_confidence = (confidence > 100u) ? 100u : confidence;
    r->families_fired   = families_fired;
    r->alarm_source     = src;
    (void)bas_strlcpy(r->alarm_detector, detector, sizeof(r->alarm_detector));
    return BAS_OK;
}

bas_verdict_t bas_run_verdict(const bas_run_t *r, uint32_t now_ms)
{
    if (r == NULL || !r->used) {
        return BAS_VERDICT_PENDING;
    }

    if (r->alarm_seen) {
        /* Caught while the signal was still on air, or after it stopped. Both
         * are successes; the distinction is the useful part of the report. */
        if (!r->closed || (int32_t)(r->alarm_ms - r->emit_end_ms) <= 0) {
            return BAS_VERDICT_CAUGHT;
        }
        return BAS_VERDICT_LATE;
    }

    /* No alarm yet. This is only a miss once the detector has had the whole
     * grace window after the emission ended — never before. */
    if (!r->closed) {
        return BAS_VERDICT_PENDING;
    }
    uint32_t deadline = r->emit_end_ms + r->grace_ms;
    if ((int32_t)(now_ms - deadline) < 0) {
        return BAS_VERDICT_PENDING;
    }
    return BAS_VERDICT_MISSED;
}

int32_t bas_run_latency_ms(const bas_run_t *r)
{
    if (r == NULL || !r->used || !r->alarm_seen) {
        return -1;
    }
    return (int32_t)(r->alarm_ms - r->emit_start_ms);
}

void bas_card_tally(const bas_card_t *c, uint32_t now_ms, bas_tally_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->best_latency_ms  = -1;
    out->worst_latency_ms = -1;
    if (c == NULL) {
        return;
    }

    for (uint8_t i = 0; i < c->count; i++) {
        const bas_run_t *r = &c->r[i];
        if (!r->used) {
            continue;
        }
        switch (bas_run_verdict(r, now_ms)) {
        case BAS_VERDICT_CAUGHT:  out->caught++;  break;
        case BAS_VERDICT_LATE:    out->late++;    break;
        case BAS_VERDICT_MISSED:  out->missed++;  break;
        default:                  out->pending++; break;
        }

        int32_t lat = bas_run_latency_ms(r);
        if (lat >= 0) {
            if (out->best_latency_ms < 0 || lat < out->best_latency_ms) {
                out->best_latency_ms = lat;
            }
            if (out->worst_latency_ms < 0 || lat > out->worst_latency_ms) {
                out->worst_latency_ms = lat;
            }
        }
    }
}

void bas_run_line(const bas_run_t *r, uint32_t now_ms, char *out, size_t out_sz)
{
    if (out == NULL || out_sz == 0u) {
        return;
    }
    if (r == NULL || !r->used) {
        out[0] = '\0';
        return;
    }

    const bas_family_spec_t *s = bas_family(r->fam);
    const char *fam = (s != NULL) ? s->name : "?";
    bas_verdict_t v = bas_run_verdict(r, now_ms);
    int32_t lat = bas_run_latency_ms(r);

    if (lat >= 0) {
        /* The source is on the line because an operator's thumb and a UART are
         * not the same measurement, and a reader comparing two latencies needs
         * to see which is which without going back to the raw log. */
        snprintf(out, out_sz, "%s  %s  %d.%01ds  %s  conf %u  via %s",
                 fam, bas_verdict_name(v),
                 (int)(lat / 1000), (int)((lat % 1000) / 100),
                 r->alarm_detector[0] ? r->alarm_detector : "-",
                 (unsigned)r->alarm_confidence,
                 bas_alarm_src_name(r->alarm_source));
    } else {
        snprintf(out, out_sz, "%s  %s  -  -", fam, bas_verdict_name(v));
    }
}
