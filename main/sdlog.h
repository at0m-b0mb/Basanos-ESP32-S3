/* Basanos — the engagement log.
 *
 * Every emission is written to the card as one CSV row: when, under what
 * authorisation, by whom, at what, and what came back. This is the artefact
 * that goes in a deliverable, and it is the answer to "what exactly did you do
 * to our network" — which is a question a client is entitled to ask and a
 * professional tool should be able to answer without reconstruction.
 *
 * Two rules about what it holds:
 *
 *   - It records the authorisation LABEL the operator typed, because that is
 *     the claim under which the run happened.
 *   - It never records key material. The PMKID family writes whether one was
 *     offered; there is nothing else to write, because nothing else is kept.
 *
 * A missing or unmountable card is not an error. The device still runs and
 * still scores; the interface reports that the log is unavailable rather than
 * refusing to work, because an engagement in progress should not stop for
 * want of a filesystem.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_SDLOG_H
#define BASANOS_SDLOG_H

#include "basanos/engage.h"
#include "basanos/family.h"
#include "basanos/score.h"
#include "transmit.h"

#include <stdbool.h>

/* Mounts the card and opens the log. Returns false when there is no usable
 * card, which the caller should treat as a capability that is absent rather
 * than as a failure. */
bool bas_sdlog_init(void);
bool bas_sdlog_ready(void);

/* Rows written since boot, and the reason it is unavailable if it is. */
uint32_t    bas_sdlog_rows(void);
const char *bas_sdlog_status(void);

/* One row per run. `note` carries a family-specific finding — the PMKID
 * result, for instance — and may be NULL. */
void bas_sdlog_run(const bas_engagement_t *e, bas_family_t f,
                   const bas_plan_t *p, const bas_tx_result_t *r,
                   const char *note);

/* The verdict is only known after the grace window, so it is written as its
 * own row rather than held back — the emission row is the record that
 * something went on air, and must not wait on a detector. */
void bas_sdlog_verdict(const bas_engagement_t *e, const bas_run_t *run,
                       uint32_t now_ms);

#endif /* BASANOS_SDLOG_H */
