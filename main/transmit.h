/* Basanos — the transmit engine.
 *
 * The only code in the firmware that puts a frame on air. Everything it emits
 * has passed the engagement lock immediately beforehand, per frame, not once
 * per run — an engagement that expires halfway through a burst stops the burst.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_TRANSMIT_H
#define BASANOS_TRANSMIT_H

#include "basanos/engage.h"
#include "basanos/family.h"
#include "esp_err.h"

/* Not every family has a radio path in this build. The UI shows the rest as
 * unavailable rather than hiding them, so the gap is visible instead of
 * looking like a feature nobody thought of. */
bool        bas_tx_supported(bas_family_t f);
const char *bas_tx_pending_reason(bas_family_t f);

typedef struct {
    uint32_t frames_sent;
    uint32_t frames_refused;   /* blocked by the gate — should stay 0      */
    uint32_t tx_errors;        /* the radio rejected the frame            */
    uint32_t elapsed_ms;
    bas_err_t stopped_by;      /* BAS_OK when the run completed normally  */
} bas_tx_result_t;

/* Called every ~100 ms during a run. Returning false aborts it: the UI uses
 * this for the abort button, so a run is always interruptible. */
typedef bool (*bas_tx_tick_cb)(const bas_tx_result_t *progress, void *ctx);

/* Run a validated plan. `e` must be locked and unexpired.
 *
 * Revalidates the plan against the role and engagement before starting, so a
 * caller cannot hand in a plan that was validated under different conditions
 * and have it accepted on the strength of that earlier check. */
esp_err_t bas_tx_run(const bas_plan_t *plan,
                     const bas_engagement_t *e,
                     uint8_t role,
                     bas_tx_tick_cb tick, void *ctx,
                     bas_tx_result_t *out);

#endif /* BASANOS_TRANSMIT_H */
