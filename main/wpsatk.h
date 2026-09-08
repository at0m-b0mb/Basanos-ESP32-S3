/* Basanos — WPS PIN recovery against the locked target.
 * SPDX-License-Identifier: MIT */
#ifndef BASANOS_WPSATK_H
#define BASANOS_WPSATK_H

#include "basanos/pixie.h"
#include "basanos/wpspin.h"
#include "esp_err.h"

typedef enum {
    BAS_WPSATK_IDLE = 0,
    BAS_WPSATK_RUNNING,
    BAS_WPSATK_GOT_PIN,      /* the PIN was accepted; credential in hand   */
    BAS_WPSATK_LOCKED,       /* the AP stopped answering: lockout          */
    BAS_WPSATK_EXHAUSTED,    /* every candidate tried, none accepted       */
    BAS_WPSATK_NO_WPS,       /* the AP never negotiated WPS at all         */
} bas_wpsatk_state_t;

typedef struct {
    bas_wpsatk_state_t state;
    uint32_t  pin;                   /* recovered PIN, or 0                */
    char      ssid[33];
    char      passphrase[65];        /* the credential, when recovered     */
    bool      have_cred;
    uint32_t  attempts;
    uint32_t  m2d;                   /* "not for you" replies: lockout tell*/
    bas_pinalg_t alg;                /* which derivation produced the PIN  */
    /* Pixie material, harvested from the one exchange that reached M4. */
    bool             have_material;
    bas_pixie_in_t   material;
    bas_pixie_out_t  pixie;
} bas_wpsatk_result_t;

/* One WPS exchange with a supplied PIN. Returns when the exchange settles.
 * `out` accumulates across calls, so a caller may loop over candidates. */
esp_err_t bas_wpsatk_try(uint32_t pin, uint32_t timeout_ms,
                         bas_wpsatk_result_t *out);

/* Harvest whatever the supplicant's WPS state machine currently holds. Valid
 * only immediately after an exchange that reached M4. Returns false when the
 * state machine is gone or the material is incomplete -- which is the normal
 * outcome against an AP that never got that far. */
bool bas_wpsatk_material(bas_pixie_in_t *out);

const char *bas_wpsatk_state_name(bas_wpsatk_state_t s);

#endif /* BASANOS_WPSATK_H */
