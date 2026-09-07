/* Basanos — application entry and the flow that leads to a transmission.
 *
 *   survey -> pick one network -> name the authorisation -> lock
 *          -> pick a family -> arm (hold, for the disruptive ones)
 *          -> run -> score it
 *
 * There is no path through this file that transmits without a locked
 * engagement, and none that reaches a disruptive family without a sustained
 * hold at the device.
 *
 * SPDX-License-Identifier: MIT
 */
#include "board.h"
#include "display.h"
#include "frames.h"
#include "power.h"
#include "selftest.h"
#include "touch.h"
#include "transmit.h"
#include "ui.h"
#include "ui_attack.h"

#include "basanos/rbac.h"
#include "basanos/score.h"
#include "basanos/station.h"
#include "basanos/target.h"

#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "basanos";

static bas_scan_t       s_scan;
static bas_engagement_t s_engage;
static bas_card_t       s_card;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* --- input ---------------------------------------------------------------

   Three buttons: left accepts, middle is power, right changes the selection.
   Back is a long press on the left button, because the middle one belongs to
   the power circuit and stealing it for navigation would make "hold to switch
   off" ambiguous.
   ------------------------------------------------------------------------- */

typedef enum {
    EV_NONE = 0,
    EV_ACCEPT,
    EV_BACK,
    EV_NEXT,
    EV_POWEROFF,
} input_ev_t;

#define HOLD_BACK_MS  600u
#define HOLD_OFF_MS  1500u

static void buttons_init(void)
{
    gpio_config_t c = {
        .pin_bit_mask = (1ULL << BOARD_BTN_ACCEPT) |
                        (1ULL << BOARD_BTN_NEXT)   |
                        (1ULL << BOARD_BTN_PWR),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&c));
}

static bool held(gpio_num_t pin) { return gpio_get_level(pin) == 0; }

static input_ev_t input_poll(void)
{
    static uint32_t accept_since, pwr_since;
    static bool     accept_was, next_was, pwr_was, accept_fired;
    uint32_t t = now_ms();

    /* Power: acts while still held, so the operator gets the shutdown at the
     * moment the hold completes rather than on release. */
    bool pwr = held(BOARD_BTN_PWR);
    if (pwr && !pwr_was) {
        pwr_since = t;
    }
    pwr_was = pwr;
    if (pwr && (t - pwr_since) >= HOLD_OFF_MS) {
        return EV_POWEROFF;
    }

    bool a = held(BOARD_BTN_ACCEPT);
    if (a && !accept_was) {
        accept_since = t;
        accept_fired = false;
    }
    /* Back fires on the threshold, not on release, so the operator feels the
     * distinction between a tap and a hold without waiting to find out. */
    if (a && !accept_fired && (t - accept_since) >= HOLD_BACK_MS) {
        accept_fired = true;
        accept_was = a;
        return EV_BACK;
    }
    bool accept_edge = (!a && accept_was && !accept_fired);
    accept_was = a;

    bool n = held(BOARD_BTN_NEXT);
    bool next_edge = (n && !next_was);
    next_was = n;

    if (accept_edge) { return EV_ACCEPT; }
    if (next_edge)   { return EV_NEXT; }
    return EV_NONE;
}

/* Level read for the hold-to-arm gesture. */
static bool input_held_down(void)
{
    if (held(BOARD_BTN_ACCEPT)) {
        return true;
    }
    if (bas_touch_present()) {
        bas_touch_t t;
        if (bas_touch_read(&t) && t.down) {
            return true;
        }
    }
    return false;
}

/* --- Wi-Fi --------------------------------------------------------------- */

static bas_sec_t sec_of(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN:          return BAS_SEC_OPEN;
    case WIFI_AUTH_WEP:           return BAS_SEC_WEP;
    case WIFI_AUTH_WPA_PSK:       return BAS_SEC_WPA;
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_WPA_WPA2_PSK:  return BAS_SEC_WPA2;
    case WIFI_AUTH_ENTERPRISE:    return BAS_SEC_WPA2_ENT;
    case WIFI_AUTH_WPA3_PSK:      return BAS_SEC_WPA3;
    case WIFI_AUTH_WPA2_WPA3_PSK: return BAS_SEC_WPA2_WPA3;
    case WIFI_AUTH_OWE:           return BAS_SEC_WPA3;
    default:                      return BAS_SEC_UNKNOWN;
    }
}

static void wifi_init(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());

    /* Optional subsystems must fail gracefully: ESP_ERROR_CHECK on a
     * double-init returns ESP_ERR_INVALID_STATE and turns a harmless case into
     * a boot loop. */
    esp_err_t rc = esp_event_loop_create_default();
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(rc);
    }

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void survey(void)
{
    bas_scan_reset(&s_scan);

    /* Passive: listen for beacons rather than soliciting responses. */
    wifi_scan_config_t cfg = {
        .ssid = NULL, .bssid = NULL, .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_PASSIVE,
        .scan_time.passive = 120,
    };

    for (uint8_t ch = 1; ch <= 13; ch++) {
        bas_ui_scanning(ch);
        cfg.channel = ch;
        if (esp_wifi_scan_start(&cfg, true) != ESP_OK) {
            continue;
        }
        uint16_t n = 0;
        esp_wifi_scan_get_ap_num(&n);
        if (n == 0u) { continue; }
        if (n > 20u) { n = 20u; }

        wifi_ap_record_t *recs = calloc(n, sizeof(wifi_ap_record_t));
        if (recs == NULL) { esp_wifi_clear_ap_list(); continue; }
        esp_wifi_scan_get_ap_records(&n, recs);

        for (uint16_t i = 0; i < n; i++) {
            bas_ap_t ap;
            memset(&ap, 0, sizeof(ap));
            memcpy(ap.bssid, recs[i].bssid, 6);
            bas_strlcpy(ap.ssid, (const char *)recs[i].ssid, sizeof(ap.ssid));
            ap.hidden        = (ap.ssid[0] == '\0');
            ap.channel       = recs[i].primary;
            ap.rssi          = recs[i].rssi;
            ap.sec           = sec_of(recs[i].authmode);
            ap.last_seen_ms  = now_ms();
            ap.first_seen_ms = ap.last_seen_ms;
            if (bas_ap_check(&ap) != BAS_OK) { continue; }
            bas_scan_observe(&s_scan, &ap);
        }
        free(recs);
    }

    bas_scan_sort_rssi(&s_scan);
    ESP_LOGI(TAG, "survey: %u networks, %u dropped",
             (unsigned)s_scan.count, (unsigned)s_scan.dropped);
    for (uint8_t i = 0; i < s_scan.count; i++) {
        const bas_ap_t *ap = &s_scan.ap[i];
        char mac[18];
        bas_mac_fmt(ap->bssid, mac, sizeof(mac));
        ESP_LOGI(TAG, "  %2u  %-20s %s ch%-3u %4ddBm %-9s%s",
                 (unsigned)i, ap->hidden ? "(hidden)" : ap->ssid, mac,
                 (unsigned)ap->channel, (int)ap->rssi, bas_sec_name(ap->sec),
                 bas_sec_likely_mfp(ap->sec) ? "  MFP" : "");
    }
}

/* --- the run ------------------------------------------------------------- */

static volatile bool s_abort;

typedef struct {
    bas_family_t f;
    uint32_t     budget;
} tx_ctx_t;

static bool tx_tick(const bas_tx_result_t *p, void *ctx)
{
    const tx_ctx_t *c = (const tx_ctx_t *)ctx;
    bas_ui_running(c->f, &s_engage, p, c->budget);

    /* A run is always interruptible, by the glass or by any button. */
    uint16_t tx, ty;
    if (bas_touch_present() && bas_touch_tapped(&tx, &ty)) {
        s_abort = true;
    }
    if (input_poll() != EV_NONE) {
        s_abort = true;
    }
    return !s_abort;
}

/* --- flow ---------------------------------------------------------------- */

typedef enum {
    ST_PICK, ST_TARGET, ST_LABEL, ST_FAMILIES,
    ST_DETAIL, ST_HOLD, ST_ARM, ST_ASK, ST_CARD
} state_t;

static bool ui_tap(uint16_t *x, uint16_t *y)
{
    if (!bas_touch_present()) {
        return false;
    }
    return bas_touch_tapped(x, y);
}

void app_main(void)
{
    /* FIRST. On battery the PWR button only supplies power while it is held;
     * this latch is what keeps the rail up after it is released. Everything
     * else — display, NVS, radio — can wait, and must, because any of it could
     * block or fail and the board would switch itself off mid-boot. USB hides
     * this completely, which is why it only shows up on battery. */
    bas_power_latch();

    ESP_LOGI(TAG, "Basanos v%d.%d.%d", BAS_VERSION_MAJOR, BAS_VERSION_MINOR,
             BAS_VERSION_PATCH);

    ESP_ERROR_CHECK(bas_display_init());
    bas_display_backlight(80);

    bas_ui_splash();
    vTaskDelay(pdMS_TO_TICKS(1400));

    bas_selftest_t st;
    bas_selftest_run(&st);
    bas_ui_selftest(&st);
    vTaskDelay(pdMS_TO_TICKS(2000));
    if (!bas_selftest_ok(&st)) {
        ESP_LOGE(TAG, "self-test failed — halting");
        while (true) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    buttons_init();
    bas_power_init();
    (void)bas_touch_init();
    ESP_LOGI(TAG, "touch: %s (chip 0x%02X)",
             bas_touch_present() ? "present" : "absent",
             (unsigned)bas_touch_chip_id());

    wifi_init();
    survey();
    bas_card_reset(&s_card);
    bas_engage_clear(&s_engage);

    ESP_LOGI(TAG, "heap: %u internal, %u psram",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    state_t st_cur = ST_PICK;
    int  net_sel = 0, fam_sel = 0;
    char label[BAS_LABEL_MAX] = {0};
    uint32_t hold_start = 0;
    bas_plan_t plan;
    uint8_t role = BAS_ROLE_OPERATOR;
    int  run_idx = -1;
    uint32_t run_frames = 0, ask_until = 0;
    bool redraw = true;

    while (true) {
        uint16_t tx = 0, ty = 0;
        bool tap = ui_tap(&tx, &ty);
        input_ev_t ev = input_poll();

        if (ev == EV_POWEROFF) {
            bas_ui_message("POWERING OFF", NULL, NULL, BAS_C_DIM);
            vTaskDelay(pdMS_TO_TICKS(600));
            bas_display_backlight(0);
            bas_power_off();
            /* On USB the rail is held up by the cable, so dropping the latch
             * does nothing visible. Say so rather than appearing to hang. */
            vTaskDelay(pdMS_TO_TICKS(400));
            bas_display_backlight(80);
            bas_ui_message("STILL ON USB", "Unplug to switch off.", NULL,
                           BAS_C_WARN);
            vTaskDelay(pdMS_TO_TICKS(2000));
            bas_power_latch();
            redraw = true;
            continue;
        }

        bool accept = (ev == EV_ACCEPT);
        bool back   = (ev == EV_BACK);
        bool next   = (ev == EV_NEXT);

        switch (st_cur) {

        case ST_PICK:
            if (redraw) { bas_ui_picker(&s_scan, net_sel); redraw = false; }
            if (next && s_scan.count) {
                net_sel = (net_sel + 1) % (int)s_scan.count;
                redraw = true;
            }
            if (accept && s_scan.count) { st_cur = ST_TARGET; redraw = true; }
            if (tap && s_scan.count) {
                const int top = 28, rh = 34, rows = 6;
                int first = (net_sel >= rows) ? net_sel - rows + 1 : 0;
                if (ty >= top && ty < top + rows * rh) {
                    int hit = first + ((int)ty - top) / rh;
                    if (hit >= 0 && hit < (int)s_scan.count) {
                        if (hit == net_sel) { st_cur = ST_TARGET; }
                        else { net_sel = hit; }
                        redraw = true;
                    }
                }
            }
            break;

        case ST_TARGET:
            if (redraw) { bas_ui_target(&s_scan.ap[net_sel], -1); redraw = false; }
            if (back) { st_cur = ST_PICK; redraw = true; }
            if (tap || accept) { label[0] = '\0'; st_cur = ST_LABEL; redraw = true; }
            break;

        case ST_LABEL: {
            if (redraw) { bas_ui_keyboard("Authorisation reference", label);
                          redraw = false; }
            if (back) { st_cur = ST_TARGET; redraw = true; break; }
            if (!tap) { break; }

            int k = bas_ui_keyboard_hit(tx, ty);
            size_t n = strlen(label);
            if (k >= 0) {
                if (n + 1u < sizeof(label)) {
                    label[n] = bas_ui_keyboard_char(k);
                    label[n + 1] = '\0';
                }
                redraw = true;
            } else if (k == -3) {
                if (n > 0u) { label[n - 1] = '\0'; }
                redraw = true;
            } else if (k == -2) {
                bas_err_t rc = bas_engage_lock(&s_engage, &s_scan.ap[net_sel],
                                               label, "operator", now_ms(),
                                               BAS_TTL_DEFAULT_MS);
                if (rc == BAS_OK) {
                    ESP_LOGI(TAG, "engagement locked: '%s' on %s", label,
                             s_engage.target.ssid);
                    st_cur = ST_FAMILIES;
                } else {
                    bas_ui_message("REFUSED", bas_err_str(rc), NULL, BAS_C_STOP);
                    vTaskDelay(pdMS_TO_TICKS(1800));
                }
                redraw = true;
            }
            break;
        }

        case ST_FAMILIES:
            if (redraw) { bas_ui_families(fam_sel, role, &s_engage);
                          redraw = false; }
            if (back) { bas_engage_clear(&s_engage); st_cur = ST_PICK;
                        redraw = true; }
            if (next) { fam_sel = (fam_sel + 1) % BAS_FAM__COUNT; redraw = true; }
            if (accept) {
                bas_plan_default(&plan, (bas_family_t)fam_sel);
                st_cur = ST_DETAIL;
                redraw = true;
            }
            if (tap) {
                int hit = bas_ui_families_hit(tx, ty, fam_sel);
                if (hit >= 0) {
                    if (hit == fam_sel) {
                        bas_plan_default(&plan, (bas_family_t)fam_sel);
                        st_cur = ST_DETAIL;
                    } else {
                        fam_sel = hit;
                    }
                    redraw = true;
                }
            }
            break;

        case ST_DETAIL: {
            const bas_family_spec_t *fs = bas_family((bas_family_t)fam_sel);
            /* Validate at operator level so the screen shows honestly whether
             * this family is reachable without elevation. */
            bas_plan_t probe = plan;
            bas_err_t gate = bas_plan_validate(&probe, BAS_ROLE_ADMIN,
                                               &s_engage, now_ms());
            if (redraw) {
                bas_ui_family_detail((bas_family_t)fam_sel, &probe, &s_engage,
                                     role, gate);
                redraw = false;
            }
            if (back) { st_cur = ST_FAMILIES; redraw = true; break; }
            if ((tap || accept) && gate == BAS_OK &&
                bas_tx_supported((bas_family_t)fam_sel)) {
                plan = probe;
                if (fs->klass == BAS_CLASS_DISRUPTIVE) {
                    hold_start = 0;
                    st_cur = ST_HOLD;
                } else {
                    role = BAS_ROLE_OPERATOR;
                    st_cur = ST_ARM;
                }
                redraw = true;
            }
            break;
        }

        case ST_HOLD: {
            /* Held for HOLD_MS without releasing, or it does not arm. The
             * progress bar is the whole affordance -- no digits to remember,
             * no keyboard on a 240px panel. */
            const uint32_t HOLD_MS = 1500u;
            uint32_t t = now_ms();

            if (input_held_down()) {
                if (hold_start == 0u) { hold_start = t; }
                uint32_t held = t - hold_start;
                bas_ui_hold_arm((bas_family_t)fam_sel, &s_engage,
                                (int)(held * 100u / HOLD_MS));
                if (held >= HOLD_MS) {
                    role = BAS_ROLE_ADMIN;   /* lasts exactly one run */
                    st_cur = ST_ARM;
                    redraw = true;
                }
            } else {
                if (hold_start != 0u) {
                    /* Released early. Back to the detail screen rather than
                     * silently sitting at zero. */
                    hold_start = 0;
                    st_cur = ST_DETAIL;
                    redraw = true;
                } else {
                    bas_ui_hold_arm((bas_family_t)fam_sel, &s_engage, 0);
                }
            }
            if (back) { st_cur = ST_DETAIL; redraw = true; }
            break;
        }

        case ST_ARM: {
            bool aborted = false;
            for (int left = 3; left > 0; left--) {
                bas_ui_arm((bas_family_t)fam_sel, &s_engage, left);
                for (int i = 0; i < 10; i++) {
                    uint16_t ax, ay;
                    if (ui_tap(&ax, &ay) || input_poll() != EV_NONE) { aborted = true; break; }
                    vTaskDelay(pdMS_TO_TICKS(100));
                }
                if (aborted) { break; }
            }
            if (aborted) {
                bas_ui_message("ABORTED", "Nothing was sent.", NULL, BAS_C_DIM);
                vTaskDelay(pdMS_TO_TICKS(1500));
                role = BAS_ROLE_OPERATOR;
                st_cur = ST_FAMILIES;
                redraw = true;
                break;
            }

            tx_ctx_t cbctx = {
                .f = (bas_family_t)fam_sel,
                .budget = bas_plan_frame_budget(&plan),
            };
            s_abort = false;
            run_idx = bas_card_begin(&s_card, (bas_family_t)fam_sel,
                                     now_ms(), BAS_GRACE_DEFAULT_MS);

            bas_tx_result_t res;
            esp_err_t rc = bas_tx_run(&plan, &s_engage, role,
                                      tx_tick, &cbctx, &res);
            run_frames = res.frames_sent;

            if (run_idx >= 0) {
                bas_card_end(&s_card, run_idx, now_ms(), res.frames_sent);
            }
            bas_engage_note_run(&s_engage);
            role = BAS_ROLE_OPERATOR;   /* elevation lasts one run          */

            if (rc != ESP_OK) {
                bas_ui_message("REFUSED", esp_err_to_name(rc),
                               bas_err_str(res.stopped_by), BAS_C_STOP);
                vTaskDelay(pdMS_TO_TICKS(2500));
                st_cur = ST_FAMILIES;
            } else if (res.frames_sent == 0u) {
                /* Nothing reached the air. Discard the run rather than let it
                 * age into a MISSED — that would blame the detector for the
                 * transmitter's failure, which is the one result this
                 * instrument must never produce. */
                ESP_LOGW(TAG, "run discarded: 0 frames sent, %u rejected",
                         (unsigned)res.tx_errors);
                if (run_idx >= 0 && run_idx == (int)s_card.count - 1) {
                    s_card.count--;
                    memset(&s_card.r[run_idx], 0, sizeof(s_card.r[run_idx]));
                    run_idx = -1;
                }
                bas_ui_tx_failed((bas_family_t)fam_sel, &res);
                while (input_poll() == EV_NONE) {
                    uint16_t ax, ay;
                    if (ui_tap(&ax, &ay)) { break; }
                    vTaskDelay(pdMS_TO_TICKS(40));
                }
                st_cur = ST_FAMILIES;
            } else {
                ask_until = now_ms() + BAS_GRACE_DEFAULT_MS;
                st_cur = ST_ASK;
            }
            redraw = true;
            break;
        }

        case ST_ASK: {
            uint32_t t = now_ms();
            uint32_t left = (t < ask_until) ? ask_until - t : 0u;
            bas_ui_ask_alarm((bas_family_t)fam_sel, run_frames, left);

            if ((tap || accept) && run_idx >= 0) {
                bas_card_alarm(&s_card, run_idx, "operator", 0, 0,
                               BAS_SRC_OPERATOR, now_ms());
                st_cur = ST_CARD;
            } else if (back || left == 0u) {
                /* No alarm inside the grace window. The scorecard will read
                 * MISSED, and only now — never the instant the burst ended. */
                st_cur = ST_CARD;
            }
            redraw = true;
            break;
        }

        case ST_CARD:
            if (redraw) { bas_ui_scorecard(&s_card, now_ms()); redraw = false; }
            if (tap || accept || back) { st_cur = ST_FAMILIES; redraw = true; }
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(40));
    }
}
