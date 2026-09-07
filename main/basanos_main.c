/* Basanos — application entry.
 *
 * This build is RECEIVE ONLY. The transmit families exist in the engine and
 * are gated by the engagement lock, but no radio path is wired to them yet:
 * bring-up proves the display, the engines on real silicon, and the passive
 * survey first. Nothing here can put a frame on air.
 *
 * SPDX-License-Identifier: MIT
 */
#include "board.h"
#include "display.h"
#include "selftest.h"
#include "touch.h"
#include "ui.h"

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

#include <string.h>

static const char *TAG = "basanos";

static bas_scan_t s_scan;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* --- buttons ------------------------------------------------------------- */

static void buttons_init(void)
{
    gpio_config_t c = {
        .pin_bit_mask = (1ULL << BOARD_BTN_PLUS) | (1ULL << BOARD_BTN_MINUS),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&c));
}

static bool pressed(gpio_num_t pin)
{
    return gpio_get_level(pin) == 0;
}

/* Edge-triggered read with a short debounce. Polling is fine here: the UI is
 * a menu, not a game, and an ISR would buy nothing but a race with the SPI
 * transfer. */
static bool tapped(gpio_num_t pin, bool *was_down)
{
    bool down = pressed(pin);
    bool edge = down && !*was_down;
    *was_down = down;
    if (edge) {
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    return edge;
}

/* --- Wi-Fi, receive only ------------------------------------------------- */

static bas_sec_t sec_of(wifi_auth_mode_t m)
{
    switch (m) {
    case WIFI_AUTH_OPEN:            return BAS_SEC_OPEN;
    case WIFI_AUTH_WEP:             return BAS_SEC_WEP;
    case WIFI_AUTH_WPA_PSK:         return BAS_SEC_WPA;
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_WPA_WPA2_PSK:    return BAS_SEC_WPA2;
    case WIFI_AUTH_ENTERPRISE:      return BAS_SEC_WPA2_ENT;
    case WIFI_AUTH_WPA3_PSK:        return BAS_SEC_WPA3;
    case WIFI_AUTH_WPA2_WPA3_PSK:   return BAS_SEC_WPA2_WPA3;
    case WIFI_AUTH_OWE:             return BAS_SEC_WPA3;
    default:                        return BAS_SEC_UNKNOWN;
    }
}

static void wifi_init(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());

    /* Optional subsystems must fail gracefully. esp_event_loop_create_default
     * returns ESP_ERR_INVALID_STATE when one already exists, and wrapping that
     * in ESP_ERROR_CHECK turns a harmless double-init into a boot loop. */
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

    /* Passive scan: listen for beacons rather than soliciting probe responses.
     * An active scan would transmit, and this build does not transmit. */
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
        if (n == 0u) {
            continue;
        }
        if (n > 20u) {
            n = 20u;
        }

        /* One page at a time off the heap rather than a 20-record array on the
         * stack: wifi_ap_record_t is ~80 bytes and this task has 8 KB. */
        wifi_ap_record_t *recs = calloc(n, sizeof(wifi_ap_record_t));
        if (recs == NULL) {
            esp_wifi_clear_ap_list();
            continue;
        }
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

            if (bas_ap_check(&ap) != BAS_OK) {
                continue;   /* not a usable target, so not in the picker */
            }
            bas_scan_observe(&s_scan, &ap);
        }
        free(recs);
    }

    bas_scan_sort_rssi(&s_scan);
    ESP_LOGI(TAG, "survey: %u networks, %u dropped",
             (unsigned)s_scan.count, (unsigned)s_scan.dropped);

    /* The picker's own data, on the console, so the list on screen can be
     * checked against something. MFP is called out because it is the flag that
     * decides whether a deauth run against that network is worth spending. */
    for (uint8_t i = 0; i < s_scan.count; i++) {
        const bas_ap_t *ap = &s_scan.ap[i];
        char mac[18];
        bas_mac_fmt(ap->bssid, mac, sizeof(mac));
        ESP_LOGI(TAG, "  %2u  %-20s %s ch%-3u %4ddBm %-9s%s",
                 (unsigned)i,
                 ap->hidden ? "(hidden)" : ap->ssid,
                 mac, (unsigned)ap->channel, (int)ap->rssi,
                 bas_sec_name(ap->sec),
                 bas_sec_likely_mfp(ap->sec) ? "  MFP" : "");
    }
}

/* --- app ----------------------------------------------------------------- */

void app_main(void)
{
    ESP_LOGI(TAG, "Basanos v%d.%d.%d — receive-only bring-up",
             BAS_VERSION_MAJOR, BAS_VERSION_MINOR, BAS_VERSION_PATCH);

    ESP_ERROR_CHECK(bas_display_init());
    bas_display_backlight(80);

    bas_ui_splash();
    vTaskDelay(pdMS_TO_TICKS(1400));

    /* The safety invariants are re-checked on the silicon that would do the
     * transmitting, not just on a laptop. */
    bas_selftest_t st;
    bas_selftest_run(&st);
    bas_ui_selftest(&st);
    vTaskDelay(pdMS_TO_TICKS(2200));

    if (!bas_selftest_ok(&st)) {
        /* A device whose safety invariants do not hold has no business showing
         * a target picker. Stop here, on screen, permanently. */
        ESP_LOGE(TAG, "self-test failed — halting");
        while (true) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    buttons_init();

    /* Touch is optional: the non-touch variant of this board is otherwise
     * identical, so a missing controller falls back to the buttons instead of
     * failing. */
    esp_err_t trc = bas_touch_init();
    ESP_LOGI(TAG, "touch: %s (chip 0x%02X)",
             bas_touch_present() ? "present" : "absent",
             (unsigned)bas_touch_chip_id());

    /* A live touch check before anything else. A wrong axis mapping is
     * obvious in one press here, and would otherwise be inferred later from a
     * menu that selects the wrong row. */
    {
        bool plus_seen = false;
        int taps = 0;
        uint32_t until = now_ms() + 20000u;
        bas_touch_t t;
        memset(&t, 0, sizeof(t));

        while (now_ms() < until) {
            if (bas_touch_present()) {
                bas_touch_t cur;
                if (bas_touch_read(&cur)) {
                    if (cur.down && !t.down) {
                        taps++;
                        ESP_LOGI(TAG, "touch: x=%u y=%u gesture=%s",
                                 (unsigned)cur.x, (unsigned)cur.y,
                                 bas_gesture_name(cur.gesture));
                    }
                    t = cur;
                }
            }
            bas_ui_touchtest(bas_touch_present(), bas_touch_chip_id(),
                             t.down, t.x, t.y, taps);

            if (tapped(BOARD_BTN_PLUS, &plus_seen)) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(60));
        }
        ESP_LOGI(TAG, "touch check done: %d taps registered", taps);
    }
    (void)trc;

    wifi_init();
    survey();

    ESP_LOGI(TAG, "heap after survey: %u internal, %u psram",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    int sel = 0;
    bool plus_down = false, minus_down = false;
    bas_ui_picker(&s_scan, sel);

    while (true) {
        bool redraw = false;
        bool open   = false;

        if (tapped(BOARD_BTN_PLUS, &plus_down) && s_scan.count > 0u) {
            sel = (sel + 1) % (int)s_scan.count;
            redraw = true;
        }

        /* Touch: a tap on a row selects it, a tap on the row already selected
         * opens it. Two taps to act on a target rather than one is deliberate
         * — this list is the first half of choosing something to transmit at. */
        if (bas_touch_present() && s_scan.count > 0u) {
            uint16_t tx = 0, ty = 0;
            if (bas_touch_tapped(&tx, &ty)) {
                const int row_h = 34, top = 28;
                const int rows  = (240 - top - 18) / row_h;
                int first = (sel >= rows) ? sel - rows + 1 : 0;

                if ((int)ty >= top && (int)ty < top + rows * row_h) {
                    int hit = first + ((int)ty - top) / row_h;
                    if (hit >= 0 && hit < (int)s_scan.count) {
                        if (hit == sel) {
                            open = true;
                        } else {
                            sel = hit;
                            redraw = true;
                        }
                    }
                }
            }

            switch (bas_touch_swipe()) {
            case BAS_GESTURE_UP:
                sel = (sel + 1) % (int)s_scan.count;
                redraw = true;
                break;
            case BAS_GESTURE_DOWN:
                sel = (sel + (int)s_scan.count - 1) % (int)s_scan.count;
                redraw = true;
                break;
            default:
                break;
            }
        }

        if ((tapped(BOARD_BTN_MINUS, &minus_down) || open) && s_scan.count > 0u) {
            const bas_ap_t *ap = &s_scan.ap[sel];
            char l1[48], l2[48];
            char mac[18];
            bas_mac_fmt(ap->bssid, mac, sizeof(mac));
            snprintf(l1, sizeof(l1), "%s  ch%u  %ddBm",
                     bas_sec_name(ap->sec), (unsigned)ap->channel, (int)ap->rssi);
            snprintf(l2, sizeof(l2), "%s", mac);
            bas_ui_message(ap->hidden ? "(hidden)" : ap->ssid, l1, l2,
                           BAS_C_SHINE);
            vTaskDelay(pdMS_TO_TICKS(2500));
            redraw = true;
        }

        if (redraw) {
            bas_ui_picker(&s_scan, sel);
        }
        vTaskDelay(pdMS_TO_TICKS(40));
    }
}
