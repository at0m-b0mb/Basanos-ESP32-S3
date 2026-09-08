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
#include "board.h"
#include "console.h"
#include "display.h"
#include "frames.h"
#include "power.h"
#include "selftest.h"
#include "theme.h"
#include "touch.h"
#include "transmit.h"
#include "ui.h"

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
    uint32_t t = now_ms();

    bool pwr = held(BOARD_BTN_PWR);
    if (pwr && !pwr_was) { pwr_since = t; }
    pwr_was = pwr;
    if (pwr && (t - pwr_since) >= HOLD_OFF_MS) { return EV_POWEROFF; }

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

/* --- runs ------------------------------------------------------------------ */

static volatile bool s_abort;

typedef struct { bas_family_t f; uint32_t budget; } tx_ctx_t;

static bool tx_tick(const bas_tx_result_t *p, void *ctx)
{
    const tx_ctx_t *c = (const tx_ctx_t *)ctx;
    bas_ui_running(c->f, &s_engage, p, c->budget);

    uint16_t tx, ty;
    if (ui_tap(&tx, &ty))        { s_abort = true; }
    if (input_poll() != EV_NONE) { s_abort = true; }
    return !s_abort;
}

/* Families reachable from the Wi-Fi section, in menu order. Grouping by radio
 * is the whole point of the restructure: an operator looking for a deauth
 * should never scroll past a BLE family to find it. */
static const bas_family_t WIFI_FAMS[] = {
    BAS_FAM_DEAUTH, BAS_FAM_DISASSOC, BAS_FAM_AUTH_FLOOD,
    BAS_FAM_EVIL_TWIN, BAS_FAM_BEACON, BAS_FAM_KARMA_RESP,
    BAS_FAM_PROBE_REQ,
};
#define WIFI_FAM_N ((int)(sizeof(WIFI_FAMS) / sizeof(WIFI_FAMS[0])))

static const bas_family_t BLE_FAMS[] = {
    BAS_FAM_BLE_ADV, BAS_FAM_BLE_TRACKER,
};
#define BLE_FAM_N ((int)(sizeof(BLE_FAMS) / sizeof(BLE_FAMS[0])))

/* --- console --------------------------------------------------------------- */

static int          s_last_run = -1;

static void console_help(void)
{
    bas_console_reply("scan                     re-survey the band");
    bas_console_reply("list                     networks, with index");
    bas_console_reply("lock <idx> <label>       lock an engagement");
    bas_console_reply("unlock                   drop it");
    bas_console_reply("fams                     families, with index");
    bas_console_reply("run <fam> [pps] [secs]   emit; disruptive needs CONFIRM");
    bas_console_reply("abort                    stop a run");
    bas_console_reply("alarm [name]             record an alarm on the last run");
    bas_console_reply("card                     the scorecard");
    bas_console_reply("status                   where things stand");
    bas_console_reply("selftest                 re-run the invariants");
}

static void console_status(void)
{
    bas_console_reply("networks=%u locked=%d", (unsigned)s_scan.count,
                      (int)s_engage.locked);
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
    if (c->secs > 0) { p.seconds = (uint16_t)c->secs; }

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
    bas_console_reply("running %s: %u frames, %u pps, ch%u", fs->name,
                      (unsigned)budget, (unsigned)p.pps, (unsigned)p.channel);

    tx_ctx_t ctx = { .f = f, .budget = budget };
    s_abort = false;
    int idx = bas_card_begin(&s_card, f, now_ms(), BAS_GRACE_DEFAULT_MS);

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
    bas_console_reply("scoring open for %ums — 'alarm <name>' if it fired",
                      (unsigned)BAS_GRACE_DEFAULT_MS);
}

static void console_exec(const bas_cmd_t *c)
{
    switch (c->kind) {
    case CMD_HELP:   console_help();   break;
    case CMD_STATUS: console_status(); break;
    case CMD_LIST:   console_list();   break;
    case CMD_FAMS:   console_fams();   break;
    case CMD_CARD:   console_card();   break;
    case CMD_ABORT:  s_abort = true; bas_console_reply("abort set"); break;
    case CMD_RUN:    console_run(c);   break;

    case CMD_SCAN:
        bas_console_reply("surveying...");
        survey();
        bas_console_reply("%u networks", (unsigned)s_scan.count);
        break;

    case CMD_LOCK: {
        if (c->index < 0 || c->index >= (int)s_scan.count) {
            bas_console_reply("no such network — 'list'");
            break;
        }
        bas_err_t rc = bas_engage_lock(&s_engage, &s_scan.ap[c->index], c->text,
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
    ST_BLE, ST_RECON, ST_CHANNELS, ST_FRAMES, ST_CLIENTS, ST_PROBES,
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
    bas_ui_selftest(&st);
    vTaskDelay(pdMS_TO_TICKS(2000));
    if (!bas_selftest_ok(&st)) {
        ESP_LOGE(TAG, "self-test failed — halting");
        while (true) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    buttons_init();
    bas_power_init();
    bas_console_start();
    (void)bas_touch_init();
    ESP_LOGI(TAG, "touch: %s (0x%02X)",
             bas_touch_present() ? "present" : "absent",
             (unsigned)bas_touch_chip_id());

    wifi_init();
    survey();
    bas_card_reset(&s_card);
    bas_engage_clear(&s_engage);

    ESP_LOGI(TAG, "heap: %u internal, %u psram",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    state_t  st_cur = ST_HOME;
    int  home_sel = 0, wifi_sel = 0, net_sel = 0, atk_sel = 0, ble_sel = 0;
    int  recon_sel = 0, cli_sel = 0, probe_sel = 0;
    bas_stalist_t clients;
    bas_sta_reset(&clients);
    char label[BAS_LABEL_MAX] = {0};
    uint32_t hold_start = 0, ask_until = 0, run_frames = 0;
    int  run_idx = -1;
    bas_plan_t plan;
    uint8_t role = BAS_ROLE_OPERATOR;
    bool redraw = true;

    static bas_row_t rows[16];
    static char subs[16][40];

    while (true) {
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
                case BAS_HOME_BLE:     st_cur = ST_BLE;     ble_sel  = 0; break;
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
            rows[3] = (bas_row_t){ "Release target", locked ? s_engage.label
                                                            : "nothing locked",
                                   0, locked };
            if (redraw) {
                bas_ui_list("Wi-Fi", NULL, rows, 4, wifi_sel,
                            "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (next) { wifi_sel = (wifi_sel + 1) % 4; redraw = true; }
            if (back) { st_cur = ST_HOME; redraw = true; break; }
            int hit = tap ? bas_ui_list_hit(tx, ty, wifi_sel, 4) : -1;
            if (hit >= 0) {
                if (hit == wifi_sel) { accept = true; }
                else { wifi_sel = hit; redraw = true; }
            }
            if (accept && rows[wifi_sel].enabled) {
                switch (wifi_sel) {
                case 0: survey(); break;
                case 1: st_cur = ST_NETWORKS; net_sel = 0; break;
                case 2: st_cur = ST_ATTACKS;  atk_sel = 0; break;
                case 3: bas_engage_clear(&s_engage); break;
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
            if (tap || accept) { label[0] = '\0'; st_cur = ST_LABEL; redraw = true; }
            break;

        case ST_LABEL: {
            if (redraw) {
                bas_ui_keyboard("Work order, client or ticket", label);
                redraw = false;
            }
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
                    ESP_LOGI(TAG, "locked '%s' on %s", label,
                             s_engage.target.ssid);
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
            int n = build_attacks(WIFI_FAMS, WIFI_FAM_N, rows, subs);
            if (redraw) {
                bas_ui_list("Wi-Fi attacks",
                            s_engage.target.hidden ? "(hidden)"
                                                   : s_engage.target.ssid,
                            rows, n, atk_sel, "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (back) { st_cur = ST_WIFI; redraw = true; break; }
            if (next) { atk_sel = (atk_sel + 1) % n; redraw = true; }
            int hit = tap ? bas_ui_list_hit(tx, ty, atk_sel, n) : -1;
            if (hit >= 0) {
                if (hit == atk_sel) { accept = true; }
                else { atk_sel = hit; redraw = true; }
            }
            if (accept) {
                bas_plan_default(&plan, WIFI_FAMS[atk_sel]);
                st_cur = ST_ATTACK;
                redraw = true;
            }
            break;
        }

        case ST_ATTACK: {
            bas_family_t f = WIFI_FAMS[atk_sel];
            const bas_family_spec_t *fs = bas_family(f);
            bas_plan_t probe = plan;
            bas_err_t gate = bas_plan_validate(&probe, BAS_ROLE_ADMIN,
                                               &s_engage, now_ms());
            if (redraw) {
                bas_ui_attack(f, &probe, &s_engage, gate);
                redraw = false;
            }
            if (back) { st_cur = ST_ATTACKS; redraw = true; break; }
            if ((tap || accept) && gate == BAS_OK && bas_tx_supported(f)) {
                plan = probe;
                if (fs->klass == BAS_CLASS_DISRUPTIVE) {
                    hold_start = 0;
                    st_cur = ST_HOLD;
                } else {
                    role = BAS_ROLE_OPERATOR;
                    goto do_run;
                }
                redraw = true;
            }
            break;
        }

        case ST_HOLD: {
            const uint32_t HOLD_MS = 1500u;
            uint32_t t = now_ms();
            if (input_held_down()) {
                if (hold_start == 0u) { hold_start = t; }
                uint32_t h = t - hold_start;
                bas_ui_hold(WIFI_FAMS[atk_sel], &s_engage,
                            (int)(h * 100u / HOLD_MS));
                if (h >= HOLD_MS) {
                    role = BAS_ROLE_ADMIN;   /* lasts exactly one run */
                    goto do_run;
                }
            } else if (hold_start != 0u) {
                hold_start = 0;
                st_cur = ST_ATTACK;
                redraw = true;
            } else {
                bas_ui_hold(WIFI_FAMS[atk_sel], &s_engage, 0);
            }
            if (back) { st_cur = ST_ATTACK; redraw = true; }
            break;

        do_run: {
                bas_family_t f = WIFI_FAMS[atk_sel];
                bool aborted = false;
                for (int left = 3; left > 0 && !aborted; left--) {
                    bas_ui_arm(f, &s_engage, left);
                    for (int i = 0; i < 10; i++) {
                        uint16_t ax, ay;
                        if (ui_tap(&ax, &ay) || input_poll() != EV_NONE) {
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

                bas_tx_result_t res;
                esp_err_t rc = bas_tx_run(&plan, &s_engage, role, tx_tick,
                                          &ctx, &res);
                run_frames = res.frames_sent;
                if (run_idx >= 0) {
                    bas_card_end(&s_card, run_idx, now_ms(), res.frames_sent);
                }
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
            uint32_t t = now_ms();
            uint32_t left = (t < ask_until) ? ask_until - t : 0u;
            bas_ui_ask(WIFI_FAMS[atk_sel], run_frames, left);
            if ((tap || accept) && run_idx >= 0) {
                bas_card_alarm(&s_card, run_idx, "operator", 0, 0,
                               BAS_SRC_OPERATOR, now_ms());
                st_cur = ST_RESULTS;
            } else if (back || left == 0u) {
                /* No alarm inside the grace window. The scorecard reads MISSED
                 * only now, never the instant the burst ended. */
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
            int n = build_attacks(BLE_FAMS, BLE_FAM_N, rows, subs);
            if (redraw) {
                bas_ui_list("Bluetooth", "no radio yet", rows, n, ble_sel,
                            "hold LEFT back");
                redraw = false;
            }
            if (next) { ble_sel = (ble_sel + 1) % n; redraw = true; }
            if (back || accept) { st_cur = ST_HOME; redraw = true; }
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
            rows[4] = (bas_row_t){ on ? "Stop listening" : "Start listening",
                                   on ? "release the radio"
                                      : "receive-only, hops the band",
                                   0, true };
            if (redraw) {
                bas_ui_list("Recon", on ? "live" : NULL, rows, 5, recon_sel,
                            "LEFT open   hold LEFT back");
                redraw = false;
            }
            if (next) { recon_sel = (recon_sel + 1) % 5; redraw = true; }
            if (back) { st_cur = ST_HOME; redraw = true; break; }
            int hit = tap ? bas_ui_list_hit(tx, ty, recon_sel, 5) : -1;
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
                case 4:
                    if (on) { bas_sniff_stop(); } else { bas_sniff_start(0); }
                    break;
                default: break;
                }
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
            if (redraw) { bas_ui_clients(&clients, cli_sel); redraw = false; }
            if (back) { st_cur = ST_RECON; redraw = true; break; }
            if (next && clients.count) {
                cli_sel = (cli_sel + 1) % (int)clients.count;
                redraw = true;
            }
            int hit = tap ? bas_ui_list_hit(tx, ty, cli_sel, clients.count) : -1;
            if (hit >= 0) { cli_sel = hit; redraw = true; }
            /* Narrowing to one client tightens the engagement, so it is only
             * offered when there is an engagement to tighten. */
            if (accept && clients.count && s_engage.locked) {
                bas_err_t rc = bas_engage_set_client(&s_engage,
                                                     clients.s[cli_sel].mac);
                char mac[18];
                bas_mac_fmt(clients.s[cli_sel].mac, mac, sizeof(mac));
                bas_ui_note(rc == BAS_OK ? "NARROWED" : "REFUSED",
                            rc == BAS_OK ? mac : bas_err_str(rc),
                            rc == BAS_OK ? "runs now target this client" : NULL,
                            rc == BAS_OK ? TH_BRASS : TH_STOP);
                vTaskDelay(pdMS_TO_TICKS(1800));
                st_cur = ST_RECON;
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
