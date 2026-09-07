/* Basanos — the screens that lead to a transmission.
 *
 * Same house style as ui.c. One extra rule applies here: any screen that can
 * result in a frame going out says what will be emitted, at whom, and for how
 * long, in words, before the operator can commit.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ui_attack.h"
#include "display.h"

#include <stdio.h>
#include <string.h>

#define W 240
#define H 240

static void head(bas_canvas_t *c, const char *label, uint16_t tint)
{
    bas_fill(c, 0, 0, W, 22, BAS_C_SURFACE);
    bas_text(c, 8, 8, "BASANOS", BAS_C_BRASS, 1);
    if (label != NULL) {
        bas_text(c, W - 8 - bas_text_width(label, 1), 8, label, tint, 1);
    }
    bas_hline(c, 0, 22, W, BAS_C_FAINT);
}

static void footer(bas_canvas_t *c, const char *s, uint16_t colour)
{
    bas_hline(c, 0, H - 16, W, BAS_C_FAINT);
    bas_text(c, 8, H - 12, s, colour, 1);
}

/* --- target confirmation -------------------------------------------------- */

void bas_ui_target(const bas_ap_t *ap, int station_count)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    head(c, "target", BAS_C_DIM);

    char buf[64];
    bas_text_clip(c, 10, 30, ap->hidden ? "(hidden)" : ap->ssid,
                  BAS_C_PAPER, 2, W - 20);

    char mac[18];
    bas_mac_fmt(ap->bssid, mac, sizeof(mac));
    bas_text(c, 10, 54, mac, BAS_C_DIM, 1);

    snprintf(buf, sizeof(buf), "ch %u   %d dBm   %s",
             (unsigned)ap->channel, (int)ap->rssi, bas_sec_name(ap->sec));
    bas_text(c, 10, 72, buf, BAS_C_PAPER, 1);

    if (station_count >= 0) {
        snprintf(buf, sizeof(buf), "%d client%s seen",
                 station_count, station_count == 1 ? "" : "s");
        bas_text(c, 10, 88, buf, BAS_C_DIM, 1);
    }

    bas_hline(c, 10, 104, W - 20, BAS_C_FAINT);

    /* The finding that saves a wasted run. */
    if (bas_sec_likely_mfp(ap->sec)) {
        bas_text(c, 10, 116, "PROTECTED", BAS_C_BRASS, 2);
        bas_text(c, 10, 140, "Management frames are", BAS_C_DIM, 1);
        bas_text(c, 10, 154, "protected here, so a", BAS_C_DIM, 1);
        bas_text(c, 10, 168, "deauth run is expected", BAS_C_DIM, 1);
        bas_text(c, 10, 182, "to bounce. That is a", BAS_C_DIM, 1);
        bas_text(c, 10, 196, "result, not a failure.", BAS_C_DIM, 1);
    } else if (ap->sec == BAS_SEC_WPA2_WPA3) {
        bas_text(c, 10, 116, "TRANSITION", BAS_C_WARN, 2);
        bas_text(c, 10, 140, "WPA2/WPA3 mixed mode.", BAS_C_DIM, 1);
        bas_text(c, 10, 154, "The WPA2 half is not", BAS_C_DIM, 1);
        bas_text(c, 10, 168, "protected.", BAS_C_DIM, 1);
    } else {
        bas_text(c, 10, 116, "UNPROTECTED", BAS_C_PAPER, 2);
        bas_text(c, 10, 140, "No management frame", BAS_C_DIM, 1);
        bas_text(c, 10, 154, "protection advertised.", BAS_C_DIM, 1);
    }

    footer(c, "TAP lock target   MINUS back", BAS_C_BRASS);
    bas_display_flush();
}

/* --- keyboard ------------------------------------------------------------- */

static const char *KB_ROWS[4] = {
    "ABCDEFGHIJ",
    "KLMNOPQRST",
    "UVWXYZ0123",
    "456789-_ .",
};

#define KB_X0 2
#define KB_Y0 108
#define KB_KW 23
#define KB_KH 27

void bas_ui_keyboard(const char *title, const char *buf)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    head(c, "authorisation", BAS_C_DIM);

    bas_text(c, 10, 30, title, BAS_C_DIM, 1);

    /* The field. Shown in brass because it is the thing that will end up in
     * the audit log. */
    bas_rect(c, 8, 48, W - 16, 26, BAS_C_FAINT);
    bas_text_clip(c, 14, 55, (buf != NULL && buf[0]) ? buf : "_",
                  BAS_C_SHINE, 2, W - 28);

    bas_text(c, 10, 84, "Name the authorisation.", BAS_C_DIM, 1);
    bas_text(c, 10, 96, "It goes in the log.", BAS_C_DIM, 1);

    for (int r = 0; r < 4; r++) {
        for (int k = 0; k < 10; k++) {
            int x = KB_X0 + k * KB_KW;
            int y = KB_Y0 + r * KB_KH;
            bas_rect(c, x, y, KB_KW - 1, KB_KH - 1, BAS_C_SURFACE);
            char s[2] = { KB_ROWS[r][k], '\0' };
            bas_text(c, x + (KB_KW - 6) / 2, y + (KB_KH - 8) / 2, s,
                     BAS_C_PAPER, 1);
        }
    }

    /* Backspace and done share the bottom strip. */
    bas_fill(c, 8, 218, 100, 18, BAS_C_SURFACE);
    bas_text(c, 32, 223, "BACK", BAS_C_PAPER, 1);
    bas_fill(c, W - 108, 218, 100, 18, BAS_C_BRASS);
    bas_text(c, W - 78, 223, "DONE", BAS_C_BLACK, 1);

    bas_display_flush();
}

int bas_ui_keyboard_hit(uint16_t x, uint16_t y)
{
    if (y >= 218) {
        if (x < 108) { return -3; }
        if (x >= (uint16_t)(W - 108)) { return -2; }
        return -1;
    }
    if (y < KB_Y0) {
        return -1;
    }
    int r = ((int)y - KB_Y0) / KB_KH;
    int k = ((int)x - KB_X0) / KB_KW;
    if (r < 0 || r > 3 || k < 0 || k > 9) {
        return -1;
    }
    return r * 10 + k;
}

char bas_ui_keyboard_char(int key)
{
    if (key < 0 || key > 39) {
        return '\0';
    }
    return KB_ROWS[key / 10][key % 10];
}

/* --- PIN pad -------------------------------------------------------------- */

void bas_ui_pinpad(const char *title, int entered, const char *note)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    head(c, "admin", BAS_C_STOP);

    bas_text(c, 10, 30, title, BAS_C_PAPER, 1);
    if (note != NULL) {
        bas_text_clip(c, 10, 44, note, BAS_C_DIM, 1, W - 20);
    }

    /* Dots, not digits. */
    for (int i = 0; i < 4; i++) {
        int x = 70 + i * 26;
        if (i < entered) {
            bas_fill(c, x, 62, 14, 14, BAS_C_SHINE);
        } else {
            bas_rect(c, x, 62, 14, 14, BAS_C_FAINT);
        }
    }

    static const char *keys = "123456789 0<";
    for (int i = 0; i < 12; i++) {
        int col = i % 3, row = i / 3;
        int x = 24 + col * 66, y = 92 + row * 32;
        if (keys[i] == ' ') {
            continue;
        }
        bas_rect(c, x, y, 60, 28, BAS_C_SURFACE);
        char s[2] = { keys[i], '\0' };
        bas_text(c, x + 27, y + 10, s, BAS_C_PAPER, 1);
    }

    footer(c, "MINUS cancel", BAS_C_DIM);
    bas_display_flush();
}

int bas_ui_pinpad_hit(uint16_t x, uint16_t y)
{
    if (y < 92 || y >= 92 + 4 * 32) {
        return -1;
    }
    int col = ((int)x - 24) / 66;
    int row = ((int)y - 92) / 32;
    if (col < 0 || col > 2 || row < 0 || row > 3) {
        return -1;
    }
    int i = row * 3 + col;
    static const char *keys = "123456789 0<";
    char k = keys[i];
    if (k == ' ') { return -1; }
    if (k == '<') { return -3; }
    if (k == '0') { return 0; }
    return k - '0';
}

/* --- family menu ---------------------------------------------------------- */

#define FAM_TOP  26
#define FAM_ROW  34
#define FAM_ROWS 6

void bas_ui_families(int sel, uint8_t role, const bas_engagement_t *e)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);

    char buf[56];
    uint32_t left = bas_engage_remaining_ms(e, 0);
    (void)left;
    snprintf(buf, sizeof(buf), "%s", bas_role_name((bas_role_t)role));
    head(c, buf, BAS_C_BRASS);

    int first = (sel >= FAM_ROWS) ? sel - FAM_ROWS + 1 : 0;

    for (int i = 0; i < FAM_ROWS; i++) {
        int idx = first + i;
        if (idx >= BAS_FAM__COUNT) {
            break;
        }
        const bas_family_spec_t *s = bas_family((bas_family_t)idx);
        int y = FAM_TOP + i * FAM_ROW;
        bool on = (idx == sel);
        bool ok = bas_tx_supported((bas_family_t)idx);
        bool allowed = role >= s->min_role;

        if (on) {
            bas_fill(c, 0, y, W, FAM_ROW - 2, BAS_C_SURFACE);
        }

        /* A severity stripe rather than a label: the class is the first thing
         * an operator needs and it should read without being parsed. */
        uint16_t stripe = (s->klass == BAS_CLASS_DISRUPTIVE) ? BAS_C_STOP
                        : (s->klass == BAS_CLASS_ACTIVE)     ? BAS_C_WARN
                                                             : BAS_C_OK;
        bas_fill(c, 0, y, 3, FAM_ROW - 2, stripe);

        uint16_t name_col = (!ok || !allowed) ? BAS_C_FAINT
                          : on ? BAS_C_PAPER : BAS_C_DIM;
        bas_text_clip(c, 10, y + 4, s->name, name_col, 1, W - 20);

        if (!ok) {
            bas_text_clip(c, 10, y + 16, bas_tx_pending_reason((bas_family_t)idx),
                          BAS_C_FAINT, 1, W - 20);
        } else if (!allowed) {
            bas_text(c, 10, y + 16, "admin only", BAS_C_STOP, 1);
        } else {
            bas_text_clip(c, 10, y + 16, s->detector, BAS_C_FAINT, 1, W - 20);
        }
    }

    footer(c, "TAP open   MINUS back", BAS_C_BRASS);
    bas_display_flush();
}

int bas_ui_families_hit(uint16_t x, uint16_t y, int sel)
{
    if (y < FAM_TOP || y >= FAM_TOP + FAM_ROWS * FAM_ROW) {
        return -1;
    }
    int first = (sel >= FAM_ROWS) ? sel - FAM_ROWS + 1 : 0;
    int hit = first + ((int)y - FAM_TOP) / FAM_ROW;
    return (hit >= 0 && hit < BAS_FAM__COUNT) ? hit : -1;
}

void bas_ui_family_detail(bas_family_t f, const bas_plan_t *p,
                          const bas_engagement_t *e, uint8_t role,
                          bas_err_t gate)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);

    const bas_family_spec_t *s = bas_family(f);
    head(c, bas_class_name(s->klass),
         s->klass == BAS_CLASS_DISRUPTIVE ? BAS_C_STOP : BAS_C_DIM);

    char buf[64];
    bas_text_clip(c, 10, 30, s->name, BAS_C_PAPER, 2, W - 20);
    bas_text_clip(c, 10, 54, s->proves, BAS_C_DIM, 1, W - 20);
    bas_text_clip(c, 10, 68, s->detector, BAS_C_BRASS, 1, W - 20);

    bas_hline(c, 10, 84, W - 20, BAS_C_FAINT);

    /* What will actually go out, in words, before anything can be committed. */
    snprintf(buf, sizeof(buf), "%u frames over %u s",
             (unsigned)bas_plan_frame_budget(p), (unsigned)p->seconds);
    bas_text(c, 10, 94, buf, BAS_C_PAPER, 1);
    snprintf(buf, sizeof(buf), "%u per second on ch %u",
             (unsigned)p->pps, (unsigned)(p->channel ? p->channel
                                                     : e->target.channel));
    bas_text(c, 10, 108, buf, BAS_C_DIM, 1);

    if (s->needs_target) {
        char mac[18];
        bas_mac_fmt(e->has_client ? e->client : e->target.bssid, mac, sizeof(mac));
        snprintf(buf, sizeof(buf), "at %s", mac);
        bas_text(c, 10, 122, buf, BAS_C_PAPER, 1);
        bas_text_clip(c, 10, 136, e->has_client ? "one client" : "the access point",
                      BAS_C_DIM, 1, W - 20);
    } else {
        bas_text(c, 10, 122, "broadcast advertisement", BAS_C_DIM, 1);
        bas_text(c, 10, 136, "named " BAS_TEST_PREFIX "nn", BAS_C_DIM, 1);
    }

    bas_hline(c, 10, 152, W - 20, BAS_C_FAINT);

    if (gate != BAS_OK) {
        bas_text(c, 10, 162, "BLOCKED", BAS_C_STOP, 2);
        bas_text_clip(c, 10, 186, bas_err_str(gate), BAS_C_PAPER, 1, W - 20);
        footer(c, "MINUS back", BAS_C_DIM);
    } else if (!bas_tx_supported(f)) {
        bas_text(c, 10, 162, "UNAVAILABLE", BAS_C_WARN, 2);
        bas_text_clip(c, 10, 186, bas_tx_pending_reason(f), BAS_C_DIM, 1, W - 20);
        footer(c, "MINUS back", BAS_C_DIM);
    } else {
        if (p->clamped_pps || p->clamped_secs) {
            bas_text(c, 10, 162, "clamped to the ceiling", BAS_C_WARN, 1);
        }
        bas_text_clip(c, 10, 178, e->label, BAS_C_BRASS, 1, W - 20);
        footer(c, s->klass == BAS_CLASS_DISRUPTIVE
                    ? "TAP arm (PIN)   MINUS back"
                    : "TAP arm   MINUS back",
               s->klass == BAS_CLASS_DISRUPTIVE ? BAS_C_STOP : BAS_C_BRASS);
    }

    bas_display_flush();
}

/* --- arming and running ---------------------------------------------------- */

void bas_ui_arm(bas_family_t f, const bas_engagement_t *e, int left)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    head(c, "armed", BAS_C_STOP);

    bas_text(c, 10, 34, "ARMED", BAS_C_STOP, 3);
    bas_text_clip(c, 10, 70, bas_family(f)->name, BAS_C_PAPER, 1, W - 20);
    bas_text_clip(c, 10, 84, e->target.hidden ? "(hidden)" : e->target.ssid,
                  BAS_C_DIM, 1, W - 20);

    char buf[16];
    snprintf(buf, sizeof(buf), "%d", left);
    bas_text(c, (W - bas_text_width(buf, 8)) / 2, 116, buf, BAS_C_SHINE, 8);

    footer(c, "TAP anywhere to abort", BAS_C_PAPER);
    bas_display_flush();
}

void bas_ui_running(bas_family_t f, const bas_engagement_t *e,
                    const bas_tx_result_t *p, uint32_t budget)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);

    /* The banner is a safety mechanism, not decoration: while this device is
     * emitting, the screen says so and cannot be turned off. */
    bas_fill(c, 0, 0, W, 22, BAS_C_STOP);
    bas_text(c, 8, 8, "TRANSMITTING", BAS_C_BLACK, 1);

    char buf[56];
    bas_text_clip(c, 10, 32, bas_family(f)->name, BAS_C_PAPER, 2, W - 20);
    bas_text_clip(c, 10, 56, e->target.hidden ? "(hidden)" : e->target.ssid,
                  BAS_C_DIM, 1, W - 20);

    snprintf(buf, sizeof(buf), "%u", (unsigned)p->frames_sent);
    bas_text(c, 10, 80, buf, BAS_C_SHINE, 5);
    bas_text(c, 10, 128, "frames sent", BAS_C_DIM, 1);

    /* Progress as a bar of the frame budget, which is the number the operator
     * was shown before arming. */
    int pw = W - 20;
    bas_rect(c, 10, 148, pw, 12, BAS_C_FAINT);
    if (budget > 0u) {
        uint32_t done = p->frames_sent > budget ? budget : p->frames_sent;
        bas_fill(c, 11, 149, (int)((uint32_t)(pw - 2) * done / budget), 10,
                 BAS_C_SHINE);
    }

    snprintf(buf, sizeof(buf), "of %u   %u.%us",
             (unsigned)budget, (unsigned)(p->elapsed_ms / 1000),
             (unsigned)((p->elapsed_ms % 1000) / 100));
    bas_text(c, 10, 166, buf, BAS_C_DIM, 1);

    if (p->tx_errors > 0u) {
        snprintf(buf, sizeof(buf), "%u radio errors", (unsigned)p->tx_errors);
        bas_text(c, 10, 182, buf, BAS_C_WARN, 1);
    }
    if (p->frames_refused > 0u) {
        snprintf(buf, sizeof(buf), "%u refused by the gate",
                 (unsigned)p->frames_refused);
        bas_text(c, 10, 196, buf, BAS_C_STOP, 1);
    }

    footer(c, "TAP to stop", BAS_C_PAPER);
    bas_display_flush();
}

void bas_ui_ask_alarm(bas_family_t f, uint32_t frames, uint32_t grace_left_ms)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    head(c, "scoring", BAS_C_BRASS);

    char buf[56];
    bas_text(c, 10, 32, "Did it alarm?", BAS_C_PAPER, 2);

    snprintf(buf, sizeof(buf), "%u frames of %s",
             (unsigned)frames, bas_family(f)->name);
    bas_text_clip(c, 10, 60, buf, BAS_C_DIM, 1, W - 20);

    bas_text(c, 10, 84, "Tap the moment your", BAS_C_DIM, 1);
    bas_text(c, 10, 98, "detector reacts.", BAS_C_DIM, 1);

    /* Honesty about what this measurement is. */
    bas_text(c, 10, 120, "Operator-timed, so the", BAS_C_FAINT, 1);
    bas_text(c, 10, 134, "latency includes you.", BAS_C_FAINT, 1);
    bas_text(c, 10, 148, "Never compared with a", BAS_C_FAINT, 1);
    bas_text(c, 10, 162, "serial-reported alarm.", BAS_C_FAINT, 1);

    int pw = W - 20;
    bas_rect(c, 10, 182, pw, 10, BAS_C_FAINT);
    uint32_t span = BAS_GRACE_DEFAULT_MS;
    uint32_t left = grace_left_ms > span ? span : grace_left_ms;
    bas_fill(c, 11, 183, (int)((uint32_t)(pw - 2) * left / span), 8, BAS_C_BRASS);

    footer(c, "TAP alarmed   MINUS missed", BAS_C_PAPER);
    bas_display_flush();
}

void bas_ui_scorecard(const bas_card_t *card, uint32_t now_ms)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);

    bas_tally_t t;
    bas_card_tally(card, now_ms, &t);

    char buf[56];
    snprintf(buf, sizeof(buf), "%u runs", (unsigned)card->count);
    head(c, buf, BAS_C_DIM);

    /* Three figures, the point of the whole device. */
    struct { const char *l; int v; uint16_t col; } cols[3] = {
        { "CAUGHT", t.caught, BAS_C_OK },
        { "LATE",   t.late,   BAS_C_WARN },
        { "MISSED", t.missed, BAS_C_STOP },
    };
    for (int i = 0; i < 3; i++) {
        int x = 12 + i * 76;
        snprintf(buf, sizeof(buf), "%d", cols[i].v);
        bas_text(c, x, 34, buf, cols[i].col, 4);
        bas_text(c, x, 72, cols[i].l, BAS_C_DIM, 1);
    }

    bas_hline(c, 10, 90, W - 20, BAS_C_FAINT);

    if (t.best_latency_ms >= 0) {
        snprintf(buf, sizeof(buf), "fastest %d.%01ds   slowest %d.%01ds",
                 (int)(t.best_latency_ms / 1000),
                 (int)((t.best_latency_ms % 1000) / 100),
                 (int)(t.worst_latency_ms / 1000),
                 (int)((t.worst_latency_ms % 1000) / 100));
        bas_text(c, 10, 98, buf, BAS_C_PAPER, 1);
    } else {
        bas_text(c, 10, 98, "nothing caught yet", BAS_C_DIM, 1);
    }

    /* The last few runs, newest first. */
    int y = 116;
    int shown = 0;
    for (int i = (int)card->count - 1; i >= 0 && shown < 6; i--, shown++) {
        char line[80];
        bas_run_line(&card->r[i], now_ms, line, sizeof(line));
        bas_verdict_t v = bas_run_verdict(&card->r[i], now_ms);
        uint16_t col = v == BAS_VERDICT_CAUGHT ? BAS_C_OK
                     : v == BAS_VERDICT_LATE   ? BAS_C_WARN
                     : v == BAS_VERDICT_MISSED ? BAS_C_STOP
                                               : BAS_C_DIM;
        bas_text_clip(c, 10, y, line, col, 1, W - 20);
        y += 14;
    }

    footer(c, "TAP continue", BAS_C_BRASS);
    bas_display_flush();
}
