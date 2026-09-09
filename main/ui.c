/* Basanos — the screen set.
 *
 * White and gold, one severity colour set kept separate from the
 * accent. Restraint over decoration: a border, a fill or a stripe is spent
 * where it means something, not stamped on every block.
 *
 * One rule specific to this device: any screen that can result in a frame
 * going out states what will be emitted, at whom, and for how long, in words,
 * before anything can be committed.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ui.h"

#include "console.h"
#include "display.h"
#include "power.h"
#include "theme.h"

#include <stdio.h>
#include <string.h>

#define W 240
#define H 240

/* --- chrome --------------------------------------------------------------- */

void bas_ui_battery(void *canvas, int x, int y)
{
    bas_canvas_t *c = (bas_canvas_t *)canvas;
    uint8_t pct = bas_power_level();

    bas_rect(c, x, y, 18, 9, TH_INK3);
    bas_fill(c, x + 18, y + 3, 2, 3, TH_INK3);

    if (bas_power_charging()) {
        /* A bolt, not a level. A bar that climbs by itself reads as a
         * misreading rather than as a charger. */
        bas_fill(c, x + 8, y + 2, 2, 3, TH_BRASS);
        bas_fill(c, x + 6, y + 4, 6, 1, TH_BRASS);
        bas_fill(c, x + 8, y + 5, 2, 3, TH_BRASS);
        return;
    }
    if (pct == 0u) {
        return;
    }
    uint16_t col = pct <= 20u ? TH_STOP : (pct <= 40u ? TH_WARN : TH_INK2);
    bas_fill(c, x + 2, y + 2, (14 * pct) / 100, 5, col);
}

static void head(bas_canvas_t *c, const char *title, const char *right)
{
    bas_fill(c, 0, 0, W, TH_HEAD_H, TH_CARD);
    bas_serif_text(c, TH_PAD, 4, title != NULL ? title : "BASANOS", TH_INK, 1);

    /* Remote control is never covert. Once a command has arrived this stays
     * for the rest of the session and there is no way to switch it off. */
    int rx = W - TH_PAD - 22;
    bas_ui_battery(c, rx, 8);

    if (bas_console_active()) {
        const char *r = "REMOTE";
        rx -= bas_text_width(r, 1) + 8;
        bas_text(c, rx, 9, r, TH_STOP, 1);
    }
    if (right != NULL) {
        rx -= bas_text_width(right, 1) + 8;
        bas_text(c, rx, 9, right, TH_INK3, 1);
    }
    bas_hline(c, 0, TH_HEAD_H, W, TH_RULE2);
}

static void foot(bas_canvas_t *c, const char *s)
{
    if (s == NULL) {
        return;
    }
    bas_hline(c, 0, H - TH_FOOT_H, W, TH_RULE);
    bas_text(c, TH_PAD, H - TH_FOOT_H + 5, s, TH_INK3, 1);
}

static void page(bas_canvas_t *c, const char *title, const char *right)
{
    bas_canvas_clear(c, TH_PAPER);
    head(c, title, right);
}

/* --- generic list --------------------------------------------------------- */

#define LIST_TOP  (TH_HEAD_H + 4)
#define LIST_ROWS 5

void bas_ui_list(const char *title, const char *right,
                 const bas_row_t *rows, int n, int sel,
                 const char *footer)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, title, right);

    if (n <= 0) {
        bas_text(c, TH_PAD, 100, "Nothing here", TH_INK3, 1);
        foot(c, footer);
        bas_display_flush();
        return;
    }

    int first = (sel >= LIST_ROWS) ? sel - LIST_ROWS + 1 : 0;

    /* Say that the list continues.
     *
     * Five rows fit and the Wi-Fi menu holds ten, so half of it lived below a
     * fold with nothing on screen admitting the fold existed. An operator
     * looking for a family that was not in the first five concluded it had not
     * been built -- which is exactly what happened with PMKID.
     *
     * A track the height of the list with a proportional thumb, plus the
     * position in words, because a 3 px bar alone is easy to miss. */
    if (n > LIST_ROWS) {
        const int track_y = LIST_TOP;
        const int track_h = LIST_ROWS * TH_ROW_H - 2;
        const int bx      = W - 4;
        bas_fill(c, bx, track_y, 3, track_h, TH_RULE);

        int thumb_h = (track_h * LIST_ROWS) / n;
        if (thumb_h < 12) { thumb_h = 12; }
        int span = n - LIST_ROWS;                 /* > 0 inside this branch */
        int thumb_y = track_y + ((track_h - thumb_h) * first) / span;
        bas_fill(c, bx, thumb_y, 3, thumb_h, TH_BRASS);

        /* Both are list indices, but the compiler only knows they are ints,
         * so the buffer is sized for two of them. */
        char pos[24];
        snprintf(pos, sizeof(pos), "%d/%d", sel + 1, n);
        bas_text(c, W - TH_PAD - bas_text_width(pos, 1) - 4,
                 H - TH_FOOT_H - 11, pos, TH_INK3, 1);
    }

    for (int i = 0; i < LIST_ROWS; i++) {
        int idx = first + i;
        if (idx >= n) {
            break;
        }
        const bas_row_t *r = &rows[idx];
        int y = LIST_TOP + i * TH_ROW_H;
        bool on = (idx == sel);

        /* Selection is a wash plus a gold edge. Unselected rows carry no fill
         * at all, so the eye lands on one thing. */
        if (on) {
            bas_fill(c, 0, y, W, TH_ROW_H - 2, TH_WASH);
            bas_fill(c, 0, y, 3, TH_ROW_H - 2, TH_SHINE);
        }
        if (r->stripe != 0u) {
            bas_fill(c, on ? 3 : 0, y, 3, TH_ROW_H - 2, r->stripe);
        }

        uint16_t tc = r->enabled ? (on ? TH_INK : TH_INK2) : TH_INK3;
        uint16_t sc = r->enabled ? TH_INK3 : TH_RULE2;

        bas_text_clip(c, TH_PAD + 4, y + 5, r->title, tc, 1, W - 2 * TH_PAD - 8);
        if (r->sub != NULL) {
            bas_text_clip(c, TH_PAD + 4, y + 18, r->sub, sc, 1,
                          W - 2 * TH_PAD - 8);
        }
        if (idx < n - 1) {
            bas_hline(c, TH_PAD, y + TH_ROW_H - 2, W - 2 * TH_PAD, TH_RULE);
        }
    }

    /* A scroll hint only when there is more than fits — no ornament that
     * carries no information. */
    if (n > LIST_ROWS) {
        int track = LIST_ROWS * TH_ROW_H;
        int knob  = track * LIST_ROWS / n;
        if (knob < 8) { knob = 8; }
        int pos = (n > 1) ? (track - knob) * sel / (n - 1) : 0;
        bas_fill(c, W - 3, LIST_TOP + pos, 2, knob, TH_RULE2);
    }

    foot(c, footer);
    bas_display_flush();
}

int bas_ui_list_hit(uint16_t x, uint16_t y, int sel, int n)
{
    if ((int)y < LIST_TOP || (int)y >= LIST_TOP + LIST_ROWS * TH_ROW_H) {
        return -1;
    }
    int first = (sel >= LIST_ROWS) ? sel - LIST_ROWS + 1 : 0;
    int hit = first + ((int)y - LIST_TOP) / TH_ROW_H;
    return (hit >= 0 && hit < n) ? hit : -1;
}

/* --- splash and self test ------------------------------------------------- */

void bas_ui_splash(void)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, TH_PAPER);

    const char *t = "BASANOS";
    int tw = bas_serif_width(t, 2);
    bas_serif_text(c, (W - tw) / 2, 74, t, TH_INK, 2);
    bas_hline(c, (W - tw) / 2, 114, tw, TH_SHINE);

    const char *s = "wireless assessment instrument";
    bas_text(c, (W - bas_text_width(s, 1)) / 2, 132, s, TH_INK3, 1);

    const char *w = "AUTHORISED TESTING ONLY";
    bas_text(c, (W - bas_text_width(w, 1)) / 2, 210, w, TH_BRASS, 1);

    bas_display_flush();
}

void bas_ui_selftest(const bas_selftest_t *r)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Self test", NULL);

    bool ok = bas_selftest_ok(r);
    char buf[48];

    snprintf(buf, sizeof(buf), "%d", r->checks);
    bas_serif_text(c, TH_PAD, 40, buf, TH_INK, 2);
    bas_text(c, TH_PAD, 84, "safety checks on this silicon", TH_INK3, 1);

    bas_hline(c, TH_PAD, 104, W - 2 * TH_PAD, TH_RULE);

    if (ok) {
        bas_serif_text(c, TH_PAD, 114, "ALL PASSED", TH_OK, 1);
        bas_text(c, TH_PAD, 146, "Broadcast targets are", TH_INK2, 1);
        bas_text(c, TH_PAD, 160, "unreachable and no role", TH_INK2, 1);
        bas_text(c, TH_PAD, 174, "transmits without a", TH_INK2, 1);
        bas_text(c, TH_PAD, 188, "locked engagement.", TH_INK2, 1);
    } else {
        bas_serif_text(c, TH_PAD, 114, "FAILED", TH_STOP, 1);
        snprintf(buf, sizeof(buf), "%d of %d failed", r->failures, r->checks);
        bas_text(c, TH_PAD, 146, buf, TH_STOP, 1);
        bas_text_clip(c, TH_PAD, 164, r->first_failure, TH_INK, 1,
                      W - 2 * TH_PAD);
        bas_text(c, TH_PAD, 192, "This device will not arm.", TH_STOP, 1);
    }
    bas_display_flush();
}

void bas_ui_scanning(uint8_t channel, int found)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Survey", "passive");

    bas_serif_text(c, TH_PAD, 44, "Listening", TH_INK, 1);

    char buf[40];
    snprintf(buf, sizeof(buf), "channel %u of 13", (unsigned)channel);
    bas_text(c, TH_PAD, 84, buf, TH_INK3, 1);

    /* Real progress across the band, not a spinner. */
    for (uint8_t ch = 1; ch <= 13; ch++) {
        int x = TH_PAD + (ch - 1) * 17;
        bool done = ch <= channel;
        bas_fill(c, x, 110, 13, 30, done ? TH_BRASS : TH_SUNK);
        if (!done) {
            bas_rect(c, x, 110, 13, 30, TH_RULE);
        }
    }

    snprintf(buf, sizeof(buf), "%d networks so far", found);
    bas_text(c, TH_PAD, 156, buf, TH_INK2, 1);

    bas_text(c, TH_PAD, 186, "Receive only. Nothing is", TH_INK3, 1);
    bas_text(c, TH_PAD, 200, "transmitted during a survey.", TH_INK3, 1);

    bas_display_flush();
}

/* --- home ----------------------------------------------------------------- */

#define TILE_X0 TH_PAD
#define TILE_Y0 92
#define TILE_W  105
#define TILE_H  60
#define TILE_GX 10
#define TILE_GY 10

static void tile(bas_canvas_t *c, int col, int row, const char *name,
                 const char *value, bool on, bool ready)
{
    int x = TILE_X0 + col * (TILE_W + TILE_GX);
    int y = TILE_Y0 + row * (TILE_H + TILE_GY);

    bas_fill(c, x, y, TILE_W, TILE_H, on ? TH_WASH : TH_CARD);
    bas_rect(c, x, y, TILE_W, TILE_H, on ? TH_BRASS : TH_RULE);
    if (on) {
        bas_fill(c, x, y, 3, TILE_H, TH_SHINE);
    }

    bas_text(c, x + 10, y + 10, name, ready ? TH_INK : TH_INK3, 1);
    /* The figure is the point of the tile, so it carries the weight. */
    bas_serif_text(c, x + 10, y + 26, value, ready ? TH_INK : TH_RULE2, 1);
}

void bas_ui_home(const bas_engagement_t *e, const bas_scan_t *s,
                 const bas_card_t *card, int sel)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "BASANOS", NULL);

    char buf[64];

    /* The engagement strip. It is the first thing on the page because nothing
     * below it can transmit without one. */
    bool locked = (e != NULL && e->locked);
    bas_fill(c, 0, TH_HEAD_H + 1, W, 40, locked ? TH_WASH : TH_SUNK);
    bas_hline(c, 0, TH_HEAD_H + 41, W, TH_RULE);

    if (locked) {
        bas_fill(c, 0, TH_HEAD_H + 1, 3, 40, TH_SHINE);
        bas_text_clip(c, TH_PAD, TH_HEAD_H + 7,
                      e->target.hidden ? "(hidden network)" : e->target.ssid,
                      TH_INK, 1, W - 2 * TH_PAD);
        snprintf(buf, sizeof(buf), "ch %u  %s  %s",
                 (unsigned)e->target.channel, bas_sec_name(e->target.sec),
                 e->label);
        bas_text_clip(c, TH_PAD, TH_HEAD_H + 22, buf, TH_INK3, 1,
                      W - 2 * TH_PAD);
    } else {
        bas_text(c, TH_PAD, TH_HEAD_H + 7, "No target locked", TH_INK2, 1);
        bas_text(c, TH_PAD, TH_HEAD_H + 22, "Wi-Fi, then pick a network",
                 TH_INK3, 1);
    }

    bas_tally_t t;
    bas_card_tally(card, 0, &t);

    snprintf(buf, sizeof(buf), "%u", (unsigned)(s ? s->count : 0));
    tile(c, 0, 0, "WI-FI", buf, sel == BAS_HOME_WIFI, true);

    snprintf(buf, sizeof(buf), "%s", bas_ble_scanning() ? "scanning" : "ready");
    tile(c, 1, 0, "BLUETOOTH", buf, sel == BAS_HOME_BLE, true);

    tile(c, 0, 1, "RECON", locked ? "ready" : "scan", sel == BAS_HOME_RECON,
         true);

    snprintf(buf, sizeof(buf), "%d/%d", t.caught, (int)card->count);
    tile(c, 1, 1, "RESULTS", buf, sel == BAS_HOME_RESULTS, card->count > 0);

    foot(c, "RIGHT move   LEFT open");
    bas_display_flush();
}

int bas_ui_home_hit(uint16_t x, uint16_t y)
{
    for (int i = 0; i < BAS_HOME__COUNT; i++) {
        int col = i % 2, row = i / 2;
        int tx = TILE_X0 + col * (TILE_W + TILE_GX);
        int ty = TILE_Y0 + row * (TILE_H + TILE_GY);
        if ((int)x >= tx && (int)x < tx + TILE_W &&
            (int)y >= ty && (int)y < ty + TILE_H) {
            return i;
        }
    }
    return -1;
}

/* --- networks and target -------------------------------------------------- */

void bas_ui_networks(const bas_scan_t *s, int sel)
{
    static bas_row_t rows[BAS_MAX_APS];
    static char subs[BAS_MAX_APS][40];

    for (uint8_t i = 0; i < s->count; i++) {
        const bas_ap_t *ap = &s->ap[i];
        snprintf(subs[i], sizeof(subs[i]), "ch%-3u %4d dBm  %s%s",
                 (unsigned)ap->channel, (int)ap->rssi, bas_sec_name(ap->sec),
                 bas_sec_likely_mfp(ap->sec) ? "  protected" : "");
        rows[i].title   = ap->hidden ? "(hidden network)" : ap->ssid;
        rows[i].sub     = subs[i];
        /* Protected networks are expected to shrug off a deauth. Marking them
         * here saves the operator spending a run to find that out. */
        rows[i].stripe  = bas_sec_likely_mfp(ap->sec) ? TH_BRASS : 0u;
        rows[i].enabled = true;
    }

    char right[24];
    snprintf(right, sizeof(right), "%u found", (unsigned)s->count);
    bas_ui_list("Networks", right, rows, s->count, sel,
                "LEFT select   hold LEFT back");
}

void bas_ui_target(const bas_ap_t *ap, int station_count)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Target", NULL);

    char buf[64], mac[18];

    bas_serif_text(c, TH_PAD, 30, ap->hidden ? "(hidden)" : ap->ssid, TH_INK, 1);

    bas_mac_fmt(ap->bssid, mac, sizeof(mac));
    bas_text(c, TH_PAD, 58, mac, TH_INK3, 1);

    snprintf(buf, sizeof(buf), "channel %u    %d dBm    %s",
             (unsigned)ap->channel, (int)ap->rssi, bas_sec_name(ap->sec));
    bas_text(c, TH_PAD, 76, buf, TH_INK2, 1);

    if (station_count >= 0) {
        snprintf(buf, sizeof(buf), "%d client%s seen", station_count,
                 station_count == 1 ? "" : "s");
        bas_text(c, TH_PAD, 92, buf, TH_INK3, 1);
    }

    bas_hline(c, TH_PAD, 108, W - 2 * TH_PAD, TH_RULE);

    /* Posture, as a finding rather than a label. */
    if (bas_sec_likely_mfp(ap->sec)) {
        bas_fill(c, TH_PAD, 118, 4, 74, TH_BRASS);
        bas_text(c, TH_PAD + 12, 120, "PROTECTED", TH_BRASS, 2);
        bas_text(c, TH_PAD + 12, 146, "Management frames are", TH_INK2, 1);
        bas_text(c, TH_PAD + 12, 160, "protected, so a deauth", TH_INK2, 1);
        bas_text(c, TH_PAD + 12, 174, "run should bounce. That", TH_INK2, 1);
        bas_text(c, TH_PAD + 12, 188, "is a result, not a fault.", TH_INK2, 1);
    } else if (ap->sec == BAS_SEC_WPA2_WPA3) {
        bas_fill(c, TH_PAD, 118, 4, 60, TH_WARN);
        bas_text(c, TH_PAD + 12, 120, "TRANSITION", TH_WARN, 2);
        bas_text(c, TH_PAD + 12, 146, "WPA2/WPA3 mixed mode.", TH_INK2, 1);
        bas_text(c, TH_PAD + 12, 160, "The WPA2 half is not", TH_INK2, 1);
        bas_text(c, TH_PAD + 12, 174, "protected.", TH_INK2, 1);
    } else {
        bas_fill(c, TH_PAD, 118, 4, 46, TH_INK3);
        bas_text(c, TH_PAD + 12, 120, "UNPROTECTED", TH_INK, 2);
        bas_text(c, TH_PAD + 12, 146, "No management frame", TH_INK2, 1);
        bas_text(c, TH_PAD + 12, 160, "protection advertised.", TH_INK2, 1);
    }

    foot(c, "LEFT lock target   hold back");
    bas_display_flush();
}

/* --- keyboard ------------------------------------------------------------- */

static const char *KB[4] = {
    "ABCDEFGHIJ",
    "KLMNOPQRST",
    "UVWXYZ0123",
    "456789-_ .",
};

#define KB_X0 2
#define KB_Y0 106
#define KB_KW 23
#define KB_KH 26

void bas_ui_keyboard(const char *title, const char *buf)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Authorisation", NULL);

    bas_text(c, TH_PAD, 32, title, TH_INK3, 1);

    /* The field carries the accent because its contents end up in the audit
     * log — it is the record of under what authority this ran. */
    bas_fill(c, TH_PAD - 2, 48, W - 2 * TH_PAD + 4, 26, TH_CARD);
    bas_rect(c, TH_PAD - 2, 48, W - 2 * TH_PAD + 4, 26, TH_BRASS);
    bas_text_clip(c, TH_PAD + 4, 55, (buf && buf[0]) ? buf : "_", TH_INK, 2,
                  W - 2 * TH_PAD - 8);

    bas_text(c, TH_PAD, 84, "Name the authorisation for", TH_INK3, 1);
    bas_text(c, TH_PAD, 96, "this engagement.", TH_INK3, 1);

    for (int r = 0; r < 4; r++) {
        for (int k = 0; k < 10; k++) {
            int x = KB_X0 + k * KB_KW;
            int y = KB_Y0 + r * KB_KH;
            bas_fill(c, x, y, KB_KW - 2, KB_KH - 2, TH_CARD);
            bas_rect(c, x, y, KB_KW - 2, KB_KH - 2, TH_RULE);
            char s[2] = { KB[r][k], '\0' };
            bas_text(c, x + 8, y + 9, s, TH_INK, 1);
        }
    }

    bas_fill(c, TH_PAD, 214, 96, 20, TH_SUNK);
    bas_rect(c, TH_PAD, 214, 96, 20, TH_RULE2);
    bas_text(c, TH_PAD + 32, 220, "BACK", TH_INK2, 1);

    bas_fill(c, W - TH_PAD - 96, 214, 96, 20, TH_BRASS);
    bas_text(c, W - TH_PAD - 62, 220, "DONE", TH_PAPER, 1);

    bas_display_flush();
}

int bas_ui_keyboard_hit(uint16_t x, uint16_t y)
{
    if (y >= 214) {
        if (x < 110)                    { return -3; }
        if (x >= (uint16_t)(W - 110))   { return -2; }
        return -1;
    }
    if ((int)y < KB_Y0) {
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
    return (key < 0 || key > 39) ? '\0' : KB[key / 10][key % 10];
}

/* --- an attack about to fire ---------------------------------------------- */

static uint16_t class_colour(bas_class_t k)
{
    return k == BAS_CLASS_DISRUPTIVE ? TH_STOP
         : k == BAS_CLASS_ACTIVE     ? TH_WARN
                                     : TH_OK;
}

bool bas_ui_arm_hit(uint16_t x, uint16_t y)
{
    return (y >= BAS_ARM_Y0) && (y <= BAS_ARM_Y1) &&
           (x >= TH_PAD) && (x <= (uint16_t)(W - TH_PAD));
}

void bas_ui_attack(bas_family_t f, const bas_plan_t *p,
                   const bas_engagement_t *e, bas_err_t gate)
{
    bas_canvas_t *c = bas_display_canvas();
    const bas_family_spec_t *s = bas_family(f);
    page(c, s->name, bas_class_name(s->klass));

    char buf[64];
    bas_fill(c, 0, TH_HEAD_H + 1, 4, 30, class_colour(s->klass));
    bas_text_clip(c, TH_PAD + 4, TH_HEAD_H + 6, s->proves, TH_INK2, 1,
                  W - 2 * TH_PAD - 4);
    bas_text_clip(c, TH_PAD + 4, TH_HEAD_H + 19, s->detector, TH_BRASS, 1,
                  W - 2 * TH_PAD - 4);

    bas_hline(c, TH_PAD, 66, W - 2 * TH_PAD, TH_RULE);

    /* What will go out, in words, before anything can be committed. */
    bas_text(c, TH_PAD, 76, "WILL EMIT", TH_INK3, 1);
    if (p->continuous) {
        /* No total, so no false precision about how much. */
        bas_serif_text(c, TH_PAD, 86, "until stopped", TH_STOP, 1);
    } else {
        snprintf(buf, sizeof(buf), "%u frames over %u s",
                 (unsigned)bas_plan_frame_budget(p), (unsigned)p->seconds);
        bas_serif_text(c, TH_PAD, 86, buf, TH_INK, 1);
    }
    bas_text(c, W - TH_PAD - bas_text_width("RIGHT: time", 1), 76,
             "RIGHT: time", TH_BRASS, 1);

    snprintf(buf, sizeof(buf), "%u per second on channel %u",
             (unsigned)p->pps,
             (unsigned)(p->channel ? p->channel : e->target.channel));
    bas_text(c, TH_PAD, 114, buf, TH_INK3, 1);

    if (s->needs_target) {
        char mac[18];
        bas_mac_fmt(e->client_n == 1u ? e->client[0] : e->target.bssid, mac,
                    sizeof(mac));
        if (e->client_n > 1u) {
            snprintf(buf, sizeof(buf), "across %u selected clients",
                     (unsigned)e->client_n);
            bas_text(c, TH_PAD, 132, buf, TH_INK2, 1);
            bas_text(c, TH_PAD, 146, "one frame each, in turn", TH_INK3, 1);
        } else {
            snprintf(buf, sizeof(buf), "at %s", mac);
            bas_text(c, TH_PAD, 132, buf, TH_INK2, 1);
            bas_text(c, TH_PAD, 146,
                     e->client_n == 1u ? "one client" : "the access point",
                     TH_INK3, 1);
        }
    } else {
        bas_text(c, TH_PAD, 132, "broadcast advertisement", TH_INK2, 1);
        bas_text(c, TH_PAD, 146, "named " BAS_TEST_PREFIX "nn", TH_INK3, 1);
    }

    bas_hline(c, TH_PAD, 164, W - 2 * TH_PAD, TH_RULE);

    if (gate != BAS_OK) {
        bas_text(c, TH_PAD, 174, "BLOCKED", TH_STOP, 2);
        bas_text_clip(c, TH_PAD, 198, bas_err_str(gate), TH_INK, 1,
                      W - 2 * TH_PAD);
        foot(c, "hold LEFT to go back");
    } else if (!bas_tx_supported(f)) {
        bas_text(c, TH_PAD, 174, "UNAVAILABLE", TH_WARN, 2);
        bas_text_clip(c, TH_PAD, 198, bas_tx_pending_reason(f), TH_INK2, 1,
                      W - 2 * TH_PAD);
        foot(c, "hold LEFT to go back");
    } else {
        if (p->clamped_pps || p->clamped_secs) {
            bas_text(c, TH_PAD, 174, "clamped to the family ceiling", TH_WARN, 1);
        }
        bas_text_clip(c, TH_PAD, 178, e->label, TH_BRASS, 1, W - 2 * TH_PAD);

        if (s->klass == BAS_CLASS_DISRUPTIVE) {
            /* A real target to hold, drawn in the family's own severity
             * colour. Everything outside it means back, so the operator can
             * put a finger anywhere else on the screen without arming. */
            const int h = BAS_ARM_Y1 - BAS_ARM_Y0;
            bas_fill(c, TH_PAD, BAS_ARM_Y0, W - 2 * TH_PAD, h, TH_STOP);
            const char *lbl = "HOLD TO ARM";
            bas_text(c, (W - bas_text_width(lbl, 1)) / 2,
                     BAS_ARM_Y0 + (h / 2) - 3, lbl, TH_PAPER, 1);
            foot(c, "hold 3s to arm   hold elsewhere back");
        } else {
            foot(c, "LEFT to arm");
        }
    }
    bas_display_flush();
}

void bas_ui_hold(bas_family_t f, const bas_engagement_t *e, int pct)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Arm", "disruptive");

    bas_serif_text(c, TH_PAD, 32, "HOLD TO ARM", TH_STOP, 1);
    bas_text_clip(c, TH_PAD, 64, bas_family(f)->name, TH_INK, 1,
                  W - 2 * TH_PAD);
    bas_text_clip(c, TH_PAD, 78, e->target.hidden ? "(hidden)" : e->target.ssid,
                  TH_INK3, 1, W - 2 * TH_PAD);

    bas_text(c, TH_PAD, 102, "This family denies service", TH_INK2, 1);
    bas_text(c, TH_PAD, 116, "to a real device.", TH_INK2, 1);

    if (pct < 0)   { pct = 0; }
    if (pct > 100) { pct = 100; }

    int pw = W - 2 * TH_PAD;
    bas_fill(c, TH_PAD, 140, pw, 28, TH_CARD);
    bas_rect(c, TH_PAD, 140, pw, 28, TH_RULE2);
    bas_fill(c, TH_PAD + 1, 141, (pw - 2) * pct / 100, 26,
             pct >= 100 ? TH_STOP : TH_BRASS);

    char buf[16];
    snprintf(buf, sizeof(buf), "%d%%", pct);
    bas_text(c, (W - bas_text_width(buf, 2)) / 2, 178, buf,
             pct > 0 ? TH_INK : TH_INK3, 2);

    foot(c, pct > 0 ? "keep holding   release cancels"
                    : "hold LEFT, or the screen");
    bas_display_flush();
}

void bas_ui_arm(bas_family_t f, const bas_engagement_t *e, int left)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Arming", NULL);

    bas_serif_text(c, TH_PAD, 34, "ARMED", TH_STOP, 2);
    bas_text_clip(c, TH_PAD, 74, bas_family(f)->name, TH_INK, 1,
                  W - 2 * TH_PAD);
    bas_text_clip(c, TH_PAD, 88, e->target.hidden ? "(hidden)" : e->target.ssid,
                  TH_INK3, 1, W - 2 * TH_PAD);

    /* `left` is a countdown that no longer runs: the three-second hold is the
     * deliberation, and a second wait after it was a delay rather than a
     * decision. Zero means "go now", and a giant 0 on screen would be a
     * number the operator is waiting on when there is nothing left to wait
     * for. The parameter stays for the callers that still count. */
    if (left > 0) {
        char buf[12];               /* an int is up to 11 characters */
        snprintf(buf, sizeof(buf), "%d", left);
        bas_text(c, (W - bas_text_width(buf, 8)) / 2, 116, buf, TH_SHINE, 8);
    } else {
        const char *g = "GO";
        bas_serif_text(c, (W - bas_text_width(g, 4)) / 2, 124, g, TH_SHINE, 4);
    }

    foot(c, "any button aborts");
    bas_display_flush();
}

void bas_ui_running(bas_family_t f, const bas_engagement_t *e,
                    const bas_tx_result_t *p, uint32_t budget)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, TH_PAPER);

    /* The banner is a safety mechanism rather than decoration: while this
     * device is emitting, the screen says so and cannot be turned off. */
    bas_fill(c, 0, 0, W, TH_HEAD_H, TH_STOP);
    bas_text_b(c, TH_PAD, 9, "TRANSMITTING", TH_PAPER, 1);
    bas_ui_battery(c, W - TH_PAD - 22, 8);

    char buf[64];
    bas_text_clip(c, TH_PAD, 36, bas_family(f)->name, TH_INK, 2,
                  W - 2 * TH_PAD);
    bas_text_clip(c, TH_PAD, 60, e->target.hidden ? "(hidden)" : e->target.ssid,
                  TH_INK3, 1, W - 2 * TH_PAD);

    snprintf(buf, sizeof(buf), "%u", (unsigned)p->frames_sent);
    bas_serif_text(c, TH_PAD, 78, buf, TH_INK, 2);
    bas_text(c, TH_PAD, 130, "frames sent", TH_INK3, 1);

    int pw = W - 2 * TH_PAD;
    bas_fill(c, TH_PAD, 150, pw, 12, TH_CARD);
    bas_rect(c, TH_PAD, 150, pw, 12, TH_RULE2);

    if (budget > 0u) {
        uint32_t done = p->frames_sent > budget ? budget : p->frames_sent;
        bas_fill(c, TH_PAD + 1, 151, (int)((uint32_t)(pw - 2) * done / budget),
                 10, TH_SHINE);
        snprintf(buf, sizeof(buf), "of %u    %u.%us elapsed", (unsigned)budget,
                 (unsigned)(p->elapsed_ms / 1000),
                 (unsigned)((p->elapsed_ms % 1000) / 100));
    } else {
        /* Continuous. A bar that fills toward an end there isn't would be a
         * lie about progress, so this is a mark that travels: it shows the run
         * is alive and claims nothing about how far along it is. */
        int span = pw - 26;
        if (span < 1) { span = 1; }
        int x = (int)((p->elapsed_ms / 40u) % (uint32_t)span);
        bas_fill(c, TH_PAD + 1 + x, 151, 24, 10, TH_SHINE);
        snprintf(buf, sizeof(buf), "until stopped    %u:%02u elapsed",
                 (unsigned)(p->elapsed_ms / 60000u),
                 (unsigned)((p->elapsed_ms / 1000u) % 60u));
    }
    bas_text(c, TH_PAD, 168, buf, TH_INK3, 1);

    if (p->tx_errors > 0u) {
        snprintf(buf, sizeof(buf), "%u rejected by the radio",
                 (unsigned)p->tx_errors);
        bas_text(c, TH_PAD, 186, buf, TH_WARN, 1);
    }
    if (p->frames_refused > 0u) {
        snprintf(buf, sizeof(buf), "%u refused by the gate",
                 (unsigned)p->frames_refused);
        bas_text(c, TH_PAD, 200, buf, TH_STOP, 1);
    }

    foot(c, "any button stops the run");
    bas_display_flush();
}

void bas_ui_ask(bas_family_t f, uint32_t frames, uint32_t grace_left_ms)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Score", NULL);

    char buf[64];
    bas_serif_text(c, TH_PAD, 32, "Did it alarm?", TH_INK, 1);

    snprintf(buf, sizeof(buf), "%u frames of %s", (unsigned)frames,
             bas_family(f)->name);
    bas_text_clip(c, TH_PAD, 64, buf, TH_INK3, 1, W - 2 * TH_PAD);

    bas_text(c, TH_PAD, 88, "Press LEFT the moment your", TH_INK2, 1);
    bas_text(c, TH_PAD, 102, "detector reacts.", TH_INK2, 1);

    /* Honesty about what this measurement is. */
    bas_fill(c, TH_PAD, 122, 3, 44, TH_RULE2);
    bas_text(c, TH_PAD + 10, 124, "Operator-timed, so the", TH_INK3, 1);
    bas_text(c, TH_PAD + 10, 138, "latency includes you. It is", TH_INK3, 1);
    bas_text(c, TH_PAD + 10, 152, "never averaged with a", TH_INK3, 1);
    bas_text(c, TH_PAD + 10, 166, "machine-reported alarm.", TH_INK3, 1);

    int pw = W - 2 * TH_PAD;
    bas_fill(c, TH_PAD, 186, pw, 10, TH_CARD);
    bas_rect(c, TH_PAD, 186, pw, 10, TH_RULE2);
    uint32_t span = BAS_GRACE_DEFAULT_MS;
    uint32_t left = grace_left_ms > span ? span : grace_left_ms;
    bas_fill(c, TH_PAD + 1, 187, (int)((uint32_t)(pw - 2) * left / span), 8,
             TH_BRASS);

    foot(c, "LEFT alarmed   hold LEFT missed");
    bas_display_flush();
}

void bas_ui_tx_failed(bas_family_t f, const bas_tx_result_t *r)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Not sent", NULL);

    char buf[64];
    bas_serif_text(c, TH_PAD, 32, "NOTHING WENT OUT", TH_STOP, 1);
    bas_text_clip(c, TH_PAD, 62, bas_family(f)->name, TH_INK, 1,
                  W - 2 * TH_PAD);

    snprintf(buf, sizeof(buf), "%u sent, %u rejected",
             (unsigned)r->frames_sent, (unsigned)r->tx_errors);
    bas_text(c, TH_PAD, 82, buf, TH_INK2, 1);

    if (r->frames_refused > 0u) {
        bas_text_clip(c, TH_PAD, 98, bas_err_str(r->stopped_by), TH_WARN, 1,
                      W - 2 * TH_PAD);
    } else if (r->stopped_by == BAS_ERR_NO_TARGET) {
        /* A targeting problem, not a radio one. Saying "the radio rejected
         * them" would send the operator to debug the wrong half. */
        bas_text(c, TH_PAD, 98, "This family needs the", TH_INK3, 1);
        bas_text(c, TH_PAD, 110, "network's name, and the", TH_INK3, 1);
        bas_text(c, TH_PAD, 122, "target is hidden.", TH_INK3, 1);
    } else {
        bas_text(c, TH_PAD, 98, "The radio rejected them.", TH_INK3, 1);
    }

    bas_hline(c, TH_PAD, 120, W - 2 * TH_PAD, TH_RULE);

    bas_text(c, TH_PAD, 132, "This run is not scored.", TH_BRASS, 1);
    bas_text(c, TH_PAD, 154, "A detector cannot miss what", TH_INK2, 1);
    bas_text(c, TH_PAD, 168, "was never sent, and recording", TH_INK2, 1);
    bas_text(c, TH_PAD, 182, "a MISSED here would blame the", TH_INK2, 1);
    bas_text(c, TH_PAD, 196, "wrong half of the test.", TH_INK2, 1);

    foot(c, "LEFT to continue");
    bas_display_flush();
}

void bas_ui_results(const bas_card_t *card, uint32_t now_ms)
{
    bas_canvas_t *c = bas_display_canvas();

    char buf[80];
    snprintf(buf, sizeof(buf), "%u runs", (unsigned)card->count);
    page(c, "Results", buf);

    bas_tally_t t;
    bas_card_tally(card, now_ms, &t);

    /* Three figures: the point of the whole instrument. */
    struct { const char *l; int v; uint16_t col; } col[3] = {
        { "CAUGHT", t.caught, TH_OK },
        { "LATE",   t.late,   TH_WARN },
        { "MISSED", t.missed, TH_STOP },
    };
    for (int i = 0; i < 3; i++) {
        int x = TH_PAD + i * 74;
        snprintf(buf, sizeof(buf), "%d", col[i].v);
        bas_serif_text(c, x, 32, buf, col[i].col, 2);
        bas_text(c, x, 74, col[i].l, TH_INK3, 1);
    }

    bas_hline(c, TH_PAD, 92, W - 2 * TH_PAD, TH_RULE);

    if (t.best_latency_ms >= 0) {
        snprintf(buf, sizeof(buf), "fastest %d.%01ds    slowest %d.%01ds",
                 (int)(t.best_latency_ms / 1000),
                 (int)((t.best_latency_ms % 1000) / 100),
                 (int)(t.worst_latency_ms / 1000),
                 (int)((t.worst_latency_ms % 1000) / 100));
        bas_text(c, TH_PAD, 100, buf, TH_INK2, 1);
    } else {
        bas_text(c, TH_PAD, 100, "nothing caught yet", TH_INK3, 1);
    }

    int y = 118;
    int shown = 0;
    for (int i = (int)card->count - 1; i >= 0 && shown < 7; i--, shown++) {
        char line[96];
        bas_run_line(&card->r[i], now_ms, line, sizeof(line));
        bas_verdict_t v = bas_run_verdict(&card->r[i], now_ms);
        uint16_t cc = v == BAS_VERDICT_CAUGHT ? TH_OK
                    : v == BAS_VERDICT_LATE   ? TH_WARN
                    : v == BAS_VERDICT_MISSED ? TH_STOP
                                              : TH_INK3;
        bas_fill(c, TH_PAD, y + 1, 3, 9, cc);
        bas_text_clip(c, TH_PAD + 8, y, line, TH_INK2, 1,
                      W - 2 * TH_PAD - 8);
        y += 13;
    }

    foot(c, "LEFT to continue");
    bas_display_flush();
}

void bas_ui_note(const char *title, const char *l1, const char *l2,
                 uint16_t accent)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "BASANOS", NULL);

    bas_fill(c, 0, TH_HEAD_H + 10, 4, 26, accent);
    bas_text_clip(c, TH_PAD + 4, TH_HEAD_H + 14, title, accent, 2,
                  W - 2 * TH_PAD);
    if (l1 != NULL) {
        bas_text_clip(c, TH_PAD, 100, l1, TH_INK, 1, W - 2 * TH_PAD);
    }
    if (l2 != NULL) {
        bas_text_clip(c, TH_PAD, 116, l2, TH_INK3, 1, W - 2 * TH_PAD);
    }
    bas_display_flush();
}

void bas_ui_touchtest(bool present, uint8_t chip_id,
                      bool down, uint16_t x, uint16_t y, int taps)
{
    bas_canvas_t *c = bas_display_canvas();
    page(c, "Touch check", NULL);

    char buf[48];

    if (!present) {
        bas_text(c, TH_PAD, 44, "NO CONTROLLER", TH_STOP, 2);
        bas_text(c, TH_PAD, 76, "Nothing answered at 0x15.", TH_INK2, 1);
        bas_text(c, TH_PAD, 100, "The buttons still work:", TH_INK, 1);
        bas_text(c, TH_PAD, 114, "RIGHT moves, LEFT opens.", TH_INK2, 1);
        bas_display_flush();
        return;
    }

    snprintf(buf, sizeof(buf), "CST816   id 0x%02X", (unsigned)chip_id);
    bas_text(c, TH_PAD, 34, buf, TH_BRASS, 1);

    bas_fill(c, 20, 50, 200, 146, TH_CARD);
    bas_rect(c, 20, 50, 200, 146, TH_RULE2);

    if (down) {
        int px = 20 + (int)((uint32_t)x * 200u / 240u);
        int py = 50 + (int)((uint32_t)y * 146u / 240u);
        bas_fill(c, px - 10, py, 21, 1, TH_SHINE);
        bas_fill(c, px, py - 10, 1, 21, TH_SHINE);
        bas_fill(c, px - 2, py - 2, 5, 5, TH_STOP);
        snprintf(buf, sizeof(buf), "x %3u   y %3u", (unsigned)x, (unsigned)y);
        bas_text(c, TH_PAD, 202, buf, TH_INK, 1);
    } else {
        bas_text(c, TH_PAD, 202, "touch the panel", TH_INK3, 1);
    }

    snprintf(buf, sizeof(buf), "%d taps", taps);
    bas_text(c, W - TH_PAD - bas_text_width(buf, 1), 202, buf,
             taps > 0 ? TH_OK : TH_INK3, 1);

    foot(c, "RIGHT to continue");
    bas_display_flush();
}

/* --- recon ---------------------------------------------------------------- */

void bas_ui_channels(const bas_chansurvey_t *ch, uint8_t current)
{
    bas_canvas_t *c = bas_display_canvas();

    char right[16];
    snprintf(right, sizeof(right), "ch %u", (unsigned)current);
    page(c, "Channels", right);

    uint8_t max_ch = bas_region_max_channel();
    const int base = 190;
    const int span = 118;
    const int bw   = (W - 2 * TH_PAD) / (int)max_ch;

    for (uint8_t i = 1; i <= max_ch; i++) {
        int x = TH_PAD + (i - 1) * bw;
        uint8_t sc = bas_chan_score(ch, i);
        int h = (span * sc) / 100;
        if (h < 1 && sc > 0) { h = 1; }

        /* A channel nobody listened to is unmeasured, not quiet. Drawing it as
         * an empty bar would say the opposite. */
        bool measured = ch->dwell_ms[i] > 0u;
        if (!measured) {
            for (int y = base - span; y < base; y += 4) {
                bas_fill(c, x + 1, y, bw - 3, 1, TH_RULE);
            }
        } else {
            bas_fill(c, x + 1, base - h, bw - 3, h,
                     i == current ? TH_SHINE : TH_BRASS);
        }

        if (i == current) {
            bas_fill(c, x + 1, base + 2, bw - 3, 2, TH_INK);
        }

        char n[4];
        snprintf(n, sizeof(n), "%u", (unsigned)i);
        bas_text(c, x + (bw - bas_text_width(n, 1)) / 2, base + 7, n,
                 i == current ? TH_INK : TH_INK3, 1);
    }

    bas_hline(c, TH_PAD, base, W - 2 * TH_PAD, TH_RULE2);

    /* The recommendation, and an honest refusal when it cannot be made. */
    uint8_t quiet = bas_chan_quietest(ch, 400);
    char buf[52];
    if (quiet != 0u) {
        snprintf(buf, sizeof(buf), "quietest measured: channel %u",
                 (unsigned)quiet);
        bas_text(c, TH_PAD, 36, buf, TH_INK, 1);
    } else {
        bas_text(c, TH_PAD, 36, "not listened to long enough", TH_INK3, 1);
    }
    bas_text(c, TH_PAD, 52, "hatched = never measured", TH_INK3, 1);

    foot(c, "RIGHT retune   hold LEFT back");
    bas_display_flush();
}

void bas_ui_frames(const bas_fcount_t *f, uint8_t channel)
{
    bas_canvas_t *c = bas_display_canvas();
    char right[16];
    snprintf(right, sizeof(right), "ch %u", (unsigned)channel);
    page(c, "Frames", right);

    char buf[52];
    snprintf(buf, sizeof(buf), "%u", (unsigned)f->total);
    bas_serif_text(c, TH_PAD, 30, buf, TH_INK, 2);

    uint32_t r = bas_fcount_rate_x100(f);
    if (r > 0u) {
        snprintf(buf, sizeof(buf), "%u.%02u per second",
                 (unsigned)(r / 100u), (unsigned)(r % 100u));
    } else {
        /* Under a quarter second is not a measurement, and inventing a rate
         * from two frames would put a fiction on the screen. */
        snprintf(buf, sizeof(buf), "measuring...");
    }
    bas_text(c, TH_PAD, 66, buf, TH_INK3, 1);

    bas_hline(c, TH_PAD, 84, W - 2 * TH_PAD, TH_RULE);

    static const bas_ftype_t show[] = {
        BAS_FT_BEACON, BAS_FT_PROBE_REQ, BAS_FT_DEAUTH,
        BAS_FT_DISASSOC, BAS_FT_AUTH, BAS_FT_DATA,
    };
    int y = 94;
    for (int i = 0; i < 6; i++) {
        bas_ftype_t k = show[i];
        uint32_t n = f->frames[k];
        /* Deauth and disassoc are what this device exists to emit, so seeing
         * them from someone else is worth colouring. */
        uint16_t col = (k == BAS_FT_DEAUTH || k == BAS_FT_DISASSOC) && n > 0u
                           ? TH_STOP : TH_INK2;
        bas_text(c, TH_PAD, y, bas_ftype_name(k), col, 1);
        snprintf(buf, sizeof(buf), "%u", (unsigned)n);
        bas_text(c, W - TH_PAD - bas_text_width(buf, 1), y, buf, col, 1);

        int bw = (int)((uint32_t)(W - 2 * TH_PAD) *
                       (f->total ? (n * 100u / f->total) : 0u) / 100u);
        bas_fill(c, TH_PAD, y + 10, bw, 2, col == TH_STOP ? TH_STOP : TH_RULE2);
        y += 20;
    }

    foot(c, "hold LEFT back");
    bas_display_flush();
}

void bas_ui_clients(const bas_stalist_t *l, int sel,
                    const bas_engagement_t *e)
{
    static bas_row_t rows[BAS_MAX_STATIONS + 1];
    static char names[BAS_MAX_STATIONS + 1][26];
    static char subs[BAS_MAX_STATIONS + 1][40];

    int chosen = 0;
    for (uint8_t i = 0; i < l->count; i++) {
        if (bas_engage_has_client(e, l->s[i].mac)) { chosen++; }
    }

    bool cell = bas_engage_is_whole_cell(e);

    /* Row 0 is the whole cell: every station on THIS network, including any
     * that stayed silent through the survey and never appeared below. */
    snprintf(names[0], sizeof(names[0]), "%s Whole network",
             cell ? "[x]" : "[ ]");
    snprintf(subs[0], sizeof(subs[0]), "%s",
             cell ? "every client on this cell"
                  : "reaches clients not listed below");
    rows[0].title   = names[0];
    rows[0].sub     = subs[0];
    rows[0].stripe  = cell ? TH_STOP : TH_BRASS;
    rows[0].enabled = true;

    for (uint8_t i = 0; i < l->count; i++) {
        const bas_station_t *st = &l->s[i];
        /* With the whole cell chosen every station is covered, so they all
         * read as selected rather than looking untouched. */
        bool on = cell || bas_engage_has_client(e, st->mac);

        char mac[18];
        bas_mac_fmt(st->mac, mac, sizeof(mac));
        /* A leading mark rather than a colour alone: which rows are selected
         * has to survive a glance in daylight. */
        snprintf(names[i + 1], sizeof(names[i + 1]), "%s %s",
                 on ? "[x]" : "[ ]", mac);
        snprintf(subs[i + 1], sizeof(subs[i + 1]), "%4d dBm  %u frames%s",
                 (int)st->rssi, (unsigned)st->frames,
                 st->randomised ? "  rotating" : "");

        rows[i + 1].title   = names[i + 1];
        rows[i + 1].sub     = subs[i + 1];
        rows[i + 1].stripe  = on ? TH_STOP : 0u;
        /* Individual picks are meaningless while the whole cell is chosen. */
        rows[i + 1].enabled = !cell;
    }

    char right[24];
    if (cell) {
        snprintf(right, sizeof(right), "whole cell");
    } else {
        snprintf(right, sizeof(right), "%d selected", chosen);
    }

    bas_ui_list("Clients", right, rows, (int)l->count + 1, sel,
                cell    ? "LEFT toggle   every client on this network"
              : chosen > 0 ? "LEFT toggle   runs hit the ticked"
                           : "LEFT toggle   none = the AP itself");
}

void bas_ui_probes(const bas_probe_t *p, int n, int sel)
{
    static bas_row_t rows[BAS_MAX_PROBES];
    static char subs[BAS_MAX_PROBES][40];

    for (int i = 0; i < n && i < BAS_MAX_PROBES; i++) {
        char mac[18];
        bas_mac_fmt(p[i].src, mac, sizeof(mac));
        snprintf(subs[i], sizeof(subs[i]), "%s  x%u", mac,
                 (unsigned)p[i].count);
        rows[i].title   = p[i].ssid;
        rows[i].sub     = subs[i];
        rows[i].stripe  = p[i].randomised ? TH_WARN : 0u;
        rows[i].enabled = true;
    }

    char right[20];
    snprintf(right, sizeof(right), "%d names", n);
    bas_ui_list("Probes", right, rows, n, sel, "hold LEFT back");
}

void bas_ui_ble_devices(const bas_ble_dev_t *d, int n, int sel,
                        uint32_t tracker_dwell_ms)
{
    static bas_row_t rows[BAS_BLE_MAX_DEV];
    static char names[BAS_BLE_MAX_DEV][26];
    static char subs[BAS_BLE_MAX_DEV][40];

    int trackers = 0;
    for (int i = 0; i < n && i < BAS_BLE_MAX_DEV; i++) {
        bool trk = bas_ble_kind_is_tracker(d[i].kind);
        if (trk) { trackers++; }

        if (d[i].name[0] != '\0') {
            snprintf(names[i], sizeof(names[i]), "%s", d[i].name);
        } else {
            bas_mac_fmt(d[i].addr, names[i], sizeof(names[i]));
        }
        snprintf(subs[i], sizeof(subs[i]), "%4d dBm  %s%s", (int)d[i].rssi,
                 bas_ble_kind_name(d[i].kind),
                 d[i].randomised ? "  rotating" : "");

        rows[i].title   = names[i];
        rows[i].sub     = subs[i];
        /* Trackers get the stripe. A phone advertising is background; a
         * tracker in range is a finding. */
        rows[i].stripe  = trk ? TH_STOP : 0u;
        rows[i].enabled = true;
    }

    char right[24];
    if (trackers > 0) {
        snprintf(right, sizeof(right), "%d tracker%s", trackers,
                 trackers == 1 ? "" : "s");
    } else {
        snprintf(right, sizeof(right), "%d seen", n);
    }

    char foot[48];
    if (trackers > 0 && tracker_dwell_ms > 0u) {
        /* Dwell is what separates a tracker following you from one that was
         * simply in the room -- so it is the number on the screen. */
        snprintf(foot, sizeof(foot), "longest dwell %us   hold LEFT back",
                 (unsigned)(tracker_dwell_ms / 1000u));
    } else {
        snprintf(foot, sizeof(foot), "hold LEFT back");
    }

    bas_ui_list("Bluetooth", right, rows, n, sel, foot);
}
