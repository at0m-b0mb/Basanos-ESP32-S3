/* Basanos — screens.
 *
 * House style, dark variant: true black ground, warm paper text, one deep
 * brass that stays readable at caption size and a bright shine used only on
 * marks that carry no words. No decoration that is not carrying information.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ui.h"
#include "display.h"

#include <stdio.h>
#include <string.h>

#define W 240
#define H 240

static void header(bas_canvas_t *c, const char *label)
{
    bas_fill(c, 0, 0, W, 22, BAS_C_SURFACE);
    bas_text(c, 8, 8, "BASANOS", BAS_C_BRASS, 1);
    if (label != NULL) {
        int w = bas_text_width(label, 1);
        bas_text(c, W - 8 - w, 8, label, BAS_C_DIM, 1);
    }
    bas_hline(c, 0, 22, W, BAS_C_FAINT);
}

void bas_ui_splash(void)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);

    const char *t = "BASANOS";
    int tw = bas_text_width(t, 4);
    bas_text(c, (W - tw) / 2, 86, t, BAS_C_PAPER, 4);

    /* The rule under the wordmark is the only ornament on this screen, and it
     * is the brand mark rather than decoration. */
    bas_hline(c, (W - tw) / 2, 122, tw, BAS_C_SHINE);

    const char *s = "detector proving ground";
    bas_text(c, (W - bas_text_width(s, 1)) / 2, 134, s, BAS_C_DIM, 1);

    const char *w = "authorised testing only";
    bas_text(c, (W - bas_text_width(w, 1)) / 2, 214, w, BAS_C_BRASS, 1);

    bas_display_flush();
}

void bas_ui_selftest(const bas_selftest_t *r)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    header(c, "self test");

    bool ok = bas_selftest_ok(r);
    uint16_t accent = ok ? BAS_C_OK : BAS_C_STOP;

    char buf[48];
    snprintf(buf, sizeof(buf), "%d", r->checks);
    bas_text(c, 16, 52, buf, BAS_C_PAPER, 4);
    bas_text(c, 16, 88, "checks on this silicon", BAS_C_DIM, 1);

    bas_fill(c, 16, 112, W - 32, 2, BAS_C_FAINT);

    bas_text(c, 16, 128, ok ? "ALL PASSED" : "FAILED", accent, 2);

    if (ok) {
        bas_text(c, 16, 156, "Safety invariants hold.", BAS_C_DIM, 1);
        bas_text(c, 16, 170, "Broadcast unreachable,", BAS_C_DIM, 1);
        bas_text(c, 16, 184, "admin needs a target.", BAS_C_DIM, 1);
    } else {
        snprintf(buf, sizeof(buf), "%d failed", r->failures);
        bas_text(c, 16, 156, buf, BAS_C_STOP, 1);
        bas_text_clip(c, 16, 174, r->first_failure, BAS_C_PAPER, 1, W - 32);
        bas_text(c, 16, 200, "Device will not arm.", BAS_C_STOP, 1);
    }

    bas_display_flush();
}

void bas_ui_scanning(uint8_t channel)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    header(c, "passive");

    bas_text(c, 16, 60, "Surveying", BAS_C_PAPER, 3);

    char buf[32];
    snprintf(buf, sizeof(buf), "channel %u", (unsigned)channel);
    bas_text(c, 16, 96, buf, BAS_C_DIM, 1);

    /* A channel strip that fills as the survey walks the band — the only
     * moving thing on the screen, and it is real progress, not a spinner. */
    for (uint8_t ch = 1; ch <= 13; ch++) {
        int x = 16 + (ch - 1) * 16;
        bool done = ch <= channel;
        bas_fill(c, x, 130, 12, 28, done ? BAS_C_BRASS : BAS_C_SURFACE);
    }

    bas_text(c, 16, 176, "Receive only. Nothing", BAS_C_DIM, 1);
    bas_text(c, 16, 190, "is transmitted here.", BAS_C_DIM, 1);

    bas_display_flush();
}

void bas_ui_picker(const bas_scan_t *s, int sel)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);

    char buf[48];
    snprintf(buf, sizeof(buf), "%u found", (unsigned)s->count);
    header(c, buf);

    if (s->count == 0u) {
        bas_text(c, 16, 100, "No networks in range", BAS_C_DIM, 1);
        bas_display_flush();
        return;
    }

    const int row_h = 34;
    const int top   = 28;
    const int rows  = (H - top - 18) / row_h;    /* 6 rows */

    int first = 0;
    if (sel >= rows) {
        first = sel - rows + 1;
    }

    for (int i = 0; i < rows; i++) {
        int idx = first + i;
        if (idx >= (int)s->count) {
            break;
        }
        const bas_ap_t *ap = &s->ap[idx];
        int y = top + i * row_h;
        bool on = (idx == sel);

        if (on) {
            bas_fill(c, 0, y, W, row_h - 2, BAS_C_SURFACE);
            bas_fill(c, 0, y, 3, row_h - 2, BAS_C_SHINE);
        }

        const char *name = ap->hidden ? "(hidden)" : ap->ssid;
        bas_text_clip(c, 10, y + 4, name,
                      on ? BAS_C_PAPER : BAS_C_DIM, 1, W - 60);

        /* Signal as a number, right-aligned. Tabular by construction because
         * the font is fixed width. */
        snprintf(buf, sizeof(buf), "%d", (int)ap->rssi);
        bas_text(c, W - 10 - bas_text_width(buf, 1), y + 4, buf,
                 on ? BAS_C_PAPER : BAS_C_DIM, 1);

        snprintf(buf, sizeof(buf), "ch%-3u %s", (unsigned)ap->channel,
                 bas_sec_name(ap->sec));
        bas_text(c, 10, y + 16, buf, BAS_C_DIM, 1);

        /* WPA3 and enterprise are expected to shrug off a deauth. Saying so
         * here saves the operator spending a run to find out. */
        if (bas_sec_likely_mfp(ap->sec)) {
            const char *m = "MFP";
            bas_text(c, W - 10 - bas_text_width(m, 1), y + 16, m, BAS_C_BRASS, 1);
        }
    }

    bas_hline(c, 0, H - 16, W, BAS_C_FAINT);
    bas_text(c, 8, H - 12, "PLUS next   PWR select", BAS_C_DIM, 1);

    bas_display_flush();
}

void bas_ui_message(const char *title, const char *line1, const char *line2,
                    uint16_t accent)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    header(c, NULL);

    bas_text(c, 16, 60, title, accent, 2);
    if (line1 != NULL) {
        bas_text_clip(c, 16, 100, line1, BAS_C_PAPER, 1, W - 32);
    }
    if (line2 != NULL) {
        bas_text_clip(c, 16, 116, line2, BAS_C_DIM, 1, W - 32);
    }
    bas_display_flush();
}

void bas_ui_touchtest(bool present, uint8_t chip_id,
                      bool down, uint16_t x, uint16_t y, int taps)
{
    bas_canvas_t *c = bas_display_canvas();
    bas_canvas_clear(c, BAS_C_BLACK);
    header(c, "touch check");

    char buf[48];

    if (!present) {
        bas_text(c, 16, 60, "NO CONTROLLER", BAS_C_STOP, 2);
        bas_text(c, 16, 96, "Nothing answered at", BAS_C_DIM, 1);
        bas_text(c, 16, 110, "I2C address 0x15.", BAS_C_DIM, 1);
        bas_text(c, 16, 132, "Buttons still work:", BAS_C_PAPER, 1);
        bas_text(c, 16, 146, "PLUS scrolls, MINUS", BAS_C_DIM, 1);
        bas_text(c, 16, 160, "opens a network.", BAS_C_DIM, 1);
        bas_display_flush();
        return;
    }

    snprintf(buf, sizeof(buf), "CST816  id 0x%02X", (unsigned)chip_id);
    bas_text(c, 16, 30, buf, BAS_C_BRASS, 1);

    /* A frame marking the live area, so it is obvious whether a press lands
     * where the finger actually is or somewhere mirrored. */
    bas_rect(c, 20, 46, 200, 150, BAS_C_FAINT);

    if (down) {
        int px = 20 + (int)((uint32_t)x * 200u / 240u);
        int py = 46 + (int)((uint32_t)y * 150u / 240u);
        bas_fill(c, px - 10, py, 21, 1, BAS_C_SHINE);
        bas_fill(c, px, py - 10, 1, 21, BAS_C_SHINE);
        bas_fill(c, px - 2, py - 2, 5, 5, BAS_C_SHINE);

        snprintf(buf, sizeof(buf), "x %3u  y %3u", (unsigned)x, (unsigned)y);
        bas_text(c, 20, 202, buf, BAS_C_PAPER, 1);
    } else {
        bas_text(c, 20, 202, "touch the screen", BAS_C_DIM, 1);
    }

    snprintf(buf, sizeof(buf), "%d taps", taps);
    bas_text(c, W - 20 - bas_text_width(buf, 1), 202, buf,
             taps > 0 ? BAS_C_OK : BAS_C_DIM, 1);

    bas_text(c, 20, 220, "PLUS to continue", BAS_C_BRASS, 1);
    bas_display_flush();
}
