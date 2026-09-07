/* Basanos — RGB565 canvas. SPDX-License-Identifier: MIT */
#include "canvas.h"

#include <string.h>

extern const uint8_t bas_font5x7[95][5];

void bas_canvas_init(bas_canvas_t *c, uint16_t *px, int w, int h)
{
    if (c == NULL) {
        return;
    }
    c->px  = px;
    c->w   = w;
    c->h   = h;
    c->oob = 0u;
}

void bas_canvas_clear(bas_canvas_t *c, uint16_t colour)
{
    if (c == NULL || c->px == NULL) {
        return;
    }
    size_t n = (size_t)c->w * (size_t)c->h;
    for (size_t i = 0; i < n; i++) {
        c->px[i] = colour;
    }
}

void bas_px(bas_canvas_t *c, int x, int y, uint16_t colour)
{
    if (c == NULL || c->px == NULL) {
        return;
    }
    if (x < 0 || y < 0 || x >= c->w || y >= c->h) {
        /* Counted, not written. A layout bug becomes a number the self-test
         * can assert on instead of a corruption two frames later. */
        c->oob++;
        return;
    }
    c->px[(size_t)y * (size_t)c->w + (size_t)x] = colour;
}

void bas_fill(bas_canvas_t *c, int x, int y, int w, int h, uint16_t colour)
{
    if (c == NULL || c->px == NULL || w <= 0 || h <= 0) {
        return;
    }
    /* Clip the rectangle rather than clipping each pixel: a fully off-screen
     * fill would otherwise add tens of thousands to the oob counter and drown
     * the signal it exists to give. */
    int x0 = x, y0 = y, x1 = x + w, y1 = y + h;
    bool clipped = false;
    if (x0 < 0)      { x0 = 0;    clipped = true; }
    if (y0 < 0)      { y0 = 0;    clipped = true; }
    if (x1 > c->w)   { x1 = c->w; clipped = true; }
    if (y1 > c->h)   { y1 = c->h; clipped = true; }
    if (clipped) {
        c->oob++;
    }
    for (int yy = y0; yy < y1; yy++) {
        uint16_t *row = &c->px[(size_t)yy * (size_t)c->w];
        for (int xx = x0; xx < x1; xx++) {
            row[xx] = colour;
        }
    }
}

void bas_rect(bas_canvas_t *c, int x, int y, int w, int h, uint16_t colour)
{
    if (w <= 0 || h <= 0) {
        return;
    }
    bas_fill(c, x, y, w, 1, colour);
    bas_fill(c, x, y + h - 1, w, 1, colour);
    bas_fill(c, x, y, 1, h, colour);
    bas_fill(c, x + w - 1, y, 1, h, colour);
}

void bas_hline(bas_canvas_t *c, int x, int y, int w, int colour)
{
    bas_fill(c, x, y, w, 1, (uint16_t)colour);
}

static void glyph(bas_canvas_t *c, int x, int y, unsigned char ch,
                  uint16_t colour, int scale)
{
    if (ch < 32u || ch > 126u) {
        ch = '?';
    }
    const uint8_t *g = bas_font5x7[ch - 32u];
    for (int col = 0; col < 5; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < 7; row++) {
            if ((bits & (1u << row)) == 0u) {
                continue;
            }
            if (scale == 1) {
                bas_px(c, x + col, y + row, colour);
            } else {
                bas_fill(c, x + col * scale, y + row * scale, scale, scale, colour);
            }
        }
    }
}

void bas_text(bas_canvas_t *c, int x, int y, const char *s,
              uint16_t colour, int scale)
{
    if (s == NULL || scale < 1) {
        return;
    }
    int cx = x;
    for (; *s != '\0'; s++) {
        glyph(c, cx, y, (unsigned char)*s, colour, scale);
        cx += 6 * scale;
    }
}

int bas_text_width(const char *s, int scale)
{
    if (s == NULL || scale < 1) {
        return 0;
    }
    size_t n = strlen(s);
    if (n == 0u) {
        return 0;
    }
    /* Six pixels of pitch per glyph, minus the trailing gap of the last one. */
    return (int)n * 6 * scale - scale;
}

int bas_text_clip(bas_canvas_t *c, int x, int y, const char *s,
                  uint16_t colour, int scale, int max_w)
{
    if (s == NULL || scale < 1 || max_w <= 0) {
        return 0;
    }
    if (bas_text_width(s, scale) <= max_w) {
        bas_text(c, x, y, s, colour, scale);
        return bas_text_width(s, scale);
    }

    /* Room for the string plus a one-glyph ellipsis. An SSID is 32 bytes and
     * the panel is 240 wide, so this path is normal, not exceptional. */
    int pitch = 6 * scale;
    int fit = (max_w + scale) / pitch;
    if (fit < 1) {
        return 0;
    }
    fit -= 1;                       /* leave a cell for the marker */
    if (fit < 1) {
        fit = 1;
    }

    int cx = x;
    for (int i = 0; i < fit && s[i] != '\0'; i++) {
        glyph(c, cx, y, (unsigned char)s[i], colour, scale);
        cx += pitch;
    }
    glyph(c, cx, y, '~', colour, scale);
    cx += pitch;
    return cx - x - scale;
}
