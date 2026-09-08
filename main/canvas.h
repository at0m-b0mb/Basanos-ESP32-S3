/* Basanos — RGB565 canvas.
 *
 * Pure drawing over a caller-owned framebuffer. No ESP-IDF, so the layout can
 * be reasoned about (and eventually tested) without a board.
 *
 * Every primitive clips. An out-of-bounds draw increments `oob` instead of
 * writing outside the buffer, so a layout bug shows up as a counter rather
 * than as memory corruption two frames later.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_CANVAS_H
#define BASANOS_CANVAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t *px;
    int       w;
    int       h;
    uint32_t  oob;      /* clipped writes — must stay 0 in a correct layout */
} bas_canvas_t;

/* Colours live in theme.h. The canvas knows nothing about them. */

void bas_canvas_init(bas_canvas_t *c, uint16_t *px, int w, int h);
void bas_canvas_clear(bas_canvas_t *c, uint16_t colour);

void bas_px(bas_canvas_t *c, int x, int y, uint16_t colour);
void bas_fill(bas_canvas_t *c, int x, int y, int w, int h, uint16_t colour);
void bas_rect(bas_canvas_t *c, int x, int y, int w, int h, uint16_t colour);
void bas_hline(bas_canvas_t *c, int x, int y, int w, int colour);

/* Text. Scale 1 gives 5x7 glyphs on a 6px pitch; scale 2 doubles both. */
void bas_text(bas_canvas_t *c, int x, int y, const char *s,
              uint16_t colour, int scale);

/* The same, emboldened by overprinting one pixel to the right. A second font
 * table would cost 1.5 KB of glyph data to do what a one-pixel smear does
 * convincingly at these sizes, and headings are the only place it is used. */
void bas_text_b(bas_canvas_t *c, int x, int y, const char *s,
                uint16_t colour, int scale);
int  bas_text_width(const char *s, int scale);

/* --- serif display face ---------------------------------------------------

   Proportional, 17 px, for titles, the wordmark and figures. Never for list
   rows: it is roughly twice the width of the 5x7 per character, and density is
   what a list needs.
   ------------------------------------------------------------------------- */

void bas_serif_text(bas_canvas_t *c, int x, int y, const char *s,
                    uint16_t colour, int scale);
int  bas_serif_width(const char *s, int scale);
int  bas_serif_height(int scale);

/* Draw `s` truncated with a trailing ellipsis so it fits `max_w` pixels.
 * Returns the width actually drawn. Long SSIDs are the reason this exists. */
int bas_text_clip(bas_canvas_t *c, int x, int y, const char *s,
                  uint16_t colour, int scale, int max_w);

#endif /* BASANOS_CANVAS_H */
