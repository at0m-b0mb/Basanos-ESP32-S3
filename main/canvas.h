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

/* The palette. This is the house dark theme: true black, warm paper text,
 * two golds — a deep brass that stays readable at caption size and a bright
 * shine reserved for marks that carry no words. */
#define BAS_C_BLACK   0x0000
#define BAS_C_PAPER   0xEF7D    /* warm off-white, body text                */
#define BAS_C_DIM     0x8410    /* secondary text                           */
#define BAS_C_FAINT   0x39E7    /* hairlines                                */
#define BAS_C_BRASS   0xA486    /* deep gold, readable as small text        */
#define BAS_C_SHINE   0xCD84    /* bright gold, marks only                  */
#define BAS_C_OK      0x5CCB    /* muted green                              */
#define BAS_C_WARN    0xD4A4    /* amber                                    */
#define BAS_C_STOP    0xC2A9    /* muted red                                */
#define BAS_C_SURFACE 0x1082    /* raised panel over black                  */

void bas_canvas_init(bas_canvas_t *c, uint16_t *px, int w, int h);
void bas_canvas_clear(bas_canvas_t *c, uint16_t colour);

void bas_px(bas_canvas_t *c, int x, int y, uint16_t colour);
void bas_fill(bas_canvas_t *c, int x, int y, int w, int h, uint16_t colour);
void bas_rect(bas_canvas_t *c, int x, int y, int w, int h, uint16_t colour);
void bas_hline(bas_canvas_t *c, int x, int y, int w, int colour);

/* Text. Scale 1 gives 5x7 glyphs on a 6px pitch; scale 2 doubles both. */
void bas_text(bas_canvas_t *c, int x, int y, const char *s,
              uint16_t colour, int scale);
int  bas_text_width(const char *s, int scale);

/* Draw `s` truncated with a trailing ellipsis so it fits `max_w` pixels.
 * Returns the width actually drawn. Long SSIDs are the reason this exists. */
int bas_text_clip(bas_canvas_t *c, int x, int y, const char *s,
                  uint16_t colour, int scale, int max_w);

#endif /* BASANOS_CANVAS_H */
