/* Basanos — ST7789 display glue.
 * SPDX-License-Identifier: MIT */
#ifndef BASANOS_DISPLAY_H
#define BASANOS_DISPLAY_H

#include "canvas.h"
#include "esp_err.h"

/* Brings up SPI2, the panel and the backlight PWM, and allocates the
 * framebuffer. The buffer lives in PSRAM: 240x240x2 is 112 KB, and taking that
 * out of internal RAM starves Wi-Fi later in a way that looks like an
 * unrelated crash. */
esp_err_t bas_display_init(void);

/* The canvas backed by that framebuffer. Draw into it, then flush. */
bas_canvas_t *bas_display_canvas(void);

/* Push the whole framebuffer to the panel and wait for the transfer to finish.
 * The wait is not optional: esp_lcd_panel_draw_bitmap is asynchronous, and
 * redrawing into the buffer while it is still being clocked out paints one
 * frame's pixels at another frame's coordinates.
 *
 * Goes out in 30-row bands through internal DMA buffers. That is a correctness
 * requirement rather than tuning — see the note at the top of display.c. */
esp_err_t bas_display_flush(void);

/* Flush only part of the frame. A list that scrolls one row does not need to
 * repaint 112 KB, and on a 40 MHz SPI bus that is the difference between a
 * responsive picker and a visibly slow one. */
esp_err_t bas_display_flush_rows(int y0, int rows);

/* 0..100. */
void bas_display_backlight(uint8_t percent);

#endif /* BASANOS_DISPLAY_H */
