/* Basanos — design tokens.
 *
 * White and gold. Cool neutrals, pure white ground, one gold accent used
 * sparingly. Light by default: this is an instrument read in daylight in an
 * office, not a novelty.
 *
 * Two golds, not one. A single gold cannot be a fill behind pale text AND a
 * bright mark AND small type on white. BRASS is the deep one that stays
 * readable at caption size; SHINE is reserved for marks that carry no words.
 * Semantic colours are a separate set and are never used as the accent.
 *
 * --- BYTE ORDER, and why every value below goes through TH_C() -------------
 *
 * The ESP32 is little-endian, so a uint16_t 0xF79D sits in memory as 9D F7.
 * esp_lcd clocks those bytes out in address order and the ST7789 reads the
 * first byte as the high half, so the panel receives 0x9DF7 -- a completely
 * different colour. Warm paper arrives as blue-teal and near-black arrives as
 * purple.
 *
 * TH_C() swaps the halves at compile time, so the constants below stay
 * readable as ordinary RGB565 while the framebuffer holds what the panel
 * actually wants. Zero runtime cost, and no per-pixel conversion in the draw
 * path. The sRGB each value came from is in the comment beside it.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_THEME_H
#define BASANOS_THEME_H

#include <stdint.h>

#define TH_C(v) ((uint16_t)((((uint16_t)(v) & 0x00FFu) << 8) | \
                            (((uint16_t)(v) & 0xFF00u) >> 8)))

/* --- ground ------------------------------------------------------------- */
#define TH_PAPER    TH_C(0xFFFF)   /* #FFFFFF  the page                     */
#define TH_CARD     TH_C(0xFFFF)   /* #FFFFFF  raised surface, ruled edge   */
#define TH_SUNK     TH_C(0xF7BE)   /* #F4F5F7  recessed band, cool grey     */

/* --- ink ---------------------------------------------------------------- */
#define TH_INK      TH_C(0x10A3)   /* #101418  body, cool near-black        */
#define TH_INK2     TH_C(0x3A29)   /* #3D444D  secondary                    */
#define TH_INK3     TH_C(0x73F1)   /* #767E88  captions                     */

/* --- rules -------------------------------------------------------------- */
#define TH_RULE     TH_C(0xE73D)   /* #E3E6EA  hairline                     */
#define TH_RULE2    TH_C(0xCE7A)   /* #C9CED6  divider                      */

/* --- accent ------------------------------------------------------------- */
#define TH_BRASS    TH_C(0x9BC3)   /* #9A7B1F  deep gold, readable small    */
#define TH_SHINE    TH_C(0xD566)   /* #D4AF37  bright gold, marks only      */
#define TH_WASH     TH_C(0xFFBC)   /* #FBF6E6  pale gold, selected row      */

/* --- semantic, separate from the accent --------------------------------- */
#define TH_OK       TH_C(0x2B49)   /* #2F6B4F                               */
#define TH_WARN     TH_C(0xABA3)   /* #A9761B                               */
#define TH_STOP     TH_C(0xA165)   /* #A32E2E                               */

/* --- rhythm ------------------------------------------------------------- */
#define TH_PAD       10
#define TH_HEAD_H    26
#define TH_FOOT_H    18
#define TH_ROW_H     34

#endif /* BASANOS_THEME_H */
