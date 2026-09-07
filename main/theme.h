/* Basanos — design tokens.
 *
 * Warm paper and gold. Light by default, because this is an instrument used in
 * daylight in an office, not a novelty. The palette is declared once here and
 * every screen draws from it; no screen picks a colour of its own.
 *
 * Two golds, not one. A single gold cannot be a fill behind white text AND a
 * bright mark AND small type on paper. BRASS is the deep one that stays
 * readable at caption size; SHINE is reserved for marks that carry no words.
 *
 * RGB565. The hex beside each token is the sRGB it was derived from, so the
 * palette can be checked against the same values used elsewhere.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_THEME_H
#define BASANOS_THEME_H

/* --- ground ------------------------------------------------------------- */
#define TH_PAPER    0xF79D   /* #F3F1EC  warm paper, the page              */
#define TH_CARD     0xFFFF   /* #FFFFFF  raised surface                    */
#define TH_SUNK     0xEF3B   /* #EDEAE2  recessed surface                  */

/* --- ink ---------------------------------------------------------------- */
#define TH_INK      0x18C2   /* #1A1814  body text, near-black warm        */
#define TH_INK2     0x4A27   /* #4A443A  secondary                         */
#define TH_INK3     0x7BAC   /* #7B7466  tertiary, captions                */

/* --- rules -------------------------------------------------------------- */
#define TH_RULE     0xDED9   /* #DFDACE  hairline                          */
#define TH_RULE2    0xCE57   /* #CFC8B8  stronger divider                  */

/* --- accent ------------------------------------------------------------- */
#define TH_BRASS    0x8B65   /* #8A6D2F  deep gold, readable as small text */
#define TH_SHINE    0xCD04   /* #C9A227  bright gold, marks only           */
#define TH_WASH     0xF75B   /* #F6EFDC  gold wash, selected row           */

/* --- semantic, separate from the accent --------------------------------- */
#define TH_OK       0x3B49   /* #3F6B4A  benign / caught                   */
#define TH_WARN     0xAB83   /* #A8701F  active / late                     */
#define TH_STOP     0x89C5   /* #8C3A2E  disruptive / missed               */

#define TH_OK_W     0xE75C   /* #E9EFE9                                    */
#define TH_WARN_W   0xF77B   /* #F7EEDF                                    */
#define TH_STOP_W   0xF75C   /* #F5E8E4                                    */

/* --- rhythm ------------------------------------------------------------- */
#define TH_PAD       10      /* page margin                                */
#define TH_HEAD_H    26      /* header band                                */
#define TH_FOOT_H    18      /* footer band                                */
#define TH_ROW_H     34      /* list row                                   */

#endif /* BASANOS_THEME_H */
