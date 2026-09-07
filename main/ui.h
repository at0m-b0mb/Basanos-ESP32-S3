/* Basanos — screens. SPDX-License-Identifier: MIT */
#ifndef BASANOS_UI_H
#define BASANOS_UI_H

#include "basanos/station.h"
#include "basanos/target.h"
#include "selftest.h"

/* Battery pip, drawn at the top right of every header. Shows a charging mark
 * rather than a level while the charger is attached, because a level that
 * climbs on its own reads as a fault. */
void bas_ui_battery(void *canvas, int x, int y);

void bas_ui_splash(void);
void bas_ui_selftest(const bas_selftest_t *r);
void bas_ui_scanning(uint8_t channel);

/* The target picker. `sel` is the highlighted row; the list scrolls to keep it
 * visible. Draws the security posture next to each network because that is
 * what decides whether a run against it is worth spending. */
void bas_ui_picker(const bas_scan_t *s, int sel);

void bas_ui_message(const char *title, const char *line1, const char *line2,
                    uint16_t accent);

/* Live touch check. Draws a crosshair wherever the glass is being touched and
 * prints the raw coordinates, so a wrong axis mapping is visible in one press
 * instead of being inferred from a menu that selects the wrong row. */
void bas_ui_touchtest(bool present, uint8_t chip_id,
                      bool down, uint16_t x, uint16_t y, int taps);

#endif /* BASANOS_UI_H */
