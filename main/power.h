/* Basanos — battery power latch, fuel gauge and shutdown.
 *
 * THE IMPORTANT ONE: on battery, the PWR button only supplies power while it
 * is physically held. The rail is held up afterwards by firmware asserting the
 * latch on GPIO 2. Until that happens the board dies the moment the button is
 * released — which looks like "it turns on and immediately turns off, but
 * works fine with the cable in", because USB holds the rail up by itself and
 * hides the bug completely.
 *
 * bas_power_latch() must therefore be the FIRST thing app_main does, before
 * the display, before NVS, before anything that can block or fail.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_POWER_H
#define BASANOS_POWER_H

#include <stdbool.h>
#include <stdint.h>

/* Hold the battery rail up. Call first, unconditionally. */
void bas_power_latch(void);

/* Fuel gauge and charge detect. Safe to call after the latch. */
void bas_power_init(void);

/* Battery voltage in millivolts. 0 when the gauge is unavailable.
 *
 * The divider on this board is 1:3, so the pin sees a third of the cell — a
 * reading taken without that factor looks like a flat battery on a full one. */
uint16_t bas_power_mv(void);

/* 0..100, from the cell voltage. Coarse by nature: a lithium cell's voltage
 * is nearly flat across the middle of its charge, so this reports bands rather
 * than pretending to a precision it does not have. */
uint8_t bas_power_level(void);

bool bas_power_charging(void);
bool bas_power_on_usb(void);

/* Drop the latch. On battery the board switches off; on USB it will not, and
 * the caller should say so rather than appearing to do nothing. */
void bas_power_off(void);

#endif /* BASANOS_POWER_H */
