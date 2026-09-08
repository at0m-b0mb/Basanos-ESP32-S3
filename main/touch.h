/* Basanos — CST816 capacitive touch.
 *
 * Written directly against the controller's register map rather than pulling
 * in a driver component, so the firmware carries no third-party dependency.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_TOUCH_H
#define BASANOS_TOUCH_H

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    BAS_GESTURE_NONE   = 0x00,
    BAS_GESTURE_UP     = 0x01,
    BAS_GESTURE_DOWN   = 0x02,
    BAS_GESTURE_LEFT   = 0x03,
    BAS_GESTURE_RIGHT  = 0x04,
    BAS_GESTURE_TAP    = 0x05,
    BAS_GESTURE_DOUBLE = 0x0B,
    BAS_GESTURE_LONG   = 0x0C,
} bas_gesture_t;

const char *bas_gesture_name(bas_gesture_t g);

/* True once per double tap reported by the controller, then cleared. This is
 * the way back from a screen whose hold gesture has taken the only button. */
bool bas_touch_double(void);

typedef struct {
    bool          down;
    uint16_t      x;
    uint16_t      y;
    bas_gesture_t gesture;
} bas_touch_t;

/* Brings up the shared I2C bus and resets the controller. Returns
 * ESP_ERR_NOT_FOUND when nothing answers at the touch address — the non-touch
 * variant of this board is otherwise identical, so that is a normal outcome
 * and the caller should fall back to buttons rather than fail. */
esp_err_t bas_touch_init(void);

bool bas_touch_present(void);

/* Current state. Returns false when there is nothing new to report. */
bool bas_touch_read(bas_touch_t *out);

/* Edge-detected tap: true once per finger-down, with the coordinates of that
 * press. This is what a menu wants — a raw "is a finger on the glass" reading
 * fires sixty times a second and scrolls a list off the end. */
bool bas_touch_tapped(uint16_t *x, uint16_t *y);

/* A completed swipe, consumed on read. */
bas_gesture_t bas_touch_swipe(void);

/* The controller's chip id, for the bring-up log. */
uint8_t bas_touch_chip_id(void);

#endif /* BASANOS_TOUCH_H */
