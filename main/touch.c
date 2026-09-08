/* Basanos — CST816 capacitive touch. SPDX-License-Identifier: MIT */
#include "touch.h"
#include "board.h"

#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

static const char *TAG = "bas_touch";

/* CST816 registers. */
#define REG_GESTURE     0x01
#define REG_FINGER_NUM  0x02
#define REG_XPOS_H      0x03
#define REG_CHIP_ID     0xA7
#define REG_DIS_AUTOSLP 0xFE

static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;
static bool     s_present;
static uint8_t  s_chip_id;
/* Edge state for bas_touch_tapped(), advanced by EVERY read.
 *
 * It has to be every read, not only the ones made through bas_touch_tapped():
 * the arming hold polls the panel through bas_touch_read(), and if that left
 * this state stale then the first tap check afterwards would see a finger
 * already resting on the glass as a fresh press. That phantom tap aborted the
 * countdown the instant it started, every time a run was armed by touch. */
static bool     s_prev_down;
static bool     s_last_down;
static bas_gesture_t s_pending_swipe;

const char *bas_gesture_name(bas_gesture_t g)
{
    switch (g) {
    case BAS_GESTURE_NONE:   return "none";
    case BAS_GESTURE_UP:     return "up";
    case BAS_GESTURE_DOWN:   return "down";
    case BAS_GESTURE_LEFT:   return "left";
    case BAS_GESTURE_RIGHT:  return "right";
    case BAS_GESTURE_TAP:    return "tap";
    case BAS_GESTURE_DOUBLE: return "double";
    case BAS_GESTURE_LONG:   return "long";
    default:                 return "?";
    }
}

static esp_err_t rd(uint8_t reg, uint8_t *buf, size_t n)
{
    if (s_dev == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    return i2c_master_transmit_receive(s_dev, &reg, 1, buf, n,
                                       pdMS_TO_TICKS(50));
}

static esp_err_t wr(uint8_t reg, uint8_t val)
{
    uint8_t b[2] = { reg, val };
    if (s_dev == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    return i2c_master_transmit(s_dev, b, sizeof(b), pdMS_TO_TICKS(50));
}

esp_err_t bas_touch_init(void)
{
    /* The touch controller, the IMU and both audio codecs share this bus, so
     * it is created once here and the other drivers attach to it later. */
    i2c_master_bus_config_t bc = {
        .clk_source                   = I2C_CLK_SRC_DEFAULT,
        .i2c_port                     = BOARD_I2C_PORT,
        .scl_io_num                   = BOARD_I2C_SCL,
        .sda_io_num                   = BOARD_I2C_SDA,
        .glitch_ignore_cnt            = 7,
        .flags.enable_internal_pullup = true,
    };
    esp_err_t rc = i2c_new_master_bus(&bc, &s_bus);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "i2c bus: %s", esp_err_to_name(rc));
        return rc;
    }

    /* Reset. The controller ignores I2C until this has been done and it has
     * had time to come up; skipping the settle is the usual reason a CST816
     * "does not respond". */
    gpio_config_t g = {
        .pin_bit_mask = (1ULL << BOARD_TP_RST),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&g));
    gpio_set_level(BOARD_TP_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(BOARD_TP_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(80));

    /* INT is an input; the controller pulls it low when it has a report. */
    gpio_config_t gi = {
        .pin_bit_mask = (1ULL << BOARD_TP_INT),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&gi));

    i2c_device_config_t dc = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = BOARD_TP_ADDR,
        .scl_speed_hz    = 400 * 1000,
    };
    rc = i2c_master_bus_add_device(s_bus, &dc, &s_dev);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "add device: %s", esp_err_to_name(rc));
        return rc;
    }

    if (i2c_master_probe(s_bus, BOARD_TP_ADDR, pdMS_TO_TICKS(100)) != ESP_OK) {
        /* The non-touch variant of this board is otherwise identical, so this
         * is a normal outcome rather than a failure. The caller falls back to
         * the buttons. */
        ESP_LOGW(TAG, "no touch controller at 0x%02X — buttons only",
                 BOARD_TP_ADDR);
        return ESP_ERR_NOT_FOUND;
    }

    if (rd(REG_CHIP_ID, &s_chip_id, 1) != ESP_OK) {
        ESP_LOGW(TAG, "chip id read failed");
        return ESP_ERR_NOT_FOUND;
    }

    /* Without this the controller sleeps after a few idle seconds and stops
     * answering, which looks exactly like a dead touchscreen. */
    (void)wr(REG_DIS_AUTOSLP, 0x01);

    s_present = true;
    ESP_LOGI(TAG, "CST816 up, chip id 0x%02X", s_chip_id);
    return ESP_OK;
}

bool bas_touch_present(void) { return s_present; }
uint8_t bas_touch_chip_id(void) { return s_chip_id; }

bool bas_touch_read(bas_touch_t *out)
{
    if (!s_present || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    /* Six bytes from 0x01: gesture, finger count, then X and Y as 12-bit
     * big-endian values with the high nibble in the low bits of the first
     * byte. The top two bits of XPOS_H are an event code, not coordinate. */
    uint8_t b[6];
    if (rd(REG_GESTURE, b, sizeof(b)) != ESP_OK) {
        return false;
    }

    out->gesture = (bas_gesture_t)b[0];
    out->down    = (b[1] & 0x0Fu) > 0u;
    out->x = (uint16_t)(((uint16_t)(b[2] & 0x0Fu) << 8) | b[3]);
    out->y = (uint16_t)(((uint16_t)(b[4] & 0x0Fu) << 8) | b[5]);

    /* A coordinate outside the panel is a misread, not a touch at the edge. */
    if (out->x >= BOARD_LCD_W || out->y >= BOARD_LCD_H) {
        out->down = false;
    }

    if (out->gesture >= BAS_GESTURE_UP && out->gesture <= BAS_GESTURE_RIGHT) {
        s_pending_swipe = out->gesture;
    }

    s_prev_down = s_last_down;
    s_last_down = out->down;
    return true;
}

bool bas_touch_tapped(uint16_t *x, uint16_t *y)
{
    bas_touch_t t;
    if (!bas_touch_read(&t)) {
        return false;
    }

    /* Edge, not level. A level read fires every poll for as long as the finger
     * rests on the glass, which scrolls a list straight off the end.
     *
     * The read above already advanced the edge state, so a finger that was
     * down before this call is not a new press. */
    bool edge = t.down && !s_prev_down;

    if (edge) {
        if (x != NULL) { *x = t.x; }
        if (y != NULL) { *y = t.y; }
    }
    return edge;
}

bas_gesture_t bas_touch_swipe(void)
{
    bas_gesture_t g = s_pending_swipe;
    s_pending_swipe = BAS_GESTURE_NONE;
    return g;
}
