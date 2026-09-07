/* Basanos — ST7789 display glue.
 *
 * Memory model, which is the part that decides whether this works:
 *
 *   Framebuffer   240x240x2 = 112 KB, in PSRAM. Taking that out of internal
 *                 RAM boots fine and then starves Wi-Fi and the TCP stack
 *                 later, which presents as an unrelated crash.
 *
 *   DMA bands     2 x 240x30x2 = 28 KB, in internal DMA-capable RAM.
 *
 * The bands are not an optimisation, they are a correctness requirement. A
 * PSRAM source whose transfer length is not cache-line aligned is bounced
 * through an internal-RAM copy of the WHOLE transfer, so pushing the entire
 * 112 KB framebuffer in one call allocates 112 KB of internal RAM behind your
 * back and fails. Bigger buffers are worse, not better. 240x30x2 = 14400 bytes
 * is an exact multiple of 64, so each band transfers without a bounce.
 *
 * The two bands are then double-buffered: the CPU fills band N+1 while the DMA
 * is still clocking out band N, which hides most of the memcpy behind the
 * transfer.
 *
 * SPDX-License-Identifier: MIT
 */
#include "display.h"
#include "board.h"
#include "theme.h"

#include "driver/ledc.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <string.h>

static const char *TAG = "bas_disp";

/* 240 * 30 * 2 = 14400 = 225 * 64. Exact cache-line multiple: no bounce. */
#define BAND_ROWS  30
#define BAND_BYTES (BOARD_LCD_W * BAND_ROWS * 2)

static esp_lcd_panel_io_handle_t s_io;
static esp_lcd_panel_handle_t    s_panel;
static bas_canvas_t              s_canvas;
static uint16_t                 *s_fb;
static uint16_t                 *s_band[2];
static SemaphoreHandle_t         s_done;
static bool                      s_tx_pending;

#define BL_TIMER   LEDC_TIMER_0
#define BL_MODE    LEDC_LOW_SPEED_MODE
#define BL_CHANNEL LEDC_CHANNEL_0
#define BL_RES     LEDC_TIMER_10_BIT
#define BL_FREQ    5000

static bool on_trans_done(esp_lcd_panel_io_handle_t io,
                          esp_lcd_panel_io_event_data_t *ev, void *ctx)
{
    BaseType_t hp = pdFALSE;
    xSemaphoreGiveFromISR(s_done, &hp);
    return hp == pdTRUE;
}

void bas_display_backlight(uint8_t percent)
{
    if (percent > 100u) {
        percent = 100u;
    }
    ledc_set_duty(BL_MODE, BL_CHANNEL, (1023u * percent) / 100u);
    ledc_update_duty(BL_MODE, BL_CHANNEL);
}

static void backlight_init(void)
{
    ledc_timer_config_t t = {
        .speed_mode      = BL_MODE,
        .timer_num       = BL_TIMER,
        .duty_resolution = BL_RES,
        .freq_hz         = BL_FREQ,
        .clk_cfg         = LEDC_AUTO_CLK,
    };
    ESP_ERROR_CHECK(ledc_timer_config(&t));

    ledc_channel_config_t ch = {
        .speed_mode = BL_MODE,
        .channel    = BL_CHANNEL,
        .timer_sel  = BL_TIMER,
        .intr_type  = LEDC_INTR_DISABLE,
        .gpio_num   = BOARD_LCD_BL,
        .duty       = 0,
        .hpoint     = 0,
    };
    ESP_ERROR_CHECK(ledc_channel_config(&ch));
}

esp_err_t bas_display_init(void)
{
    s_done = xSemaphoreCreateBinary();
    if (s_done == NULL) {
        return ESP_ERR_NO_MEM;
    }

    spi_bus_config_t bus = {
        .sclk_io_num   = BOARD_LCD_SCLK,
        .mosi_io_num   = BOARD_LCD_MOSI,
        .miso_io_num   = BOARD_LCD_MISO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        /* Sized to one band, not one frame. The SPI driver allocates DMA
         * descriptors from this, so asking for a full frame here would reserve
         * internal RAM for a transfer that never happens. */
        .max_transfer_sz = BAND_BYTES,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(BOARD_LCD_HOST, &bus, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_spi_config_t io = {
        .cs_gpio_num         = BOARD_LCD_CS,
        .dc_gpio_num         = BOARD_LCD_DC,
        .spi_mode            = BOARD_LCD_SPI_MODE,
        .pclk_hz             = BOARD_LCD_PCLK_HZ,
        .trans_queue_depth   = 4,
        .lcd_cmd_bits        = 8,
        .lcd_param_bits      = 8,
        .on_color_trans_done = on_trans_done,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi(
        (esp_lcd_spi_bus_handle_t)BOARD_LCD_HOST, &io, &s_io));

    esp_lcd_panel_dev_config_t pc = {
        .reset_gpio_num = BOARD_LCD_RST,
        .rgb_ele_order  = LCD_RGB_ELEMENT_ORDER_RGB,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(s_io, &pc, &s_panel));

    ESP_ERROR_CHECK(esp_lcd_panel_reset(s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_init(s_panel));
    /* Both are panel facts from the vendor bring-up, not preferences. */
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(s_panel, BOARD_LCD_INVERT));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(s_panel, true));

    s_fb = heap_caps_malloc(BOARD_LCD_W * BOARD_LCD_H * 2, MALLOC_CAP_SPIRAM);
    if (s_fb == NULL) {
        ESP_LOGE(TAG, "framebuffer: no PSRAM (is SPIRAM_MODE_OCT set?)");
        return ESP_ERR_NO_MEM;
    }

    for (int i = 0; i < 2; i++) {
        s_band[i] = heap_caps_malloc(BAND_BYTES, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
        if (s_band[i] == NULL) {
            ESP_LOGE(TAG, "band buffer %d: out of internal DMA RAM", i);
            return ESP_ERR_NO_MEM;
        }
    }

    bas_canvas_init(&s_canvas, s_fb, BOARD_LCD_W, BOARD_LCD_H);
    bas_canvas_clear(&s_canvas, TH_PAPER);

    backlight_init();

    ESP_LOGI(TAG, "ST7789 %dx%d up", BOARD_LCD_W, BOARD_LCD_H);
    ESP_LOGI(TAG, "fb %d KB psram, bands 2 x %d B internal",
             (BOARD_LCD_W * BOARD_LCD_H * 2) / 1024, BAND_BYTES);
    ESP_LOGI(TAG, "heap: %u internal, %u psram",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    return ESP_OK;
}

bas_canvas_t *bas_display_canvas(void)
{
    return &s_canvas;
}

/* Wait for an outstanding transfer, if there is one. Keeping this separate
 * means the caller can fill the next band before blocking. */
static esp_err_t wait_tx(void)
{
    if (!s_tx_pending) {
        return ESP_OK;
    }
    s_tx_pending = false;
    if (xSemaphoreTake(s_done, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "flush timeout");
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

esp_err_t bas_display_flush_rows(int y0, int rows)
{
    if (s_panel == NULL || s_fb == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (y0 < 0) {
        rows += y0;
        y0 = 0;
    }
    if (y0 >= BOARD_LCD_H || rows <= 0) {
        return ESP_OK;
    }
    if (y0 + rows > BOARD_LCD_H) {
        rows = BOARD_LCD_H - y0;
    }

    int buf = 0;
    for (int y = y0; y < y0 + rows; y += BAND_ROWS) {
        int n = BAND_ROWS;
        if (y + n > y0 + rows) {
            n = y0 + rows - y;
        }

        /* Fill this band while the previous one is still going out. */
        memcpy(s_band[buf], &s_fb[(size_t)y * BOARD_LCD_W],
               (size_t)n * BOARD_LCD_W * 2);

        esp_err_t rc = wait_tx();
        if (rc != ESP_OK) {
            return rc;
        }

        rc = esp_lcd_panel_draw_bitmap(s_panel, 0, y, BOARD_LCD_W, y + n,
                                       s_band[buf]);
        if (rc != ESP_OK) {
            ESP_LOGE(TAG, "draw_bitmap rows %d..%d: %s", y, y + n,
                     esp_err_to_name(rc));
            return rc;
        }
        s_tx_pending = true;
        buf ^= 1;
    }

    return wait_tx();
}

esp_err_t bas_display_flush(void)
{
    return bas_display_flush_rows(0, BOARD_LCD_H);
}
