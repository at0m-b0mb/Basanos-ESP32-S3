/* Basanos — the detector's own voice, over the UART pads.
 * SPDX-License-Identifier: MIT */
#include "uartalarm.h"
#include "board.h"

#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <string.h>

static const char *TAG = "bas_uart";

#define UART_PORT   UART_NUM_1
#define RX_BUF      1024
#define BAS_LINE_MAX 192
#define ALARM_Q     8

static QueueHandle_t s_q;
static TaskHandle_t  s_task;
static bool          s_active;
static uint32_t      s_lines, s_parsed;
static char          s_last[BAS_LINE_MAX];

uint32_t bas_uart_alarm_lines(void)  { return s_lines; }
uint32_t bas_uart_alarm_parsed(void) { return s_parsed; }
const char *bas_uart_alarm_last(void) { return s_last; }
bool bas_uart_alarm_active(void) { return s_active; }

static void reader(void *arg)
{
    char line[BAS_LINE_MAX];
    size_t len = 0;

    while (s_active) {
        uint8_t ch;
        int n = uart_read_bytes(UART_PORT, &ch, 1, pdMS_TO_TICKS(200));
        if (n != 1) {
            continue;
        }

        if (ch == '\n' || ch == '\r') {
            if (len == 0u) {
                continue;
            }
            line[len] = '\0';
            len = 0;

            s_lines++;
            /* Kept whether or not it parses: a detector talking in the wrong
             * format looks identical to silence unless its actual output can
             * be seen. */
            strncpy(s_last, line, sizeof(s_last) - 1u);
            s_last[sizeof(s_last) - 1u] = '\0';

            bas_alarm_t a;
            if (bas_alarm_parse(line, BAS_SRC_SERIAL, &a)) {
                s_parsed++;
                /* Drop rather than block. The reader must keep draining the
                 * port; a detector that alarms faster than runs are scored is
                 * reporting the same event repeatedly, and the first one is
                 * the measurement anyway. */
                (void)xQueueSend(s_q, &a, 0);
            }
            continue;
        }

        if (len + 1u < sizeof(line)) {
            line[len++] = (char)ch;
        } else {
            /* Overlong: drop it rather than parse a truncated line that might
             * mean something different from what was sent. */
            len = 0;
        }
    }
    vTaskDelete(NULL);
}

/* End-to-end self-test using the UART's internal loopback.
 *
 * Wires TX back to RX inside the peripheral, sends a well-formed alarm line,
 * and waits for it to come back out of the parser. That exercises the whole
 * path -- transmit, line assembly, parse, queue -- without a second device or
 * a jumper across the pads, so "the listener works" is a checked claim rather
 * than an assumption about wiring that has never been tried. */
bool bas_uart_alarm_selftest(void)
{
    if (!s_active) {
        return false;
    }

    uint32_t before = s_parsed;
    uart_set_loop_back(UART_PORT, true);

    static const char probe[] =
        "BASANOS-ALARM detector=loopback conf=1 fam=0x01\n";
    uart_write_bytes(UART_PORT, probe, sizeof(probe) - 1u);

    /* The reader task has to be scheduled, read the bytes and parse them. */
    bool ok = false;
    for (int i = 0; i < 50 && !ok; i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
        ok = (s_parsed > before);
    }

    uart_set_loop_back(UART_PORT, false);

    /* Drop the probe so a synthetic alarm can never be credited to a real
     * run -- the point was to test the path, not to score anything. */
    bas_alarm_t discard;
    while (bas_uart_alarm_take(&discard)) { }

    ESP_LOGI(TAG, "loopback self-test: %s", ok ? "passed" : "FAILED");
    return ok;
}

esp_err_t bas_uart_alarm_start(int baud)
{
    if (s_active) {
        return ESP_OK;
    }
    if (baud <= 0) {
        baud = BAS_UART_ALARM_BAUD;
    }

    if (s_q == NULL) {
        s_q = xQueueCreate(ALARM_Q, sizeof(bas_alarm_t));
        if (s_q == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    uart_config_t cfg = {
        .baud_rate = baud,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t rc = uart_driver_install(UART_PORT, RX_BUF, 0, 0, NULL, 0);
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "driver: %s", esp_err_to_name(rc));
        return rc;
    }
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &cfg));
    /* TX is wired as well as RX so a detector can be given a marker later,
     * but nothing is transmitted here today. */
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, BOARD_UART_TX, BOARD_UART_RX,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    s_active = true;
    s_lines = s_parsed = 0;
    s_last[0] = '\0';

    if (xTaskCreate(reader, "bas_uart", 3072, NULL, 5, &s_task) != pdPASS) {
        s_active = false;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "listening for alarms on GPIO %d at %d baud",
             (int)BOARD_UART_RX, baud);
    return ESP_OK;
}

void bas_uart_alarm_stop(void)
{
    s_active = false;
    s_task = NULL;
}

bool bas_uart_alarm_take(bas_alarm_t *out)
{
    if (s_q == NULL || out == NULL) {
        return false;
    }
    return xQueueReceive(s_q, out, 0) == pdTRUE;
}
