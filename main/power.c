/* Basanos — battery power latch and fuel gauge. SPDX-License-Identifier: MIT */
#include "power.h"
#include "board.h"

#include "driver/gpio.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_log.h"

static const char *TAG = "bas_power";

static adc_oneshot_unit_handle_t s_adc;
static adc_cali_handle_t         s_cali;
static bool                      s_calibrated;
static bool                      s_latched;

void bas_power_latch(void)
{
    /* Deliberately minimal: a plain output and a high level, with no error
     * checking that could abort and no logging that needs a console. Anything
     * that can fail or block belongs after the rail is holding itself up. */
    gpio_config_t io = {
        .intr_type    = GPIO_INTR_DISABLE,
        .mode         = GPIO_MODE_OUTPUT,
        .pin_bit_mask = 1ULL << BOARD_BAT_EN,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
    };
    gpio_config(&io);
    gpio_set_level(BOARD_BAT_EN, 1);
    s_latched = true;
}

void bas_power_init(void)
{
    gpio_config_t io = {
        .intr_type    = GPIO_INTR_DISABLE,
        .mode         = GPIO_MODE_INPUT,
        .pin_bit_mask = 1ULL << BOARD_CHG_STAT,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&io);

    adc_oneshot_unit_init_cfg_t unit = {
        .unit_id  = ADC_UNIT_1,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    if (adc_oneshot_new_unit(&unit, &s_adc) != ESP_OK) {
        ESP_LOGW(TAG, "no ADC unit — battery reading unavailable");
        s_adc = NULL;
        return;
    }

    adc_oneshot_chan_cfg_t ch = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten    = ADC_ATTEN_DB_12,
    };
    /* GPIO 1 is ADC1 channel 0. */
    if (adc_oneshot_config_channel(s_adc, ADC_CHANNEL_0, &ch) != ESP_OK) {
        ESP_LOGW(TAG, "ADC channel config failed");
        return;
    }

    adc_cali_curve_fitting_config_t cal = {
        .unit_id  = ADC_UNIT_1,
        .chan     = ADC_CHANNEL_0,
        .atten    = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    s_calibrated = (adc_cali_create_scheme_curve_fitting(&cal, &s_cali) == ESP_OK);

    ESP_LOGI(TAG, "latched=%d calibrated=%d %umV (%u%%)%s",
             (int)s_latched, (int)s_calibrated,
             (unsigned)bas_power_mv(), (unsigned)bas_power_level(),
             bas_power_charging() ? " charging" : "");
}

uint16_t bas_power_mv(void)
{
    if (s_adc == NULL || !s_calibrated) {
        return 0u;
    }
    int raw = 0;
    if (adc_oneshot_read(s_adc, ADC_CHANNEL_0, &raw) != ESP_OK) {
        return 0u;
    }
    int mv = 0;
    if (adc_cali_raw_to_voltage(s_cali, raw, &mv) != ESP_OK) {
        return 0u;
    }
    /* 1:3 divider. Without this a full cell reads about 1.4 V. */
    return (uint16_t)(mv * 3);
}

uint8_t bas_power_level(void)
{
    uint16_t mv = bas_power_mv();
    if (mv == 0u)    { return 0u; }
    if (mv < 3520u)  { return 1u; }
    if (mv < 3640u)  { return 20u; }
    if (mv < 3760u)  { return 40u; }
    if (mv < 3880u)  { return 60u; }
    if (mv < 4000u)  { return 80u; }
    return 100u;
}

bool bas_power_charging(void)
{
    /* Active low, and a full cell stops charging without the line changing. */
    if (bas_power_level() >= 100u) {
        return false;
    }
    return gpio_get_level(BOARD_CHG_STAT) == 0;
}

bool bas_power_on_usb(void)
{
    /* The charge line being asserted means a supply is attached. Not exact —
     * a full battery on USB reads false — but it is the only signal this board
     * gives, and it is only used to explain why a shutdown did nothing. */
    return gpio_get_level(BOARD_CHG_STAT) == 0;
}

void bas_power_off(void)
{
    ESP_LOGI(TAG, "dropping the power latch");
    gpio_set_level(BOARD_BAT_EN, 0);
    s_latched = false;
}
