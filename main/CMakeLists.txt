idf_component_register(
    SRCS "basanos_main.c" "display.c" "canvas.c" "font5x7.c" "selftest.c" "ui.c" "touch.c" "frames.c" "transmit.c" "ui_attack.c" "power.c"
    INCLUDE_DIRS "."
    REQUIRES engine rbac score esp_lcd driver esp_driver_i2c esp_wifi nvs_flash esp_timer esp_hw_support esp_adc)
