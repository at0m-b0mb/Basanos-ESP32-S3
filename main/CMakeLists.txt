idf_component_register(
    SRCS "basanos_main.c" "display.c" "canvas.c" "font5x7.c" "selftest.c" "ui.c" "touch.c"
    INCLUDE_DIRS "."
    REQUIRES engine rbac score esp_lcd driver esp_driver_i2c esp_wifi nvs_flash esp_timer)
