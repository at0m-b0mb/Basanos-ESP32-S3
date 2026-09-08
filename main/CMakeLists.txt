idf_component_register(
    SRCS "basanos_main.c" "display.c" "canvas.c" "font5x7.c" "font_serif.c" "selftest.c" "ui.c" "touch.c" "frames.c" "transmit.c" "power.c" "console.c" "sniffer.c" "sniffer.c"
    INCLUDE_DIRS "."
    REQUIRES engine rbac score esp_lcd driver esp_driver_i2c esp_wifi nvs_flash esp_timer esp_hw_support esp_adc esp_driver_usb_serial_jtag vfs)
