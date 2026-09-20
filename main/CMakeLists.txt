idf_component_register(
    SRCS "basanos_main.c" "display.c" "canvas.c" "font5x7.c" "font_serif.c" "selftest.c" "ui.c" "touch.c" "frames.c" "transmit.c" "power.c" "console.c" "sniffer.c" "ble.c" "rawtx.c" "sdlog.c" "uartalarm.c" "wpsatk.c" "sniffer.c"
    INCLUDE_DIRS "."
    REQUIRES engine rbac score wpa_supplicant esp_lcd driver esp_driver_i2c esp_wifi nvs_flash esp_timer fatfs sdmmc esp_driver_sdmmc esp_driver_uart esp_hw_support esp_adc esp_driver_usb_serial_jtag vfs bt)

# Raw 802.11 injection. The Wi-Fi library sanity-checks frames handed to
# esp_wifi_80211_tx and refuses deauth, disassoc and auth outright.
#
# Its symbol is strong, so overriding it needs the link to accept two
# definitions and take ours. --wrap was tried and does not work here: the
# library both defines and calls the function within one object file, so the
# call never crosses a boundary the linker can rewrite. See main/rawtx.c.
target_link_libraries(${COMPONENT_LIB} INTERFACE
                      "-Wl,--allow-multiple-definition")

# The WPS state machine's internals.
#
# main/wpsatk.c needs the real struct wps_data and struct wps_sm to harvest the
# Pixie Dust material. These are private headers with no public equivalent.
#
# They are INCLUDED rather than mirrored by hand. A hand-written copy of a
# struct layout is wrong the moment the SDK reorders a field, and it fails
# silently: the first version of this file omitted three leading members and
# read every field 12 bytes out, which built a wild pointer from hash bytes.
# Letting the compiler read the real declaration makes that impossible.
target_include_directories(${COMPONENT_LIB} PRIVATE
    "$ENV{IDF_PATH}/components/wpa_supplicant/src"
    "$ENV{IDF_PATH}/components/wpa_supplicant/esp_supplicant/src")
