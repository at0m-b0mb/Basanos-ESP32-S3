/* Basanos — board pinout for the Waveshare ESP32-S3-Touch-LCD-1.54.
 *
 * Verified against the vendor BSP source and the official pinout table. The
 * product wiki is a placeholder, so this file is the reference.
 *
 * Not one GPIO is free. GPIO 6 is the IMU interrupt; everything else is
 * display, storage, audio, buttons, power, PSRAM or flash. The only external
 * connections are the I2C, UART and USB pads.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_BOARD_H
#define BASANOS_BOARD_H

#include "driver/gpio.h"
#include "driver/spi_master.h"

/* --- display: ST7789, 240x240, 4-wire SPI on SPI2 ------------------------ */
#define BOARD_LCD_HOST      SPI2_HOST
#define BOARD_LCD_SCLK      GPIO_NUM_38
#define BOARD_LCD_MOSI      GPIO_NUM_39
#define BOARD_LCD_MISO      GPIO_NUM_NC   /* display only, no read-back      */
#define BOARD_LCD_CS        GPIO_NUM_21
#define BOARD_LCD_DC        GPIO_NUM_45
#define BOARD_LCD_RST       GPIO_NUM_40
#define BOARD_LCD_BL        GPIO_NUM_46

#define BOARD_LCD_W         240
#define BOARD_LCD_H         240

/* The vendor drives this panel in SPI mode 3 with the colour inverted. Both
 * are panel facts, not preferences — getting either wrong gives a display that
 * lights up and shows nonsense. */
#define BOARD_LCD_SPI_MODE  3
#define BOARD_LCD_INVERT    true
#define BOARD_LCD_PCLK_HZ   (40 * 1000 * 1000)

/* --- touch: CST816, on the shared I2C bus -------------------------------- */
#define BOARD_TP_RST        GPIO_NUM_47
#define BOARD_TP_INT        GPIO_NUM_48
#define BOARD_TP_ADDR       0x15

/* --- I2C: touch, IMU and both audio codecs share this bus ---------------- */
#define BOARD_I2C_PORT      0
#define BOARD_I2C_SCL       GPIO_NUM_41
#define BOARD_I2C_SDA       GPIO_NUM_42

/* --- buttons ------------------------------------------------------------- */
/* Three buttons, left to right across the bottom of the case. GPIO 0 is the
 * left key and also the boot strapping pin.
 *
 *   left   GPIO 0   accept / select     (long press: back)
 *   middle GPIO 5   power               (long press: off)
 *   right  GPIO 4   change selection
 */
#define BOARD_BTN_MINUS     GPIO_NUM_0
#define BOARD_BTN_PLUS      GPIO_NUM_4
#define BOARD_BTN_PWR       GPIO_NUM_5

#define BOARD_BTN_ACCEPT    BOARD_BTN_MINUS
#define BOARD_BTN_NEXT      BOARD_BTN_PLUS

/* --- power --------------------------------------------------------------- */
#define BOARD_BAT_ADC       GPIO_NUM_1    /* ADC1 channel 0                  */
#define BOARD_BAT_EN        GPIO_NUM_2
#define BOARD_CHG_STAT      GPIO_NUM_3

/* --- IMU ----------------------------------------------------------------- */
#define BOARD_IMU_INT       GPIO_NUM_6    /* the only reclaimable pin        */
#define BOARD_IMU_ADDR      0x6B

/* --- microSD: 4-bit SDMMC ------------------------------------------------ */
#define BOARD_SD_CLK        GPIO_NUM_16
#define BOARD_SD_CMD        GPIO_NUM_15
#define BOARD_SD_D0         GPIO_NUM_17
#define BOARD_SD_D1         GPIO_NUM_18
#define BOARD_SD_D2         GPIO_NUM_13
#define BOARD_SD_D3         GPIO_NUM_14

/* --- expansion pads ------------------------------------------------------ */
/* UART0 is genuinely available: the console runs over the S3's built-in
 * USB-Serial/JTAG instead, so 43/44 can carry a detector's alarm line. */
#define BOARD_UART_TX       GPIO_NUM_43
#define BOARD_UART_RX       GPIO_NUM_44

/* There is no RTC on this board. The README of the vendor demo claims one; it
 * is absent from the official resource list and from the BSP. Wall-clock time
 * comes from the network or the log carries time-since-boot. */

#endif /* BASANOS_BOARD_H */
