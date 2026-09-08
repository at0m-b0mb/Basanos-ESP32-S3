/* Basanos — the detector's own voice, over the UART pads.
 *
 * This closes the measurement loop for machine timing. A detector under test
 * prints one line when it fires:
 *
 *     BASANOS-ALARM detector=Aegis conf=82 fam=0x0F
 *
 * and the scorecard credits it with the timestamp of the byte arriving, not of
 * an operator noticing. The difference matters: an operator-timed latency
 * includes human reaction time and is worth hundreds of milliseconds, so the
 * two are recorded with their source and never averaged together.
 *
 * The pads are GPIO 43/44, which are free because the console runs over the
 * S3's built-in USB-Serial/JTAG rather than UART0.
 *
 * Everything arriving here is a detector's output — untrusted text from
 * another device. It is parsed strictly and never executed: a line that does
 * not match becomes nothing at all.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_UARTALARM_H
#define BASANOS_UARTALARM_H

#include "basanos/alarm.h"
#include "esp_err.h"

/* Default for a detector's debug console. Configurable because the detector
 * chose its own rate and this end has to follow. */
#define BAS_UART_ALARM_BAUD 115200

esp_err_t bas_uart_alarm_start(int baud);
void      bas_uart_alarm_stop(void);
bool      bas_uart_alarm_active(void);

/* Loops TX back to RX inside the peripheral, sends a well-formed alarm and
 * waits for it to arrive parsed. Proves the whole path without a second device
 * or a jumper. The probe is discarded rather than scored. */
bool bas_uart_alarm_selftest(void);

/* Pops the next parsed alarm. False when none is waiting. */
bool bas_uart_alarm_take(bas_alarm_t *out);

/* Lines seen, and lines that parsed. The gap between them is the useful
 * diagnostic: bytes arriving but nothing parsing means the detector is talking
 * and the format is wrong, which is a different problem from silence. */
uint32_t bas_uart_alarm_lines(void);
uint32_t bas_uart_alarm_parsed(void);

/* The last line received, parsed or not, for the interface to show. Seeing the
 * detector's actual output is how a format mismatch gets diagnosed. */
const char *bas_uart_alarm_last(void);

#endif /* BASANOS_UARTALARM_H */
