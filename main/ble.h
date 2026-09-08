/* Basanos — BLE advertising.
 *
 * Two families live on this radio, and the difference between them is the
 * whole measurement:
 *
 *   ADVERT SPAM     many distinct advertiser addresses in a short window. A
 *                   detector scores advertiser multiplicity and channel
 *                   balance, so what matters is the spread of addresses, not
 *                   what any one of them claims to be.
 *
 *   TRACKER DWELL   one persistent address, present for a long time. A tracker
 *                   detector scores dwell span against sightings, separating a
 *                   device that follows you from fixed furniture.
 *
 * Every name carries the BASANOS- prefix and no advertisement imitates a
 * vendor's pairing payload. Real Continuity or Fast Pair frames would pop
 * dialogs on the phones of bystanders who did not consent to the engagement,
 * and they buy nothing: the detectors being tested score the shape, not the
 * payload.
 *
 * Advertising is non-connectable throughout. There is nothing to connect to.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_BLE_H
#define BASANOS_BLE_H

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

/* Brings up the controller and host. Safe to call more than once. Returns
 * ESP_ERR_NOT_SUPPORTED when the build has Bluetooth disabled, so the caller
 * can report the family as unavailable rather than fail. */
esp_err_t bas_ble_init(void);
bool      bas_ble_ready(void);

/* Advertise as `name` from a synthetic random-static address derived from
 * `seed`. Calling again re-advertises under a new identity, which is what the
 * spam family does; calling once and leaving it is the tracker family. */
esp_err_t bas_ble_advertise(const char *name, uint32_t seed);
esp_err_t bas_ble_stop(void);

/* Distinct identities advertised since the last reset. */
uint32_t bas_ble_advert_count(void);
void     bas_ble_reset_count(void);

#endif /* BASANOS_BLE_H */
