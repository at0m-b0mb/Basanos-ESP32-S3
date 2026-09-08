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

/* The shape of an advertisement.
 *
 * Different detectors key on different things -- an advertiser count, a name,
 * a beacon payload, a connectable peripheral appearing where none belongs --
 * so the shape is what distinguishes one family from another, not the rate. */
typedef enum {
    BAS_ADV_NAME = 0,     /* name only, non-connectable                     */
    BAS_ADV_BEACON,       /* proximity-beacon shaped: UUID, major, minor    */
    BAS_ADV_CONNECTABLE,  /* a peripheral that accepts connections          */
    BAS_ADV_SERVICE,      /* a service UUID with data behind it             */
} bas_adv_shape_t;

/* Advertise as `name` from a synthetic random-static address derived from
 * `seed`. Calling again re-advertises under a new identity, which is what the
 * spam family does; calling once and leaving it is the tracker family. */
esp_err_t bas_ble_advertise(const char *name, uint32_t seed);

/* The same, with an explicit payload shape.
 *
 * Manufacturer payloads use company id 0xFFFF, which the Bluetooth SIG
 * reserves for testing. That gives a well-formed frame a parser will accept
 * without wearing a real vendor's identity -- the detectors being tested score
 * the shape, and borrowing Apple's or Google's id would put dialogs on the
 * phones of people who did not consent to the engagement. */
esp_err_t bas_ble_advertise_as(const char *name, uint32_t seed,
                               bas_adv_shape_t shape);

#define BAS_BLE_TEST_COMPANY 0xFFFFu
esp_err_t bas_ble_stop(void);

/* --- observer -------------------------------------------------------------

   Passive BLE scanning. Nothing is transmitted; the radio listens to
   advertisements every device in the room is broadcasting unprompted.

   Devices are classified by what their advertisement carries, which is how a
   tracker is told from a phone. The classification is deliberately coarse and
   named honestly -- "looks like Find My" is a claim the data supports, "is an
   AirTag" is not.
   ------------------------------------------------------------------------- */

typedef enum {
    BAS_BLE_UNKNOWN = 0,
    BAS_BLE_BASANOS,     /* our own synthetic advertisers                   */
    BAS_BLE_FINDMY,      /* Apple Find My network -- AirTag and friends     */
    BAS_BLE_APPLE,       /* other Apple Continuity traffic                  */
    BAS_BLE_TILE,
    BAS_BLE_SMARTTAG,    /* Samsung                                         */
    BAS_BLE_FASTPAIR,    /* Google                                          */
    BAS_BLE_MICROSOFT,   /* Swift Pair                                      */
    BAS_BLE_FLIPPER,
    BAS_BLE__COUNT
} bas_ble_kind_t;

const char *bas_ble_kind_name(bas_ble_kind_t k);

/* True for kinds that are trackers by design. These are the ones worth
 * surfacing on their own, because a tracker following you is a finding and a
 * phone advertising is not. */
bool bas_ble_kind_is_tracker(bas_ble_kind_t k);

#define BAS_BLE_NAME_MAX 22
#define BAS_BLE_MAX_DEV  40

typedef struct {
    uint8_t        addr[6];
    uint8_t        addr_type;
    char           name[BAS_BLE_NAME_MAX];
    int8_t         rssi;
    bas_ble_kind_t kind;
    uint16_t       count;
    uint32_t       first_ms;
    uint32_t       last_ms;
    bool           randomised;
} bas_ble_dev_t;

esp_err_t bas_ble_scan_start(void);
esp_err_t bas_ble_scan_stop(void);
bool      bas_ble_scanning(void);

const bas_ble_dev_t *bas_ble_devices(int *count);
void bas_ble_scan_reset(void);

/* How long the longest-dwelling tracker has been in range. A tracker seen once
 * is furniture; one seen across many minutes is following you -- which is the
 * distinction GhostTag exists to make, and the reason dwell is reported
 * separately from a sighting count. */
uint32_t bas_ble_longest_tracker_dwell(uint32_t now_ms);

/* Distinct identities advertised since the last reset. */
uint32_t bas_ble_advert_count(void);
void     bas_ble_reset_count(void);

#endif /* BASANOS_BLE_H */
