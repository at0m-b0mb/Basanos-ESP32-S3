/* Basanos — station enumeration.
 *
 * An engagement may narrow from one access point to one client. That requires
 * knowing which clients are there, which is what this list is for: frames seen
 * on the target's channel are attributed to a station and an AP.
 *
 * This is observation only. Nothing here transmits, and a station appearing in
 * the list confers no permission to address it — bas_engage_permits_frame() is
 * still the gate.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_STATION_H
#define BASANOS_STATION_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  mac[6];
    uint8_t  bssid[6];      /* the AP it was seen talking to            */
    int8_t   rssi;
    uint32_t frames;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    bool     randomised;    /* locally-administered bit set             */
} bas_station_t;

#define BAS_MAX_STATIONS 32

typedef struct {
    bas_station_t s[BAS_MAX_STATIONS];
    uint8_t       count;
    uint16_t      dropped;
} bas_stalist_t;

void bas_sta_reset(bas_stalist_t *l);

/* Record a sighting. Refuses group addresses and all-zero MACs — those are not
 * stations, and a list that contained one could be selected as a target.
 * Returns the index, or -1 if refused or the table is full. */
int bas_sta_observe(bas_stalist_t *l,
                    const uint8_t mac[6],
                    const uint8_t bssid[6],
                    int8_t rssi,
                    uint32_t now_ms);

int bas_sta_find(const bas_stalist_t *l, const uint8_t mac[6]);

/* How many stations are associated with this BSSID. The UI shows this next to
 * the target so an operator knows how many devices a run could affect. */
int bas_sta_count_for(const bas_stalist_t *l, const uint8_t bssid[6]);

/* Compact the list to just this BSSID's stations, for the client picker. */
void bas_sta_filter(bas_stalist_t *l, const uint8_t bssid[6]);

void bas_sta_sort_rssi(bas_stalist_t *l);
void bas_sta_expire(bas_stalist_t *l, uint32_t cutoff_ms);

/* A locally-administered address is almost certainly randomised by the client
 * for privacy. Basanos reports this rather than hiding it: a randomised MAC
 * means the station may not be the same device it was ten minutes ago, and an
 * operator narrowing an engagement to it should know that. */
bool bas_mac_is_randomised(const uint8_t mac[6]);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_STATION_H */
