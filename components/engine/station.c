/* Basanos — station enumeration. SPDX-License-Identifier: MIT */
#include "basanos/station.h"

#include <string.h>

bool bas_mac_is_randomised(const uint8_t mac[6])
{
    if (mac == NULL) {
        return false;
    }
    /* Bit 1 of the first octet is the locally-administered flag. Every major
     * client OS sets it when randomising. Bit 0 is the group bit and is
     * handled separately — a group address is not a station at all. */
    return (mac[0] & 0x02u) != 0u;
}

void bas_sta_reset(bas_stalist_t *l)
{
    if (l == NULL) {
        return;
    }
    memset(l, 0, sizeof(*l));
}

int bas_sta_find(const bas_stalist_t *l, const uint8_t mac[6])
{
    if (l == NULL || mac == NULL) {
        return -1;
    }
    for (uint8_t i = 0; i < l->count; i++) {
        if (bas_mac_eq(l->s[i].mac, mac)) {
            return (int)i;
        }
    }
    return -1;
}

int bas_sta_observe(bas_stalist_t *l,
                    const uint8_t mac[6],
                    const uint8_t bssid[6],
                    int8_t rssi,
                    uint32_t now_ms)
{
    if (l == NULL || mac == NULL || bssid == NULL) {
        return -1;
    }

    /* A broadcast or multicast address is a destination, never a station. If
     * one reached this list it could be picked in the client selector, which
     * is precisely the thing the engagement lock exists to prevent. */
    if (bas_mac_is_broadcast(mac) || bas_mac_is_zero(mac)) {
        return -1;
    }
    /* The AP side must be a real BSSID for the same reason. */
    if (bas_mac_is_broadcast(bssid) || bas_mac_is_zero(bssid)) {
        return -1;
    }
    /* A frame from an AP to itself is not a station sighting. */
    if (bas_mac_eq(mac, bssid)) {
        return -1;
    }

    int idx = bas_sta_find(l, mac);
    if (idx >= 0) {
        bas_station_t *s = &l->s[idx];
        memcpy(s->bssid, bssid, 6);
        s->rssi = rssi;
        s->last_seen_ms = now_ms;
        if (s->frames < UINT32_MAX) {
            s->frames++;
        }
        return idx;
    }

    if (l->count >= BAS_MAX_STATIONS) {
        if (l->dropped < UINT16_MAX) {
            l->dropped++;
        }
        return -1;
    }

    bas_station_t *s = &l->s[l->count];
    memset(s, 0, sizeof(*s));
    memcpy(s->mac, mac, 6);
    memcpy(s->bssid, bssid, 6);
    s->rssi          = rssi;
    s->frames        = 1u;
    s->first_seen_ms = now_ms;
    s->last_seen_ms  = now_ms;
    s->randomised    = bas_mac_is_randomised(mac);
    l->count++;
    return (int)(l->count - 1u);
}

int bas_sta_count_for(const bas_stalist_t *l, const uint8_t bssid[6])
{
    if (l == NULL || bssid == NULL) {
        return 0;
    }
    int n = 0;
    for (uint8_t i = 0; i < l->count; i++) {
        if (bas_mac_eq(l->s[i].bssid, bssid)) {
            n++;
        }
    }
    return n;
}

void bas_sta_filter(bas_stalist_t *l, const uint8_t bssid[6])
{
    if (l == NULL || bssid == NULL) {
        return;
    }
    uint8_t w = 0;
    for (uint8_t i = 0; i < l->count; i++) {
        if (bas_mac_eq(l->s[i].bssid, bssid)) {
            if (w != i) {
                l->s[w] = l->s[i];
            }
            w++;
        }
    }
    for (uint8_t i = w; i < l->count; i++) {
        memset(&l->s[i], 0, sizeof(l->s[i]));
    }
    l->count = w;
}

void bas_sta_sort_rssi(bas_stalist_t *l)
{
    if (l == NULL || l->count < 2u) {
        return;
    }
    for (uint8_t i = 1; i < l->count; i++) {
        bas_station_t key = l->s[i];
        int j = (int)i - 1;
        while (j >= 0 && l->s[j].rssi < key.rssi) {
            l->s[j + 1] = l->s[j];
            j--;
        }
        l->s[j + 1] = key;
    }
}

void bas_sta_expire(bas_stalist_t *l, uint32_t cutoff_ms)
{
    if (l == NULL) {
        return;
    }
    uint8_t w = 0;
    for (uint8_t i = 0; i < l->count; i++) {
        if (l->s[i].last_seen_ms >= cutoff_ms) {
            if (w != i) {
                l->s[w] = l->s[i];
            }
            w++;
        }
    }
    for (uint8_t i = w; i < l->count; i++) {
        memset(&l->s[i], 0, sizeof(l->s[i]));
    }
    l->count = w;
}
