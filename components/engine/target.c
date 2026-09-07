/* Basanos — scan list and target validation. SPDX-License-Identifier: MIT */
#include "basanos/target.h"

#include <string.h>

const char *bas_sec_name(bas_sec_t s)
{
    switch (s) {
    case BAS_SEC_OPEN:      return "Open";
    case BAS_SEC_WEP:       return "WEP";
    case BAS_SEC_WPA:       return "WPA";
    case BAS_SEC_WPA2:      return "WPA2";
    case BAS_SEC_WPA2_ENT:  return "WPA2-Ent";
    case BAS_SEC_WPA3:      return "WPA3";
    case BAS_SEC_WPA2_WPA3: return "WPA2/3";
    default:                return "?";
    }
}

bool bas_sec_is_open(bas_sec_t s) { return s == BAS_SEC_OPEN; }

bool bas_sec_likely_mfp(bas_sec_t s)
{
    /* WPA3 requires management frame protection; WPA2-Enterprise very often
     * enables it. A deauth run against these is expected to bounce, and that
     * outcome is a finding rather than a failure — the UI says so before the
     * operator wastes a run. WPA2/WPA3 transition mode is not included: its
     * WPA2 half is unprotected, which is the whole problem with it. */
    return s == BAS_SEC_WPA3 || s == BAS_SEC_WPA2_ENT;
}

void bas_scan_reset(bas_scan_t *s)
{
    if (s == NULL) {
        return;
    }
    memset(s, 0, sizeof(*s));
}

int bas_scan_find_bssid(const bas_scan_t *s, const uint8_t bssid[6])
{
    if (s == NULL || bssid == NULL) {
        return -1;
    }
    for (uint8_t i = 0; i < s->count; i++) {
        if (bas_mac_eq(s->ap[i].bssid, bssid)) {
            return (int)i;
        }
    }
    return -1;
}

int bas_scan_observe(bas_scan_t *s, const bas_ap_t *ap)
{
    if (s == NULL || ap == NULL) {
        return -1;
    }

    int idx = bas_scan_find_bssid(s, ap->bssid);
    if (idx >= 0) {
        /* Update in place. first_seen is the identity of the sighting and must
         * survive: a detector test cares how long an AP has been around. */
        uint32_t first = s->ap[idx].first_seen_ms;
        s->ap[idx] = *ap;
        s->ap[idx].first_seen_ms = first;
        return idx;
    }

    if (s->count >= BAS_MAX_APS) {
        if (s->dropped < UINT16_MAX) {
            s->dropped++;
        }
        return -1;
    }

    s->ap[s->count] = *ap;
    if (s->ap[s->count].first_seen_ms == 0u) {
        s->ap[s->count].first_seen_ms = ap->last_seen_ms;
    }
    s->count++;
    return (int)(s->count - 1u);
}

int bas_scan_find_ssid(const bas_scan_t *s, const char *ssid)
{
    if (s == NULL || ssid == NULL || ssid[0] == '\0') {
        return -1;
    }
    int best = -1;
    for (uint8_t i = 0; i < s->count; i++) {
        if (strncmp(s->ap[i].ssid, ssid, sizeof(s->ap[i].ssid)) != 0) {
            continue;
        }
        if (best < 0 || s->ap[i].rssi > s->ap[best].rssi) {
            best = (int)i;
        }
    }
    return best;
}

int bas_scan_count_ssid(const bas_scan_t *s, const char *ssid)
{
    if (s == NULL || ssid == NULL || ssid[0] == '\0') {
        return 0;
    }
    int n = 0;
    for (uint8_t i = 0; i < s->count; i++) {
        if (strncmp(s->ap[i].ssid, ssid, sizeof(s->ap[i].ssid)) == 0) {
            n++;
        }
    }
    return n;
}

void bas_scan_sort_rssi(bas_scan_t *s)
{
    if (s == NULL || s->count < 2u) {
        return;
    }
    /* Insertion sort: the list is at most 48 entries and this keeps equal-RSSI
     * neighbours in discovery order, so the picker does not shuffle under the
     * operator's finger between refreshes. */
    for (uint8_t i = 1; i < s->count; i++) {
        bas_ap_t key = s->ap[i];
        int j = (int)i - 1;
        while (j >= 0 && s->ap[j].rssi < key.rssi) {
            s->ap[j + 1] = s->ap[j];
            j--;
        }
        s->ap[j + 1] = key;
    }
}

void bas_scan_expire(bas_scan_t *s, uint32_t cutoff_ms)
{
    if (s == NULL) {
        return;
    }
    uint8_t w = 0;
    for (uint8_t i = 0; i < s->count; i++) {
        if (s->ap[i].last_seen_ms >= cutoff_ms) {
            if (w != i) {
                s->ap[w] = s->ap[i];
            }
            w++;
        }
    }
    for (uint8_t i = w; i < s->count; i++) {
        memset(&s->ap[i], 0, sizeof(s->ap[i]));
    }
    s->count = w;
}

bas_err_t bas_ap_check(const bas_ap_t *ap)
{
    if (ap == NULL) {
        return BAS_ERR_ARG;
    }
    if (bas_mac_is_zero(ap->bssid)) {
        return BAS_ERR_BAD_BSSID;
    }
    if (bas_mac_is_broadcast(ap->bssid)) {
        /* A multicast bit in a BSSID is not a real access point. Refusing it
         * here is what stops "select all" being expressible at all. */
        return BAS_ERR_BROADCAST;
    }
    if (ap->channel < 1u || ap->channel > 14u) {
        return BAS_ERR_CHANNEL;
    }
    return BAS_OK;
}
