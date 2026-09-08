/* Basanos — the scan list and the one network you pick out of it.
 *
 * Basanos has exactly one targeting mode: manual. You scan, you look at the
 * list, you choose a single access point that you have authorisation to test.
 * There is no "all", no broadcast, and no wildcard anywhere in this header.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_TARGET_H
#define BASANOS_TARGET_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BAS_SEC_OPEN = 0,
    BAS_SEC_WEP,
    BAS_SEC_WPA,
    BAS_SEC_WPA2,
    BAS_SEC_WPA2_ENT,
    BAS_SEC_WPA3,
    BAS_SEC_WPA2_WPA3,
    BAS_SEC_UNKNOWN
} bas_sec_t;

const char *bas_sec_name(bas_sec_t s);

/* True when the network offers no link-layer confidentiality at all. Used by
 * the UI to warn, never to permit: an open network is not more legal to test. */
bool bas_sec_is_open(bas_sec_t s);

/* 802.11 management frames are protected on this network (WPA3 or WPA2-Ent
 * with MFP). Deauth against these is expected to fail, which is a *result*,
 * not an error — Pharos' watch engine grades exactly this. */
bool bas_sec_likely_mfp(bas_sec_t s);

typedef struct {
    char      ssid[33];      /* NUL-terminated; empty when hidden           */
    uint8_t   bssid[6];
    uint8_t   channel;       /* 1..14 for 2.4 GHz                           */
    int8_t    rssi;          /* dBm, negative                               */
    bas_sec_t sec;
    bool      hidden;
    uint32_t  first_seen_ms;
    uint32_t  last_seen_ms;
    /* The regulatory domain this AP claims, from its Country element. Empty
     * when it advertises none, which many consumer APs do not. */
    char      country[3];
} bas_ap_t;

#define BAS_MAX_APS 48

typedef struct {
    bas_ap_t ap[BAS_MAX_APS];
    uint8_t  count;
    uint16_t dropped;        /* seen but no room — surfaced in the UI       */
} bas_scan_t;

void bas_scan_reset(bas_scan_t *s);

/* Insert or update by BSSID. Two APs may share an SSID (roaming) and that is
 * normal; BSSID is the identity. Returns the index, or -1 when the table is
 * full (and bumps `dropped` so the operator knows the list is not complete). */
int bas_scan_observe(bas_scan_t *s, const bas_ap_t *ap);

int bas_scan_find_bssid(const bas_scan_t *s, const uint8_t bssid[6]);

/* First AP whose SSID matches exactly. Returns -1 if none. When several BSSIDs
 * share the SSID this returns the strongest, so the picker does the sensible
 * thing for "sunshine 12" on a mesh — but the operator still confirms a BSSID. */
int bas_scan_find_ssid(const bas_scan_t *s, const char *ssid);

/* How many distinct BSSIDs advertise this SSID. >1 means the operator is about
 * to pick one radio out of several and should be told so. */
int bas_scan_count_ssid(const bas_scan_t *s, const char *ssid);

/* Strongest first. The picker shows the list in this order. */
void bas_scan_sort_rssi(bas_scan_t *s);

/* Drop entries not seen since `cutoff_ms`, so a stale AP cannot be selected. */
void bas_scan_expire(bas_scan_t *s, uint32_t cutoff_ms);

/* Validate an AP as a *candidate* target. Checks the BSSID is real (not zero,
 * not broadcast/multicast) and the channel is sane. Does not consider
 * authorisation — that is bas_engage_lock's job. */
bas_err_t bas_ap_check(const bas_ap_t *ap);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_TARGET_H */
