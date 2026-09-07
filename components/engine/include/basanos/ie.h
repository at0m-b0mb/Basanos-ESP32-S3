/* Basanos — 802.11 information-element parsing.
 *
 * Turns the tagged parameters of a beacon or probe response into the posture
 * an operator needs before choosing a target: the real security suite, whether
 * management frames are protected, and whether WPS is exposed.
 *
 * Everything here consumes attacker-controlled bytes off the air, so every
 * read is bounds-checked and a malformed element truncates the parse rather
 * than walking off the buffer. The host tests feed it deliberately broken
 * input; that suite is the point of this file.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_IE_H
#define BASANOS_IE_H

#include "basanos/target.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Element ids used here. */
#define BAS_IE_SSID      0u
#define BAS_IE_DS_PARAM  3u
#define BAS_IE_RSN      48u
#define BAS_IE_VENDOR  221u

typedef struct {
    bool ssid_present;
    bool hidden;            /* zero-length or all-NUL SSID element        */
    bool ds_present;
    bool rsn_present;

    bool pmf_capable;       /* RSN capabilities bit 6 (MFPC)              */
    bool pmf_required;      /* RSN capabilities bit 7 (MFPR)              */

    bool akm_psk;
    bool akm_enterprise;    /* 802.1X                                      */
    bool akm_sae;           /* WPA3                                        */
    bool akm_owe;           /* opportunistic wireless encryption           */

    bool wps_present;
    bool wps_locked;        /* AP setup locked attribute                   */

    uint16_t elements;      /* how many elements parsed                    */
    bool     truncated;     /* a length ran past the end of the buffer     */
} bas_posture_t;

/* Parse the tagged-parameter region. `ap` may be NULL; when given, its ssid,
 * hidden flag, channel and sec fields are filled from what was found.
 *
 * Returns BAS_OK when the region parsed cleanly to the end, and still fills
 * everything it managed to read when it did not — a truncated beacon is common
 * on a busy channel and is not a reason to discard the AP. `truncated` in the
 * posture says which happened. */
bas_err_t bas_ie_parse(const uint8_t *ies, size_t len,
                       bas_ap_t *ap, bas_posture_t *out);

/* Classify from a parsed posture. WPA2/WPA3 transition mode is reported as
 * BAS_SEC_WPA2_WPA3 rather than WPA3, because its WPA2 half is unprotected and
 * calling it WPA3 would overstate the target's resistance. */
bas_sec_t bas_ie_classify(const bas_posture_t *p, bool privacy_bit);

/* True when a deauthentication run against this target is expected to bounce.
 * The UI says so before the operator spends a run on it. */
bool bas_posture_deauth_resistant(const bas_posture_t *p);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_IE_H */
