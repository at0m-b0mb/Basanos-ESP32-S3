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
#define BAS_IE_COUNTRY   7u
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

    char country[3];        /* claimed regulatory domain, or empty         */
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

/* --- WPS -------------------------------------------------------------------

   Wi-Fi Protected Setup is the highest-value finding a passive survey can
   produce. An access point with WPS enabled and unlocked, advertising a PIN
   method, is exposed to an online PIN attack -- and on many chipsets to the
   offline Pixie Dust attack, which recovers the PIN in seconds because the
   registrar's nonces are predictable. Either yields the network passphrase.

   Everything below is read from the beacon. That matters: the finding is
   available without touching the AP at all, which makes it the cheapest and
   safest thing in the catalogue to check.

   What this does NOT do is recover the PIN or the passphrase. The finding a
   report needs is "WPS is enabled and exploitable, disable it" -- the
   credential adds nothing to that recommendation and creates custody of a key
   the engagement has no reason to hold.
   ------------------------------------------------------------------------- */

/* The finding type itself lives in wps_fwd.h, because a scan entry
   carries one and ie.h includes target.h. */

const char *bas_wps_risk_name(bas_wps_risk_t r);

/* One line an operator can act on, and a report can quote. */
const char *bas_wps_advice(bas_wps_risk_t r);

bas_wps_risk_t bas_wps_grade(const bas_wps_t *w);

/* True for the chipset vendors with documented weak registrar nonce
 * generation -- the Pixie Dust family.
 *
 * A NAME is weak evidence and this says so: the vendor string is chosen by the
 * firmware author, several vendors ship more than one chipset, and a rebadged
 * device may name a company that never made its radio. It raises suspicion; it
 * does not establish the vulnerability, and only an M1 exchange would. */
bool bas_wps_vendor_suspect(const bas_wps_t *w);

/* Parse the WPS vendor element out of a beacon's tagged parameters. */
bas_err_t bas_wps_parse(const uint8_t *ies, size_t len, bas_wps_t *out);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_IE_H */
