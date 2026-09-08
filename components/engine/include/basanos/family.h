/* Basanos — the signal families, and the ceilings on each.
 *
 * Every family here exists because one of the defensive projects claims to
 * detect it. The `detector` field is not documentation: it is the reason the
 * family is in the build. A family that exercises nothing does not ship.
 *
 * Two deliberate omissions, and one correction:
 *
 *   - Evil portal / captive portal. Credential harvesting and brand
 *     impersonation. Not a measurement.
 *   - Four-way handshake capture. Genuinely passive, so no detector can
 *     observe it happening; it exercises nothing and yields only crackable
 *     material.
 *
 * PMKID was originally excluded on the same "passive" reasoning and that was
 * WRONG. A PMKID is not captured passively -- it is solicited: the tester
 * sends an association request and the AP volunteers EAPOL M1 in reply. That
 * solicitation is exactly what a sensor detects, so the family belongs here.
 * It records only that a PMKID was OFFERED and never the value, which leaves
 * the sensor test identical and the crackable material non-existent.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_FAMILY_H
#define BASANOS_FAMILY_H

#include "basanos/engage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* --- benign: things an ordinary phone does unprompted --------------- */
    BAS_FAM_PROBE_REQ = 0,   /* probe requests naming chosen SSIDs          */
    BAS_FAM_BLE_ADV,         /* BLE advertisements, distinct addresses      */
    BAS_FAM_BLE_TRACKER,     /* one persistent BLE address, dwelling        */
    BAS_FAM_HID_TIMING,      /* USB HID keystroke timing profile            */

    /* --- active: visible on air, aimed at the locked target ------------- */
    BAS_FAM_BEACON,          /* bounded, prefixed, fake APs                 */
    BAS_FAM_KARMA_RESP,      /* answer others' probes; log, never portal    */
    BAS_FAM_EVIL_TWIN,       /* duplicate BSSID w/ security-class conflict  */
    BAS_FAM_PMKID,           /* solicit EAPOL M1; record only that a PMKID
                              * was OFFERED, never the PMKID itself         */

    /* --- disruptive: denies service to something real ------------------- */
    BAS_FAM_AUTH_FLOOD,      /* fills the target AP's association table     */
    BAS_FAM_DISASSOC,
    BAS_FAM_DEAUTH,

    BAS_FAM__COUNT
} bas_family_t;

typedef enum {
    BAS_CLASS_BENIGN = 0,
    BAS_CLASS_ACTIVE,
    BAS_CLASS_DISRUPTIVE
} bas_class_t;

typedef struct {
    const char *name;        /* shown in the picker                         */
    const char *detector;    /* which defensive project this exercises      */
    const char *proves;      /* one line: what a CAUGHT verdict means here  */
    bas_class_t klass;
    bool     needs_target;   /* requires a locked AP                        */
    bool     needs_client;   /* meaningless without a specific STA          */
    uint16_t default_pps;    /* frames per second                           */
    uint16_t max_pps;        /* hard ceiling — a plan may lower, never raise*/
    uint16_t max_seconds;    /* hard ceiling on a single run                */
    uint8_t  min_role;       /* bas_role_t value required to run it         */
} bas_family_spec_t;

/* NULL for an out-of-range family. */
const bas_family_spec_t *bas_family(bas_family_t f);
const char *bas_class_name(bas_class_t c);

/* A plan is what the operator asked for. Validation clamps it to what the
 * family permits and the engagement covers — it never widens anything. */
typedef struct {
    bas_family_t fam;
    uint16_t pps;
    uint16_t seconds;
    uint8_t  reason_code;    /* 802.11 reason for deauth/disassoc; 7 default*/
    uint8_t  channel;        /* 0 = follow the target's channel             */
    bool     clamped_pps;    /* set by validate when it lowered the rate    */
    bool     clamped_secs;
} bas_plan_t;

/* Fill a plan with the family's defaults. */
void bas_plan_default(bas_plan_t *p, bas_family_t f);

/* The gate every transmit path goes through.
 *
 * Checks, in this order: family known; role permits the class; engagement
 * locked and unexpired when the family needs a target; a client is present
 * when the family needs one; channel inside the regulatory clamp. Then clamps
 * pps and seconds to the family ceiling, recording that it did so.
 *
 * Returns BAS_OK only when the run may proceed. `p` is modified in place. */
bas_err_t bas_plan_validate(bas_plan_t *p,
                            uint8_t role,
                            const bas_engagement_t *e,
                            uint32_t now_ms);

/* Total frames a validated plan will emit. The UI shows this before arming,
 * because "600 frames" is a number an operator can reason about and
 * "20 pps for 30 s" is not. */
uint32_t bas_plan_frame_budget(const bas_plan_t *p);

/* Regulatory clamp. Basanos will not transmit outside the operator's domain
 * even when the target is there — a 2.4 GHz channel above the domain's limit
 * is refused rather than silently retuned. */
typedef enum { BAS_REGION_FCC = 0, BAS_REGION_ETSI, BAS_REGION_JP } bas_region_t;
void bas_region_set(bas_region_t r);
bas_region_t bas_region_get(void);
uint8_t bas_region_max_channel(void);
bas_err_t bas_region_check_channel(uint8_t ch);

/* The prefix every SSID and BLE name Basanos invents must carry, so anyone
 * else sniffing the room sees a test rig and not an attack. Enforced by
 * bas_family_label_ok(). */
#define BAS_TEST_PREFIX "BASANOS-"
bool bas_family_label_ok(const char *ssid);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_FAMILY_H */
