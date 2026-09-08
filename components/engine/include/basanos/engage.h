/* Basanos — the engagement: one operator, one target, one clock.
 *
 * Nothing transmits unless an engagement is locked. Locking requires a target
 * chosen by hand from the scan, a label naming the authorisation, and the name
 * of the operator doing it. All three end up in the audit log.
 *
 * The lock is deliberately narrow: ONE BSSID. An optional single client MAC
 * narrows it further. Broadcast destinations are refused at this layer, so no
 * caller anywhere in the firmware can construct a room-clearing run.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_ENGAGE_H
#define BASANOS_ENGAGE_H

#include "basanos/target.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAS_LABEL_MAX    48
#define BAS_OPERATOR_MAX 24

/* An engagement expires. A device that outlives its authorisation is the most
 * common way a legitimate test becomes an unauthorised one, so the TTL is not
 * optional and cannot be set to "forever". */
#define BAS_TTL_MIN_MS   (60u * 1000u)          /*  1 minute  */
#define BAS_TTL_MAX_MS   (4u * 60u * 60u * 1000u) /* 4 hours  */
#define BAS_TTL_DEFAULT_MS (30u * 60u * 1000u)  /* 30 minutes */

typedef struct {
    bool     locked;
    bool     has_target;                 /* false for a label-only lock     */
    bas_ap_t target;                     /* the single AP under test        */
    bool     has_client;
    uint8_t  client[6];                  /* optional single STA             */
    char     label[BAS_LABEL_MAX];       /* authorisation reference         */
    char     operator_name[BAS_OPERATOR_MAX];
    uint32_t locked_ms;
    uint32_t expires_ms;
    uint32_t runs;                       /* emissions made under this lock  */
} bas_engagement_t;

void bas_engage_clear(bas_engagement_t *e);

/* Lock onto a target.
 *
 * Refuses: a NULL/invalid AP (BAS_ERR_BAD_BSSID), a broadcast or multicast
 * BSSID (BAS_ERR_BROADCAST), an empty label (BAS_ERR_NO_LABEL), an empty
 * operator name (BAS_ERR_ARG), or a TTL outside [BAS_TTL_MIN_MS,
 * BAS_TTL_MAX_MS] (BAS_ERR_ARG).
 *
 * `label` is free text — a work-order number, a client name, a ticket. It is
 * not verified and Basanos does not pretend it is; it exists so the audit log
 * can answer "under what authority" with something the operator typed before
 * the fact rather than reconstructed after it. */
bas_err_t bas_engage_lock(bas_engagement_t *e,
                          const bas_ap_t *target,
                          const char *label,
                          const char *operator_name,
                          uint32_t now_ms,
                          uint32_t ttl_ms);

/* An engagement with an authorisation but no Wi-Fi target.
 *
 * The families that address a network need one; the families that address
 * nobody -- BLE advertising, probe requests -- do not, and requiring an
 * operator to pick an access point in order to authorise a Bluetooth emission
 * is incoherent. The label is the authorisation. The target is scope, and
 * scope is per-family.
 *
 * Every family with needs_target is refused under this lock, so it widens
 * nothing: it separates "who authorised this" from "what may be addressed". */
bas_err_t bas_engage_lock_area(bas_engagement_t *e,
                               const char *label,
                               const char *operator_name,
                               uint32_t now_ms,
                               uint32_t ttl_ms);

/* Narrow to one client. Refuses broadcast/multicast and all-zero. */
bas_err_t bas_engage_set_client(bas_engagement_t *e, const uint8_t mac[6]);
void      bas_engage_clear_client(bas_engagement_t *e);

/* BAS_OK only while a lock is live and unexpired. Every transmit path calls
 * this immediately before emitting, not once at arm time — an engagement that
 * expires mid-run stops the run. */
bas_err_t bas_engage_check(const bas_engagement_t *e, uint32_t now_ms);

/* Milliseconds left, 0 once expired. The UI shows this as a countdown; the
 * operator should always be able to see how long the device still believes it
 * is authorised. */
uint32_t bas_engage_remaining_ms(const bas_engagement_t *e, uint32_t now_ms);

/* Confirm a frame's destination is inside the lock before it goes out. This is
 * the last gate: it takes the actual destination and BSSID a transmit path is
 * about to use and refuses anything the engagement does not cover. */
bas_err_t bas_engage_permits_frame(const bas_engagement_t *e,
                                   const uint8_t dest[6],
                                   const uint8_t bssid[6],
                                   uint32_t now_ms);

void bas_engage_note_run(bas_engagement_t *e);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_ENGAGE_H */
