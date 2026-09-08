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

/* Enough for a household or a small office cell. A limit that has to be
 * chosen deliberately is a limit an operator notices; an unbounded list would
 * quietly become "everyone" again. */
#define BAS_MAX_CLIENTS  8

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
    /* The clients this engagement may address. Empty means the access point
     * itself and nothing else.
     *
     * A set rather than a single address, because "disconnect everyone" is a
     * real need and broadcast is the wrong way to serve it: a broadcast frame
     * reaches devices the operator never enumerated and never chose, and no
     * report can say afterwards which they were. Iterating directed frames
     * across a chosen set has the same effect on those devices, keeps a real
     * destination on every frame, and is auditable. */
    uint8_t  client[BAS_MAX_CLIENTS][6];
    uint8_t  client_n;

    /* Address the whole cell with a broadcast destination.
     *
     * A deauthentication frame carries the BSSID in addresses 2 and 3, and a
     * station acts on it only when it is associated with THAT cell -- a device
     * on a neighbouring network ignores it. So the scope of a broadcast frame
     * is the BSSID, which this engagement has already locked, and not the
     * destination address.
     *
     * That matters because a client which stayed silent through the capture
     * window never appears in the station list, and an assessment that can
     * only reach enumerated clients has a blind spot it cannot see. This is
     * how a whole cell gets tested honestly.
     *
     * It is a separate, deliberate mode rather than a default: the operator
     * chooses the whole cell, and the log records that they did. */
    bool     whole_cell;
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

/* Add a client to the addressable set. Refuses broadcast, multicast, all-zero,
 * the access point itself, and a full set. Adding one already present is a
 * no-op rather than an error. */
bas_err_t bas_engage_add_client(bas_engagement_t *e, const uint8_t mac[6]);

/* Remove one. Returns BAS_ERR_NO_TARGET when it was not in the set. */
bas_err_t bas_engage_remove_client(bas_engagement_t *e, const uint8_t mac[6]);

/* Present in the set? */
bool bas_engage_has_client(const bas_engagement_t *e, const uint8_t mac[6]);

/* Narrow to exactly one, discarding any others. */
bas_err_t bas_engage_set_client(bas_engagement_t *e, const uint8_t mac[6]);

void bas_engage_clear_clients(bas_engagement_t *e);

/* Choose the whole cell instead of a client list. Requires a locked target,
 * because a broadcast frame is scoped by the BSSID it carries and there has to
 * be one. Selecting it clears any client selection: the two are alternatives,
 * not layers. */
bas_err_t bas_engage_set_whole_cell(bas_engagement_t *e, bool on);
bool      bas_engage_is_whole_cell(const bas_engagement_t *e);

/* How many destinations a directed family will cycle through: the selected
 * clients, or 1 (the access point) when none are selected. */
uint8_t bas_engage_dest_count(const bas_engagement_t *e);

/* The nth destination, wrapping. Never returns a group address. */
const uint8_t *bas_engage_dest(const bas_engagement_t *e, uint32_t n);

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
