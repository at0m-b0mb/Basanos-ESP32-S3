/* Basanos — WPS PIN recovery.
 *
 * This is the part of a wireless assessment that changes behaviour. A finding
 * that says "WPS is enabled" gets filed; the network's own passphrase on a
 * slide gets WPS turned off that week. Both are the same defect. Only one of
 * them is believed.
 *
 * Two attacks live here, and the cheap one is the one that works:
 *
 *   Default PIN.  A great many consumer access points derive their WPS PIN
 *   from their own BSSID -- which they broadcast continuously. The PIN is
 *   therefore not a secret at all, and a dozen candidate values recover it in
 *   seconds. This is the finding worth reporting: the credential was
 *   computable from a value printed in every beacon.
 *
 *   Exhaustive PIN.  The protocol splits the PIN and validates each half
 *   separately, so the search is 10^4 + 10^3 attempts rather than 10^7. That
 *   is still hours at the rate an AP will answer, and most modern firmware
 *   locks out long before the end. It is included for completeness and is
 *   honest about how rarely it finishes.
 *
 * Everything in this file is arithmetic on a MAC address. It transmits
 * nothing and has no ESP-IDF dependency, so every algorithm below is checked
 * against published vectors on the host before it ever reaches the radio.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_WPSPIN_H
#define BASANOS_WPSPIN_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The eighth digit is a checksum over the first seven, defined by the
 * specification. A PIN that fails it is rejected by the AP without being
 * counted as an attempt, so generating one wastes nothing but is still wrong. */
uint8_t bas_wps_pin_checksum(uint32_t seven_digits);

/* True when all eight digits are consistent. */
bool bas_wps_pin_valid(uint32_t pin8);

/* Attach the checksum to a seven-digit body, giving a full eight-digit PIN. */
uint32_t bas_wps_pin_complete(uint32_t seven_digits);

typedef enum {
    BAS_PINALG_STATIC = 0,   /* the vendor never changed the default        */
    BAS_PINALG_NIC24,        /* low 24 bits of the BSSID                    */
    BAS_PINALG_NIC28,
    BAS_PINALG_NIC32,
    BAS_PINALG_DLINK,
    BAS_PINALG_DLINK_1,      /* the same, on the BSSID plus one             */
    BAS_PINALG_ASUS,
    BAS_PINALG_AIROCON,
    BAS_PINALG_INV_NIC,
    BAS_PINALG_NIC_X2,
    BAS_PINALG_NIC_X3,
    BAS_PINALG_OUI_ADD_NIC,
    BAS_PINALG_OUI_SUB_NIC,
    BAS_PINALG_OUI_XOR_NIC,
    BAS_PINALG__COUNT
} bas_pinalg_t;

const char *bas_pinalg_name(bas_pinalg_t a);

/* One candidate, with the reason it is being tried. The reason is not
 * decoration: it is what the report says about WHY the PIN was guessable. */
typedef struct {
    uint32_t     pin;        /* eight digits, checksum already correct      */
    bas_pinalg_t alg;
} bas_pin_cand_t;

#define BAS_MAX_PIN_CANDS 24

/* Fill `out` with candidate PINs for this BSSID, best-first.
 *
 * Ordering is by observed hit rate, not by algorithm number: the point of the
 * default-PIN attack is that it finishes before an AP's lockout counter does,
 * and that only holds if the likely candidates go first.
 *
 * Duplicates are removed -- several algorithms collapse to the same value on
 * some address ranges, and trying a PIN twice spends a lockout budget for
 * nothing. Returns how many were written. */
int bas_wps_pin_candidates(const uint8_t bssid[6],
                           bas_pin_cand_t *out, int max);

/* --- exhaustive search -----------------------------------------------------

   The AP validates the first four digits and the next three separately, so the
   search is two small spaces rather than one large one. This generates the
   nth attempt of that search, given how much of the PIN is already known.
   ------------------------------------------------------------------------- */

typedef struct {
    bool     first_half_known;
    uint16_t first_half;     /* 0..9999                                     */
    uint16_t next;           /* cursor within whichever half is in progress */
} bas_pin_search_t;

void bas_pin_search_init(bas_pin_search_t *s);

/* Next PIN to try, or 0 when the space is exhausted. */
uint32_t bas_pin_search_next(bas_pin_search_t *s);

/* Tell the search what the AP said. `first_half_ok` comes from the protocol
 * distinguishing "wrong first half" from "wrong second half", which is the
 * whole reason the search is small. */
void bas_pin_search_result(bas_pin_search_t *s, bool first_half_ok);

/* How many attempts remain in the worst case. The UI shows this because
 * "10,097 left" is the number that tells an operator to go home. */
uint32_t bas_pin_search_remaining(const bas_pin_search_t *s);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_WPSPIN_H */
