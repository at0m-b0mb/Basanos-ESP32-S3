/* Basanos — common types and result codes.
 *
 * Pure C11. This header, and everything in components/engine, components/rbac
 * and components/score, must build with a plain host compiler and must not
 * include a single ESP-IDF header. That is what makes the judgement testable.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_H
#define BASANOS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BAS_VERSION_MAJOR 0
#define BAS_VERSION_MINOR 1
#define BAS_VERSION_PATCH 0

/* Every refusal in Basanos has a name. The UI prints these verbatim, because
 * "it did not fire" is a bug report and "target not locked" is an instruction. */
typedef enum {
    BAS_OK = 0,

    /* target / engagement */
    BAS_ERR_NO_TARGET,        /* nothing selected from the scan            */
    BAS_ERR_NOT_LOCKED,       /* selected but not confirmed by the operator*/
    BAS_ERR_EXPIRED,          /* engagement TTL ran out                    */
    BAS_ERR_BROADCAST,        /* refused: broadcast/multicast destination   */
    BAS_ERR_SELF,             /* refused: target is this device            */
    BAS_ERR_BAD_BSSID,        /* all-zero or otherwise unusable BSSID      */
    BAS_ERR_NO_LABEL,         /* engagement label is required before arming*/

    /* access control */
    BAS_ERR_ROLE,             /* the operator's role does not permit this  */
    BAS_ERR_AUTH,             /* bad username or password                  */
    BAS_ERR_LOCKED_OUT,       /* too many failures, cooling off            */
    BAS_ERR_NO_SPACE,         /* user table full                           */
    BAS_ERR_EXISTS,           /* duplicate user name                       */

    /* plans and bounds */
    BAS_ERR_UNKNOWN_FAMILY,
    BAS_ERR_RATE,             /* requested rate above the family ceiling   */
    BAS_ERR_DURATION,         /* requested run longer than the ceiling     */
    BAS_ERR_CHANNEL,          /* channel outside the regulatory clamp      */

    /* scorecard */
    BAS_ERR_NO_RUN,
    BAS_ERR_RUN_CLOSED,
    BAS_ERR_FULL,

    BAS_ERR_ARG,              /* caller passed nonsense                    */
    BAS_ERR__COUNT
} bas_err_t;

/* Human-readable, stable, and short enough for a 240px line. */
const char *bas_err_str(bas_err_t e);

/* --- small helpers shared across components ------------------------------ */

/* A MAC that must never be a destination: broadcast or any multicast (LSB of
 * the first octet set). Basanos refuses these everywhere, at every role. */
bool bas_mac_is_broadcast(const uint8_t mac[6]);
bool bas_mac_is_zero(const uint8_t mac[6]);
bool bas_mac_eq(const uint8_t a[6], const uint8_t b[6]);

/* "AA:BB:CC:DD:EE:FF" — out must hold at least 18 bytes. */
void bas_mac_fmt(const uint8_t mac[6], char *out, size_t out_len);

/* Bounded string copy that always terminates. Returns false if it truncated. */
bool bas_strlcpy(char *dst, const char *src, size_t dst_sz);

/* Constant-time equality over n bytes. Used for secrets; do not replace with
 * memcmp, and do not "optimise" the early exit back in. */
bool bas_ct_eq(const void *a, const void *b, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_H */
