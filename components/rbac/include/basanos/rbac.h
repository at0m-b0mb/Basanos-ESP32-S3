/* Basanos — role-based access control.
 *
 * Three roles. The split that matters is that OPERATOR can run everything
 * that does not deny service, and only ADMIN can reach the two families that
 * do. A shared team device with no roles is a device where anyone who picks
 * it up can transmit.
 *
 * RBAC answers "who may press the button". It is not, and cannot be, a control
 * on *which network* may be tested — that is the engagement lock in engage.h.
 * Both are required; neither substitutes for the other.
 *
 * Password verification is PBKDF2-HMAC-SHA256 with a per-user salt, a
 * constant-time compare, and a failure lockout. No credential is shipped: the
 * device generates its own admin password on first boot and shows it on the
 * screen.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_RBAC_H
#define BASANOS_RBAC_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BAS_ROLE_VIEWER   = 0,   /* read results and audit log; transmits nothing */
    BAS_ROLE_OPERATOR = 1,   /* benign + active families                      */
    BAS_ROLE_ADMIN    = 2    /* + disruptive families, users, log export      */
} bas_role_t;

const char *bas_role_name(bas_role_t r);

typedef enum {
    BAS_CAP_VIEW = 0,
    BAS_CAP_RUN_BENIGN,
    BAS_CAP_RUN_ACTIVE,
    BAS_CAP_RUN_DISRUPTIVE,
    BAS_CAP_MANAGE_USERS,
    BAS_CAP_EXPORT_LOG,
    BAS_CAP__COUNT
} bas_cap_t;

bool bas_rbac_can(bas_role_t role, bas_cap_t cap);

/* --- user table ---------------------------------------------------------- */

#define BAS_USER_NAME_MAX 24
#define BAS_MAX_USERS      8
#define BAS_SALT_LEN      16
#define BAS_HASH_LEN      32

/* Deliberately low for a 240 MHz MCU that must stay responsive while an
 * operator waits: enough to make an offline guess expensive, not so much that
 * unlocking the device takes a visible pause. Tunable per-user on creation. */
#define BAS_PBKDF2_ITERS_DEFAULT 20000u

/* Five wrong passwords costs a minute. Basanos does not escalate beyond this:
 * an unbounded lockout on a field device turns a typo into a dead instrument. */
#define BAS_LOCKOUT_FAILS    5
#define BAS_LOCKOUT_MS   (60u * 1000u)

typedef struct {
    bool       used;
    char       name[BAS_USER_NAME_MAX];
    uint8_t    salt[BAS_SALT_LEN];
    uint8_t    hash[BAS_HASH_LEN];
    uint32_t   iters;
    bas_role_t role;
    uint8_t    fails;
    uint32_t   lock_until_ms;
} bas_user_t;

typedef struct {
    bas_user_t u[BAS_MAX_USERS];
} bas_userdb_t;

void bas_rbac_init(bas_userdb_t *db);

/* Add a user. `salt` must be BAS_SALT_LEN bytes of real entropy from the
 * caller (on device: esp_fill_random; in tests: a fixed vector). Refuses
 * duplicate names, an empty name or password, and a full table. */
bas_err_t bas_rbac_add(bas_userdb_t *db,
                       const char *name,
                       const char *password,
                       bas_role_t role,
                       const uint8_t salt[BAS_SALT_LEN],
                       uint32_t iters);

bas_err_t bas_rbac_remove(bas_userdb_t *db, const char *name);

/* Verify a password.
 *
 * On success: resets the failure counter and writes the role to `out_role`.
 * On failure: increments the counter and, at BAS_LOCKOUT_FAILS, sets a cool-off
 * and returns BAS_ERR_LOCKED_OUT for the duration.
 *
 * An unknown user costs the same work as a known one with a wrong password —
 * the lookup does not short-circuit, so the response time does not disclose
 * which names exist. */
bas_err_t bas_rbac_auth(bas_userdb_t *db,
                        const char *name,
                        const char *password,
                        uint32_t now_ms,
                        bas_role_t *out_role);

int bas_rbac_count(const bas_userdb_t *db);
const bas_user_t *bas_rbac_get(const bas_userdb_t *db, const char *name);

/* True when at least one admin exists. The device refuses to leave setup until
 * this holds, and refuses to remove the last admin. */
bool bas_rbac_has_admin(const bas_userdb_t *db);

/* --- primitives (exposed so the host tests can run published vectors) ----- */

void bas_sha256(const void *data, size_t len, uint8_t out[32]);
void bas_hmac_sha256(const void *key, size_t key_len,
                     const void *msg, size_t msg_len,
                     uint8_t out[32]);
void bas_pbkdf2_sha256(const void *pw, size_t pw_len,
                       const void *salt, size_t salt_len,
                       uint32_t iters, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_RBAC_H */
