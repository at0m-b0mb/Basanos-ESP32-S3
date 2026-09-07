/* Basanos — roles, the user table, and password verification.
 * SPDX-License-Identifier: MIT */
#include "basanos/rbac.h"

#include <string.h>

const char *bas_role_name(bas_role_t r)
{
    switch (r) {
    case BAS_ROLE_VIEWER:   return "viewer";
    case BAS_ROLE_OPERATOR: return "operator";
    case BAS_ROLE_ADMIN:    return "admin";
    default:                return "?";
    }
}

bool bas_rbac_can(bas_role_t role, bas_cap_t cap)
{
    switch (cap) {
    case BAS_CAP_VIEW:
        return role >= BAS_ROLE_VIEWER;
    case BAS_CAP_RUN_BENIGN:
    case BAS_CAP_RUN_ACTIVE:
        return role >= BAS_ROLE_OPERATOR;
    case BAS_CAP_RUN_DISRUPTIVE:
    case BAS_CAP_MANAGE_USERS:
    case BAS_CAP_EXPORT_LOG:
        return role >= BAS_ROLE_ADMIN;
    default:
        /* Unknown capability denies. A capability added to the enum without a
         * decision here must not silently become available to everyone. */
        return false;
    }
}

void bas_rbac_init(bas_userdb_t *db)
{
    if (db == NULL) {
        return;
    }
    memset(db, 0, sizeof(*db));
}

static int find_slot(const bas_userdb_t *db, const char *name)
{
    for (int i = 0; i < BAS_MAX_USERS; i++) {
        if (db->u[i].used && strncmp(db->u[i].name, name, BAS_USER_NAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}

static bool has_content(const char *s)
{
    return s != NULL && s[0] != '\0';
}

bas_err_t bas_rbac_add(bas_userdb_t *db,
                       const char *name,
                       const char *password,
                       bas_role_t role,
                       const uint8_t salt[BAS_SALT_LEN],
                       uint32_t iters)
{
    if (db == NULL || !has_content(name) || !has_content(password) || salt == NULL) {
        return BAS_ERR_ARG;
    }
    if (role != BAS_ROLE_VIEWER && role != BAS_ROLE_OPERATOR && role != BAS_ROLE_ADMIN) {
        return BAS_ERR_ARG;
    }
    if (find_slot(db, name) >= 0) {
        return BAS_ERR_EXISTS;
    }

    int slot = -1;
    for (int i = 0; i < BAS_MAX_USERS; i++) {
        if (!db->u[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        return BAS_ERR_NO_SPACE;
    }

    if (iters == 0u) {
        iters = BAS_PBKDF2_ITERS_DEFAULT;
    }

    bas_user_t *u = &db->u[slot];
    memset(u, 0, sizeof(*u));
    (void)bas_strlcpy(u->name, name, sizeof(u->name));
    memcpy(u->salt, salt, BAS_SALT_LEN);
    u->iters = iters;
    u->role  = role;
    bas_pbkdf2_sha256(password, strlen(password), u->salt, BAS_SALT_LEN,
                      iters, u->hash, BAS_HASH_LEN);
    u->used = true;
    return BAS_OK;
}

bas_err_t bas_rbac_remove(bas_userdb_t *db, const char *name)
{
    if (db == NULL || !has_content(name)) {
        return BAS_ERR_ARG;
    }
    int slot = find_slot(db, name);
    if (slot < 0) {
        return BAS_ERR_AUTH;
    }

    /* Removing the last admin would leave a device nobody can administer and,
     * worse, one where the disruptive families are unreachable but the log
     * cannot be exported either. Refuse. */
    if (db->u[slot].role == BAS_ROLE_ADMIN) {
        int admins = 0;
        for (int i = 0; i < BAS_MAX_USERS; i++) {
            if (db->u[i].used && db->u[i].role == BAS_ROLE_ADMIN) {
                admins++;
            }
        }
        if (admins <= 1) {
            return BAS_ERR_ROLE;
        }
    }

    memset(&db->u[slot], 0, sizeof(db->u[slot]));
    return BAS_OK;
}

bas_err_t bas_rbac_auth(bas_userdb_t *db,
                        const char *name,
                        const char *password,
                        uint32_t now_ms,
                        bas_role_t *out_role)
{
    if (db == NULL || !has_content(name) || password == NULL) {
        return BAS_ERR_ARG;
    }

    int slot = find_slot(db, name);

    /* An unknown user must cost what a known one costs. Derive against a
     * fixed dummy salt so the work — and therefore the response time — does
     * not disclose which names exist. */
    static const uint8_t k_dummy_salt[BAS_SALT_LEN] = {
        0x42,0x61,0x73,0x61,0x6e,0x6f,0x73,0x2d,
        0x64,0x75,0x6d,0x6d,0x79,0x2d,0x76,0x31
    };
    const uint8_t *salt  = (slot >= 0) ? db->u[slot].salt : k_dummy_salt;
    uint32_t       iters = (slot >= 0) ? db->u[slot].iters : BAS_PBKDF2_ITERS_DEFAULT;

    if (slot >= 0) {
        bas_user_t *u = &db->u[slot];
        if (u->lock_until_ms != 0u && (int32_t)(now_ms - u->lock_until_ms) < 0) {
            return BAS_ERR_LOCKED_OUT;
        }
        if (u->lock_until_ms != 0u) {
            /* Cool-off elapsed. Clear it and give a fresh set of attempts. */
            u->lock_until_ms = 0u;
            u->fails = 0u;
        }
    }

    uint8_t derived[BAS_HASH_LEN];
    bas_pbkdf2_sha256(password, strlen(password), salt, BAS_SALT_LEN,
                      iters, derived, BAS_HASH_LEN);

    if (slot < 0) {
        memset(derived, 0, sizeof(derived));
        return BAS_ERR_AUTH;
    }

    bas_user_t *u = &db->u[slot];
    bool ok = bas_ct_eq(derived, u->hash, BAS_HASH_LEN);
    memset(derived, 0, sizeof(derived));

    if (!ok) {
        if (u->fails < 255u) {
            u->fails++;
        }
        if (u->fails >= BAS_LOCKOUT_FAILS) {
            u->lock_until_ms = now_ms + BAS_LOCKOUT_MS;
            /* Non-zero even if the tick counter is at 0, so the "is locked"
             * test above never misreads a fresh boot as unlocked. */
            if (u->lock_until_ms == 0u) {
                u->lock_until_ms = 1u;
            }
            return BAS_ERR_LOCKED_OUT;
        }
        return BAS_ERR_AUTH;
    }

    u->fails = 0u;
    u->lock_until_ms = 0u;
    if (out_role != NULL) {
        *out_role = u->role;
    }
    return BAS_OK;
}

int bas_rbac_count(const bas_userdb_t *db)
{
    if (db == NULL) {
        return 0;
    }
    int n = 0;
    for (int i = 0; i < BAS_MAX_USERS; i++) {
        if (db->u[i].used) {
            n++;
        }
    }
    return n;
}

const bas_user_t *bas_rbac_get(const bas_userdb_t *db, const char *name)
{
    if (db == NULL || !has_content(name)) {
        return NULL;
    }
    int slot = find_slot(db, name);
    return (slot >= 0) ? &db->u[slot] : NULL;
}

bool bas_rbac_has_admin(const bas_userdb_t *db)
{
    if (db == NULL) {
        return false;
    }
    for (int i = 0; i < BAS_MAX_USERS; i++) {
        if (db->u[i].used && db->u[i].role == BAS_ROLE_ADMIN) {
            return true;
        }
    }
    return false;
}
