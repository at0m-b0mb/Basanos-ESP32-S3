/* Basanos — RBAC, and the crypto underneath it against published vectors.
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/rbac.h"

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2 + 0] = d[b[i] >> 4];
        out[i * 2 + 1] = d[b[i] & 0x0fu];
    }
    out[n * 2] = '\0';
}

static const uint8_t k_salt[BAS_SALT_LEN] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
};

/* Keep the test suite fast: the derivation cost is asserted separately by the
 * vector tests, and the RBAC logic does not depend on the iteration count. */
#define FAST_ITERS 64u

void suite_rbac(void)
{
    SUITE("rbac: SHA-256 published vectors (FIPS 180-4)");

    uint8_t h[32];
    char s[65];

    bas_sha256("", 0, h);
    hex(h, 32, s);
    CHECK_STR(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    bas_sha256("abc", 3, h);
    hex(h, 32, s);
    CHECK_STR(s, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    bas_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, h);
    hex(h, 32, s);
    CHECK_STR(s, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    SUITE("rbac: HMAC-SHA256 published vectors (RFC 4231)");

    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    bas_hmac_sha256(key1, sizeof(key1), "Hi There", 8, h);
    hex(h, 32, s);
    CHECK_STR(s, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    bas_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, h);
    hex(h, 32, s);
    CHECK_STR(s, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    SUITE("rbac: PBKDF2-HMAC-SHA256 published vectors (RFC 7914)");

    uint8_t dk[32];
    bas_pbkdf2_sha256("password", 8, "salt", 4, 1, dk, sizeof(dk));
    hex(dk, 32, s);
    CHECK_STR(s, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

    bas_pbkdf2_sha256("password", 8, "salt", 4, 2, dk, sizeof(dk));
    hex(dk, 32, s);
    CHECK_STR(s, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");

    bas_pbkdf2_sha256("password", 8, "salt", 4, 4096, dk, sizeof(dk));
    hex(dk, 32, s);
    CHECK_STR(s, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

    SUITE("rbac: capability matrix");

    CHECK(bas_rbac_can(BAS_ROLE_VIEWER,   BAS_CAP_VIEW));
    CHECK(!bas_rbac_can(BAS_ROLE_VIEWER,  BAS_CAP_RUN_BENIGN));
    CHECK(!bas_rbac_can(BAS_ROLE_VIEWER,  BAS_CAP_RUN_ACTIVE));
    CHECK(!bas_rbac_can(BAS_ROLE_VIEWER,  BAS_CAP_RUN_DISRUPTIVE));

    CHECK(bas_rbac_can(BAS_ROLE_OPERATOR, BAS_CAP_RUN_BENIGN));
    CHECK(bas_rbac_can(BAS_ROLE_OPERATOR, BAS_CAP_RUN_ACTIVE));
    CHECK(!bas_rbac_can(BAS_ROLE_OPERATOR, BAS_CAP_RUN_DISRUPTIVE));
    CHECK(!bas_rbac_can(BAS_ROLE_OPERATOR, BAS_CAP_MANAGE_USERS));
    CHECK(!bas_rbac_can(BAS_ROLE_OPERATOR, BAS_CAP_EXPORT_LOG));

    CHECK(bas_rbac_can(BAS_ROLE_ADMIN, BAS_CAP_RUN_DISRUPTIVE));
    CHECK(bas_rbac_can(BAS_ROLE_ADMIN, BAS_CAP_MANAGE_USERS));
    CHECK(bas_rbac_can(BAS_ROLE_ADMIN, BAS_CAP_EXPORT_LOG));

    /* An unrecognised capability denies rather than defaults open. */
    CHECK(!bas_rbac_can(BAS_ROLE_ADMIN, (bas_cap_t)BAS_CAP__COUNT));
    CHECK(!bas_rbac_can(BAS_ROLE_ADMIN, (bas_cap_t)999));

    SUITE("rbac: user table");

    bas_userdb_t db;
    bas_rbac_init(&db);
    CHECK_EQ(bas_rbac_count(&db), 0);
    CHECK(!bas_rbac_has_admin(&db));

    CHECK_EQ(bas_rbac_add(&db, "kailash", "correct horse", BAS_ROLE_ADMIN, k_salt, FAST_ITERS), BAS_OK);
    CHECK_EQ(bas_rbac_count(&db), 1);
    CHECK(bas_rbac_has_admin(&db));

    /* The password is never stored. */
    const bas_user_t *u = bas_rbac_get(&db, "kailash");
    CHECK(u != NULL);
    bool plaintext_found = false;
    for (size_t i = 0; u != NULL && i + 7u <= sizeof(u->hash); i++) {
        if (memcmp(&u->hash[i], "correct", 7) == 0) {
            plaintext_found = true;
        }
    }
    CHECK(!plaintext_found);

    CHECK_EQ(bas_rbac_add(&db, "kailash", "other", BAS_ROLE_VIEWER, k_salt, FAST_ITERS), BAS_ERR_EXISTS);
    CHECK_EQ(bas_rbac_add(&db, "", "x", BAS_ROLE_VIEWER, k_salt, FAST_ITERS), BAS_ERR_ARG);
    CHECK_EQ(bas_rbac_add(&db, "bob", "", BAS_ROLE_VIEWER, k_salt, FAST_ITERS), BAS_ERR_ARG);
    CHECK_EQ(bas_rbac_add(&db, "bob", "x", (bas_role_t)9, k_salt, FAST_ITERS), BAS_ERR_ARG);

    SUITE("rbac: authentication");

    bas_role_t role = BAS_ROLE_VIEWER;
    CHECK_EQ(bas_rbac_auth(&db, "kailash", "correct horse", 1000, &role), BAS_OK);
    CHECK_EQ(role, BAS_ROLE_ADMIN);

    CHECK_EQ(bas_rbac_auth(&db, "kailash", "wrong", 1000, &role), BAS_ERR_AUTH);
    /* An unknown user is indistinguishable from a wrong password. */
    CHECK_EQ(bas_rbac_auth(&db, "nobody", "anything", 1000, &role), BAS_ERR_AUTH);

    /* A success resets the counter. */
    CHECK_EQ(bas_rbac_auth(&db, "kailash", "correct horse", 1000, &role), BAS_OK);
    CHECK_EQ(bas_rbac_get(&db, "kailash")->fails, 0);

    SUITE("rbac: lockout after repeated failure, and its release");

    for (int i = 0; i < BAS_LOCKOUT_FAILS - 1; i++) {
        CHECK_EQ(bas_rbac_auth(&db, "kailash", "nope", 2000, &role), BAS_ERR_AUTH);
    }
    /* The failure that trips the lock reports the lock, not a plain refusal. */
    CHECK_EQ(bas_rbac_auth(&db, "kailash", "nope", 2000, &role), BAS_ERR_LOCKED_OUT);

    /* And the correct password does not get in while locked. */
    CHECK_EQ(bas_rbac_auth(&db, "kailash", "correct horse", 2000, &role), BAS_ERR_LOCKED_OUT);
    CHECK_EQ(bas_rbac_auth(&db, "kailash", "correct horse", 2000 + BAS_LOCKOUT_MS - 1, &role),
             BAS_ERR_LOCKED_OUT);

    /* Once the cool-off elapses the account works again — a typo must not
     * brick a field instrument. */
    CHECK_EQ(bas_rbac_auth(&db, "kailash", "correct horse", 2000 + BAS_LOCKOUT_MS, &role), BAS_OK);
    CHECK_EQ(role, BAS_ROLE_ADMIN);
    CHECK_EQ(bas_rbac_get(&db, "kailash")->fails, 0);

    SUITE("rbac: the last admin cannot be removed");

    CHECK_EQ(bas_rbac_add(&db, "sam", "pw-sam", BAS_ROLE_OPERATOR, k_salt, FAST_ITERS), BAS_OK);
    CHECK_EQ(bas_rbac_remove(&db, "kailash"), BAS_ERR_ROLE);
    CHECK(bas_rbac_has_admin(&db));

    /* With a second admin present, the first may go. */
    CHECK_EQ(bas_rbac_add(&db, "ada", "pw-ada", BAS_ROLE_ADMIN, k_salt, FAST_ITERS), BAS_OK);
    CHECK_EQ(bas_rbac_remove(&db, "kailash"), BAS_OK);
    CHECK(bas_rbac_has_admin(&db));
    CHECK_EQ(bas_rbac_count(&db), 2);

    CHECK_EQ(bas_rbac_remove(&db, "ghost"), BAS_ERR_AUTH);

    SUITE("rbac: distinct salts produce distinct hashes for one password");

    bas_userdb_t db2;
    bas_rbac_init(&db2);
    uint8_t salt_b[BAS_SALT_LEN];
    memset(salt_b, 0xAB, sizeof(salt_b));
    CHECK_EQ(bas_rbac_add(&db2, "a", "same-password", BAS_ROLE_VIEWER, k_salt, FAST_ITERS), BAS_OK);
    CHECK_EQ(bas_rbac_add(&db2, "b", "same-password", BAS_ROLE_VIEWER, salt_b, FAST_ITERS), BAS_OK);
    CHECK(memcmp(bas_rbac_get(&db2, "a")->hash,
                 bas_rbac_get(&db2, "b")->hash, BAS_HASH_LEN) != 0);

    SUITE("rbac: table full");

    bas_userdb_t db3;
    bas_rbac_init(&db3);
    char name[8];
    for (int i = 0; i < BAS_MAX_USERS; i++) {
        snprintf(name, sizeof(name), "u%d", i);
        CHECK_EQ(bas_rbac_add(&db3, name, "pw", BAS_ROLE_VIEWER, k_salt, FAST_ITERS), BAS_OK);
    }
    CHECK_EQ(bas_rbac_add(&db3, "one-more", "pw", BAS_ROLE_VIEWER, k_salt, FAST_ITERS), BAS_ERR_NO_SPACE);
    CHECK_EQ(bas_rbac_count(&db3), BAS_MAX_USERS);
}
