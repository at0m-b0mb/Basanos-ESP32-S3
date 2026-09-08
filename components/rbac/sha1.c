/* Basanos — SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1.
 *
 * Needed only for WPA2 key derivation, which specifies SHA-1 and cannot be
 * given a better hash. It is not used for anything Basanos itself protects:
 * the device's own credentials go through PBKDF2-HMAC-SHA256 in rbac.c.
 *
 * SPDX-License-Identifier: MIT
 */
#include "basanos/wpa.h"

#include <string.h>

/* --- SHA-1 (FIPS 180-4) --------------------------------------------------- */

typedef struct {
    uint32_t state[5];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha1_ctx;

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_compress(sha1_ctx *c, const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = c->state[0], b = c->state[1], d = c->state[2];
    uint32_t e = c->state[3], f = c->state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t k, t;
        if (i < 20)      { t = (b & d) | (~b & e);            k = 0x5A827999u; }
        else if (i < 40) { t = b ^ d ^ e;                     k = 0x6ED9EBA1u; }
        else if (i < 60) { t = (b & d) | (b & e) | (d & e);   k = 0x8F1BBCDCu; }
        else             { t = b ^ d ^ e;                     k = 0xCA62C1D6u; }

        uint32_t tmp = ROL(a, 5) + t + f + k + w[i];
        f = e; e = d; d = ROL(b, 30); b = a; a = tmp;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += d;
    c->state[3] += e; c->state[4] += f;
}

static void sha1_init(sha1_ctx *c)
{
    c->state[0] = 0x67452301u; c->state[1] = 0xEFCDAB89u;
    c->state[2] = 0x98BADCFEu; c->state[3] = 0x10325476u;
    c->state[4] = 0xC3D2E1F0u;
    c->bitlen = 0u;
    c->buflen = 0u;
}

static void sha1_update(sha1_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)len * 8u;
    while (len > 0u) {
        size_t take = 64u - c->buflen;
        if (take > len) { take = len; }
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64u) {
            sha1_compress(c, c->buf);
            c->buflen = 0u;
        }
    }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20])
{
    uint64_t bits = c->bitlen;
    uint8_t pad = 0x80u;
    sha1_update(c, &pad, 1u);
    pad = 0x00u;
    while (c->buflen != 56u) {
        sha1_update(c, &pad, 1u);
    }
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) {
        lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    sha1_update(c, lenb, 8u);
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

void bas_sha1(const void *data, size_t len, uint8_t out[20])
{
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, data, len);
    sha1_final(&c, out);
}

/* --- HMAC-SHA1 ------------------------------------------------------------ */

void bas_hmac_sha1(const void *key, size_t key_len,
                   const void *msg, size_t msg_len, uint8_t out[20])
{
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64u) {
        bas_sha1(key, key_len, k);
    } else if (key_len > 0u) {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64], inner[20];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        opad[i] = (uint8_t)(k[i] ^ 0x5Cu);
    }

    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, ipad, 64u);
    sha1_update(&c, msg, msg_len);
    sha1_final(&c, inner);

    sha1_init(&c);
    sha1_update(&c, opad, 64u);
    sha1_update(&c, inner, 20u);
    sha1_final(&c, out);

    memset(k, 0, sizeof(k));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(inner, 0, sizeof(inner));
}

/* --- PBKDF2-HMAC-SHA1 ----------------------------------------------------- */

void bas_pbkdf2_sha1(const void *pw, size_t pw_len,
                     const void *salt, size_t salt_len,
                     uint32_t iters, uint8_t *out, size_t out_len)
{
    if (out == NULL || out_len == 0u) {
        return;
    }
    if (iters == 0u) {
        iters = 1u;
    }

    uint8_t u[20], t[20];
    uint8_t saltblk[64 + 4];
    if (salt_len > sizeof(saltblk) - 4u) {
        salt_len = sizeof(saltblk) - 4u;
    }
    if (salt_len > 0u && salt != NULL) {
        memcpy(saltblk, salt, salt_len);
    }

    uint32_t block = 1u;
    size_t done = 0u;
    while (done < out_len) {
        saltblk[salt_len]     = (uint8_t)(block >> 24);
        saltblk[salt_len + 1] = (uint8_t)(block >> 16);
        saltblk[salt_len + 2] = (uint8_t)(block >> 8);
        saltblk[salt_len + 3] = (uint8_t)(block);

        bas_hmac_sha1(pw, pw_len, saltblk, salt_len + 4u, u);
        memcpy(t, u, 20u);

        for (uint32_t i = 1u; i < iters; i++) {
            bas_hmac_sha1(pw, pw_len, u, 20u, u);
            for (int j = 0; j < 20; j++) {
                t[j] ^= u[j];
            }
        }

        size_t take = out_len - done;
        if (take > 20u) { take = 20u; }
        memcpy(out + done, t, take);
        done += take;
        block++;
    }

    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
}
