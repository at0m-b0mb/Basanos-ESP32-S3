/* Basanos — SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256.
 *
 * Self-contained so the host tests can run the published RFC vectors without
 * ESP-IDF or mbedTLS. On device this is small enough not to be worth swapping
 * for the ROM implementation, and keeping one copy means the vectors that pass
 * on the host are the code that runs on the board.
 *
 * SPDX-License-Identifier: MIT
 */
#include "basanos/rbac.h"

#include <string.h>

/* --- SHA-256 (FIPS 180-4) ------------------------------------------------ */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROR(x, 2) ^ ROR(x,13) ^ ROR(x,22))
#define S1(x) (ROR(x, 6) ^ ROR(x,11) ^ ROR(x,25))
#define s0(x) (ROR(x, 7) ^ ROR(x,18) ^ ((x) >>  3))
#define s1(x) (ROR(x,17) ^ ROR(x,19) ^ ((x) >> 10))

static void sha256_compress(sha256_ctx *c, const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] <<  8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + S1(e) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = S0(a) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bitlen = 0u;
    c->buflen = 0u;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)len * 8u;
    while (len > 0u) {
        size_t take = 64u - c->buflen;
        if (take > len) {
            take = len;
        }
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64u) {
            sha256_compress(c, c->buf);
            c->buflen = 0u;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->bitlen;
    uint8_t pad = 0x80u;
    sha256_update(c, &pad, 1u);
    pad = 0x00u;
    while (c->buflen != 56u) {
        sha256_update(c, &pad, 1u);
    }
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) {
        lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    sha256_update(c, lenb, 8u);
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >>  8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

void bas_sha256(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* --- HMAC-SHA256 (RFC 2104) ---------------------------------------------- */

void bas_hmac_sha256(const void *key, size_t key_len,
                     const void *msg, size_t msg_len,
                     uint8_t out[32])
{
    uint8_t k[64];
    memset(k, 0, sizeof(k));

    if (key_len > 64u) {
        bas_sha256(key, key_len, k);
    } else if (key_len > 0u) {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        opad[i] = (uint8_t)(k[i] ^ 0x5cu);
    }

    sha256_ctx c;
    uint8_t inner[32];
    sha256_init(&c);
    sha256_update(&c, ipad, 64u);
    sha256_update(&c, msg, msg_len);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, 64u);
    sha256_update(&c, inner, 32u);
    sha256_final(&c, out);

    memset(k, 0, sizeof(k));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(inner, 0, sizeof(inner));
}

/* --- PBKDF2-HMAC-SHA256 (RFC 8018) --------------------------------------- */

void bas_pbkdf2_sha256(const void *pw, size_t pw_len,
                       const void *salt, size_t salt_len,
                       uint32_t iters, uint8_t *out, size_t out_len)
{
    if (out == NULL || out_len == 0u) {
        return;
    }
    if (iters == 0u) {
        iters = 1u;
    }

    uint8_t u[32], t[32];
    uint32_t block = 1u;
    size_t done = 0u;

    /* salt || INT_BE32(block) for the first HMAC of each block. Bounded so a
     * long salt cannot overrun; callers here use 16 bytes. */
    uint8_t saltblk[128 + 4];
    if (salt_len > sizeof(saltblk) - 4u) {
        salt_len = sizeof(saltblk) - 4u;
    }
    if (salt_len > 0u && salt != NULL) {
        memcpy(saltblk, salt, salt_len);
    }

    while (done < out_len) {
        saltblk[salt_len + 0] = (uint8_t)(block >> 24);
        saltblk[salt_len + 1] = (uint8_t)(block >> 16);
        saltblk[salt_len + 2] = (uint8_t)(block >>  8);
        saltblk[salt_len + 3] = (uint8_t)(block);

        bas_hmac_sha256(pw, pw_len, saltblk, salt_len + 4u, u);
        memcpy(t, u, 32u);

        for (uint32_t i = 1u; i < iters; i++) {
            bas_hmac_sha256(pw, pw_len, u, 32u, u);
            for (int j = 0; j < 32; j++) {
                t[j] ^= u[j];
            }
        }

        size_t take = out_len - done;
        if (take > 32u) {
            take = 32u;
        }
        memcpy(out + done, t, take);
        done += take;
        block++;
    }

    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
}
