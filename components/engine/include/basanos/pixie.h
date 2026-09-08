/* Basanos — Pixie Dust: offline WPS PIN recovery.
 *
 * The online PIN attack needs thousands of exchanges with an access point and
 * dies against any firmware that implements lockout. Pixie Dust needs ONE
 * exchange, carried only as far as M4, and then finishes offline in under a
 * second. That difference is why it is the WPS attack worth having: a router
 * with lockout enabled and a vulnerable chipset is still a total loss, and the
 * assessment that only tried the online attack would have called it fine.
 *
 * The defect it exploits is not in the protocol. It is that the registrar's
 * two secret nonces, R-S1 and R-S2, must be unpredictable, and on a large
 * family of chipsets they are not -- they are zero, or a value already sent in
 * the clear, or the output of a generator seeded from the clock. Once they are
 * known, the PIN follows from values the AP itself transmitted.
 *
 * The arithmetic:
 *
 *     PSK1    = HMAC-SHA256(AuthKey, first four PIN digits) [0..15]
 *     PSK2    = HMAC-SHA256(AuthKey, last four PIN digits)  [0..15]
 *     R-Hash1 = HMAC-SHA256(AuthKey, R-S1 || PSK1 || PKE || PKR)
 *     R-Hash2 = HMAC-SHA256(AuthKey, R-S2 || PSK2 || PKE || PKR)
 *
 * AuthKey, PKE, PKR, R-Hash1 and R-Hash2 all come out of M1..M4. So with R-S1
 * guessed, the first half of the PIN is a ten-thousand-entry search and the
 * second half is a thousand -- eleven thousand HMACs, not eleven thousand
 * radio exchanges.
 *
 * WHICH DIRECTION THIS IS, because it is not the published one.
 *
 * The classic tool attacks E-Hash1/E-Hash2: the attacker acts as an external
 * registrar and the access point is the enrollee, so the weak secrets are the
 * AP's E-S1/E-S2. Basanos cannot take that role -- the radio stack here is an
 * enrollee -- so it attacks the mirror image: the AP is the registrar, and the
 * weak secrets are its R-S1/R-S2 from M4.
 *
 * The arithmetic is identical and the generator is the same one in the same
 * firmware, so an AP weak in one direction is very likely weak in the other.
 * "Very likely" is not "certainly", and this file does not pretend otherwise:
 * a negative result here rules out the registrar path and says nothing final
 * about the enrollee path. The solver takes whichever hash pair it is given,
 * so material captured from the classic direction can be run through it
 * unchanged.
 *
 * The AP hands over M4 before it can possibly have validated the PIN -- M3 is
 * only a commitment, and the proof does not arrive until M5. So a single
 * attempt with any PIN at all yields everything above. That is why this costs
 * one exchange and not eleven thousand.
 *
 * Nothing here touches a radio. It is arithmetic on captured values, which is
 * why every part of it is checked on the host.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_PIXIE_H
#define BASANOS_PIXIE_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAS_PIXIE_DH_LEN   192   /* 1536-bit DH public key                  */
#define BAS_PIXIE_NONCE    16
#define BAS_PIXIE_HASH     32

/* Everything the attack needs, all of it observed during M1..M4. */
typedef struct {
    uint8_t authkey[BAS_PIXIE_HASH];
    uint8_t pke[BAS_PIXIE_DH_LEN];        /* enrollee public key, our own   */
    uint8_t pkr[BAS_PIXIE_DH_LEN];        /* registrar public key, from M2  */
    uint8_t enonce[BAS_PIXIE_NONCE];      /* our nonce, sent in M1          */
    uint8_t rnonce[BAS_PIXIE_NONCE];      /* registrar nonce, from M2       */
    uint8_t rhash1[BAS_PIXIE_HASH];       /* from M4                        */
    uint8_t rhash2[BAS_PIXIE_HASH];
} bas_pixie_in_t;

/* Which weakness produced the answer. This is the finding: "the PIN was
 * recovered" is a result, but "the registrar's secret nonces were zero" is
 * the sentence that explains why the router must be replaced or patched. */
typedef enum {
    BAS_PIXIE_NONE = 0,
    BAS_PIXIE_ZERO,        /* both secret nonces were all-zero              */
    BAS_PIXIE_ENONCE,      /* reused the enrollee nonce, sent in clear      */
    BAS_PIXIE_RNONCE,      /* reused its own nonce, sent in clear           */
    BAS_PIXIE_PRNG_TIME,   /* clock-seeded generator, state recovered       */
} bas_pixie_vuln_t;

const char *bas_pixie_vuln_name(bas_pixie_vuln_t v);

/* One line for a report explaining what the defect actually is. */
const char *bas_pixie_vuln_detail(bas_pixie_vuln_t v);

typedef struct {
    bool             found;
    uint32_t         pin;        /* eight digits, checksum included         */
    bas_pixie_vuln_t vuln;
    uint32_t         tried;      /* HMACs performed, for the operator       */
} bas_pixie_out_t;

/* Recover the first four PIN digits given a candidate R-S1.
 *
 * Returns 0..9999, or -1 when no first half reproduces R-Hash1 -- which is
 * the normal answer for an access point that generates its nonces properly,
 * and must never be reported as anything but "not vulnerable". */
int bas_pixie_first_half(const bas_pixie_in_t *in,
                         const uint8_t rs1[BAS_PIXIE_NONCE]);

/* The last four digits, given the first half and a candidate R-S2. The eighth
 * digit is the specification's checksum, so only a thousand values are legal
 * rather than ten thousand. Returns 0..9999 as the four digits, or -1. */
int bas_pixie_second_half(const bas_pixie_in_t *in,
                          const uint8_t rs2[BAS_PIXIE_NONCE],
                          uint16_t first_half);

/* Try every known weak-nonce class in order of how cheap it is to rule out.
 *
 * A negative result here is a real finding and should be reported as one: it
 * means the registrar's nonces were not any of the values a broken
 * implementation produces. It does NOT mean the PIN is unrecoverable by other
 * means, and the caller must not paraphrase it that way. */
void bas_pixie_run(const bas_pixie_in_t *in, bas_pixie_out_t *out);

/* --- the clock-seeded generator --------------------------------------------

   Some registrars seed the standard C library generator from the current time
   and then draw the enrollee nonce and both secret nonces from it back to
   back. The nonce is transmitted in the clear, so it identifies the seed --
   and the seed yields the secrets.

   This is glibc's additive-feedback generator restated, because that is the
   one those firmwares link against.
   ------------------------------------------------------------------------- */

typedef struct {
    int32_t  r[344];
    unsigned idx;
} bas_glibc_rng_t;

void     bas_glibc_srand(bas_glibc_rng_t *g, uint32_t seed);
uint32_t bas_glibc_rand(bas_glibc_rng_t *g);

/* Fill `out` with `n` bytes as that generator's low byte per draw, which is
 * how the vulnerable firmwares build a nonce. */
void bas_glibc_bytes(bas_glibc_rng_t *g, uint8_t *out, size_t n);

/* How many seeds bas_pixie_run sweeps for the clock-seeded class.
 *
 * This covers a registrar whose clock starts at zero -- its seed is then just
 * its uptime in seconds, and 262,144 of them is about three days. A registrar
 * with real time has a seed near the true epoch, which the device has no way
 * to know, so that case is out of reach here and the result says so rather
 * than reporting "not vulnerable". */
#define BAS_PIXIE_SEED_SWEEP  262144u

/* Search a window of seeds for one whose first draw reproduces the observed
 * enrollee nonce. Returns the seed, or 0 when the window holds none. */
uint32_t bas_pixie_find_seed(const uint8_t enonce[BAS_PIXIE_NONCE],
                             uint32_t from, uint32_t to);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_PIXIE_H */
