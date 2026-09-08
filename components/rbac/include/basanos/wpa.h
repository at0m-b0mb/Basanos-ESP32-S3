/* Basanos — WPA2 passphrase strength assessment.
 *
 * What this is for, and what it deliberately is not.
 *
 * A wireless assessment is expected to answer "is the passphrase any good".
 * The usual way is to capture a four-way handshake and take it away to a
 * cracking rig, which leaves the tester holding material that recovers the
 * client's network password — a custody problem that outlives the engagement.
 *
 * This does the test on the device and keeps nothing. A captured handshake is
 * held in RAM only, tested against a list of passphrases that are weak by
 * construction, and then wiped. The finding is the output; the handshake is
 * not. Nothing here writes key material to the card, the console or the log.
 *
 * It cannot recover a strong passphrase and is not meant to. Exhausting a few
 * thousand candidates says one useful thing — that the passphrase was NOT one
 * of the obvious ones — and the report says exactly that rather than implying
 * the key is strong.
 *
 * The maths is standard: PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 256),
 * PTK = PRF-512(PMK, "Pairwise key expansion", ...), and the candidate is
 * confirmed by recomputing the MIC over EAPOL message 2.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_WPA_H
#define BASANOS_WPA_H

#include "basanos/basanos.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- primitives, exposed so the host tests can run published vectors ------ */

void bas_sha1(const void *data, size_t len, uint8_t out[20]);
void bas_hmac_sha1(const void *key, size_t key_len,
                   const void *msg, size_t msg_len, uint8_t out[20]);
void bas_pbkdf2_sha1(const void *pw, size_t pw_len,
                     const void *salt, size_t salt_len,
                     uint32_t iters, uint8_t *out, size_t out_len);

/* --- the handshake -------------------------------------------------------- */

#define BAS_EAPOL_MAX 256

typedef struct {
    bool     have_m1;
    bool     have_m2;
    uint8_t  ssid[33];
    uint8_t  ssid_len;
    uint8_t  ap[6];          /* authenticator                               */
    uint8_t  sta[6];         /* supplicant                                  */
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  mic[16];        /* the MIC carried in message 2                */
    uint8_t  key_ver;        /* 1 = MD5/RC4 (WPA), 2 = SHA1/CCMP (WPA2)     */
    uint8_t  m2[BAS_EAPOL_MAX];  /* message 2 with its MIC field zeroed     */
    uint16_t m2_len;
} bas_handshake_t;

void bas_wpa_reset(bas_handshake_t *h);

/* True once both halves are present and the pair can be tested. */
bool bas_wpa_complete(const bas_handshake_t *h);

/* Wipe every byte of key material. Called the moment an audit finishes,
 * whatever the outcome. */
void bas_wpa_wipe(bas_handshake_t *h);

/* Derive the pairwise master key for one candidate passphrase. This is the
 * expensive step: 4096 iterations of HMAC-SHA1 per candidate, which is what
 * makes an exhaustive search impossible on a microcontroller and a
 * weak-password check entirely practical. */
void bas_wpa_pmk(const char *passphrase, const uint8_t *ssid, size_t ssid_len,
                 uint8_t pmk[32]);

/* True when this passphrase reproduces the captured MIC. */
bool bas_wpa_check(const bas_handshake_t *h, const char *passphrase);

/* --- the audit ------------------------------------------------------------ */

typedef enum {
    BAS_PSK_UNTESTED = 0,
    BAS_PSK_WEAK,        /* a candidate matched — the passphrase is guessable */
    BAS_PSK_SURVIVED,    /* the list was exhausted without a match            */
} bas_psk_verdict_t;

typedef struct {
    bas_psk_verdict_t verdict;
    uint32_t          tried;
    uint32_t          elapsed_ms;
    char              found[64];   /* only set when the verdict is WEAK      */
} bas_psk_result_t;

/* The built-in list: passphrases that are weak by construction — defaults,
 * keyboard walks, and the handful that appear at the top of every breach
 * corpus. Deliberately small. This is a strength check, not a cracker, and a
 * larger list would change what the tool is. */
const char *bas_psk_candidate(uint32_t i);
uint32_t    bas_psk_candidate_count(void);

const char *bas_psk_verdict_name(bas_psk_verdict_t v);

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_WPA_H */
