/* Basanos — WPA2 passphrase strength assessment.
 * SPDX-License-Identifier: MIT */
#include "basanos/wpa.h"

#include <string.h>

void bas_wpa_reset(bas_handshake_t *h)
{
    if (h != NULL) {
        memset(h, 0, sizeof(*h));
    }
}

bool bas_wpa_complete(const bas_handshake_t *h)
{
    /* Both halves, a name to salt with, and a version whose MIC this code can
     * actually recompute. */
    return h != NULL && h->have_m1 && h->have_m2 &&
           h->ssid_len > 0u && h->m2_len > 0u && h->key_ver == 2u;
}

void bas_wpa_wipe(bas_handshake_t *h)
{
    if (h == NULL) {
        return;
    }
    /* volatile so the compiler cannot decide a struct about to go out of
     * scope need not actually be cleared. */
    volatile uint8_t *p = (volatile uint8_t *)h;
    for (size_t i = 0; i < sizeof(*h); i++) {
        p[i] = 0u;
    }
}

void bas_wpa_pmk(const char *passphrase, const uint8_t *ssid, size_t ssid_len,
                 uint8_t pmk[32])
{
    if (passphrase == NULL || pmk == NULL) {
        return;
    }
    /* The standard: 4096 iterations, the SSID as salt. This is the entire
     * cost of a candidate, and it is why an exhaustive search is hopeless on
     * a microcontroller while a weak-password list is quick. */
    bas_pbkdf2_sha1(passphrase, strlen(passphrase), ssid, ssid_len,
                    4096u, pmk, 32u);
}

/* IEEE 802.11 PRF, SHA-1 flavour: repeated HMAC over
 * label || 0x00 || data || counter. */
static void sha1_prf(const uint8_t *key, size_t klen, const char *label,
                     const uint8_t *data, size_t dlen,
                     uint8_t *out, size_t olen)
{
    uint8_t buf[128];
    size_t llen = strlen(label);
    if (llen + 1u + dlen + 1u > sizeof(buf)) {
        return;
    }

    uint8_t counter = 0u;
    size_t pos = 0u;
    while (pos < olen) {
        memcpy(buf, label, llen);
        buf[llen] = 0u;
        memcpy(buf + llen + 1u, data, dlen);
        buf[llen + 1u + dlen] = counter;

        uint8_t digest[20];
        bas_hmac_sha1(key, klen, buf, llen + 1u + dlen + 1u, digest);

        size_t take = olen - pos;
        if (take > 20u) { take = 20u; }
        memcpy(out + pos, digest, take);
        pos += take;
        counter++;
        memset(digest, 0, sizeof(digest));
    }
    memset(buf, 0, sizeof(buf));
}

bool bas_wpa_check(const bas_handshake_t *h, const char *passphrase)
{
    if (!bas_wpa_complete(h) || passphrase == NULL) {
        return false;
    }
    size_t plen = strlen(passphrase);
    /* WPA2 passphrases are 8..63 characters. A candidate outside that could
     * never have been configured, so testing it wastes 4096 iterations. */
    if (plen < 8u || plen > 63u) {
        return false;
    }

    uint8_t pmk[32];
    bas_wpa_pmk(passphrase, h->ssid, h->ssid_len, pmk);

    /* The PRF input pairs the two addresses and the two nonces in a fixed
     * order, so both ends derive the same key without agreeing who is who. */
    uint8_t data[76];
    const uint8_t *a1 = h->ap, *a2 = h->sta;
    if (memcmp(h->ap, h->sta, 6) > 0) {
        a1 = h->sta; a2 = h->ap;
    }
    memcpy(&data[0], a1, 6);
    memcpy(&data[6], a2, 6);

    const uint8_t *n1 = h->anonce, *n2 = h->snonce;
    if (memcmp(h->anonce, h->snonce, 32) > 0) {
        n1 = h->snonce; n2 = h->anonce;
    }
    memcpy(&data[12], n1, 32);
    memcpy(&data[44], n2, 32);

    uint8_t ptk[64];
    sha1_prf(pmk, 32u, "Pairwise key expansion", data, sizeof(data),
             ptk, sizeof(ptk));

    /* The MIC is computed with the first 16 bytes of the PTK -- the key
     * confirmation key -- over message 2 with its own MIC field zeroed. */
    uint8_t mic[20];
    bas_hmac_sha1(ptk, 16u, h->m2, h->m2_len, mic);

    bool ok = bas_ct_eq(mic, h->mic, 16u);

    /* Nothing derived from a candidate outlives the check. */
    memset(pmk, 0, sizeof(pmk));
    memset(ptk, 0, sizeof(ptk));
    memset(mic, 0, sizeof(mic));
    memset(data, 0, sizeof(data));
    return ok;
}

const char *bas_psk_verdict_name(bas_psk_verdict_t v)
{
    switch (v) {
    case BAS_PSK_WEAK:     return "WEAK";
    case BAS_PSK_SURVIVED: return "SURVIVED";
    default:               return "UNTESTED";
    }
}

/* Passphrases that are weak by construction: router defaults, keyboard walks,
 * dates, and the handful that top every breach corpus.
 *
 * Deliberately small. This is a strength check and not a cracker, and a larger
 * list would change what the tool is -- as well as what it takes to carry one
 * across a border. Everything here is at least eight characters, because
 * anything shorter cannot be a WPA2 passphrase. */
static const char *const k_weak[] = {
    "password", "password1", "password123", "Password1", "Password123",
    "12345678", "123456789", "1234567890", "123123123", "111111111",
    "000000000", "88888888", "1qaz2wsx", "qwertyuiop", "qwerty123",
    "asdfghjkl", "zxcvbnm123", "1q2w3e4r", "1q2w3e4r5t", "q1w2e3r4",
    "abc12345", "abcd1234", "a1b2c3d4", "letmein1", "letmein123",
    "welcome1", "welcome123", "iloveyou", "iloveyou1", "princess1",
    "sunshine1", "football1", "baseball1", "superman1", "batman123",
    "trustno1", "starwars1", "pokemon123", "michael1", "jennifer1",
    "internet", "internet1", "wireless", "wireless1", "wifipassword",
    "password!", "P@ssw0rd", "P@ssword1", "Passw0rd!", "Adm1n123",
    "administrator", "admin1234", "admin12345", "administrator1",
    "changeme", "changeme1", "changeme123", "default1", "defaultpassword",
    "guestguest", "guest1234", "test1234", "testtest", "test12345",
    "homewifi1", "myhomewifi", "homenetwork", "networkkey", "network123",
    "router123", "routerpassword", "linksys123", "netgear123",
    "dlink1234", "tplink123", "belkin123", "asus12345", "xfinitywifi",
    "comcast123", "verizon123", "attwifi123", "spectrum123",
    "guestwifi", "guestwifi1", "freewifi123", "openwifi123",
    "summer2023", "summer2024", "summer2025", "winter2024", "winter2025",
    "spring2024", "spring2025", "autumn2024", "january2024",
    "company123", "office123", "business1", "corporate1", "workwifi1",
    "familywifi", "family123", "mypassword", "mypassword1", "secret123",
    "computer1", "qazwsxedc", "zaq12wsx", "1qazxsw2", "poiuytrewq",
    "11223344", "12341234", "12121212", "10101010", "99999999",
    "abcdefgh", "abcdefghij", "aaaaaaaa", "qwertyui", "asdfasdf",
    "monkey123", "dragon123", "shadow123", "master123", "hunter123",
    "freedom1", "whatever1", "nothing1", "chocolate1", "butterfly1",
};

const char *bas_psk_candidate(uint32_t i)
{
    if (i >= (uint32_t)(sizeof(k_weak) / sizeof(k_weak[0]))) {
        return NULL;
    }
    return k_weak[i];
}

uint32_t bas_psk_candidate_count(void)
{
    return (uint32_t)(sizeof(k_weak) / sizeof(k_weak[0]));
}
