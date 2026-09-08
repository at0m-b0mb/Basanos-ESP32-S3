/* Basanos — WPA2 key derivation and the passphrase audit.
 *
 * The crypto is checked against published vectors, because "it compiles" is
 * not evidence that a key-derivation function is correct — and a wrong PMK
 * would silently report every passphrase in the world as strong.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/wpa.h"

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = d[b[i] >> 4];
        out[i * 2 + 1] = d[b[i] & 0x0F];
    }
    out[n * 2] = '\0';
}

void suite_wpa(void)
{
    char got[96];

    SUITE("wpa: SHA-1 against FIPS 180-2");

    uint8_t h[20];
    bas_sha1("abc", 3, h);
    hex(h, 20, got);
    CHECK_STR(got, "a9993e364706816aba3e25717850c26c9cd0d89d");

    bas_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, h);
    hex(h, 20, got);
    CHECK_STR(got, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

    bas_sha1("", 0, h);
    hex(h, 20, got);
    CHECK_STR(got, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    SUITE("wpa: HMAC-SHA1 against RFC 2202");

    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    bas_hmac_sha1(key1, 20, "Hi There", 8, h);
    hex(h, 20, got);
    CHECK_STR(got, "b617318655057264e28bc0b6fb378c8ef146be00");

    bas_hmac_sha1("Jefe", 4, "what do ya want for nothing?", 28, h);
    hex(h, 20, got);
    CHECK_STR(got, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

    SUITE("wpa: PBKDF2-HMAC-SHA1 against RFC 6070");

    uint8_t dk[25];
    bas_pbkdf2_sha1("password", 8, "salt", 4, 1, dk, 20);
    hex(dk, 20, got);
    CHECK_STR(got, "0c60c80f961f0e71f3a9b524af6012062fe037a6");

    bas_pbkdf2_sha1("password", 8, "salt", 4, 2, dk, 20);
    hex(dk, 20, got);
    CHECK_STR(got, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

    bas_pbkdf2_sha1("password", 8, "salt", 4, 4096, dk, 20);
    hex(dk, 20, got);
    CHECK_STR(got, "4b007901b765489abead49d926f721d065a429c1");

    SUITE("wpa: the PMK against the 802.11i vectors");

    /* IEEE 802.11i-2004 Annex H.4. A wrong PMK is the failure that would make
     * every audit report SURVIVED, so this is the load-bearing vector. */
    uint8_t pmk[32];
    bas_wpa_pmk("password", (const uint8_t *)"IEEE", 4, pmk);
    hex(pmk, 32, got);
    CHECK_STR(got,
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");

    bas_wpa_pmk("ThisIsAPassword", (const uint8_t *)"ThisIsASSID", 11, pmk);
    hex(pmk, 32, got);
    CHECK_STR(got,
        "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af");

    SUITE("wpa: an incomplete handshake is never tested");

    bas_handshake_t hs;
    bas_wpa_reset(&hs);
    CHECK(!bas_wpa_complete(&hs));
    CHECK(!bas_wpa_check(&hs, "password"));

    hs.have_m1 = true;
    CHECK(!bas_wpa_complete(&hs));
    hs.have_m2 = true;
    CHECK(!bas_wpa_complete(&hs));

    memcpy(hs.ssid, "lab", 3);
    hs.ssid_len = 3;
    hs.m2_len = 100;
    hs.key_ver = 2;
    CHECK(bas_wpa_complete(&hs));

    /* WPA version 1 uses an HMAC-MD5 MIC this code cannot recompute, so it is
     * refused rather than silently reported as a strong passphrase. */
    hs.key_ver = 1;
    CHECK(!bas_wpa_complete(&hs));
    hs.key_ver = 2;

    SUITE("wpa: candidates outside the legal length are not spent on");

    CHECK(!bas_wpa_check(&hs, "short"));
    CHECK(!bas_wpa_check(&hs, ""));
    CHECK(!bas_wpa_check(&hs, NULL));

    SUITE("wpa: the wipe leaves nothing behind");

    bas_wpa_reset(&hs);
    memset(hs.anonce, 0xAB, sizeof(hs.anonce));
    memset(hs.snonce, 0xCD, sizeof(hs.snonce));
    memset(hs.mic, 0xEF, sizeof(hs.mic));
    memcpy(hs.ssid, "secret", 6);
    hs.ssid_len = 6;
    hs.have_m1 = hs.have_m2 = true;

    bas_wpa_wipe(&hs);

    const uint8_t *raw = (const uint8_t *)&hs;
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(hs); i++) {
        if (raw[i] != 0u) { nonzero++; }
    }
    CHECK_EQ(nonzero, 0);
    CHECK(!bas_wpa_complete(&hs));

    SUITE("wpa: the candidate list is bounded and legal");

    uint32_t n = bas_psk_candidate_count();
    CHECK(n > 50);
    /* Deliberately small: a strength check, not a cracker. */
    CHECK(n < 2000);
    CHECK(bas_psk_candidate(n) == NULL);
    CHECK(bas_psk_candidate(n + 100) == NULL);

    for (uint32_t i = 0; i < n; i++) {
        const char *c = bas_psk_candidate(i);
        CHECK(c != NULL);
        size_t l = strlen(c);
        CHECK(l >= 8 && l <= 63);
    }

    CHECK_STR(bas_psk_verdict_name(BAS_PSK_WEAK), "WEAK");
    CHECK_STR(bas_psk_verdict_name(BAS_PSK_SURVIVED), "SURVIVED");
    CHECK_STR(bas_psk_verdict_name(BAS_PSK_UNTESTED), "UNTESTED");
}
