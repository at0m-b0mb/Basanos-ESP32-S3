/* Basanos — information-element parsing, including hostile input.
 *
 * These bytes come off the air and are entirely attacker-controlled. The
 * malformed cases at the end of this suite are the reason the file exists.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/ie.h"

/* RSN element body: version, group cipher, 1 pairwise, 1 AKM, caps. */
#define RSN_BODY(akm, cap_lo, cap_hi)                                          \
    0x01, 0x00,                     /* version                            */   \
    0x00, 0x0F, 0xAC, 0x04,         /* group: CCMP                        */   \
    0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, /* 1 pairwise: CCMP               */   \
    0x01, 0x00, 0x00, 0x0F, 0xAC, (akm), /* 1 AKM                         */   \
    (cap_lo), (cap_hi)

void suite_ie(void)
{
    SUITE("ie: a well-formed WPA2-PSK beacon");

    static const uint8_t wpa2[] = {
        0x00, 0x0B, 's','u','n','s','h','i','n','e',' ','1','2',
        0x03, 0x01, 0x06,                       /* DS param: channel 6    */
        0x30, 0x14, RSN_BODY(0x02, 0x00, 0x00), /* AKM PSK, no PMF        */
    };

    bas_ap_t ap;
    bas_posture_t p;
    memset(&ap, 0, sizeof(ap));
    CHECK_EQ(bas_ie_parse(wpa2, sizeof(wpa2), &ap, &p), BAS_OK);

    CHECK_STR(ap.ssid, "sunshine 12");
    CHECK_EQ(ap.channel, 6);
    CHECK(!ap.hidden);
    CHECK(p.rsn_present);
    CHECK(p.akm_psk);
    CHECK(!p.akm_sae);
    CHECK(!p.pmf_capable);
    CHECK(!p.pmf_required);
    CHECK(!p.truncated);
    CHECK_EQ(ap.sec, BAS_SEC_WPA2);
    CHECK(!bas_posture_deauth_resistant(&p));

    SUITE("ie: WPA3 with management frame protection required");

    static const uint8_t wpa3[] = {
        0x00, 0x04, 'l','a','b','3',
        0x03, 0x01, 0x0B,
        0x30, 0x14, RSN_BODY(0x08, 0xC0, 0x00), /* SAE, MFPC|MFPR         */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK_EQ(bas_ie_parse(wpa3, sizeof(wpa3), &ap, &p), BAS_OK);
    CHECK(p.akm_sae);
    CHECK(p.pmf_capable);
    CHECK(p.pmf_required);
    CHECK_EQ(ap.sec, BAS_SEC_WPA3);

    /* This is the finding that saves an operator a wasted run. */
    CHECK(bas_posture_deauth_resistant(&p));

    SUITE("ie: transition mode is reported as transition mode");

    /* Two AKMs: PSK and SAE. Calling this WPA3 would overstate the target's
     * resistance, because the WPA2 half is unprotected. */
    static const uint8_t trans[] = {
        0x00, 0x03, 'm','i','x',
        0x30, 0x18,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
        0x02, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x0F, 0xAC, 0x08,
        0x80, 0x00,                              /* MFPC only, not MFPR   */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK_EQ(bas_ie_parse(trans, sizeof(trans), &ap, &p), BAS_OK);
    CHECK(p.akm_psk);
    CHECK(p.akm_sae);
    CHECK_EQ(ap.sec, BAS_SEC_WPA2_WPA3);
    CHECK(p.pmf_capable);
    CHECK(!p.pmf_required);

    /* Capable but not required does not resist: some clients negotiate it and
     * some do not, which is a useful finding rather than a wall. */
    CHECK(!bas_posture_deauth_resistant(&p));

    SUITE("ie: enterprise and open");

    static const uint8_t ent[] = {
        0x00, 0x03, 'c','o','r',
        0x30, 0x14, RSN_BODY(0x01, 0x00, 0x00),  /* 802.1X                */
    };
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(ent, sizeof(ent), &ap, &p);
    CHECK(p.akm_enterprise);
    CHECK_EQ(ap.sec, BAS_SEC_WPA2_ENT);

    static const uint8_t open_ap[] = { 0x00, 0x04, 'c','a','f','e' };
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(open_ap, sizeof(open_ap), &ap, &p);
    CHECK(!p.rsn_present);
    CHECK_EQ(ap.sec, BAS_SEC_OPEN);

    SUITE("ie: hidden networks");

    static const uint8_t hidden_zero[] = { 0x00, 0x00 };
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(hidden_zero, sizeof(hidden_zero), &ap, &p);
    CHECK(p.ssid_present);
    CHECK(p.hidden);
    CHECK(ap.hidden);
    CHECK_STR(ap.ssid, "");

    /* Some APs pad with NULs instead of using a zero-length element. */
    static const uint8_t hidden_nul[] = { 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(hidden_nul, sizeof(hidden_nul), &ap, &p);
    CHECK(p.hidden);
    CHECK(ap.hidden);

    SUITE("ie: WPS detection");

    static const uint8_t wps[] = {
        0x00, 0x03, 'w','p','s',
        0xDD, 0x0C,
        0x00, 0x50, 0xF2, 0x04,               /* MS OUI, WPS              */
        0x10, 0x57, 0x00, 0x01, 0x01,         /* AP setup locked = 1      */
        0x10, 0x44, 0x00,                     /* truncated trailing TLV   */
    };
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(wps, sizeof(wps), &ap, &p);
    CHECK(p.wps_present);
    CHECK(p.wps_locked);

    SUITE("ie: malformed input truncates, it does not walk off the buffer");

    /* An element claiming more bytes than remain. The classic overrun. */
    static const uint8_t overrun[] = { 0x00, 0x40, 'a', 'b' };
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(overrun, sizeof(overrun), &ap, &p);
    CHECK(p.truncated);

    /* A header with no length byte. */
    static const uint8_t stub[] = { 0x00 };
    bas_ie_parse(stub, sizeof(stub), NULL, &p);
    CHECK(p.truncated);

    /* An RSN whose pairwise count is absurd. Left unchecked this multiplies
     * into an out-of-bounds read. */
    static const uint8_t bad_rsn[] = {
        0x30, 0x0A,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0xFF, 0xFF,                            /* 65535 pairwise ciphers  */
        0x00, 0x0F,
    };
    bas_ie_parse(bad_rsn, sizeof(bad_rsn), NULL, &p);
    CHECK(p.rsn_present);
    CHECK(p.truncated);
    CHECK(!p.akm_psk);

    /* An RSN whose AKM count is absurd. */
    static const uint8_t bad_akm[] = {
        0x30, 0x10,
        0x01, 0x00,
        0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
        0xFF, 0x7F,                            /* enormous AKM count      */
        0x00, 0x0F,
    };
    bas_ie_parse(bad_akm, sizeof(bad_akm), NULL, &p);
    CHECK(p.truncated);

    /* A WPS attribute whose length runs past the vendor element. */
    static const uint8_t bad_wps[] = {
        0xDD, 0x0A,
        0x00, 0x50, 0xF2, 0x04,
        0x10, 0x57, 0x7F, 0xFF,                /* length 0x7FFF           */
        0x01, 0x02,
    };
    bas_ie_parse(bad_wps, sizeof(bad_wps), NULL, &p);
    CHECK(p.wps_present);
    CHECK(p.truncated);

    /* An SSID longer than the field it lands in must truncate cleanly. */
    uint8_t longssid[2 + 60];
    longssid[0] = 0x00;
    longssid[1] = 60;
    memset(&longssid[2], 'A', 60);
    memset(&ap, 0, sizeof(ap));
    bas_ie_parse(longssid, sizeof(longssid), &ap, &p);
    CHECK_EQ(strlen(ap.ssid), sizeof(ap.ssid) - 1u);

    SUITE("ie: empty and null input");

    CHECK_EQ(bas_ie_parse(NULL, 0, NULL, &p), BAS_OK);
    CHECK_EQ(p.elements, 0);
    CHECK(!p.truncated);
    CHECK_EQ(bas_ie_parse(NULL, 8, NULL, &p), BAS_ERR_ARG);

    /* out may be NULL — the AP fields still fill. */
    memset(&ap, 0, sizeof(ap));
    CHECK_EQ(bas_ie_parse(wpa2, sizeof(wpa2), &ap, NULL), BAS_OK);
    CHECK_STR(ap.ssid, "sunshine 12");

    SUITE("ie: classification helper");

    bas_posture_t z;
    memset(&z, 0, sizeof(z));
    CHECK_EQ(bas_ie_classify(&z, false), BAS_SEC_OPEN);
    CHECK_EQ(bas_ie_classify(&z, true), BAS_SEC_WEP);
    CHECK_EQ(bas_ie_classify(NULL, false), BAS_SEC_UNKNOWN);
}

void suite_ie_akm(void)
{
    SUITE("ie: a fast-transition network is not WEP");

    /* The finding that prompted this suite. 802.11r is standard on enterprise
     * and mesh gear, and its AKM numbers are nowhere near the base ones. An
     * unrecognised AKM set no posture flag, classification fell through every
     * branch to the privacy bit, and an ordinary WPA2-Enterprise-FT network
     * was reported as WEP -- the single most damning verdict this instrument
     * can produce, on a network that is not vulnerable at all. */
    static const uint8_t ft_psk[] = {
        0x00, 0x04, 'r','o','a','m',
        0x30, 0x14, RSN_BODY(0x04, 0x00, 0x00),   /* AKM 4: FT-PSK        */
    };
    bas_ap_t ap;
    bas_posture_t p;
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(ft_psk, sizeof(ft_psk), &ap, &p) == BAS_OK);
    CHECK(p.akm_psk);
    CHECK(!p.akm_unknown);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_WPA2);
    CHECK(bas_ie_classify(&p, true) != BAS_SEC_WEP);

    static const uint8_t ft_ent[] = {
        0x00, 0x04, 'c','o','r','p',
        0x30, 0x14, RSN_BODY(0x03, 0x00, 0x00),   /* AKM 3: FT-802.1X     */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(ft_ent, sizeof(ft_ent), &ap, &p) == BAS_OK);
    CHECK(p.akm_enterprise);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_WPA2_ENT);

    static const uint8_t ft_sae[] = {
        0x00, 0x03, 'w','p','3',
        0x30, 0x14, RSN_BODY(0x09, 0x00, 0x00),   /* AKM 9: FT-SAE        */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(ft_sae, sizeof(ft_sae), &ap, &p) == BAS_OK);
    CHECK(p.akm_sae);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_WPA3);

    /* Suite-B and SAE-EXT-KEY are the other two that were falling through. */
    static const uint8_t suiteb[] = {
        0x00, 0x02, 'g','b',
        0x30, 0x14, RSN_BODY(0x0C, 0x00, 0x00),   /* AKM 12: Suite-B-192  */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(suiteb, sizeof(suiteb), &ap, &p) == BAS_OK);
    CHECK(p.akm_enterprise);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_WPA2_ENT);

    static const uint8_t sae_ext[] = {
        0x00, 0x02, 'x','k',
        0x30, 0x14, RSN_BODY(0x18, 0x00, 0x00),   /* AKM 24: SAE-EXT-KEY  */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(sae_ext, sizeof(sae_ext), &ap, &p) == BAS_OK);
    CHECK(p.akm_sae);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_WPA3);

    SUITE("ie: an AKM from a future amendment is unknown, never WEP");

    /* Every amendment adds suite numbers. The honest answer for one this
     * table has never seen is "I could not identify it", which is a different
     * claim from "it is WEP" -- and only one of them is true. */
    static const uint8_t future[] = {
        0x00, 0x02, 'f','x',
        0x30, 0x14, RSN_BODY(0x7F, 0x00, 0x00),   /* AKM 127: not defined */
    };
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(future, sizeof(future), &ap, &p) == BAS_OK);
    CHECK(p.akm_unknown);
    CHECK(!p.akm_psk && !p.akm_sae && !p.akm_enterprise && !p.akm_owe);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_UNKNOWN);
    CHECK(bas_ie_classify(&p, true) != BAS_SEC_WEP);

    SUITE("ie: real WEP is still reported as WEP");

    /* The branch must still work for the case it was written for: privacy bit
     * set, no RSN element and no WPA vendor element at all. */
    static const uint8_t wep[] = {
        0x00, 0x03, 'o','l','d',
        0x03, 0x01, 0x06,
    };
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(wep, sizeof(wep), &ap, &p) == BAS_OK);
    CHECK(!p.rsn_present);
    CHECK(!p.akm_unknown);
    CHECK(bas_ie_classify(&p, true) == BAS_SEC_WEP);
    CHECK(bas_ie_classify(&p, false) == BAS_SEC_OPEN);
}
