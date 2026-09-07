/* Basanos — 802.11 information-element parsing.
 * SPDX-License-Identifier: MIT */
#include "basanos/ie.h"

#include <string.h>

/* AKM selector suite types under the 00-0F-AC OUI. */
#define AKM_8021X 1u
#define AKM_PSK   2u
#define AKM_SAE   8u
#define AKM_OWE  18u

static const uint8_t k_oui_rsn[3] = { 0x00, 0x0F, 0xAC };
static const uint8_t k_oui_ms[3]  = { 0x00, 0x50, 0xF2 };

static void parse_rsn(const uint8_t *p, size_t len, bas_posture_t *o)
{
    /* version(2) group(4) pairwiseCount(2) ... akmCount(2) ... caps(2) */
    size_t off = 0;
    if (len < 2u) {
        return;               /* version alone is a legal-but-useless RSN */
    }
    off += 2u;                                    /* version              */

    if (off + 4u > len) {
        return;
    }
    off += 4u;                                    /* group cipher         */

    if (off + 2u > len) {
        return;
    }
    uint16_t pc = (uint16_t)(p[off] | ((uint16_t)p[off + 1] << 8));
    off += 2u;
    /* Guard the multiply as well as the add: a crafted count of 0xFFFF would
     * overflow a 16-bit product on a smaller type and wrap the bounds test. */
    if (pc > (len / 4u) + 1u || off + (size_t)pc * 4u > len) {
        o->truncated = true;
        return;
    }
    off += (size_t)pc * 4u;                       /* pairwise ciphers     */

    if (off + 2u > len) {
        return;
    }
    uint16_t ac = (uint16_t)(p[off] | ((uint16_t)p[off + 1] << 8));
    off += 2u;
    if (ac > (len / 4u) + 1u || off + (size_t)ac * 4u > len) {
        o->truncated = true;
        return;
    }

    for (uint16_t i = 0; i < ac; i++) {
        const uint8_t *s = &p[off + (size_t)i * 4u];
        if (memcmp(s, k_oui_rsn, 3) != 0) {
            continue;                             /* vendor-specific AKM  */
        }
        switch (s[3]) {
        case AKM_8021X: o->akm_enterprise = true; break;
        case AKM_PSK:   o->akm_psk        = true; break;
        case AKM_SAE:   o->akm_sae        = true; break;
        case AKM_OWE:   o->akm_owe        = true; break;
        default: break;
        }
    }
    off += (size_t)ac * 4u;

    if (off + 2u > len) {
        return;                                   /* caps are optional    */
    }
    uint16_t caps = (uint16_t)(p[off] | ((uint16_t)p[off + 1] << 8));
    o->pmf_capable  = (caps & 0x0080u) != 0u;     /* bit 7: MFPC          */
    o->pmf_required = (caps & 0x0040u) != 0u;     /* bit 6: MFPR          */
}

static void parse_wps(const uint8_t *p, size_t len, bas_posture_t *o)
{
    /* Inside the vendor IE past OUI+type: big-endian TLVs, id(2) len(2). */
    o->wps_present = true;
    size_t off = 0;
    while (off + 4u <= len) {
        uint16_t id  = (uint16_t)(((uint16_t)p[off] << 8) | p[off + 1]);
        uint16_t alen = (uint16_t)(((uint16_t)p[off + 2] << 8) | p[off + 3]);
        off += 4u;
        if (off + alen > len) {
            o->truncated = true;
            return;
        }
        if (id == 0x1057u && alen >= 1u) {        /* AP setup locked      */
            o->wps_locked = (p[off] != 0u);
        }
        off += alen;
    }
}

bas_err_t bas_ie_parse(const uint8_t *ies, size_t len,
                       bas_ap_t *ap, bas_posture_t *out)
{
    bas_posture_t local;
    if (out == NULL) {
        out = &local;
    }
    memset(out, 0, sizeof(*out));

    if (ies == NULL && len != 0u) {
        return BAS_ERR_ARG;
    }

    size_t off = 0;
    while (off + 2u <= len) {
        uint8_t id   = ies[off];
        uint8_t elen = ies[off + 1];
        off += 2u;

        if (off + elen > len) {
            /* A length that runs past the buffer is where a naive parser walks
             * off the end. Stop, flag it, keep what was already read. */
            out->truncated = true;
            break;
        }

        const uint8_t *body = &ies[off];
        out->elements++;

        switch (id) {
        case BAS_IE_SSID: {
            out->ssid_present = true;
            bool all_nul = true;
            for (uint8_t i = 0; i < elen; i++) {
                if (body[i] != 0u) {
                    all_nul = false;
                    break;
                }
            }
            out->hidden = (elen == 0u) || all_nul;
            if (ap != NULL) {
                size_t n = elen;
                if (n > sizeof(ap->ssid) - 1u) {
                    n = sizeof(ap->ssid) - 1u;
                }
                if (!out->hidden) {
                    memcpy(ap->ssid, body, n);
                    ap->ssid[n] = '\0';
                } else {
                    ap->ssid[0] = '\0';
                }
                ap->hidden = out->hidden;
            }
            break;
        }
        case BAS_IE_DS_PARAM:
            if (elen >= 1u) {
                out->ds_present = true;
                if (ap != NULL && body[0] >= 1u && body[0] <= 14u) {
                    ap->channel = body[0];
                }
            }
            break;
        case BAS_IE_RSN:
            out->rsn_present = true;
            parse_rsn(body, elen, out);
            break;
        case BAS_IE_VENDOR:
            if (elen >= 4u && memcmp(body, k_oui_ms, 3) == 0) {
                if (body[3] == 0x04u) {           /* WPS                   */
                    parse_wps(body + 4, (size_t)elen - 4u, out);
                } else if (body[3] == 0x01u) {    /* WPA1                  */
                    /* Presence is enough; WPA1 never has PMF. */
                    out->akm_psk = true;
                }
            }
            break;
        default:
            break;
        }

        off += elen;
    }

    if (off != len) {
        out->truncated = true;
    }

    if (ap != NULL) {
        ap->sec = bas_ie_classify(out, out->rsn_present);
    }
    return out->truncated ? BAS_OK : BAS_OK;
}

bas_sec_t bas_ie_classify(const bas_posture_t *p, bool privacy_bit)
{
    if (p == NULL) {
        return BAS_SEC_UNKNOWN;
    }

    /* SAE alongside PSK is transition mode. Report it as such: its WPA2 half
     * is unprotected, and calling it WPA3 would overstate the target's
     * resistance to exactly the family this device emits. */
    if (p->akm_sae && p->akm_psk) {
        return BAS_SEC_WPA2_WPA3;
    }
    if (p->akm_sae) {
        return BAS_SEC_WPA3;
    }
    if (p->akm_enterprise) {
        return BAS_SEC_WPA2_ENT;
    }
    if (p->akm_owe) {
        /* Encrypted but unauthenticated. Not open, not WPA2. */
        return BAS_SEC_WPA3;
    }
    if (p->akm_psk) {
        return p->rsn_present ? BAS_SEC_WPA2 : BAS_SEC_WPA;
    }
    if (privacy_bit) {
        return BAS_SEC_WEP;
    }
    return BAS_SEC_OPEN;
}

bool bas_posture_deauth_resistant(const bas_posture_t *p)
{
    /* Only *required* protection actually stops the frame. Capable-but-not-
     * required means clients may negotiate it, so some will be affected and
     * some will not — which is a useful finding rather than a resistance. */
    return p != NULL && p->pmf_required;
}
