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

/* Defined below with the rest of the WPS code; declared here because the
 * beacon walk is the only place that has both the element and somewhere to
 * put the result. There is one WPS attribute parser, not two -- a second one
 * for "just the locked bit" is how the two quietly disagree later. */
static bool wps_attrs(const uint8_t *p, size_t len, bas_wps_t *o);

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
        case BAS_IE_COUNTRY:
            /* Two letters and an operating class. Consumer APs often omit
             * this element entirely, so its absence says nothing. */
            if (elen >= 3u) {
                bool printable = (body[0] >= 'A' && body[0] <= 'Z') &&
                                 (body[1] >= 'A' && body[1] <= 'Z');
                if (printable) {
                    out->country[0] = (char)body[0];
                    out->country[1] = (char)body[1];
                    out->country[2] = '\0';
                    if (ap != NULL) {
                        ap->country[0] = out->country[0];
                        ap->country[1] = out->country[1];
                        ap->country[2] = '\0';
                    }
                }
            }
            break;

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
                    bas_wps_t scratch;
                    bas_wps_t *w = (ap != NULL) ? &ap->wps : &scratch;
                    memset(w, 0, sizeof(*w));
                    w->present = true;
                    if (!wps_attrs(body + 4, (size_t)elen - 4u, w)) {
                        out->truncated = true;
                    }
                    out->wps_present = true;
                    out->wps_locked  = w->locked;
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

/* --- WPS -------------------------------------------------------------------
 * Attributes are big-endian TLVs inside the Microsoft vendor element.
 * ------------------------------------------------------------------------- */

#define WPS_ATTR_VERSION        0x104Au
#define WPS_ATTR_STATE          0x1044u
#define WPS_ATTR_LOCKED         0x1057u
#define WPS_ATTR_SELECTED_REG   0x1041u
#define WPS_ATTR_CONFIG_METHODS 0x1008u
#define WPS_ATTR_MANUFACTURER   0x1021u
#define WPS_ATTR_MODEL_NAME     0x1023u

static void wps_string(char *dst, size_t dst_n, const uint8_t *v, uint16_t n)
{
    size_t take = n;
    if (take > dst_n - 1u) {
        take = dst_n - 1u;
    }
    size_t w = 0;
    for (size_t i = 0; i < take; i++) {
        /* These strings are chosen by the AP's firmware author and land on a
         * screen and in a report, so a control byte is replaced rather than
         * carried through. */
        dst[w++] = ((unsigned char)v[i] < 0x20u) ? '.' : (char)v[i];
    }
    dst[w] = '\0';
}

/* Returns false when an attribute length runs past the element, which is
 * where a naive parser walks off the end. The caller records that: a beacon
 * that cannot be fully parsed is reported as such rather than as one whose
 * missing attributes were simply absent. */
static bool wps_attrs(const uint8_t *p, size_t len, bas_wps_t *o)
{
    size_t off = 0;
    while (off + 4u <= len) {
        uint16_t id = (uint16_t)(((uint16_t)p[off] << 8) | p[off + 1]);
        uint16_t n  = (uint16_t)(((uint16_t)p[off + 2] << 8) | p[off + 3]);
        off += 4u;
        if (off + n > len) {
            return false;           /* truncated: keep what was read */
        }
        const uint8_t *v = &p[off];

        switch (id) {
        case WPS_ATTR_VERSION:
            if (n >= 1u) { o->version = v[0]; }
            break;
        case WPS_ATTR_STATE:
            /* 1 = unconfigured, 2 = configured. */
            if (n >= 1u) { o->configured = (v[0] == 0x02u); }
            break;
        case WPS_ATTR_LOCKED:
            if (n >= 1u) { o->locked = (v[0] != 0u); }
            break;
        case WPS_ATTR_SELECTED_REG:
            if (n >= 1u) { o->selected_reg = (v[0] != 0u); }
            break;
        case WPS_ATTR_CONFIG_METHODS:
            if (n >= 2u) {
                o->config_methods = (uint16_t)(((uint16_t)v[0] << 8) | v[1]);
            }
            break;
        case WPS_ATTR_MANUFACTURER:
            wps_string(o->manufacturer, sizeof(o->manufacturer), v, n);
            break;
        case WPS_ATTR_MODEL_NAME:
            wps_string(o->model, sizeof(o->model), v, n);
            break;
        default:
            break;
        }
        off += n;
    }
    return true;
}

bas_err_t bas_wps_parse(const uint8_t *ies, size_t len, bas_wps_t *out)
{
    if (out == NULL) {
        return BAS_ERR_ARG;
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
            break;
        }
        const uint8_t *body = &ies[off];

        if (id == BAS_IE_VENDOR && elen >= 4u &&
            memcmp(body, k_oui_ms, 3) == 0 && body[3] == 0x04u) {
            out->present = true;
            (void)wps_attrs(body + 4, (size_t)elen - 4u, out);
        }
        off += elen;
    }
    return BAS_OK;
}

bas_wps_risk_t bas_wps_grade(const bas_wps_t *w)
{
    if (w == NULL || !w->present) {
        return BAS_WPS_NONE;
    }
    /* Locked first: a locked AP is not attackable however it is configured,
     * and saying otherwise would send an operator after a closed door. */
    if (w->locked) {
        return BAS_WPS_LOCKED;
    }
    if (w->selected_reg) {
        return BAS_WPS_REGISTRAR;
    }

    /* A PIN method is a standing door: the PIN exists whether or not anyone is
     * at the router, so an attack can start at any time. */
    const uint16_t pin_methods = BAS_WPS_CM_LABEL | BAS_WPS_CM_DISPLAY |
                                 BAS_WPS_CM_KEYPAD;
    if ((w->config_methods & pin_methods) != 0u) {
        return BAS_WPS_PIN_OPEN;
    }
    if ((w->config_methods & BAS_WPS_CM_PBC) != 0u) {
        return BAS_WPS_PBC_ONLY;
    }
    /* No Config Methods attribute at all. Most beacons omit it -- it usually
     * travels in probe responses -- so this is the ordinary case, not an
     * anomaly. It must not be graded as push-button: that would report a PIN
     * method as absent when it was simply never advertised. */
    return BAS_WPS_ON_UNKNOWN;
}

const char *bas_wps_risk_name(bas_wps_risk_t r)
{
    switch (r) {
    case BAS_WPS_LOCKED:    return "WPS locked";
    case BAS_WPS_PBC_ONLY:  return "WPS push-button";
    case BAS_WPS_ON_UNKNOWN: return "WPS on, methods unknown";
    case BAS_WPS_PIN_OPEN:  return "WPS PIN exposed";
    case BAS_WPS_REGISTRAR: return "WPS registrar ACTIVE";
    default:                return "no WPS";
    }
}

const char *bas_wps_advice(bas_wps_risk_t r)
{
    switch (r) {
    case BAS_WPS_LOCKED:
        return "Locked out. Lockouts expire, so disabling WPS is still better.";
    case BAS_WPS_PBC_ONLY:
        return "Push-button only: exposed while someone presses it.";
    case BAS_WPS_ON_UNKNOWN:
        return "Enabled and unlocked. The beacon does not say which methods, "
               "so a PIN method is not ruled out. Probe it to find out.";
    case BAS_WPS_PIN_OPEN:
        return "A PIN method is open. Recoverable; disable WPS.";
    case BAS_WPS_REGISTRAR:
        return "A registrar is open right now. Disable WPS.";
    default:
        return "Not advertised.";
    }
}

bool bas_wps_vendor_suspect(const bas_wps_t *w)
{
    if (w == NULL || w->manufacturer[0] == '\0') {
        return false;
    }
    /* Chipset families with documented weak registrar nonce generation. This
     * is suspicion, not proof: the string is chosen by the firmware author,
     * vendors ship more than one chipset, and a rebadged box may name a
     * company that never made its radio. */
    static const char *const suspect[] = {
        "Ralink", "MediaTek", "Realtek", "Broadcom", "RTL", "MTK", NULL
    };
    for (int i = 0; suspect[i] != NULL; i++) {
        const char *h = w->manufacturer;
        size_t nl = strlen(suspect[i]);
        for (; *h != '\0'; h++) {
            size_t k = 0;
            while (k < nl && h[k] != '\0' &&
                   (h[k] | 0x20) == (suspect[i][k] | 0x20)) {
                k++;
            }
            if (k == nl) {
                return true;
            }
        }
    }
    return false;
}
