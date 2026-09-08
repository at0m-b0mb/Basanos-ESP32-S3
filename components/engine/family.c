/* Basanos — signal families, ceilings, and the validation gate.
 * SPDX-License-Identifier: MIT */
#include "basanos/family.h"

#include <string.h>

/* Role values are duplicated as integers here so components/engine keeps no
 * dependency on components/rbac. The host tests assert the two agree. */
#define ROLE_VIEWER   0u
#define ROLE_OPERATOR 1u
#define ROLE_ADMIN    2u

static const bas_family_spec_t k_fam[BAS_FAM__COUNT] = {
    [BAS_FAM_PROBE_REQ] = {
        .name = "Probe requests", .detector = "Echo, Pharos probe",
        .proves = "Fingerprint + sequence tracking survives MAC randomisation",
        .klass = BAS_CLASS_BENIGN, .needs_target = false, .needs_client = false,
        .default_pps = 10, .max_pps = 50, .max_seconds = 60, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_BLE_ADV] = {
        .name = "BLE advert spam", .detector = "Aegis BLE-spam, Bulwark",
        .proves = "Advertiser multiplicity and tri-channel balance fire",
        .klass = BAS_CLASS_BENIGN, .needs_target = false, .needs_client = false,
        .default_pps = 20, .max_pps = 100, .max_seconds = 60, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_BLE_TRACKER] = {
        .name = "BLE tracker dwell", .detector = "GhostTag, Aegis tracker",
        .proves = "Dwell-span scoring separates a follower from a fixed beacon",
        .klass = BAS_CLASS_BENIGN, .needs_target = false, .needs_client = false,
        .default_pps = 2, .max_pps = 10, .max_seconds = 300, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_HID_TIMING] = {
        .name = "HID keystroke timing", .detector = "DuckHound",
        .proves = "How fast the timing engine calls an injection",
        .klass = BAS_CLASS_BENIGN, .needs_target = false, .needs_client = false,
        .default_pps = 15, .max_pps = 60, .max_seconds = 60, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_BEACON] = {
        .name = "Beacon set", .detector = "Aegis beacon-flood, Pharos Mirage",
        .proves = "New-BSSID arrival rate scores; a dense room stays BUSY",
        .klass = BAS_CLASS_ACTIVE, .needs_target = false, .needs_client = false,
        .default_pps = 20, .max_pps = 100, .max_seconds = 60, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_KARMA_RESP] = {
        .name = "Karma responder", .detector = "Pharos karma",
        .proves = "The gap between names a radio answers and announces",
        .klass = BAS_CLASS_ACTIVE, .needs_target = false, .needs_client = false,
        .default_pps = 10, .max_pps = 50, .max_seconds = 60, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_EVIL_TWIN] = {
        .name = "Evil twin", .detector = "Aegis evil-twin, Pharos twin, Argus",
        .proves = "Roaming stays clear; a security-class conflict escalates",
        .klass = BAS_CLASS_ACTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 10, .max_pps = 30, .max_seconds = 60, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_PMKID] = {
        .name = "PMKID solicitation", .detector = "PMKID capture sensors",
        .proves = "An unauthenticated association draws EAPOL M1",
        /* Active, not disruptive: it associates once and denies nothing. The
         * detectable event is the solicitation, which is why the family is
         * worth having even though the reply is never kept. */
        .klass = BAS_CLASS_ACTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 1, .max_pps = 4, .max_seconds = 30, .min_role = ROLE_OPERATOR,
    },
    [BAS_FAM_CSA] = {
        .name = "Channel switch", .detector = "Aegis watch, Pharos watch",
        .proves = "A forged channel-switch is scored as an attack, not a move",
        /* Disruptive and cheap: a handful of frames moves every client off the
         * channel, so the ceiling is deliberately low. Volume is not what
         * makes this work, which is exactly why a rate-only detector misses
         * it -- and why it is worth having as a separate family. */
        .klass = BAS_CLASS_DISRUPTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 5, .max_pps = 20, .max_seconds = 20, .min_role = ROLE_ADMIN,
    },
    [BAS_FAM_ASSOC_FLOOD] = {
        .name = "Association flood", .detector = "Aegis, Argus",
        .proves = "Association-table pressure separates from auth-only load",
        .klass = BAS_CLASS_DISRUPTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 20, .max_pps = 100, .max_seconds = 30, .min_role = ROLE_ADMIN,
    },
    [BAS_FAM_AUTH_FLOOD] = {
        .name = "Auth flood", .detector = "Aegis, Argus",
        .proves = "Association-table pressure is seen as an attack, not load",
        /* Disruptive: this fills a real AP's association table. It is not an
         * "active" family just because it never touches a client directly. */
        .klass = BAS_CLASS_DISRUPTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 20, .max_pps = 100, .max_seconds = 30, .min_role = ROLE_ADMIN,
    },
    [BAS_FAM_DISASSOC] = {
        .name = "Disassociation", .detector = "Aegis watch, Pharos watch",
        .proves = "The shape family scores disassoc as well as deauth",
        .klass = BAS_CLASS_DISRUPTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 10, .max_pps = 50, .max_seconds = 30, .min_role = ROLE_ADMIN,
    },
    [BAS_FAM_DEAUTH] = {
        .name = "Deauthentication", .detector = "Aegis watch, Pharos 4-family, Argus",
        .proves = "Rate, shape, forgery and aftermath each fire",
        .klass = BAS_CLASS_DISRUPTIVE, .needs_target = true, .needs_client = false,
        .default_pps = 10, .max_pps = 50, .max_seconds = 30, .min_role = ROLE_ADMIN,
    },
};

const bas_family_spec_t *bas_family(bas_family_t f)
{
    if ((int)f < 0 || f >= BAS_FAM__COUNT) {
        return NULL;
    }
    return &k_fam[f];
}

const char *bas_class_name(bas_class_t c)
{
    switch (c) {
    case BAS_CLASS_BENIGN:     return "benign";
    case BAS_CLASS_ACTIVE:     return "active";
    case BAS_CLASS_DISRUPTIVE: return "disruptive";
    default:                   return "?";
    }
}

void bas_plan_default(bas_plan_t *p, bas_family_t f)
{
    if (p == NULL) {
        return;
    }
    memset(p, 0, sizeof(*p));
    p->fam = f;
    const bas_family_spec_t *s = bas_family(f);
    if (s == NULL) {
        return;
    }
    p->pps     = s->default_pps;
    p->seconds = (uint16_t)(s->max_seconds > 10u ? 10u : s->max_seconds);
    /* Reason 7 — "class 3 frame received from nonassociated STA" — is what the
     * public tools send and what the detectors weight, so it is the default a
     * comparison run should use. */
    p->reason_code = 7u;
    p->channel     = 0u; /* follow the target */
}

/* --- regulatory clamp ---------------------------------------------------- */

static bas_region_t s_region = BAS_REGION_FCC;

void bas_region_set(bas_region_t r)
{
    if (r == BAS_REGION_FCC || r == BAS_REGION_ETSI || r == BAS_REGION_JP) {
        s_region = r;
    }
}

bas_region_t bas_region_get(void) { return s_region; }

uint8_t bas_region_max_channel(void)
{
    switch (s_region) {
    case BAS_REGION_ETSI: return 13u;
    case BAS_REGION_JP:   return 14u;
    case BAS_REGION_FCC:
    default:              return 11u;
    }
}

bas_err_t bas_region_check_channel(uint8_t ch)
{
    if (ch < 1u || ch > bas_region_max_channel()) {
        return BAS_ERR_CHANNEL;
    }
    return BAS_OK;
}

const char *bas_region_name(bas_region_t r)
{
    switch (r) {
    case BAS_REGION_ETSI: return "ETSI";
    case BAS_REGION_JP:   return "JP";
    case BAS_REGION_FCC:
    default:              return "FCC";
    }
}

bas_region_t bas_region_from_country(const char *cc)
{
    if (cc == NULL || cc[0] == '\0') {
        return BAS_REGION_FCC;
    }

    /* Japan is the only 2.4 GHz plan that reaches channel 14. */
    if (cc[0] == 'J' && cc[1] == 'P') {
        return BAS_REGION_JP;
    }

    /* The FCC plan (1..11) covers the Americas and the countries that adopted
     * it. Everything else in common use runs 1..13. */
    static const char *const fcc[] = {
        "US", "CA", "MX", "BR", "CO", "AR", "CL", "PE", "VE", "DO",
        "GT", "CR", "PA", "TW", "PH", NULL
    };
    for (int i = 0; fcc[i] != NULL; i++) {
        if (cc[0] == fcc[i][0] && cc[1] == fcc[i][1]) {
            return BAS_REGION_FCC;
        }
    }

    /* A two-letter code we recognise as a country but not as FCC or JP is
     * almost certainly a 1..13 domain. Anything unrecognised falls through to
     * the narrow default rather than being assumed wide. */
    static const char *const etsi[] = {
        "GB", "IE", "FR", "DE", "ES", "IT", "PT", "NL", "BE", "LU",
        "AT", "CH", "SE", "NO", "DK", "FI", "IS", "PL", "CZ", "SK",
        "HU", "RO", "BG", "GR", "HR", "SI", "EE", "LV", "LT", "CY",
        "MT", "IN", "CN", "AU", "NZ", "ZA", "AE", "SA", "IL", "TR",
        "RU", "UA", "KR", "SG", "MY", "TH", "ID", "VN", "HK", NULL
    };
    for (int i = 0; etsi[i] != NULL; i++) {
        if (cc[0] == etsi[i][0] && cc[1] == etsi[i][1]) {
            return BAS_REGION_ETSI;
        }
    }
    return BAS_REGION_FCC;
}

bool bas_family_label_ok(const char *ssid)
{
    if (ssid == NULL) {
        return false;
    }
    return strncmp(ssid, BAS_TEST_PREFIX, sizeof(BAS_TEST_PREFIX) - 1u) == 0;
}

/* --- the gate ------------------------------------------------------------ */

bas_err_t bas_plan_validate(bas_plan_t *p,
                            uint8_t role,
                            const bas_engagement_t *e,
                            uint32_t now_ms)
{
    if (p == NULL) {
        return BAS_ERR_ARG;
    }

    const bas_family_spec_t *s = bas_family(p->fam);
    if (s == NULL) {
        return BAS_ERR_UNKNOWN_FAMILY;
    }

    /* Role first. A viewer gets the same answer for every family, and finds
     * out nothing about the engagement by asking. */
    if (role < s->min_role) {
        return BAS_ERR_ROLE;
    }

    if (s->needs_target) {
        if (e == NULL) {
            return BAS_ERR_NO_TARGET;
        }
        bas_err_t rc = bas_engage_check(e, now_ms);
        if (rc != BAS_OK) {
            return rc;
        }
        if (!e->has_target) {
            /* A label-only engagement authorises the work but scopes no
             * network, so every family that addresses one is refused. */
            return BAS_ERR_NO_TARGET;
        }
        if (s->needs_client && e->client_n == 0u) {
            return BAS_ERR_NO_TARGET;
        }
    }

    /* Channel 0 means "follow the target", which is only meaningful when there
     * is one. Resolve it here so the transmit path never has to guess. */
    uint8_t ch = p->channel;
    if (ch == 0u) {
        if (e != NULL && e->locked) {
            ch = e->target.channel;
        } else if (s->needs_target) {
            return BAS_ERR_NO_TARGET;
        }
    }
    if (ch != 0u) {
        bas_err_t rc = bas_region_check_channel(ch);
        if (rc != BAS_OK) {
            return rc;
        }
        p->channel = ch;
    }

    /* Clamp, never widen. A plan asking for more than the family allows is not
     * an error — the operator gets the run at the ceiling, and the flag tells
     * the UI to say so rather than silently delivering something else. */
    p->clamped_pps  = false;
    p->clamped_secs = false;
    if (p->pps == 0u) {
        p->pps = s->default_pps;
    }
    if (p->pps > s->max_pps) {
        p->pps = s->max_pps;
        p->clamped_pps = true;
    }
    if (p->seconds == 0u) {
        p->seconds = 1u;
    }
    if (p->seconds > s->max_seconds) {
        p->seconds = s->max_seconds;
        p->clamped_secs = true;
    }

    return BAS_OK;
}

uint32_t bas_plan_frame_budget(const bas_plan_t *p)
{
    if (p == NULL) {
        return 0u;
    }
    return (uint32_t)p->pps * (uint32_t)p->seconds;
}
