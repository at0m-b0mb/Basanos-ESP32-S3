/* Basanos — alarm ingest. SPDX-License-Identifier: MIT */
#include "basanos/alarm.h"

#include <string.h>

const char *bas_alarm_src_name(bas_alarm_src_t s)
{
    switch (s) {
    case BAS_SRC_OPERATOR: return "operator";
    case BAS_SRC_SERIAL:   return "serial";
    case BAS_SRC_NETWORK:  return "network";
    default:               return "?";
    }
}

bool bas_alarm_src_is_machine(bas_alarm_src_t s)
{
    return s == BAS_SRC_SERIAL || s == BAS_SRC_NETWORK;
}

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Parse an unsigned integer, decimal or 0x-prefixed hex, stopping at the first
 * character that is not part of it. Refuses anything that would overflow so a
 * crafted "conf=99999999999999" cannot wrap into a small plausible number. */
static bool parse_uint(const char *s, size_t len, uint32_t *out)
{
    if (s == NULL || len == 0u) {
        return false;
    }
    uint32_t base = 10u;
    size_t i = 0;
    if (len > 2u && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16u;
        i = 2u;
        if (i >= len) {
            return false;
        }
    }

    uint32_t v = 0u;
    bool any = false;
    for (; i < len; i++) {
        uint32_t d;
        char c = s[i];
        if (c >= '0' && c <= '9') {
            d = (uint32_t)(c - '0');
        } else if (base == 16u && c >= 'a' && c <= 'f') {
            d = (uint32_t)(c - 'a') + 10u;
        } else if (base == 16u && c >= 'A' && c <= 'F') {
            d = (uint32_t)(c - 'A') + 10u;
        } else {
            return false;               /* trailing junk is not a number  */
        }
        if (v > (UINT32_MAX - d) / base) {
            return false;               /* would overflow                 */
        }
        v = v * base + d;
        any = true;
    }
    if (!any) {
        return false;
    }
    *out = v;
    return true;
}

bool bas_alarm_parse(const char *line, bas_alarm_src_t src, bas_alarm_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->source = src;

    if (line == NULL) {
        return false;
    }
    if ((int)src < 0 || src >= BAS_SRC__COUNT) {
        return false;
    }

    /* Leading whitespace is fine; anything else before the prefix is not. A
     * detector printing "see BASANOS-ALARM detector=X for the format" in its
     * help text must not be mistaken for an alarm, so the prefix has to start
     * the line rather than merely appear in it. */
    size_t i = 0;
    while (line[i] != '\0' && is_space(line[i])) {
        i++;
    }
    const size_t plen = sizeof(BAS_ALARM_PREFIX) - 1u;
    if (strncmp(&line[i], BAS_ALARM_PREFIX, plen) != 0) {
        return false;
    }
    i += plen;
    /* The prefix must be followed by whitespace or end of line, so
     * "BASANOS-ALARMED" is not an alarm. */
    if (line[i] != '\0' && !is_space(line[i])) {
        return false;
    }

    bool have_detector = false;

    while (line[i] != '\0') {
        while (line[i] != '\0' && is_space(line[i])) {
            i++;
        }
        if (line[i] == '\0') {
            break;
        }

        size_t kstart = i;
        while (line[i] != '\0' && line[i] != '=' && !is_space(line[i])) {
            i++;
        }
        size_t klen = i - kstart;
        if (line[i] != '=' || klen == 0u) {
            /* A bare token with no value. Skip it rather than failing: the
             * format is meant to tolerate a detector adding fields. */
            while (line[i] != '\0' && !is_space(line[i])) {
                i++;
            }
            continue;
        }
        i++;                                   /* past '='                */

        size_t vstart = i;
        while (line[i] != '\0' && !is_space(line[i])) {
            i++;
        }
        size_t vlen = i - vstart;
        if (vlen == 0u) {
            continue;
        }

        const char *k = &line[kstart];
        const char *v = &line[vstart];

        if (klen == 8u && strncmp(k, "detector", 8) == 0) {
            size_t n = vlen;
            if (n > BAS_ALARM_NAME_MAX - 1u) {
                n = BAS_ALARM_NAME_MAX - 1u;   /* truncate, never overrun */
            }
            memcpy(out->detector, v, n);
            out->detector[n] = '\0';
            have_detector = true;
        } else if (klen == 4u && strncmp(k, "conf", 4) == 0) {
            uint32_t n = 0u;
            if (parse_uint(v, vlen, &n)) {
                out->confidence = (uint8_t)(n > 100u ? 100u : n);
            }
        } else if (klen == 3u && strncmp(k, "fam", 3) == 0) {
            uint32_t n = 0u;
            if (parse_uint(v, vlen, &n)) {
                out->families = (uint8_t)(n & 0xFFu);
            }
        }
        /* Unknown keys ignored on purpose. */
    }

    if (!have_detector || out->detector[0] == '\0') {
        return false;
    }

    out->valid = true;
    return true;
}
