/* Basanos — 802.11 frame construction. SPDX-License-Identifier: MIT */
#include "frames.h"

#include "basanos/family.h"

#include <string.h>

static const uint8_t BCAST[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

/* Common management header: frame control, duration, three addresses and the
 * sequence control field. Returns the offset past it. */
static size_t mgmt_hdr(uint8_t *b, uint8_t subtype,
                       const uint8_t a1[6], const uint8_t a2[6],
                       const uint8_t a3[6], uint16_t seq)
{
    b[0] = (uint8_t)(subtype << 4);   /* type 0 (management) in bits 2..3 */
    b[1] = 0x00;
    b[2] = 0x00;                       /* duration                        */
    b[3] = 0x00;
    memcpy(&b[4],  a1, 6);
    memcpy(&b[10], a2, 6);
    memcpy(&b[16], a3, 6);
    /* Sequence number occupies the top 12 bits; the low 4 are the fragment
     * number and stay zero. */
    uint16_t sc = (uint16_t)(seq << 4);
    b[22] = (uint8_t)(sc & 0xFFu);
    b[23] = (uint8_t)(sc >> 8);
    return 24;
}

size_t bas_frame_deauth(uint8_t *buf, const uint8_t dst[6],
                        const uint8_t src[6], const uint8_t bssid[6],
                        uint16_t reason, uint16_t seq)
{
    if (buf == NULL || dst == NULL || src == NULL || bssid == NULL) {
        return 0;
    }
    size_t n = mgmt_hdr(buf, 12, dst, src, bssid, seq);
    buf[n++] = (uint8_t)(reason & 0xFFu);
    buf[n++] = (uint8_t)(reason >> 8);
    return n;
}

size_t bas_frame_disassoc(uint8_t *buf, const uint8_t dst[6],
                          const uint8_t src[6], const uint8_t bssid[6],
                          uint16_t reason, uint16_t seq)
{
    if (buf == NULL || dst == NULL || src == NULL || bssid == NULL) {
        return 0;
    }
    size_t n = mgmt_hdr(buf, 10, dst, src, bssid, seq);
    buf[n++] = (uint8_t)(reason & 0xFFu);
    buf[n++] = (uint8_t)(reason >> 8);
    return n;
}

size_t bas_frame_auth(uint8_t *buf, const uint8_t bssid[6],
                      const uint8_t src[6], uint16_t seq)
{
    if (buf == NULL || bssid == NULL || src == NULL) {
        return 0;
    }
    size_t n = mgmt_hdr(buf, 11, bssid, src, bssid, seq);
    buf[n++] = 0x00; buf[n++] = 0x00;   /* algorithm: open system         */
    buf[n++] = 0x01; buf[n++] = 0x00;   /* transaction sequence 1         */
    buf[n++] = 0x00; buf[n++] = 0x00;   /* status: reserved in a request  */
    return n;
}

/* Rates the ESP32 radio actually supports, as a supported-rates element. */
static size_t add_rates(uint8_t *b, size_t n)
{
    static const uint8_t rates[] = {
        0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24
    };
    b[n++] = 0x01;                       /* element: supported rates      */
    b[n++] = (uint8_t)sizeof(rates);
    memcpy(&b[n], rates, sizeof(rates));
    return n + sizeof(rates);
}

size_t bas_frame_beacon(uint8_t *buf, const uint8_t bssid[6],
                        const char *ssid, uint8_t channel, uint16_t seq)
{
    if (buf == NULL || bssid == NULL || ssid == NULL) {
        return 0;
    }
    /* Every name this device invents must be identifiable as a test rig by
     * anyone else sniffing the room. Refused here as well as in the UI, so no
     * caller can emit an unlabelled synthetic network. */
    if (!bas_family_label_ok(ssid)) {
        return 0;
    }
    size_t sl = strlen(ssid);
    if (sl > 32u) {
        return 0;
    }

    size_t n = mgmt_hdr(buf, 8, BCAST, bssid, bssid, seq);

    memset(&buf[n], 0, 8);               /* timestamp, filled by hardware */
    n += 8;
    buf[n++] = 0x64; buf[n++] = 0x00;    /* beacon interval: 100 TU       */
    buf[n++] = 0x01; buf[n++] = 0x00;    /* capability: ESS, no privacy   */

    buf[n++] = 0x00;                     /* element: SSID                 */
    buf[n++] = (uint8_t)sl;
    memcpy(&buf[n], ssid, sl);
    n += sl;

    n = add_rates(buf, n);

    buf[n++] = 0x03;                     /* element: DS parameter set     */
    buf[n++] = 0x01;
    buf[n++] = channel;

    return n;
}

size_t bas_frame_probe_req(uint8_t *buf, const uint8_t src[6],
                           const char *ssid, uint8_t channel, uint16_t seq)
{
    if (buf == NULL || src == NULL) {
        return 0;
    }
    size_t sl = (ssid != NULL) ? strlen(ssid) : 0u;
    if (sl > 32u) {
        return 0;
    }
    /* A named probe advertises a network name into the room, so it carries the
     * same labelling requirement. A wildcard probe names nothing and is what
     * every handset in range is already sending. */
    if (sl > 0u && !bas_family_label_ok(ssid)) {
        return 0;
    }

    size_t n = mgmt_hdr(buf, 4, BCAST, src, BCAST, seq);

    buf[n++] = 0x00;                     /* element: SSID                 */
    buf[n++] = (uint8_t)sl;
    if (sl > 0u) {
        memcpy(&buf[n], ssid, sl);
        n += sl;
    }

    n = add_rates(buf, n);

    buf[n++] = 0x03;
    buf[n++] = 0x01;
    buf[n++] = channel;

    return n;
}

void bas_frame_synth_mac(uint8_t out[6], uint32_t seed)
{
    if (out == NULL) {
        return;
    }
    /* A small mix so consecutive seeds do not produce addresses that differ
     * only in the last octet — a detector counting distinct advertisers should
     * see a realistic spread rather than a contiguous block. */
    uint32_t h = seed * 2654435761u;
    out[0] = 0x02;                       /* locally administered, unicast  */
    out[1] = (uint8_t)(h >> 24);
    out[2] = (uint8_t)(h >> 16);
    out[3] = (uint8_t)(h >> 8);
    out[4] = (uint8_t)(h);
    out[5] = (uint8_t)(seed & 0xFFu);

    /* Belt and braces: the group bit must never be set on an address this
     * device generates, or a synthetic identity could become a broadcast
     * destination somewhere downstream. */
    out[0] &= (uint8_t)~0x01u;
}

size_t bas_frame_twin(uint8_t *buf, const uint8_t bssid[6],
                      const char *ssid, uint8_t channel,
                      bool open_conflict, uint16_t seq)
{
    if (buf == NULL || bssid == NULL || ssid == NULL) {
        return 0;
    }
    size_t sl = strlen(ssid);
    if (sl == 0u || sl > 32u) {
        /* A twin of a hidden network has nothing to duplicate. */
        return 0;
    }

    size_t n = mgmt_hdr(buf, 8, BCAST, bssid, bssid, seq);

    memset(&buf[n], 0, 8);
    n += 8;
    buf[n++] = 0x64; buf[n++] = 0x00;    /* beacon interval               */

    /* The conflict is the point: a twin advertising a different security
     * posture from the real network is what a twin detector escalates on.
     * Bit 4 is the Privacy bit. */
    uint16_t cap = open_conflict ? 0x0001u : 0x0011u;
    buf[n++] = (uint8_t)(cap & 0xFFu);
    buf[n++] = (uint8_t)(cap >> 8);

    buf[n++] = 0x00;
    buf[n++] = (uint8_t)sl;
    memcpy(&buf[n], ssid, sl);
    n += sl;

    n = add_rates(buf, n);

    buf[n++] = 0x03;
    buf[n++] = 0x01;
    buf[n++] = channel;

    return n;
}

size_t bas_frame_probe_resp(uint8_t *buf, const uint8_t dst[6],
                            const uint8_t bssid[6], const char *ssid,
                            uint8_t channel, uint16_t seq)
{
    if (buf == NULL || dst == NULL || bssid == NULL || ssid == NULL) {
        return 0;
    }
    /* A response addressed to everybody is a beacon, not an answer, and the
     * karma family is defined by answering one asker at a time. */
    if (bas_mac_is_broadcast(dst) || bas_mac_is_zero(dst)) {
        return 0;
    }
    size_t sl = strlen(ssid);
    if (sl == 0u || sl > 32u) {
        return 0;
    }

    size_t n = mgmt_hdr(buf, 5, dst, bssid, bssid, seq);

    memset(&buf[n], 0, 8);               /* timestamp                     */
    n += 8;
    buf[n++] = 0x64; buf[n++] = 0x00;    /* beacon interval               */
    buf[n++] = 0x01; buf[n++] = 0x00;    /* ESS, no privacy               */

    buf[n++] = 0x00;
    buf[n++] = (uint8_t)sl;
    memcpy(&buf[n], ssid, sl);
    n += sl;

    n = add_rates(buf, n);

    buf[n++] = 0x03;
    buf[n++] = 0x01;
    buf[n++] = channel;

    return n;
}
