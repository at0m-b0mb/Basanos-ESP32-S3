/* Basanos — the promiscuous receiver. SPDX-License-Identifier: MIT */
#include "sniffer.h"
#include "board.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"

#include <string.h>

static const char *TAG = "bas_sniff";

static bas_fcount_t     s_frames;
static bas_chansurvey_t s_chan;
static bas_stalist_t    s_stations;
static bas_probe_t      s_probes[BAS_MAX_PROBES];
static int              s_probe_n;

static bas_karma_req_t   s_kq[BAS_KARMA_Q];
static volatile uint8_t  s_k_head, s_k_tail;
static volatile bool     s_karma;
static volatile uint32_t s_k_answered, s_k_dropped;

static bas_handshake_t   s_hs;
static uint8_t           s_hs_bssid[6];
static bool              s_hs_armed;

static bas_pmkid_watch_t s_watch;
static uint8_t           s_watch_sta[6];
static uint8_t           s_watch_bssid[6];

static volatile uint32_t s_raw;   /* callback entries, before any parsing */
static bool    s_active;
static bool    s_hopping;
static uint8_t s_channel = 1;
static uint32_t s_dwell_start;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* --- 802.11 header, only as much as is needed ----------------------------- */

typedef struct {
    uint8_t fc[2];
    uint8_t dur[2];
    uint8_t a1[6];
    uint8_t a2[6];
    uint8_t a3[6];
    uint8_t seq[2];
} __attribute__((packed)) hdr_t;

static void note_probe(const uint8_t *ies, size_t len, const uint8_t src[6],
                       int8_t rssi, uint32_t t)
{
    /* Element 0 is the SSID and is first in a probe request. A wildcard probe
     * carries a zero-length one and names nothing, so it is not a leak and is
     * not recorded. */
    if (len < 2u || ies[0] != 0u) {
        return;
    }
    uint8_t n = ies[1];
    if (n == 0u || n > 32u || (size_t)n + 2u > len) {
        return;
    }

    char ssid[33];
    memcpy(ssid, &ies[2], n);
    ssid[n] = '\0';
    for (uint8_t i = 0; i < n; i++) {
        /* A control byte in an SSID is either a broken AP or someone probing
         * the parser. Either way it does not go in a list that gets drawn. */
        if ((unsigned char)ssid[i] < 0x20u) {
            return;
        }
    }

    if (s_karma) {
        uint8_t next = (uint8_t)((s_k_head + 1u) % BAS_KARMA_Q);
        if (next == s_k_tail) {
            /* Full. Drop rather than block the receiver or grow a backlog
             * that would be answered far too late to be a response. */
            s_k_dropped++;
        } else {
            memcpy(s_kq[s_k_head].ssid, ssid, (size_t)n + 1u);
            memcpy(s_kq[s_k_head].dst, src, 6);
            s_k_head = next;
        }
    }

    for (int i = 0; i < s_probe_n; i++) {
        if (strcmp(s_probes[i].ssid, ssid) == 0 &&
            memcmp(s_probes[i].src, src, 6) == 0) {
            s_probes[i].last_ms = t;
            s_probes[i].rssi    = rssi;
            if (s_probes[i].count < 0xFFFFu) {
                s_probes[i].count++;
            }
            return;
        }
    }
    if (s_probe_n >= BAS_MAX_PROBES) {
        return;
    }
    bas_probe_t *p = &s_probes[s_probe_n++];
    memset(p, 0, sizeof(*p));
    memcpy(p->ssid, ssid, (size_t)n + 1u);
    memcpy(p->src, src, 6);
    p->rssi       = rssi;
    p->count      = 1;
    p->first_ms   = t;
    p->last_ms    = t;
    p->randomised = bas_mac_is_randomised(src);
}

/* Look for a PMKID key-data element in EAPOL message 1.
 *
 * Records only that one was present. The value is deliberately never copied
 * anywhere: this function has no out-parameter for it and no caller could ask.
 */
/* Collect the two halves of the four-way handshake.
 *
 * Message 1 carries the authenticator nonce; message 2 carries the supplicant
 * nonce and a MIC computed over itself. Verifying a candidate passphrase means
 * recomputing that MIC, so message 2 is kept verbatim with its MIC field
 * zeroed -- which is the form the computation needs. */
static void note_handshake(const uint8_t *e, size_t len, const uint8_t *a1,
                           const uint8_t *a2, bool from_ap)
{
    if (!s_hs_armed || len < 99u) {
        return;
    }
    uint16_t info = (uint16_t)((e[5] << 8) | e[6]);
    bool ack = (info & 0x0080u) != 0u;
    bool mic = (info & 0x0100u) != 0u;
    uint8_t ver = (uint8_t)(info & 0x0007u);

    if (ack && !mic && from_ap) {                  /* message 1            */
        memcpy(s_hs.anonce, &e[17], 32);
        memcpy(s_hs.ap, a2, 6);
        memcpy(s_hs.sta, a1, 6);
        s_hs.key_ver = ver;
        s_hs.have_m1 = true;
        return;
    }

    if (mic && !ack && !from_ap) {                 /* message 2            */
        /* Only the pair that belongs together: a message 2 answering some
         * other message 1 would derive a key that never validates and would
         * report a weak passphrase as strong. */
        if (!s_hs.have_m1 || memcmp(s_hs.sta, a2, 6) != 0) {
            return;
        }
        size_t flen = 4u + (size_t)((e[2] << 8) | e[3]);
        if (flen > len || flen > BAS_EAPOL_MAX) {
            return;
        }
        memcpy(s_hs.snonce, &e[17], 32);
        memcpy(s_hs.mic, &e[81], 16);
        memcpy(s_hs.m2, e, flen);
        memset(&s_hs.m2[81], 0, 16);               /* MIC zeroed for the sum */
        s_hs.m2_len = (uint16_t)flen;
        s_hs.key_ver = ver;
        s_hs.have_m2 = true;
    }
}

static void note_eapol(const uint8_t *p, size_t len, uint32_t t)
{
    /* LLC/SNAP then EtherType 0x888E. */
    static const uint8_t snap[] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00,
                                    0x88, 0x8E };
    if (len < sizeof(snap) || memcmp(p, snap, sizeof(snap)) != 0) {
        return;
    }
    size_t off = sizeof(snap);

    /* EAPOL header: version, type (3 = key), length. */
    if (off + 4u > len || p[off + 1] != 0x03u) {
        return;
    }
    off += 4u;

    /* Key descriptor type, then key information. */
    if (off + 3u > len) {
        return;
    }
    off += 1u;
    uint16_t info = (uint16_t)((p[off] << 8) | p[off + 1]);

    /* M1 is the one with ACK set and MIC clear: the AP has spoken first and
     * nothing has been proven yet, which is exactly why a PMKID here is
     * available to anybody who asks. */
    bool ack = (info & 0x0080u) != 0u;
    bool mic = (info & 0x0100u) != 0u;
    if (!ack || mic) {
        return;
    }

    s_watch.eapol_m1 = true;
    s_watch.m1_ms = t;

    /* Skip to the key-data length: info(2) len(2) replay(8) nonce(32) iv(16)
     * rsc(8) reserved(8) mic(16). */
    size_t kd_len_off = off + 2u + 2u + 8u + 32u + 16u + 8u + 8u + 16u;
    if (kd_len_off + 2u > len) {
        return;
    }
    uint16_t kd_len = (uint16_t)((p[kd_len_off] << 8) | p[kd_len_off + 1]);
    size_t kd = kd_len_off + 2u;
    if (kd_len == 0u || kd + kd_len > len) {
        return;
    }

    /* The PMKID KDE: vendor-specific, length 20, OUI 00-0F-AC, data type 4. */
    for (size_t i = 0; i + 6u <= (size_t)kd_len; i++) {
        const uint8_t *q = &p[kd + i];
        if (q[0] == 0xDDu && q[1] == 0x14u &&
            q[2] == 0x00u && q[3] == 0x0Fu && q[4] == 0xACu && q[5] == 0x04u) {
            s_watch.pmkid_offered = true;
            return;
        }
    }
}

static void IRAM_ATTR on_packet(void *buf, wifi_promiscuous_pkt_type_t type)
{
    s_raw++;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    if (pkt == NULL || pkt->rx_ctrl.sig_len < (int)sizeof(hdr_t)) {
        return;
    }

    const hdr_t *h = (const hdr_t *)pkt->payload;
    uint8_t ftype    = (uint8_t)((h->fc[0] >> 2) & 0x03u);
    uint8_t fsubtype = (uint8_t)((h->fc[0] >> 4) & 0x0Fu);
    int8_t  rssi     = (int8_t)pkt->rx_ctrl.rssi;
    uint8_t ch       = (uint8_t)pkt->rx_ctrl.channel;
    uint32_t t       = now_ms();

    bas_ftype_t k = bas_ftype_of(ftype, fsubtype);
    bas_fcount_add(&s_frames, k, (uint16_t)pkt->rx_ctrl.sig_len, t);
    bas_chan_note_frame(&s_chan, ch, rssi);

    if (k == BAS_FT_BEACON) {
        bas_chan_note_ap(&s_chan, ch);
        return;
    }

    if (k == BAS_FT_PROBE_REQ) {
        size_t off = sizeof(hdr_t);
        if ((size_t)pkt->rx_ctrl.sig_len > off) {
            note_probe(&pkt->payload[off],
                       (size_t)pkt->rx_ctrl.sig_len - off, h->a2, rssi, t);
        }
        return;
    }

    /* The PMKID watch: only frames the access point addressed to our
     * synthetic station. */
    if (s_watch.watching && bas_mac_eq(h->a1, s_watch_sta) &&
        bas_mac_eq(h->a2, s_watch_bssid)) {
        size_t hlen = sizeof(hdr_t);
        if (ftype == 0u && fsubtype == 11u) {          /* auth response   */
            if ((size_t)pkt->rx_ctrl.sig_len >= hlen + 6u) {
                s_watch.auth_resp = true;
                s_watch.auth_status =
                    (uint16_t)(pkt->payload[hlen + 4] |
                               (pkt->payload[hlen + 5] << 8));
            }
        } else if (ftype == 0u && fsubtype == 1u) {    /* assoc response  */
            if ((size_t)pkt->rx_ctrl.sig_len >= hlen + 4u) {
                s_watch.assoc_resp = true;
                s_watch.assoc_status =
                    (uint16_t)(pkt->payload[hlen + 2] |
                               (pkt->payload[hlen + 3] << 8));
            }
        } else if (ftype == 2u) {                      /* data: EAPOL?    */
            /* QoS data carries two extra header bytes before the payload. */
            size_t off = hlen + ((fsubtype & 0x08u) ? 2u : 0u);
            if ((size_t)pkt->rx_ctrl.sig_len > off) {
                note_eapol(&pkt->payload[off],
                           (size_t)pkt->rx_ctrl.sig_len - off, t);
            }
        }
    }

    /* Attribute a station to a cell. The three addresses mean different things
     * depending on the direction bits, and getting that wrong files the AP as
     * one of its own clients. */
    if (ftype == 2u) {                       /* data */
        bool to_ds   = (h->fc[1] & 0x01u) != 0u;
        bool from_ds = (h->fc[1] & 0x02u) != 0u;

        if (s_hs_armed &&
            (bas_mac_eq(h->a1, s_hs_bssid) || bas_mac_eq(h->a2, s_hs_bssid) ||
             bas_mac_eq(h->a3, s_hs_bssid))) {
            size_t off = sizeof(hdr_t) + ((fsubtype & 0x08u) ? 2u : 0u);
            static const uint8_t snap[] = { 0xAA, 0xAA, 0x03, 0x00, 0x00,
                                            0x00, 0x88, 0x8E };
            if ((size_t)pkt->rx_ctrl.sig_len > off + sizeof(snap) &&
                memcmp(&pkt->payload[off], snap, sizeof(snap)) == 0) {
                note_handshake(&pkt->payload[off + sizeof(snap)],
                               (size_t)pkt->rx_ctrl.sig_len - off - sizeof(snap),
                               h->a1, h->a2, from_ds);
            }
        }
        if (to_ds && !from_ds) {
            /* station -> AP: a2 is the client, a1 the BSSID */
            bas_sta_observe(&s_stations, h->a2, h->a1, rssi, t);
        } else if (!to_ds && from_ds) {
            /* AP -> station: a1 is the client, a2 the BSSID */
            bas_sta_observe(&s_stations, h->a1, h->a2, rssi, t);
        }
    }
}

/* --- control -------------------------------------------------------------- */

uint32_t bas_sniff_raw(void) { return s_raw; }

void bas_sniff_handshake_arm(const uint8_t bssid[6], const char *ssid)
{
    if (bssid == NULL || ssid == NULL) {
        return;
    }
    bas_wpa_wipe(&s_hs);
    memcpy(s_hs_bssid, bssid, 6);
    size_t n = strlen(ssid);
    if (n > 32u) { n = 32u; }
    memcpy(s_hs.ssid, ssid, n);
    s_hs.ssid_len = (uint8_t)n;
    s_hs_armed = true;
}

void bas_sniff_handshake_disarm(void) { s_hs_armed = false; }
bool bas_sniff_handshake_armed(void)  { return s_hs_armed; }
const bas_handshake_t *bas_sniff_handshake(void) { return &s_hs; }

void bas_sniff_handshake_wipe(void)
{
    s_hs_armed = false;
    bas_wpa_wipe(&s_hs);
}

void bas_sniff_watch(const uint8_t sta[6], const uint8_t bssid[6])
{
    if (sta == NULL || bssid == NULL) {
        return;
    }
    /* A run cycles through several identities, and the answer it is looking
     * for may arrive under any of them. The findings are therefore sticky
     * across a re-watch: resetting them would let a later identity erase the
     * evidence an earlier one earned. */
    bool m1     = s_watch.eapol_m1;
    bool pmkid  = s_watch.pmkid_offered;
    bool sticky = s_watch.watching;

    memset(&s_watch, 0, sizeof(s_watch));
    if (sticky) {
        s_watch.eapol_m1      = m1;
        s_watch.pmkid_offered = pmkid;
    }
    memcpy(s_watch_sta, sta, 6);
    memcpy(s_watch_bssid, bssid, 6);
    s_watch.started_ms = now_ms();
    s_watch.watching = true;
}

void bas_sniff_watch_stop(void) { s_watch.watching = false; }

const bas_pmkid_watch_t *bas_sniff_watch_result(void) { return &s_watch; }

void bas_sniff_karma_arm(bool on)
{
    s_karma = on;
    if (!on) {
        s_k_head = s_k_tail = 0;
    }
}

bool bas_sniff_karma_armed(void) { return s_karma; }

bool bas_sniff_karma_take(bas_karma_req_t *out)
{
    if (out == NULL || s_k_tail == s_k_head) {
        return false;
    }
    *out = s_kq[s_k_tail];
    s_k_tail = (uint8_t)((s_k_tail + 1u) % BAS_KARMA_Q);
    return true;
}

uint32_t bas_sniff_karma_answered(void) { return s_k_answered; }
uint32_t bas_sniff_karma_dropped(void)  { return s_k_dropped; }
void     bas_sniff_karma_note_answer(void) { s_k_answered++; }

void bas_sniff_reset(void)
{
    s_raw = 0;
    s_k_head = s_k_tail = 0;
    s_k_answered = s_k_dropped = 0;
    bas_fcount_reset(&s_frames, now_ms());
    bas_chan_reset(&s_chan);
    bas_sta_reset(&s_stations);
    memset(s_probes, 0, sizeof(s_probes));
    s_probe_n = 0;
}

esp_err_t bas_sniff_start(uint8_t channel)
{
    if (s_active) {
        return bas_sniff_channel(channel);
    }

    bas_sniff_reset();

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_CTRL,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(on_packet);

    esp_err_t rc = esp_wifi_set_promiscuous(true);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "promiscuous: %s", esp_err_to_name(rc));
        return rc;
    }

    s_active  = true;
    s_hopping = (channel == 0u);
    s_channel = s_hopping ? 1u : channel;
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    s_dwell_start = now_ms();

    ESP_LOGI(TAG, "listening, %s", s_hopping ? "hopping" : "camped");
    return ESP_OK;
}

esp_err_t bas_sniff_stop(void)
{
    if (!s_active) {
        return ESP_OK;
    }
    s_active  = false;
    s_hopping = false;
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "stopped");
    return ESP_OK;
}

bool bas_sniff_active(void) { return s_active; }

esp_err_t bas_sniff_channel(uint8_t channel)
{
    if (channel < 1u || channel > 14u) {
        return ESP_ERR_INVALID_ARG;
    }
    /* Credit the dwell to the channel that earned it, before moving. */
    bas_chan_note_dwell(&s_chan, s_channel, now_ms() - s_dwell_start);
    s_channel = channel;
    s_hopping = false;
    s_dwell_start = now_ms();
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

uint8_t bas_sniff_current_channel(void) { return s_channel; }

void bas_sniff_hop(uint32_t dwell_ms)
{
    if (!s_active) {
        return;
    }
    uint32_t t = now_ms();
    if ((t - s_dwell_start) < dwell_ms) {
        return;
    }
    bas_chan_note_dwell(&s_chan, s_channel, t - s_dwell_start);

    uint8_t max_ch = bas_region_max_channel();
    s_channel = (uint8_t)((s_channel % max_ch) + 1u);
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    s_dwell_start = t;
    s_hopping = true;
}

const bas_fcount_t     *bas_sniff_frames(void)   { return &s_frames; }

const bas_chansurvey_t *bas_sniff_channels(void)
{
    /* Bank the time spent on the current channel before handing the survey
     * out. Crediting dwell only when retuning meant a camped channel never
     * banked any, so ten seconds of listening still reported "not measured
     * long enough to judge" -- the honest refusal firing on a measurement that
     * had actually been made. */
    if (s_active) {
        uint32_t t = now_ms();
        bas_chan_note_dwell(&s_chan, s_channel, t - s_dwell_start);
        s_dwell_start = t;
    }
    return &s_chan;
}
const bas_stalist_t    *bas_sniff_stations(void) { return &s_stations; }

const bas_probe_t *bas_sniff_probes(int *count)
{
    if (count != NULL) {
        *count = s_probe_n;
    }
    return s_probes;
}

int bas_sniff_clients_of(const uint8_t bssid[6], bas_stalist_t *out)
{
    if (out == NULL || bssid == NULL) {
        return 0;
    }
    *out = s_stations;
    bas_sta_filter(out, bssid);
    bas_sta_sort_rssi(out);
    return out->count;
}
