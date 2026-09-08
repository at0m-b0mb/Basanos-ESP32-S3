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

    /* Attribute a station to a cell. The three addresses mean different things
     * depending on the direction bits, and getting that wrong files the AP as
     * one of its own clients. */
    if (ftype == 2u) {                       /* data */
        bool to_ds   = (h->fc[1] & 0x01u) != 0u;
        bool from_ds = (h->fc[1] & 0x02u) != 0u;
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

void bas_sniff_reset(void)
{
    s_raw = 0;
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
