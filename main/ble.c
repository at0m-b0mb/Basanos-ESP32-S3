/* Basanos — BLE advertising. SPDX-License-Identifier: MIT */
#include "ble.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "basanos/family.h"

static const char *TAG = "bas_ble";

#if CONFIG_BT_NIMBLE_ENABLED

#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

static volatile bool s_synced;
static bool          s_inited;
static bool          s_advertising;
static uint32_t      s_count;

static void on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    s_synced = true;
    ESP_LOGI(TAG, "host synced");
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "host reset, reason %d", reason);
    s_synced = false;
}

static void host_task(void *arg)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t bas_ble_init(void)
{
    if (s_inited) {
        return s_synced ? ESP_OK : ESP_ERR_INVALID_STATE;
    }

    esp_err_t rc = nimble_port_init();
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init: %s", esp_err_to_name(rc));
        return rc;
    }

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ble_svc_gap_init();
    nimble_port_freertos_init(host_task);
    s_inited = true;

    /* The host syncs asynchronously. Wait briefly rather than returning a
     * handle that is not usable yet -- a family that starts advertising into
     * an unsynced host fails silently, which is the worst outcome for an
     * instrument whose job is telling you whether something was emitted. */
    for (int i = 0; i < 100 && !s_synced; i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (!s_synced) {
        ESP_LOGE(TAG, "host did not sync");
        return ESP_ERR_TIMEOUT;
    }
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

bool bas_ble_ready(void) { return s_inited && s_synced; }

uint32_t bas_ble_advert_count(void) { return s_count; }
void     bas_ble_reset_count(void)  { s_count = 0; }

/* --- observer -------------------------------------------------------------- */

static bas_ble_dev_t s_dev[BAS_BLE_MAX_DEV];
static int           s_dev_n;
static bool          s_scanning;

const char *bas_ble_kind_name(bas_ble_kind_t k)
{
    switch (k) {
    case BAS_BLE_BASANOS:   return "ours";
    case BAS_BLE_FINDMY:    return "Find My tracker";
    case BAS_BLE_APPLE:     return "Apple";
    case BAS_BLE_TILE:      return "Tile tracker";
    case BAS_BLE_SMARTTAG:  return "SmartTag";
    case BAS_BLE_FASTPAIR:  return "Fast Pair";
    case BAS_BLE_MICROSOFT: return "Swift Pair";
    case BAS_BLE_FLIPPER:   return "Flipper Zero";
    default:                return "unknown";
    }
}

bool bas_ble_kind_is_tracker(bas_ble_kind_t k)
{
    return k == BAS_BLE_FINDMY || k == BAS_BLE_TILE || k == BAS_BLE_SMARTTAG;
}

/* Classify from the advertisement payload.
 *
 * Deliberately coarse. Manufacturer data tells you which ecosystem a device
 * belongs to, not what the device is, so "looks like Find My" is a claim the
 * bytes support and "is an AirTag" is not -- and the interface says the former.
 */
static bas_ble_kind_t classify(const uint8_t *d, size_t len, const char *name)
{
    if (name != NULL && strncmp(name, BAS_TEST_PREFIX,
                                sizeof(BAS_TEST_PREFIX) - 1u) == 0) {
        return BAS_BLE_BASANOS;
    }
    /* The Flipper advertises its user-set name, which conventionally leads
     * with the product name. Weak evidence, and labelled as a guess. */
    if (name != NULL && strncasecmp(name, "Flipper", 7) == 0) {
        return BAS_BLE_FLIPPER;
    }

    size_t i = 0;
    while (i + 1u < len) {
        uint8_t l = d[i];
        if (l == 0u || i + 1u + l > len) {
            break;
        }
        uint8_t type = d[i + 1];
        const uint8_t *v = &d[i + 2];
        uint8_t vlen = (uint8_t)(l - 1u);

        if (type == 0xFFu && vlen >= 2u) {          /* manufacturer data   */
            uint16_t cid = (uint16_t)(v[0] | (v[1] << 8));
            if (cid == 0x004Cu && vlen >= 3u) {     /* Apple               */
                /* Type 0x12 is the Find My network advertisement a separated
                 * tracker sends. Type 0x07/0x0F/0x10 are proximity pairing and
                 * Continuity, which is a phone or a pair of earbuds. */
                return (v[2] == 0x12u) ? BAS_BLE_FINDMY : BAS_BLE_APPLE;
            }
            if (cid == 0x0075u) { return BAS_BLE_SMARTTAG; }
            if (cid == 0x0006u) { return BAS_BLE_MICROSOFT; }
        }

        if ((type == 0x03u || type == 0x02u) && vlen >= 2u) {  /* 16-bit UUIDs */
            for (uint8_t k = 0; k + 1u < vlen; k += 2u) {
                uint16_t u = (uint16_t)(v[k] | (v[k + 1] << 8));
                if (u == 0xFEEDu) { return BAS_BLE_TILE; }
                if (u == 0xFE2Cu) { return BAS_BLE_FASTPAIR; }
                if (u == 0xFD5Au) { return BAS_BLE_SMARTTAG; }
            }
        }
        i += 1u + l;
    }
    return BAS_BLE_UNKNOWN;
}

static void extract_name(const uint8_t *d, size_t len, char *out, size_t n)
{
    out[0] = '\0';
    size_t i = 0;
    while (i + 1u < len) {
        uint8_t l = d[i];
        if (l == 0u || i + 1u + l > len) {
            break;
        }
        uint8_t type = d[i + 1];
        if (type == 0x09u || type == 0x08u) {       /* complete/short name */
            size_t take = l - 1u;
            if (take > n - 1u) { take = n - 1u; }
            for (size_t k = 0; k < take; k++) {
                char c = (char)d[i + 2 + k];
                /* A control byte in a name is either a broken device or
                 * someone probing the parser; neither belongs on a screen. */
                out[k] = ((unsigned char)c < 0x20u) ? '.' : c;
            }
            out[take] = '\0';
            return;
        }
        i += 1u + l;
    }
}

static void observe(const struct ble_gap_disc_desc *d)
{
    uint32_t t = (uint32_t)(esp_timer_get_time() / 1000);

    char name[BAS_BLE_NAME_MAX];
    extract_name(d->data, d->length_data, name, sizeof(name));
    bas_ble_kind_t kind = classify(d->data, d->length_data, name);

    for (int i = 0; i < s_dev_n; i++) {
        if (memcmp(s_dev[i].addr, d->addr.val, 6) == 0) {
            s_dev[i].rssi    = d->rssi;
            s_dev[i].last_ms = t;
            if (s_dev[i].count < 0xFFFFu) { s_dev[i].count++; }
            if (name[0] != '\0' && s_dev[i].name[0] == '\0') {
                strncpy(s_dev[i].name, name, sizeof(s_dev[i].name) - 1u);
            }
            /* An advertisement that classifies is better evidence than one
             * that does not, so a later identification is kept. */
            if (kind != BAS_BLE_UNKNOWN) { s_dev[i].kind = kind; }
            return;
        }
    }
    if (s_dev_n >= BAS_BLE_MAX_DEV) {
        return;
    }
    bas_ble_dev_t *e = &s_dev[s_dev_n++];
    memset(e, 0, sizeof(*e));
    memcpy(e->addr, d->addr.val, 6);
    e->addr_type  = d->addr.type;
    e->rssi       = d->rssi;
    e->kind       = kind;
    e->count      = 1;
    e->first_ms   = t;
    e->last_ms    = t;
    /* A resolvable-private or non-resolvable random address is rotated for
     * privacy, so this device may not be the same one it was ten minutes ago. */
    e->randomised = (d->addr.type == BLE_ADDR_RANDOM);
    strncpy(e->name, name, sizeof(e->name) - 1u);
}

static int on_disc(struct ble_gap_event *ev, void *arg)
{
    if (ev->type == BLE_GAP_EVENT_DISC) {
        observe(&ev->disc);
    }
    return 0;
}

esp_err_t bas_ble_scan_start(void)
{
    if (bas_ble_init() != ESP_OK) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (s_scanning) {
        return ESP_OK;
    }

    struct ble_gap_disc_params p;
    memset(&p, 0, sizeof(p));
    /* Passive: never send a scan request. An active scan solicits a response
     * and would make this a transmission, which the recon section is not. */
    p.passive        = 1;
    p.filter_duplicates = 0;
    p.itvl           = 0x0060;
    p.window         = 0x0030;

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &p, on_disc, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "disc: %d", rc);
        return ESP_FAIL;
    }
    s_scanning = true;
    ESP_LOGI(TAG, "scanning, passive");
    return ESP_OK;
}

esp_err_t bas_ble_scan_stop(void)
{
    if (!s_scanning) {
        return ESP_OK;
    }
    ble_gap_disc_cancel();
    s_scanning = false;
    return ESP_OK;
}

bool bas_ble_scanning(void) { return s_scanning; }

const bas_ble_dev_t *bas_ble_devices(int *count)
{
    if (count != NULL) { *count = s_dev_n; }
    return s_dev;
}

void bas_ble_scan_reset(void)
{
    memset(s_dev, 0, sizeof(s_dev));
    s_dev_n = 0;
}

uint32_t bas_ble_longest_tracker_dwell(uint32_t now_ms)
{
    uint32_t best = 0;
    for (int i = 0; i < s_dev_n; i++) {
        if (!bas_ble_kind_is_tracker(s_dev[i].kind)) {
            continue;
        }
        /* Dwell is first-seen to last-seen, not to now: a tracker that left
         * ten minutes ago did not dwell for ten more minutes. */
        uint32_t d = s_dev[i].last_ms - s_dev[i].first_ms;
        if (d > best) { best = d; }
    }
    (void)now_ms;
    return best;
}

esp_err_t bas_ble_stop(void)
{
    if (!s_advertising) {
        return ESP_OK;
    }
    ble_gap_adv_stop();
    s_advertising = false;
    return ESP_OK;
}

esp_err_t bas_ble_advertise(const char *name, uint32_t seed)
{
    return bas_ble_advertise_as(name, seed, BAS_ADV_NAME);
}

esp_err_t bas_ble_advertise_as(const char *name, uint32_t seed,
                               bas_adv_shape_t shape)
{
    if (!bas_ble_ready()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Re-advertising under a new identity means stopping first; NimBLE will
     * not change the address while an advertisement is live. */
    if (s_advertising) {
        ble_gap_adv_stop();
        s_advertising = false;
    }

    /* A random static address must carry 0b11 in the top two bits of its most
     * significant octet, and NimBLE takes the address little-endian, so that
     * octet is byte 5. Getting either wrong is rejected by the host rather
     * than silently advertised. */
    uint32_t h = seed * 2654435761u;
    ble_addr_t addr = { .type = BLE_ADDR_RANDOM };
    addr.val[0] = (uint8_t)(seed & 0xFFu);
    addr.val[1] = (uint8_t)(h);
    addr.val[2] = (uint8_t)(h >> 8);
    addr.val[3] = (uint8_t)(h >> 16);
    addr.val[4] = (uint8_t)(h >> 24);
    addr.val[5] = (uint8_t)((h >> 16) | 0xC0u);

    /* A static address is invalid if its random part is all zeros or all ones,
     * and the host rejects it rather than advertising something malformed.
     * Seed 0 hashes to exactly zero and produced that on the first identity of
     * every spam run -- one guaranteed failure per run, every run. */
    if ((addr.val[0] | addr.val[1] | addr.val[2] |
         addr.val[3] | addr.val[4]) == 0u && (addr.val[5] & 0x3Fu) == 0u) {
        addr.val[0] = 0x01u;
    }
    if ((addr.val[0] & addr.val[1] & addr.val[2] &
         addr.val[3] & addr.val[4]) == 0xFFu && (addr.val[5] & 0x3Fu) == 0x3Fu) {
        addr.val[0] = 0xFEu;
    }

    int rc = ble_hs_id_set_rnd(addr.val);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "set_rnd: %d", rc);
    }

    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)name;
    fields.name_len = (uint8_t)strlen(name);
    fields.name_is_complete = 1;

    /* Company id 0xFFFF is reserved by the SIG for testing. A well-formed
     * manufacturer payload that belongs to nobody. */
    static uint8_t mfr[25];
    static ble_uuid16_t svc16;

    if (shape == BAS_ADV_BEACON) {
        /* An advertisement is 31 bytes. Flags take 3, a 25-byte manufacturer
         * payload takes 27, and a name would take a dozen more -- the host
         * rejects the whole frame and nothing goes out. A real proximity
         * beacon carries no name either, so dropping it is the authentic
         * shape as well as the one that fits. */
        fields.name = NULL;
        fields.name_len = 0;
        fields.name_is_complete = 0;

        /* Proximity-beacon shape: company, type, length, a 16-byte identifier,
         * major, minor, measured power. The identifier is derived from the
         * seed rather than copied from anyone. */
        mfr[0] = (uint8_t)(BAS_BLE_TEST_COMPANY & 0xFFu);
        mfr[1] = (uint8_t)(BAS_BLE_TEST_COMPANY >> 8);
        mfr[2] = 0x02;                 /* beacon type    */
        mfr[3] = 0x15;                 /* 21 bytes follow */
        for (int i = 0; i < 16; i++) {
            mfr[4 + i] = (uint8_t)((h >> ((i % 4) * 8)) ^ (0xA5u + i));
        }
        mfr[20] = (uint8_t)(seed >> 8);   /* major */
        mfr[21] = (uint8_t)(seed);
        mfr[22] = (uint8_t)(seed >> 16);  /* minor */
        mfr[23] = (uint8_t)(seed >> 24);
        mfr[24] = 0xC5;                   /* measured power */
        fields.mfg_data     = mfr;
        fields.mfg_data_len = 25;
    } else if (shape == BAS_ADV_SERVICE) {
        /* 0xFFF0 sits in the range vendors use for private services, so it
         * reads as a real service to a scanner without claiming a registered
         * one. */
        svc16 = (ble_uuid16_t)BLE_UUID16_INIT(0xFFF0);
        fields.uuids16 = &svc16;
        fields.num_uuids16 = 1;
        fields.uuids16_is_complete = 1;
    }

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv_set_fields: %d", rc);
        return ESP_FAIL;
    }

    struct ble_gap_adv_params params;
    memset(&params, 0, sizeof(params));
    /* Non-connectable by default: there is nothing here to connect to, and an
     * advertiser that accepts connections is a service rather than a signal.
     *
     * The peripheral shape is the deliberate exception. A connectable device
     * appearing where none belongs is exactly what a rogue-peripheral detector
     * looks for, and it cannot be tested with an advertisement that refuses
     * connections. Nothing is served behind it -- there are no characteristics
     * and no data to read. */
    params.conn_mode = (shape == BAS_ADV_CONNECTABLE) ? BLE_GAP_CONN_MODE_UND
                                                      : BLE_GAP_CONN_MODE_NON;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    params.itvl_min  = 0x0020;    /* 20 ms */
    params.itvl_max  = 0x0030;    /* 30 ms */

    rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER,
                           &params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv_start: %d", rc);
        return ESP_FAIL;
    }

    s_advertising = true;
    s_count++;
    return ESP_OK;
}

#else  /* Bluetooth disabled in the build */

esp_err_t bas_ble_init(void)   { return ESP_ERR_NOT_SUPPORTED; }
bool      bas_ble_ready(void)  { return false; }
esp_err_t bas_ble_stop(void)   { return ESP_OK; }
uint32_t  bas_ble_advert_count(void) { return 0; }
void      bas_ble_reset_count(void)  { }

esp_err_t bas_ble_advertise(const char *name, uint32_t seed)
{
    return bas_ble_advertise_as(name, seed, BAS_ADV_NAME);
}

esp_err_t bas_ble_advertise_as(const char *name, uint32_t seed,
                               bas_adv_shape_t shape)
{
    (void)name; (void)seed;
    return ESP_ERR_NOT_SUPPORTED;
}

const char *bas_ble_kind_name(bas_ble_kind_t k) { (void)k; return "unknown"; }
bool bas_ble_kind_is_tracker(bas_ble_kind_t k)  { (void)k; return false; }
esp_err_t bas_ble_scan_start(void) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t bas_ble_scan_stop(void)  { return ESP_OK; }
bool bas_ble_scanning(void)        { return false; }
void bas_ble_scan_reset(void)      { }
uint32_t bas_ble_longest_tracker_dwell(uint32_t n) { (void)n; return 0; }
const bas_ble_dev_t *bas_ble_devices(int *count)
{
    if (count != NULL) { *count = 0; }
    return NULL;
}

#endif
