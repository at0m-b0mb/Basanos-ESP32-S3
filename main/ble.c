/* Basanos — BLE advertising. SPDX-License-Identifier: MIT */
#include "ble.h"

#include "esp_log.h"

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

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv_set_fields: %d", rc);
        return ESP_FAIL;
    }

    struct ble_gap_adv_params params;
    memset(&params, 0, sizeof(params));
    /* Non-connectable: there is nothing here to connect to, and an advertiser
     * that accepts connections is a service, not a signal. */
    params.conn_mode = BLE_GAP_CONN_MODE_NON;
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
    (void)name; (void)seed;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif
