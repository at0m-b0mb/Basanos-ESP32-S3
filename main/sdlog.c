/* Basanos — the engagement log. SPDX-License-Identifier: MIT */
#include "sdlog.h"
#include "board.h"

#include "driver/sdmmc_host.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "bas_sdlog";

#define MOUNT "/sdcard"
#define LOGFILE MOUNT "/BASANOS.CSV"

static sdmmc_card_t *s_card;
static bool          s_ready;
static uint32_t      s_rows;
static char          s_status[48] = "not initialised";

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

bool bas_sdlog_ready(void)  { return s_ready; }
uint32_t bas_sdlog_rows(void) { return s_rows; }
const char *bas_sdlog_status(void) { return s_status; }

bool bas_sdlog_init(void)
{
    if (s_ready) {
        return true;
    }

    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    host.flags = SDMMC_HOST_FLAG_4BIT;
    host.max_freq_khz = SDMMC_FREQ_DEFAULT;

    sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
    slot.width = 4;
    slot.clk = BOARD_SD_CLK;
    slot.cmd = BOARD_SD_CMD;
    slot.d0  = BOARD_SD_D0;
    slot.d1  = BOARD_SD_D1;
    slot.d2  = BOARD_SD_D2;
    slot.d3  = BOARD_SD_D3;
    slot.flags = SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

    esp_vfs_fat_sdmmc_mount_config_t cfg = {
        /* Do not format a card the operator put in the device. A card that
         * will not mount is a card to look at, not one to erase. */
        .format_if_mount_failed = false,
        .max_files = 3,
        .allocation_unit_size = 16 * 1024,
    };

    esp_err_t rc = esp_vfs_fat_sdmmc_mount(MOUNT, &host, &slot, &cfg, &s_card);
    if (rc != ESP_OK) {
        snprintf(s_status, sizeof(s_status), "no card (%s)",
                 esp_err_to_name(rc));
        ESP_LOGW(TAG, "%s", s_status);
        return false;
    }

    /* Write the header only for a new file, so a card carrying several
     * engagements stays one continuous record. */
    FILE *f = fopen(LOGFILE, "r");
    bool fresh = (f == NULL);
    if (f != NULL) {
        fclose(f);
    }
    f = fopen(LOGFILE, "a");
    if (f == NULL) {
        snprintf(s_status, sizeof(s_status), "card is read-only");
        esp_vfs_fat_sdcard_unmount(MOUNT, s_card);
        s_card = NULL;
        return false;
    }
    if (fresh) {
        fprintf(f, "uptime_ms,record,engagement,operator,family,class,"
                   "ssid,bssid,client,channel,pps,seconds,sent,errors,"
                   "refused,note\n");
    }
    fclose(f);

    s_ready = true;
    snprintf(s_status, sizeof(s_status), "%s", LOGFILE);
    ESP_LOGI(TAG, "logging to %s", LOGFILE);
    return true;
}

/* Commas and newlines in an operator-typed label would split a row into two
 * fields or two rows, so they are replaced rather than quoted -- a log that
 * needs a CSV parser to survive its own input is a log that will be misread. */
static void safe(char *dst, size_t n, const char *src)
{
    if (dst == NULL || n == 0u) {
        return;
    }
    size_t i = 0;
    if (src != NULL) {
        for (; src[i] != '\0' && i + 1u < n; i++) {
            char c = src[i];
            dst[i] = (c == ',' || c == '\n' || c == '\r' || c == '"') ? ' ' : c;
        }
    }
    dst[i] = '\0';
}

static FILE *open_row(void)
{
    if (!s_ready) {
        return NULL;
    }
    return fopen(LOGFILE, "a");
}

void bas_sdlog_run(const bas_engagement_t *e, bas_family_t f,
                   const bas_plan_t *p, const bas_tx_result_t *r,
                   const char *note)
{
    FILE *fp = open_row();
    if (fp == NULL) {
        return;
    }

    const bas_family_spec_t *fs = bas_family(f);
    char label[BAS_LABEL_MAX], oper[BAS_OPERATOR_MAX], ssid[33], note_s[64];
    char bssid[18], client[18];

    safe(label, sizeof(label), e ? e->label : "");
    safe(oper, sizeof(oper), e ? e->operator_name : "");
    safe(ssid, sizeof(ssid), (e && !e->target.hidden) ? e->target.ssid
                                                      : "(hidden)");
    safe(note_s, sizeof(note_s), note);
    bas_mac_fmt(e ? e->target.bssid : NULL, bssid, sizeof(bssid));
    if (e != NULL && e->has_client) {
        bas_mac_fmt(e->client, client, sizeof(client));
    } else {
        snprintf(client, sizeof(client), "-");
    }

    fprintf(fp, "%u,emit,%s,%s,%s,%s,%s,%s,%s,%u,%u,%u,%u,%u,%u,%s\n",
            (unsigned)now_ms(), label, oper,
            fs ? fs->name : "?", fs ? bas_class_name(fs->klass) : "?",
            ssid, bssid, client,
            (unsigned)(p ? p->channel : 0), (unsigned)(p ? p->pps : 0),
            (unsigned)(p ? p->seconds : 0),
            (unsigned)(r ? r->frames_sent : 0),
            (unsigned)(r ? r->tx_errors : 0),
            (unsigned)(r ? r->frames_refused : 0),
            note_s);
    fclose(fp);
    s_rows++;
}

void bas_sdlog_verdict(const bas_engagement_t *e, const bas_run_t *run,
                       uint32_t now_ms_val)
{
    FILE *fp = open_row();
    if (fp == NULL || run == NULL) {
        if (fp != NULL) { fclose(fp); }
        return;
    }

    const bas_family_spec_t *fs = bas_family(run->fam);
    char label[BAS_LABEL_MAX], det[BAS_DETECTOR_NAME_MAX];
    safe(label, sizeof(label), e ? e->label : "");
    safe(det, sizeof(det), run->alarm_detector);

    int32_t lat = bas_run_latency_ms(run);

    fprintf(fp, "%u,verdict,%s,,%s,%s,,,,,,,%u,,,%s latency=%d source=%s\n",
            (unsigned)now_ms_val, label,
            fs ? fs->name : "?", fs ? bas_class_name(fs->klass) : "?",
            (unsigned)run->frames_sent,
            bas_verdict_name(bas_run_verdict(run, now_ms_val)),
            (int)lat,
            run->alarm_seen ? bas_alarm_src_name(run->alarm_source) : "none");
    fclose(fp);
    s_rows++;
}
