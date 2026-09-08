/* Basanos — serial control console. SPDX-License-Identifier: MIT */
#include "console.h"

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *TAG = "bas_con";

static QueueHandle_t s_q;
static volatile bool s_active;

bool bas_console_active(void) { return s_active; }

void bas_console_reply(const char *fmt, ...)
{
    char line[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    printf("%s %s\n", BAS_CONSOLE_PREFIX, line);
    fflush(stdout);
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0u && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                      s[n - 1] == ' '  || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

/* Split on whitespace, in place. Returns the token count. */
static int tokenise(char *s, char *tok[], int max)
{
    int n = 0;
    char *p = s;
    while (*p != '\0' && n < max) {
        while (*p == ' ' || *p == '\t') { p++; }
        if (*p == '\0') { break; }
        tok[n++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t') { p++; }
        if (*p != '\0') { *p++ = '\0'; }
    }
    return n;
}

static int atoi_safe(const char *s)
{
    if (s == NULL) { return 0; }
    int v = 0;
    for (; *s >= '0' && *s <= '9'; s++) {
        if (v > 100000) { return 100000; }
        v = v * 10 + (*s - '0');
    }
    return v;
}

static bool parse(char *line, bas_cmd_t *c)
{
    memset(c, 0, sizeof(*c));

    char *tok[10];
    int n = tokenise(line, tok, 10);
    if (n == 0) { return false; }

    /* CONFIRM may sit anywhere; it is a deliberate extra act, not a position.
     * Case-sensitive on purpose: a lowercase "confirm" does not arm anything,
     * so the token cannot be produced by habit. */
    for (int i = 1; i < n; i++) {
        if (strcmp(tok[i], "CONFIRM") == 0) {
            c->confirm = true;
        }
    }

    const char *v = tok[0];
    if (!strcmp(v, "help") || !strcmp(v, "?")) { c->kind = CMD_HELP; return true; }
    if (!strcmp(v, "status"))   { c->kind = CMD_STATUS;   return true; }
    if (!strcmp(v, "scan"))     { c->kind = CMD_SCAN;     return true; }
    if (!strcmp(v, "list"))     { c->kind = CMD_LIST;     return true; }
    if (!strcmp(v, "unlock"))   { c->kind = CMD_UNLOCK;   return true; }
    if (!strcmp(v, "fams"))     { c->kind = CMD_FAMS;     return true; }
    if (!strcmp(v, "abort"))    { c->kind = CMD_ABORT;    return true; }
    if (!strcmp(v, "card"))     { c->kind = CMD_CARD;     return true; }
    if (!strcmp(v, "selftest")) { c->kind = CMD_SELFTEST; return true; }
    if (!strcmp(v, "recon"))    { c->kind = CMD_RECON;    return true; }

    if (!strcmp(v, "sniff")) {
        c->kind = CMD_SNIFF;
        /* "sniff off" stops; "sniff" hops; "sniff 6" camps on a channel. */
        if (n >= 2 && !strcmp(tok[1], "off")) { c->index = -1; }
        else if (n >= 2)                      { c->index = atoi_safe(tok[1]); }
        else                                  { c->index = 0; }
        return true;
    }

    if (!strcmp(v, "lock")) {
        if (n < 3) { return false; }
        c->kind  = CMD_LOCK;
        c->index = atoi_safe(tok[1]);
        /* Everything after the index is the label, spaces included. */
        c->text[0] = '\0';
        for (int i = 2; i < n; i++) {
            if (c->confirm && !strcmp(tok[i], "CONFIRM")) { continue; }
            if (c->text[0] != '\0') {
                strncat(c->text, " ", sizeof(c->text) - strlen(c->text) - 1u);
            }
            strncat(c->text, tok[i], sizeof(c->text) - strlen(c->text) - 1u);
        }
        return c->text[0] != '\0';
    }

    if (!strcmp(v, "run")) {
        if (n < 2) { return false; }
        c->kind  = CMD_RUN;
        c->index = atoi_safe(tok[1]);
        c->pps   = (n >= 3) ? atoi_safe(tok[2]) : 0;
        c->secs  = (n >= 4) ? atoi_safe(tok[3]) : 0;
        return true;
    }

    if (!strcmp(v, "alarm")) {
        c->kind = CMD_ALARM;
        if (n >= 2) {
            strncpy(c->text, tok[1], sizeof(c->text) - 1u);
        } else {
            strncpy(c->text, "console", sizeof(c->text) - 1u);
        }
        return true;
    }

    return false;
}

static void reader(void *arg)
{
    char line[160];
    size_t len = 0;

    bas_console_reply("ready — 'help' for commands");

    while (true) {
        char ch;
        int r = read(fileno(stdin), &ch, 1);
        if (r != 1) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        if (ch == '\n' || ch == '\r') {
            if (len == 0u) { continue; }
            line[len] = '\0';
            len = 0;

            trim(line);
            bas_cmd_t c;
            if (parse(line, &c)) {
                s_active = true;
                if (xQueueSend(s_q, &c, 0) != pdTRUE) {
                    bas_console_reply("busy");
                }
            } else {
                bas_console_reply("bad command — 'help'");
            }
            continue;
        }

        if (len + 1u < sizeof(line)) {
            line[len++] = ch;
        } else {
            /* Overlong line: drop it rather than executing a truncated
             * command that might mean something different. */
            len = 0;
            bas_console_reply("line too long");
        }
    }
}

void bas_console_start(void)
{
    /* Deep enough that a script issuing a few commands back to back is
     * not rejected while the panel repaints between them. */
    s_q = xQueueCreate(12, sizeof(bas_cmd_t));
    if (s_q == NULL) {
        ESP_LOGE(TAG, "no queue");
        return;
    }

    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    if (usb_serial_jtag_driver_install(&cfg) == ESP_OK) {
        usb_serial_jtag_vfs_use_driver();
    }
    setvbuf(stdin, NULL, _IONBF, 0);

    xTaskCreate(reader, "bas_con", 4096, NULL, 4, NULL);
    ESP_LOGI(TAG, "console up on USB-Serial/JTAG");
}

bool bas_console_take(bas_cmd_t *out)
{
    if (s_q == NULL || out == NULL) {
        return false;
    }
    return xQueueReceive(s_q, out, 0) == pdTRUE;
}
