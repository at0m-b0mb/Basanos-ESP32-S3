/* Basanos — the engagement lock. SPDX-License-Identifier: MIT */
#include "basanos/engage.h"

#include <string.h>

void bas_engage_clear(bas_engagement_t *e)
{
    if (e == NULL) {
        return;
    }
    memset(e, 0, sizeof(*e));
}

static bool str_has_content(const char *s)
{
    if (s == NULL) {
        return false;
    }
    for (; *s != '\0'; s++) {
        if (*s != ' ' && *s != '\t') {
            return true;
        }
    }
    return false;
}

bas_err_t bas_engage_lock(bas_engagement_t *e,
                          const bas_ap_t *target,
                          const char *label,
                          const char *operator_name,
                          uint32_t now_ms,
                          uint32_t ttl_ms)
{
    if (e == NULL || target == NULL) {
        return BAS_ERR_ARG;
    }

    bas_err_t rc = bas_ap_check(target);
    if (rc != BAS_OK) {
        return rc;
    }

    /* A whitespace-only label is not a label. This is the one field that says
     * under what authority the run happened, and it is worth being strict
     * about — an operator who cannot name the authorisation should stop. */
    if (!str_has_content(label)) {
        return BAS_ERR_NO_LABEL;
    }
    if (!str_has_content(operator_name)) {
        return BAS_ERR_ARG;
    }
    if (ttl_ms < BAS_TTL_MIN_MS || ttl_ms > BAS_TTL_MAX_MS) {
        return BAS_ERR_ARG;
    }

    memset(e, 0, sizeof(*e));
    e->target = *target;
    e->has_target = true;
    (void)bas_strlcpy(e->label, label, sizeof(e->label));
    (void)bas_strlcpy(e->operator_name, operator_name, sizeof(e->operator_name));
    e->locked_ms  = now_ms;
    e->expires_ms = now_ms + ttl_ms;
    e->locked     = true;
    return BAS_OK;
}

bas_err_t bas_engage_lock_area(bas_engagement_t *e,
                               const char *label,
                               const char *operator_name,
                               uint32_t now_ms,
                               uint32_t ttl_ms)
{
    if (e == NULL) {
        return BAS_ERR_ARG;
    }
    if (!str_has_content(label)) {
        return BAS_ERR_NO_LABEL;
    }
    if (!str_has_content(operator_name)) {
        return BAS_ERR_ARG;
    }
    if (ttl_ms < BAS_TTL_MIN_MS || ttl_ms > BAS_TTL_MAX_MS) {
        return BAS_ERR_ARG;
    }

    memset(e, 0, sizeof(*e));
    (void)bas_strlcpy(e->label, label, sizeof(e->label));
    (void)bas_strlcpy(e->operator_name, operator_name, sizeof(e->operator_name));
    e->locked     = true;
    e->has_target = false;    /* every needs_target family is refused */
    e->locked_ms  = now_ms;
    e->expires_ms = now_ms + ttl_ms;
    return BAS_OK;
}

bool bas_engage_has_client(const bas_engagement_t *e, const uint8_t mac[6])
{
    if (e == NULL || mac == NULL) {
        return false;
    }
    for (uint8_t i = 0; i < e->client_n; i++) {
        if (bas_mac_eq(e->client[i], mac)) {
            return true;
        }
    }
    return false;
}

bas_err_t bas_engage_add_client(bas_engagement_t *e, const uint8_t mac[6])
{
    if (e == NULL || mac == NULL) {
        return BAS_ERR_ARG;
    }
    if (!e->locked) {
        return BAS_ERR_NOT_LOCKED;
    }
    if (!e->has_target) {
        /* A client narrows a target. There is nothing here to narrow. */
        return BAS_ERR_NO_TARGET;
    }
    if (bas_mac_is_zero(mac)) {
        return BAS_ERR_ARG;
    }
    /* The whole point of a set is that every member is a real chosen device.
     * A group address in it would reintroduce broadcast by the back door. */
    if (bas_mac_is_broadcast(mac)) {
        return BAS_ERR_BROADCAST;
    }
    /* The access point is already the default destination; listing it as a
     * client would double it. */
    if (bas_mac_eq(mac, e->target.bssid)) {
        return BAS_ERR_ARG;
    }
    if (bas_engage_has_client(e, mac)) {
        return BAS_OK;
    }
    if (e->client_n >= BAS_MAX_CLIENTS) {
        return BAS_ERR_NO_SPACE;
    }
    memcpy(e->client[e->client_n], mac, 6);
    e->client_n++;
    return BAS_OK;
}

bas_err_t bas_engage_remove_client(bas_engagement_t *e, const uint8_t mac[6])
{
    if (e == NULL || mac == NULL) {
        return BAS_ERR_ARG;
    }
    for (uint8_t i = 0; i < e->client_n; i++) {
        if (bas_mac_eq(e->client[i], mac)) {
            for (uint8_t j = i; j + 1u < e->client_n; j++) {
                memcpy(e->client[j], e->client[j + 1], 6);
            }
            e->client_n--;
            memset(e->client[e->client_n], 0, 6);
            return BAS_OK;
        }
    }
    return BAS_ERR_NO_TARGET;
}

bas_err_t bas_engage_set_client(bas_engagement_t *e, const uint8_t mac[6])
{
    if (e == NULL) {
        return BAS_ERR_ARG;
    }
    bas_engage_clear_clients(e);
    return bas_engage_add_client(e, mac);
}

void bas_engage_clear_clients(bas_engagement_t *e)
{
    if (e == NULL) {
        return;
    }
    e->client_n = 0;
    memset(e->client, 0, sizeof(e->client));
}

bas_err_t bas_engage_set_whole_cell(bas_engagement_t *e, bool on)
{
    if (e == NULL) {
        return BAS_ERR_ARG;
    }
    if (!e->locked) {
        return BAS_ERR_NOT_LOCKED;
    }
    if (on && !e->has_target) {
        /* A broadcast frame is scoped by the BSSID it carries. Without a
         * target there is no BSSID, so there is no cell to address and the
         * frame would be the untargeted one this device will not send. */
        return BAS_ERR_NO_TARGET;
    }
    if (on) {
        /* The two are alternatives, not layers: a broadcast already reaches
         * every station in the cell, so a client list alongside it would be
         * decoration that implies a narrowing which is not happening. */
        bas_engage_clear_clients(e);
    }
    e->whole_cell = on;
    return BAS_OK;
}

bool bas_engage_is_whole_cell(const bas_engagement_t *e)
{
    return e != NULL && e->whole_cell;
}

uint8_t bas_engage_dest_count(const bas_engagement_t *e)
{
    if (e == NULL || !e->locked || !e->has_target) {
        return 0u;
    }
    /* With nothing selected the access point is the only destination -- an
     * un-narrowed engagement still cannot spray the clients of a cell. */
    return (e->client_n > 0u) ? e->client_n : 1u;
}

const uint8_t *bas_engage_dest(const bas_engagement_t *e, uint32_t n)
{
    if (e == NULL || !e->locked || !e->has_target) {
        return NULL;
    }
    if (e->whole_cell) {
        static const uint8_t bcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
        return bcast;
    }
    if (e->client_n == 0u) {
        return e->target.bssid;
    }
    return e->client[n % e->client_n];
}

bas_err_t bas_engage_check(const bas_engagement_t *e, uint32_t now_ms)
{
    if (e == NULL) {
        return BAS_ERR_ARG;
    }
    if (!e->locked) {
        return BAS_ERR_NOT_LOCKED;
    }
    /* Unsigned subtraction so a wrapped tick counter cannot resurrect an
     * expired engagement: the device runs for days and esp_timer wraps. */
    if ((uint32_t)(now_ms - e->locked_ms) >= (uint32_t)(e->expires_ms - e->locked_ms)) {
        return BAS_ERR_EXPIRED;
    }
    return BAS_OK;
}

uint32_t bas_engage_remaining_ms(const bas_engagement_t *e, uint32_t now_ms)
{
    if (e == NULL || !e->locked) {
        return 0u;
    }
    uint32_t span    = e->expires_ms - e->locked_ms;
    uint32_t elapsed = now_ms - e->locked_ms;
    if (elapsed >= span) {
        return 0u;
    }
    return span - elapsed;
}

bas_err_t bas_engage_permits_frame(const bas_engagement_t *e,
                                   const uint8_t dest[6],
                                   const uint8_t bssid[6],
                                   uint32_t now_ms)
{
    if (e == NULL || dest == NULL || bssid == NULL) {
        return BAS_ERR_ARG;
    }

    bas_err_t rc = bas_engage_check(e, now_ms);
    if (rc != BAS_OK) {
        return rc;
    }
    if (!e->has_target) {
        /* A label-only engagement addresses nothing. */
        return BAS_ERR_NO_TARGET;
    }

    /* The BSSID is what scopes a frame, so it is checked first and always.
     * A broadcast frame carrying the locked target's BSSID reaches that cell
     * and no other; one carrying any other BSSID is the untargeted sweep this
     * device will not send, and no mode enables it. */
    if (!bas_mac_eq(bssid, e->target.bssid)) {
        return BAS_ERR_NO_TARGET;
    }

    if (bas_mac_is_broadcast(dest)) {
        /* Deliberate, per-engagement, and never the default. */
        if (!e->whole_cell) {
            return BAS_ERR_BROADCAST;
        }
        return BAS_OK;
    }
    if (bas_mac_is_zero(dest)) {
        return BAS_ERR_ARG;
    }

    /* With a client selected, the only legal destinations are that client and
     * the AP itself. Without one, the AP is the only legal destination — an
     * un-narrowed engagement still cannot spray the clients of a BSS. */
    /* With clients selected, the legal destinations are those clients and the
     * access point. Without any, the access point alone. Either way every
     * frame is addressed to something the operator chose. */
    if (e->client_n > 0u) {
        if (!bas_engage_has_client(e, dest) &&
            !bas_mac_eq(dest, e->target.bssid)) {
            return BAS_ERR_NO_TARGET;
        }
    } else if (!bas_mac_eq(dest, e->target.bssid)) {
        return BAS_ERR_NO_TARGET;
    }

    return BAS_OK;
}

void bas_engage_note_run(bas_engagement_t *e)
{
    if (e != NULL && e->runs < UINT32_MAX) {
        e->runs++;
    }
}
