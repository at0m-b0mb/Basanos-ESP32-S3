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

bas_err_t bas_engage_set_client(bas_engagement_t *e, const uint8_t mac[6])
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
    if (bas_mac_is_broadcast(mac)) {
        return BAS_ERR_BROADCAST;
    }
    memcpy(e->client, mac, 6);
    e->has_client = true;
    return BAS_OK;
}

void bas_engage_clear_client(bas_engagement_t *e)
{
    if (e == NULL) {
        return;
    }
    e->has_client = false;
    memset(e->client, 0, sizeof(e->client));
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

    /* Refuse the group bit before anything else. This is the single check that
     * separates Basanos from every "deauthall" on GitHub, so it does not sit
     * behind a role, a setting, or a build flag. */
    if (bas_mac_is_broadcast(dest)) {
        return BAS_ERR_BROADCAST;
    }
    if (bas_mac_is_zero(dest)) {
        return BAS_ERR_ARG;
    }

    if (!bas_mac_eq(bssid, e->target.bssid)) {
        return BAS_ERR_NO_TARGET;
    }

    /* With a client selected, the only legal destinations are that client and
     * the AP itself. Without one, the AP is the only legal destination — an
     * un-narrowed engagement still cannot spray the clients of a BSS. */
    if (e->has_client) {
        if (!bas_mac_eq(dest, e->client) && !bas_mac_eq(dest, e->target.bssid)) {
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
