/* Basanos — shared helpers. SPDX-License-Identifier: MIT */
#include "basanos/basanos.h"

#include <string.h>
#include <stdio.h>

static const char *const k_err[BAS_ERR__COUNT] = {
    [BAS_OK]                  = "ok",
    [BAS_ERR_NO_TARGET]       = "no target selected",
    [BAS_ERR_NOT_LOCKED]      = "target not locked",
    [BAS_ERR_EXPIRED]         = "engagement expired",
    [BAS_ERR_BROADCAST]       = "broadcast target refused",
    [BAS_ERR_SELF]            = "target is this device",
    [BAS_ERR_BAD_BSSID]       = "invalid BSSID",
    [BAS_ERR_NO_LABEL]        = "authorisation label required",
    [BAS_ERR_ROLE]            = "role not permitted",
    [BAS_ERR_AUTH]            = "bad user or password",
    [BAS_ERR_LOCKED_OUT]      = "locked out, wait",
    [BAS_ERR_NO_SPACE]        = "user table full",
    [BAS_ERR_EXISTS]          = "user exists",
    [BAS_ERR_UNKNOWN_FAMILY]  = "unknown family",
    [BAS_ERR_RATE]            = "rate above ceiling",
    [BAS_ERR_DURATION]        = "duration above ceiling",
    [BAS_ERR_CHANNEL]         = "channel outside region",
    [BAS_ERR_NO_RUN]          = "no such run",
    [BAS_ERR_RUN_CLOSED]      = "run already closed",
    [BAS_ERR_FULL]            = "card full",
    [BAS_ERR_ARG]             = "bad argument",
};

const char *bas_err_str(bas_err_t e)
{
    if ((int)e < 0 || e >= BAS_ERR__COUNT || k_err[e] == NULL) {
        return "unknown error";
    }
    return k_err[e];
}

bool bas_mac_is_broadcast(const uint8_t mac[6])
{
    if (mac == NULL) {
        return false;
    }
    /* Broadcast is the all-ones case, but every multicast address (group bit
     * set in the first octet) is equally unacceptable as a destination — one
     * of them is how you deauth an entire BSS. Treat the whole class alike. */
    return (mac[0] & 0x01u) != 0u;
}

bool bas_mac_is_zero(const uint8_t mac[6])
{
    if (mac == NULL) {
        return true;
    }
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0u) {
            return false;
        }
    }
    return true;
}

bool bas_mac_eq(const uint8_t a[6], const uint8_t b[6])
{
    if (a == NULL || b == NULL) {
        return false;
    }
    return memcmp(a, b, 6) == 0;
}

void bas_mac_fmt(const uint8_t mac[6], char *out, size_t out_len)
{
    if (out == NULL || out_len == 0u) {
        return;
    }
    if (mac == NULL || out_len < 18u) {
        out[0] = '\0';
        return;
    }
    snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool bas_strlcpy(char *dst, const char *src, size_t dst_sz)
{
    if (dst == NULL || dst_sz == 0u) {
        return false;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return true;
    }
    size_t i = 0;
    for (; src[i] != '\0' && i + 1u < dst_sz; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
    return src[i] == '\0';
}

bool bas_ct_eq(const void *a, const void *b, size_t n)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0u;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0u;
}
