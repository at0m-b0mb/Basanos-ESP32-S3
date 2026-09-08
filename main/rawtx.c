/* Basanos — raw 802.11 injection availability. SPDX-License-Identifier: MIT */
#include "rawtx.h"

#include <stdint.h>

/* The magic argument. The real library function has no reason to treat any
 * particular value specially, so a distinctive answer to this one is proof
 * that the override below is the symbol that linked. */
#define BAS_RAWTX_PROBE 31337

/* Intercepts the sanity check inside the closed-source Wi-Fi library.
 *
 * The library's symbol is strong, so this collides at link time unless the
 * link is told to allow it -- see main/CMakeLists.txt. --wrap was tried first
 * and does not work: the library both defines and calls this function inside
 * one object file, so the call never crosses a boundary the linker can
 * rewrite.
 *
 * Returning 0 means "this frame is fine", which is what lets deauthentication,
 * disassociation and authentication frames reach the radio. Without it those
 * three families are accepted by the API and silently dropped.
 *
 * This is deliberately the only place in the firmware that widens what the
 * radio will emit. Everything about WHO may emit, at WHAT, and for how long
 * is decided before a frame is ever built -- the engagement lock, the role,
 * the ceilings and the frame gate all sit upstream of here and are untouched
 * by it. */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2,
                                     int32_t arg3)
{
    (void)arg2;
    (void)arg3;
    if (arg == BAS_RAWTX_PROBE) {
        return 1;               /* the probe: "yes, this override is linked" */
    }
    return 0;                   /* every real frame: permitted              */
}

bool bas_rawtx_available(void)
{
    /* Calling the unwrapped name reaches the wrapper, so a distinctive answer
     * proves the redirect is in this binary. */
    return ieee80211_raw_frame_sanity_check(BAS_RAWTX_PROBE, 0, 0) == 1;
}

const char *bas_rawtx_status(void)
{
    return bas_rawtx_available() ? "raw injection available"
                                 : "raw injection blocked by the Wi-Fi library";
}
