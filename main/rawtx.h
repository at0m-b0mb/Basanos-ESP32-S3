/* Basanos — raw 802.11 injection availability.
 *
 * ESP-IDF's Wi-Fi library sanity-checks every frame handed to
 * esp_wifi_80211_tx and refuses management subtypes it considers abusive:
 * deauthentication, disassociation and authentication. The rejection is
 * `unsupport frame type: 0c0` and ESP_ERR_INVALID_ARG, so a run reports
 * success at the API level and emits nothing.
 *
 * The check lives behind a weak symbol, so a firmware that needs raw injection
 * overrides it. That is what rawtx.c does, and it is why the three disruptive
 * families can transmit at all.
 *
 * The part that matters for an instrument: whether the override actually
 * LINKED is not knowable at compile time -- it depends on link order against a
 * closed-source blob. So the override answers a magic argument distinctively,
 * and this module asks. A build where the bypass did not take reports its
 * disruptive families as unavailable rather than running them and scoring the
 * silence as a detector's failure.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_RAWTX_H
#define BASANOS_RAWTX_H

#include <stdbool.h>

/* True when raw management injection is actually available in this binary. */
bool bas_rawtx_available(void);

/* One line for the self-test and the interface. */
const char *bas_rawtx_status(void);

#endif /* BASANOS_RAWTX_H */
