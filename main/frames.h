/* Basanos — 802.11 frame construction.
 *
 * Builders only. Nothing here transmits and nothing here checks authorisation;
 * transmit.c does both. Keeping construction separate means a frame can be
 * built and inspected in a test without a radio.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_FRAMES_H
#define BASANOS_FRAMES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest frame any builder here produces (a beacon with a 32-byte SSID). */
#define BAS_FRAME_MAX 128

/* Directed management frames. `dst` is the station being addressed, `src` is
 * the transmitter, `bssid` the cell. Return the frame length. */
size_t bas_frame_deauth(uint8_t *buf, const uint8_t dst[6],
                        const uint8_t src[6], const uint8_t bssid[6],
                        uint16_t reason, uint16_t seq);

size_t bas_frame_disassoc(uint8_t *buf, const uint8_t dst[6],
                          const uint8_t src[6], const uint8_t bssid[6],
                          uint16_t reason, uint16_t seq);

/* Authentication request, open system, sequence 1. Sent from a synthetic
 * station to the target AP — this is the association-table pressure family. */
size_t bas_frame_auth(uint8_t *buf, const uint8_t bssid[6],
                      const uint8_t src[6], uint16_t seq);

/* Broadcast advertisement frames. These are addressed to everyone by
 * definition, which is why they are not subject to the target lock — they deny
 * nothing to anybody. `ssid` must carry the BASANOS- prefix; the builder
 * refuses and returns 0 if it does not. */
size_t bas_frame_beacon(uint8_t *buf, const uint8_t bssid[6],
                        const char *ssid, uint8_t channel, uint16_t seq);

size_t bas_frame_probe_req(uint8_t *buf, const uint8_t src[6],
                           const char *ssid, uint8_t channel, uint16_t seq);

/* Evil twin: a beacon carrying an arbitrary SSID from a synthetic BSSID.
 *
 * This is the ONLY builder that will put a name on air without the BASANOS-
 * prefix, and it exists for exactly one purpose: duplicating the network the
 * engagement is locked to, so a detector's twin logic has something real to
 * score. The caller must pass the locked target's own SSID — transmit.c takes
 * it straight from the engagement and from nowhere else.
 *
 * `open_conflict` advertises the twin without privacy, which is the
 * security-class conflict a twin detector is supposed to escalate on. */
size_t bas_frame_twin(uint8_t *buf, const uint8_t bssid[6],
                      const char *ssid, uint8_t channel,
                      bool open_conflict, uint16_t seq);

/* A locally-administered, unicast MAC derived from `seed`. Used for the
 * synthetic identities the beacon, probe and auth families need.
 *
 * The locally-administered bit is set deliberately: these addresses must be
 * recognisable as synthetic rather than colliding with a real vendor prefix,
 * and the group bit is always cleared so a generated address can never become
 * a broadcast destination. */
void bas_frame_synth_mac(uint8_t out[6], uint32_t seed);

#endif /* BASANOS_FRAMES_H */
