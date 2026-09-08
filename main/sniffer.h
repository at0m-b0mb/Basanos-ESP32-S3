/* Basanos — the promiscuous receiver.
 *
 * One piece of infrastructure that unlocks five capabilities at once: the
 * channel analyser, the frame monitor, client enumeration, the probe log, and
 * the karma responder. Everything here is receive-only; the transmit path is
 * still transmit.c and still goes through the engagement lock.
 *
 * The callback runs in the Wi-Fi driver's task. It does the minimum — classify,
 * count, attribute — and never allocates, logs or blocks. Anything expensive
 * belongs in the reader.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_SNIFFER_H
#define BASANOS_SNIFFER_H

#include "basanos/station.h"
#include "basanos/survey.h"
#include "esp_err.h"

/* A network some device in the room asked for by name. This is the client's
 * own history leaking: a phone probing for "Heathrow_WiFi" is telling the room
 * where it has been. */
#define BAS_MAX_PROBES 24

typedef struct {
    char     ssid[33];
    uint8_t  src[6];
    int8_t   rssi;
    uint16_t count;
    uint32_t first_ms;
    uint32_t last_ms;
    bool     randomised;   /* the source MAC is locally administered */
} bas_probe_t;

/* Start listening. `channel` 0 means hop across the regulatory range, which is
 * what the channel analyser wants; a fixed channel is what a run wants, so the
 * emission and the measurement are on the same channel. */
esp_err_t bas_sniff_start(uint8_t channel);
esp_err_t bas_sniff_stop(void);
bool      bas_sniff_active(void);

/* Retune without restarting. */
esp_err_t bas_sniff_channel(uint8_t channel);
uint8_t   bas_sniff_current_channel(void);

/* Hopping steps one channel per call; the caller paces it, so dwell time is a
 * decision the survey makes rather than a constant buried in here. */
void bas_sniff_hop(uint32_t dwell_ms);

void bas_sniff_reset(void);

/* Callback entries before any parsing. Separates "the receiver is not being
 * called" from "the parser is dropping everything". */
uint32_t bas_sniff_raw(void);

/* --- karma ----------------------------------------------------------------

   While armed, every named probe request is queued for one answer. The queue
   is small and drops rather than grows: a busy room can out-produce the
   transmitter, and a backlog answered thirty seconds late is not a karma
   response, it is noise.
   ------------------------------------------------------------------------- */

#define BAS_KARMA_Q 8

typedef struct {
    char    ssid[33];
    uint8_t dst[6];
} bas_karma_req_t;

void bas_sniff_karma_arm(bool on);
bool bas_sniff_karma_armed(void);

/* Pops one pending request. False when there is nothing to answer. */
bool bas_sniff_karma_take(bas_karma_req_t *out);

/* How many names have been answered, and how many were dropped because the
 * queue was full. Both go in the report: a detector's karma logic is scored on
 * the gap between names answered and names announced, so the count of answers
 * is the measurement. */
uint32_t bas_sniff_karma_answered(void);
uint32_t bas_sniff_karma_dropped(void);
void     bas_sniff_karma_note_answer(void);

/* Live views. The structures update under the caller's feet, which is fine for
 * drawing a screen and wrong for arithmetic you intend to keep -- copy first
 * if a number has to stay still. */
const bas_fcount_t     *bas_sniff_frames(void);
const bas_chansurvey_t *bas_sniff_channels(void);
const bas_stalist_t    *bas_sniff_stations(void);
const bas_probe_t      *bas_sniff_probes(int *count);

/* Frames seen carrying this BSSID, for the client picker. */
int bas_sniff_clients_of(const uint8_t bssid[6], bas_stalist_t *out);

#endif /* BASANOS_SNIFFER_H */
