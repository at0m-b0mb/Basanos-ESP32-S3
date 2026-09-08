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
#include "basanos/target.h"
#include "basanos/wpa.h"
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

/* --- passive discovery -----------------------------------------------------

   Networks assembled from beacons as they arrive, rather than by asking. A
   blocking scan takes about thirteen seconds and freezes the interface for all
   of it; the receiver is already hopping the band, so the same information can
   be had continuously and for free.

   The posture (security, channel, hidden) is parsed once on first sighting.
   Re-parsing every beacon would cost a full element walk hundreds of times a
   second for information that does not change.
   ------------------------------------------------------------------------- */

const bas_scan_t *bas_sniff_networks(void);

/* Merge what the receiver has found into an existing scan list, so a passive
 * discovery does not discard what an active scan already established. Returns
 * how many entries were new. */
int bas_sniff_merge_networks(bas_scan_t *dst);

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

/* --- PMKID solicitation watch ----------------------------------------------

   While a synthetic station is being watched, the receiver follows what the
   access point says back to it: the authentication response, the association
   response, and EAPOL message 1.

   It records WHETHER a PMKID was offered. It does not record the PMKID. The
   sensor being tested detects the solicitation, not what the tester keeps, so
   storing sixteen bytes of crackable material would add liability and no
   measurement. "This AP hands a PMKID to any unauthenticated device" is the
   finding worth putting in a report.
   ------------------------------------------------------------------------- */

typedef struct {
    bool     watching;
    bool     auth_resp;
    uint16_t auth_status;
    bool     assoc_resp;
    uint16_t assoc_status;
    bool     eapol_m1;
    bool     pmkid_offered;   /* a PMKID KDE was present -- never its value */
    uint32_t started_ms;
    uint32_t m1_ms;
} bas_pmkid_watch_t;

/* Follow what `bssid` says to `sta`. */
void bas_sniff_watch(const uint8_t sta[6], const uint8_t bssid[6]);
void bas_sniff_watch_stop(void);
const bas_pmkid_watch_t *bas_sniff_watch_result(void);

/* --- four-way handshake capture -------------------------------------------

   Held in RAM only, for exactly as long as the audit takes. Nothing here is
   written to the card, the console or the log: the finding is the output, the
   handshake is not. bas_sniff_handshake_wipe() is called the moment an audit
   finishes, whatever the verdict.
   ------------------------------------------------------------------------- */

/* Capture the next handshake seen for this BSSID. `ssid` is needed because it
 * salts the key derivation, and a capture without it cannot be tested. */
void bas_sniff_handshake_arm(const uint8_t bssid[6], const char *ssid);
void bas_sniff_handshake_disarm(void);
bool bas_sniff_handshake_armed(void);

const bas_handshake_t *bas_sniff_handshake(void);
void bas_sniff_handshake_wipe(void);

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
