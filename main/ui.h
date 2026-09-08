/* Basanos — the screen set.
 *
 * One generic list renderer does most of the work, so every menu in the device
 * has the same edges, baselines and selection treatment. Screens that are not
 * lists are the ones where the content genuinely differs: the hub, a target,
 * an attack about to fire, a run in flight, the results.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_UI_H
#define BASANOS_UI_H

#include "basanos/engage.h"
#include "basanos/family.h"
#include "basanos/rbac.h"
#include "basanos/score.h"
#include "basanos/station.h"
#include "basanos/target.h"
#include "selftest.h"
#include "ble.h"
#include "sniffer.h"
#include "transmit.h"

/* --- chrome --------------------------------------------------------------- */

/* Battery pip. Draws a charging mark rather than a level while a supply is
 * attached, because a bar that climbs on its own reads as a fault. */
void bas_ui_battery(void *canvas, int x, int y);

/* --- generic list --------------------------------------------------------- */

typedef struct {
    const char *title;
    const char *sub;      /* second line, may be NULL                      */
    uint16_t    stripe;   /* left severity stripe; 0 for none              */
    bool        enabled;  /* disabled rows draw greyed and are not chosen  */
} bas_row_t;

/* `right` is the small label at the top right of the header, may be NULL.
 * The list scrolls to keep `sel` visible. */
void bas_ui_list(const char *title, const char *right,
                 const bas_row_t *rows, int n, int sel,
                 const char *footer);

/* Which row a touch at (x,y) lands on, given the current selection so the
 * scroll offset matches what was drawn. -1 for none. */
int bas_ui_list_hit(uint16_t x, uint16_t y, int sel, int n);

/* --- fixed screens -------------------------------------------------------- */

void bas_ui_splash(void);
void bas_ui_selftest(const bas_selftest_t *r);
void bas_ui_scanning(uint8_t channel, int found);

/* The hub. `sel` highlights one of the four sections. */
typedef enum {
    BAS_HOME_WIFI = 0,
    BAS_HOME_BLE,
    BAS_HOME_RECON,
    BAS_HOME_RESULTS,
    BAS_HOME__COUNT
} bas_home_t;

void bas_ui_home(const bas_engagement_t *e, const bas_scan_t *s,
                 const bas_card_t *card, int sel);
int  bas_ui_home_hit(uint16_t x, uint16_t y);

void bas_ui_networks(const bas_scan_t *s, int sel);
void bas_ui_target(const bas_ap_t *ap, int station_count);

void bas_ui_keyboard(const char *title, const char *buf);
int  bas_ui_keyboard_hit(uint16_t x, uint16_t y);  /* -1 none -2 done -3 back */
char bas_ui_keyboard_char(int key);

/* The arming button on a disruptive family's detail screen.
 *
 * Arming is a hold, and so is going back. Sharing the whole glass between them
 * is what made every other gesture flash the arming gauge, so the hold that
 * arms is confined to this rectangle and a hold anywhere else means back. The
 * two can no longer be confused because they no longer overlap. */
#define BAS_ARM_Y0  192
#define BAS_ARM_Y1  222
bool bas_ui_arm_hit(uint16_t x, uint16_t y);

void bas_ui_attack(bas_family_t f, const bas_plan_t *p,
                   const bas_engagement_t *e, bas_err_t gate);
void bas_ui_hold(bas_family_t f, const bas_engagement_t *e, int pct);
void bas_ui_arm(bas_family_t f, const bas_engagement_t *e, int left);
void bas_ui_running(bas_family_t f, const bas_engagement_t *e,
                    const bas_tx_result_t *p, uint32_t budget);
void bas_ui_ask(bas_family_t f, uint32_t frames, uint32_t grace_left_ms);
void bas_ui_tx_failed(bas_family_t f, const bas_tx_result_t *r);
void bas_ui_results(const bas_card_t *c, uint32_t now_ms);

void bas_ui_note(const char *title, const char *l1, const char *l2,
                 uint16_t accent);

/* --- recon ---------------------------------------------------------------- */

/* Occupancy across the band, as a bar per channel. The channel currently being
 * listened to is marked, because a tall bar on a channel nobody dwelt on means
 * nothing. */
void bas_ui_channels(const bas_chansurvey_t *ch, uint8_t current);

/* What is on air, by frame type, with the rate. */
void bas_ui_frames(const bas_fcount_t *f, uint8_t channel);

/* Clients seen, for narrowing an engagement to one device. */
/* Clients seen, with the selected ones ticked. Row 0 is a select-all/clear
 * action, so the whole set can be taken or dropped without walking the list. */
void bas_ui_clients(const bas_stalist_t *l, int sel,
                    const bas_engagement_t *e);

/* Networks devices in the room are asking for by name -- their own history,
 * leaking. */
void bas_ui_probes(const bas_probe_t *p, int n, int sel);

/* BLE devices in range, trackers striped so they read at a glance. */
void bas_ui_ble_devices(const bas_ble_dev_t *d, int n, int sel,
                        uint32_t tracker_dwell_ms);

/* Live touch check, kept from bring-up: a crosshair where the glass is
 * pressed, so a wrong axis mapping is one press to spot. */
void bas_ui_touchtest(bool present, uint8_t chip_id,
                      bool down, uint16_t x, uint16_t y, int taps);

#endif /* BASANOS_UI_H */
