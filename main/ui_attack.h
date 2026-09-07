/* Basanos — the screens that lead to a transmission.
 * SPDX-License-Identifier: MIT */
#ifndef BASANOS_UI_ATTACK_H
#define BASANOS_UI_ATTACK_H

#include "basanos/engage.h"
#include "basanos/rbac.h"
#include "basanos/family.h"
#include "basanos/score.h"
#include "transmit.h"

/* Target confirmation, before an engagement exists. Shows the posture that
 * decides whether a run against this network is worth spending. */
void bas_ui_target(const bas_ap_t *ap, int station_count);

/* On-screen keyboard for the authorisation label. `buf` is edited in place.
 * Returns via the hit-test helpers below; the caller owns the loop. */
void bas_ui_keyboard(const char *title, const char *buf);
int  bas_ui_keyboard_hit(uint16_t x, uint16_t y);   /* -1 none, -2 done, -3 back */
char bas_ui_keyboard_char(int key);

/* Hold-to-arm, for the disruptive families.
 *
 * Replaces a typed PIN. A sustained physical act cannot happen by accident,
 * needs no keyboard on a 240px panel, and is over in a second and a half --
 * the point was never to make the operator prove they can type. `pct` is 0..100.
 */
void bas_ui_hold_arm(bas_family_t f, const bas_engagement_t *e, int pct);

/* The family menu. Unavailable families are shown greyed with the reason,
 * rather than hidden — a missing capability should be visible. */
void bas_ui_families(int sel, uint8_t role, const bas_engagement_t *e);
int  bas_ui_families_hit(uint16_t x, uint16_t y, int sel);

void bas_ui_family_detail(bas_family_t f, const bas_plan_t *p,
                          const bas_engagement_t *e, uint8_t role,
                          bas_err_t gate);

/* Arming countdown. `left` counts down to zero. */
void bas_ui_arm(bas_family_t f, const bas_engagement_t *e, int left);

/* Live run. Drawn from the transmit engine's own progress. */
void bas_ui_running(bas_family_t f, const bas_engagement_t *e,
                    const bas_tx_result_t *p, uint32_t budget);

/* After a run: ask whether the detector reacted. This is the operator alarm
 * path, and the screen says so, because the latency it produces includes a
 * human and must not be compared with a wire. */
void bas_ui_ask_alarm(bas_family_t f, uint32_t frames, uint32_t grace_left_ms);

void bas_ui_scorecard(const bas_card_t *c, uint32_t now_ms);

#endif /* BASANOS_UI_ATTACK_H */
