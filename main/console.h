/* Basanos — serial control console.
 *
 * Drives the device over the USB cable so a run can be set up and fired
 * without hands on the glass. Built for bring-up and for automated regression
 * against a detector, where pressing buttons by hand is not workable.
 *
 * The safety model does not weaken, it changes shape:
 *
 *   - The cable IS the physical presence. This console exists only on the
 *     USB-Serial/JTAG port; there is no network path to it.
 *   - Remote control is NEVER covert. The moment a command arrives the screen
 *     shows a REMOTE banner, and it stays for the rest of the session.
 *   - The disruptive families still need a deliberate second act. On the glass
 *     that is the hold; here it is the literal word CONFIRM as the last
 *     argument, which cannot arrive by typo or by a stray byte on the line.
 *   - Every command still goes through bas_plan_validate and the engagement
 *     lock. The console is another set of fingers, not a bypass.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_CONSOLE_H
#define BASANOS_CONSOLE_H

#include "basanos/engage.h"
#include "basanos/family.h"

#include <stdbool.h>

typedef enum {
    CMD_NONE = 0,
    CMD_HELP,
    CMD_STATUS,
    CMD_SCAN,
    CMD_LIST,
    CMD_LOCK,
    CMD_UNLOCK,
    CMD_FAMS,
    CMD_RUN,
    CMD_ABORT,
    CMD_CARD,
    CMD_ALARM,
    CMD_SELFTEST,
    CMD_SNIFF,
    CMD_RECON,
} bas_cmd_kind_t;

typedef struct {
    bas_cmd_kind_t kind;
    int  index;                    /* scan index, or family index          */
    int  pps;                      /* 0 = family default                   */
    int  secs;                     /* 0 = family default                   */
    bool confirm;                  /* the CONFIRM token was present        */
    char text[BAS_LABEL_MAX];      /* label, detector name                 */
} bas_cmd_t;

/* Starts the reader task. Safe to call when no host is attached. */
void bas_console_start(void);

/* Non-blocking. Returns true and fills `out` when a command is waiting. */
bool bas_console_take(bas_cmd_t *out);

/* True once any command has been received this session. The UI draws the
 * REMOTE banner from this and does not stop drawing it. */
bool bas_console_active(void);

/* Reply to the host. Prefixed so a script can filter device replies out of
 * the ESP-IDF log stream. */
void bas_console_reply(const char *fmt, ...);

#define BAS_CONSOLE_PREFIX "BAS>"

#endif /* BASANOS_CONSOLE_H */
