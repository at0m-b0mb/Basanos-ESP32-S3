/* Basanos — on-device self-test.
 *
 * The host suite proves the engines are correct on a laptop. This proves the
 * same invariants hold on the silicon that will actually transmit — different
 * compiler, different word size assumptions, different alignment rules.
 *
 * It runs on every boot, before the radio is initialised. The safety
 * invariants are the ones worth re-checking here: if "an admin with no
 * engagement cannot transmit" is not true on this chip, the device must say so
 * on its own screen rather than proceed.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_SELFTEST_H
#define BASANOS_SELFTEST_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int  checks;
    int  failures;
    char first_failure[48];
} bas_selftest_t;

void bas_selftest_run(bas_selftest_t *out);

/* True only when every check passed. The UI refuses to leave the self-test
 * screen when this is false — a device whose safety invariants do not hold on
 * its own hardware has no business showing a target picker. */
bool bas_selftest_ok(const bas_selftest_t *r);

#endif /* BASANOS_SELFTEST_H */
