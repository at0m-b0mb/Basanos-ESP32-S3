/* Basanos — WPS parsing and the exposure grade.
 *
 * These bytes come off the air and are entirely attacker-controlled, so the
 * malformed cases matter as much as the well-formed ones. The grading tests
 * exist for a different reason: the grade is what lands in a report, and a
 * grade that overstates ("exploitable" when the AP is locked) sends an
 * operator after a closed door, while one that understates hides a finding
 * that ends the engagement.
 *
 * SPDX-License-Identifier: MIT */
#include "harness.h"
#include "basanos/ie.h"

/* A WPS vendor element: 0xDD, length, MS OUI, type 0x04, then TLVs. */
#define WPS_HDR(len) 0xDD, (len), 0x00, 0x50, 0xF2, 0x04

void suite_wps(void)
{
    bas_wps_t w;

    SUITE("wps: a consumer router with the PIN method open");

    /* This is the shape that ends an engagement: configured, not locked, and
     * advertising Label + Display + Keypad. */
    static const uint8_t open_pin[] = {
        WPS_HDR(0x2E),
        0x10, 0x4A, 0x00, 0x01, 0x10,             /* version 1.0          */
        0x10, 0x44, 0x00, 0x01, 0x02,             /* state: configured    */
        0x10, 0x57, 0x00, 0x01, 0x00,             /* not locked           */
        0x10, 0x08, 0x00, 0x02, 0x01, 0x0C,       /* Label|Display|Keypad */
        0x10, 0x21, 0x00, 0x07, 'R','a','l','i','n','k',' ',
        0x10, 0x23, 0x00, 0x06, 'R','T','3','0','7','0',
    };
    CHECK(bas_wps_parse(open_pin, sizeof(open_pin), &w) == BAS_OK);
    CHECK(w.present);
    CHECK(!w.locked);
    CHECK(w.configured);
    CHECK(w.version == 0x10);
    CHECK((w.config_methods & BAS_WPS_CM_LABEL) != 0u);
    CHECK((w.config_methods & BAS_WPS_CM_KEYPAD) != 0u);
    CHECK(strcmp(w.manufacturer, "Ralink ") == 0);
    CHECK(strcmp(w.model, "RT3070") == 0);
    CHECK(bas_wps_grade(&w) == BAS_WPS_PIN_OPEN);
    CHECK(bas_wps_vendor_suspect(&w));

    SUITE("wps: locked beats every other signal");

    /* A locked AP is not attackable however its methods are configured. If
     * this ever grades as PIN_OPEN, the device is sending operators at a door
     * that will not open, and the report is wrong. */
    static const uint8_t locked[] = {
        WPS_HDR(0x14),
        0x10, 0x57, 0x00, 0x01, 0x01,             /* LOCKED               */
        0x10, 0x08, 0x00, 0x02, 0x01, 0x0C,       /* PIN methods anyway   */
        0x10, 0x41, 0x00, 0x01, 0x01,             /* registrar selected   */
    };
    CHECK(bas_wps_parse(locked, sizeof(locked), &w) == BAS_OK);
    CHECK(w.locked);
    CHECK(w.selected_reg);
    CHECK(bas_wps_grade(&w) == BAS_WPS_LOCKED);

    SUITE("wps: push-button only is a window, not a standing door");

    static const uint8_t pbc[] = {
        WPS_HDR(0x0F),
        0x10, 0x57, 0x00, 0x01, 0x00,
        0x10, 0x08, 0x00, 0x02, 0x00, 0x80,       /* PBC alone            */
    };
    CHECK(bas_wps_parse(pbc, sizeof(pbc), &w) == BAS_OK);
    CHECK(bas_wps_grade(&w) == BAS_WPS_PBC_ONLY);
    CHECK(!bas_wps_vendor_suspect(&w));           /* no vendor string     */

    SUITE("wps: silence about methods is not a claim about methods");

    /* Real beacons overwhelmingly omit Config Methods -- it travels in probe
     * responses. Grading that silence as push-button would report a PIN
     * method as absent when it was simply never advertised, and a report
     * built on it would tell a client they are safer than they are. */
    static const uint8_t methods_absent[] = {
        WPS_HDR(0x0E),
        0x10, 0x57, 0x00, 0x01, 0x00,             /* unlocked             */
        0x10, 0x44, 0x00, 0x01, 0x02,             /* configured           */
    };
    CHECK(bas_wps_parse(methods_absent, sizeof(methods_absent), &w) == BAS_OK);
    CHECK(w.present);
    CHECK(w.config_methods == 0u);
    CHECK(bas_wps_grade(&w) == BAS_WPS_ON_UNKNOWN);
    CHECK(bas_wps_grade(&w) != BAS_WPS_PBC_ONLY);

    SUITE("wps: an open registrar outranks a merely open PIN");

    static const uint8_t reg[] = {
        WPS_HDR(0x14),
        0x10, 0x57, 0x00, 0x01, 0x00,
        0x10, 0x41, 0x00, 0x01, 0x01,             /* registrar OPEN NOW   */
        0x10, 0x08, 0x00, 0x02, 0x01, 0x0C,
    };
    CHECK(bas_wps_parse(reg, sizeof(reg), &w) == BAS_OK);
    CHECK(bas_wps_grade(&w) == BAS_WPS_REGISTRAR);

    SUITE("wps: absent means absent, not safe-by-default");

    static const uint8_t no_wps[] = {
        0x00, 0x04, 't','e','s','t',
        0x03, 0x01, 0x06,
    };
    CHECK(bas_wps_parse(no_wps, sizeof(no_wps), &w) == BAS_OK);
    CHECK(!w.present);
    CHECK(bas_wps_grade(&w) == BAS_WPS_NONE);

    /* A DIFFERENT vendor's element must not be read as WPS. Broadcom's OUI
     * with WPS's type byte, and the MS OUI with a non-WPS type, are both
     * common in real beacons. */
    static const uint8_t other_vendor[] = {
        0xDD, 0x08, 0x00, 0x10, 0x18, 0x04, 0x10, 0x57, 0x00, 0x01,
    };
    CHECK(bas_wps_parse(other_vendor, sizeof(other_vendor), &w) == BAS_OK);
    CHECK(!w.present);

    static const uint8_t ms_not_wps[] = {
        0xDD, 0x08, 0x00, 0x50, 0xF2, 0x02, 0x00, 0x01, 0x00, 0x00,
    };
    CHECK(bas_wps_parse(ms_not_wps, sizeof(ms_not_wps), &w) == BAS_OK);
    CHECK(!w.present);

    SUITE("wps: malformed input keeps what it read and stops");

    /* An attribute claiming 0xFFFF bytes inside an 11-byte element. */
    static const uint8_t liar[] = {
        WPS_HDR(0x0F),
        0x10, 0x57, 0x00, 0x01, 0x00,
        0x10, 0x08, 0xFF, 0xFF, 0x01, 0x0C,
    };
    CHECK(bas_wps_parse(liar, sizeof(liar), &w) == BAS_OK);
    CHECK(w.present);
    CHECK(!w.locked);                    /* the attribute before it survived */
    CHECK(w.config_methods == 0u);       /* the liar contributed nothing     */

    /* An element header that runs past the buffer. */
    static const uint8_t short_elem[] = { 0xDD, 0x40, 0x00, 0x50 };
    CHECK(bas_wps_parse(short_elem, sizeof(short_elem), &w) == BAS_OK);
    CHECK(!w.present);

    /* A trailing attribute header with no room for its own length field. */
    static const uint8_t stub[] = { WPS_HDR(0x07), 0x10, 0x57, 0x00 };
    CHECK(bas_wps_parse(stub, sizeof(stub), &w) == BAS_OK);
    CHECK(w.present);

    CHECK(bas_wps_parse(NULL, 0, &w) == BAS_OK);
    CHECK(!w.present);
    CHECK(bas_wps_parse(open_pin, sizeof(open_pin), NULL) == BAS_ERR_ARG);

    SUITE("wps: strings are bounded and stripped of control bytes");

    /* A 60-byte manufacturer name into a 24-byte field, carrying a newline
     * that would otherwise break a report line and a NUL mid-string. */
    static const uint8_t nasty[] = {
        WPS_HDR(0x30),
        0x10, 0x21, 0x00, 0x28,                   /* 40 bytes of value    */
        'A','A','A','A','A','A','A','A','A','A','A','A',
        '\n', 0x00, 0x07,                         /* control bytes        */
        'B','B','B','B','B','B','B','B','B','B','B','B','B',
        'B','B','B','B','B','B','B','B','B','B','B','B',
    };
    CHECK(bas_wps_parse(nasty, sizeof(nasty), &w) == BAS_OK);
    CHECK(strlen(w.manufacturer) == sizeof(w.manufacturer) - 1u);
    CHECK(strchr(w.manufacturer, '\n') == NULL);
    CHECK(w.manufacturer[12] == '.');    /* newline replaced, not dropped  */

    SUITE("wps: every grade has a name and advice an operator can act on");

    for (int r = BAS_WPS_NONE; r <= BAS_WPS_REGISTRAR; r++) {
        const char *n = bas_wps_risk_name((bas_wps_risk_t)r);
        const char *a = bas_wps_advice((bas_wps_risk_t)r);
        CHECK(n != NULL && n[0] != '\0');
        CHECK(a != NULL && a[0] != '\0');
    }
    CHECK(!bas_wps_vendor_suspect(NULL));

    SUITE("wps: the scan entry carries the finding");

    /* The point of the whole feature: by the time an AP is in the list, the
     * finding is already there. Nothing is transmitted to learn it. */
    static const uint8_t beacon[] = {
        0x00, 0x06, 'l','i','n','k','s','y',
        0x03, 0x01, 0x0B,
        WPS_HDR(0x14),
        0x10, 0x57, 0x00, 0x01, 0x00,
        0x10, 0x08, 0x00, 0x02, 0x00, 0x08,       /* Display              */
        0x10, 0x44, 0x00, 0x01, 0x02,
    };
    bas_ap_t ap;
    bas_posture_t p;
    memset(&ap, 0, sizeof(ap));
    CHECK(bas_ie_parse(beacon, sizeof(beacon), &ap, &p) == BAS_OK);
    CHECK(ap.channel == 11);
    CHECK(ap.wps.present);
    CHECK(ap.wps.configured);
    CHECK(bas_wps_grade(&ap.wps) == BAS_WPS_PIN_OPEN);
    /* The posture flags and the full record must agree — they are filled by
     * one parser precisely so they cannot drift. */
    CHECK(p.wps_present == ap.wps.present);
    CHECK(p.wps_locked  == ap.wps.locked);
}
