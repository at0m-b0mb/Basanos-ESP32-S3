/* Basanos — the WPS finding, split out so the scan entry can carry it.
 *
 * ie.h includes target.h, so the type a scan entry stores cannot live in ie.h.
 * SPDX-License-Identifier: MIT
 */
#ifndef BASANOS_WPS_FWD_H
#define BASANOS_WPS_FWD_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WPS config-method bits, from the specification. */
#define BAS_WPS_CM_USBA        0x0001u
#define BAS_WPS_CM_ETHERNET    0x0002u
#define BAS_WPS_CM_LABEL       0x0004u
#define BAS_WPS_CM_DISPLAY     0x0008u
#define BAS_WPS_CM_EXT_NFC     0x0010u
#define BAS_WPS_CM_INT_NFC     0x0020u
#define BAS_WPS_CM_NFC_IFACE   0x0040u
#define BAS_WPS_CM_PBC         0x0080u
#define BAS_WPS_CM_KEYPAD      0x0100u

typedef struct {
    bool     present;
    bool     locked;          /* AP setup locked                            */
    bool     configured;      /* WPS state 2, rather than 1 (unconfigured)  */
    bool     selected_reg;    /* a registrar session is open right now      */
    uint16_t config_methods;
    uint8_t  version;         /* 0x10 = 1.0, 0x20 = 2.0                     */
    char     manufacturer[24];
    char     model[24];
} bas_wps_t;

typedef enum {
    BAS_WPS_NONE = 0,     /* not advertised                                 */
    BAS_WPS_LOCKED,       /* present but locked out                         */
    BAS_WPS_PBC_ONLY,     /* push-button only: a window, not a standing door*/
    BAS_WPS_PIN_OPEN,     /* a PIN method, unlocked: online attack applies  */
    BAS_WPS_REGISTRAR,    /* a registrar is active this moment              */
} bas_wps_risk_t;

#ifdef __cplusplus
}
#endif
#endif /* BASANOS_WPS_FWD_H */
