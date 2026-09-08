<p align="center">
  <img src="assets/banner.svg" alt="Basanos — the touchstone for wireless defences" width="100%">
</p>

<p align="center">
  <a href="#authorised-testing-only"><img alt="authorised use only" src="https://img.shields.io/badge/use-authorised%20testing%20only-8C3A2E?style=flat-square"></a>
  <img alt="platform" src="https://img.shields.io/badge/platform-ESP32--S3-8A6D2F?style=flat-square">
  <img alt="tests" src="https://img.shields.io/badge/host%20checks-587-3F6B4A?style=flat-square">
  <img alt="licence" src="https://img.shields.io/badge/licence-MIT-4A443A?style=flat-square">
</p>

---

*βάσανος — the touchstone jewellers rubbed gold against to see whether it was
real. It does not make gold. It tells you whether what you have is.*

**Basanos is a wireless assessment instrument.** It emits a known signal at a
network you are authorised to test, watches for your detection equipment to
react, and scores it: caught or missed, how many seconds late, at what
confidence.

Every other tool of this class answers *"can I knock this over?"*. That
question has been answered for twenty years. The one worth money is *"would we
have seen it?"* — and until you have fired something real at your own
defences, you do not know.

---

## Authorised testing only

Transmitting deauthentication or disassociation frames at a network you do not
own or have written permission to test is a criminal offence in most
jurisdictions. This firmware makes that harder to do by accident and does
nothing whatever to make it lawful.

**If you cannot name the authorisation, the device will not arm.** That is not
a formality you can switch off in a menu.

---

## What it does

### Manual targeting, and nothing else

You scan, you look at the list, you choose **one access point**. Optionally you
narrow further to **one client**.

There is no "all", no wildcard, and no broadcast mode. This is enforced in the
type system rather than the menu: `bas_ap_check()` refuses any BSSID carrying
the multicast group bit, and `bas_engage_permits_frame()` refuses any
destination outside the lock — so *"attack everything"* is not a feature that
was left out of the interface, it is a frame the firmware cannot construct.

```
survey → pick one network → name the authorisation → lock
       → pick a family → arm → run → score
```

### Signal families

Each exists because some class of detector claims to catch it. The `detector`
field in the source is not documentation — it is the reason the family ships.
A family that grades nothing does not ship.

| Family | Class | What a catch proves |
|---|---|---|
| Deauthentication | disruptive | Rate, shape, forgery and aftermath evidence each fire |
| Disassociation | disruptive | Frame-shape analysis is not narrowly deauth-specific |
| Auth flood | disruptive | Association-table pressure reads as attack, not load |
| Evil twin | active | Roaming stays clear while a posture conflict escalates |
| PMKID solicitation | active | An unauthenticated association draws EAPOL M1 |
| Beacon set | active | New-BSSID arrival rate scores; a busy room is not a flood |
| Karma responder | active | The gap between names a radio answers and announces |
| Probe requests | benign | Client tracking survives MAC randomisation |
| Channel analyser | passive | Occupancy per channel, and refuses to name one it never listened to |
| Client enumeration | passive | Stations attributed to cells, randomised addresses flagged |
| Probe log | passive | The names nearby devices ask for — their own history, leaking |
| BLE advertisements | benign | Advertiser multiplicity and channel-balance scoring |
| BLE tracker dwell | benign | Dwell-span separates a follower from fixed furniture |
| HID keystroke timing | benign | Injection-timing detection reacts, and how fast |

Seven of the ten are things an ordinary handset produces unprompted. Three deny
service to something real, and those three are gated accordingly.

### The scorecard, and why it is fair

A run is **never** called `MISSED` until the grace window after the emission
has fully elapsed. A detector that alarms two seconds after the burst ends has
caught it; an instrument that scored the instant the burst stopped would call
that a miss and quietly slander a working detector.

```
PENDING  → still emitting, or inside the grace window
CAUGHT   → alarmed while the signal was still on air
LATE     → alarmed, but only after the emission ended
MISSED   → grace elapsed with no alarm
```

The first alarm wins, so a detector that keeps shouting earns no better
latency. An alarm arriving after the grace window is refused rather than
credited to the wrong run.

**A run that transmitted nothing is discarded, not scored.** If the radio
rejects the frames, recording a `MISSED` would blame the detector for the
transmitter's failure — the one output this instrument must never produce.

There is deliberately **no letter grade**. One run against one signal is not
evidence about a detector in general, and an A+ would imply that it was.

### Knowing whether it worked

A detector under test reports in three ways — an operator watching it, a line
on the UART pads, or a post over Wi-Fi:

```
BASANOS-ALARM detector=Aegis conf=82 fam=0x0F
```

The source travels with the alarm into the report, because 300 ms from a wire
and 300 ms from a human thumb are not the same measurement and must never be
averaged together.

### Passive capability

None of it transmits.

- **Network survey** with real posture parsed from the beacon — WPA2/WPA3
  transition mode is reported *as transition mode*, because calling it WPA3
  would overstate the target's resistance to the exact family this device
  emits.
- **Management-frame-protection detection**, so the interface can say a deauth
  run is expected to bounce before the operator spends one.
- **Station enumeration**, so an engagement can narrow to one client. A
  randomised MAC is flagged rather than hidden.
- **Channel analyser** that reports "do not know" rather than nominate a
  channel nobody listened to. Unmeasured is not the same as quiet.
- **Frame counters**, so "the detector was busy" is a number in the report
  rather than an excuse afterwards.

---

## What is deliberately absent

These are missing by decision, not oversight. Each would be straightforward to
build; none would move a number on a scorecard.

**Key material.** The PMKID family solicits EAPOL M1 and records **whether a
PMKID was offered** — never the value. There is no buffer for it anywhere in
the firmware and no caller could ask for one. A sensor detects the
solicitation, not what the tester keeps, so storing sixteen bytes of crackable
material would add custody and liability without adding a measurement. *"This
AP hands a PMKID to any unauthenticated device"* is the line that belongs in a
report.

Four-way handshake capture is absent for the original reason: it is genuinely
passive, so nothing can observe it happening and it exercises no detector.

**HID keystroke timing** is listed but cannot ship on this board. USB HID means
TinyUSB taking the port, and the USB-Serial/JTAG console — the device's control
channel — disappears with it. That trade is not worth making here.

**Credential capture in every form.** No captive portal, no cloned sign-in
page, no credential store. A harvested password does not tell a customer
whether their detection works, and building the capability creates custody of
material the engagement has no reason to hold.

**Brand impersonation.** Synthetic networks and advertisements carry a fixed
`BASANOS-` prefix, so a third party sniffing the room identifies a test rig
rather than an attack. The single exception is the evil-twin family, which
duplicates *the network the engagement is locked to* and no other name.

**Broadcast and untargeted transmission.** Enforced structurally: any address
carrying the multicast group bit is refused at the frame gate.

**Jamming.** Untargetable by construction, denies service to an entire band,
cannot respect a single-target lock.

**Post-exploitation.** No network joining, port scanning, address-service
manipulation or tunnelling. Basanos measures wireless detection.

**Self-detection.** The instrument does not grade itself. Building a detector
into the tester would let it mark its own homework.

---

## Hardware

Waveshare **ESP32-S3-Touch-LCD-1.54** — 240×240 touch LCD, 16 MB flash, 8 MB
octal PSRAM, Li-ion, microSD.

Not one GPIO on this board is free; every pin is claimed by the display,
storage, audio, buttons, power or memory, and the only external connections are
I2C, UART and USB pads. An SPI radio module does not fit, so Sub-GHz, NFC and
proprietary 2.4 GHz protocols are out of reach on this platform. The UART pads
leave the door open for a companion radio without changing the engagement model.

### Raw injection

The Wi-Fi library sanity-checks every frame handed to `esp_wifi_80211_tx` and
refuses deauthentication, disassociation and authentication outright —
`unsupport frame type: 0c0`, returned as `ESP_ERR_INVALID_ARG`. Without a
bypass those three families are accepted by the API and silently emit nothing,
which for this instrument is the worst possible failure: it would score the
silence against the detector.

`main/rawtx.c` overrides the check. The symbol is strong, so the link is told
to accept two definitions and take ours. `--wrap` does not work here — the
library both defines and calls the function inside one object file, so the call
never crosses a boundary the linker can rewrite.

Because whether the override actually took is a link-time accident, the
firmware **asks at runtime** and reports the answer in the self-test and in
`status`. A build where the bypass did not link shows those three families as
unavailable instead of running them and blaming the detector for the silence.

The bypass widens only what the *radio* will emit. Who may emit, at what, and
for how long is decided upstream of it — the engagement lock, the role, the
ceilings and the frame gate are all untouched.

### Building

```bash
idf.py set-target esp32s3
idf.py build
./tools/flash.sh          # not idf.py flash — see below
```

`idf.py flash` fails intermittently on this board with *"No serial data
received"* while the chip is up and enumerating. `tools/flash.sh` drives the
download-mode line sequence itself and then connects with `--before no_reset`.

### Driving it from a host

```bash
tools/basctl.py                    # interactive
tools/basctl.py list
tools/basctl.py -f session.txt
```

The console exists on the USB port only — there is no network path to it. The
cable is the physical presence, and the moment a command arrives the screen
shows a **REMOTE** banner that stays for the session. Disruptive families need
the literal token `CONFIRM`, which is the remote equivalent of the on-device
hold.

---

## Architecture

Judgement never touches hardware. Everything that decides anything is plain C11
with no ESP-IDF dependency, so it is testable on a laptop:

```
components/engine/   targets, engagement lock, families, ceilings,
                     802.11 element parsing, passive survey
components/rbac/     roles, SHA-256 / HMAC / PBKDF2, lockout
components/score/    the scorecard and alarm ingest
main/                display, touch, power, radio, screens, console
test/host/           587 checks, no hardware required
```

```bash
make -C test/host          # 587 checks
make -C test/host asan     # the same under ASan + UBSan
```

The same safety invariants are re-checked on the silicon at every boot —
broadcast targets unreachable, no role transmitting without a locked
engagement, ceilings clamping, published crypto vectors. **If any of them fail,
the device halts on that screen rather than showing a target picker.**

---

## Status

| Layer | State |
|---|---|
| Engine, RBAC, scorecard | ✅ 587 host checks, ASan + UBSan clean |
| Display, touch, power, survey | ✅ verified on hardware |
| Wi-Fi transmit | ✅ verified — 436 frames, 0 rejected |
| Wi-Fi families | ✅ deauth, disassoc, auth flood, evil twin, beacon, probe |
| Deauth / disassoc / auth flood | ✅ verified — 54 / 54 / 106 frames, 0 rejected |
| Karma responder | ✅ verified — 8 names answered from live probes |
| Promiscuous receiver | ✅ verified — 1118 frames in 10 s, 6 clients, 15 probed names |
| BLE families | ✅ verified — 120 identities spam, 1 persistent for tracker dwell |
| PMKID solicitation | ✅ verified — full auth→assoc→M1 conversation, finding recorded |
| HID keystroke timing | 🧱 blocked by design — see below |

Transmission is verified independently rather than by trusting a return code:
a separate machine's Wi-Fi scanner picks the synthetic networks out of the air
while the device is beaconing. `ESP_OK` from the radio means the stack accepted
a frame, not that anything radiated, and those are different claims.

---

## Licence

MIT. All firmware here is original work; the signal families implement
behaviour defined by the IEEE 802.11 and Bluetooth Core specifications, and no
third-party source is vendored or adapted.
