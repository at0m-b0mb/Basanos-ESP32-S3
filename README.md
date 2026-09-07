# Basanos

**A red-team instrument whose output is a grade on your own defences.**

*βάσανος — the touchstone jewellers rubbed gold against to see whether it was
real. It does not make gold. It tells you whether what you have is.*

Firmware for the Waveshare **ESP32-S3-Touch-LCD-1.54**. Every other ESP32 Wi-Fi
tool answers *"can I knock this over?"*. Basanos answers *"did my detector see
it?"* — it emits a known signal at a network you are authorised to test, watches
for your detector to react, and scores the detector: caught or missed, how many
seconds late, at what confidence, and which evidence family fired.

---

## For authorised security testing only

Transmitting deauthentication or disassociation frames at a network you do not
own or have written permission to test is a criminal offence in most
jurisdictions. This firmware makes that harder to do by accident and does
nothing to make it lawful.

The tool is built for one job: proving that a defensive device works, against a
network in your own lab or inside a scoped engagement. If you cannot name the
authorisation, the device will not arm — and that is not a formality you can
switch off in a menu.

---

## Why it exists

There is a shelf of finished detectors in this catalogue — Aegis, Pharos,
Argus, Echo, Bulwark, GhostTag, DuckHound — and until now the only way to know
whether any of them actually fires was to wait for a real attack, or to trust
the unit tests. That is not good enough, and it has already gone wrong once:
Pharos shipped a scoring bug that made its alarm band mathematically
unreachable. A detector that could not alarm. It was caught by a human noticing
that nothing ever fired.

One press of this box would have caught it in three seconds, repeatably.

| Signal family | Detector it exercises | Class |
|---|---|---|
| Probe requests | Echo, Pharos probe | benign |
| BLE advert spam | Aegis BLE-spam, Bulwark | benign |
| BLE tracker dwell | GhostTag, Aegis tracker | benign |
| HID keystroke timing | DuckHound | benign |
| Beacon set | Aegis beacon-flood, Pharos Mirage | active |
| Karma responder | Pharos karma | active |
| Evil twin | Aegis evil-twin, Pharos twin, Argus | active |
| Auth flood | Aegis, Argus | disruptive |
| Disassociation | Aegis watch, Pharos watch | disruptive |
| Deauthentication | Aegis watch, Pharos 4-family, Argus | disruptive |

Seven of these ten are things an ordinary phone does unprompted. Three deny
service to something real, and those three are gated accordingly.

---

## Manual targeting, and nothing else

There is exactly one targeting mode. You scan, you look at the list, you choose
**one access point** you have authorisation to test. Optionally you narrow
further to **one client**.

There is no "all", no wildcard, and no broadcast. This is enforced in the type
system rather than the menu: `bas_ap_check()` refuses any BSSID with the
multicast group bit set, and `bas_engage_permits_frame()` refuses any
destination outside the lock — so *"attack everything"* is not a feature that
was left out of the UI, it is a frame the firmware cannot construct.

```
scan  →  pick "sunshine 12"  →  name the authorisation  →  lock  →  arm  →  run
```

## What deliberately is not here

Two capabilities every comparable tool ships, left out on purpose:

- **PMKID / EAPOL handshake capture.** It is passive, so no detector can
  observe it happening. It exercises nothing and yields only crackable
  material.
- **Evil portal / captive portal.** Credential harvesting and brand
  impersonation. Not a measurement.

Neither omission costs the defensive side anything, which is the test a feature
has to pass to be in this repo.

---

## The two axes of authorisation

**RBAC answers "who may press the button."** Three roles: `viewer` reads
results and transmits nothing; `operator` runs benign and active families;
`admin` additionally reaches the three disruptive ones, manages users, and
exports the log. Passwords are PBKDF2-HMAC-SHA256 with a per-user salt, a
constant-time compare, and a five-failure lockout. **No credential ships with
the firmware** — the device generates its own admin password on first boot and
shows it on the screen.

**The engagement lock answers "which network may be tested."** One BSSID chosen
by hand, an authorisation label the operator types before the fact, a named
operator, and a mandatory TTL between one minute and four hours. It is checked
again immediately before every frame, not once at arm time, so an engagement
that expires mid-run stops the run.

Neither substitutes for the other. An admin with no engagement transmits
nothing — asserted as a test, not left to the flow of the code:

```c
/* the highest role in the system, with no target selected */
bas_plan_default(&p, BAS_FAM_AUTH_FLOOD);
CHECK_EQ(bas_plan_validate(&p, ADMIN, &none, 2000), BAS_ERR_NOT_LOCKED);
```

Be honest about what the label is: **paperwork you typed into your own
device.** It proves nothing about who owns the network. What it buys is a
target an operator cannot widen, an expiry that stops the device outliving its
engagement, and a log that reconstructs exactly what was emitted and at whom.

---

## The scorecard, and why it is fair

A run is **never** called `MISSED` until the grace window after the emission has
fully elapsed. A detector that alarms two seconds after the burst ends has
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
credited — otherwise the next run's alarm would invent a detector that works.

There is deliberately **no letter grade**. One run against one signal is not
evidence about a detector in general, and an A+ would imply that it was.

---

## Knowing whether it worked

Emitting a signal is half a test. The other half is observing the response, and
a detector under test can report in three ways — an operator watching it and
tapping the screen, a line on the UART pads, or a post over Wi-Fi:

```
BASANOS-ALARM detector=Aegis conf=82 fam=0x0F
```

The source travels with the alarm into the report, because 300 ms from a wire
and 300 ms from a human thumb are not the same measurement and must never be
averaged together.

## Passive capability

None of this transmits. It exists so a run happens against a known baseline
rather than into noise.

- **Network survey** with real security posture parsed from the beacon —
  including WPA2/WPA3 transition mode reported as transition mode, because
  calling it WPA3 would overstate the target's resistance to the exact family
  this device emits.
- **Station enumeration**, so an engagement can narrow to one client. A
  randomised MAC is flagged rather than hidden: it may not be the same device
  it was ten minutes ago, and an operator narrowing to it should know.
- **Management-frame protection detection**, so the UI can say a deauth run is
  expected to bounce before the operator spends one.
- **Channel analyser** that will report "do not know" rather than nominate a
  channel nobody listened to. Unmeasured is not the same as quiet.
- **Frame counters**, so "the detector was busy" becomes a number in the report
  instead of an excuse afterwards.

## Architecture

Judgement never touches hardware. Everything in `components/` is plain C11 with
no ESP-IDF dependency, so it runs on the host:

```
components/engine/   target + station selection, engagement lock, families,
                     ceilings, 802.11 element parsing, passive survey
components/rbac/     roles, SHA-256/HMAC/PBKDF2, user table, lockout
components/score/    the scorecard and alarm ingest
main/                ESP-IDF glue (display, radio, UI) — thin, replaceable
test/host/           587 checks, no hardware required
```

```bash
make -C test/host          # build and run
make -C test/host asan     # the same under ASan + UBSan
```

If that Makefile ever needs an ESP-IDF include path, something has leaked into
the pure layer.

The crypto is verified against published vectors — FIPS 180-4 for SHA-256,
RFC 4231 for HMAC, RFC 7914 for PBKDF2 — so the code that passes on the host is
the code that runs on the board.

---

## Board notes

Read from the vendor BSP and confirmed against Waveshare's official
documentation. Two things worth knowing before you plan hardware:

- **No GPIO is free.** GPIO 6 is the QMI8658 interrupt; everything else is
  display, SD, audio, buttons, battery, PSRAM or flash. Expansion is the I2C,
  UART and USB pads only — an SPI radio module does not fit.
- **There is no RTC.** The GitHub README claims one; it is absent from the
  official onboard-resources list and from the BSP. Log timestamps come from
  the network or are relative to boot.

---

## Status

| Layer | State |
|---|---|
| Engine, RBAC, scorecard | ✅ 587 host checks, ASan + UBSan clean |
| ESP-IDF glue, radio, UI | 🧱 not yet written |
| Hardware bring-up | 🧱 not started |

## Licence

MIT. See `LICENSE`.
