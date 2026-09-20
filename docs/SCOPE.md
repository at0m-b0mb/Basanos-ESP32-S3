# Capability scope

What Basanos does, what it deliberately does not, and the reasoning for each.

The product is a **measurement instrument**. It emits a known wireless signal at
an authorised target and scores whether the customer's detection equipment saw
it. That single sentence decides every entry below: a capability is in scope
when a defensive system could be graded against it, and out of scope when it
could not — regardless of how impressive the capability is on its own.

---

## In scope — signal families

Each family exists because some class of detector claims to catch it. A family
that grades nothing does not ship.

### Benign — behaviour an ordinary handset produces unprompted

| Family | What it emits | What a catch proves |
|---|---|---|
| Probe requests | Client probes naming a configured SSID set | Client-tracking survives MAC randomisation |
| BLE advertisements | Many distinct advertiser addresses at a set rate | Advertiser multiplicity and channel-balance scoring fire |
| BLE tracker dwell | One persistent address, sustained over time | Dwell-span scoring separates a follower from fixed furniture |
| HID keystroke timing | A keystroke cadence profile over USB | Injection-timing detection reacts, and how fast |

### Active — visible on air, aimed at the locked target

| Family | What it emits | What a catch proves |
|---|---|---|
| Beacon set | A bounded set of prefixed synthetic APs | New-BSSID arrival rate scores; a busy room is not mistaken for an attack |
| Karma responder | Probe responses to names the air is already asking for | The gap between names a radio answers and names it announces is measurable |
| Evil twin | A duplicate BSSID carrying a security-class conflict | Roaming stays clear while a genuine posture conflict escalates |

### Disruptive — denies service to something real, admin-gated

| Family | What it emits | What a catch proves |
|---|---|---|
| Auth flood | Authentication requests at the target AP | Association-table pressure reads as an attack, not as load |
| Disassociation | Disassociation frames at the locked target | Frame-shape analysis is not narrowly deauth-specific |
| Deauthentication | Deauthentication frames at the locked target | Rate, shape, forgery and aftermath evidence each fire |

## In scope — passive capability

Recon that supports manual targeting, and measurement of the environment a run
took place in. None of it transmits.

- **Network survey** — nearby access points with security posture, channel and
  signal, the first step of choosing a target.
- **Station enumeration** — clients associated with the locked BSSID, so an
  engagement can be narrowed to a single device.
- **Channel analyser** — per-channel occupancy, so a run happens on a channel
  whose baseline is known.
- **Frame monitor** — frame-type counters during a run, so "the detector was
  busy" is a measurable claim rather than an excuse.
- **Posture findings** — WPS exposure, graded from the beacon alone and
  recorded passively as part of the survey.

Two things listed here previously are not built, and are named as gaps rather
than left reading as capabilities: **capture export** (there is no pcap writer
in the tree) and **hidden-network naming** (the receiver parses beacons and
probe requests, not the probe responses and association requests that would
carry the name).

---

## Out of scope, and why

These are absent by decision, not by omission. Each would be straightforward to
build; none of them would move a number on a scorecard.

**Credential capture from people.** No captive portal, no cloned sign-in page,
no credential store. The instrument never deceives a person into handing over a
secret. Recovering a network's own key from a protocol flaw in its router --
see WPS above -- is a different act, and is in scope. A harvested password does not tell a customer whether their detection
works, and building the capability creates custody and liability for material
the engagement has no reason to hold.

**Key material kept.** This reasoning changed, and the document has been
corrected rather than left standing.

Three families now touch key material, because each one is *solicited* and so
is exactly what a sensor is supposed to notice: PMKID solicitation draws EAPOL
M1 with an association request, the passphrase audit captures a handshake it
forces, and WPS PIN recovery associates with the access point. The original
claim that these are passive was wrong.

What remains out of scope is *keeping* any of it. The PMKID family records
only that a PMKID was offered and has no buffer for the value. The passphrase
audit runs on the device and wipes the handshake, asserted byte by byte by a
test. A recovered WPS credential is shown on the screen and written nowhere.
The finding is the deliverable; custody of the key is not.

**Brand impersonation.** The instrument never presents itself as a named
company, product or service. Synthetic networks and advertisements it creates
carry a fixed product prefix, so a third party sniffing the room identifies a
test rig rather than an attack.

**Broadcast and untargeted transmission.** There is no "all targets" mode and
no broadcast destination. This is enforced structurally rather than by menu
design: any address carrying the multicast group bit is refused at the frame
gate, so an untargeted frame is not something the firmware can construct.

**Jamming.** Untargetable by construction. It denies service to an entire band,
cannot respect a single-target lock, and is unlawful in most jurisdictions.

**Third-party network injection.** Nothing is published into someone else's
device-location or asset-tracking ecosystem, because the people affected are
outside the engagement.

**Post-exploitation.** No network joining, port scanning, address-service
manipulation, tunnelling or remote shells. Basanos measures wireless detection.
Once traffic is on the wire, a different class of tool applies.

**Detection.** The instrument does not grade itself. Building a detector into
the tester would let it mark its own homework; the customer's equipment is the
system under test.

---

## Not possible on this hardware

The reference board exposes no free GPIO — every pin is claimed by the display,
storage, audio, buttons, power or memory, and the only external connections are
I2C, UART and USB pads. An SPI radio module does not fit. Sub-GHz, NFC, infrared
and proprietary 2.4 GHz protocols are therefore out of reach on this platform.

The UART pads leave the door open: a companion radio addressed over a serial
link would extend the instrument past 2.4 GHz without changing the engagement
model. That is a hardware revision, not a firmware setting.

---

## Originality

All firmware in this repository is original work. The signal families implement
behaviour defined by the IEEE 802.11 and Bluetooth Core specifications —
publicly documented protocol mechanics — and the detection-scoring model,
engagement lock, access control and cryptographic layer were written for this
product. No third-party source is vendored or adapted, and the build has no
dependency whose licence restricts commercial distribution.
