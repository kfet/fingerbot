# fingerbot

Press a Tuya Fingerbot over BLE from the command line. One command, no
arguments, no daemon, no Home Assistant.

```
$ fingerbot
clicked
```

It talks to the device directly over Bluetooth Low Energy using the Tuya BLE
protocol, so it needs no cloud connection and no Tuya gateway at run time —
only the four per-device credentials you fetch once from the Tuya IoT
platform (see [Configure](#configure)).

Developed against a Fingerbot Plus (`category: kg`), but
nothing in it is model-specific beyond datapoint 108; any Tuya Fingerbot that
exposes a momentary "click" datapoint should work.

Requires Linux with a Bluetooth LE controller and `python3` 3.9 or newer.
Nothing else: it is one file, standard library only — no pip, no `bleak`,
no D-Bus, no root.

## Install

Copy one file:

```
curl -fsSLo ~/.local/bin/fingerbot \
  https://raw.githubusercontent.com/kfet/fingerbot/main/src/fingerbot/__init__.py
chmod +x ~/.local/bin/fingerbot
```

or `scp src/fingerbot/__init__.py host:fingerbot.py` and run it as
`python3 fingerbot.py`. Then add the credentials file (below). That is the
whole install — the box needs no network at run time.

It is also an ordinary package, if you prefer: `uv tool install
git+https://github.com/kfet/fingerbot` gives the same `fingerbot` command.

## Configure

Credentials live in `~/.config/fingerbot/device.env`, mode 600. Override the
location with `$FINGERBOT_ENV`.

```
FB_MAC=AA:BB:CC:DD:EE:FF
FB_DEVICE_ID=...
FB_LOCAL_KEY=...
FB_UUID=...
FB_PRODUCT_ID=...
FB_CATEGORY=kg
#FB_ADDR_TYPE=public
#FB_ADAPTER=hci0
```

Optional calibration, re-written before every click (`FB_TRAVEL` enables it):

```
FB_TRAVEL=74   # dp102, down travel % (the app's "Downward movement")
FB_HOLD=0      # dp103, sustain; >0 can park the arm on the button
FB_MODE=0      # dp101, 0 = click
```

Travel is nudged one step off and back before it is set, because the device
does not reliably honour a stored calibration on a cold click. The press is
refused, before connecting, if a value is out of range (travel 0–100), and
after logging in if the calibration datapoints are not published.

`FB_MAC` and `FB_LOCAL_KEY`, `FB_DEVICE_ID`, `FB_UUID` are required.
Optional: `FB_ADDR_TYPE` (`public`, the default, or `random` — the LE
address type; `bluetoothctl info <mac>` shows it), `FB_ADAPTER` (`hci0`,
`hci1`, …; default: let the kernel pick), and `FB_PRODUCT_ID` /
`FB_CATEGORY`, which are informational.

### Getting the four Tuya credentials

1. Pair the Fingerbot in the **Smart Life** app as usual.
2. On [platform.tuya.com](https://platform.tuya.com), create a Cloud Project.
   Set both *Industry* and *Development Method* to "Smart Home", and pick the
   data centre that matches your Smart Life account's region.
3. In the project: **Devices → Link App Account**, and scan the QR code from
   the Smart Life app (Me → top-right scan icon). Your devices appear.
4. **Cloud → API Explorer → Device Management → Query Device Details** with
   your device id. The response contains `local_key`, `uuid`, `id`
   (= `FB_DEVICE_ID`), `product_id` and `category`.

The BLE MAC is *not* in that response — Bluetooth-only devices carry no
`mac`/`ip` field. Read it from the device page in the Smart Life app, or find
it by scanning (`bluetoothctl scan le`).

`local_key` rotates if you unbind and re-pair the device in the app; refetch
it if presses suddenly stop working.

## One-time host setup

None. There is nothing to pair, trust or bond: the Fingerbot does not bond
anyway (Tuya encrypts at the application layer with `local_key`), and the
tool does not go through BlueZ's D-Bus device objects, so there is no cached
object to create or to go stale. `bluetoothd` may keep running; it just sees
a connection come and go.

## Usage

```
fingerbot           # click once (same as `fingerbot press`)
fingerbot info      # diagnostics; never actuates the arm
```

`fingerbot info` prints the resolved config (`local_key` redacted to its
length; `uuid` and `device_id` are identifiers and print in clear), how long
the connection and GATT discovery took, the device's firmware and protocol
versions, every Tuya frame it sent (so you can see there was no datapoint
write), and the full datapoint map. It is read-only by construction: its session refuses to send
a datapoint write at all.

Exit status of a press: `0` and `clicked` — the click was acknowledged.
`3` — the click frame was sent (at least partly) and then the session failed
or was interrupted, so the arm may have moved; check the host before pressing
again. Any other non-zero status — the press failed before any of the click
frame was sent (calibration writes may have gone out).

Retries, scheduling and "should I press?" logic belong to whatever calls
this, not here.

## How it works

1. **Connect** — open an L2CAP socket on the LE ATT channel (CID 4) to
   `FB_MAC`. The kernel scans passively and connects; no discovery session,
   nothing to arbitrate with other BLE users on the host. About 1.5 s on a
   Pi Zero W.
2. **GATT** — find service `1910`, its `2b11` write characteristic and
   `2b10` notify characteristic, and enable notifications.
3. **Log in** — Tuya BLE v3: device info (gives the session key), pair,
   status request. The device then reports every datapoint. Frames are
   AES-128-CBC with keys derived from `local_key`; the AES is pure Python.
4. **Press** — re-write the calibration datapoints (see Configure), then
   write datapoint **108**, the momentary click DP: one write, one actuation.
   `dp1` is the latching switch state — writing that presses twice.

The whole `info` round trip, connect to datapoint dump, takes under 5 s on a
Pi Zero W (armv6).

Datapoint map dumped from a live Fingerbot Plus:

```
  1  bool   switch state -- LATCHING, do not use to click
101  enum   mode, 0 = click
102  value  down position %
103  value  hold time
104  enum   reverse
106  value  up position %
108  bool   click            <- this one
111  value  unknown -- NOT battery (reads 256 on a healthy cell)
```

Travel, hold and mode come from `device.env` and are re-written before every
click; everything else is the Smart Life app's business.

## Troubleshooting

Run `fingerbot info` first — it separates the common failures:

| symptom in `info` | cause | fix |
|---|---|---|
| `LE connect ... timed out` | out of range, dead CR2 cell, or the Smart Life app holds the link | move closer; replace the cell; close the app |
| `ProtocolError: ... (wrong local_key?)` | wrong `local_key` | refetch `local_key` from the Tuya API |
| `no response to Tuya code 0x0000` | wrong `local_key` (the device ignores the login) | as above |
| `dp108 never appeared` | logged in, but the device reported no click DP | not a Fingerbot, or a different firmware |

Working RSSI is roughly −38 to −60 dBm in the same room; around −80 dBm it
stops connecting reliably. The vendor manual specifies a minimum of 10 s
between presses.

## Dependencies

None at run time. The Tuya BLE protocol and AES-128 are implemented in the
module itself. The protocol follows `tuya-ble` on PyPI (a 2023 snapshot of
[`PlusPlus-ua/ha_tuya_ble`](https://github.com/PlusPlus-ua/ha_tuya_ble)); it
is frozen device firmware, so it does not rot. `tuya-ble` and `pycryptodome`
remain as dev-only dependencies: the test suite cross-checks the AES and the
Tuya codec against them byte for byte.

## Development

```
uv sync
uv run scripts/check.py               # the whole gate
git config core.hooksPath .githooks   # ...and run it on every commit
```

`scripts/check.py` runs ruff, ty, pyrefly and pytest in that order, stops at
the first failure and names it. It is the *only* definition of the gate:
CI runs that same script, and so does the pre-commit hook, so the three can
never drift apart. Standard library only — `uv sync` is the whole setup.

The module must keep running on Python 3.9; run the gate there too (CI
does):

```
UV_PROJECT_ENVIRONMENT=/tmp/fb-venv39 uv run --python 3.9 scripts/check.py
```

Individual steps, when you want just one:

```
uv run ruff check      # lint
uv run ty check        # type check (Astral)
uv run pyrefly check   # type check (Meta)
uv run pytest          # 100% coverage, enforced
```

The test suite replaces the Bluetooth socket with a fake Fingerbot that
speaks ATT and Tuya BLE v3, so it needs no Bluetooth adapter and no
hardware; it passes on any host.

Two type checkers, deliberately: they are both pre-1.0 and they disagree in
useful ways, so a finding from either is worth reading. Source and tests are
both checked. CI runs the gate on Python 3.9 and 3.13.

## Licence

MIT — see [LICENSE](LICENSE).
