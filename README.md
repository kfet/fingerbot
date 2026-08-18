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

Developed against a Fingerbot Plus (`category: kg`, product `6jcvqwh0`), but
nothing in it is model-specific beyond datapoint 108; any Tuya Fingerbot that
exposes a momentary "click" datapoint should work.

Requires Linux with BlueZ — it uses `bleak`'s BlueZ backend and BlueZ D-Bus
object paths.

## Install

```
uv tool install git+https://github.com/kfet/fingerbot
```

or, from a clone:

```
uv tool install .
```

`uv tool install` materialises a self-contained venv under
`~/.local/share/uv/tools`, so afterwards the command runs with no network and
no git access. Update with `uv tool upgrade fingerbot`.

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
#FB_ADAPTER=hci0
```

`FB_MAC` and `FB_LOCAL_KEY`, `FB_DEVICE_ID`, `FB_UUID` are required;
`FB_PRODUCT_ID`, `FB_CATEGORY` (default `kg`) and `FB_ADAPTER` (default
`hci0`) are optional.

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

```
bluetoothctl trust <FB_MAC>
```

The Fingerbot will not bond — `pair()` returns
`org.bluez.Error.AuthenticationFailed`, because Tuya encrypts at the
application layer with `local_key`, so there is nothing to bond at the link
layer. Trusting it is enough: it gives a persistent BlueZ object path, which
the tool connects to directly, without scanning. That keeps it out of
contention with anything else using the adapter.

## Usage

```
fingerbot           # click once (same as `fingerbot press`)
fingerbot info      # diagnostics; never actuates the arm
```

`fingerbot info` prints the resolved config (with `local_key` redacted), the
adapter state, whether BlueZ still has the device cached and trusted, a 12 s
RSSI measurement, which connect path was taken and how long it took, and the
full datapoint map.

Retries, scheduling and "should I press?" logic belong to whatever calls
this, not here.

## How it works

1. **Fast path** — connect straight to `/org/bluez/hci0/dev_<MAC>`, the
   trusted cached object. No discovery, so nothing to arbitrate with other
   BLE users on the host. Typically 9–18 s, most of it the BLE connection
   itself; the device sleeps between commands.
2. **Slow path** — if that fails, the cached object is stale or absent.
   Rediscover with the scanner held *open* (BlueZ evicts un-paired devices
   the moment discovery stops), connect, and thereby repopulate the cached
   object so the fast path works again next time.
3. Write datapoint **108**, the momentary click DP: one write, one actuation.
   `dp1` is the latching switch state — writing that presses twice.

Datapoint map dumped from a live Fingerbot Plus:

```
  1  bool   switch state -- LATCHING, do not use to click
101  enum   mode, 0 = click
102  value  down position %
103  value  hold time
104  enum   reverse
106  value  up position %
108  bool   click            <- this one
111  value  battery %
```

Set travel and hold time in the Smart Life app; this tool only clicks.

## Troubleshooting

Run `fingerbot info` first — it separates the common failures:

| symptom in `info` | cause | fix |
|---|---|---|
| no adverts seen | out of range, or dead CR2 cell | move closer; replace the cell |
| adverts fine, fast path times out, slow path recovers | stale BlueZ cached object | nothing — it self-heals; the next press uses the fast path again |
| `org.bluez.Error.InProgress` | another process holds discovery | stop it, or let the fast path handle it (it does not scan) |
| `dp108 never appeared` | wrong `local_key` (decryption fails silently) | refetch `local_key` from the Tuya API |
| absent from BlueZ cache | never trusted, or cache cleared | `bluetoothctl trust <FB_MAC>` |

Working RSSI is roughly −38 to −60 dBm in the same room; around −80 dBm it
stops connecting reliably. The vendor manual specifies a minimum of 10 s
between presses.

## Dependencies

`tuya-ble` on PyPI is a 2023 snapshot extracted from
[`PlusPlus-ua/ha_tuya_ble`](https://github.com/PlusPlus-ua/ha_tuya_ble).
There is no official Tuya BLE SDK for Python: the `tuya` GitHub org ships C
firmware for the device MCU under that name, and the official Python SDKs are
cloud-REST only, which would require a Tuya Bluetooth gateway. The protocol
is frozen device firmware, so a stale codec is not a rotting dependency.
`tuya-ble` under-declares `pycryptodome`, hence the explicit dependency here.

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

Individual steps, when you want just one:

```
uv run ruff check      # lint
uv run ty check        # type check (Astral)
uv run pyrefly check   # type check (Meta)
uv run pytest          # 100% coverage, enforced
```

The test suite mocks `bleak`, `tuya_ble` and `subprocess`, so it needs no
Bluetooth adapter and no hardware; it passes on any host.

Two type checkers, deliberately: they are both pre-1.0 and they disagree in
useful ways, so a finding from either is worth reading. Source and tests are
both checked. CI runs the gate on Python 3.11, 3.12 and 3.13.

## Licence

MIT — see [LICENSE](LICENSE).
