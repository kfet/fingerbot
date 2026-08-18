"""Press a Tuya Fingerbot (Fingerbot Plus / ADFBB521) over BLE.

tuya-ble does the protocol. This supplies only what it leaves to the caller:
credentials and a BLEDevice. Four facts, all measured against real hardware:

  * the Fingerbot will not bond -- pair() returns
    org.bluez.Error.AuthenticationFailed, because Tuya crypto is app-layer
    (local_key), not link-layer. Marking it TRUSTED is enough: that gives a
    BlueZ object path which survives `systemctl restart bluetooth`.
  * so the fast path connects straight to that object path and never scans,
    which removes us from contention with any other BLE project on the host.
  * that cached object can go STALE -- connect then times out forever while
    the device is plainly advertising at -40 dBm. Recovery is to drop the
    object, rediscover with the scanner held open, and re-trust. The slow
    path below does exactly that, so the tool self-heals.
  * dp108 is the momentary click datapoint: one write, one actuation.
    dp1 is the latching switch state; writing it actuates twice.

Usage:
    fingerbot          click once
    fingerbot info     diagnostics: config, adapter, RSSI, datapoints
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from tuya_ble import AbstaractTuyaDeviceManager, TuyaBLE, TuyaDeviceInfo

DP_CLICK = 108

# What a caller does with an open session. `press` clicks; `info` dumps.
Action = Callable[[TuyaBLE], Awaitable[None]]
# Progress reporting: `info` prints these, `press` discards them.
Trace = Callable[[str], None]


def _env_path() -> Path:
    """Path to the credentials file: $FINGERBOT_ENV, else the XDG default."""
    return Path(os.environ.get("FINGERBOT_ENV")
                or Path.home() / ".config" / "fingerbot" / "device.env")


class _StaticManager(AbstaractTuyaDeviceManager):
    """Feeds tuya-ble credentials we already have, instead of a cloud lookup."""

    def __init__(self, info: TuyaDeviceInfo) -> None:
        self._info = info

    async def get_device_info(self, mac_address: str,
                              force_update: bool = False) -> TuyaDeviceInfo:
        return self._info


def _config() -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in
        (raw.strip() for raw in _env_path().read_text().splitlines())
        if line and not line.startswith("#") and "=" in line
    )


async def _session(cfg: dict[str, str], ble: BLEDevice, action: Action) -> None:
    """Open a Tuya BLE session, wait for datapoints, run `action(dev)`."""
    dev = TuyaBLE(_StaticManager(TuyaDeviceInfo(
        uuid=cfg["FB_UUID"], local_key=cfg["FB_LOCAL_KEY"],
        device_id=cfg["FB_DEVICE_ID"], device_name="fingerbot",
        product_id=cfg.get("FB_PRODUCT_ID", ""),
        product_name="Fingerbot", category=cfg.get("FB_CATEGORY", "kg"),
    )), ble)
    try:
        await dev.initialize()
        for _ in range(40):
            if DP_CLICK in dev.datapoints._datapoints:
                break
            await asyncio.sleep(0.5)
        else:
            raise RuntimeError(f"dp{DP_CLICK} never appeared")
        await action(dev)
    finally:
        await dev.stop()


async def _connect(cfg: dict[str, str], action: Action,
                   discover_timeout: float = 45.0,
                   trace: Trace = lambda _m: None) -> None:
    mac = cfg["FB_MAC"]
    adapter = cfg.get("FB_ADAPTER", "hci0")
    path = f"/org/bluez/{adapter}/dev_" + mac.replace(":", "_")

    t = time.monotonic()
    try:  # fast path: the trusted, cached object. No scanning.
        await _session(cfg, BLEDevice(mac, "fingerbot",
                                      {"path": path, "props": {"Address": mac}}),
                       action)
        trace(f"fast path OK ({time.monotonic() - t:.1f}s, no scan)")
        return
    except Exception as e:
        trace(f"fast path failed after {time.monotonic() - t:.1f}s: "
              f"{type(e).__name__}: {str(e)[:120]}")

    # slow path: the cached object is stale or absent. Rediscover it, which
    # repopulates BlueZ, and connect with the scanner held open -- BlueZ evicts
    # un-paired devices the moment discovery stops.
    found = asyncio.Event()
    holder: dict[str, BLEDevice] = {}
    strength: dict[str, int] = {}

    def seen(device: BLEDevice, adv: AdvertisementData) -> None:
        if device.address == mac and not holder:
            holder["ble"] = device
            strength["rssi"] = adv.rssi
            found.set()

    scanner = BleakScanner(detection_callback=seen)
    await scanner.start()
    try:
        t = time.monotonic()
        await asyncio.wait_for(found.wait(), discover_timeout)
        trace(f"slow path: discovered at {strength.get('rssi')} dBm "
              f"after {time.monotonic() - t:.1f}s")
        await _session(cfg, holder["ble"], action)
        trace("slow path OK")
    finally:
        await scanner.stop()


async def press() -> None:
    async def click(dev: TuyaBLE) -> None:
        dev.datapoints[DP_CLICK].value = True
        await asyncio.sleep(2)
    await _connect(_config(), click)


async def info(scan_secs: float = 12.0) -> None:
    cfg = _config()
    mac = cfg["FB_MAC"]
    adapter = cfg.get("FB_ADAPTER", "hci0")

    print(f"config      {_env_path()}")
    for k in ("FB_MAC", "FB_ADAPTER", "FB_DEVICE_ID", "FB_UUID",
              "FB_PRODUCT_ID", "FB_CATEGORY"):
        if k in cfg:
            print(f"  {k:<14} {cfg[k]}")
    print(f"  {'FB_LOCAL_KEY':<14} {'set' if cfg.get('FB_LOCAL_KEY') else 'MISSING'} "
          f"({len(cfg.get('FB_LOCAL_KEY', ''))} chars)")
    print(f"  {'object path':<14} /org/bluez/{adapter}/dev_{mac.replace(':', '_')}")

    def sh(*cmd: str) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=15).stdout
        except Exception as e:
            return f"({type(e).__name__})"

    print("\nadapter")
    for line in sh("bluetoothctl", "show").splitlines():
        if any(w in line for w in ("Powered", "Discovering", "Controller")):
            print("  " + line.strip())

    print("\nbluez cache")
    out = sh("bluetoothctl", "info", mac)
    hit = [line.strip() for line in out.splitlines()
           if any(w in line for w in ("Name", "Alias", "Paired", "Bonded",
                                      "Trusted", "Connected", "RSSI"))]
    print("\n".join("  " + line for line in hit) if hit else "  (absent from cache)")

    print(f"\nadvertising ({scan_secs:.0f}s passive scan)")
    rssi: list[int] = []

    def seen(d: BLEDevice, adv: AdvertisementData) -> None:
        if d.address == mac:
            rssi.append(adv.rssi)
    scanner = BleakScanner(detection_callback=seen)
    await scanner.start()
    await asyncio.sleep(scan_secs)
    await scanner.stop()
    if rssi:
        print(f"  {len(rssi)} adverts   rssi min={min(rssi)} max={max(rssi)} "
              f"median={sorted(rssi)[len(rssi) // 2]} dBm")
    else:
        print("  NONE SEEN -- out of range, powered off, or discovery is "
              "held by another process")

    print("\nsession")
    async def dump(dev: TuyaBLE) -> None:
        dps = dev.datapoints._datapoints
        print(f"  {len(dps)} datapoints")
        for i in sorted(dps):
            dp = dps[i]
            mark = "  <- click" if i == DP_CLICK else ""
            print(f"    dp {i:>3}  {dp.type.name:<12} {dp.value!r}{mark}")
    try:
        await _connect(cfg, dump, trace=lambda m: print("  " + m))
    except Exception as e:
        print(f"  CONNECT FAILED: {type(e).__name__}: {str(e)[:200]}")
        raise SystemExit(1) from e


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "press"
    if cmd in ("press", "click"):
        asyncio.run(press())
        print("clicked")
    elif cmd == "info":
        asyncio.run(info())
    else:
        raise SystemExit(f"usage: fingerbot [press|info]  (got {cmd!r})")
