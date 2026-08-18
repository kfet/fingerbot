"""Fakes for bleak / tuya-ble / subprocess.

Nothing here touches a radio, a D-Bus socket, or the network. Every test
runs identically on a host with no Bluetooth controller at all.
"""
from __future__ import annotations

import asyncio
import pathlib
from typing import ClassVar

import pytest
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData, AdvertisementDataCallback
from tuya_ble import AbstaractTuyaDeviceManager

import fingerbot


# --------------------------------------------------------------------------
# tuya-ble fakes
# --------------------------------------------------------------------------
class FakeDPType:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeDatapoint:
    """A datapoint whose `.value` assignments are recorded on the session."""

    def __init__(self, index: int, value: object, type_name: str,
                 writes: list[tuple[int, object]]) -> None:
        self.index = index
        self.type = FakeDPType(type_name)
        self._value = value
        self._writes = writes

    @property
    def value(self) -> object:
        return self._value

    @value.setter
    def value(self, new: object) -> None:
        self._value = new
        self._writes.append((self.index, new))


class FakeDatapoints:
    def __init__(self) -> None:
        self._datapoints: dict[int, FakeDatapoint] = {}

    def __getitem__(self, index: int) -> FakeDatapoint:
        return self._datapoints[index]


class FakeTuyaBLE:
    """Stands in for tuya_ble.TuyaBLE.

    Class attributes configure behaviour per test:
      dps            -- {index: (value, type_name)} published on initialize()
      appear_after   -- how many wait-loop polls before dp108 shows up
      initialize_exc -- raise this from initialize()
    """

    dps: ClassVar[dict[int, tuple[object, str]]] = {108: (False, "bool")}
    appear_after: int = 0
    initialize_exc: BaseException | None = None

    instances: ClassVar[list[FakeTuyaBLE]] = []
    writes: ClassVar[list[tuple[int, object]]] = []

    def __init__(self, manager: AbstaractTuyaDeviceManager, ble_device: BLEDevice,
                 advertisement_data: AdvertisementData | None = None) -> None:
        self.manager = manager
        self.ble_device = ble_device
        self.datapoints = FakeDatapoints()
        self.initialized = False
        self.stopped = 0
        self._polls_left = type(self).appear_after
        type(self).instances.append(self)

    def _publish(self) -> None:
        for index, (value, type_name) in type(self).dps.items():
            self.datapoints._datapoints[index] = FakeDatapoint(
                index, value, type_name, type(self).writes
            )

    async def initialize(self) -> None:
        exc = type(self).initialize_exc
        if exc is not None:
            raise exc
        self.initialized = True
        if self._polls_left == 0:
            self._publish()

    async def stop(self) -> None:
        self.stopped += 1

    def _tick(self) -> None:
        """Called from the patched asyncio.sleep, to model a delayed dp."""
        if self._polls_left > 0:
            self._polls_left -= 1
            if self._polls_left == 0:
                self._publish()


# --------------------------------------------------------------------------
# bleak fakes
# --------------------------------------------------------------------------
def fake_adv(rssi: int) -> AdvertisementData:
    """A real AdvertisementData; only `.rssi` is read by the code under test."""
    return AdvertisementData(local_name="fingerbot", manufacturer_data={},
                             service_data={}, service_uuids=[], tx_power=None,
                             rssi=rssi, platform_data=())


def ble_device(address: str = "", name: str = "fingerbot") -> BLEDevice:
    """A real BLEDevice. It is inert data: no radio, no D-Bus, no adapter."""
    return BLEDevice(address or MAC, name, {"path": "/discovered", "props": {}})


class FakeScanner:
    """Stands in for bleak.BleakScanner.

    `adverts` is a class-level list of (address, rssi) emitted on start().
    """

    adverts: ClassVar[list[tuple[str, int]]] = []
    instances: ClassVar[list[FakeScanner]] = []
    start_exc: BaseException | None = None

    def __init__(self, detection_callback: AdvertisementDataCallback,
                 **kwargs: object) -> None:
        self.callback = detection_callback
        self.started = 0
        self.stopped = 0
        type(self).instances.append(self)

    async def start(self) -> None:
        exc = type(self).start_exc
        if exc is not None:
            raise exc
        self.started += 1
        for address, rssi in type(self).adverts:
            self.callback(ble_device(address), fake_adv(rssi))

    async def stop(self) -> None:
        self.stopped += 1


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------
MAC = "AA:BB:CC:11:22:33"

CONFIG = {
    "FB_MAC": MAC,
    "FB_DEVICE_ID": "deviceid0000",
    "FB_LOCAL_KEY": "0123456789abcdef",
    "FB_UUID": "uuid00000000",
    "FB_PRODUCT_ID": "prod0000",
    "FB_CATEGORY": "kg",
}


@pytest.fixture
def cfg() -> dict[str, str]:
    return dict(CONFIG)


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Write a credentials file and point $FINGERBOT_ENV at it."""

    def write(text: str, name: str = "device.env") -> pathlib.Path:
        path = tmp_path / name
        path.write_text(text)
        monkeypatch.setenv("FINGERBOT_ENV", str(path))
        return path

    return write


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    """Patch out every I/O boundary of the module, for every test."""
    FakeTuyaBLE.instances = []
    FakeTuyaBLE.writes = []
    FakeTuyaBLE.dps = {108: (False, "bool")}
    FakeTuyaBLE.appear_after = 0
    FakeTuyaBLE.initialize_exc = None
    FakeScanner.instances = []
    FakeScanner.adverts = []
    FakeScanner.start_exc = None

    monkeypatch.setattr(fingerbot, "TuyaBLE", FakeTuyaBLE)
    monkeypatch.setattr(fingerbot, "BleakScanner", FakeScanner)

    real_sleep = asyncio.sleep

    async def fake_sleep(delay: float, *args: object, **kwargs: object) -> None:
        for session in FakeTuyaBLE.instances:
            session._tick()
        return await real_sleep(0)

    monkeypatch.setattr(fingerbot.asyncio, "sleep", fake_sleep)

    def no_subprocess(*args: object, **kwargs: object) -> None:  # pragma: no cover
        raise AssertionError("subprocess.run was not mocked")

    monkeypatch.setattr(fingerbot.subprocess, "run", no_subprocess)
    return FakeTuyaBLE
