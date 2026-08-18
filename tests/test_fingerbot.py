"""Unit tests for fingerbot. No radio, no D-Bus, no network."""
from __future__ import annotations

import asyncio

import pytest
from conftest import CONFIG, MAC, FakeScanner, FakeTuyaBLE, ble_device
from tuya_ble import TuyaDeviceInfo

import fingerbot


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
def test_config_parses_and_ignores_noise(env_file):
    env_file(
        "# a comment\n"
        "\n"
        "FB_MAC=AA:BB:CC:11:22:33\n"
        "  FB_CATEGORY=kg  \n"
        "garbage-without-equals\n"
        "FB_LOCAL_KEY=key=with=equals\n"
    )
    cfg = fingerbot._config()
    assert cfg == {
        "FB_MAC": "AA:BB:CC:11:22:33",
        "FB_CATEGORY": "kg",
        "FB_LOCAL_KEY": "key=with=equals",
    }


def test_config_missing_file_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGERBOT_ENV", str(tmp_path / "nope.env"))
    with pytest.raises(FileNotFoundError):
        fingerbot._config()


def test_env_path_honours_override(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGERBOT_ENV", str(tmp_path / "custom.env"))
    assert fingerbot._env_path() == tmp_path / "custom.env"


def test_env_path_default_is_under_home(tmp_path, monkeypatch):
    monkeypatch.delenv("FINGERBOT_ENV", raising=False)
    monkeypatch.setattr(fingerbot.Path, "home", classmethod(lambda cls: tmp_path))
    assert fingerbot._env_path() == tmp_path / ".config" / "fingerbot" / "device.env"


async def test_missing_mac_raises_keyerror(env_file):
    env_file("FB_CATEGORY=kg\n")
    with pytest.raises(KeyError, match="FB_MAC"):
        await fingerbot._connect(fingerbot._config(), _noop, discover_timeout=0.01)


async def _noop(dev):  # pragma: no cover - only reached if a test misbehaves
    raise AssertionError("action should not have run")


# --------------------------------------------------------------------------
# _StaticManager
# --------------------------------------------------------------------------
async def test_static_manager_returns_its_info():
    sentinel = TuyaDeviceInfo(uuid="u", local_key="k", device_id="d",
                              device_name="fingerbot", product_id="p",
                              product_name="Fingerbot", category="kg")
    manager = fingerbot._StaticManager(sentinel)
    assert await manager.get_device_info("any-address") is sentinel
    assert await manager.get_device_info("any-address", force_update=True) is sentinel


# --------------------------------------------------------------------------
# _session
# --------------------------------------------------------------------------
async def test_session_initialises_runs_action_and_stops(cfg):
    seen = []

    async def action(dev):
        seen.append(dev)

    await fingerbot._session(cfg, ble_device(MAC), action)

    session = FakeTuyaBLE.instances[0]
    assert session.initialized
    assert seen == [session]
    assert session.stopped == 1
    manager = session.manager
    assert isinstance(manager, fingerbot._StaticManager)
    info = manager._info
    assert info.uuid == cfg["FB_UUID"]
    assert info.local_key == cfg["FB_LOCAL_KEY"]
    assert info.device_id == cfg["FB_DEVICE_ID"]
    assert info.product_id == cfg["FB_PRODUCT_ID"]
    assert info.category == cfg["FB_CATEGORY"]


async def test_session_defaults_product_and_category(cfg):
    del cfg["FB_PRODUCT_ID"]
    del cfg["FB_CATEGORY"]

    async def action(dev):
        pass

    await fingerbot._session(cfg, ble_device(MAC), action)
    manager = FakeTuyaBLE.instances[0].manager
    assert isinstance(manager, fingerbot._StaticManager)
    info = manager._info
    assert info.product_id == ""
    assert info.category == "kg"


async def test_session_waits_for_late_datapoint(cfg):
    FakeTuyaBLE.appear_after = 3
    ran = []

    async def action(dev):
        ran.append(fingerbot.DP_CLICK in dev.datapoints._datapoints)

    await fingerbot._session(cfg, ble_device(MAC), action)
    assert ran == [True]


async def test_session_datapoint_timeout(cfg):
    FakeTuyaBLE.dps = {1: (False, "bool")}  # dp108 never arrives

    with pytest.raises(RuntimeError, match="dp108 never appeared"):
        await fingerbot._session(cfg, ble_device(MAC), _noop)

    assert FakeTuyaBLE.instances[0].stopped == 1


async def test_session_stops_even_when_initialize_fails(cfg):
    FakeTuyaBLE.initialize_exc = OSError("boom")

    with pytest.raises(OSError):
        await fingerbot._session(cfg, ble_device(MAC), _noop)

    assert FakeTuyaBLE.instances[0].stopped == 1


# --------------------------------------------------------------------------
# _connect: fast path
# --------------------------------------------------------------------------
async def test_fast_path_connects_to_cached_object_without_scanning(cfg):
    traces = []
    ran = []

    async def action(dev):
        ran.append(dev)

    await fingerbot._connect(cfg, action, trace=traces.append)

    assert FakeScanner.instances == []  # never scanned
    assert len(ran) == 1
    ble = FakeTuyaBLE.instances[0].ble_device
    assert ble.address == MAC
    assert ble.details["path"] == "/org/bluez/hci0/dev_AA_BB_CC_11_22_33"
    assert ble.details["props"] == {"Address": MAC}
    assert traces[0].startswith("fast path OK")


async def test_fast_path_uses_adapter_override(cfg):
    cfg["FB_ADAPTER"] = "hci7"

    async def action(dev):
        pass

    await fingerbot._connect(cfg, action)
    ble = FakeTuyaBLE.instances[0].ble_device
    assert ble.details["path"] == "/org/bluez/hci7/dev_AA_BB_CC_11_22_33"


async def test_connect_default_trace_is_silent(cfg, capsys):
    async def action(dev):
        pass

    await fingerbot._connect(cfg, action)
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------
# _connect: slow path
# --------------------------------------------------------------------------
async def test_slow_path_rediscovers_after_fast_path_failure(cfg):
    FakeTuyaBLE.initialize_exc = TimeoutError("stale object")
    FakeScanner.adverts = [("00:00:00:00:00:00", -90), (MAC, -41), (MAC, -42)]
    traces = []
    ran = []

    async def action(dev):
        ran.append(dev)

    # the fast path fails once; the slow path's session must succeed
    async def initialize(self):
        if len(FakeTuyaBLE.instances) == 1:
            raise TimeoutError("stale object")
        self.initialized = True
        self._publish()

    FakeTuyaBLE.initialize_exc = None
    original = FakeTuyaBLE.initialize
    FakeTuyaBLE.initialize = initialize
    try:
        await fingerbot._connect(cfg, action, trace=traces.append)
    finally:
        FakeTuyaBLE.initialize = original

    scanner = FakeScanner.instances[0]
    assert scanner.started == 1 and scanner.stopped == 1
    assert len(ran) == 1
    # the second session used the *discovered* device, not the cached path
    discovered = FakeTuyaBLE.instances[1].ble_device
    assert discovered.address == MAC
    assert traces[0].startswith("fast path failed after ")
    assert "TimeoutError" in traces[0]
    assert "discovered at -41 dBm" in traces[1]  # first advert wins, no overwrite
    assert traces[2] == "slow path OK"


async def test_slow_path_discovery_timeout_stops_scanner(cfg):
    FakeTuyaBLE.initialize_exc = TimeoutError("stale object")
    FakeScanner.adverts = [("11:11:11:11:11:11", -50)]  # never our MAC

    with pytest.raises(asyncio.TimeoutError):
        await fingerbot._connect(cfg, _noop, discover_timeout=0.01)

    scanner = FakeScanner.instances[0]
    assert scanner.started == 1 and scanner.stopped == 1
    assert len(FakeTuyaBLE.instances) == 1  # only the failed fast-path session


# --------------------------------------------------------------------------
# press / info
# --------------------------------------------------------------------------
async def test_press_writes_dp108_exactly_once(env_file):
    env_file("\n".join(f"{k}={v}" for k, v in CONFIG.items()))

    await fingerbot.press()

    assert FakeTuyaBLE.writes == [(fingerbot.DP_CLICK, True)]


def _bluetoothctl(monkeypatch, show="", info_out=""):
    class Result:
        def __init__(self, stdout):
            self.stdout = stdout

    def run(cmd, **kwargs):
        assert cmd[0] == "bluetoothctl"
        return Result(show if cmd[1] == "show" else info_out)

    monkeypatch.setattr(fingerbot.subprocess, "run", run)


async def test_info_writes_no_datapoint(env_file, monkeypatch, capsys):
    env_file("\n".join(f"{k}={v}" for k, v in CONFIG.items()))
    _bluetoothctl(
        monkeypatch,
        show="Controller AA:BB\n\tPowered: yes\n\tDiscovering: no\n\tirrelevant\n",
        info_out=f"Device {MAC}\n\tName: fingerbot\n\tTrusted: yes\n\tnoise\n",
    )
    FakeTuyaBLE.dps = {1: (False, "bool"), 108: (False, "bool"), 111: (87, "value")}
    FakeScanner.adverts = [(MAC, -44), (MAC, -40), ("99:99:99:99:99:99", -70)]

    await fingerbot.info(scan_secs=0)

    assert FakeTuyaBLE.writes == []  # the real invariant: info never actuates
    out = capsys.readouterr().out
    assert "FB_MAC         AA:BB:CC:11:22:33" in out
    assert "FB_LOCAL_KEY   set (16 chars)" in out
    assert "object path    /org/bluez/hci0/dev_AA_BB_CC_11_22_33" in out
    assert "Powered: yes" in out
    assert "irrelevant" not in out
    assert "Trusted: yes" in out
    assert "noise" not in out
    assert "2 adverts   rssi min=-44 max=-40 median=-40 dBm" in out
    assert "3 datapoints" in out
    assert "dp 108  bool         False  <- click" in out
    assert "dp 111  value        87\n" in out
    assert "fast path OK" in out


async def test_info_reports_missing_pieces(env_file, monkeypatch, capsys):
    env_file(f"FB_MAC={MAC}\nFB_LOCAL_KEY=\n")

    def run(cmd, **kwargs):
        raise FileNotFoundError("bluetoothctl")

    monkeypatch.setattr(fingerbot.subprocess, "run", run)

    async def boom(cfg, action, **kwargs):
        raise TimeoutError("stale object")

    monkeypatch.setattr(fingerbot, "_connect", boom)

    with pytest.raises(SystemExit) as excinfo:
        await fingerbot.info(scan_secs=0)

    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "FB_LOCAL_KEY   MISSING (0 chars)" in out
    assert "FB_DEVICE_ID" not in out  # absent keys are not printed
    assert "(absent from cache)" in out  # sh() swallowed the OSError
    assert "NONE SEEN" in out
    assert "CONNECT FAILED: TimeoutError: stale object" in out


# --------------------------------------------------------------------------
# main()
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", ["press", "click"])
def test_main_presses(monkeypatch, capsys, cmd):
    calls = []

    async def fake_press():
        calls.append("pressed")

    monkeypatch.setattr(fingerbot, "press", fake_press)
    monkeypatch.setattr(fingerbot.sys, "argv", ["fingerbot", cmd])

    fingerbot.main()

    assert calls == ["pressed"]
    assert capsys.readouterr().out == "clicked\n"


def test_main_defaults_to_press(monkeypatch, capsys):
    calls = []

    async def fake_press():
        calls.append("pressed")

    monkeypatch.setattr(fingerbot, "press", fake_press)
    monkeypatch.setattr(fingerbot.sys, "argv", ["fingerbot"])

    fingerbot.main()

    assert calls == ["pressed"]
    assert capsys.readouterr().out == "clicked\n"


def test_main_info(monkeypatch):
    calls = []

    async def fake_info():
        calls.append("info")

    monkeypatch.setattr(fingerbot, "info", fake_info)
    monkeypatch.setattr(fingerbot.sys, "argv", ["fingerbot", "info"])

    fingerbot.main()

    assert calls == ["info"]


def test_main_usage_error(monkeypatch):
    monkeypatch.setattr(fingerbot.sys, "argv", ["fingerbot", "wat"])

    with pytest.raises(SystemExit) as excinfo:
        fingerbot.main()

    assert "usage: fingerbot [press|info]" in str(excinfo.value)
    assert "'wat'" in str(excinfo.value)
