"""Fakes for the radio. Nothing here touches Bluetooth: the module's socket
is replaced by FakeLink, behind which FakeFingerbot speaks just enough ATT
and Tuya BLE v3 to log in, report datapoints and accept writes -- and
records every Tuya frame it receives, so tests can prove what was sent.
"""
from __future__ import annotations

import pathlib
import socket
import struct

import pytest

import fingerbot as fb

MAC = "AA:BB:CC:11:22:33"
REAL_ATT_CONNECT = fb.att_connect

CONFIG = {
    "FB_MAC": MAC,
    "FB_DEVICE_ID": "deviceid0000",
    "FB_LOCAL_KEY": "0123456789abcdef",
    "FB_UUID": "uuid00000000",
    "FB_PRODUCT_ID": "prod0000",
    "FB_CATEGORY": "kg",
}

SRAND = bytes.fromhex("0a0b0c0d0e0f")

# The real device's GATT table, as discovered over the air.
# (start, end, uuid16) services; characteristics (decl, props, value, uuid16);
# descriptors (handle, uuid16).
SERVICES = [(0x0001, 0x0003, 0x1800), (0x0004, 0x0007, 0x1801), (0x0008, 0x000D, 0x1910)]
CHARS = [(0x0002, 0x0A, 0x0003, 0x2A00), (0x0005, 0x22, 0x0006, 0x2A05),
         (0x0009, 0x04, 0x000A, 0x2B11), (0x000B, 0x10, 0x000C, 0x2B10)]
DESCS = [(0x0007, 0x2902), (0x000D, 0x2902)]
H_WRITE, H_NOTIFY, H_CCCD = 0x000A, 0x000C, 0x000D

DEFAULT_DPS = {
    1: (fb.DT_BOOL, False), 101: (fb.DT_ENUM, 0), 102: (fb.DT_VALUE, 74),
    103: (fb.DT_VALUE, 0), 104: (fb.DT_ENUM, 0), 106: (fb.DT_VALUE, 0),
    108: (fb.DT_BOOL, False), 111: (fb.DT_VALUE, 100),
}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class FakeFingerbot:
    """The far end of the link. Knobs are plain attributes."""

    def __init__(self, cfg: dict[str, str]) -> None:
        self.local_key = cfg["FB_LOCAL_KEY"]
        self.keys = {fb.SECURITY_LOGIN: fb.login_key(self.local_key)}
        self.dps: dict[int, tuple[int, int]] = dict(DEFAULT_DPS)
        self.protocol = 3
        self.seq = 100
        self.reasm = fb.Reassembler()
        self.outbox: list[bytes] = []
        self.frames: list[fb.Frame] = []      # every Tuya frame received
        self.writes: list[tuple[int, object]] = []  # applied dp writes, in order
        self.cccd = 0
        # knobs
        self.pair_result = 0
        self.status_result = 0
        self.dp_result = 0
        self.report = True                    # report dps after status
        self.after_pair: list[tuple[int, bytes]] = []   # (code, data) to push
        self.mute: set[int] = set()           # codes to never answer
        self.info_code = fb.FUN_SENDER_DEVICE_INFO
        self.reply_key: bytes | None = None   # encrypt replies with this instead
        self.gatt_services = list(SERVICES)
        self.gatt_chars = list(CHARS)
        self.gatt_descs = list(DESCS)

    # -- ATT --------------------------------------------------------------
    def att(self, pdu: bytes) -> None:
        op = pdu[0]
        if op == fb.ATT_READ_BY_GROUP_REQ:
            start, end = struct.unpack_from("<HH", pdu, 1)
            hits = [s for s in self.gatt_services if start <= s[0] <= end]
            self._one(op, hits[:1], lambda s: struct.pack("<HHH", *s), 6)
        elif op == fb.ATT_READ_BY_TYPE_REQ:
            start, end = struct.unpack_from("<HH", pdu, 1)
            hits = [c for c in self.gatt_chars if start <= c[0] <= end]
            self._one(op, hits[:1], lambda c: struct.pack("<HBHH", *c), 7)
        elif op == fb.ATT_FIND_INFO_REQ:
            start, end = struct.unpack_from("<HH", pdu, 1)
            hits = [d for d in self.gatt_descs if start <= d[0] <= end]
            self._one(op, hits[:1], lambda d: struct.pack("<HH", *d), 1)
        elif op == fb.ATT_WRITE_REQ:
            handle = struct.unpack_from("<H", pdu, 1)[0]
            assert handle == H_CCCD, f"write request to 0x{handle:04x}"
            self.cccd = struct.unpack_from("<H", pdu, 3)[0]
            self.outbox.append(bytes([fb.ATT_WRITE_RSP]))
        elif op == fb.ATT_WRITE_CMD:
            handle = struct.unpack_from("<H", pdu, 1)[0]
            assert handle == H_WRITE, f"write command to 0x{handle:04x}"
            blob = self.reasm.feed(pdu[3:])
            if blob is not None:
                self.tuya(fb.decode_frame(blob, self.keys))
        else:  # pragma: no cover - the client sent something unexpected
            raise AssertionError(f"unexpected ATT pdu {pdu.hex()}")

    def _one(self, op: int, hits: list, pack, size: int) -> None:
        if not hits:
            self.outbox.append(struct.pack("<BBHB", fb.ATT_ERROR_RSP, op, 0, fb.ATT_NOT_FOUND))
        else:
            self.outbox.append(bytes([op + 1, size]) + b"".join(pack(h) for h in hits))

    # -- Tuya -------------------------------------------------------------
    def notify(self, code: int, data: bytes, response_to: int = 0,
               security: int = fb.SECURITY_SESSION) -> None:
        self.seq += 1
        key = self.reply_key or self.keys[security]
        for frag in fb.encode_frame(self.seq, code, data, key, security,
                                    self.protocol, response_to):
            self.outbox.append(struct.pack("<BH", fb.ATT_NOTIFY, H_NOTIFY) + frag)

    def report_dps(self, ids: list[int]) -> None:
        self.notify(fb.FUN_RECEIVE_DP, b"".join(
            fb.encode_dp(i, *self.dps[i]) for i in ids))

    def tuya(self, f: fb.Frame) -> None:
        self.frames.append(f)
        if f.code in self.mute:
            return
        if f.code == fb.FUN_SENDER_DEVICE_INFO:
            info = (bytes([1, 2, self.protocol, 0, 0, 1]) + SRAND + bytes([4, 5])
                    + bytes(range(32)))
            self.notify(self.info_code, info, f.seq, fb.SECURITY_LOGIN)
            self.keys[fb.SECURITY_SESSION] = fb.session_key(self.local_key, SRAND)
        elif f.code == fb.FUN_SENDER_PAIR:
            self.notify(f.code, bytes([self.pair_result]), f.seq)
            for code, data in self.after_pair:
                self.notify(code, data)
        elif f.code == fb.FUN_SENDER_DEVICE_STATUS:
            self.notify(f.code, bytes([self.status_result]), f.seq)
            if self.report:
                self.report_dps(sorted(self.dps))
        elif f.code == fb.FUN_SENDER_DPS:
            changed = []
            for dp, dtype, value in fb.parse_dps(f.data):
                assert dtype == self.dps[dp][0], f"dp{dp} written as type {dtype}"
                assert isinstance(value, int)
                self.dps[dp] = (dtype, value)
                self.writes.append((dp, value))
                changed.append(dp)
            self.notify(f.code, bytes([self.dp_result]), f.seq)
            self.report_dps(changed)
        # replies (f.response_to != 0) are just recorded

    def codes(self) -> list[int]:
        return [f.code for f in self.frames]


class FakeLink:
    """Stands in for the connected L2CAP socket."""

    def __init__(self, device: FakeFingerbot, clock: Clock) -> None:
        self.device = device
        self.clock = clock
        self.timeout = 0.0
        self.closed = False
        self.sent: list[bytes] = []

    def send(self, pdu: bytes, /) -> int:
        assert not self.closed
        self.sent.append(bytes(pdu))
        if pdu[0] in (fb.ATT_ERROR_RSP, fb.ATT_MTU_RSP, fb.ATT_CONFIRM):
            return len(pdu)   # replies to the device's own requests
        self.device.att(bytes(pdu))
        return len(pdu)

    def settimeout(self, value: float | None, /) -> None:
        self.timeout = value or 0.0

    def recv(self, n: int, /) -> bytes:
        if self.device.outbox:
            return self.device.outbox.pop(0)
        self.clock.t += self.timeout
        raise socket.timeout("timed out")

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def cfg() -> dict[str, str]:
    return dict(CONFIG)


@pytest.fixture
def clock(monkeypatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(fb, "_now", c)
    return c


@pytest.fixture
def device(cfg) -> FakeFingerbot:
    return FakeFingerbot(cfg)


@pytest.fixture
def link(device, clock) -> FakeLink:
    return FakeLink(device, clock)


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Write a credentials file and point $FINGERBOT_ENV at it."""

    def write(text: str, name: str = "device.env") -> pathlib.Path:
        path = tmp_path / name
        path.write_text(text)
        monkeypatch.setenv("FINGERBOT_ENV", str(path))
        return path

    return write


@pytest.fixture
def wired(monkeypatch, env_file, link):
    """Config on disk plus att_connect patched to hand out `link`.
    Returns a list of every att_connect call."""
    env_file("".join(f"{k}={v}\n" for k, v in CONFIG.items()))
    calls: list[tuple] = []

    def fake_connect(mac, addr_type, local, timeout):
        calls.append((mac, addr_type, local, timeout))
        return link

    monkeypatch.setattr(fb, "att_connect", fake_connect)
    return calls


@pytest.fixture(autouse=True)
def no_radio(monkeypatch):
    """Fail loudly if anything reaches for a real Bluetooth socket."""

    def refuse(*a, **k):  # pragma: no cover - only hit by a broken test
        raise AssertionError("real att_connect reached")

    monkeypatch.setattr(fb, "att_connect", refuse)
