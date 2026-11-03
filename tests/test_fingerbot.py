"""Unit tests for fingerbot. No radio, no network: see conftest.FakeFingerbot."""
from __future__ import annotations

import ast
import ctypes
import errno
import inspect
import os
import pathlib
import runpy
import socket
import struct
import subprocess
import sys
from typing import ClassVar

import pytest
from conftest import (
    CONFIG,
    H_CCCD,
    H_NOTIFY,
    H_WRITE,
    MAC,
    REAL_ATT_CONNECT,
    FakeLink,
)

import fingerbot as fb


def session(link: FakeLink, cfg=None, actuate: bool = False) -> fb.Session:
    att = fb.Att(link)
    handles = att.discover()
    att.write_request(handles.cccd, b"\x01\x00")
    return fb.Session(att, handles, dict(cfg or CONFIG), actuate=actuate)


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
def test_config_parses_and_ignores_noise(env_file):
    env_file("# a comment\n\nFB_MAC=AA:BB:CC:11:22:33\n  FB_CATEGORY=kg  \n"
             "garbage-without-equals\nFB_LOCAL_KEY=key=with=equals\n")
    assert fb._config() == {"FB_MAC": "AA:BB:CC:11:22:33", "FB_CATEGORY": "kg",
                            "FB_LOCAL_KEY": "key=with=equals"}


def test_config_missing_file_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGERBOT_ENV", str(tmp_path / "nope.env"))
    with pytest.raises(FileNotFoundError):
        fb._config()


def test_env_path_honours_override(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGERBOT_ENV", str(tmp_path / "custom.env"))
    assert fb._env_path() == tmp_path / "custom.env"


def test_env_path_default_is_under_home(tmp_path, monkeypatch):
    monkeypatch.delenv("FINGERBOT_ENV", raising=False)
    monkeypatch.setattr(fb.Path, "home", classmethod(lambda cls: tmp_path))
    assert fb._env_path() == tmp_path / ".config" / "fingerbot" / "device.env"


def test_now_is_monotonic():
    assert fb._now() <= fb._now()


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------
def test_sockaddr_l2_layout():
    sa = fb.sockaddr_l2("AA:BB:CC:11:22:33", fb.BDADDR_LE_PUBLIC)
    assert len(sa) == 14
    assert sa == (struct.pack("<HH", 31, 0) + bytes.fromhex("332211ccbbaa")
                  + struct.pack("<HB", 4, 1) + b"\x00")


@pytest.mark.parametrize("bad", ["AA:BB", "AA:BB:CC:DD:EE:FF:00"])
def test_bdaddr_rejects_garbage(bad):
    with pytest.raises(ValueError, match="not a Bluetooth address"):
        fb._bdaddr(bad)


def test_libc_loads():
    assert hasattr(fb._libc(), "connect")


class FakeSock:
    """A socket.socket stand-in for the transport functions."""

    instances: ClassVar[list[FakeSock]] = []

    def __init__(self, *args) -> None:
        self.args = args
        self.closed = False
        self.blocking: list[bool] = []
        self.opts: list[tuple] = []
        self.so_error = 0
        FakeSock.instances.append(self)

    def fileno(self) -> int:
        return 99

    def setsockopt(self, *a) -> None:
        self.opts.append(a)

    def getsockopt(self, level, opt) -> int:
        assert (level, opt) == (socket.SOL_SOCKET, socket.SO_ERROR)
        return self.so_error

    def setblocking(self, flag: bool) -> None:
        self.blocking.append(flag)

    def close(self) -> None:
        self.closed = True


class FakeLibc:
    def __init__(self, bind_err: int = 0, connect_err: int = 0) -> None:
        self.bind_err, self.connect_err = bind_err, connect_err
        self.calls: list[tuple[str, bytes]] = []
        self.writable = True
        self.selected: list[float] = []

    def _call(self, name: str, err: int, fd: int, addr, size: int) -> int:
        self.calls.append((name, ctypes.string_at(addr, size)))
        if err:
            ctypes.set_errno(err)
            return -1
        return 0

    def bind(self, fd, addr, size):
        return self._call("bind", self.bind_err, fd, addr, size)

    def connect(self, fd, addr, size):
        return self._call("connect", self.connect_err, fd, addr, size)


@pytest.fixture
def transport(monkeypatch):
    FakeSock.instances = []
    libc = FakeLibc()
    monkeypatch.setattr(fb, "_libc", lambda: libc)
    monkeypatch.setattr(fb.socket, "socket", FakeSock)

    class FakePoll:
        def register(self, fd: int, mask: int) -> None:
            assert (fd, mask) == (99, fb.select.POLLOUT)

        def poll(self, ms: int) -> list[tuple[int, int]]:
            libc.selected.append(ms / 1000)
            return [(99, fb.select.POLLOUT)] if libc.writable else []

    monkeypatch.setattr(fb.select, "poll", FakePoll)
    return libc


def test_att_connect_immediate(transport):
    s = REAL_ATT_CONNECT(MAC, fb.BDADDR_LE_RANDOM, fb.BDADDR_ANY, 5.0)
    assert isinstance(s, FakeSock)
    assert s.args == (fb.AF_BLUETOOTH, socket.SOCK_SEQPACKET, fb.BTPROTO_L2CAP)
    assert [c[0] for c in transport.calls] == ["bind", "connect"]
    assert transport.calls[1][1] == fb.sockaddr_l2(MAC, fb.BDADDR_LE_RANDOM)
    assert s.opts == [(fb.SOL_BLUETOOTH, fb.BT_SECURITY, b"\x01\x00")]
    assert s.blocking == [False, True]
    assert transport.selected == []
    assert not s.closed


def test_att_connect_in_progress_then_ok(transport):
    transport.connect_err = errno.EINPROGRESS
    s = REAL_ATT_CONNECT(MAC, fb.BDADDR_LE_PUBLIC, fb.BDADDR_ANY, 7.0)
    assert isinstance(s, FakeSock)
    assert transport.selected == [7.0]
    assert not s.closed


def test_att_connect_times_out(transport):
    transport.connect_err = errno.EINPROGRESS
    transport.writable = False
    with pytest.raises(TimeoutError, match="timed out after 3s"):
        REAL_ATT_CONNECT(MAC, fb.BDADDR_LE_PUBLIC, fb.BDADDR_ANY, 3.0)
    assert FakeSock.instances[0].closed


def test_att_connect_async_error(transport, monkeypatch):
    transport.connect_err = errno.EAGAIN
    orig = FakeSock.__init__

    def init(self, *a):
        orig(self, *a)
        self.so_error = errno.EHOSTDOWN

    monkeypatch.setattr(FakeSock, "__init__", init)
    with pytest.raises(OSError, match="connect: ") as e:
        REAL_ATT_CONNECT(MAC, fb.BDADDR_LE_PUBLIC, fb.BDADDR_ANY, 3.0)
    assert e.value.errno == errno.EHOSTDOWN
    assert FakeSock.instances[0].closed


@pytest.mark.parametrize(("which", "what"), [("bind_err", "bind"), ("connect_err", "connect")])
def test_att_connect_hard_errors(transport, which, what):
    setattr(transport, which, errno.EPERM)
    with pytest.raises(OSError, match=f"{what}: ") as e:
        REAL_ATT_CONNECT(MAC, fb.BDADDR_LE_PUBLIC, fb.BDADDR_ANY, 3.0)
    assert e.value.errno == errno.EPERM
    assert FakeSock.instances[0].closed


def test_adapter_address(monkeypatch, transport):
    def ioctl(fd, req, buf):
        assert (fd, req) == (99, fb.HCIGETDEVINFO)
        assert struct.unpack_from("=H", buf)[0] == 1
        buf[10:16] = bytes.fromhex("7feA7deb27b8")
        return 0

    monkeypatch.setattr(fb.fcntl, "ioctl", ioctl)
    assert fb.adapter_address("hci1") == "B8:27:EB:7D:EA:7F"
    assert FakeSock.instances[0].args == (fb.AF_BLUETOOTH, socket.SOCK_RAW, fb.BTPROTO_HCI)
    assert FakeSock.instances[0].closed


@pytest.mark.parametrize("bad", ["hcix", "usb0", "hci"])
def test_adapter_address_rejects_names(bad):
    with pytest.raises(ValueError, match="FB_ADAPTER"):
        fb.adapter_address(bad)


# --------------------------------------------------------------------------
# ATT
# --------------------------------------------------------------------------
@pytest.mark.parametrize(("raw", "want"), [
    (bytes.fromhex("1019"), "1910"),
    (bytes.fromhex("fb349b5f800000800010000010190000"), "1910"),
    (bytes(range(16)), "0f0e0d0c-0b0a-0908-0706-050403020100"),
])
def test_uuid_str(raw, want):
    assert fb.uuid_str(raw) == want


def test_discover_real_layout(link):
    att = fb.Att(link)
    assert att.discover() == fb.Handles(H_WRITE, H_NOTIFY, H_CCCD)


def test_discover_128bit_service_uuid(link, device):
    # a 128-bit SIG-base declaration of 1910 must be recognised too
    base = bytes.fromhex("fb349b5f800000800010000010190000")
    device.gatt_services = [(1, 3, 0x1800)]
    orig = device.att

    def att(pdu):
        if pdu[0] == fb.ATT_READ_BY_GROUP_REQ and struct.unpack_from("<H", pdu, 1)[0] > 3:
            if struct.unpack_from("<H", pdu, 1)[0] > 8:
                device._one(pdu[0], [], None, 0)
            else:
                device.outbox.append(bytes([0x11, 20]) + struct.pack("<HH", 8, 13) + base)
            return
        orig(pdu)

    device.att = att
    assert fb.Att(link).discover() == fb.Handles(H_WRITE, H_NOTIFY, H_CCCD)


def test_discover_no_tuya_service(link, device):
    device.gatt_services = device.gatt_services[:2]
    with pytest.raises(OSError, match="no GATT service 1910"):
        fb.Att(link).discover()


@pytest.mark.parametrize("drop", ["2b11", "2b10", "cccd"])
def test_discover_incomplete_service(link, device, drop):
    if drop == "cccd":
        device.gatt_descs = device.gatt_descs[:1]
    else:
        device.gatt_chars = [c for c in device.gatt_chars if f"{c[3]:04x}" != drop]
    with pytest.raises(OSError, match="lacks 2b11/2b10/CCCD"):
        fb.Att(link).discover()


def test_discover_notify_not_last(link, device):
    # 2b10 first, so its descriptor range ends at the next declaration
    device.gatt_chars = [(0x0002, 0x0A, 0x0003, 0x2A00), (0x0005, 0x22, 0x0006, 0x2A05),
                         (0x0009, 0x10, 0x000A, 0x2B10), (0x000C, 0x04, 0x000D, 0x2B11)]
    device.gatt_descs = [(0x0007, 0x2902), (0x000B, 0x2902)]
    assert fb.Att(link).discover() == fb.Handles(0x000D, 0x000A, 0x000B)


def test_walk_att_error(link, device):
    device.att = lambda pdu: device.outbox.append(bytes([1, pdu[0], 1, 0, 0x02]))
    with pytest.raises(OSError, match="failed: 01"):
        fb.Att(link).discover()


@pytest.mark.parametrize("rsp", [b"\x09\x06", b"\x11", b"\x11\x06\x01\x00"])
def test_walk_unexpected_or_empty(link, device, rsp):
    device.att = lambda pdu: device.outbox.append(rsp)
    with pytest.raises(OSError, match=r"unexpected|empty"):
        fb.Att(link).discover()


def test_walk_stops_at_ffff(link, device):
    device.gatt_services = [(1, 0xFFFF, 0x1910)]
    device.gatt_chars = []
    with pytest.raises(OSError, match="lacks"):
        fb.Att(link).discover()


def test_write_request_failure(link, device):
    device.att = lambda pdu: device.outbox.append(bytes([1, 0x12, 0x0D, 0, 0x03]))
    with pytest.raises(OSError, match="write to 0x000d failed"):
        fb.Att(link).write_request(H_CCCD, b"\x01\x00")


def test_request_timeout(link, device, clock):
    device.att = lambda pdu: None
    t = clock.t
    with pytest.raises(TimeoutError, match="no response"):
        fb.Att(link, timeout=4).request(b"\x10\x01\x00\xff\xff\x00\x28")
    assert clock.t == t + 4


def test_att_serves_peer_pdus_while_waiting(link, device):
    """Indications are confirmed, the peer's MTU exchange and requests are
    answered, its commands and empty reads are ignored -- all while we wait
    for our own response."""
    got: list[tuple[int, bytes]] = []
    att = fb.Att(link)
    att.on_notify = lambda h, v: got.append((h, v))
    device.outbox += [b"", bytes([0x1D, 0x0C, 0, 0xAA]), bytes([0x02, 0x00, 0x02]),
                      bytes([0x0A, 0x03, 0x00]), bytes([0xD2, 1, 0, 0, 0]),
                      bytes([0x1B, 0x0C, 0, 0xBB])]
    att.write_request(H_CCCD, b"\x01\x00")
    assert got == [(0x0C, b"\xaa"), (0x0C, b"\xbb")]
    assert link.sent[1:4] == [bytes([0x1E]), bytes([0x03, 23, 0]),
                             bytes([0x01, 0x0A, 0, 0, fb.ATT_REQ_NOT_SUPPORTED])]
    assert device.cccd == 1


def test_pump(link, device, clock):
    att = fb.Att(link)
    assert att.pump(lambda: True, 5) is True
    device.outbox += [b"", bytes([0x1B, 0x0C, 0, 1])]
    seen: list[bytes] = []
    att.on_notify = lambda h, v: seen.append(v)
    assert att.pump(lambda: False, 5) is False
    assert seen == [b"\x01"]
    att.pump(lambda: False, 0)   # zero budget: returns at once


def test_default_on_notify_is_inert(link, device):
    att = fb.Att(link)
    device.outbox.append(bytes([0x1B, 0x0C, 0, 1]))
    assert att.pump(lambda: False, 1) is False


# --------------------------------------------------------------------------
# Tuya session
# --------------------------------------------------------------------------
def test_login_reports_dps(link, device):
    s = session(link)
    s.login()
    assert s.info is not None and s.info.protocol_version == 3
    assert s.info.device_version == "1.2" and s.info.bound
    assert {k: (v.type, v.value) for k, v in s.dps.items()} == device.dps
    codes = device.codes()
    assert codes[:3] == [fb.FUN_SENDER_DEVICE_INFO, fb.FUN_SENDER_PAIR,
                         fb.FUN_SENDER_DEVICE_STATUS]
    # the dp report was acked as a reply
    acks = [f for f in device.frames if f.code == fb.FUN_RECEIVE_DP]
    assert len(acks) == 1 and acks[0].response_to != 0 and acks[0].data == b""
    assert fb.FUN_SENDER_DPS not in codes
    assert s.sent == [(f.code, f.response_to) for f in device.frames]


def test_login_already_paired_is_ok(link, device):
    device.pair_result = 2
    session(link).login()


def test_login_pair_failure(link, device):
    device.pair_result = 1
    with pytest.raises(fb.ProtocolError, match="pair failed: 01"):
        session(link).login()


def test_login_status_failure(link, device):
    device.status_result = 3
    with pytest.raises(fb.ProtocolError, match="status failed: 03"):
        session(link).login()


def test_login_dp_never_appears(link, device, clock):
    device.report = False
    with pytest.raises(RuntimeError, match="dp108 never appeared"):
        session(link).login(dp_timeout=7)


def test_login_device_info_missing(link, device):
    device.info_code = fb.FUN_SENDER_PAIR     # answers, but not with device info
    with pytest.raises(fb.ProtocolError, match="carried no device info"):
        session(link).login()


def test_request_timeout_names_code(link, device):
    device.mute = {fb.FUN_SENDER_DEVICE_INFO}
    with pytest.raises(TimeoutError, match="0x0000"):
        session(link).login()


def test_wrong_local_key_fails_loudly(link, device):
    """Our side cannot decrypt the device-info reply: that must abort the
    login with a ProtocolError, not time out or be dropped silently."""
    device.reply_key = b"\x00" * 16
    with pytest.raises(fb.ProtocolError):
        session(link).login()


def test_session_key_needed_before_info(link):
    s = session(link)
    with pytest.raises(fb.ProtocolError, match="needs the session key"):
        s._send(fb.FUN_SENDER_PAIR, b"")


def test_device_initiated_frames_are_answered(link, device):
    device.after_pair = [
        (fb.FUN_RECEIVE_TIME1_REQ, b""),
        (fb.FUN_RECEIVE_TIME2_REQ, b""),
        (fb.FUN_RECEIVE_TIME_DP, b"\x00" + b"1700000000000" + fb.encode_dp(111, fb.DT_VALUE, 55)),
        (fb.FUN_RECEIVE_TIME_DP, b"\x01" + bytes(4) + fb.encode_dp(106, fb.DT_VALUE, 9)),
        (fb.FUN_RECEIVE_SIGN_DP, b"\x00\x07\x00" + fb.encode_dp(104, fb.DT_ENUM, 1)),
        (fb.FUN_RECEIVE_SIGN_TIME_DP, b"\x00\x08\x01\x01" + bytes(4)
         + fb.encode_dp(1, fb.DT_BOOL, True)),
        (fb.FUN_RECEIVE_SIGN_TIME_DP, b"\x00\x09\x01\x00" + b"1700000000000"
         + fb.encode_dp(103, fb.DT_VALUE, 0)),
    ]
    device.report = False
    device.dps = {108: (fb.DT_BOOL, False)}
    device.after_pair.append((fb.FUN_RECEIVE_DP, fb.encode_dp(108, fb.DT_BOOL, False)))
    s = session(link)
    s.login()
    assert s.dps[111].value == 55 and s.dps[106].value == 9 and s.dps[104].value == 1
    assert s.dps[1].value is True and s.dps[103].value == 0
    replies = {f.code: f for f in device.frames if f.response_to}
    assert set(replies) == {fb.FUN_RECEIVE_TIME1_REQ, fb.FUN_RECEIVE_TIME2_REQ,
                            fb.FUN_RECEIVE_TIME_DP, fb.FUN_RECEIVE_SIGN_DP,
                            fb.FUN_RECEIVE_SIGN_TIME_DP, fb.FUN_RECEIVE_DP}
    assert len(replies[fb.FUN_RECEIVE_TIME1_REQ].data) == 15
    assert len(replies[fb.FUN_RECEIVE_TIME2_REQ].data) == 9
    sign = [f for f in device.frames if f.code == fb.FUN_RECEIVE_SIGN_TIME_DP]
    assert [f.data for f in sign] == [b"\x00\x08\x01\x00", b"\x00\x09\x01\x00"]


def test_notifications_on_other_handles_ignored(link, device):
    s = session(link)
    device.outbox.append(bytes([0x1B, 0x06, 0x00, 0xFF]))  # service changed, say
    s.wait(1)
    assert s.dps == {}


# --------------------------------------------------------------------------
# SAFETY: the read-only guarantee
# --------------------------------------------------------------------------
def test_read_only_session_refuses_dp_write_before_touching_link(link, device):
    s = session(link)
    s.login()
    sent = len(link.sent)
    for dp, value in [(108, True), (1, True), (101, 0), (102, 74), (103, 0)]:
        with pytest.raises(fb.ReadOnlyViolation):
            s.write_dp(dp, value)
        with pytest.raises(fb.ReadOnlyViolation):
            s._send(fb.FUN_SENDER_DPS, fb.encode_dp(dp, s.dps[dp].type, value))
    assert len(link.sent) == sent
    assert fb.FUN_SENDER_DPS not in device.codes()
    assert device.writes == []


@pytest.mark.parametrize("actuate", [False, True])
@pytest.mark.parametrize(("code", "response_to"), [
    (fb.FUN_SENDER_DPS, 5),          # a dp write dressed up as a reply
    (0x0005, 0), (0x0006, 0),        # unbind, reset
    (0x000C, 0), (0x0027, 0),        # OTA start, DPS v4
    (fb.FUN_RECEIVE_DP, 0),          # a reply code with nothing to reply to
    (fb.FUN_SENDER_PAIR, 3),         # a request code dressed up as a reply
])
def test_send_refuses_everything_off_the_allow_list(link, device, actuate, code, response_to):
    s = session(link, actuate=actuate)
    s.login()
    sent = len(link.sent)
    with pytest.raises(fb.ReadOnlyViolation, match=f"0x{code:04x}"):
        s._send(code, b"\x00", response_to)
    assert len(link.sent) == sent


def test_info_never_sends_a_dp_write(wired, device, link, capsys, monkeypatch):
    built: list[bool] = []
    real = fb.Session

    class Spy(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            built.append(self._actuate)

    monkeypatch.setattr(fb, "Session", Spy)
    fb.info()
    assert built == [False]
    assert fb.FUN_SENDER_DPS not in device.codes()
    assert device.writes == []
    assert set(device.codes()) <= {fb.FUN_SENDER_DEVICE_INFO, fb.FUN_SENDER_PAIR,
                                   fb.FUN_SENDER_DEVICE_STATUS, fb.FUN_RECEIVE_DP}


def test_only_press_can_build_an_actuating_session():
    """Structural: across the whole module, the sole place a Session is
    built with actuate=True is inside press()."""
    tree = ast.parse(inspect.getsource(fb))
    hits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "actuate" and not (
                            isinstance(kw.value, ast.Constant) and kw.value.value is False):
                        hits.append((fn.name, ast.unparse(kw.value)))
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Session" and len(node.args) > 3):
                hits.append((fn.name, "positional actuate"))
    assert [h[0] for h in hits] == ["press"]
    actuate = inspect.signature(fb.Session.__init__).parameters["actuate"]
    assert actuate.default is False
    assert actuate.kind is inspect.Parameter.KEYWORD_ONLY


def test_actuate_cannot_be_passed_positionally(link):
    att = fb.Att(link)
    with pytest.raises(TypeError):
        args: tuple = (att, fb.Handles(H_WRITE, H_NOTIFY, H_CCCD), dict(CONFIG), True)
        fb.Session(*args)


# --------------------------------------------------------------------------
# press (fakes only -- never a real device)
# --------------------------------------------------------------------------
def write_env(env_file, **extra):
    env_file("".join(f"{k}={v}\n" for k, v in {**CONFIG, **extra}.items()))


def test_press_reasserts_calibration_then_clicks(wired, env_file, device, link):
    write_env(env_file, FB_TRAVEL=74, FB_HOLD=0, FB_MODE=0)
    fb.press(settle=0.5)
    assert device.writes == [(102, 73), (102, 74), (103, 0), (101, 0), (108, True)]
    assert link.closed
    assert wired == [(MAC, fb.BDADDR_LE_PUBLIC, fb.BDADDR_ANY, 30.0)]


def test_press_nudges_up_from_zero(wired, env_file, device):
    write_env(env_file, FB_TRAVEL=0)
    fb.press(settle=0)
    assert device.writes == [(102, 1), (102, 0), (103, 0), (101, 0), (108, True)]


def test_press_without_calibration_just_clicks(wired, device):
    fb.press(settle=0)
    assert device.writes == [(108, True)]


def test_press_refuses_when_calibration_dps_absent(wired, env_file, device, link):
    write_env(env_file, FB_TRAVEL=74)
    del device.dps[103]
    with pytest.raises(fb.Refused, match=r"\[103\]"):
        fb.press()
    assert fb.FUN_SENDER_DPS not in device.codes()
    assert link.closed


def test_press_refuses_protocol_2(wired, device):
    device.protocol = 2
    with pytest.raises(fb.ProtocolError, match="protocol 3"):
        fb.press()
    assert fb.FUN_SENDER_DPS not in device.codes()


def test_write_dp_refuses_unpublished_dp(link, device):
    s = session(link, actuate=True)
    s.login()
    with pytest.raises(fb.Refused, match="dp99"):
        s.write_dp(99, 1)


def test_write_dp_accepts_any_response_like_tuya_ble(link, device):
    s = session(link, actuate=True)
    s.login()
    assert s.write_dp(102, 74) == b"\x00"
    device.dp_result = 1
    assert s.write_dp(102, 74) == b"\x01"
    assert device.writes == [(102, 74), (102, 74)]


def test_press_click_sent_then_failure_is_flagged(wired, device, link):
    device.mute = {fb.FUN_SENDER_DPS}       # click goes out, ack never comes
    with pytest.raises(fb.ClickUnconfirmed, match="click was sent"):
        fb.press(settle=0)
    assert device.codes().count(fb.FUN_SENDER_DPS) == 1
    assert link.closed


def test_press_failure_before_click_is_plain(wired, env_file, device):
    write_env(env_file, FB_TRAVEL=74)
    device.mute = {fb.FUN_SENDER_DPS}       # first calibration write times out
    with pytest.raises(TimeoutError):
        fb.press(settle=0)


def test_press_failure_after_click_without_dps_frame(wired, device, monkeypatch):
    # an error raised before the click frame left: not ClickUnconfirmed
    def boom(self, dp, value):
        raise OSError("link lost")

    monkeypatch.setattr(fb.Session, "write_dp", boom)
    with pytest.raises(OSError, match="link lost"):
        fb.press(settle=0)


def test_stray_frames_dropped_after_login(link, device):
    s = session(link)
    s.login()
    device.keys[1] = bytes(16)
    device.notify(fb.FUN_RECEIVE_DP, b"", security=1)       # we hold no auth key
    device.notify(fb.FUN_RECEIVE_DP, bytes.fromhex("01090100"))  # bad dp type
    s.wait(1)
    assert s.dropped == 2


def test_press_traces(wired, device):
    lines: list[str] = []
    fb.press(settle=0, trace=lines.append)
    assert lines[0].startswith("connected in") and lines[1].startswith("gatt 1910")


def test_calibration_values():
    assert fb._calibration({}) == []
    assert fb._calibration({"FB_TRAVEL": "74"}) == [(102, 73), (102, 74), (103, 0), (101, 0)]
    assert fb._calibration({"FB_TRAVEL": "60", "FB_HOLD": "2", "FB_MODE": "1"}) == [
        (102, 59), (102, 60), (103, 2), (101, 1)]


# --------------------------------------------------------------------------
# _open
# --------------------------------------------------------------------------
def test_open_random_and_adapter(wired, link, monkeypatch, cfg):
    monkeypatch.setattr(fb, "adapter_address", lambda a: "B8:27:EB:7D:EA:7F")
    sock, _att, handles = fb._open({**cfg, "FB_ADDR_TYPE": "random", "FB_ADAPTER": "hci0"},
                                   lambda m: None)
    assert sock is link and handles == fb.Handles(H_WRITE, H_NOTIFY, H_CCCD)
    assert wired[0][1:3] == (fb.BDADDR_LE_RANDOM, "B8:27:EB:7D:EA:7F")


def test_open_bad_addr_type(cfg):
    with pytest.raises(ValueError, match="FB_ADDR_TYPE must be public or random"):
        fb._open({**cfg, "FB_ADDR_TYPE": "weird"}, lambda m: None)


def test_open_closes_socket_on_gatt_failure(wired, link, device, cfg):
    device.gatt_services = []
    with pytest.raises(OSError, match="no GATT service"):
        fb._open(cfg, lambda m: None)
    assert link.closed


# --------------------------------------------------------------------------
# info
# --------------------------------------------------------------------------
def test_info_output_and_redaction(wired, env_file, capsys):
    write_env(env_file, FB_TRAVEL=74, FB_ADDR_TYPE="public")
    fb.info()
    out = capsys.readouterr().out
    assert CONFIG["FB_LOCAL_KEY"] not in out
    assert f"FB_LOCAL_KEY   set ({len(CONFIG['FB_LOCAL_KEY'])} chars)" in out
    for ident in ("FB_UUID", "FB_DEVICE_ID"):
        assert f"{ident:<14} {CONFIG[ident]}\n" in out
    assert "FB_TRAVEL      74" in out
    assert "gatt 1910: write 0x000a notify 0x000c cccd 0x000d" in out
    assert "firmware 1.2, protocol 3.0, hardware 4.5, bound=yes" in out
    assert "frames sent: 0x0000 0x0001 0x0003 0x8001(reply)" in out
    assert "8 datapoints" in out
    assert "dp 108  bool     False  <- click" in out
    assert "dp 102  value    74" in out


def test_info_missing_credentials(wired, env_file, capsys, device):
    env_file(f"FB_MAC={MAC}\n")
    with pytest.raises(SystemExit):
        fb.info()
    out = capsys.readouterr().out
    config = out.split("\nsession")[0]
    assert "FB_LOCAL_KEY   MISSING (0 chars)" in config
    assert "FB_UUID" not in config and "FB_DEVICE_ID" not in config
    assert "FAILED" in out and "KeyError" in out


def test_info_failure_exits_1(wired, device, capsys):
    device.report = False
    with pytest.raises(SystemExit) as e:
        fb.info()
    assert e.value.code == 1
    assert "FAILED after" in capsys.readouterr().out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
@pytest.mark.parametrize("argv", [[], ["press"], ["click"]])
def test_main_press(monkeypatch, capsys, argv):
    calls: list[int] = []
    monkeypatch.setattr(fb, "press", lambda: calls.append(1))
    fb.main(argv)
    assert calls == [1] and capsys.readouterr().out == "clicked\n"


def test_main_click_unconfirmed_exits_3(monkeypatch, capsys):
    def press():
        raise fb.ClickUnconfirmed("dp108 click was SENT")

    monkeypatch.setattr(fb, "press", press)
    with pytest.raises(SystemExit) as e:
        fb.main(["press"])
    assert e.value.code == 3
    captured = capsys.readouterr()
    assert "click was SENT" in captured.err and "clicked" not in captured.out


def test_main_info(monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(fb, "info", lambda: calls.append(1))
    monkeypatch.setattr(sys, "argv", ["fingerbot", "info"])
    fb.main()
    assert calls == [1]


def test_main_usage():
    with pytest.raises(SystemExit, match="usage"):
        fb.main(["bogus"])


def test_runs_as_script(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["fingerbot.py", "bogus"])
    with pytest.raises(SystemExit, match="usage"):
        runpy.run_path(fb.__file__, run_name="__main__")


def test_standalone_copy_runs_and_imports_only_stdlib(tmp_path):
    """Copied alone as fingerbot.py, the file runs as `python3 -I fingerbot.py`
    and pulls in nothing outside the standard library."""
    dst = tmp_path / "fingerbot.py"
    dst.write_bytes(pathlib.Path(fb.__file__).read_bytes())
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "COV_"))}
    run = subprocess.run([sys.executable, "-I", str(dst), "bogus"], capture_output=True,
                         text=True, cwd=tmp_path, env=env)
    assert run.returncode == 1
    assert "usage: fingerbot [press|info]" in run.stderr
    probe = ("import runpy, sys; before = set(sys.modules); "
             f"runpy.run_path({str(dst)!r}, run_name='probe'); "
             "std = getattr(sys, 'stdlib_module_names', None); "
             "print(sorted(m for m in set(sys.modules) - before "
             "if std is not None and m.split('.')[0] not in std))")
    out = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True,
                         text=True, cwd=tmp_path, env=env, check=True).stdout
    assert out.strip() == "[]"


def test_discover_skips_non_cccd_descriptors(link, device):
    device.gatt_services[2] = (0x0008, 0x000E, 0x1910)
    device.gatt_descs = [(0x0007, 0x2902), (0x000D, 0x2901), (0x000E, 0x2902)]
    assert fb.Att(link).discover() == fb.Handles(H_WRITE, H_NOTIFY, 0x000E)


def test_short_sign_time_frame_dropped_after_login(link, device):
    s = session(link)
    s.login()
    device.notify(fb.FUN_RECEIVE_SIGN_TIME_DP, b"\x00\x01\x00")   # no time-type byte
    s.wait(1)
    assert s.dropped == 1


def test_seq_zero_frames_are_not_answered(link, device):
    s = session(link)
    s.login()
    device.seq = -1                      # next frame goes out with seq 0
    device.report_dps([102])
    s.wait(1)
    assert [f for f in device.frames if f.response_to == 0 and f.code & 0x8000] == []
    assert s.dps[102].value == 74


def test_press_interrupt_after_click_is_flagged(wired, device, monkeypatch):
    real_wait = fb.Session.wait

    def wait(self, secs):
        if any(c == fb.FUN_SENDER_DPS for c, _ in self.sent):
            raise KeyboardInterrupt
        real_wait(self, secs)

    monkeypatch.setattr(fb.Session, "wait", wait)
    with pytest.raises(fb.ClickUnconfirmed, match="KeyboardInterrupt"):
        fb.press(settle=0)


@pytest.mark.parametrize("pdu", [b"\x1b", b"\x1b\x0c", b"\x1d\x0c"])
def test_runt_notifications_ignored(link, device, pdu):
    att = fb.Att(link)
    device.outbox.append(pdu)
    assert att.pump(lambda: False, 1) is False


@pytest.mark.parametrize("rsp", [
    b"\x11\x00" + bytes(6),                     # entry size 0
    b"\x11\x04\x08\x00\x0d\x00",                # group entry too short for a uuid
    b"\x09\x03\x09\x00\x04",                    # char entry too short
    b"\x05\x07\x0d\x00\x02\x29",                # find-info: unknown format
])
def test_walk_rejects_malformed_entries(link, device, rsp):
    device.att = lambda pdu: device.outbox.append(rsp)
    with pytest.raises(OSError, match="malformed"):
        fb.Att(link)._walk(rsp[0] - 1, 1, 0xFFFF, b"")


def test_walk_refuses_to_go_backwards(link, device):
    # a group ending before the requested start would loop forever
    device.att = lambda pdu: device.outbox.append(
        b"\x11\x06" + struct.pack("<HHH", 1, 1, 0x1800))
    with pytest.raises(OSError, match="did not advance"):
        fb.Att(link)._walk(fb.ATT_READ_BY_GROUP_REQ, 5, 0xFFFF, b"")


@pytest.mark.parametrize(("extra", "match"), [
    ({"FB_TRAVEL": "101"}, "FB_TRAVEL"), ({"FB_TRAVEL": "-1"}, "FB_TRAVEL"),
    ({"FB_TRAVEL": "74", "FB_HOLD": "-1"}, "FB_HOLD"),
    ({"FB_TRAVEL": "74", "FB_MODE": "300"}, "FB_MODE"),
])
def test_calibration_out_of_range_refused_before_connecting(wired, env_file, extra, match):
    write_env(env_file, **extra)
    with pytest.raises(fb.Refused, match=match):
        fb.press(settle=0)
    assert wired == []
