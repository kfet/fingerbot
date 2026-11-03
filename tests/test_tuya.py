"""Tuya BLE v3 codec: unit tests, and byte-for-byte cross-checks against
tuya-ble (dev-only; skipped where it is not installed, e.g. on 3.9)."""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct

import pytest

import fingerbot as fb

LOCAL_KEY = "0123456789abcdef"
LOGIN = hashlib.md5(b"012345").digest()
SRAND = bytes.fromhex("a1b2c3d4e5f6")
SESSION = hashlib.md5(b"012345" + SRAND).digest()
KEYS = {fb.SECURITY_LOGIN: LOGIN, fb.SECURITY_SESSION: SESSION}
IV = bytes(range(16))


def reassemble(fragments: list[bytes]) -> bytes:
    r = fb.Reassembler()
    out = [r.feed(f) for f in fragments]
    assert out[:-1] == [None] * (len(out) - 1)
    blob = out[-1]
    assert blob is not None
    return blob


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------
def test_crc16_modbus_check_value():
    assert fb.crc16(b"123456789") == 0x4B37


@pytest.mark.parametrize("v", [0, 1, 127, 128, 300, 16383, 16384, 2**21, 2**28 - 1])
def test_varint_roundtrip(v):
    enc = fb.pack_varint(v)
    assert fb.unpack_varint(b"\xaa" + enc + b"\xbb", 1) == (v, 1 + len(enc))


def test_varint_errors():
    with pytest.raises(fb.ProtocolError, match="truncated"):
        fb.unpack_varint(b"\x80", 0)
    with pytest.raises(fb.ProtocolError, match="longer than 4"):
        fb.unpack_varint(b"\x80\x80\x80\x80\x01", 0)


def test_keys():
    assert fb.login_key(LOCAL_KEY) == LOGIN
    assert fb.session_key(LOCAL_KEY, SRAND) == SESSION


def test_pair_payload():
    p = fb.pair_payload("uuid00000000", LOCAL_KEY, "dev0000000000000000000")
    assert p == b"uuid00000000" + b"012345" + b"dev0000000000000000000" + bytes(4)
    assert len(p) == 44


# --------------------------------------------------------------------------
# frames
# --------------------------------------------------------------------------
@pytest.mark.parametrize("size", [0, 1, 3, 20, 44, 100])
def test_frame_roundtrip(size):
    data = os.urandom(size)
    frags = fb.encode_frame(7, fb.FUN_SENDER_PAIR, data, SESSION, fb.SECURITY_SESSION, 3,
                            response_to=5)
    assert all(len(f) <= fb.GATT_MTU for f in frags)
    blob = reassemble(frags)
    assert fb.decode_frame(blob, KEYS) == fb.Frame(7, 5, fb.FUN_SENDER_PAIR, data)


def test_frame_header_bytes():
    frags = fb.encode_frame(1, fb.FUN_SENDER_DEVICE_INFO, b"", LOGIN, fb.SECURITY_LOGIN, 2,
                            iv=IV)
    # fragment 0: num=0, total=1+16+16=33, protocol 2<<4, flag 4, then the IV
    assert frags[0][:4] == bytes([0, 33, 0x20, 4])
    assert frags[0][4:] == IV[:16]
    assert frags[1][0] == 1


def test_frame_random_iv_differs():
    a = fb.encode_frame(1, 0, b"", LOGIN, 4, 3)
    b = fb.encode_frame(1, 0, b"", LOGIN, 4, 3)
    assert a != b


def _blob(raw: bytes, key: bytes = SESSION, flag: int = 5) -> bytes:
    raw += b"\x00" * (-len(raw) % 16)
    return bytes([flag]) + IV + fb.aes_cbc_encrypt(key, IV, raw)


def test_decode_rejects_bad_length():
    with pytest.raises(fb.ProtocolError, match="bad encrypted length"):
        fb.decode_frame(b"\x05" + IV + bytes(15), KEYS)
    with pytest.raises(fb.ProtocolError, match="bad encrypted length"):
        fb.decode_frame(b"\x05" + IV[:10], KEYS)


def test_decode_rejects_unknown_key():
    with pytest.raises(fb.ProtocolError, match="no key for security flag 5"):
        fb.decode_frame(_blob(bytes(16)), {fb.SECURITY_LOGIN: LOGIN})


def test_decode_rejects_overrun():
    raw = struct.pack(">IIHH", 1, 0, 3, 40) + b"x"
    with pytest.raises(fb.ProtocolError, match="overruns"):
        fb.decode_frame(_blob(raw), KEYS)


def test_decode_rejects_bad_crc():
    raw = struct.pack(">IIHH", 1, 0, 3, 1) + b"x"
    raw += struct.pack(">H", fb.crc16(raw) ^ 1)
    with pytest.raises(fb.ProtocolError, match="crc"):
        fb.decode_frame(_blob(raw), KEYS)


def test_decode_rejects_crc_cut_short():
    raw = struct.pack(">IIHH", 1, 0, 3, 3) + b"xyz"   # 15 bytes, 1 byte of slack
    with pytest.raises(fb.ProtocolError, match="crc"):
        fb.decode_frame(_blob(raw), KEYS)


def test_decode_exact_fit_has_no_crc():
    raw = struct.pack(">IIHH", 9, 2, 0x8001, 4) + b"abcd"   # exactly 16
    assert fb.decode_frame(_blob(raw), KEYS) == fb.Frame(9, 2, 0x8001, b"abcd")


def test_wrong_key_is_a_protocol_error():
    frags = fb.encode_frame(1, 3, b"\x00" * 30, SESSION, 5, 3)
    with pytest.raises(fb.ProtocolError):
        fb.decode_frame(reassemble(frags), {5: os.urandom(16)})


# --------------------------------------------------------------------------
# reassembly
# --------------------------------------------------------------------------
def _frags(n_bytes: int = 40) -> list[bytes]:
    return fb.encode_frame(1, 3, bytes(n_bytes), SESSION, 5, 3)


def test_reassembler_drops_stray_continuation():
    r = fb.Reassembler()
    frags = _frags()
    assert r.feed(frags[1]) is None          # no frame 0 yet: dropped
    assert reassemble(frags)


def test_reassembler_restarts_on_new_frame_zero():
    r = fb.Reassembler()
    a, b = _frags(), _frags()
    assert r.feed(a[0]) is None
    for f in b[:-1]:
        assert r.feed(f) is None
    assert fb.decode_frame(r.feed(b[-1]) or b"", KEYS).code == 3


def test_reassembler_drops_gap():
    r = fb.Reassembler()
    frags = _frags()
    assert len(frags) == 5
    assert r.feed(frags[0]) is None
    for f in frags[2:]:                      # skipped 1: nothing completes
        assert r.feed(f) is None


def test_reassembler_drops_overlong():
    r = fb.Reassembler()
    frags = _frags()
    last = frags[-1] + b"extra"
    for f in frags[:-1]:
        r.feed(f)
    assert r.feed(last) is None
    assert reassemble(frags)                 # and a fresh frame still works


# --------------------------------------------------------------------------
# datapoints
# --------------------------------------------------------------------------
DPS_WIRE = bytes.fromhex(
    "01" "01" "01" "00"            # dp1 bool false
    "65" "04" "01" "00"            # dp101 enum 0
    "66" "02" "04" "0000004a"      # dp102 value 74
    "67" "02" "04" "00000000"      # dp103 value 0
    "6c" "01" "01" "01"            # dp108 bool true
    "6f" "02" "04" "ffffffff"      # dp111 value -1
    "70" "03" "02" "6869"          # dp112 string "hi"
    "71" "00" "02" "beef"          # dp113 raw
    "72" "05" "01" "03"            # dp114 bitmap
)


def test_parse_dps():
    assert fb.parse_dps(DPS_WIRE) == [
        (1, fb.DT_BOOL, False), (101, fb.DT_ENUM, 0), (102, fb.DT_VALUE, 74),
        (103, fb.DT_VALUE, 0), (108, fb.DT_BOOL, True), (111, fb.DT_VALUE, -1),
        (112, fb.DT_STRING, "hi"), (113, fb.DT_RAW, b"\xbe\xef"),
        (114, fb.DT_BITMAP, b"\x03"),
    ]


def test_parse_dps_offset_and_trailing_short():
    assert fb.parse_dps(b"\xff\xff" + bytes.fromhex("6c010101") + b"\x00\x00", 2) == [
        (108, fb.DT_BOOL, True)]


def test_parse_dps_errors():
    with pytest.raises(fb.ProtocolError, match="unknown type 9"):
        fb.parse_dps(bytes.fromhex("01090100"))
    with pytest.raises(fb.ProtocolError, match="4 bytes declared, 1 present"):
        fb.parse_dps(bytes.fromhex("66020400"))


def test_encode_dp():
    assert fb.encode_dp(108, fb.DT_BOOL, True) == bytes.fromhex("6c010101")
    assert fb.encode_dp(1, fb.DT_BOOL, False) == bytes.fromhex("01010100")
    assert fb.encode_dp(102, fb.DT_VALUE, 74) == bytes.fromhex("660204" "0000004a")
    assert fb.encode_dp(102, fb.DT_VALUE, -2) == bytes.fromhex("660204" "fffffffe")
    assert fb.encode_dp(101, fb.DT_ENUM, 0) == bytes.fromhex("65040100")
    assert fb.encode_dp(101, fb.DT_ENUM, 0x100) == bytes.fromhex("6504020100")
    assert fb.encode_dp(101, fb.DT_ENUM, 0x10000) == bytes.fromhex("65040400010000")


def test_encode_dp_refusals():
    with pytest.raises(ValueError, match="< 0"):
        fb.encode_dp(101, fb.DT_ENUM, -1)
    with pytest.raises(ValueError, match="refusing to encode type string"):
        fb.encode_dp(5, fb.DT_STRING, 1)


def test_parse_device_info():
    data = bytes([1, 2, 3, 0, 0x7, 1]) + SRAND + bytes([4, 5]) + bytes(range(32))
    info = fb.parse_device_info(data)
    assert info == fb.DeviceInfo("1.2", 3, "3.0", "4.5", 7, True, SRAND, bytes(range(32)))
    assert not fb.parse_device_info(data[:5] + b"\x00" + data[6:]).bound
    with pytest.raises(fb.ProtocolError, match="45 bytes"):
        fb.parse_device_info(data[:45])


# --------------------------------------------------------------------------
# cross-checks against tuya-ble (the reference implementation)
# --------------------------------------------------------------------------
@pytest.fixture
def ref(monkeypatch):
    """A real tuya_ble.TuyaBLE with keys installed and a fixed IV."""
    tb = pytest.importorskip("tuya_ble.tuya_ble")
    device = pytest.importorskip("bleak.backends.device")

    dev = tb.TuyaBLE(None, device.BLEDevice("AA:BB:CC:11:22:33", "x", {}))
    dev._local_key = LOCAL_KEY[:6].encode()
    dev._login_key = LOGIN
    dev._session_key = SESSION
    monkeypatch.setattr(tb.secrets, "token_bytes", lambda n: IV)
    return tb, dev


@pytest.mark.parametrize(("code", "data", "proto", "response_to"), [
    (0x0000, b"", 2, 0),
    (0x0001, fb.pair_payload("uuid00000000", LOCAL_KEY, "deviceid0000"), 3, 0),
    (0x0003, b"", 3, 0),
    (0x0002, fb.encode_dp(102, fb.DT_VALUE, 74) + fb.encode_dp(108, fb.DT_BOOL, True), 3, 0),
    (0x8001, b"", 3, 12),
])
def test_build_matches_tuya_ble(ref, code, data, proto, response_to):
    tb, dev = ref
    dev._protocol_version = proto
    want = dev._build_packets(42, tb.TuyaBLECode(code), data, response_to)
    flag = fb.SECURITY_LOGIN if code == 0 else fb.SECURITY_SESSION
    got = fb.encode_frame(42, code, data, KEYS[flag], flag, proto, response_to, iv=IV)
    assert [bytes(p) for p in want] == got


def test_decode_what_tuya_ble_builds(ref):
    tb, dev = ref
    dev._protocol_version = 3
    data = os.urandom(57)
    pkts = dev._build_packets(77, tb.TuyaBLECode.FUN_SENDER_DPS, data, 3)
    assert fb.decode_frame(reassemble([bytes(p) for p in pkts]), KEYS) == fb.Frame(
        77, 3, fb.FUN_SENDER_DPS, data)


def test_tuya_ble_parses_what_we_build(ref):
    """Feed our fragments to tuya-ble's notification handler: a device-info
    response, which it fully decodes into session keys without any I/O."""
    _tb, dev = ref
    info = bytes([1, 2, 3, 0, 0, 1]) + bytes.fromhex("0f0e0d0c0b0a") + bytes([4, 5]) + bytes(32)
    for frag in fb.encode_frame(1, 0, info, LOGIN, 4, 3, response_to=0):
        dev._notification_handler(0, bytearray(frag))
    assert dev._protocol_version == 3
    assert dev._session_key == fb.session_key(LOCAL_KEY, bytes.fromhex("0f0e0d0c0b0a"))
    assert fb.parse_device_info(info).srand == bytes.fromhex("0f0e0d0c0b0a")


def test_dps_parse_matches_tuya_ble(ref):
    _tb, dev = ref
    dev._parse_datapoints_v3(0.0, 0, DPS_WIRE, 0)
    theirs = {i: (p.type.value, p.value) for i, p in dev.datapoints._datapoints.items()}
    ours = {i: (t, v) for i, t, v in fb.parse_dps(DPS_WIRE)}
    assert ours == theirs


@pytest.mark.parametrize(("dtype", "value"), [
    (fb.DT_BOOL, True), (fb.DT_BOOL, False), (fb.DT_VALUE, 74), (fb.DT_VALUE, -5),
    (fb.DT_ENUM, 0), (fb.DT_ENUM, 3), (fb.DT_ENUM, 0x1234), (fb.DT_ENUM, 0x12345),
])
def test_dp_encode_matches_tuya_ble(ref, dtype, value):
    _tb, dev = ref
    sent: list[bytes] = []

    async def capture(code, data, *a, **k):
        sent.append(bytes(data))

    dev._send_packet = capture
    dev._protocol_version = 3
    dev._parse_datapoints_v3(0.0, 0, bytes([9, dtype, 1, 0]), 0)
    async def go():
        dev.datapoints[9].value = value
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    asyncio.run(go())
    assert sent == [fb.encode_dp(9, dtype, value)]


def test_decode_rejects_iv_only_blob():
    with pytest.raises(fb.ProtocolError, match="bad encrypted length 17"):
        fb.decode_frame(b"\x05" + IV, KEYS)
