#!/usr/bin/env python3
"""Press a Tuya Fingerbot (Fingerbot Plus / ADFBB521) over BLE.

One file, standard library only, Python 3.9+. Copy it to a box together
with its credentials file and run it with python3: no pip, no BlueZ D-Bus,
no third-party packages.

How, in four layers, each measured against real hardware:

  * transport -- an L2CAP socket on the LE ATT fixed channel (CID 4),
    connected through libc via ctypes, because CPython's L2CAP address
    tuple cannot carry the channel id or the LE address type. The kernel
    does the passive scan and LE connection itself, so there is nothing to
    arbitrate with bluetoothd or other BLE users: no discovery, no D-Bus
    object path to go stale. No root needed.
  * GATT -- a minimal ATT client finds service 1910, the 2b11 command
    characteristic (write without response) and 2b10 (notify).
  * crypto -- AES-128-CBC in pure Python; Tuya encrypts at the application
    layer with local_key, which is also why the device never bonds.
  * Tuya BLE protocol v3 -- device info, pair, status, datapoint reports.
    dp108 is the momentary click: one write, one actuation. dp1 is the
    latching switch state; writing it actuates twice.

Safety: only `press` can construct a session that may send a datapoint
write (FUN_SENDER_DPS). Every other code path, `info` included, gets a
read-only session whose send function refuses that code outright.

Usage:
    fingerbot          click once
    fingerbot info     read-only diagnostics: config, connect, datapoints
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import os
import secrets
import select
import socket
import struct
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple, Protocol

DP_CLICK = 108
# Calibration, re-written before every click (see _calibration).
DP_MODE = 101    # 0 = click
DP_TRAVEL = 102  # down travel %, = the app's "Downward movement"
DP_HOLD = 103    # sustain; >0 can park the arm on the button

# Progress reporting: `info` prints these, `press` discards them.
Trace = Callable[[str], None]


class Refused(RuntimeError):
    """The action declined to run. Not a connection fault: never retried."""


class ClickUnconfirmed(RuntimeError):
    """The click frame went out but the session then failed. The arm may
    have moved: check the host before pressing again."""


def _now() -> float:
    return time.monotonic()


# --------------------------------------------------------------------------
# AES-128, pure Python (FIPS-197), CBC mode (SP 800-38A). No padding: Tuya
# zero-pads to the block size itself. Speed is irrelevant -- a session moves
# a few dozen blocks -- so this favours being obviously the textbook cipher.
# --------------------------------------------------------------------------
def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _gmul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


def _make_sbox() -> tuple[bytes, bytes]:
    """S-box from its definition: multiplicative inverse in GF(2^8), then
    the affine map. Walks the field with generator 3 (p) and its inverse (q)."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ _xtime(p)                            # p *= 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:                                 # q /= 3
            q ^= 0x09
        rot = [((q << k) | (q >> (8 - k))) & 0xFF for k in range(1, 5)]
        sbox[p] = q ^ rot[0] ^ rot[1] ^ rot[2] ^ rot[3] ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, s in enumerate(sbox):
        inv[s] = i
    return bytes(sbox), bytes(inv)


_SBOX, _INV_SBOX = _make_sbox()
# ShiftRows on the column-major state: out[i] = in[_SHIFT[i]].
_SHIFT = [(r + 4 * ((c + r) % 4)) for c in range(4) for r in range(4)]
_INV_SHIFT = [(r + 4 * ((c - r) % 4)) for c in range(4) for r in range(4)]


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], t)])
    return [[b for w in words[4 * r:4 * r + 4] for b in w] for r in range(11)]


_MIX = (2, 3, 1, 1)
_INV_MIX = (14, 11, 13, 9)
# Multiplication tables for the MixColumns coefficients: an armv6 Pi spends
# most of a session in _gmul otherwise.
_MUL = {m: bytes(_gmul(a, m) for a in range(256)) for m in (1, 2, 3, 9, 11, 13, 14)}


def _mix(s: list[int], m: tuple[int, int, int, int]) -> list[int]:
    t = [_MUL[m[k]] for k in range(4)]
    out = [0] * 16
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c:c + 4]
        for r in range(4):
            out[c + r] = (t[(0 - r) % 4][a0] ^ t[(1 - r) % 4][a1]
                          ^ t[(2 - r) % 4][a2] ^ t[(3 - r) % 4][a3])
    return out


def _encrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 11):
        s = [_SBOX[s[i]] for i in _SHIFT]
        if r != 10:
            s = _mix(s, _MIX)
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def _decrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[10])]
    for r in range(9, -1, -1):
        s = [_INV_SBOX[s[i]] for i in _INV_SHIFT]
        s = [b ^ k for b, k in zip(s, rk[r])]
        if r != 0:
            s = _mix(s, _INV_MIX)
    return bytes(s)


def _check_cbc(iv: bytes, data: bytes) -> None:
    if len(iv) != 16:
        raise ValueError(f"CBC IV must be 16 bytes, got {len(iv)}")
    if len(data) % 16:
        raise ValueError(f"CBC data must be a multiple of 16 bytes, got {len(data)}")


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    _check_cbc(iv, data)
    rk = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        prev = _encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return bytes(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    _check_cbc(iv, data)
    rk = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(rk, block), prev))
        prev = block
    return bytes(out)


# --------------------------------------------------------------------------
# Tuya BLE protocol v3 -- the subset this tool uses.
#
# A frame is: seq u32 | response_to u32 | code u16 | len u16 | data | crc16,
# zero-padded to 16, AES-128-CBC encrypted, prefixed with a security flag
# byte (4 = login key, 5 = session key) and the 16-byte IV, then cut into
# 20-byte GATT writes. Each fragment starts with a varint fragment number;
# fragment 0 also carries the varint total length and a protocol byte.
# Wire-compatible with tuya-ble (PlusPlus-ua/ha_tuya_ble); the dev test
# suite cross-checks it byte-for-byte.
# --------------------------------------------------------------------------
GATT_MTU = 20

FUN_SENDER_DEVICE_INFO = 0x0000
FUN_SENDER_PAIR = 0x0001
FUN_SENDER_DPS = 0x0002            # the only code that moves the arm
FUN_SENDER_DEVICE_STATUS = 0x0003
FUN_RECEIVE_DP = 0x8001
FUN_RECEIVE_TIME_DP = 0x8003
FUN_RECEIVE_SIGN_DP = 0x8004
FUN_RECEIVE_SIGN_TIME_DP = 0x8005
FUN_RECEIVE_TIME1_REQ = 0x8011
FUN_RECEIVE_TIME2_REQ = 0x8012

SECURITY_LOGIN = 4    # key = md5(local_key[:6])
SECURITY_SESSION = 5  # key = md5(local_key[:6] + srand)

DT_RAW, DT_BOOL, DT_VALUE, DT_STRING, DT_ENUM, DT_BITMAP = range(6)
DT_NAMES = ("raw", "bool", "value", "string", "enum", "bitmap")


class ProtocolError(ValueError):
    """A frame that does not parse, decrypt or checksum."""


class Frame(NamedTuple):
    seq: int
    response_to: int
    code: int
    data: bytes


def crc16(data: bytes) -> int:
    """CRC-16/MODBUS, as Tuya uses it."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def pack_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def unpack_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    for offset in range(4):
        if pos + offset >= len(data):
            raise ProtocolError("truncated varint")
        byte = data[pos + offset]
        result |= (byte & 0x7F) << (7 * offset)
        if not byte & 0x80:
            return result, pos + offset + 1
    raise ProtocolError("varint longer than 4 bytes")


def login_key(local_key: str) -> bytes:
    return hashlib.md5(local_key[:6].encode()).digest()


def session_key(local_key: str, srand: bytes) -> bytes:
    return hashlib.md5(local_key[:6].encode() + srand).digest()


def encode_frame(seq: int, code: int, data: bytes, key: bytes, security: int,
                 protocol: int, response_to: int = 0,
                 iv: bytes | None = None) -> list[bytes]:
    """One Tuya frame -> the list of <=20-byte GATT writes that carry it."""
    raw = struct.pack(">IIHH", seq, response_to, code, len(data)) + data
    raw += struct.pack(">H", crc16(raw))
    raw += b"\x00" * (-len(raw) % 16)
    iv = secrets.token_bytes(16) if iv is None else iv
    blob = bytes([security]) + iv + aes_cbc_encrypt(key, iv, raw)
    out: list[bytes] = []
    pos = 0
    while pos < len(blob):
        head = pack_varint(len(out))
        if not out:
            head += pack_varint(len(blob)) + bytes([protocol << 4])
        chunk = blob[pos:pos + GATT_MTU - len(head)]
        out.append(head + chunk)
        pos += len(chunk)
    return out


def decode_frame(blob: bytes, keys: dict[int, bytes]) -> Frame:
    """Reassembled notification bytes -> Frame. `keys` maps security flag
    to key; a flag with no key yet is a protocol error."""
    if len(blob) < 33 or (len(blob) - 17) % 16:
        raise ProtocolError(f"bad encrypted length {len(blob)}")
    key = keys.get(blob[0])
    if key is None:
        raise ProtocolError(f"no key for security flag {blob[0]}")
    raw = aes_cbc_decrypt(key, blob[1:17], blob[17:])
    seq, response_to, code, length = struct.unpack(">IIHH", raw[:12])
    end = 12 + length
    if end > len(raw):
        raise ProtocolError(f"frame length {length} overruns {len(raw)} bytes "
                            "(wrong local_key?)")
    if end < len(raw):
        if end + 2 > len(raw) or crc16(raw[:end]) != struct.unpack(">H", raw[end:end + 2])[0]:
            raise ProtocolError("crc mismatch (wrong local_key?)")
    return Frame(seq, response_to, code, raw[12:end])


class Reassembler:
    """Collects 2b10 notifications into whole encrypted frames."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._want = 0
        self._next = 0

    def _reset(self) -> None:
        self.__init__()

    def feed(self, fragment: bytes) -> bytes | None:
        """Add one notification. Returns a complete frame blob, or None.
        Out-of-order or overlong input drops the partial frame."""
        num, pos = unpack_varint(fragment, 0)
        if num != self._next:
            self._reset()
            if num != 0:
                return None
        if num == 0:
            self._want, pos = unpack_varint(fragment, pos)
            pos += 1                                 # protocol byte
            self._buf = bytearray()
        self._buf += fragment[pos:]
        self._next += 1
        if len(self._buf) < self._want:
            return None
        blob, ok = bytes(self._buf), len(self._buf) == self._want
        self._reset()
        return blob if ok else None


def parse_dps(data: bytes, pos: int = 0) -> list[tuple[int, int, object]]:
    """v3 datapoint list -> [(dp, type, value)]."""
    out: list[tuple[int, int, object]] = []
    while len(data) - pos >= 4:
        dp, dtype, size = data[pos], data[pos + 1], data[pos + 2]
        if dtype > DT_BITMAP:
            raise ProtocolError(f"dp{dp}: unknown type {dtype}")
        pos += 3
        raw = data[pos:pos + size]
        if len(raw) != size:
            raise ProtocolError(f"dp{dp}: {size} bytes declared, {len(raw)} present")
        value: object
        if dtype == DT_BOOL:
            value = int.from_bytes(raw, "big") != 0
        elif dtype in (DT_VALUE, DT_ENUM):
            value = int.from_bytes(raw, "big", signed=True)
        elif dtype == DT_STRING:
            value = raw.decode()
        else:
            value = bytes(raw)
        out.append((dp, dtype, value))
        pos += size
    return out


def encode_dp(dp: int, dtype: int, value: int) -> bytes:
    """One v3 datapoint write, encoded as the device reported its type."""
    if dtype == DT_BOOL:
        raw = b"\x01" if value else b"\x00"
    elif dtype == DT_VALUE:
        raw = struct.pack(">i", value)
    elif dtype == DT_ENUM:
        if value < 0:
            raise ValueError(f"dp{dp}: enum value {value} < 0")
        raw = struct.pack(">I" if value > 0xFFFF else ">H" if value > 0xFF else ">B", value)
    else:
        raise ValueError(f"dp{dp}: refusing to encode type {DT_NAMES[dtype]}")
    return bytes([dp, dtype, len(raw)]) + raw


class DeviceInfo(NamedTuple):
    device_version: str
    protocol_version: int
    protocol_str: str
    hardware_version: str
    flags: int
    bound: bool
    srand: bytes
    auth_key: bytes


def parse_device_info(data: bytes) -> DeviceInfo:
    if len(data) < 46:
        raise ProtocolError(f"device info is {len(data)} bytes, need 46")
    return DeviceInfo(f"{data[0]}.{data[1]}", data[2], f"{data[2]}.{data[3]}",
                      f"{data[12]}.{data[13]}", data[4], data[5] != 0,
                      bytes(data[6:12]), bytes(data[14:46]))


def pair_payload(uuid: str, local_key: str, device_id: str) -> bytes:
    data = uuid.encode() + local_key[:6].encode() + device_id.encode()
    return data + b"\x00" * (44 - len(data))


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def _env_path() -> Path:
    """Path to the credentials file: $FINGERBOT_ENV, else the XDG default."""
    return Path(os.environ.get("FINGERBOT_ENV")
                or Path.home() / ".config" / "fingerbot" / "device.env")


def _config() -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in
        (raw.strip() for raw in _env_path().read_text().splitlines())
        if line and not line.startswith("#") and "=" in line
    )


# --------------------------------------------------------------------------
# Transport: LE L2CAP on the ATT fixed channel, via libc.
# --------------------------------------------------------------------------
AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0
BTPROTO_HCI = 1
ATT_CID = 4
BDADDR_LE_PUBLIC = 1
BDADDR_LE_RANDOM = 2
SOL_BLUETOOTH = 274
BT_SECURITY = 4
BT_SECURITY_LOW = 1
HCIGETDEVINFO = 0x800448D3       # _IOR('H', 211, int)
BDADDR_ANY = "00:00:00:00:00:00"

# struct sockaddr_l2 {sa_family_t family; __le16 psm; bdaddr_t bdaddr;
#                     __le16 cid; u8 bdaddr_type} + 1 pad byte = 14 bytes.
# family is host order, psm/cid little-endian.
_SOCKADDR_L2 = struct.Struct("<H6sHBx")


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _bdaddr(mac: str) -> bytes:
    raw = bytes(int(b, 16) for b in mac.split(":"))
    if len(raw) != 6:
        raise ValueError(f"not a Bluetooth address: {mac!r}")
    return raw[::-1]


def sockaddr_l2(mac: str, addr_type: int) -> bytes:
    return struct.pack("=H", AF_BLUETOOTH) + _SOCKADDR_L2.pack(0, _bdaddr(mac), ATT_CID,
                                                                addr_type)


def adapter_address(adapter: str) -> str:
    """'hci0' -> its BD address, via the HCIGETDEVINFO ioctl (no root)."""
    if not adapter.startswith("hci") or not adapter[3:].isdigit():
        raise ValueError(f"FB_ADAPTER must look like hci0, got {adapter!r}")
    buf = bytearray(128)
    struct.pack_into("=H", buf, 0, int(adapter[3:]))   # hci_dev_info.dev_id, host order
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
    try:
        fcntl.ioctl(s.fileno(), HCIGETDEVINFO, buf)
    finally:
        s.close()
    return ":".join(f"{b:02X}" for b in reversed(buf[10:16]))


def _libc_call(fn: Callable[..., int], sock: socket.socket, addr: bytes, what: str,
               ok: tuple[int, ...] = ()) -> int:
    if fn(sock.fileno(), ctypes.c_char_p(addr), len(addr)) == 0:
        return 0
    err = ctypes.get_errno()
    if err in ok:
        return err
    raise OSError(err, f"{what}: {os.strerror(err)}")


def att_connect(mac: str, addr_type: int, local: str, timeout: float) -> socket.socket:
    """Connect an LE ATT socket (CID 4) to `mac`. Blocks at most `timeout`."""
    libc = _libc()
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    try:
        _libc_call(libc.bind, s, sockaddr_l2(local, BDADDR_LE_PUBLIC), "bind")
        s.setsockopt(SOL_BLUETOOTH, BT_SECURITY, struct.pack("<BB", BT_SECURITY_LOW, 0))
        s.setblocking(False)
        if _libc_call(libc.connect, s, sockaddr_l2(mac, addr_type), "connect",
                      ok=(errno.EINPROGRESS, errno.EAGAIN)):
            poller = select.poll()
            poller.register(s.fileno(), select.POLLOUT)
            if not poller.poll(max(0, int(timeout * 1000))):
                raise TimeoutError(f"LE connect to {mac} timed out after {timeout:.0f}s")
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err:
                raise OSError(err, f"connect: {os.strerror(err)}")
        s.setblocking(True)
        return s
    except BaseException:
        s.close()
        raise


# --------------------------------------------------------------------------
# ATT client: just enough GATT to find 1910/2b10/2b11 and enable notify.
# --------------------------------------------------------------------------
ATT_ERROR_RSP = 0x01
ATT_MTU_REQ, ATT_MTU_RSP = 0x02, 0x03
ATT_FIND_INFO_REQ = 0x04
ATT_READ_BY_TYPE_REQ = 0x08
ATT_READ_BY_GROUP_REQ = 0x10
ATT_WRITE_REQ, ATT_WRITE_RSP = 0x12, 0x13
ATT_NOTIFY, ATT_INDICATE, ATT_CONFIRM = 0x1B, 0x1D, 0x1E
ATT_WRITE_CMD = 0x52
ATT_NOT_FOUND = 0x0A
ATT_REQ_NOT_SUPPORTED = 0x06

# Smallest legal entry per discovery op: handles plus a 16-bit UUID.
_MIN_ENTRY = {ATT_READ_BY_GROUP_REQ: 6, ATT_READ_BY_TYPE_REQ: 7, ATT_FIND_INFO_REQ: 4}

SVC_TUYA = "1910"
CHR_WRITE = "2b11"
CHR_NOTIFY = "2b10"
DSC_CCCD = "2902"


class Handles(NamedTuple):
    write: int
    notify: int
    cccd: int


def uuid_str(raw: bytes) -> str:
    """ATT little-endian UUID -> '1910' for SIG-base UUIDs, else dashed form."""
    u = raw[::-1].hex()
    if len(raw) == 2:
        return u
    if u.startswith("0000") and u.endswith("00001000800000805f9b34fb"):
        return u[4:8]
    return f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}"


class Link(Protocol):
    """What Att needs of its socket. A connected L2CAP socket.socket fits."""

    def send(self, data: bytes, /) -> int: ...
    def recv(self, bufsize: int, /) -> bytes: ...
    def settimeout(self, value: float | None, /) -> None: ...


class Att:
    """Minimal synchronous ATT client: one outstanding request at a time.

    Inbound notifications are handed to `on_notify` as they arrive, whether
    we are waiting on a response or just pumping. Requests the peer makes
    of *our* (empty) GATT server are answered so its ATT bearer never stalls.
    """

    def __init__(self, sock: Link, timeout: float = 10.0) -> None:
        self.sock = sock
        self.timeout = timeout
        self.on_notify: Callable[[int, bytes], None] = lambda _h, _v: None

    def _recv(self, deadline: float) -> bytes | None:
        remaining = deadline - _now()
        if remaining <= 0:
            return None
        self.sock.settimeout(remaining)
        try:
            return self.sock.recv(512)
        except (TimeoutError, socket.timeout):
            return None

    def _serve(self, pdu: bytes) -> bool:
        """Handle a PDU the peer initiated. True if it was one."""
        op = pdu[0]
        if op in (ATT_NOTIFY, ATT_INDICATE):
            if len(pdu) < 3:
                return True            # runt: nothing to deliver
            if op == ATT_INDICATE:
                self.sock.send(bytes([ATT_CONFIRM]))
            self.on_notify(struct.unpack_from("<H", pdu, 1)[0], bytes(pdu[3:]))
            return True
        if op == ATT_MTU_REQ:
            self.sock.send(struct.pack("<BH", ATT_MTU_RSP, 23))
            return True
        if op < 0x40 and op % 2 == 0 and op != ATT_CONFIRM:
            self.sock.send(struct.pack("<BBHB", ATT_ERROR_RSP, op, 0, ATT_REQ_NOT_SUPPORTED))
            return True
        return op & 0x40 != 0          # a peer command: ignore it

    def request(self, pdu: bytes) -> bytes:
        self.sock.send(pdu)
        deadline = _now() + self.timeout
        while True:
            rsp = self._recv(deadline)
            if rsp is None:
                raise TimeoutError(f"ATT request 0x{pdu[0]:02x}: no response")
            if rsp and not self._serve(rsp):
                return rsp

    def pump(self, until: Callable[[], bool], timeout: float) -> bool:
        """Process inbound PDUs until `until()` holds (True) or time runs out."""
        deadline = _now() + timeout
        while not until():
            pdu = self._recv(deadline)
            if pdu is None:
                return False
            if pdu:
                self._serve(pdu)
        return True

    def write_command(self, handle: int, value: bytes) -> None:
        self.sock.send(struct.pack("<BH", ATT_WRITE_CMD, handle) + value)

    def write_request(self, handle: int, value: bytes) -> None:
        rsp = self.request(struct.pack("<BH", ATT_WRITE_REQ, handle) + value)
        if rsp[0] != ATT_WRITE_RSP:
            raise OSError(f"ATT write to 0x{handle:04x} failed: {rsp.hex()}")

    def _walk(self, op: int, start: int, end: int, tail: bytes) -> list[bytes]:
        """Run a Read-By-Group-Type / Read-By-Type / Find-Information loop."""
        out: list[bytes] = []
        while start <= end:
            rsp = self.request(struct.pack("<BHH", op, start, end) + tail)
            if rsp[0] == ATT_ERROR_RSP:
                if len(rsp) >= 5 and rsp[4] == ATT_NOT_FOUND:
                    break
                raise OSError(f"ATT op 0x{op:02x} failed: {rsp.hex()}")
            if rsp[0] != op + 1 or len(rsp) < 2:
                raise OSError(f"ATT op 0x{op:02x}: unexpected {rsp.hex()}")
            size = {1: 4, 2: 18}.get(rsp[1], 0) if op == ATT_FIND_INFO_REQ else rsp[1]
            if size < _MIN_ENTRY[op]:
                raise OSError(f"ATT op 0x{op:02x}: malformed {rsp.hex()}")
            entries = [rsp[i:i + size] for i in range(2, len(rsp) - size + 1, size)]
            if not entries:
                raise OSError(f"ATT op 0x{op:02x}: empty response")
            out.extend(entries)
            # group responses end with the group's end handle; the others
            # lead with the attribute handle.
            last = struct.unpack_from("<H", entries[-1], 2 if op == ATT_READ_BY_GROUP_REQ else 0)[0]
            if last < start:
                raise OSError(f"ATT op 0x{op:02x}: handle 0x{last:04x} did not advance "
                              f"past 0x{start:04x}")
            start = last + 1
        return out

    def discover(self) -> Handles:
        for e in self._walk(ATT_READ_BY_GROUP_REQ, 1, 0xFFFF, struct.pack("<H", 0x2800)):
            if uuid_str(e[4:]) != SVC_TUYA:
                continue
            s_start, s_end = struct.unpack_from("<HH", e)
            chars = [(struct.unpack_from("<H", c)[0], struct.unpack_from("<H", c, 3)[0],
                      uuid_str(c[5:]))
                     for c in self._walk(ATT_READ_BY_TYPE_REQ, s_start, s_end,
                                         struct.pack("<H", 0x2803))]
            found: dict[str, int] = {}
            cccd = 0
            for i, (_decl, value, uuid) in enumerate(chars):
                found[uuid] = value
                if uuid == CHR_NOTIFY:
                    last = chars[i + 1][0] - 1 if i + 1 < len(chars) else s_end
                    for d in self._walk(ATT_FIND_INFO_REQ, value + 1, last, b""):
                        if uuid_str(d[2:]) == DSC_CCCD:
                            cccd = struct.unpack_from("<H", d)[0]
            if CHR_WRITE not in found or CHR_NOTIFY not in found or not cccd:
                raise OSError(f"service {SVC_TUYA} lacks {CHR_WRITE}/{CHR_NOTIFY}/CCCD: "
                              f"{sorted(found)} cccd={cccd}")
            return Handles(found[CHR_WRITE], found[CHR_NOTIFY], cccd)
        raise OSError(f"no GATT service {SVC_TUYA} -- not a Tuya BLE device?")


# --------------------------------------------------------------------------
# Tuya session
# --------------------------------------------------------------------------
# Codes a read-only session may originate: the login handshake and the
# status query that makes the device report its datapoints.
_READ_ONLY_CODES = frozenset({FUN_SENDER_DEVICE_INFO, FUN_SENDER_PAIR, FUN_SENDER_DEVICE_STATUS})
# Device-initiated codes we answer (acks / clock replies). Only ever sent
# with response_to set, i.e. as replies.
_REPLY_CODES = frozenset({FUN_RECEIVE_DP, FUN_RECEIVE_TIME_DP, FUN_RECEIVE_SIGN_DP,
                          FUN_RECEIVE_SIGN_TIME_DP, FUN_RECEIVE_TIME1_REQ,
                          FUN_RECEIVE_TIME2_REQ})


class ReadOnlyViolation(PermissionError):
    """A read-only session was asked to send something that could actuate."""


class Datapoint(NamedTuple):
    type: int
    value: object


class Session:
    """A Tuya BLE v3 session over an ATT link.

    `actuate=False` (the default) makes the session read-only: `_send`
    refuses FUN_SENDER_DPS -- the one code that moves the arm -- and every
    other code not on the read-only allow-list. Only `press()` passes
    actuate=True; a test pins that down.
    """

    def __init__(self, att: Att, handles: Handles, cfg: dict[str, str], *,
                 actuate: bool = False) -> None:
        self._att = att
        self._handles = handles
        self._actuate = actuate
        self._local_key = cfg["FB_LOCAL_KEY"]
        self._uuid = cfg["FB_UUID"]
        self._device_id = cfg["FB_DEVICE_ID"]
        self._keys = {SECURITY_LOGIN: login_key(self._local_key)}
        self._seq = 1
        self._protocol = 2             # what tuya-ble assumes until device info says
        self._reasm = Reassembler()
        self._responses: dict[int, Frame] = {}
        self.dps: dict[int, Datapoint] = {}
        self.info: DeviceInfo | None = None
        self.sent: list[tuple[int, int]] = []   # (code, response_to), for audit
        # Strict until logged in, so a wrong local_key fails loudly; after
        # that a stray undecodable frame is dropped rather than aborting a
        # press half way through its calibration writes.
        self.strict = True
        self.dropped = 0
        att.on_notify = self._on_notify

    # -- the one choke point every outbound Tuya frame passes through -----
    def _send(self, code: int, data: bytes, response_to: int = 0) -> int:
        if response_to:
            allowed = code in _REPLY_CODES
        elif code == FUN_SENDER_DPS:
            allowed = self._actuate
        else:
            allowed = code in _READ_ONLY_CODES
        if not allowed:
            raise ReadOnlyViolation(
                f"refusing to send Tuya code 0x{code:04x} (response_to={response_to}) "
                f"on a {'press' if self._actuate else 'read-only'} session")
        if code == FUN_SENDER_DEVICE_INFO:
            security = SECURITY_LOGIN
        elif SECURITY_SESSION in self._keys:
            security = SECURITY_SESSION
        else:
            raise ProtocolError(f"code 0x{code:04x} needs the session key; no device info yet")
        seq = self._seq
        self._seq += 1
        self.sent.append((code, response_to))
        for frag in encode_frame(seq, code, data, self._keys[security], security,
                                 self._protocol, response_to):
            self._att.write_command(self._handles.write, frag)
        return seq

    def request(self, code: int, data: bytes, timeout: float = 10.0) -> Frame:
        seq = self._send(code, data)
        if not self._att.pump(lambda: seq in self._responses, timeout):
            raise TimeoutError(f"no response to Tuya code 0x{code:04x} in {timeout:.0f}s")
        return self._responses.pop(seq)

    def wait(self, secs: float) -> None:
        """Let `secs` pass while servicing the link (acks, datapoint reports)."""
        self._att.pump(lambda: False, secs)

    # -- inbound ----------------------------------------------------------
    def _on_notify(self, handle: int, value: bytes) -> None:
        if handle != self._handles.notify:
            return
        blob = self._reasm.feed(value)
        if blob is None:
            return
        try:
            self._handle(decode_frame(blob, self._keys))
        except (ProtocolError, struct.error):
            if self.strict:
                raise
            self.dropped += 1

    def _store(self, data: bytes, pos: int) -> None:
        for dp, dtype, value in parse_dps(data, pos):
            self.dps[dp] = Datapoint(dtype, value)

    def _reply(self, frame: Frame, data: bytes) -> None:
        """Answer a device-initiated frame. A frame with seq 0 cannot be
        answered (response_to 0 means "not a reply"), so it is not."""
        if frame.seq:
            self._send(frame.code, data, frame.seq)

    def _handle(self, frame: Frame) -> None:
        code, data = frame.code, frame.data
        if code == FUN_SENDER_DEVICE_INFO:
            self.info = parse_device_info(data)
            self._protocol = self.info.protocol_version
            self._keys[SECURITY_SESSION] = session_key(self._local_key, self.info.srand)
        elif code == FUN_RECEIVE_DP:
            self._store(data, 0)
            self._reply(frame, b"")
        elif code == FUN_RECEIVE_TIME_DP:
            self._store(data, 1 + (13 if data[:1] == b"\x00" else 4))
            self._reply(frame, b"")
        elif code in (FUN_RECEIVE_SIGN_DP, FUN_RECEIVE_SIGN_TIME_DP):
            dp_seq, flags = struct.unpack_from(">HB", data)
            pos = 3
            if code == FUN_RECEIVE_SIGN_TIME_DP:
                if len(data) < 4:
                    raise ProtocolError("signed time dp frame without a time")
                pos += 1 + (13 if data[3] == 0 else 4)
            self._store(data, pos)
            self._reply(frame, struct.pack(">HBB", dp_seq, flags, 0))
        elif code == FUN_RECEIVE_TIME1_REQ:
            tz = -int(time.timezone / 36)
            self._reply(frame, str(int(time.time() * 1000)).encode() + struct.pack(">h", tz))
        elif code == FUN_RECEIVE_TIME2_REQ:
            t = time.localtime()
            self._reply(frame, struct.pack(">BBBBBBBh", t.tm_year % 100, t.tm_mon, t.tm_mday,
                                           t.tm_hour, t.tm_min, t.tm_sec, t.tm_wday,
                                           -int(time.timezone / 36)))
        if frame.response_to:
            self._responses[frame.response_to] = frame

    # -- the handshake, then the one write path ---------------------------
    @staticmethod
    def _result(frame: Frame, what: str, ok: tuple[int, ...] = (0,)) -> int:
        if len(frame.data) != 1 or frame.data[0] not in ok:
            raise ProtocolError(f"{what} failed: {frame.data.hex() or 'empty'}")
        return frame.data[0]

    def login(self, dp_timeout: float = 20.0) -> None:
        """Device info -> session key, pair (log in), ask for status, and
        wait until the click datapoint has been reported."""
        self.request(FUN_SENDER_DEVICE_INFO, b"")
        if self.info is None:
            raise ProtocolError("device info response carried no device info")
        self._result(self.request(FUN_SENDER_PAIR, pair_payload(
            self._uuid, self._local_key, self._device_id)), "pair", ok=(0, 2))
        self.wait(0.5)                  # let the device ask for the time
        self._result(self.request(FUN_SENDER_DEVICE_STATUS, b""), "status")
        if not self._att.pump(lambda: DP_CLICK in self.dps, dp_timeout):
            raise RuntimeError(f"dp{DP_CLICK} never appeared")
        self.strict = False

    def write_dp(self, dp: int, value: int) -> bytes:
        """Write one datapoint, encoded as the device reported its type, and
        return the device's response payload. Raises ReadOnlyViolation on a
        read-only session, before encoding anything."""
        if not self._actuate:
            raise ReadOnlyViolation(f"dp{dp} write on a read-only session")
        if self._protocol != 3:
            raise ProtocolError(f"datapoint writes need protocol 3, device speaks "
                                f"{self._protocol}")
        if dp not in self.dps:
            raise Refused(f"dp{dp} not published by the device")
        # Any response is the ack, as in tuya-ble (the path every real press
        # so far has taken). Deliberately not stricter: aborting between the
        # travel nudge and its restore would leave travel one step short.
        return self.request(FUN_SENDER_DPS, encode_dp(dp, self.dps[dp].type, value)).data


# --------------------------------------------------------------------------
# Connect + run
# --------------------------------------------------------------------------
def _open(cfg: dict[str, str], trace: Trace,
          connect_timeout: float = 30.0) -> tuple[socket.socket, Att, Handles]:
    mac = cfg["FB_MAC"]
    kind = cfg.get("FB_ADDR_TYPE", "public")
    addr_type = {"public": BDADDR_LE_PUBLIC, "random": BDADDR_LE_RANDOM}.get(kind)
    if addr_type is None:
        raise ValueError(f"FB_ADDR_TYPE must be public or random, got {kind!r}")
    local = adapter_address(cfg["FB_ADAPTER"]) if cfg.get("FB_ADAPTER") else BDADDR_ANY
    t = _now()
    sock = att_connect(mac, addr_type, local, connect_timeout)
    trace(f"connected in {_now() - t:.1f}s (LE {kind}, "
          f"from {local if local != BDADDR_ANY else 'default adapter'})")
    try:
        att = Att(sock)
        t = _now()
        handles = att.discover()
        att.write_request(handles.cccd, struct.pack("<H", 1))
        trace(f"gatt {SVC_TUYA}: write 0x{handles.write:04x} notify 0x{handles.notify:04x} "
              f"cccd 0x{handles.cccd:04x} ({_now() - t:.1f}s)")
        return sock, att, handles
    except BaseException:
        sock.close()
        raise


def _calibration(cfg: dict[str, str]) -> list[tuple[int, int]]:
    """(dp, value) writes to make before every click, from FB_MODE/TRAVEL/HOLD.

    The device does not reliably honour its stored calibration on a cold
    click -- by hand it took moving the app's travel slider back and forth.
    So travel is nudged one step off and back, then hold and mode are written.
    """
    if "FB_TRAVEL" not in cfg:
        return []

    def setting(key: str, default: str, top: int) -> int:
        value = int(cfg.get(key, default))
        if not 0 <= value <= top:
            raise Refused(f"{key}={value} is outside 0..{top}; not pressing")
        return value

    travel = setting("FB_TRAVEL", "", 100)
    nudge = travel - 1 if travel > 0 else travel + 1
    return [(DP_TRAVEL, nudge), (DP_TRAVEL, travel),
            (DP_HOLD, setting("FB_HOLD", "0", 0xFFFF)),
            (DP_MODE, setting("FB_MODE", "0", 0xFF))]


def press(settle: float = 1.0, trace: Trace = lambda _m: None) -> None:
    """Re-assert calibration, then click once. THE ONLY ACTUATING PATH."""
    cfg = _config()
    writes = _calibration(cfg)
    sock, att, handles = _open(cfg, trace)
    try:
        session = Session(att, handles, cfg, actuate=True)
        session.login()
        missing = sorted({dp for dp, _ in writes} - session.dps.keys())
        if missing:
            raise Refused(f"calibration dps {missing} not published; not clicking")
        for dp, value in writes:
            session.write_dp(dp, value)
            session.wait(settle)
        sent = len(session.sent)
        try:
            session.write_dp(DP_CLICK, True)
            session.wait(2.0)
        except BaseException as e:
            if any(code == FUN_SENDER_DPS for code, _ in session.sent[sent:]):
                raise ClickUnconfirmed(
                    f"dp{DP_CLICK} click was sent (at least partly), then "
                    f"{type(e).__name__}: {e}. The arm may have moved -- check the host "
                    "before retrying") from e
            raise
    finally:
        sock.close()


def info() -> None:
    """Read-only diagnostics. Never actuates: its session cannot send a
    datapoint write."""
    cfg = _config()
    print(f"config      {_env_path()}")
    # uuid and device_id are identifiers, not secrets: without local_key they
    # grant nothing over BLE. Only local_key is redacted.
    for k in ("FB_MAC", "FB_ADDR_TYPE", "FB_ADAPTER", "FB_DEVICE_ID", "FB_UUID",
              "FB_PRODUCT_ID", "FB_CATEGORY", "FB_MODE", "FB_TRAVEL", "FB_HOLD"):
        if k in cfg:
            print(f"  {k:<14} {cfg[k]}")
    print(f"  {'FB_LOCAL_KEY':<14} {'set' if cfg.get('FB_LOCAL_KEY') else 'MISSING'} "
          f"({len(cfg.get('FB_LOCAL_KEY', ''))} chars)")

    print("\nsession")
    t = _now()
    try:
        sock, att, handles = _open(cfg, lambda m: print("  " + m))
        try:
            session = Session(att, handles, cfg)
            session.login()
        finally:
            sock.close()
    except Exception as e:
        print(f"  FAILED after {_now() - t:.1f}s: {type(e).__name__}: {str(e)[:200]}")
        raise SystemExit(1) from e
    d = session.info
    assert d is not None
    print(f"  logged in, {_now() - t:.1f}s total")
    print(f"  device firmware {d.device_version}, protocol {d.protocol_str}, "
          f"hardware {d.hardware_version}, bound={'yes' if d.bound else 'no'}")
    print("  frames sent: " + " ".join(
        f"0x{code:04x}{'(reply)' if rsp else ''}" for code, rsp in session.sent))
    print(f"\n  {len(session.dps)} datapoints")
    for i in sorted(session.dps):
        dp = session.dps[i]
        mark = "  <- click" if i == DP_CLICK else ""
        print(f"    dp {i:>3}  {DT_NAMES[dp.type]:<8} {dp.value!r}{mark}")


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    cmd = args[0] if args else "press"
    if cmd in ("press", "click"):
        try:
            press()
        except ClickUnconfirmed as e:
            print(f"fingerbot: {e}", file=sys.stderr)
            raise SystemExit(3) from e
        print("clicked")
    elif cmd == "info":
        info()
    else:
        raise SystemExit(f"usage: fingerbot [press|info]  (got {cmd!r})")


if __name__ == "__main__":
    main()
