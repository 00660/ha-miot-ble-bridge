"""MIoT protocol, independent of Home Assistant and the BLE transport.

Ported from miot-ble-sdk, revision e9058f09ad2b1040d8a79d6aa2a7fb79767892a1.
Copyright (c) 2026 miot-ble-sdk contributors.
The upstream miot-ble-sdk Non-Commercial License applies to this derived port.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
import hmac
import json
import math
import secrets
import struct
import time
from typing import Any, NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .models import DEFAULT_MODEL, get_model

PID = 0x4683
MODEL = DEFAULT_MODEL
CHANNEL_CONTROL = 0x0010
CHANNEL_AUTH = 0x0019
CHANNEL_SPEC = 0x001A
CHANNEL_SPEC_WRITE = 0x001B
NUS_RX = 0x6E400002
NUS_TX = 0x6E400003
MAX_NOTIFICATIONS = 128
MAX_FRAME_SIZE = 512
MAX_SPEC_ITEMS = 64
MAX_PENDING_REQUESTS = 16
MAX_REPLAY_CACHE = 64
MAX_NUS_QUEUE = 16
REQUEST_TIMEOUT = 20.0
COUNTER_LIMIT = 1 << 32

OBJECT_PROPERTIES = {
    0x484E: (2, 1078),
    0x4805: (2, 1005),
    0x4852: (2, 1082),
    0x4851: (2, 1081),
    0x100A: (3, 1003),
}


class ProtocolError(ValueError):
    """The current protocol operation cannot be completed safely."""


class PersistenceRequired(ProtocolError):
    """The next operation requires an acknowledged durable write."""


class Request(NamedTuple):
    """A validated request for an application to execute and acknowledge."""

    kind: str
    tid: int
    session_id: int
    request_id: int
    response_channel: int
    items: tuple[tuple[str, Any], ...] = ()
    action_key: str | None = None
    args: tuple[tuple[str, Any], ...] = ()


_SCALAR_FORMATS = {0: "B", 1: "B", 2: "b", 3: "H", 4: "h", 5: "I", 6: "i", 7: "Q", 8: "q", 9: "f"}


def _encode_raw(type_code: int, value: Any) -> bytes:
    if type_code == 10:
        if not isinstance(value, str):
            raise ProtocolError("String property requires text")
        return value.encode("utf-8")
    if type_code not in _SCALAR_FORMATS:
        raise ProtocolError("Unknown spec value type")
    if type_code == 0 and value not in (False, True, 0, 1):
        raise ProtocolError("Invalid boolean property")
    try:
        if type_code == 9:
            value = float(value)
            if not math.isfinite(value):
                raise ProtocolError("Float property must be finite")
        else:
            if value != int(value):
                raise ProtocolError("Integer property requires an integral value")
            value = int(value)
        return struct.pack("<" + _SCALAR_FORMATS[type_code], value)
    except (struct.error, OverflowError, ValueError, TypeError) as error:
        raise ProtocolError("Spec value is outside its wire range") from error


def _decode_raw(type_code: int, value: bytes) -> Any:
    if type_code == 10:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("Spec string is not valid UTF-8") from error
    if type_code not in _SCALAR_FORMATS or len(value) != struct.calcsize("<" + _SCALAR_FORMATS[type_code]):
        raise ProtocolError("Spec scalar has an invalid type or length")
    decoded = struct.unpack("<" + _SCALAR_FORMATS[type_code], value)[0]
    if type_code == 0:
        if decoded not in (0, 1):
            raise ProtocolError("Invalid spec boolean")
        return bool(decoded)
    if type_code == 9 and not math.isfinite(decoded):
        raise ProtocolError("Spec float must be finite")
    return decoded


def _rc4(key: bytes, data: bytes) -> bytes:
    if not key:
        raise ProtocolError("RC4 requires a key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 255
        state[i], state[j] = state[j], state[i]
    i = j = 0
    result = bytearray()
    for value in data:
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        result.append(value ^ state[(state[i] + state[j]) & 255])
    return bytes(result)


def _mix_a(mac: bytes, pid: int) -> bytes:
    return bytes([mac[0], mac[2], mac[5], pid & 255, pid & 255, mac[4], mac[5], mac[1]])


def _mix_b(mac: bytes, pid: int) -> bytes:
    return bytes([mac[0], mac[2], mac[5], pid >> 8, mac[4], mac[0], mac[5], pid & 255])


class CounterLease:
    """Reserve counters durably before consuming them; skip a lease on restart."""

    def __init__(self, reserved_until: int = 0, block_size: int = 1024) -> None:
        if not 0 <= reserved_until <= COUNTER_LIMIT or block_size < 1:
            raise ValueError("Invalid counter lease")
        self.next_counter = reserved_until
        self.reserved_until = reserved_until
        self.block_size = block_size

    def required_reservation(self) -> int | None:
        if self.next_counter < self.reserved_until:
            return None
        if self.next_counter == COUNTER_LIMIT:
            raise ProtocolError("Beacon counter exhausted; a new binding is required")
        return min(COUNTER_LIMIT, self.next_counter + self.block_size)

    def commit_reservation(self, reserved_until: int) -> None:
        if reserved_until != self.required_reservation():
            raise ProtocolError("Counter reservation does not match the durable write")
        self.reserved_until = reserved_until

    def take(self) -> int:
        if self.required_reservation() is not None:
            raise PersistenceRequired("Persist and commit the counter reservation first")
        value = self.next_counter
        self.next_counter += 1
        return value


def _mac_bytes(mac: str) -> bytes:
    try:
        value = bytes.fromhex(mac.replace(":", ""))
    except ValueError as error:
        raise ValueError("Invalid Bluetooth address") from error
    if len(value) != 6 or value == bytes(6):
        raise ValueError("Invalid Bluetooth address")
    return value


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 64, salt, info).derive(ikm)


def _parcel(package_type: int, payload: bytes) -> list[bytes]:
    if not payload or len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError("Invalid AG2 payload size")
    chunks = [payload[i : i + 18] for i in range(0, len(payload), 18)]
    return [b"\x00\x00\x00" + bytes([package_type]) + struct.pack("<H", len(chunks))] + [
        struct.pack("<H", number) + chunk
        for number, chunk in enumerate(chunks, start=1)
    ]


class _Receiver:
    def __init__(self) -> None:
        self.error: str | None = None
        self.reset()

    def reset(self) -> None:
        self.count = 0
        self.package_type = 0
        self.chunks: dict[int, bytes] = {}
        self.size = 0
        self.deadline: float | None = None

    def fail(self, message: str) -> tuple[list[bytes], None]:
        self.reset()
        self.error = message
        return [], None

    def expire(self, now: float) -> None:
        if self.deadline is not None and now >= self.deadline:
            self.fail("AG2 receive timeout")

    def feed(
        self, data: bytes, now: float, *, acknowledge_single: bool
    ) -> tuple[list[bytes], tuple[int, bytes] | None]:
        self.error = None
        self.expire(now)
        if not 2 <= len(data) <= MAX_FRAME_SIZE:
            return self.fail("Invalid AG2 frame size")
        if data[:2] == b"\x00\x00":
            if len(data) < 4:
                return self.fail("Truncated AG2 control frame")
            command = data[2]
            if command == 0:
                if len(data) != 6:
                    return self.fail("Invalid AG2 START")
                count = struct.unpack_from("<H", data, 4)[0]
                if not 1 <= count <= 64:
                    return self.fail("Invalid AG2 fragment count")
                self.reset()
                self.count, self.package_type = count, data[3]
                self.deadline = now + 5.0
                return [b"\x00\x00\x01\x01"], None
            if command == 2:
                self.reset()
                acknowledgements = [b"\x00\x00\x01\x00"] if acknowledge_single else []
                return acknowledgements, (data[3], data[4:])
            if command in (1, 3, 5):
                return [], None
            return self.fail("Unsupported AG2 control frame")
        if not self.count:
            return [], None
        number = struct.unpack_from("<H", data)[0]
        chunk = data[2:]
        if not 1 <= number <= self.count or not 1 <= len(chunk) <= 18:
            return self.fail("Invalid AG2 fragment")
        if number in self.chunks:
            if self.chunks[number] != chunk:
                return self.fail("Conflicting AG2 fragment")
            return [], None
        if self.size + len(chunk) > MAX_FRAME_SIZE:
            return self.fail("AG2 payload exceeds receive capacity")
        self.chunks[number] = chunk
        self.size += len(chunk)
        if len(self.chunks) != self.count:
            return [], None
        package_type = self.package_type
        payload = b"".join(self.chunks[i] for i in range(1, self.count + 1))
        self.reset()
        return [b"\x00\x00\x01\x00"], (package_type, payload)


class MiotProtocol:
    """One model, one cloud identity and one authenticated connection."""

    def __init__(
        self,
        mac: str,
        identity: dict[str, Any] | None = None,
        model: str = DEFAULT_MODEL,
        *,
        on_set: Callable[[Request], None] | None = None,
        on_action: Callable[[Request], None] | None = None,
    ) -> None:
        self.model = get_model(model)
        self.pid = self.model.pid
        self.on_set = on_set
        self.on_action = on_action
        normal_mac = _mac_bytes(mac)
        self.mac = ":".join(f"{part:02X}" for part in normal_mac)
        self.mac_air = normal_mac[::-1]
        self._identity = self._validate_identity(identity) if identity else None
        self._pending_identity: dict[str, Any] | None = None
        self._pending_psk_identity: dict[str, Any] | None = None
        self._outgoing: deque[tuple[int, bytes]] = deque()
        self._values: dict[int, bytes] = {}
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._auth_rx = _Receiver()
        self._spec_rx = _Receiver()
        self._connected = False
        self._session_id = 0
        self._next_request_id = 0
        self._requests: dict[int, dict[str, Any]] = {}
        self._inbound: OrderedDict[int, dict[str, Any]] = OrderedDict()
        self._notify_channels: set[int] = set()
        self._last_spec_channel: int | None = None
        self._mtu = 23
        self._nus_queue: deque[tuple[float, bytes]] = deque()
        self._nus_scenes = ((60, 25000), (20, 30000), (100, 10000), (40, 5000))
        self._nus_scene_number = 0
        self.last_error: str | None = None
        self.properties: dict[tuple[int, int], tuple[int, Any]] = {}
        self._property_values: dict[str, Any] = {}
        self._reset_session()
        if self.model.model == DEFAULT_MODEL:
            self.set_properties(0)
        else:
            self.set_property_values({
                prop.key: prop.default for prop in self.model.properties
                if prop.default is not None and prop.derived not in ("present_minutes", "absent_minutes")
            })

    def _validate_identity(self, identity: dict[str, Any]) -> dict[str, Any]:
        if self.model.auth_mode == "psk":
            raise ValueError("Experimental PSK identities cannot be loaded as standard MIoT identities")
        try:
            if identity.get("version", 1) != 1 or identity["pid"] != self.pid:
                raise ValueError
            if _mac_bytes(identity["mac"]) != _mac_bytes(self.mac):
                raise ValueError
            scheme = identity.get("auth_scheme", "standard")
            fields = [("token", 12), ("bind_key", 16)]
            if scheme == "standard":
                fields += [("dev_key", 16), ("sign", 64)]
            elif scheme == "legacy_rc4" and self.model.auth_mode == "standard_nus":
                pass
            else:
                raise ValueError
            for key, length in fields:
                if len(bytes.fromhex(identity[key])) != length:
                    raise ValueError
            did = identity["did"].encode("ascii")
            if not 1 <= len(did) <= 20 or b"\x00" in did:
                raise ValueError
            if not 0 <= identity["utc"] < COUNTER_LIMIT:
                raise ValueError
            if scheme == "legacy_rc4" and identity.get("mac_order", "air") not in ("air", "human"):
                raise ValueError
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            raise ValueError("Stored MIoT identity is invalid or belongs to another address") from error
        return {
            "version": 1,
            "pid": self.pid,
            "mac": self.mac,
            "token": identity["token"],
            "bind_key": identity["bind_key"],
            "did": identity["did"],
            "utc": identity["utc"],
            "auth_scheme": scheme,
            **({"dev_key": identity["dev_key"], "sign": identity["sign"]} if scheme == "standard" else {}),
            **({"mac_order": identity.get("mac_order", "air")} if scheme == "legacy_rc4" else {}),
        }

    @property
    def identity(self) -> dict[str, Any] | None:
        return dict(self._identity) if self._identity is not None else None

    @property
    def pending_identity(self) -> dict[str, Any] | None:
        return dict(self._pending_identity) if self._pending_identity is not None else None

    @property
    def pending_psk_identity(self) -> dict[str, Any] | None:
        """Experimental key/DID capture; it cannot grant a normal binding."""
        return dict(self._pending_psk_identity) if self._pending_psk_identity is not None else None

    @property
    def bound(self) -> bool:
        return self._identity is not None

    @property
    def logged_in(self) -> bool:
        return self._authenticated and (self._session is not None or self._legacy_logged_in)

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def pending_requests(self) -> tuple[Request, ...]:
        return tuple(record["request"] for record in self._requests.values())

    @property
    def property_values(self) -> dict[str, Any]:
        return dict(self._property_values)

    def set_notify_channels(self, channels: set[int], now: float | None = None) -> None:
        added = set(channels) - self._notify_channels
        self._notify_channels = set(channels)
        if self._connected and self.model.auth_mode == "standard_nus" and not self._channel_ready:
            now = time.monotonic() if now is None else now
            for channel in (CHANNEL_SPEC_WRITE, CHANNEL_SPEC):
                if channel in added:
                    self._emit(channel, [bytes.fromhex("000004000612")])
                    self._link_probe_channel = channel
                    self._link_probe_at = now + 0.400

    def set_mtu(self, mtu: int) -> None:
        if not 23 <= mtu <= 517:
            raise ValueError("Invalid ATT MTU")
        self._mtu = mtu

    def _begin_application_session(self, *, clear_notifications: bool = True) -> None:
        self._session_id += 1
        self._requests.clear()
        self._inbound.clear()
        self._last_spec_channel = None
        if clear_notifications:
            self._outgoing.clear()
        self._values.clear()
        self._nus_queue.clear()
        self._auth_rx.reset()
        self._spec_rx.reset()

    def _spec_channel(self, source: int | None = None) -> int:
        if self.model.gatt_strategy == "fixed_control":
            return CHANNEL_CONTROL
        source = self._last_spec_channel if source is None else source
        if source in self._notify_channels:
            return source
        if CHANNEL_SPEC in self._notify_channels:
            return CHANNEL_SPEC
        return CHANNEL_CONTROL

    def _reset_session(self) -> None:
        self._begin_application_session()
        self._session: bytes | None = None
        self._authenticated = False
        self._state = "idle"
        self._registration: dict[str, Any] | None = None
        self._certificate_received = False
        self._confirm: bytes | None = None
        self._app_random: bytes | None = None
        self._device_random: bytes | None = None
        self._confirm_at: float | None = None
        self._confirm_count = 0
        self._info_at: float | None = None
        self._info_count = 0
        self._channel_info_at: float | None = None
        self._snapshot_at: float | None = None
        self._info_sent = False
        self._last_auth_channel: int | None = None
        self._channel_ready = False
        self._link_test_sent = False
        self._link_probe_channel: int | None = None
        self._link_probe_at: float | None = None
        self._link_info_channel: int | None = None
        self._tx_sequence = 0
        self._last_rx_sequence = -1
        self._last_rx_wire = b""
        self._psk_stage = "wait_start"
        self._psk_start = b""
        self._psk_keys: bytes | None = None
        self._psk_login_key_ready = False
        self._psk_device_random: bytes | None = None
        self._psk_app_random = bytes(16)
        self._psk_server_public = b""
        self._legacy_logged_in = False
        self._legacy_active = False
        self._legacy_proven = False
        legacy = self._identity if self._identity and self._identity.get("auth_scheme") == "legacy_rc4" else None
        self._legacy_token = bytes.fromhex(legacy["token"]) if legacy else None
        self._legacy_bonded = legacy is not None
        self._legacy_did = legacy["did"] if legacy else None
        self._legacy_bind_key = bytes.fromhex(legacy["bind_key"]) if legacy else None
        self._legacy_random = bytes(4)
        self._legacy_random_at: float | None = None
        self._legacy_random_started = 0.0
        self._legacy_random_channel = 0x0001
        self._legacy_order = self._identity.get("mac_order", "air") if self._identity else "air"
        self._nus_queue.clear()
        self._notify_channels.clear()
        self._mtu = 23
        self._auth_rx.reset()
        self._spec_rx.reset()

    def connect(self, now: float | None = None) -> None:
        self.disconnect()
        self._connected = True
        self.last_error = None

    def disconnect(self) -> None:
        self._connected = False
        self._outgoing.clear()
        self._values.clear()
        self._reset_session()

    def _emit(self, channel: int, frames: list[bytes]) -> None:
        if not self._connected:
            return
        maximum = self._mtu - 3 if channel == NUS_TX else 20
        if any(len(frame) > maximum for frame in frames):
            raise ProtocolError("Notification exceeds the minimum ATT MTU")
        if len(self._outgoing) + len(frames) > MAX_NOTIFICATIONS:
            self.disconnect()
            raise ProtocolError("Notification queue exceeded its capacity")
        self._outgoing.extend((channel, frame) for frame in frames)
        if frames:
            self._values[channel] = frames[-1]

    def drain_notifications(self) -> list[tuple[int, bytes]]:
        result = list(self._outgoing)
        self._outgoing.clear()
        return result

    def read(self, channel: int) -> bytes:
        if self.model.gatt_strategy == "prefer_source" or self.model.auth_mode == "standard_nus":
            if channel == 0x0001:
                token = self._legacy_token if self._legacy_bonded else None
                return token or (bytes.fromhex(self._identity["token"]) if self._identity else b"\xff" * 12)
            if channel == 0x0002:
                return struct.pack("<H", self.pid)
            if channel == 0x0004:
                return b"9.9.9_9999"
            if channel == 0x0013:
                did = self._legacy_did or (self._identity["did"] if self._identity else None)
                return did.encode("ascii").rjust(20, b"\x00") if did else bytes(20)
            if channel == 0x0014:
                key = self._legacy_bind_key or (bytes.fromhex(self._identity["bind_key"]) if self._identity else bytes(16))
                if self._legacy_active or (self._identity and self._identity.get("auth_scheme") == "legacy_rc4"):
                    token = self._legacy_token or (bytes.fromhex(self._identity["token"]) if self._identity else None)
                    return _rc4(token, key) if token else bytes(16)
                return key
            if channel in (0x0016, 0x0017, 0x0018):
                return b"\x00"
            if channel == CHANNEL_SPEC_WRITE:
                return b"\x02"
        return self._values.get(channel, b"")

    def _result(self, value: int) -> None:
        self._emit(CHANNEL_CONTROL, [bytes([value, 0, 0, 0])])

    def _auth_channel(self, source: int | None = None) -> int:
        if self.model.auth_mode != "standard_nus":
            return CHANNEL_AUTH
        source = self._last_auth_channel if source is None else source
        for channel in (source, CHANNEL_SPEC, CHANNEL_SPEC_WRITE, CHANNEL_AUTH):
            if channel in self._notify_channels:
                return channel
        return CHANNEL_AUTH

    def _emit_auth(self, frames: list[bytes], source: int | None = None) -> None:
        self._emit(self._auth_channel(source), frames)

    def _device_info(self, channel: int | None = None) -> None:
        did = self._legacy_did or (self._identity["did"] if self._identity else "")
        did = did.encode("ascii")
        payload = b"\x02\x00\x00\x00" + did
        frames = [b"\x00\x00\x02\x00" + payload] if len(payload) <= 16 else _parcel(0, payload)
        self._emit_auth(frames, channel)
        self._info_sent = True

    def write(self, channel: int, data: bytes, now: float | None = None) -> None:
        if not self._connected or not data:
            return
        now = time.monotonic() if now is None else now
        data = bytes(data)
        if len(data) > MAX_FRAME_SIZE:
            self.last_error = "GATT write exceeds receive capacity"
            return
        if self.model.auth_mode == "standard_nus" and self._write_nus_link(channel, data, now):
            return
        if channel == CHANNEL_CONTROL:
            if data == b"\xa4" or data == b"\xa4\x00\x00\x00":
                self._emit_auth([b"\x00\x00\x04\x00\x06\x12"])
                self._info_sent = False
                self._channel_info_at = None
                return
            if data in (b"\xa2\x00\x00\x00", b"\x22\x00\x00\x00"):
                self._begin_application_session()
                self._authenticated = False
                self._session = None
                self._legacy_active = False
                self._legacy_logged_in = False
                self._legacy_proven = False
                self._registration = None
                self._certificate_received = False
                self._state = "psk_setup" if self.model.auth_mode == "psk" else "register_key"
                self._psk_stage = "wait_pub"
                self._psk_start = b""
                self._psk_keys = None
                self._psk_app_random = bytes(16)
                self._psk_device_random = None
                self._pending_psk_identity = None
                self._device_info()
                self._info_count = 1
                self._info_at = now + 0.150
                return
            if data == b"\x24\x00\x00\x00":
                if not self.bound and not (self.model.auth_mode == "psk" and self._psk_keys is not None):
                    if self.model.auth_mode == "psk":
                        self.last_error = "Experimental PSK login requires a completed ECDH handshake"
                    self._result(0xE2)
                    return
                self._begin_application_session()
                self._state = "login_random"
                self._authenticated = False
                self._session = None
                self._legacy_active = False
                self._legacy_logged_in = False
                self._legacy_proven = False
                self._confirm_at = None
                self._info_at = None
                if self.model.auth_mode == "psk":
                    self._psk_login_key_ready = False
                    self._emit_auth(_parcel(3, self._public_key()))
                return
            if data == b"\x13\x00\x00\x00":
                # Cloud DID, rather than this unauthenticated result, grants identity.
                return
        if self.model.auth_mode == "standard_nus" and self._write_legacy(channel, data, now):
            return
        if channel == NUS_RX and self.model.auth_mode == "standard_nus":
            self._write_nus(data, now)
        elif channel in (0x0001, 0x0013, 0x0016, 0x0017, 0x0018):
            return
        elif channel == CHANNEL_AUTH:
            if self.logged_in and self.model.gatt_strategy == "prefer_source":
                self._write_spec(channel, data, now)
                return
            self._write_auth(data, now, channel)
        elif channel in (CHANNEL_CONTROL, CHANNEL_SPEC, CHANNEL_SPEC_WRITE):
            if channel != CHANNEL_CONTROL and not self.logged_in and (self.model.gatt_strategy == "prefer_source" or self.model.auth_mode == "standard_nus"):
                self._write_auth(data, now, channel)
            else:
                self._write_spec(channel, data, now)
        else:
            self.last_error = "Unknown GATT channel"

    def _write_nus_link(self, channel: int, data: bytes, now: float) -> bool:
        if channel not in (CHANNEL_AUTH, CHANNEL_SPEC, CHANNEL_SPEC_WRITE) or data[:2] != b"\x00\x00" or len(data) < 3 or data[2] not in (4, 5):
            return False
        self._last_auth_channel = channel
        if len(data) < 4:
            self.last_error = "Truncated NUS AG2 management frame"
            return True
        command, code = data[2:4]
        if (command, code) == (5, 0):
            if len(data) not in (4, 6):
                self.last_error = "Invalid NUS AG2 management acknowledgement"
                return True
            if self._channel_ready:
                return True
        elif (command, code) == (4, 1):
            if len(data) != 20 or data[4:] != b"\x12" * 16:
                self.last_error = "Invalid NUS AG2 peer test"
                return True
        elif (command, code) == (5, 1):
            if not self._link_test_sent or not self._channel_ready:
                self.last_error = "NUS AG2 test acknowledgement arrived before the test"
                return True
            if len(data) not in (4, 20) or (len(data) == 20 and data[4:] != b"\x12" * 16):
                self.last_error = "Invalid NUS AG2 test acknowledgement"
                return True
            if not self._info_sent:
                self._device_info(channel)
                self._channel_info_at = None
            return True
        else:
            return True
        self._emit_auth([b"\x00\x00\x05\x01" + b"\x12" * 16], channel)
        self._channel_ready = self._link_test_sent = True
        self._link_probe_at = None
        self._info_sent = False
        self._link_info_channel = channel
        self._channel_info_at = now + 0.250
        return True

    def _legacy_reply_channel(self, source: int) -> int:
        for channel in (source, 0x0001, CHANNEL_CONTROL):
            if channel in self._notify_channels:
                return channel
        return 0x0001

    def _legacy_identity_matches(self) -> bool:
        return self._identity is not None and self._legacy_token is not None and (
            self._identity["token"] == self._legacy_token.hex()
            and (self._legacy_did is None or self._identity["did"] == self._legacy_did)
        )

    def _pending_legacy_identity(self) -> None:
        if not self._legacy_bonded or not self._legacy_proven or not self._legacy_token or not self._legacy_did:
            return
        if self._legacy_identity_matches():
            self._authenticated = self._legacy_logged_in
            return
        if self._legacy_bind_key is None:
            self._legacy_bind_key = secrets.token_bytes(16)
        candidate = {
            "version": 1, "pid": self.pid, "mac": self.mac,
            "auth_scheme": "legacy_rc4", "mac_order": self._legacy_order,
            "token": self._legacy_token.hex(), "bind_key": self._legacy_bind_key.hex(),
            "did": self._legacy_did, "utc": int(time.time()) & 0xFFFFFFFF,
        }
        if self._pending_identity and all(self._pending_identity.get(key) == value for key, value in candidate.items() if key != "utc"):
            return
        self._pending_identity = self._validate_identity(candidate)

    def _write_legacy(self, channel: int, data: bytes, now: float) -> bool:
        if channel == 0x0013:
            if not self._legacy_active and self._legacy_token is None:
                return False
            try:
                if len(data) != 20:
                    raise ValueError
                did = data.strip(b"\x00").decode("ascii")
                if not did or "\x00" in did:
                    raise ValueError
            except (UnicodeError, ValueError):
                self.last_error = "Invalid legacy cloud DeviceID"
                return True
            self._legacy_did = did
            self._pending_legacy_identity()
            return True
        if channel not in (0x0001, CHANNEL_CONTROL):
            return False
        if self._state in ("register_key", "register_cloud", "login_random", "login_confirm"):
            return False
        if channel == CHANNEL_CONTROL and (
            data[:2] == b"\x00\x00"
            or ((self._auth_rx.count or self._spec_rx.count) and len(data) >= 2 and data[1] == 0)
        ):
            return False
        if data == bytes.fromhex("90ca85de"):
            self._begin_application_session()
            self._legacy_active = True
            self._legacy_proven = False
            self._legacy_logged_in = False
            self._authenticated = False
            self._session = None
            return True
        if data == bytes.fromhex("00bc43cd"):
            if self._legacy_logged_in or self._authenticated:
                self._begin_application_session()
                self._authenticated = False
                self._legacy_logged_in = False
                self._legacy_proven = False
            self._legacy_active = True
            if self._legacy_token is None and self._identity:
                self._legacy_token = bytes.fromhex(self._identity["token"])
                self._legacy_bind_key = bytes.fromhex(self._identity["bind_key"])
                self._legacy_did = self._identity["did"]
                self._legacy_bonded = True
            if self._legacy_token is not None:
                self._legacy_random = secrets.token_bytes(4)
                self._legacy_random_started = now
                self._legacy_random_at = now + 0.040
                self._legacy_random_channel = channel
            return True
        if len(data) == 12:
            self._begin_application_session()
            self._legacy_active = True
            self._legacy_proven = False
            self._legacy_logged_in = False
            self._authenticated = False
            self._session = None
            mac = self.mac_air if self._legacy_order == "air" else _mac_bytes(self.mac)
            self._legacy_token = _rc4(_mix_a(mac, self.pid), data)
            self._legacy_bonded = False
            self._legacy_did = self._identity["did"] if self._legacy_identity_matches() else None
            self._legacy_bind_key = bytes.fromhex(self._identity["bind_key"]) if self._identity else secrets.token_bytes(16)
            acknowledgement = _rc4(_mix_b(mac, self.pid), _rc4(_mix_a(mac, self.pid), self._legacy_token))
            self._emit(0x0001, [acknowledgement])
            return True
        if len(data) != 4 or not self._legacy_active or self._legacy_token is None:
            return False
        if data[1:] == bytes(3) and data[0] in (*range(0x10, 0x16), *range(0x20, 0x25), 0xA2, 0xA4, 0xE1, 0xE2):
            return False
        for xor_random in (True, False):
            key = bytearray(self._legacy_token)
            if xor_random:
                for index in range(4):
                    key[index] ^= self._legacy_random[index]
            decoded = struct.unpack("<I", _rc4(bytes(key), data))[0]
            if decoded == 0xFA54AB92:
                self._legacy_bonded = self._legacy_proven = True
                self._legacy_random_at = None
                self._pending_legacy_identity()
                return True
            if decoded in (0x369A58C9, 0x93BFAC09):
                self._legacy_proven = self._legacy_logged_in = True
                self._legacy_random_at = None
                self._authenticated = self._legacy_identity_matches()
                self._emit(self._legacy_reply_channel(channel), [_rc4(bytes(key), struct.pack("<I", 0x369A58C9))])
                return True
        if self._legacy_bonded and self._legacy_proven:
            self._legacy_logged_in = True
            self._authenticated = self._legacy_identity_matches()
            self._emit(self._legacy_reply_channel(channel), [bytes(value ^ delta for value, delta in zip(data, bytes.fromhex("c0f425a5")))])
            return True
        self.last_error = "Legacy login confirmation failed"
        return True

    def _nus_message(self, flag: str, result: Mapping[str, Any], now: float) -> None:
        payload = json.dumps({"flag": flag, "result": dict(result)}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(payload) > 514 or len(self._nus_queue) >= MAX_NUS_QUEUE:
            self.disconnect()
            raise ProtocolError("NUS notification queue exceeded its capacity")
        due = max(now + 0.020, self._nus_queue[-1][0] + 0.020 if self._nus_queue else 0)
        self._nus_queue.append((due, payload))

    def _nus_properties(self) -> dict[str, Any]:
        values = self.property_values
        result = {"lux": 1, "snm": self._nus_scene_number}
        for key, name in (("2.3", "power"), ("2.1", "bright"), ("2.2", "dur")):
            if key in values:
                result[name] = int(values[key])
        return result

    def load_nus_scenes(self, scenes: Mapping[str | int, Mapping[str, int]]) -> None:
        """Restore scene presets saved by the host without changing current light values."""
        if self.model.auth_mode != "standard_nus":
            if not scenes:
                return
            raise ProtocolError("NUS scenes require a night light model")
        restored = list(self._nus_scenes)
        try:
            for key, values in scenes.items():
                scene_id = int(key)
                bright, duration = int(values["bright"]), int(values["dur"])
                if not 1 <= scene_id <= 4 or not 1 <= bright <= 100 or not 5000 <= duration <= 60000:
                    raise ValueError
                if bright != values["bright"] or duration != values["dur"]:
                    raise ValueError
                restored[scene_id - 1] = (bright, duration)
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            raise ProtocolError("Stored NUS scene preset is invalid") from error
        self._nus_scenes = tuple(restored)

    def _write_nus(self, data: bytes, now: float) -> None:
        if not self.bound or not self.logged_in:
            self.last_error = "NUS command requires an authenticated identity"
            return
        try:
            if len(data) > 128 or b"\x00" in data:
                raise ValueError
            tokens = data.decode("ascii").split()
            if not tokens:
                return
        except (UnicodeError, ValueError):
            self.last_error = "Malformed NUS command"
            return
        flag = tokens[0]
        if flag == "notify_ol":
            current = self._nus_properties()
            self._nus_message(flag, {"power": current["power"]} if "power" in current else {}, now)
            return
        if flag == "get_prop":
            self._nus_message(flag, self._nus_properties(), now)
            return
        if flag == "get_s_prop":
            self._nus_message(flag, {"scene": [{"bright": bright, "dur": duration} for bright, duration in self._nus_scenes]}, now)
            return
        arities = {"set_power": 1, "set_bright": 1, "set_duration": 1, "set_dur": 1,
                   "set_bridur": 2, "apply_fixed_scene": 1, "set_scene": 3}
        try:
            if flag not in arities or len(tokens) != arities[flag] + 1:
                raise ValueError
            args = [int(token, 10) for token in tokens[1:]]
            values, scene = {}, None
            if flag == "set_power":
                if args[0] not in (0, 1):
                    raise ValueError
                values["2.3"] = args[0]
            elif flag == "set_bright":
                values = {"2.1": max(1, min(100, args[0])), "2.3": 1}
            elif flag in ("set_duration", "set_dur"):
                values["2.2"] = max(5000, min(60000, args[0]))
            elif flag == "set_bridur":
                values = {"2.1": max(1, min(100, args[0])), "2.2": max(5000, min(60000, args[1])), "2.3": 1}
            elif flag == "apply_fixed_scene":
                if not 1 <= args[0] <= 4:
                    raise ValueError
                bright, duration = self._nus_scenes[args[0] - 1]
                values = {"2.1": bright, "2.2": duration, "2.3": 1}
            else:
                if not 1 <= args[0] <= 4:
                    raise ValueError
                scene = (args[0], max(1, min(100, args[1])), max(5000, min(60000, args[2])))
                values = {"2.1": scene[1], "2.2": scene[2]}
            items = []
            for key, value in values.items():
                definition = self.model.property_by_key[key]
                if not definition.writable:
                    raise ValueError
                items.append((key, definition.validate(value)))
        except (KeyError, ValueError, TypeError):
            self.last_error = "Invalid or unsupported NUS command"
            self._nus_message(flag, {"code": 1}, now)
            return
        request = self._request("set", 0, NUS_TX, items=tuple(items),
                                action_key="nus_set_scene" if scene else None,
                                args=(("scene_id", scene[0]),) if scene else ())
        metadata = {"transport": "nus", "flag": flag, "scene": scene, "received_at": now}
        self._queue_request(request, metadata, now)

    def _nus_reply_set(self, record: dict[str, Any], statuses: Mapping[str, int]) -> None:
        flag = record["flag"]
        if record.get("failed") or any(code != 0 for code in statuses.values()):
            self._nus_message(flag, {"code": 1}, record["received_at"])
            return
        if record["scene"] is not None:
            scene_id, bright, duration = record["scene"]
            scenes = list(self._nus_scenes)
            scenes[scene_id - 1] = (bright, duration)
            self._nus_scenes = tuple(scenes)
        current = self._nus_properties()
        pair = (current.get("bright"), current.get("dur"))
        self._nus_scene_number = next((index for index, scene in enumerate(self._nus_scenes, 1) if scene == pair), 0)
        current["snm"] = self._nus_scene_number
        fields = {"set_power": ("power",), "set_bright": ("bright",), "set_duration": ("dur",),
                  "set_dur": ("dur",), "set_bridur": ("bright", "dur"), "apply_fixed_scene": ("snm", "bright", "dur")}
        if flag == "set_scene":
            result = {"id": scene_id, "bright": bright, "dur": duration}
        else:
            result = {key: current[key] for key in fields[flag] if key in current}
        self._nus_message(flag, result, record["received_at"])

    def _write_auth(self, data: bytes, now: float, channel: int = CHANNEL_AUTH) -> None:
        if self.model.auth_mode == "standard_nus":
            self._last_auth_channel = channel
        if len(data) >= 4 and data[:2] == b"\x00\x00" and data[2] in (4, 5):
            if (data[2] == 4 and data[3] == 1) or (data[2] == 5 and data[3] == 0):
                self._info_sent = False
                self._emit_auth([b"\x00\x00\x05\x01" + b"\x12" * 16])
                self._channel_info_at = now + 0.250
            elif data[2:4] == b"\x05\x01" and not self._info_sent:
                self._device_info()
                self._channel_info_at = None
            return
        if self.model.auth_mode == "psk" and not self._auth_rx.count and data[:2] != b"\x00\x00" and len(data) in (13, 16, 26, 28, 64):
            self._psk_payload(0, data, now)
            return
        acknowledgements, complete = self._auth_rx.feed(data, now, acknowledge_single=False)
        self._emit_auth(acknowledgements)
        if self._auth_rx.error:
            self.last_error = self._auth_rx.error
        if complete is None:
            return
        package_type, payload = complete
        if self.model.auth_mode == "psk":
            if self._state == "login_random" and package_type in (0, 3) and len(payload) == 64:
                self._psk_public_key(payload)
            elif self._state == "login_random" and package_type == 0x0B and len(payload) == 16:
                if self._psk_login_key_ready:
                    self._login_random(payload, now)
                else:
                    self.last_error = "Experimental PSK login is awaiting the application public key"
            elif self._state == "login_confirm" and package_type == 0x0A:
                self._login_confirm(payload, now)
            else:
                self._psk_payload(package_type, payload, now)
            return
        if self._state == "register_key" and len(payload) == 64:
            self._register_key(payload)
        elif self._state == "register_cloud" and (
            (package_type == 0x07 and 1 <= len(payload) <= MAX_FRAME_SIZE)
            or (package_type == 0x00 and len(payload) in (24, 163))
        ):
            # The phone can wait for this receipt before sending its cloud DID.
            if not self._certificate_received:
                self._certificate_received = True
                self._result(0x11)
            self._finish_registration()
        elif self._state == "register_cloud" and len(payload) == 92:
            self._register_did(payload)
        elif self._state == "login_random" and package_type == 0x0B and len(payload) == 16:
            self._login_random(payload, now)
        elif self._state == "login_confirm" and package_type == 0x0A:
            self._login_confirm(payload, now)

    def _public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]

    def _psk_public_key(self, payload: bytes) -> None:
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + payload)
            shared = self._private_key.exchange(ec.ECDH(), peer)
        except ValueError:
            self.last_error = "Invalid experimental PSK public key"
            self._result(0x22)
            return
        relogin = self._state == "login_random"
        self._psk_keys = _hkdf(
            shared, b"smartcfg-login-salt" if relogin else b"smartcfg-setup-salt",
            b"smartcfg-login-info" if relogin else b"smartcfg-setup-info",
        )
        if relogin:
            self._psk_login_key_ready = True
            return
        if self._psk_device_random is None:
            self._psk_device_random = secrets.token_bytes(16)
        self._psk_handshake()

    def _psk_handshake(self) -> None:
        if self._psk_keys is None or self._psk_device_random is None:
            return
        if not self._psk_start:
            self._device_info()
        body = self._psk_device_random + self._psk_app_random
        confirm = hmac.digest(self._psk_keys[:32], body, "sha256")
        der_signature = self._private_key.sign(body, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der_signature)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        self._emit_auth(_parcel(0x0D, self._psk_device_random) + _parcel(3, self._public_key())
                   + _parcel(0x0C, confirm) + _parcel(4, signature))
        self._psk_stage = "wait_server_pub"
        self._state = "psk_setup"

    def _psk_payload(self, package_type: int, payload: bytes, now: float) -> None:
        if package_type == 0 and len(payload) in (26, 28) and self._psk_stage in ("wait_start", "wait_pub"):
            self._begin_application_session(clear_notifications=False)
            self._authenticated = False
            self._session = None
            self._psk_start = payload
            self._psk_keys = None
            self._psk_device_random = None
            self._psk_app_random = bytes(16)
            self._pending_psk_identity = None
            self._psk_stage = "wait_pub"
            self._state = "psk_setup"
            self._device_info()
        elif package_type in (0, 3) and len(payload) == 64 and self._psk_stage in ("wait_start", "wait_pub", "wait_server_pub"):
            self._psk_public_key(payload)
        elif len(payload) == 16 and (package_type == 0x0B or (package_type == 0 and self._psk_stage == "wait_pub")):
            self._psk_app_random = payload
            if self._psk_keys is not None:
                self._psk_handshake()
        elif package_type == 0 and len(payload) == 16 and self._psk_stage == "wait_server_pub" and self._psk_keys is not None:
            self._psk_server_public = payload
            self._psk_stage = "wait_bind"
        elif package_type == 0 and len(payload) == 13 and self._psk_stage == "wait_bind" and self._psk_keys is not None:
            did = payload.strip(b"\x00")
            if not did or len(did) > 20 or not all(0x30 <= byte <= 0x39 for byte in did):
                self.last_error = "Invalid experimental PSK cloud DeviceID"
                return
            self._pending_psk_identity = {"version": 1, "pid": self.pid, "mac": self.mac,
                                          "auth_scheme": "psk", "did": did.decode("ascii"),
                                          "psk_key": self._psk_keys[:32].hex()}
            self._psk_stage = "pending_identity"
            self.last_error = "Experimental PSK beacon credentials are unconfirmed; binding is not supported"
        else:
            self.last_error = "Unsupported experimental PSK payload"

    def _register_key(self, payload: bytes) -> None:
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + payload)
            shared = self._private_key.exchange(ec.ECDH(), peer)
        except ValueError:
            self.last_error = "Invalid registration public key"
            self._result(0x22)
            self._state = "idle"
            self._info_at = None
            return
        setup = _hkdf(shared, bytes(16), b"mible-setup-info")
        self._registration = {
            "version": 1,
            "pid": self.pid,
            "mac": self.mac,
            "token": setup[:12].hex(),
            "bind_key": setup[12:28].hex(),
            "dev_key": setup[28:44].hex(),
            "auth_scheme": "standard",
        }
        public_key = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]
        random = secrets.token_bytes(16)
        confirm = hmac.digest(shared, random + bytes(16), "sha256")
        self._emit_auth(_parcel(3, public_key) + _parcel(0x0D, random) + _parcel(0x0C, confirm))
        self._state = "register_cloud"
        self._info_at = None

    def _register_did(self, payload: bytes) -> None:
        if self._registration is None:
            return
        try:
            plaintext = AESCCM(bytes.fromhex(self._registration["dev_key"]), tag_length=4).decrypt(
                bytes(range(0x10, 0x1C)), payload, b"devID"
            )
            if len(plaintext) != 88:
                raise ValueError
            did = plaintext[:20].strip(b"\x00").decode("ascii")
            if not did or "\x00" in did:
                raise ValueError
        except (InvalidTag, ValueError, UnicodeError):
            self.last_error = "Cloud identity authentication failed"
            self._result(0x22)
            self._state = "idle"
            self._registration = None
            return
        candidate = {
            **self._registration,
            "did": did,
            "sign": plaintext[20:84].hex(),
            "utc": struct.unpack_from("<I", plaintext, 84)[0],
        }
        self._registration = self._validate_identity(candidate)
        self._pending_identity = dict(self._registration)

    def commit_identity(self, expected: dict[str, Any] | None = None) -> None:
        """Call only after saving pending_identity successfully and durably."""
        if self._pending_identity is None:
            raise ProtocolError("No identity is awaiting persistence")
        if expected is not None and expected != self._pending_identity:
            raise ProtocolError("Persisted identity does not match the pending identity")
        self._identity = self._pending_identity
        self._pending_identity = None
        if self._identity.get("auth_scheme") == "legacy_rc4":
            self._authenticated = self._connected and self._legacy_logged_in
        self._finish_registration()

    def reject_identity(self) -> None:
        self._pending_identity = None
        self._registration = None
        self._state = "idle"
        self._result(0x22)
        self.last_error = "Identity persistence failed"

    def _finish_registration(self) -> None:
        if (
            self._certificate_received
            and self._registration is not None
            and self._identity == self._registration
            and self._pending_identity is None
        ):
            self._state = "idle"
            self._certificate_received = False

    def _login_random(self, random: bytes, now: float) -> None:
        if self.model.auth_mode == "psk":
            if self._psk_keys is None or not self._psk_login_key_ready:
                return
            key, info = self._psk_keys[:32], b"smartcfg-login-info"
        else:
            if self._identity is None:
                return
            key, info = bytes.fromhex(self._identity["token"]), b"mible-login-info"
        self._app_random = random
        self._device_random = secrets.token_bytes(16)
        self._session = _hkdf(
            key, random + self._device_random, info
        )
        self._confirm = hmac.digest(self._session[:16], self._device_random + random, "sha256")
        self._emit_auth(_parcel(0x0D, self._device_random))
        self._confirm_count = 0
        self._confirm_at = now + 0.120
        self._state = "login_confirm"

    def _login_confirm(self, payload: bytes, now: float) -> None:
        if self._session is None or self._app_random is None or self._device_random is None:
            return
        expected = hmac.digest(self._session[16:32], self._app_random + self._device_random, "sha256")
        self._confirm_at = None
        if len(payload) not in (16, 32) or not hmac.compare_digest(payload, expected[: len(payload)]):
            self._session = None
            self._authenticated = False
            self._state = "idle"
            self.last_error = "Login confirmation failed"
            self._result(0xE2)
            return
        self._authenticated = True
        self._state = "idle"
        self._tx_sequence = 0
        self._last_rx_sequence = -1
        self._last_rx_wire = b""
        self._result(0x21)
        self._snapshot_at = now + 1.0

    def poll(self, now: float | None = None) -> None:
        if not self._connected:
            return
        now = time.monotonic() if now is None else now
        for receiver in (self._auth_rx, self._spec_rx):
            receiver.expire(now)
            if receiver.error:
                self.last_error = receiver.error
        if self._channel_info_at is not None and now >= self._channel_info_at:
            if not self._info_sent:
                self._device_info(self._link_info_channel)
            self._channel_info_at = None
        if self._link_probe_at is not None and now >= self._link_probe_at:
            self._link_probe_at = None
            if not self._channel_ready:
                channel = next((item for item in (self._link_probe_channel, CHANNEL_SPEC, CHANNEL_SPEC_WRITE) if item in self._notify_channels), None)
                if channel is not None:
                    self._emit(channel, [bytes.fromhex("000004000612")])
        if self._info_at is not None and now >= self._info_at:
            if self._state == "register_key" and self._info_count < 4:
                self._device_info()
                self._info_count += 1
                self._info_at = now + 0.400
            else:
                self._info_at = None
        if self._confirm_at is not None and now >= self._confirm_at:
            if self._state == "login_confirm" and self._confirm is not None and self._confirm_count < 4:
                self._emit_auth(_parcel(0x0C, self._confirm))
                self._confirm_count += 1
                self._confirm_at = now + 0.400
            else:
                self._confirm_at = None
        if self._snapshot_at is not None and now >= self._snapshot_at and not self._outgoing:
            self._snapshot_at = None
            self.send_snapshot()
        for record in tuple(self._requests.values()):
            if now >= record["deadline"]:
                request = record["request"]
                record["failed"] = True
                if request.kind == "set":
                    self.reply_set(request, {})
                else:
                    self.reply_action(request, 1, {})
        if self._legacy_random_at is not None and now >= self._legacy_random_at:
            channel = self._legacy_reply_channel(self._legacy_random_channel)
            if channel not in self._notify_channels and now - self._legacy_random_started < 1.2:
                self._legacy_random_at = now + 0.050
            else:
                self._legacy_random_at = None
                self._emit(channel, [self._legacy_random])
        if self._nus_queue and now >= self._nus_queue[0][0] and NUS_TX in self._notify_channels:
            if len(self._nus_queue[0][1]) <= self._mtu - 3:
                self._emit(NUS_TX, [self._nus_queue.popleft()[1]])

    def set_property_values(self, values: Mapping[str, Any]) -> None:
        """Replace the complete available-value snapshot supplied by the host."""
        current = {}
        available = {}
        for key, value in values.items():
            definition = self.model.property_by_key.get(key)
            if definition is None:
                raise ProtocolError("Property does not belong to the selected model")
            if value is not None:
                value = definition.validate(value)
                available[key] = value
                if getattr(definition, "spec_visible", True):
                    current[(definition.siid, definition.piid)] = (definition.type_code, value)
        changed = {key: value for key, value in current.items() if self.properties.get(key) != value}
        self.properties = current
        self._property_values = available
        if changed and self.logged_in:
            self._send_properties(changed)

    @staticmethod
    def _value(object_id: int, value: int | float) -> tuple[int, int | float, bytes]:
        if object_id == 0x4805:
            if not math.isfinite(float(value)):
                raise ValueError("Illuminance must be finite")
            normalized = float(math.floor(min(1000.0, max(0.0, float(value))) + 0.5))
            return 9, normalized, struct.pack("<f", normalized)
        valid = {
            0x484E: (0, 1, 2),
            0x4852: (0, 2, 5, 10, 30),
            0x4851: (0, 2, 5),
        }
        if object_id == 0x100A:
            if value != int(value) or not 0 <= value <= 100:
                raise ValueError("Invalid battery percentage")
        elif object_id not in valid or value not in valid[object_id]:
            raise ValueError("Invalid occupancy property")
        return 1, int(value), bytes([int(value)])

    def set_properties(
        self,
        presence: int | bool | None,
        lux: float | None = 0.0,
        no_presence_minutes: int = 0,
        presence_minutes: int = 0,
        battery: int = 100,
    ) -> None:
        if self.model.model != DEFAULT_MODEL:
            raise ProtocolError("Occupancy convenience API requires the occupancy model")
        current = {}
        values = {0x484E: presence, 0x4805: lux, 0x4852: no_presence_minutes, 0x4851: presence_minutes, 0x100A: battery}
        for object_id, value in values.items():
            if value is None or (object_id in (0x4852, 0x4851) and not value):
                continue
            _, normalized, _ = self._value(object_id, value)
            siid, piid = OBJECT_PROPERTIES[object_id]
            current[f"{siid}.{piid}"] = normalized
        self.set_property_values(current)

    def _encoded_property(self, key: str, value: Any) -> bytes:
        definition = self.model.property_by_key[key]
        raw = definition.encode(value)
        if len(raw) > 0xFFF:
            raise ProtocolError("Spec property exceeds its encoded length range")
        return struct.pack("<H", (definition.type_code << 12) | len(raw)) + raw

    def _send_properties(self, properties: dict[tuple[int, int], tuple[int, Any]]) -> None:
        entries = []
        size = 6
        for (siid, piid), (_, value) in properties.items():
            if not getattr(self.model.property_by_key[f"{siid}.{piid}"], "notify", True):
                continue
            encoded = bytes([siid]) + struct.pack("<H", piid) + self._encoded_property(f"{siid}.{piid}", value)
            if 6 + len(encoded) > MAX_FRAME_SIZE - 6:
                raise ProtocolError("A property notification exceeds the spec packet capacity")
            if entries and (size + len(encoded) > MAX_FRAME_SIZE - 6 or len(entries) == MAX_SPEC_ITEMS):
                self._send_spec(4, self._tx_sequence, bytes([len(entries)]) + b"".join(entries))
                entries, size = [], 6
            entries.append(encoded)
            size += len(encoded)
        if entries:
            self._send_spec(4, self._tx_sequence, bytes([len(entries)]) + b"".join(entries))

    def send_snapshot(self) -> None:
        """Queue the current protocol properties after authentication."""
        if self.logged_in and self.properties:
            self._send_properties(self.properties)

    def hello(self, counter: int = 0) -> bytes:
        capability = 0x09 if self.model.auth_mode == "standard_nus" else 0x11
        return b"\x70\x2a" + struct.pack("<H", self.pid) + bytes([counter & 0xFF]) + self.mac_air + bytes([capability]) + b"\x11\x10\x01\x00"

    def beacon(
        self,
        object_id: int,
        value: Any,
        counter: int,
        *,
        pairing: bool = False,
        include_mac: bool = False,
    ) -> bytes:
        definition = next((field for field in self.model.beacons if field.object_id == object_id), None)
        if definition is None:
            raise ProtocolError("No beacon codec is defined for this object")
        if self.model.model == DEFAULT_MODEL:
            _, value, _ = self._value(object_id, value)
        encoded = definition.encode(value)
        return self.beacon_object(object_id, encoded, counter, pairing=pairing, include_mac=include_mac)

    def beacon_object(
        self, object_id: int, payload: bytes, counter: int, *, pairing: bool = False, include_mac: bool = False
    ) -> bytes:
        if self._identity is None:
            raise PersistenceRequired("A persisted cloud identity is required for encrypted beacons")
        if not 0 <= counter < COUNTER_LIMIT:
            raise ProtocolError("Beacon counter is outside its 32-bit range")
        if not 0 <= object_id <= 0xFFFF or len(payload) > 4:
            raise ProtocolError("Beacon object exceeds the single-object legacy advertising budget")
        obj = struct.pack("<HB", object_id, len(payload)) + bytes(payload)
        nonce = self.mac_air + struct.pack("<HI", self.pid, counter)
        encrypted = AESCCM(bytes.fromhex(self._identity["bind_key"]), tag_length=4).encrypt(nonce, obj, b"\x11")
        header = bytes([0x58 if include_mac else 0x48, 0x5B if pairing else 0x59]) + struct.pack("<H", self.pid) + bytes([counter & 0xFF])
        if include_mac:
            header += self.mac_air
        return header + encrypted[:-4] + struct.pack("<I", counter)[1:] + encrypted[-4:]

    @staticmethod
    def _encode_value(type_code: int, value: Any) -> bytes:
        encoded = _encode_raw(type_code, value)
        if len(encoded) > 0xFFF:
            raise ProtocolError("Spec value exceeds its encoded length range")
        return struct.pack("<H", (type_code << 12) | len(encoded)) + encoded

    @staticmethod
    def _spec_plain(opcode: int, tid: int, body: bytes = b"") -> bytes:
        if 5 + len(body) > MAX_FRAME_SIZE - 6:
            raise ProtocolError("Spec plaintext exceeds packet capacity")
        return struct.pack("<HHB", 0x2000 | (5 + len(body)), tid & 0xFFFF, opcode) + body

    def _send_spec(self, opcode: int, tid: int, body: bytes = b"", *, channel: int | None = None) -> tuple[bytes, ...]:
        if not self.logged_in or self._session is None:
            return ()
        if self._tx_sequence >= 1 << 16:
            self.disconnect()
            raise ProtocolError("Spec sequence exhausted; establish a new session")
        sequence = self._tx_sequence
        nonce = self._session[32:36] + bytes(4) + struct.pack("<I", sequence)
        wire = struct.pack("<H", sequence) + AESCCM(self._session[:16], tag_length=4).encrypt(
            nonce, self._spec_plain(opcode, tid, body), None
        )
        frames = tuple(_parcel(0, wire))
        self._emit(self._spec_channel() if channel is None else channel, list(frames))
        self._tx_sequence += 1
        return frames

    def _write_spec(self, channel: int, data: bytes, now: float) -> None:
        if not self.logged_in or self._session is None:
            return
        self._last_spec_channel = channel
        response_channel = self._spec_channel(channel)
        acknowledgements, complete = self._spec_rx.feed(data, now, acknowledge_single=True)
        self._emit(response_channel, acknowledgements)
        if self._spec_rx.error:
            self.last_error = self._spec_rx.error
        if complete is None:
            return
        _, wire = complete
        if len(wire) < 6:
            self.last_error = "Truncated encrypted spec frame"
            return
        sequence = struct.unpack_from("<H", wire)[0]
        cached = self._inbound.get(sequence)
        if cached is not None:
            if cached["wire"] != wire:
                self.last_error = "Replayed or reused spec sequence"
            elif cached["completed"] and cached["response"]:
                self._emit(self._spec_channel(cached["channel"]), list(cached["response"]))
            return
        if sequence < self._last_rx_sequence or (
            sequence == self._last_rx_sequence and wire != self._last_rx_wire
        ):
            self.last_error = "Replayed or reused spec sequence"
            return
        nonce = self._session[36:40] + bytes(4) + struct.pack("<I", sequence)
        try:
            plain = AESCCM(self._session[16:32], tag_length=4).decrypt(nonce, wire[2:], None)
        except InvalidTag:
            self.last_error = "Spec frame authentication failed"
            return
        self._last_rx_sequence, self._last_rx_wire = sequence, wire
        while len(self._inbound) >= MAX_REPLAY_CACHE:
            removable = next((key for key, record in self._inbound.items() if record["completed"]), None)
            if removable is None:
                self.last_error = "Too many uncompleted spec requests"
                return
            del self._inbound[removable]
        self._inbound[sequence] = {"wire": wire, "channel": response_channel, "completed": False, "response": ()}
        self._dispatch_spec(plain, sequence, response_channel, now)

    def _reply_spec(self, sequence: int, opcode: int, tid: int, body: bytes = b"") -> None:
        cached = self._inbound[sequence]
        channel = self._spec_channel(cached["channel"])
        cached["response"] = self._send_spec(opcode, tid, body, channel=channel)
        cached["completed"] = True

    def _dispatch_spec(self, plain: bytes, sequence: int, response_channel: int, now: float) -> None:
        if len(plain) < 5 or struct.unpack_from("<H", plain)[0] != (0x2000 | len(plain)):
            self.last_error = "Invalid spec frame header"
            self._inbound[sequence]["completed"] = True
            return
        tid = struct.unpack_from("<H", plain, 2)[0]
        opcode, body = plain[4], plain[5:]
        if opcode == 0xF0 and not body:
            self._reply_spec(sequence, 0xF0, tid)
        elif opcode == 2 and body and len(body) == 1 + body[0] * 3 and body[0] <= MAX_SPEC_ITEMS:
            reply = bytearray(body[:1])
            value_budget = MAX_FRAME_SIZE - 12 - body[0] * 5
            for offset in range(1, len(body), 3):
                siid, piid = body[offset], struct.unpack_from("<H", body, offset + 1)[0]
                value = self.properties.get((siid, piid))
                encoded = self._encoded_property(f"{siid}.{piid}", value[1]) if value is not None else b""
                if len(encoded) > value_budget:
                    value, encoded = None, b""
                value_budget -= len(encoded)
                reply += struct.pack("<BHH", siid, piid, 0 if value is not None else 1)
                if value is not None:
                    reply += encoded
            self._reply_spec(sequence, 3, tid, bytes(reply))
        elif opcode == 0:
            self._dispatch_set(tid, body, sequence, response_channel, now)
        elif opcode == 5 and len(body) >= 3:
            self._dispatch_action(tid, body, sequence, response_channel, now)
        else:
            self.last_error = "Unsupported or malformed spec request"
            self._inbound[sequence]["completed"] = True

    def _parse_set(self, body: bytes) -> tuple[tuple[str, int, Any], ...]:
        if not body or body[0] > MAX_SPEC_ITEMS:
            raise ProtocolError("Invalid spec SET count")
        candidates = []
        for legacy in (False, True):
            offset, items, score = 1, [], 0
            try:
                for _ in range(body[0]):
                    header_size = 6 if legacy else 5
                    if len(body) - offset < header_size:
                        raise ProtocolError("Truncated spec SET property")
                    siid, piid, encoded_type = struct.unpack_from("<BHH", body, offset)
                    type_code = encoded_type if legacy else encoded_type >> 12
                    length = body[offset + 5] if legacy else encoded_type & 0xFFF
                    offset += header_size
                    if offset + length > len(body):
                        raise ProtocolError("Truncated spec SET value")
                    key = f"{siid}.{piid}"
                    raw = body[offset : offset + length]
                    if (self.model.model == "xiaomi.diffuser.xwczxf" and key == "2.1032"
                            and type_code in (0, 1) and len(raw) == 1 and raw[0] in (0, 1, 4)):
                        # The upstream diffuser receives the on enum 4 in this bool field.
                        type_code, value = 0, bool(raw[0])
                    else:
                        try:
                            value = _decode_raw(type_code, raw)
                        except ProtocolError:
                            value = None
                    offset += length
                    definition = self.model.property_by_key.get(key)
                    score += int(definition is not None and definition.type_code == type_code)
                    items.append((key, type_code, value))
                if offset != len(body):
                    raise ProtocolError("Trailing spec SET data")
            except ProtocolError:
                continue
            candidates.append((score, not legacy, tuple(items)))
        if not candidates:
            raise ProtocolError("Malformed spec SET request")
        return max(candidates, key=lambda item: item[:2])[2]

    def _request(self, kind: str, tid: int, channel: int, **kwargs: Any) -> Request:
        self._next_request_id += 1
        return Request(kind, tid, self.session_id, self._next_request_id, channel, **kwargs)

    def _queue_request(self, request: Request, metadata: dict[str, Any], now: float) -> None:
        metadata.update(request=request, deadline=now + REQUEST_TIMEOUT)
        self._requests[request.request_id] = metadata
        callback = self.on_set if request.kind == "set" else self.on_action
        if callback is None or len(self._requests) > MAX_PENDING_REQUESTS:
            metadata["failed"] = True
            if request.kind == "set":
                self.reply_set(request, {})
            else:
                self.reply_action(request, 1, {})
            return
        try:
            callback(request)
        except Exception:
            metadata["failed"] = True
            self.last_error = "Application request handler failed"
            if request.kind == "set":
                self.reply_set(request, {})
            else:
                self.reply_action(request, 1, {})

    def _dispatch_set(self, tid: int, body: bytes, sequence: int, channel: int, now: float) -> None:
        try:
            parsed = self._parse_set(body)
        except ProtocolError as error:
            self.last_error = str(error)
            self._inbound[sequence]["completed"] = True
            return
        errors, valid, keys = {}, [], [key for key, _, _ in parsed]
        duplicates = {key for key in keys if keys.count(key) > 1}
        for key, type_code, value in parsed:
            definition = self.model.property_by_key.get(key)
            try:
                if key in duplicates or definition is None or not getattr(definition, "spec_visible", True) or not definition.writable or type_code != definition.type_code or value is None:
                    raise ValueError
                valid.append((key, definition.validate(value)))
            except (TypeError, ValueError):
                errors[key] = 1
        request = self._request("set", tid, channel, items=tuple(valid))
        metadata = {"sequence": sequence, "keys": tuple(keys), "errors": errors, "transport": "spec"}
        if not valid:
            self._requests[request.request_id] = {**metadata, "request": request}
            self.reply_set(request, {})
        else:
            self._queue_request(request, metadata, now)

    @staticmethod
    def _result_code(value: int) -> int:
        if not isinstance(value, int) or not -32768 <= value <= 65535:
            raise ProtocolError("Invalid spec result code")
        return value & 0xFFFF

    def _pending_request(self, request: Request) -> dict[str, Any] | None:
        record = self._requests.get(request.request_id)
        if not self.logged_in or request.session_id != self.session_id or record is None or record["request"] is not request:
            return None
        return record

    def reply_set(self, request: Request, results: Mapping[str, int]) -> bool:
        record = self._pending_request(request)
        if record is None or request.kind != "set":
            return False
        statuses = {key: self._result_code(results.get(key, 1)) for key, _ in request.items}
        statuses.update(record.get("errors", {}))
        updated = {}
        for key, value in request.items:
            if statuses.get(key) == 0:
                definition = self.model.property_by_key[key]
                updated[(definition.siid, definition.piid)] = (definition.type_code, value)
        if record["transport"] == "nus":
            if updated and record["scene"] is None:
                self.properties.update(updated)
                self._property_values.update({f"{siid}.{piid}": value for (siid, piid), (_, value) in updated.items()})
            self._nus_reply_set(record, statuses)
        else:
            body = bytearray([len(record["keys"])])
            for key in record["keys"]:
                siid, piid = map(int, key.split("."))
                body += struct.pack("<BHH", siid, piid, statuses.get(key, 1))
            self._reply_spec(record["sequence"], 1, request.tid, bytes(body))
            if updated:
                self.properties.update(updated)
                self._property_values.update({f"{siid}.{piid}": value for (siid, piid), (_, value) in updated.items()})
                self._send_properties(updated)
        del self._requests[request.request_id]
        return True

    def _dispatch_action(self, tid: int, body: bytes, sequence: int, channel: int, now: float) -> None:
        key = f"{body[0]}.{body[1]}"
        action = next((item for item in self.model.actions if item.key == key), None)
        args, offset = [], 3
        try:
            if action is None or body[2] > MAX_SPEC_ITEMS:
                raise ProtocolError("Unknown action or excessive argument count")
            for _ in range(body[2]):
                if len(body) - offset < 4:
                    raise ProtocolError("Truncated action argument")
                piid, encoded_type = struct.unpack_from("<HH", body, offset)
                type_code, length = encoded_type >> 12, encoded_type & 0xFFF
                offset += 4
                if offset + length > len(body):
                    raise ProtocolError("Truncated action value")
                property_key = f"{action.siid}.{piid}"
                definition = self.model.property_by_key.get(property_key)
                if definition is None or type_code != definition.type_code:
                    raise ProtocolError("Action argument type does not match schema")
                value = definition.validate(_decode_raw(type_code, body[offset : offset + length]))
                args.append((property_key, value))
                offset += length
            if offset != len(body) or len(args) != len(action.input_keys) or set(key for key, _ in args) != set(action.input_keys):
                raise ProtocolError("Action arguments do not match schema")
        except (TypeError, ValueError) as error:
            self.last_error = str(error)
            self._reply_spec(sequence, 6, tid, b"\x01\x00\x00")
            return
        request = self._request("action", tid, channel, action_key=key, args=tuple(args))
        self._queue_request(request, {"sequence": sequence, "action": action, "transport": "spec"}, now)

    def reply_action(self, request: Request, result: int, outputs: Mapping[str, Any] | None = None) -> bool:
        record = self._pending_request(request)
        if record is None or request.kind != "action":
            return False
        result = self._result_code(result)
        action, outputs = record["action"], outputs or {}
        encoded_outputs = []
        if result == 0:
            try:
                for key in action.output_keys:
                    definition = self.model.property_by_key[key]
                    value = outputs[key]
                    encoded_outputs.append(bytes([definition.piid]) + self._encoded_property(key, value))
                if 8 + sum(map(len, encoded_outputs)) > MAX_FRAME_SIZE - 6:
                    raise ProtocolError("Action outputs exceed the spec packet capacity")
            except (KeyError, TypeError, ValueError):
                result, encoded_outputs = 1, []
        body = struct.pack("<HB", result, len(encoded_outputs)) + b"".join(encoded_outputs)
        self._reply_spec(record["sequence"], 6, request.tid, body)
        del self._requests[request.request_id]
        return True

    def send_event(self, key: str, arguments: Mapping[str, Any] | None = None) -> None:
        event = next((item for item in self.model.events if item.key == key), None)
        if event is None:
            raise ProtocolError("Event does not belong to this model")
        arguments = self.property_values if arguments is None else arguments
        body = bytes([event.siid]) + struct.pack("<HB", event.eiid, len(event.argument_keys))
        for property_key in event.argument_keys:
            definition = self.model.property_by_key[property_key]
            body += struct.pack("<H", definition.piid) + self._encoded_property(property_key, arguments[property_key])
        self._send_spec(7, self._tx_sequence, body)


Protocol = MiotProtocol
