"""MIoT occupancy protocol, independent of Home Assistant and the BLE transport.

Ported from miot-ble-sdk, revision e9058f09ad2b1040d8a79d6aa2a7fb79767892a1.
Copyright (c) 2026 miot-ble-sdk contributors.
The upstream miot-ble-sdk Non-Commercial License applies to this derived port.
"""

from __future__ import annotations

from collections import deque
import hmac
import math
import secrets
import struct
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PID = 0x4683
MODEL = "xiaomi.sensor_occupy.03"
CHANNEL_CONTROL = 0x0010
CHANNEL_AUTH = 0x0019
CHANNEL_SPEC = 0x001A
CHANNEL_SPEC_WRITE = 0x001B
MAX_NOTIFICATIONS = 128
MAX_FRAME_SIZE = 512
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
    """One cloud identity and one authenticated connection for one radar."""

    def __init__(self, mac: str, identity: dict[str, Any] | None = None) -> None:
        normal_mac = _mac_bytes(mac)
        self.mac = ":".join(f"{part:02X}" for part in normal_mac)
        self.mac_air = normal_mac[::-1]
        self._identity = self._validate_identity(identity) if identity else None
        self._pending_identity: dict[str, Any] | None = None
        self._outgoing: deque[tuple[int, bytes]] = deque()
        self._values: dict[int, bytes] = {}
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._auth_rx = _Receiver()
        self._spec_rx = _Receiver()
        self._connected = False
        self.last_error: str | None = None
        self.properties: dict[tuple[int, int], tuple[int, int | float]] = {}
        self._reset_session()
        self.set_properties(0)

    def _validate_identity(self, identity: dict[str, Any]) -> dict[str, Any]:
        try:
            if identity.get("version", 1) != 1 or identity["pid"] != PID:
                raise ValueError
            if _mac_bytes(identity["mac"]) != _mac_bytes(self.mac):
                raise ValueError
            for key, length in (("token", 12), ("bind_key", 16), ("dev_key", 16), ("sign", 64)):
                if len(bytes.fromhex(identity[key])) != length:
                    raise ValueError
            did = identity["did"].encode("ascii")
            if not 1 <= len(did) <= 20 or b"\x00" in did:
                raise ValueError
            if not 0 <= identity["utc"] < COUNTER_LIMIT:
                raise ValueError
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            raise ValueError("Stored MIoT identity is invalid or belongs to another address") from error
        return {
            "version": 1,
            "pid": PID,
            "mac": self.mac,
            "token": identity["token"],
            "bind_key": identity["bind_key"],
            "dev_key": identity["dev_key"],
            "did": identity["did"],
            "sign": identity["sign"],
            "utc": identity["utc"],
        }

    @property
    def identity(self) -> dict[str, Any] | None:
        return dict(self._identity) if self._identity is not None else None

    @property
    def pending_identity(self) -> dict[str, Any] | None:
        return dict(self._pending_identity) if self._pending_identity is not None else None

    @property
    def bound(self) -> bool:
        return self._identity is not None

    @property
    def logged_in(self) -> bool:
        return self._session is not None and self._authenticated

    def _reset_session(self) -> None:
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
        self._tx_sequence = 0
        self._last_rx_sequence = -1
        self._last_rx_wire = b""
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
        if any(len(frame) > 20 for frame in frames):
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
        return self._values.get(channel, b"")

    def _result(self, value: int) -> None:
        self._emit(CHANNEL_CONTROL, [bytes([value, 0, 0, 0])])

    def _device_info(self) -> None:
        did = self._identity["did"].encode("ascii") if self._identity else b""
        payload = b"\x02\x00\x00\x00" + did
        frames = [b"\x00\x00\x02\x00" + payload] if len(payload) <= 16 else _parcel(0, payload)
        self._emit(CHANNEL_AUTH, frames)
        self._info_sent = True

    def write(self, channel: int, data: bytes, now: float | None = None) -> None:
        if not self._connected or not data:
            return
        now = time.monotonic() if now is None else now
        data = bytes(data)
        if len(data) > MAX_FRAME_SIZE:
            self.last_error = "GATT write exceeds receive capacity"
            return
        if channel == CHANNEL_CONTROL:
            if data == b"\xa4" or data == b"\xa4\x00\x00\x00":
                self._emit(CHANNEL_AUTH, [b"\x00\x00\x04\x00\x06\x12"])
                self._info_sent = False
                self._channel_info_at = None
                return
            if data in (b"\xa2\x00\x00\x00", b"\x22\x00\x00\x00"):
                self._authenticated = False
                self._session = None
                self._registration = None
                self._certificate_received = False
                self._state = "register_key"
                self._device_info()
                self._info_count = 1
                self._info_at = now + 0.150
                return
            if data == b"\x24\x00\x00\x00":
                if not self.bound:
                    self._result(0xE2)
                    return
                self._state = "login_random"
                self._authenticated = False
                self._session = None
                self._confirm_at = None
                self._info_at = None
                return
            if data == b"\x13\x00\x00\x00":
                # Cloud DID, rather than this unauthenticated result, grants identity.
                return
        if channel == CHANNEL_AUTH:
            self._write_auth(data, now)
        elif channel in (CHANNEL_CONTROL, CHANNEL_SPEC, CHANNEL_SPEC_WRITE):
            self._write_spec(data, now)
        else:
            self.last_error = "Unknown GATT channel"

    def _write_auth(self, data: bytes, now: float) -> None:
        if len(data) >= 4 and data[:2] == b"\x00\x00" and data[2] in (4, 5):
            if (data[2] == 4 and data[3] == 1) or (data[2] == 5 and data[3] == 0):
                self._info_sent = False
                self._emit(CHANNEL_AUTH, [b"\x00\x00\x05\x01" + b"\x12" * 16])
                self._channel_info_at = now + 0.250
            elif data[2:4] == b"\x05\x01" and not self._info_sent:
                self._device_info()
                self._channel_info_at = None
            return
        acknowledgements, complete = self._auth_rx.feed(data, now, acknowledge_single=False)
        self._emit(CHANNEL_AUTH, acknowledgements)
        if self._auth_rx.error:
            self.last_error = self._auth_rx.error
        if complete is None:
            return
        package_type, payload = complete
        if self._state == "register_key" and len(payload) == 64:
            self._register_key(payload)
        elif self._state == "register_cloud" and len(payload) == 92:
            self._register_did(payload)
        elif self._state == "register_cloud" and len(payload) in (24, 163):
            # The phone can wait for this receipt before sending its cloud DID.
            if not self._certificate_received:
                self._certificate_received = True
                self._result(0x11)
            self._finish_registration()
        elif self._state == "login_random" and package_type == 0x0B and len(payload) == 16:
            self._login_random(payload, now)
        elif self._state == "login_confirm" and package_type == 0x0A:
            self._login_confirm(payload, now)

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
            "pid": PID,
            "mac": self.mac,
            "token": setup[:12].hex(),
            "bind_key": setup[12:28].hex(),
            "dev_key": setup[28:44].hex(),
        }
        public_key = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]
        random = secrets.token_bytes(16)
        confirm = hmac.digest(shared, random + bytes(16), "sha256")
        self._emit(CHANNEL_AUTH, _parcel(3, public_key) + _parcel(0x0D, random) + _parcel(0x0C, confirm))
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
        if self._identity is None:
            return
        self._app_random = random
        self._device_random = secrets.token_bytes(16)
        self._session = _hkdf(
            bytes.fromhex(self._identity["token"]), random + self._device_random, b"mible-login-info"
        )
        self._confirm = hmac.digest(self._session[:16], self._device_random + random, "sha256")
        self._emit(CHANNEL_AUTH, _parcel(0x0D, self._device_random))
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
                self._device_info()
            self._channel_info_at = None
        if self._info_at is not None and now >= self._info_at:
            if self._state == "register_key" and self._info_count < 4:
                self._device_info()
                self._info_count += 1
                self._info_at = now + 0.400
            else:
                self._info_at = None
        if self._confirm_at is not None and now >= self._confirm_at:
            if self._state == "login_confirm" and self._confirm is not None and self._confirm_count < 4:
                self._emit(CHANNEL_AUTH, _parcel(0x0C, self._confirm))
                self._confirm_count += 1
                self._confirm_at = now + 0.400
            else:
                self._confirm_at = None
        if self._snapshot_at is not None and now >= self._snapshot_at and not self._outgoing:
            self._snapshot_at = None
            self.send_snapshot()

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
        previous = self.properties
        current: dict[tuple[int, int], tuple[int, int | float]] = {}
        values = {0x484E: presence, 0x4805: lux, 0x4852: no_presence_minutes, 0x4851: presence_minutes, 0x100A: battery}
        for object_id, value in values.items():
            if value is None or (object_id in (0x4852, 0x4851) and not value):
                continue
            type_code, normalized, _ = self._value(object_id, value)
            current[OBJECT_PROPERTIES[object_id]] = (type_code, normalized)
        self.properties = current
        changed = {key: value for key, value in current.items() if previous.get(key) != value}
        if changed and self.logged_in:
            self._send_properties(changed)

    def _send_properties(self, properties: dict[tuple[int, int], tuple[int, int | float]]) -> None:
        body = bytes([len(properties)]) + b"".join(
            bytes([siid]) + struct.pack("<H", piid) + self._encode_value(*value)
            for (siid, piid), value in properties.items()
        )
        self._send_spec(4, self._tx_sequence, body)

    def send_snapshot(self) -> None:
        """Queue the current protocol properties after authentication."""
        if self.logged_in and self.properties:
            self._send_properties(self.properties)

    def hello(self, counter: int = 0) -> bytes:
        return b"\x70\x2a" + struct.pack("<H", PID) + bytes([counter & 0xFF]) + self.mac_air + b"\x11\x11\x10\x01\x00"

    def beacon(
        self,
        object_id: int,
        value: int | float,
        counter: int,
        *,
        pairing: bool = False,
        include_mac: bool = False,
    ) -> bytes:
        if self._identity is None:
            raise PersistenceRequired("A persisted cloud identity is required for encrypted beacons")
        if not 0 <= counter < COUNTER_LIMIT:
            raise ProtocolError("Beacon counter is outside its 32-bit range")
        _, _, encoded = self._value(object_id, value)
        obj = struct.pack("<HB", object_id, len(encoded)) + encoded
        nonce = self.mac_air + struct.pack("<HI", PID, counter)
        encrypted = AESCCM(bytes.fromhex(self._identity["bind_key"]), tag_length=4).encrypt(nonce, obj, b"\x11")
        header = bytes([0x58 if include_mac else 0x48, 0x5B if pairing else 0x59]) + struct.pack("<H", PID) + bytes([counter & 0xFF])
        if include_mac:
            header += self.mac_air
        return header + encrypted[:-4] + struct.pack("<I", counter)[1:] + encrypted[-4:]

    @staticmethod
    def _encode_value(type_code: int, value: int | float) -> bytes:
        encoded = struct.pack("<f", float(value)) if type_code == 9 else bytes([int(value)])
        return struct.pack("<H", (type_code << 12) | len(encoded)) + encoded

    @staticmethod
    def _spec_plain(opcode: int, tid: int, body: bytes = b"") -> bytes:
        return struct.pack("<HHB", 0x2000 | (5 + len(body)), tid & 0xFFFF, opcode) + body

    def _send_spec(self, opcode: int, tid: int, body: bytes = b"") -> None:
        if not self.logged_in or self._session is None:
            return
        if self._tx_sequence >= 1 << 16:
            self.disconnect()
            raise ProtocolError("Spec sequence exhausted; establish a new session")
        sequence = self._tx_sequence
        nonce = self._session[32:36] + bytes(4) + struct.pack("<I", sequence)
        wire = struct.pack("<H", sequence) + AESCCM(self._session[:16], tag_length=4).encrypt(
            nonce, self._spec_plain(opcode, tid, body), None
        )
        self._emit(CHANNEL_CONTROL, _parcel(0, wire))
        self._tx_sequence += 1

    def _write_spec(self, data: bytes, now: float) -> None:
        if not self.logged_in or self._session is None:
            return
        acknowledgements, complete = self._spec_rx.feed(data, now, acknowledge_single=True)
        self._emit(CHANNEL_CONTROL, acknowledgements)
        if self._spec_rx.error:
            self.last_error = self._spec_rx.error
        if complete is None:
            return
        _, wire = complete
        if len(wire) < 6:
            self.last_error = "Truncated encrypted spec frame"
            return
        sequence = struct.unpack_from("<H", wire)[0]
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
        self._dispatch_spec(plain)

    def _dispatch_spec(self, plain: bytes) -> None:
        if len(plain) < 5 or struct.unpack_from("<H", plain)[0] != (0x2000 | len(plain)):
            self.last_error = "Invalid spec frame header"
            return
        tid = struct.unpack_from("<H", plain, 2)[0]
        opcode, body = plain[4], plain[5:]
        if opcode == 0xF0 and not body:
            self._send_spec(0xF0, tid)
        elif opcode == 2 and body and len(body) == 1 + body[0] * 3 and body[0] <= 32:
            reply = bytearray(body[:1])
            for offset in range(1, len(body), 3):
                siid, piid = body[offset], struct.unpack_from("<H", body, offset + 1)[0]
                value = self.properties.get((siid, piid))
                reply += struct.pack("<BHH", siid, piid, 0 if value is not None else 1)
                if value is not None:
                    reply += self._encode_value(*value)
            self._send_spec(3, tid, bytes(reply))
        elif opcode == 0:
            self._reject_set(tid, body)
        elif opcode == 5 and len(body) >= 3:
            # This occupancy model exposes no writable actions.
            self._send_spec(6, tid, b"\x01\x00\x00")
        else:
            self.last_error = "Unsupported or malformed spec request"

    def _reject_set(self, tid: int, body: bytes) -> None:
        if not body or body[0] > 32:
            self.last_error = "Invalid spec SET request"
            return
        reply = bytearray(body[:1])
        offset = 1
        for _ in range(body[0]):
            if len(body) - offset < 5:
                self.last_error = "Truncated spec SET property"
                return
            siid, piid, type_length = struct.unpack_from("<BHH", body, offset)
            length = type_length & 0x0FFF
            if type_length >> 12 == 0 and len(body) - offset != 5 + length:
                if len(body) - offset < 6 or type_length > 10:
                    self.last_error = "Invalid spec SET value"
                    return
                length = body[offset + 5]
                offset += 1
            offset += 5 + length
            if offset > len(body):
                self.last_error = "Truncated spec SET value"
                return
            reply += struct.pack("<BHH", siid, piid, 1)
        if offset != len(body):
            self.last_error = "Trailing spec SET data"
            return
        self._send_spec(1, tid, bytes(reply))


Protocol = MiotProtocol
