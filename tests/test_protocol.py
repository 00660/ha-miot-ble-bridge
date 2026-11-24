"""Protocol regression tests with an independent phone-side crypto oracle."""

from __future__ import annotations

import importlib.util
import hmac
import json
from pathlib import Path
import struct
import sys
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

COMPONENT_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "miot_ble_bridge"
PACKAGE = "miot_protocol_test_package"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(COMPONENT_PATH)]
sys.modules[PACKAGE] = package
SPEC = importlib.util.spec_from_file_location(f"{PACKAGE}.protocol", COMPONENT_PATH / "protocol.py")
assert SPEC is not None and SPEC.loader is not None
protocol = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol
SPEC.loader.exec_module(protocol)
models = sys.modules[f"{PACKAGE}.models"]

MAC = "D4:3B:04:5E:2A:10"
IDENTITY = {
    "version": 1,
    "mac": MAC,
    "pid": 0x4683,
    "token": bytes(range(12)).hex(),
    "bind_key": bytes(range(16)).hex(),
    "dev_key": bytes(range(16, 32)).hex(),
    "did": "blt.3.test0000001",
    "sign": bytes(range(64)).hex(),
    "utc": 1795480000,
}


def deliver_parcel(device, package_type, payload, channel=0x0019, now=0.0):
    chunks = [payload[i : i + 18] for i in range(0, len(payload), 18)]
    device.write(channel, b"\x00\x00\x00" + bytes([package_type]) + struct.pack("<H", len(chunks)), now)
    for number, chunk in enumerate(chunks, start=1):
        device.write(channel, struct.pack("<H", number) + chunk, now)


def decode_parcels(notifications, channel=0x0019):
    results = []
    current = None
    for message_channel, data in notifications:
        if message_channel != channel:
            continue
        if data[:3] == b"\x00\x00\x00":
            current = [data[3], struct.unpack_from("<H", data, 4)[0], []]
        elif data[:3] == b"\x00\x00\x02":
            results.append((data[3], data[4:]))
        elif data[:2] != b"\x00\x00" and current is not None:
            current[2].append(data[2:])
            if len(current[2]) == current[1]:
                results.append((current[0], b"".join(current[2])))
                current = None
    return results


def establish_login(device, now=0.0, *, connect=True):
    if connect:
        device.connect(now)
    device.write(0x0010, b"\x24\x00\x00\x00", now)
    app_random = bytes(range(0xA0, 0xB0))
    deliver_parcel(device, 0x0B, app_random, now=now)
    messages = decode_parcels(device.drain_notifications())
    device_random = next(payload for kind, payload in messages if kind == 0x0D)
    session = HKDF(hashes.SHA256(), 64, app_random + device_random, b"mible-login-info").derive(
        bytes.fromhex(device.identity["token"])
    )
    device.poll(now + 0.121)
    confirmations = decode_parcels(device.drain_notifications())
    device_confirm = next(payload for kind, payload in confirmations if kind == 0x0C)
    assert hmac.compare_digest(device_confirm, hmac.digest(session[:16], device_random + app_random, "sha256"))
    confirm = hmac.digest(session[16:32], app_random + device_random, "sha256")
    deliver_parcel(device, 0x0A, confirm, now=now + 0.122)
    result = device.drain_notifications()
    assert (0x0010, b"\x21\x00\x00\x00") in result
    assert device.logged_in
    return session


def encrypt_phone_spec(session, plaintext, sequence=0):
    nonce = session[36:40] + bytes(4) + struct.pack("<I", sequence)
    return struct.pack("<H", sequence) + AESCCM(session[16:32], tag_length=4).encrypt(nonce, plaintext, None)


def decrypt_device_spec(session, notifications, channel=0x0010):
    packets = decode_parcels(notifications, channel=channel)
    replies = []
    for _, wire in packets:
        sequence = struct.unpack_from("<H", wire)[0]
        nonce = session[32:36] + bytes(4) + struct.pack("<I", sequence)
        replies.append(AESCCM(session[:16], tag_length=4).decrypt(nonce, wire[2:], None))
    return replies


TYPE_VECTORS = (
    (0, True, "B"), (1, 255, "B"), (2, -120, "b"), (3, 65000, "H"),
    (4, -32000, "h"), (5, 4000000000, "I"), (6, -2000000000, "i"),
    (7, (1 << 63) + 17, "Q"), (8, -(1 << 62), "q"), (9, -12.5, "f"),
    (10, "测试桥接", None),
)


def phone_value(type_code, value):
    fmt = TYPE_VECTORS[type_code][2]
    raw = value.encode("utf-8") if fmt is None else struct.pack("<" + fmt, value)
    return struct.pack("<H", (type_code << 12) | len(raw)) + raw


def phone_plain(opcode, tid, body=b""):
    return struct.pack("<HHB", 0x2000 | (5 + len(body)), tid, opcode) + body


def codec_model():
    return models.ModelDefinition(
        "bridge.test.codec", "Codec test", 0x1234,
        properties=tuple(
            models.PropertyDefinition(f"Value {index}", 2, index, type_code, value, writable=index != 9)
            for index, (type_code, value, _) in enumerate(TYPE_VECTORS, 1)
        ),
        beacons=(models.BeaconDefinition(0x1234, "2.3", "i8"),),
        actions=(models.ActionDefinition("2.1", "Sync", 2, 1, ("2.6", "2.11"),
                                         ("2.1", "2.3", "2.8", "2.10", "2.11")),),
        events=(models.EventDefinition("2.e.1", "Changed", 2, 1, ("2.3", "2.11")),),
        gatt_strategy="prefer_source",
    )


LEGACY_TOKEN = bytes.fromhex(IDENTITY["token"])
LEGACY_IDENTITY = {
    "version": 1, "mac": MAC, "pid": 0x03DD, "auth_scheme": "legacy_rc4",
    "token": IDENTITY["token"], "bind_key": IDENTITY["bind_key"],
    "did": IDENTITY["did"], "utc": IDENTITY["utc"], "mac_order": "air",
}


def phone_rc4(key, payload):
    permutation = list(range(256))
    cursor = 0
    for index, value in enumerate(permutation):
        cursor = (cursor + value + key[index % len(key)]) % 256
        permutation[index], permutation[cursor] = permutation[cursor], permutation[index]
    output = []
    left = right = 0
    for byte in payload:
        left = (left + 1) % 256
        right = (right + permutation[left]) % 256
        permutation[left], permutation[right] = permutation[right], permutation[left]
        output.append(byte ^ permutation[(permutation[left] + permutation[right]) % 256])
    return bytes(output)


def night_light_model():
    return models.ModelDefinition(
        "MUE4094RT", "Night light", 0x03DD,
        properties=(
            models.PropertyDefinition("Brightness", 2, 1, 1, 60, True, 1, 100),
            models.PropertyDefinition("Duration", 2, 2, 5, 25000, True, 5000, 60000),
            models.PropertyDefinition("Power", 2, 3, 1, 1, True, 0, 1),
            models.PropertyDefinition("Battery", 3, 1, 1, 100, False, 0, 100),
        ),
        auth_mode="standard_nus", gatt_strategy="prefer_source",
    )


def new_night_light(identity=None, on_set=None):
    model = night_light_model()
    with patch.object(protocol, "get_model", return_value=model):
        device = protocol.MiotProtocol(MAC, identity, model.model, on_set=on_set)
    device.connect(0.0)
    device.set_notify_channels({0x0001, 0x001A, 0x001B, protocol.NUS_TX})
    device.set_mtu(247)
    device.drain_notifications()
    return device


def establish_legacy_login(device, now=0.0):
    random = bytes.fromhex("11223344")
    with patch.object(protocol.secrets, "token_bytes", return_value=random):
        device.write(0x0001, bytes.fromhex("00bc43cd"), now)
    device.poll(now + 0.041)
    assert (0x0001, random) in device.drain_notifications()
    key = bytes(value ^ random[index] if index < 4 else value for index, value in enumerate(LEGACY_TOKEN))
    device.write(0x0001, phone_rc4(key, struct.pack("<I", 0x93BFAC09)), now + 0.042)
    assert device.drain_notifications() == [(0x0001, phone_rc4(key, struct.pack("<I", 0x369A58C9)))]
    assert device.logged_in
    return key


class BeaconTests(unittest.TestCase):
    def setUp(self):
        self.device = protocol.MiotProtocol(MAC, IDENTITY)

    def test_presence_known_ciphertext_vector(self):
        # Fixed oracle from independently executed cryptography AESCCM.
        self.assertEqual(
            self.device.beacon(0x484E, 1, 0x12345678).hex(),
            "48598346782d68637b563412017f2f64",
        )

    def test_float_known_ciphertext_vector(self):
        self.assertEqual(
            self.device.beacon(0x4805, 0.0, 0x12345678).hex(),
            "48598346786668667ab5f69956341212721c0c",
        )

    def test_embedded_mac_and_pairing_flag(self):
        frame = self.device.beacon(0x484E, 1, 0x12345678, include_mac=True, pairing=True)
        self.assertEqual(frame[:11].hex(), "585b834678102a5e043bd4")
        self.assertEqual(frame[11:].hex(), "2d68637b563412017f2f64")

    def test_unbound_hello_and_identity_barrier(self):
        unbound = protocol.MiotProtocol(MAC)
        self.assertEqual(unbound.hello(0x78).hex(), "702a834678102a5e043bd41111100100")
        with self.assertRaises(protocol.PersistenceRequired):
            unbound.beacon(0x484E, 1, 0)

    def test_object_validation_and_illuminance_limits(self):
        for value in (float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                self.device.beacon(0x4805, value, 1)
        with self.assertRaises(ValueError):
            self.device.beacon(0x484E, 3, 1)
        with self.assertRaises(protocol.ProtocolError):
            self.device.beacon(0x484E, 1, 1 << 32)
        self.device.set_properties(1, 2000.0)
        self.assertEqual(self.device.properties[(2, 1005)], (9, 1000.0))
        self.device.set_properties(1, -1.0)
        self.assertEqual(self.device.properties[(2, 1005)], (9, 0.0))

    def test_identity_cannot_migrate_to_another_address_or_product(self):
        for changes in ({"mac": "D4:3B:04:5E:2A:11"}, {"pid": 0x55B}, {"did": ""}, {"token": "00"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                protocol.MiotProtocol(MAC, {**IDENTITY, **changes})


class CounterTests(unittest.TestCase):
    def test_persistence_required_before_first_frame(self):
        lease = protocol.CounterLease()
        self.assertEqual(lease.required_reservation(), 1024)
        with self.assertRaises(protocol.PersistenceRequired):
            lease.take()
        lease.commit_reservation(1024)
        self.assertEqual(lease.take(), 0)

    def test_crash_skips_unused_counters(self):
        original = protocol.CounterLease()
        durable_limit = original.required_reservation()
        original.commit_reservation(durable_limit)
        used = [original.take() for _ in range(17)]
        restarted = protocol.CounterLease(durable_limit)
        with self.assertRaises(protocol.PersistenceRequired):
            restarted.take()
        next_limit = restarted.required_reservation()
        self.assertEqual(next_limit, 2048)
        restarted.commit_reservation(next_limit)
        self.assertGreater(restarted.take(), max(used))

    def test_failed_or_stale_reservation_cannot_enable_frames(self):
        lease = protocol.CounterLease(1024)
        with self.assertRaises(protocol.ProtocolError):
            lease.commit_reservation(1024)
        with self.assertRaises(protocol.PersistenceRequired):
            lease.take()

    def test_counter_never_wraps(self):
        lease = protocol.CounterLease((1 << 32) - 1)
        lease.commit_reservation(1 << 32)
        self.assertEqual(lease.take(), (1 << 32) - 1)
        with self.assertRaises(protocol.ProtocolError):
            lease.take()


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.device = protocol.MiotProtocol(MAC)
        self.device.connect(0.0)

    def start_registration(self):
        self.device.write(0x0010, b"\xa2\x00\x00\x00", 0.0)
        self.device.drain_notifications()
        app_private = ec.derive_private_key(1, ec.SECP256R1())
        app_public = app_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]
        deliver_parcel(self.device, 3, app_public)
        packets = decode_parcels(self.device.drain_notifications())
        public_key = next(payload for kind, payload in packets if kind == 3)
        device_random = next(payload for kind, payload in packets if kind == 0x0D)
        device_confirm = next(payload for kind, payload in packets if kind == 0x0C)
        device_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + public_key)
        shared = app_private.exchange(ec.ECDH(), device_public)
        self.assertEqual(device_confirm, hmac.digest(shared, device_random + bytes(16), "sha256"))
        return HKDF(hashes.SHA256(), 64, bytes(16), b"mible-setup-info").derive(shared)

    def send_cloud_identity(self, setup):
        plaintext = IDENTITY["did"].encode("ascii").rjust(20, b"\x00") + bytes.fromhex(IDENTITY["sign"]) + struct.pack("<I", IDENTITY["utc"])
        encrypted = AESCCM(setup[28:44], tag_length=4).encrypt(bytes(range(0x10, 0x1C)), plaintext, b"devID")
        deliver_parcel(self.device, 6, encrypted)

    def send_observed_cloud_certificate(self):
        # Real trace: pkg 7, 22 fragments, 21 * 18 bytes plus one final byte.
        self.device.write(0x0019, bytes.fromhex("000000071600"), 0.2)
        for number in range(1, 22):
            self.device.write(0x0019, struct.pack("<H", number) + bytes(18), 0.2)
        self.device.write(0x0019, bytes.fromhex("160000"), 0.2)

    def test_a4_and_channel_initialization(self):
        self.device.write(0x0010, b"\xa4", 0.0)
        self.assertEqual(self.device.drain_notifications(), [(0x0019, bytes.fromhex("000004000612"))])
        self.device.write(0x0019, b"\x00\x00\x04\x01" + b"\x12" * 16, 0.0)
        self.assertEqual(self.device.drain_notifications(), [(0x0019, b"\x00\x00\x05\x01" + b"\x12" * 16)])
        self.device.write(0x0019, b"\x00\x00\x05\x01", 0.010)
        self.assertIn((0, b"\x02\x00\x00\x00"), decode_parcels(self.device.drain_notifications()))

    def test_register_requires_cloud_identity_and_acknowledged_storage(self):
        setup = self.start_registration()
        self.device.write(0x0010, b"\x13\x00\x00\x00", 0.0)
        self.assertFalse(self.device.bound)
        self.send_cloud_identity(setup)
        pending = self.device.pending_identity
        self.assertIsNotNone(pending)
        self.assertEqual(pending["did"], IDENTITY["did"])
        self.assertEqual(pending["token"], setup[:12].hex())
        self.assertEqual(pending["bind_key"], setup[12:28].hex())
        self.assertFalse(self.device.bound)
        deliver_parcel(self.device, 7, bytes(163))
        self.assertIn((0x0010, b"\x11\x00\x00\x00"), self.device.drain_notifications())
        self.assertFalse(self.device.bound)
        self.device.commit_identity(pending)
        self.assertTrue(self.device.bound)
        self.assertEqual(self.device.drain_notifications(), [])
        restarted = protocol.MiotProtocol(MAC, pending)
        self.assertTrue(restarted.bound)

    def test_certificate_first_acknowledges_before_cloud_did_and_save(self):
        for certificate_size in (24, 163):
            with self.subTest(certificate_size=certificate_size):
                self.setUp()
                setup = self.start_registration()
                deliver_parcel(self.device, 7, bytes(certificate_size))
                self.assertIn((0x0010, b"\x11\x00\x00\x00"), self.device.drain_notifications())
                self.assertFalse(self.device.bound)
                self.assertIsNone(self.device.pending_identity)
                self.assertEqual(self.device._state, "register_cloud")
                self.device.write(0x0010, b"\x13\x00\x00\x00", 0.1)
                self.assertFalse(self.device.bound)
                self.send_cloud_identity(setup)
                self.assertFalse(self.device.bound)
                pending = self.device.pending_identity
                self.assertEqual(pending["did"], IDENTITY["did"])
                self.device.drain_notifications()
                self.device.commit_identity(pending)
                self.assertTrue(self.device.bound)
                self.assertEqual(self.device._state, "idle")
                self.assertEqual(self.device.drain_notifications(), [])

    def test_saved_cloud_did_first_waits_for_certificate_receipt(self):
        setup = self.start_registration()
        self.send_cloud_identity(setup)
        pending = self.device.pending_identity
        self.device.drain_notifications()
        self.device.commit_identity(pending)
        self.assertTrue(self.device.bound)
        self.assertEqual(self.device.drain_notifications(), [])
        deliver_parcel(self.device, 7, bytes(24))
        results = [packet for channel, packet in self.device.drain_notifications() if channel == 0x0010]
        self.assertEqual(results, [b"\x11\x00\x00\x00"])
        self.assertEqual(self.device._state, "idle")

    def test_duplicate_certificate_does_not_duplicate_registration_receipt(self):
        setup = self.start_registration()
        deliver_parcel(self.device, 7, bytes(163))
        deliver_parcel(self.device, 7, bytes(163))
        results = [packet for channel, packet in self.device.drain_notifications() if channel == 0x0010]
        self.assertEqual(results, [b"\x11\x00\x00\x00"])
        self.assertFalse(self.device.bound)
        self.send_cloud_identity(setup)
        pending = self.device.pending_identity
        self.device.drain_notifications()
        self.device.commit_identity(pending)
        deliver_parcel(self.device, 7, bytes(163))
        results = [packet for channel, packet in self.device.drain_notifications() if channel == 0x0010]
        self.assertEqual(results, [])

    def test_observed_379_byte_certificate_after_saved_did_and_then_login(self):
        setup = self.start_registration()
        self.send_cloud_identity(setup)
        self.device.commit_identity(self.device.pending_identity)
        self.device.drain_notifications()
        self.assertTrue(self.device.bound)
        self.device.write(0x0019, bytes.fromhex("000000071600"), 0.2)
        self.assertEqual(self.device.drain_notifications(), [(0x0019, bytes.fromhex("00000101"))])
        for number in range(1, 22):
            frame = struct.pack("<H", number) + bytes(18)
            self.assertEqual(len(frame), 20)
            self.device.write(0x0019, frame, 0.2)
            self.assertEqual(self.device.drain_notifications(), [])
        final_frame = bytes.fromhex("160000")
        self.assertEqual(len(final_frame), 3)
        self.device.write(0x0019, final_frame, 0.2)
        self.assertEqual(
            self.device.drain_notifications(),
            [(0x0019, bytes.fromhex("00000100")), (0x0010, bytes.fromhex("11000000"))],
        )
        self.send_observed_cloud_certificate()
        self.assertTrue(all(channel == 0x0019 for channel, _ in self.device.drain_notifications()))
        establish_login(self.device, now=0.3, connect=False)
        self.assertTrue(self.device.logged_in)

    def test_observed_379_byte_certificate_before_did_and_then_login(self):
        setup = self.start_registration()
        self.send_observed_cloud_certificate()
        self.assertIn((0x0010, bytes.fromhex("11000000")), self.device.drain_notifications())
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        self.device.write(0x0010, bytes.fromhex("13000000"), 0.3)
        self.assertFalse(self.device.bound)
        self.send_cloud_identity(setup)
        self.assertFalse(self.device.bound)
        self.device.commit_identity(self.device.pending_identity)
        self.assertTrue(self.device.bound)
        self.assertTrue(all(channel == 0x0019 for channel, _ in self.device.drain_notifications()))
        establish_login(self.device, now=0.4, connect=False)
        self.assertTrue(self.device.logged_in)

    def test_legacy_channel_certificate_lengths_are_preserved(self):
        for size in (24, 163):
            with self.subTest(size=size):
                self.setUp()
                self.start_registration()
                deliver_parcel(self.device, 0, bytes(size))
                results = [packet for channel, packet in self.device.drain_notifications() if channel == 0x0010]
                self.assertEqual(results, [bytes.fromhex("11000000")])
                self.assertFalse(self.device.bound)

    def test_wrong_package_cannot_impersonate_certificate_by_length(self):
        for package_type, size in ((0, 379), (3, 24), (3, 163), (5, 24), (6, 163), (6, 379)):
            with self.subTest(package_type=package_type, size=size):
                self.setUp()
                self.start_registration()
                deliver_parcel(self.device, package_type, bytes(size))
                self.assertTrue(all(channel == 0x0019 for channel, _ in self.device.drain_notifications()))
                self.assertFalse(self.device.bound)
                self.assertIsNone(self.device.pending_identity)

    def test_certificate_payload_is_nonempty_and_bounded(self):
        for size in (0, 1, 92, 512, 513):
            with self.subTest(size=size):
                self.setUp()
                self.start_registration()
                if size == 0:
                    self.device.write(0x0019, bytes.fromhex("00000207"), 0.2)
                else:
                    deliver_parcel(self.device, 7, bytes(size))
                results = [packet for channel, packet in self.device.drain_notifications() if channel == 0x0010]
                self.assertEqual(results, [bytes.fromhex("11000000")] if 1 <= size <= 512 else [])
                self.assertFalse(self.device.bound)
                self.assertIsNone(self.device.pending_identity)

    def test_incomplete_379_byte_certificate_is_not_acknowledged(self):
        self.start_registration()
        self.device.write(0x0019, bytes.fromhex("000000071600"), 0.2)
        self.device.drain_notifications()
        for number in range(1, 22):
            if number != 10:
                self.device.write(0x0019, struct.pack("<H", number) + bytes(18), 0.2)
        self.device.write(0x0019, bytes.fromhex("160000"), 0.2)
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertFalse(self.device.bound)

    def test_certificate_without_authenticated_did_cannot_bind(self):
        self.start_registration()
        deliver_parcel(self.device, 7, bytes(163))
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        self.assertIn((0x0010, b"\x11\x00\x00\x00"), self.device.drain_notifications())

    def test_failed_save_does_not_complete_cloud_binding(self):
        setup = self.start_registration()
        self.send_cloud_identity(setup)
        deliver_parcel(self.device, 7, bytes(24))
        self.device.drain_notifications()
        self.device.reject_identity()
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        self.assertEqual(self.device.drain_notifications(), [(0x0010, b"\x22\x00\x00\x00")])

    def test_corrupt_cloud_identity_does_not_bind(self):
        self.start_registration()
        deliver_parcel(self.device, 6, bytes(92))
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        self.assertIn((0x0010, b"\x22\x00\x00\x00"), self.device.drain_notifications())

    def test_valid_identity_can_be_committed_after_disconnect(self):
        setup = self.start_registration()
        self.send_cloud_identity(setup)
        pending = self.device.pending_identity
        self.device.disconnect()
        self.device.commit_identity(pending)
        self.assertTrue(self.device.bound)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_stale_persistence_completion_is_rejected(self):
        setup = self.start_registration()
        self.send_cloud_identity(setup)
        with self.assertRaises(protocol.ProtocolError):
            self.device.commit_identity({**self.device.pending_identity, "did": "stale"})
        self.assertFalse(self.device.bound)

    def test_invalid_curve_point_aborts_registration(self):
        self.device.write(0x0010, b"\xa2\x00\x00\x00", 0.0)
        self.device.drain_notifications()
        deliver_parcel(self.device, 3, bytes(64))
        self.assertIsNone(self.device.pending_identity)
        self.assertIn((0x0010, b"\x22\x00\x00\x00"), self.device.drain_notifications())

    def test_registration_info_retries_are_bounded(self):
        self.device.write(0x0010, b"\xa2\x00\x00\x00", 0.0)
        packets = self.device.drain_notifications()
        for now in (0.151, 0.552, 0.953, 1.354, 5.0, 15.0):
            self.device.poll(now)
            packets += self.device.drain_notifications()
        self.assertEqual(len(decode_parcels(packets)), 4)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.device = protocol.MiotProtocol(MAC)
        self.device.connect(0.0)

    def test_duplicate_fragment_does_not_complete_incomplete_parcel(self):
        self.device.write(0x0019, bytes.fromhex("000000030200"), 0.0)
        self.device.drain_notifications()
        self.device.write(0x0019, b"\x01\x00" + bytes(18), 0.1)
        self.device.write(0x0019, b"\x01\x00" + bytes(18), 0.2)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.write(0x0019, b"\x02\x00" + bytes(18), 0.3)
        self.assertEqual(self.device.drain_notifications(), [(0x0019, b"\x00\x00\x01\x00")])

    def test_out_of_order_fragments_are_reassembled_once(self):
        self.device.write(0x0019, bytes.fromhex("000000030200"), 0.0)
        self.device.drain_notifications()
        self.device.write(0x0019, b"\x02\x00" + bytes(18), 0.1)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.write(0x0019, b"\x01\x00" + bytes(18), 0.2)
        self.assertEqual(self.device.drain_notifications(), [(0x0019, b"\x00\x00\x01\x00")])
        self.device.write(0x0019, b"\x02\x00" + bytes(18), 0.3)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_invalid_counts_truncated_frames_and_conflicting_duplicates(self):
        for data in (bytes.fromhex("000000030000"), bytes.fromhex("000000034100"), b"\x00\x00\x00", b"\x00\x00\x00\x03"):
            self.device.write(0x0019, data, 0.0)
            self.assertEqual(self.device.drain_notifications(), [])
            self.assertIsNotNone(self.device.last_error)
        self.device.write(0x0019, bytes.fromhex("000000030200"), 0.0)
        self.device.drain_notifications()
        self.device.write(0x0019, b"\x01\x00" + bytes(18), 0.1)
        self.device.write(0x0019, b"\x01\x00" + bytes([1]) * 18, 0.2)
        self.assertEqual(self.device.last_error, "Conflicting AG2 fragment")
        self.device.write(0x0019, b"\x02\x00" + bytes(18), 0.3)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_fragment_timeout_discards_stale_data(self):
        self.device.write(0x0019, bytes.fromhex("000000030100"), 0.0)
        self.device.drain_notifications()
        self.device.poll(5.001)
        self.device.write(0x0019, b"\x01\x00" + bytes(18), 5.002)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_queue_overflow_disconnects_instead_of_silently_dropping(self):
        for _ in range(protocol.MAX_NOTIFICATIONS):
            self.device.write(0x0010, b"\xa4", 0.0)
        with self.assertRaises(protocol.ProtocolError):
            self.device.write(0x0010, b"\xa4", 0.0)
        self.assertEqual(self.device.drain_notifications(), [])


class LoginAndSpecTests(unittest.TestCase):
    def setUp(self):
        self.device = protocol.MiotProtocol(MAC, IDENTITY)

    def test_login_and_disconnect_preserve_binding(self):
        establish_login(self.device)
        self.device.disconnect()
        self.assertTrue(self.device.bound)
        self.assertFalse(self.device.logged_in)
        self.assertEqual(self.device.read(0x0010), b"")
        self.assertEqual(self.device.drain_notifications(), [])

    def test_connect_reuses_startup_ec_key_without_generating_in_callback(self):
        startup_key = self.device._private_key
        with patch.object(protocol.ec, "generate_private_key", side_effect=AssertionError("Callback generated an EC key")):
            self.device.connect(0.0)
            self.device.disconnect()
            self.device.connect(1.0)
        self.assertIs(self.device._private_key, startup_key)

    def test_unbound_or_invalid_login_never_creates_spec_session(self):
        unbound = protocol.MiotProtocol(MAC)
        unbound.connect()
        unbound.write(0x0010, b"\x24\x00\x00\x00", 0.0)
        self.assertFalse(unbound.logged_in)
        self.device.connect()
        self.device.write(0x0010, b"\x24\x00\x00\x00", 0.0)
        deliver_parcel(self.device, 0x0B, bytes(16))
        self.device.drain_notifications()
        deliver_parcel(self.device, 0x0A, bytes(32), now=0.1)
        self.assertFalse(self.device.logged_in)
        self.assertIn((0x0010, b"\xe2\x00\x00\x00"), self.device.drain_notifications())

    def test_login_confirm_retries_are_bounded(self):
        self.device.connect()
        self.device.write(0x0010, b"\x24\x00\x00\x00", 0.0)
        deliver_parcel(self.device, 0x0B, bytes(16))
        self.device.drain_notifications()
        packets = []
        for now in (0.121, 0.522, 0.923, 1.324, 1.725, 5.0):
            self.device.poll(now)
            packets += self.device.drain_notifications()
        self.assertEqual([kind for kind, _ in decode_parcels(packets)], [0x0C] * 4)

    def test_spec_get_float_matches_independent_wire_layout(self):
        session = establish_login(self.device)
        self.device.set_properties(1, 123.0)
        self.device.drain_notifications()
        request = bytes.fromhex("0c203412020202ed03023604")
        deliver_parcel(self.device, 0, encrypt_phone_spec(session, request), channel=0x001A, now=0.2)
        notifications = self.device.drain_notifications()
        self.assertTrue(all(channel == 0x0010 for channel, _ in notifications))
        self.assertEqual(
            decrypt_device_spec(session, notifications),
            [bytes.fromhex("19203412030202ed03000004900000f6420236040000011001")],
        )

    def test_spec_version_exchange(self):
        session = establish_login(self.device)
        request = bytes.fromhex("052055aaf0")
        deliver_parcel(self.device, 0, encrypt_phone_spec(session, request), channel=0x0010, now=0.2)
        self.assertEqual(decrypt_device_spec(session, self.device.drain_notifications()), [request])

    def test_login_sends_snapshot_after_one_second(self):
        self.device.set_properties(1, 0.0)
        session = establish_login(self.device)
        self.device.poll(1.121)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.poll(1.123)
        replies = decrypt_device_spec(session, self.device.drain_notifications())
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0][4:6], b"\x04\x03")
        self.device.poll(2.0)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_corrupt_tag_and_reused_sequence_are_rejected(self):
        session = establish_login(self.device)
        request = bytes.fromhex("05200100f0")
        wire = encrypt_phone_spec(session, request)
        deliver_parcel(self.device, 0, wire[:-1] + bytes([wire[-1] ^ 1]), channel=0x001A, now=0.2)
        self.assertEqual(decrypt_device_spec(session, self.device.drain_notifications()), [])
        deliver_parcel(self.device, 0, wire, channel=0x001A, now=0.3)
        self.assertEqual(len(decrypt_device_spec(session, self.device.drain_notifications())), 1)
        second_request = bytes.fromhex("05200200f0")
        deliver_parcel(self.device, 0, encrypt_phone_spec(session, second_request), channel=0x001A, now=0.4)
        self.assertEqual(decrypt_device_spec(session, self.device.drain_notifications()), [])
        self.assertEqual(self.device.last_error, "Replayed or reused spec sequence")

    def test_missing_and_read_only_properties_return_errors(self):
        session = establish_login(self.device)
        get_unknown = bytes.fromhex("092012000201027f7f")
        deliver_parcel(self.device, 0, encrypt_phone_spec(session, get_unknown), channel=0x001A, now=0.2)
        self.assertEqual(
            decrypt_device_spec(session, self.device.drain_notifications()),
            [bytes.fromhex("0b2012000301027f7f0100")],
        )
        set_presence = bytes.fromhex("0c2013000001023604011000")
        deliver_parcel(self.device, 0, encrypt_phone_spec(session, set_presence, sequence=1), channel=0x001B, now=0.3)
        self.assertEqual(
            decrypt_device_spec(session, self.device.drain_notifications()),
            [bytes.fromhex("0b20130001010236040100")],
        )
        self.assertEqual(self.device.properties[(2, 1078)], (1, 0))

    def test_continuous_state_clear_and_virtual_lux_are_protocol_properties(self):
        self.device.set_properties(1, 0.0, presence_minutes=2)
        self.assertIn((2, 1081), self.device.properties)
        self.device.set_properties(0, 0.0, no_presence_minutes=2)
        self.assertNotIn((2, 1081), self.device.properties)
        self.assertEqual(self.device.properties[(2, 1082)], (1, 2))
        self.assertEqual(self.device.properties[(2, 1005)], (9, 0.0))

    def test_spec_tx_sequence_cannot_reuse_nonce(self):
        session = establish_login(self.device)
        self.device._tx_sequence = 1 << 16
        request = bytes.fromhex("05200100f0")
        with self.assertRaises(protocol.ProtocolError):
            deliver_parcel(self.device, 0, encrypt_phone_spec(session, request), channel=0x001A, now=0.2)
        self.assertFalse(self.device.logged_in)


class GenericSpecTests(unittest.TestCase):
    def setUp(self):
        self.model = codec_model()
        self.set_requests, self.action_requests = [], []
        with patch.object(protocol, "get_model", return_value=self.model):
            self.device = protocol.MiotProtocol(
                MAC, {**IDENTITY, "pid": self.model.pid}, self.model.model,
                on_set=self.set_requests.append, on_action=self.action_requests.append,
            )
        self.session = establish_login(self.device)
        self.device.set_notify_channels({0x001A, 0x001B})
        self.sequence = 0

    def send(self, opcode, body=b"", *, channel=0x001B, tid=0x3456, now=0.2):
        plain = phone_plain(opcode, tid, body)
        wire = encrypt_phone_spec(self.session, plain, self.sequence)
        self.sequence += 1
        deliver_parcel(self.device, 0, wire, channel=channel, now=now)
        return wire, self.device.drain_notifications()

    def set_body(self, items, *, legacy=False):
        body = bytes([len(items)])
        for piid, type_code, value in items:
            encoded = phone_value(type_code, value)
            body += struct.pack("<BH", 2, piid)
            body += struct.pack("<HB", type_code, len(encoded) - 2) + encoded[2:] if legacy else encoded
        return body

    def action_body(self):
        return b"\x02\x01\x02" + struct.pack("<H", 6) + phone_value(5, 37) + struct.pack("<H", 11) + phone_value(10, "同步")

    def test_all_scalar_types_get_matches_phone_wire_layout(self):
        body = bytes([len(TYPE_VECTORS)]) + b"".join(struct.pack("<BH", 2, index) for index in range(1, 12))
        _, notifications = self.send(2, body)
        expected = bytes([len(TYPE_VECTORS)]) + b"".join(
            struct.pack("<BHH", 2, index, 0) + phone_value(type_code, value)
            for index, (type_code, value, _) in enumerate(TYPE_VECTORS, 1)
        )
        self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B), [phone_plain(3, 0x3456, expected)])

    def test_model_pid_is_used_in_identity_hello_and_beacon_nonce(self):
        self.assertEqual(self.device.identity["pid"], 0x1234)
        self.assertEqual(self.device.hello()[2:4], b"\x34\x12")
        frame = self.device.beacon(0x1234, -12, 0x12345678)
        nonce = bytes.fromhex(MAC.replace(":", ""))[::-1] + struct.pack("<HI", 0x1234, 0x12345678)
        encrypted = frame[5:-7] + frame[-4:]
        self.assertEqual(AESCCM(bytes.fromhex(IDENTITY["bind_key"]), tag_length=4).decrypt(nonce, encrypted, b"\x11"),
                         bytes.fromhex("341201f4"))
        with patch.object(protocol, "get_model", return_value=self.model), self.assertRaises(ValueError):
            protocol.MiotProtocol(MAC, IDENTITY, self.model.model)

    def test_source_channel_and_subscription_fallback(self):
        _, notifications = self.send(0xF0)
        self.assertEqual({channel for channel, _ in notifications}, {0x001B})
        self.device.set_notify_channels({0x001A})
        _, notifications = self.send(0xF0)
        self.assertEqual({channel for channel, _ in notifications}, {0x001A})
        self.device.set_notify_channels(set())
        _, notifications = self.send(0xF0)
        self.assertEqual({channel for channel, _ in notifications}, {0x0010})

    def test_auxiliary_gatt_reads_use_real_model_identity(self):
        self.assertEqual(self.device.read(0x0001), bytes.fromhex(IDENTITY["token"]))
        self.assertEqual(self.device.read(0x0002), b"\x34\x12")
        self.assertEqual(self.device.read(0x0004), b"9.9.9_9999")
        self.assertEqual(self.device.read(0x0013), IDENTITY["did"].encode("ascii").rjust(20, b"\x00"))
        self.assertEqual(self.device.read(0x0014), bytes.fromhex(IDENTITY["bind_key"]))
        self.assertEqual(self.device.read(0x001B), b"\x02")
        self.assertEqual([self.device.read(channel) for channel in (0x0016, 0x0017, 0x0018)], [b"\x00"] * 3)

    def test_set_waits_for_host_success_then_notifies_the_committed_value(self):
        _, notifications = self.send(0, self.set_body(((2, 1, 42),)))
        self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B), [])
        self.assertEqual(self.device.property_values["2.2"], 255)
        request = self.set_requests[0]
        self.assertEqual(request.items, (("2.2", 42),))
        self.assertTrue(self.device.reply_set(request, {"2.2": 0}))
        replies = decrypt_device_spec(self.session, self.device.drain_notifications(), 0x001B)
        self.assertEqual(replies[0], phone_plain(1, 0x3456, bytes.fromhex("010202000000")))
        self.assertEqual(replies[1][4:], bytes.fromhex("040102020001102a"))
        self.assertEqual(self.device.property_values["2.2"], 42)
        self.assertFalse(self.device.reply_set(request, {"2.2": 0}))

    def test_failed_set_does_not_change_the_mirror(self):
        self.send(0, self.set_body(((2, 1, 42),)))
        self.device.reply_set(self.set_requests[0], {"2.2": -4004})
        replies = decrypt_device_spec(self.session, self.device.drain_notifications(), 0x001B)
        self.assertEqual(replies, [phone_plain(1, 0x3456, struct.pack("<BBHH", 1, 2, 2, (-4004) & 0xFFFF))])
        self.assertEqual(self.device.property_values["2.2"], 255)

    def test_legacy_set_layout_is_parsed_as_a_complete_packet(self):
        self.send(0, self.set_body(((2, 1, 42), (3, 2, -11), (11, 10, "亮灯")), legacy=True))
        self.assertEqual(self.set_requests[0].items, (("2.2", 42), ("2.3", -11), ("2.11", "亮灯")))

    def test_read_only_unknown_bad_type_and_invalid_utf8_never_execute(self):
        body = self.set_body(((9, 8, -17), (99, 1, 1), (2, 3, 42)))
        body = b"\x04" + body[1:] + struct.pack("<BHH", 2, 11, 0xA001) + b"\xff"
        _, notifications = self.send(0, body)
        self.assertEqual(self.set_requests, [])
        reply = decrypt_device_spec(self.session, notifications, 0x001B)[0]
        self.assertEqual(reply[4:6], b"\x01\x04")
        self.assertEqual(self.device.property_values["2.2"], 255)

    def test_duplicate_set_key_is_rejected_without_mutating_the_host(self):
        _, notifications = self.send(0, self.set_body(((2, 1, 42), (2, 1, 43))))
        self.assertEqual(self.set_requests, [])
        self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B),
                         [phone_plain(1, 0x3456, bytes.fromhex("0202020001000202000100"))])

    def test_set_retransmission_executes_once_and_replays_identical_ciphertext(self):
        wire, _ = self.send(0, self.set_body(((2, 1, 42),)))
        deliver_parcel(self.device, 0, wire, channel=0x001B, now=0.3)
        self.device.drain_notifications()
        self.assertEqual(len(self.set_requests), 1)
        self.device.reply_set(self.set_requests[0], {"2.2": 0})
        first_response = decode_parcels(self.device.drain_notifications(), 0x001B)[0]
        tx_sequence = self.device._tx_sequence
        deliver_parcel(self.device, 0, wire, channel=0x001B, now=0.4)
        self.assertEqual(decode_parcels(self.device.drain_notifications(), 0x001B), [first_response])
        self.assertEqual(self.device._tx_sequence, tx_sequence)
        self.assertEqual(len(self.set_requests), 1)

    def test_late_set_reply_is_rejected_after_reconnect(self):
        self.send(0, self.set_body(((2, 1, 42),)))
        old_request = self.set_requests[0]
        self.session = establish_login(self.device, now=1.0)
        self.assertNotEqual(old_request.session_id, self.device.session_id)
        self.assertFalse(self.device.reply_set(old_request, {"2.2": 0}))
        self.assertEqual(self.device.property_values["2.2"], 255)

    def test_unanswered_set_times_out_and_reports_failure(self):
        self.send(0, self.set_body(((2, 1, 42),)))
        self.device.poll(20.201)
        replies = decrypt_device_spec(self.session, self.device.drain_notifications(), 0x001B)
        self.assertEqual([reply for reply in replies if reply[4] == 1],
                         [phone_plain(1, 0x3456, bytes.fromhex("010202000100"))])
        self.assertEqual(self.device.pending_requests, ())
        self.assertEqual(self.device.property_values["2.2"], 255)

    def test_callback_failure_reports_error_and_preserves_state(self):
        def broken_handler(request):
            raise RuntimeError("HA service unavailable")
        self.device.on_set = broken_handler
        _, notifications = self.send(0, self.set_body(((2, 1, 42),)))
        self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B),
                         [phone_plain(1, 0x3456, bytes.fromhex("010202000100"))])
        self.assertEqual(self.device.last_error, "Application request handler failed")
        self.assertEqual(self.device.property_values["2.2"], 255)

    def test_pending_request_survives_completed_replay_cache_eviction(self):
        with patch.object(protocol, "MAX_REPLAY_CACHE", 4):
            wire, _ = self.send(0, self.set_body(((2, 1, 42),)))
            for _ in range(6):
                self.send(0xF0)
            deliver_parcel(self.device, 0, wire, channel=0x001B, now=0.3)
            self.assertEqual(len(self.set_requests), 1)
            self.assertEqual(len(self.device.pending_requests), 1)
            self.assertTrue(self.device.reply_set(self.set_requests[0], {"2.2": 0}))

    def test_action_waits_for_host_and_returns_all_outputs_with_piid8(self):
        _, notifications = self.send(5, self.action_body())
        self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B), [])
        request = self.action_requests[0]
        self.assertEqual(request.action_key, "2.1")
        self.assertEqual(request.args, (("2.6", 37), ("2.11", "同步")))
        outputs = {key: self.device.property_values[key] for key in self.model.actions[0].output_keys}
        self.device.reply_action(request, 0, outputs)
        expected = b"\x00\x00\x05" + b"".join(
            bytes([int(key.split(".")[1])]) + phone_value(self.model.property_by_key[key].type_code, outputs[key])
            for key in self.model.actions[0].output_keys
        )
        self.assertEqual(decrypt_device_spec(self.session, self.device.drain_notifications(), 0x001B),
                         [phone_plain(6, 0x3456, expected)])

    def test_missing_action_output_is_failure_instead_of_partial_success(self):
        self.send(5, self.action_body())
        self.device.reply_action(self.action_requests[0], 0, {"2.1": True})
        self.assertEqual(decrypt_device_spec(self.session, self.device.drain_notifications(), 0x001B),
                         [phone_plain(6, 0x3456, b"\x01\x00\x00")])

    def test_malformed_action_never_calls_the_host(self):
        for body in (b"\x02\x63\x00", self.action_body()[:-1], self.action_body() + b"\x00"):
            _, notifications = self.send(5, body)
            self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B),
                             [phone_plain(6, 0x3456, b"\x01\x00\x00")])
        self.assertEqual(self.action_requests, [])

    def test_event_has_eiid16_and_typed_piid16_arguments(self):
        self.send(0xF0)
        self.device.send_event("2.e.1", {"2.3": -17, "2.11": "有人"})
        expected = b"\x02\x01\x00\x02" + struct.pack("<H", 3) + phone_value(2, -17) + struct.pack("<H", 11) + phone_value(10, "有人")
        reply = decrypt_device_spec(self.session, self.device.drain_notifications(), 0x001B)[0]
        self.assertEqual(reply[4:], b"\x07" + expected)

    def test_complete_snapshot_omits_unavailable_properties(self):
        self.device.set_property_values({"2.2": 42, "2.11": None})
        self.assertEqual(self.device.property_values, {"2.2": 42})
        body = b"\x02" + struct.pack("<BH", 2, 2) + struct.pack("<BH", 2, 11)
        self.device.drain_notifications()
        _, notifications = self.send(2, body)
        expected = b"\x02" + struct.pack("<BHH", 2, 2, 0) + phone_value(1, 42) + struct.pack("<BHH", 2, 11, 1)
        self.assertEqual(decrypt_device_spec(self.session, notifications, 0x001B), [phone_plain(3, 0x3456, expected)])

    def test_integer_encoder_accepts_integral_values_and_rejects_fractional_values(self):
        self.assertEqual(self.device._encode_value(1, 1.0), bytes.fromhex("011001"))
        for value in (1.2, None, float("nan"), 256):
            with self.subTest(value=value), self.assertRaises(protocol.ProtocolError):
                self.device._encode_value(1, value)


class LegacyNightLightTests(unittest.TestCase):
    def setUp(self):
        self.device = new_night_light()

    def adopt_token(self):
        self.device.write(0x0010, bytes.fromhex("90ca85de"), 0.0)
        self.assertEqual(self.device.drain_notifications(), [])
        encrypted = phone_rc4(bytes.fromhex("105ed4dddd3bd42a"), LEGACY_TOKEN)
        self.device.write(0x0001, encrypted, 0.1)
        expected = phone_rc4(bytes.fromhex("105ed4033b10d4dd"), encrypted)
        self.assertEqual(self.device.drain_notifications(), [(0x0001, expected)])

    def register(self, save=True):
        self.adopt_token()
        self.device.write(0x0001, phone_rc4(LEGACY_TOKEN, struct.pack("<I", 0xFA54AB92)), 0.2)
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        self.device.write(0x0013, IDENTITY["did"].encode("ascii").rjust(20, b"\x00"), 0.3)
        pending = self.device.pending_identity
        self.assertIsNotNone(pending)
        if save:
            self.device.commit_identity(pending)
        return pending

    def test_rc4_matches_known_external_vector_and_phone_oracle(self):
        expected = bytes.fromhex("bbf316e8d940af0ad3")
        self.assertEqual(phone_rc4(b"Key", b"Plaintext"), expected)
        self.assertEqual(protocol._rc4(b"Key", b"Plaintext"), expected)

    def test_token_ack_and_bond_wait_for_real_did_and_durable_identity(self):
        pending = self.register(save=False)
        self.assertEqual(pending["token"], IDENTITY["token"])
        self.assertEqual(pending["auth_scheme"], "legacy_rc4")
        self.assertNotIn("sign", pending)
        self.assertNotIn("dev_key", pending)
        self.assertFalse(self.device.bound)
        self.device.commit_identity(pending)
        self.assertTrue(self.device.bound)
        self.assertFalse(self.device.logged_in)

    def test_legacy_login_uses_plain_random_and_xor_random_key(self):
        self.register()
        establish_legacy_login(self.device, 0.4)
        self.assertTrue(self.device.logged_in)

    def test_legacy_login_also_accepts_raw_token_key(self):
        self.register()
        self.device.write(0x0001, phone_rc4(LEGACY_TOKEN, struct.pack("<I", 0x369A58C9)), 0.4)
        self.assertEqual(self.device.drain_notifications(),
                         [(0x0001, phone_rc4(LEGACY_TOKEN, struct.pack("<I", 0x369A58C9)))])
        self.assertTrue(self.device.logged_in)

    def test_getrand_reselects_subscribed_channel_and_waits_for_cccd(self):
        self.register()
        self.device.set_notify_channels(set())
        with patch.object(protocol.secrets, "token_bytes", return_value=b"\x11\x22\x33\x44"):
            self.device.write(0x0010, bytes.fromhex("00bc43cd"), 0.4)
        self.device.poll(0.441)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.set_notify_channels({0x0001})
        self.device.poll(0.492)
        self.assertEqual(self.device.drain_notifications(), [(0x0001, b"\x11\x22\x33\x44")])

    def test_identity_restores_bind_key_without_invented_standard_credentials(self):
        pending = self.register()
        restored = new_night_light(pending)
        self.assertEqual(restored.read(0x0001), LEGACY_TOKEN)
        self.assertEqual(restored.read(0x0014), phone_rc4(LEGACY_TOKEN, bytes.fromhex(pending["bind_key"])))
        self.assertEqual(restored.read(0x0013), IDENTITY["did"].encode("ascii").rjust(20, b"\x00"))
        establish_legacy_login(restored)
        self.assertEqual(restored.identity["bind_key"], pending["bind_key"])

    def test_unauthenticated_did_write_and_connector_word_do_not_bind(self):
        self.device.write(0x0013, IDENTITY["did"].encode("ascii").rjust(20, b"\x00"), 0.1)
        self.device.write(0x0010, bytes.fromhex("13000000"), 0.2)
        self.assertIsNone(self.device.pending_identity)
        self.assertFalse(self.device.bound)

    def test_invalid_cloud_did_does_not_create_identity(self):
        self.adopt_token()
        self.device.write(0x0001, phone_rc4(LEGACY_TOKEN, struct.pack("<I", 0xFA54AB92)), 0.2)
        for did in (bytes(20), b"\xff" * 20, b"abc\x00def".ljust(20, b"\x00"), b"short"):
            self.device.write(0x0013, did, 0.3)
            self.assertIsNone(self.device.pending_identity)
            self.assertFalse(self.device.bound)

    def test_bind_save_failure_keeps_identity_unbound(self):
        self.register(save=False)
        self.device.reject_identity()
        self.assertFalse(self.device.bound)
        self.assertFalse(self.device.logged_in)
        self.assertIsNone(self.device.pending_identity)

    def test_unknown_four_byte_fallback_requires_a_proven_bond_in_this_connection(self):
        self.adopt_token()
        self.device.write(0x0001, bytes.fromhex("deadbeef"), 0.2)
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertFalse(self.device.logged_in)
        self.device.write(0x0001, phone_rc4(LEGACY_TOKEN, struct.pack("<I", 0xFA54AB92)), 0.3)
        self.device.write(0x0001, bytes.fromhex("deadbeef"), 0.4)
        self.assertEqual(self.device.drain_notifications(), [(0x0001, bytes.fromhex("1e599b4a"))])
        self.assertFalse(self.device.logged_in)
        self.device.write(0x0013, IDENTITY["did"].encode("ascii").rjust(20, b"\x00"), 0.5)
        self.device.commit_identity(self.device.pending_identity)
        self.assertTrue(self.device.logged_in)
        restored = new_night_light(self.device.identity)
        restored.write(0x0001, bytes.fromhex("00bc43cd"), 0.6)
        restored.write(0x0001, bytes.fromhex("deadbeef"), 0.7)
        self.assertEqual(restored.drain_notifications(), [])
        self.assertFalse(restored.logged_in)

    def test_standard_registration_frames_do_not_enter_legacy_fallback(self):
        self.register()
        establish_legacy_login(self.device, 0.4)
        self.device.write(0x0010, bytes.fromhex("a2000000"), 0.5)
        self.device.drain_notifications()
        self.device.write(0x0010, bytes.fromhex("deadbeef"), 0.6)
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertFalse(self.device.logged_in)

    def test_standard_authentication_remains_a_second_entry_for_nus_model(self):
        device = new_night_light({**IDENTITY, "pid": 0x03DD})
        establish_login(device)
        device.set_notify_channels({protocol.NUS_TX})
        device.set_mtu(247)
        device.write(protocol.NUS_RX, b"get_prop power bright lux snm dur", 0.2)
        device.poll(0.221)
        messages = device.drain_notifications()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][0], protocol.NUS_TX)
        self.assertEqual(json.loads(messages[0][1])["result"]["bright"], 60)


class NightLightNusTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.device = new_night_light(LEGACY_IDENTITY, self.requests.append)
        establish_legacy_login(self.device)

    def command(self, command, now=0.2):
        self.device.write(protocol.NUS_RX, command.encode("ascii"), now)

    def messages(self):
        return [json.loads(payload) for channel, payload in self.device.drain_notifications() if channel == protocol.NUS_TX]

    def complete(self, request, success=True):
        self.assertTrue(self.device.reply_set(request, {key: 0 if success else 1 for key, _ in request.items}))
        self.device.poll(0.221)
        return self.messages()

    def test_startup_replies_are_complete_json_queued_after_att_write(self):
        for command in ("notify_ol", "get_prop power bright lux snm dur", "get_s_prop scene"):
            self.command(command)
        self.device.poll(0.219)
        self.assertEqual(self.messages(), [])
        replies = []
        for now in (0.221, 0.241, 0.261):
            self.device.poll(now)
            replies.extend(self.messages())
        self.assertEqual([reply["flag"] for reply in replies], ["notify_ol", "get_prop", "get_s_prop"])
        self.assertEqual(replies[1]["result"], {"power": 1, "bright": 60, "lux": 1, "snm": 0, "dur": 25000})
        self.assertEqual(replies[2]["result"]["scene"], [
            {"bright": 60, "dur": 25000}, {"bright": 20, "dur": 30000},
            {"bright": 100, "dur": 10000}, {"bright": 40, "dur": 5000},
        ])

    def test_nus_never_splits_json_when_mtu_is_small(self):
        self.device.set_mtu(23)
        self.command("get_s_prop scene")
        self.device.poll(0.221)
        self.assertEqual(self.messages(), [])
        self.device.set_mtu(247)
        self.device.poll(0.222)
        self.assertEqual(len(self.messages()), 1)

    def test_nus_waits_for_tx_subscription(self):
        self.device.set_notify_channels({0x0001})
        self.command("get_prop")
        self.device.poll(0.221)
        self.assertEqual(self.messages(), [])
        self.device.set_notify_channels({protocol.NUS_TX})
        self.device.poll(0.222)
        self.assertEqual(len(self.messages()), 1)

    def test_brightness_write_waits_for_host_and_uses_upstream_clamp(self):
        self.command("set_bright 200")
        request = self.requests[0]
        self.assertEqual(request.items, (("2.1", 100), ("2.3", 1)))
        self.assertEqual(self.device.property_values["2.1"], 60)
        self.assertEqual(self.messages(), [])
        self.assertEqual(self.complete(request), [{"flag": "set_bright", "result": {"bright": 100}}])
        self.assertEqual(self.device.property_values["2.1"], 100)

    def test_failed_nus_write_reports_error_and_keeps_previous_values(self):
        self.command("set_bridur 58 30000")
        self.assertEqual(self.complete(self.requests[0], False), [{"flag": "set_bridur", "result": {"code": 1}}])
        self.assertEqual((self.device.property_values["2.1"], self.device.property_values["2.2"]), (60, 25000))

    def test_nus_duration_power_and_duration_alias_use_the_property_callback(self):
        commands = (("set_duration 1", (("2.2", 5000),)), ("set_dur 90000", (("2.2", 60000),)),
                    ("set_power 0", (("2.3", 0),)))
        for command, expected in commands:
            self.command(command)
            self.assertEqual(self.requests[-1].items, expected)
            self.complete(self.requests[-1])
        self.assertEqual(self.device.property_values["2.3"], 0)

    def test_apply_scene_changes_current_values_only_after_success(self):
        self.command("apply_fixed_scene 2")
        self.assertEqual(self.requests[0].items, (("2.1", 20), ("2.2", 30000), ("2.3", 1)))
        self.assertEqual(self.device.property_values["2.1"], 60)
        self.assertEqual(self.complete(self.requests[0]), [{"flag": "apply_fixed_scene", "result": {"snm": 2, "bright": 20, "dur": 30000}}])

    def test_scene_edit_waits_for_durable_save_and_never_changes_current_light(self):
        original = self.device.property_values
        self.command("set_scene 2 55 35000")
        request = self.requests[0]
        self.assertEqual(request.action_key, "nus_set_scene")
        self.assertEqual(request.items, (("2.1", 55), ("2.2", 35000)))
        self.assertEqual(request.args, (("scene_id", 2),))
        self.assertEqual(self.device._nus_scenes[1], (20, 30000))
        self.assertEqual(self.complete(request), [{"flag": "set_scene", "result": {"id": 2, "bright": 55, "dur": 35000}}])
        self.assertEqual(self.device._nus_scenes[1], (55, 35000))
        self.assertEqual(self.device.property_values, original)

    def test_failed_scene_save_preserves_scene_and_current_values(self):
        self.command("set_scene 2 55 35000")
        self.assertEqual(self.complete(self.requests[0], False), [{"flag": "set_scene", "result": {"code": 1}}])
        self.assertEqual(self.device._nus_scenes[1], (20, 30000))
        self.assertEqual(self.device.property_values["2.1"], 60)

    def test_scene_restore_is_atomic_and_independent_of_current_light(self):
        self.device.load_nus_scenes({"2": {"bright": 55, "dur": 35000}})
        self.assertEqual(self.device._nus_scenes[1], (55, 35000))
        self.assertEqual(self.device.property_values["2.1"], 60)
        for scenes in ({"0": {"bright": 50, "dur": 30000}}, {"2": {"bright": 55, "dur": 300}},
                       {"2": {"bright": 22, "dur": 35000}, "3": {"bright": 200, "dur": 30000}}):
            with self.subTest(scenes=scenes), self.assertRaises(protocol.ProtocolError):
                self.device.load_nus_scenes(scenes)
            self.assertEqual(self.device._nus_scenes[1], (55, 35000))

    def test_scene_edits_survive_disconnect_in_the_same_protocol_instance(self):
        self.command("set_scene 2 55 35000")
        self.complete(self.requests[0])
        self.device.disconnect()
        self.device.connect(1.0)
        self.assertEqual(self.device._nus_scenes[1], (55, 35000))

    def test_malformed_nus_values_never_execute_a_host_request(self):
        for command in ("set_bright abc", "set_duration", "set_scene 5 40 30000", "set_power 2"):
            self.command(command)
        self.assertEqual(self.requests, [])

    def test_nus_queue_overflow_disconnects_instead_of_sending_truncated_json(self):
        for _ in range(protocol.MAX_NUS_QUEUE):
            self.command("get_s_prop")
        with self.assertRaises(protocol.ProtocolError):
            self.command("get_s_prop")
        self.assertFalse(self.device.logged_in)
        self.assertEqual(self.messages(), [])

    def test_unbound_nus_writes_cannot_bypass_authentication(self):
        device = new_night_light(on_set=self.requests.append)
        device.write(protocol.NUS_RX, b"set_bright 100", 0.2)
        device.poll(0.221)
        self.assertEqual(self.requests, [])
        self.assertEqual(device.property_values["2.1"], 60)
        self.assertEqual(device.drain_notifications(), [])


class CatalogProtocolTests(unittest.TestCase):
    def test_carlight_initialization_placeholder_is_a_successful_empty_string(self):
        model = models.get_model("careco.nlight.o654")
        device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model)
        session = establish_login(device)
        device.set_notify_channels({0x001B})
        request = bytes.fromhex("092024010201080200")
        deliver_parcel(device, 0, encrypt_phone_spec(session, request), channel=0x001B, now=0.2)
        self.assertEqual(decrypt_device_spec(session, device.drain_notifications(), 0x001B),
                         [bytes.fromhex("0d2024010301080200000000a0")])

    def test_diffuser_on_enum_is_normalized_only_after_a_confirmed_host_write(self):
        model = models.get_model("xiaomi.diffuser.xwczxf")
        for legacy in (False, True):
            for type_code in (0, 1):
                for raw_value, expected in ((4, True), (0, False), (1, True)):
                    with self.subTest(legacy=legacy, type_code=type_code, raw_value=raw_value):
                        requests = []
                        device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model, on_set=requests.append)
                        device.set_property_values({"2.1032": not expected})
                        session = establish_login(device)
                        device.set_notify_channels({0x001B})
                        header = struct.pack("<HB", type_code, 1) if legacy else struct.pack("<H", (type_code << 12) | 1)
                        body = b"\x01" + struct.pack("<BH", 2, 1032) + header + bytes([raw_value])
                        deliver_parcel(device, 0, encrypt_phone_spec(session, phone_plain(0, 0x1234, body)), channel=0x001B, now=0.2)
                        self.assertEqual(decrypt_device_spec(session, device.drain_notifications(), 0x001B), [])
                        self.assertEqual(requests[0].items, (("2.1032", expected),))
                        self.assertIs(device.property_values["2.1032"], not expected)
                        device.reply_set(requests[0], {"2.1032": 0})
                        replies = decrypt_device_spec(session, device.drain_notifications(), 0x001B)
                        self.assertEqual(replies[0], phone_plain(1, 0x1234, bytes.fromhex("010208040000")))
                        self.assertEqual(replies[1][4:], bytes.fromhex("04010208040100") + bytes([int(expected)]))
                        self.assertIs(device.property_values["2.1032"], expected)

    def test_diffuser_bool_exception_does_not_accept_other_values_or_widths(self):
        model = models.get_model("xiaomi.diffuser.xwczxf")
        requests = []
        device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model, on_set=requests.append)
        session = establish_login(device)
        device.set_notify_channels({0x001B})
        malformed = (b"\x01\x00\x02", b"\x01\x00\x05", b"\x01\x10\x02", b"\x02\x30\x04\x00", b"\x02\x00\x04\x00")
        for sequence, encoded in enumerate(malformed):
            body = b"\x01" + struct.pack("<BH", 2, 1032) + encoded
            deliver_parcel(device, 0, encrypt_phone_spec(session, phone_plain(0, 0x1234, body), sequence), channel=0x001B, now=0.2)
            self.assertEqual(decrypt_device_spec(session, device.drain_notifications(), 0x001B),
                             [phone_plain(1, 0x1234, bytes.fromhex("010208040100"))])
        self.assertEqual(requests, [])
        self.assertIs(device.property_values["2.1032"], True)

    def test_other_bool_properties_still_reject_the_diffuser_on_enum(self):
        for model_id, siid, piid in (("xiaomi.diffuser.xwczxf", 6, 1032), ("careco.nlight.o654", 7, 1), ("xiaomi.cooler.r02p", 4, 1)):
            with self.subTest(model=model_id, key=(siid, piid)):
                model = models.get_model(model_id)
                requests = []
                device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model_id, on_set=requests.append)
                session = establish_login(device)
                device.set_notify_channels({0x001B})
                body = b"\x01" + struct.pack("<BH", siid, piid) + bytes.fromhex("010004")
                deliver_parcel(device, 0, encrypt_phone_spec(session, phone_plain(0, 0x1234, body)), channel=0x001B, now=0.2)
                self.assertEqual(requests, [])
                self.assertEqual(decrypt_device_spec(session, device.drain_notifications(), 0x001B),
                                 [phone_plain(1, 0x1234, struct.pack("<BBHH", 1, siid, piid, 1))])

    def test_available_catalog_models_login_and_get_with_their_real_schema(self):
        for model in models.AVAILABLE_MODELS:
            with self.subTest(model=model.model):
                device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model)
                session = establish_login(device)
                device.set_notify_channels({0x001A, 0x001B})
                properties = tuple(prop for prop in model.properties if prop.spec_visible)
                body = bytes([len(properties)]) + b"".join(struct.pack("<BH", prop.siid, prop.piid) for prop in properties)
                plain = phone_plain(2, 0x1357, body)
                deliver_parcel(device, 0, encrypt_phone_spec(session, plain), channel=0x001B, now=0.2)
                channel = 0x0010 if model.gatt_strategy == "fixed_control" else 0x001B
                expected = bytes([len(properties)])
                for prop in properties:
                    value = device.property_values.get(prop.key)
                    expected += struct.pack("<BHH", prop.siid, prop.piid, 1 if value is None else 0)
                    if value is not None:
                        expected += phone_value(prop.type_code, value)
                self.assertEqual(decrypt_device_spec(session, device.drain_notifications(), channel), [phone_plain(3, 0x1357, expected)])

    def test_all_catalog_beacons_use_the_independent_codec_payload_and_real_pid(self):
        for model in models.AVAILABLE_MODELS:
            with self.subTest(model=model.model):
                device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model)
                values = {prop.key: prop.default for prop in model.properties if prop.default is not None}
                for field in model.beacons:
                    payload = field.encode_values(values)
                    frame = device.beacon_object(field.object_id, payload, 17)
                    nonce = bytes.fromhex(MAC.replace(":", ""))[::-1] + struct.pack("<HI", model.pid, 17)
                    obj = AESCCM(bytes.fromhex(IDENTITY["bind_key"]), tag_length=4).decrypt(nonce, frame[5:-7] + frame[-4:], b"\x11")
                    self.assertEqual(obj, struct.pack("<HB", field.object_id, len(payload)) + payload)

    def test_internal_mapping_values_never_become_spec_get_set_or_changed_properties(self):
        hidden = models.PropertyDefinition("Internal presence", 0, 1, 0, False, True, spec_visible=False)
        model = models.ModelDefinition("bridge.test.hidden", "Hidden", 0x1234, (hidden,))
        requests = []
        with patch.object(protocol, "get_model", return_value=model):
            device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model, on_set=requests.append)
        session = establish_login(device)
        device.set_property_values({"0.1": True})
        self.assertEqual(device.property_values, {"0.1": True})
        self.assertEqual(device.properties, {})
        self.assertEqual(device.drain_notifications(), [])
        get = phone_plain(2, 1, bytes.fromhex("01000100"))
        deliver_parcel(device, 0, encrypt_phone_spec(session, get), channel=0x001A, now=0.2)
        self.assertEqual(decrypt_device_spec(session, device.drain_notifications()),
                         [phone_plain(3, 1, bytes.fromhex("010001000100"))])
        set_value = phone_plain(0, 2, bytes.fromhex("01000100") + phone_value(0, False))
        deliver_parcel(device, 0, encrypt_phone_spec(session, set_value, 1), channel=0x001A, now=0.3)
        self.assertEqual(requests, [])
        self.assertEqual(decrypt_device_spec(session, device.drain_notifications()),
                         [phone_plain(1, 2, bytes.fromhex("010001000100"))])
        self.assertEqual(device.property_values, {"0.1": True})

    def test_real_s400_sync_accepts_hidden_input_and_requires_all_five_outputs(self):
        model = models.get_model("yunmai.scales.ms103")
        requests = []
        device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model, on_action=requests.append)
        session = establish_login(device)
        device.set_notify_channels({0x001B})
        action = model.actions[0]
        values = {"13.1": 3, "13.2": 1, "13.3": True, "13.4": IDENTITY["utc"], "13.5": "[]"}
        body = bytes([13, 1, len(action.input_keys)]) + b"".join(
            struct.pack("<H", model.property_by_key[key].piid) + phone_value(model.property_by_key[key].type_code, values[key])
            for key in action.input_keys
        )
        deliver_parcel(device, 0, encrypt_phone_spec(session, phone_plain(5, 0x4321, body)), channel=0x001B, now=0.2)
        device.drain_notifications()
        self.assertEqual(requests[0].args, tuple((key, values[key]) for key in action.input_keys))
        outputs = {"13.6": 0, "13.7": "SN0000000001", "13.8": MAC, "13.9": "9.9.9_9999", "13.10": 0}
        device.reply_action(requests[0], 0, outputs)
        expected = b"\x00\x00\x05" + b"".join(
            bytes([model.property_by_key[key].piid]) + phone_value(model.property_by_key[key].type_code, outputs[key])
            for key in action.output_keys
        )
        self.assertEqual(decrypt_device_spec(session, device.drain_notifications(), 0x001B), [phone_plain(6, 0x4321, expected)])

    def test_real_s400_event_uses_hidden_argument_definitions_without_pushing_fake_properties(self):
        model = models.get_model("yunmai.scales.ms103")
        device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": model.pid}, model.model)
        session = establish_login(device)
        values = {"11.1": 2, "11.2": 0x12345678, "11.3": IDENTITY["utc"]}
        device.set_property_values(values)
        self.assertEqual(device.drain_notifications(), [])
        device.send_event("11.e.1022")
        body = struct.pack("<BHB", 11, 1022, 3) + b"".join(
            struct.pack("<H", model.property_by_key[key].piid) + phone_value(model.property_by_key[key].type_code, value)
            for key, value in values.items()
        )
        replies = decrypt_device_spec(session, device.drain_notifications())
        self.assertEqual(replies[0][4:], b"\x07" + body)

    def test_real_nus_catalog_model_supports_legacy_login_and_scene_callback(self):
        model = models.get_model("MUE4094RT")
        requests = []
        device = protocol.MiotProtocol(MAC, LEGACY_IDENTITY, model.model, on_set=requests.append)
        device.connect()
        device.set_notify_channels({0x0001, protocol.NUS_TX})
        device.set_mtu(247)
        establish_legacy_login(device)
        device.write(protocol.NUS_RX, b"set_bridur 58 30000", 0.2)
        self.assertEqual(requests[0].items, (("2.1", 58), ("2.2", 30000), ("2.3", True)))
        device.reply_set(requests[0], {key: 0 for key, _ in requests[0].items})
        device.poll(0.221)
        self.assertEqual([json.loads(value) for channel, value in device.drain_notifications() if channel == protocol.NUS_TX],
                         [{"flag": "set_bridur", "result": {"bright": 58, "dur": 30000}}])


class NightLightLinkTests(unittest.TestCase):
    def setUp(self):
        self.model = models.get_model("MUE4094RT")
        self.device = protocol.MiotProtocol(MAC, LEGACY_IDENTITY, self.model.model)
        self.device.connect(0.0)
        self.device.set_mtu(247)

    def subscribe(self, channels, now=0.0):
        self.device.set_notify_channels(set(channels), now)
        return self.device.drain_notifications()

    def start_link(self, channel=0x001B, now=0.1):
        self.subscribe({channel})
        self.device.write(channel, bytes.fromhex("000005000612"), now)
        self.assertEqual(self.device.drain_notifications(), [(channel, bytes.fromhex("00000501") + b"\x12" * 16)])

    def test_night_light_hello_has_legacy_bond_ability_and_pairing_object(self):
        self.assertEqual(self.device.hello(0x78).hex(), "702add0378102a5e043bd40911100100")
        self.assertEqual(protocol.MiotProtocol(MAC).hello(0x78).hex(), "702a834678102a5e043bd41111100100")

    def test_new_subscriptions_trigger_management_probe_and_one_bounded_retry(self):
        self.assertEqual(self.subscribe({0x001B, 0x001A}),
                         [(0x001B, bytes.fromhex("000004000612")), (0x001A, bytes.fromhex("000004000612"))])
        self.device.poll(0.399)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.poll(0.401)
        self.assertEqual(self.device.drain_notifications(), [(0x001A, bytes.fromhex("000004000612"))])
        self.device.poll(2.0)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_repeated_subscription_does_not_repeat_the_initial_management_probe(self):
        self.subscribe({0x001B})
        self.assertEqual(self.subscribe({0x001B}, 0.1), [])

    def test_management_test_reply_uses_the_subscribed_input_without_channel_0019(self):
        self.start_link()
        self.assertTrue(self.device._channel_ready)
        self.assertTrue(self.device.bound)
        self.assertFalse(self.device.logged_in)
        self.device.poll(0.2)
        self.assertEqual(self.device.drain_notifications(), [])

    def test_test_acknowledgement_sends_real_device_info_immediately_as_one_parcel(self):
        self.start_link()
        self.device.write(0x001B, bytes.fromhex("00000501") + b"\x12" * 16, 0.2)
        notifications = self.device.drain_notifications()
        self.assertTrue(all(channel == 0x001B and len(frame) <= 20 for channel, frame in notifications))
        self.assertEqual(decode_parcels(notifications, 0x001B), [(0, bytes.fromhex("02000000") + IDENTITY["did"].encode("ascii"))])
        self.device.poll(0.351)
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertFalse(self.device.logged_in)

    def test_short_test_acknowledgement_after_the_test_is_supported(self):
        self.start_link()
        self.device.write(0x001B, bytes.fromhex("00000501"), 0.2)
        self.assertEqual(decode_parcels(self.device.drain_notifications(), 0x001B),
                         [(0, bytes.fromhex("02000000") + IDENTITY["did"].encode("ascii"))])

    def test_device_info_fallback_waits_250ms_and_does_not_use_80ms_fragment_gaps(self):
        self.start_link()
        self.device.poll(0.349)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.poll(0.351)
        messages = self.device.drain_notifications()
        self.assertEqual(decode_parcels(messages, 0x001B), [(0, bytes.fromhex("02000000") + IDENTITY["did"].encode("ascii"))])
        self.assertTrue(all(channel == 0x001B and len(frame) <= 20 for channel, frame in messages))

    def test_ready_cancels_probe_retry_and_deduplicates_management_acknowledgements(self):
        self.start_link()
        self.device.write(0x001B, bytes.fromhex("000005000612"), 0.2)
        self.assertEqual(self.device.drain_notifications(), [])
        self.device.poll(0.401)
        messages = self.device.drain_notifications()
        self.assertFalse(any(frame == bytes.fromhex("000004000612") for _, frame in messages))

    def test_peer_initiated_test_is_echoed_then_returns_device_info(self):
        self.subscribe({0x001A})
        self.device.write(0x001A, bytes.fromhex("00000401") + b"\x12" * 16, 0.1)
        self.assertEqual(self.device.drain_notifications(), [(0x001A, bytes.fromhex("00000501") + b"\x12" * 16)])
        self.device.write(0x001A, bytes.fromhex("00000501") + b"\x12" * 16, 0.2)
        self.assertEqual(decode_parcels(self.device.drain_notifications(), 0x001A),
                         [(0, bytes.fromhex("02000000") + IDENTITY["did"].encode("ascii"))])

    def test_test_ack_before_link_or_invalid_peer_test_cannot_grant_identity_or_session(self):
        device = protocol.MiotProtocol(MAC, model=self.model.model)
        device.connect()
        device.set_notify_channels({0x001B}, 0.0)
        device.drain_notifications()
        for frame in (bytes.fromhex("00000501"), bytes.fromhex("00000401") + bytes(16), bytes.fromhex("00000500061200")):
            device.write(0x001B, frame, 0.1)
            self.assertEqual(device.drain_notifications(), [])
            self.assertFalse(device._channel_ready)
            self.assertFalse(device.bound)
            self.assertFalse(device.logged_in)
            self.assertIsNone(device.pending_identity)

    def test_legacy_authenticated_session_without_spec_key_still_handles_link_control(self):
        self.subscribe({0x0001, 0x001B, protocol.NUS_TX})
        establish_legacy_login(self.device)
        self.assertIsNone(self.device._session)
        self.device.write(0x001B, bytes.fromhex("000005000612"), 0.1)
        self.assertEqual(self.device.drain_notifications(), [(0x001B, bytes.fromhex("00000501") + b"\x12" * 16)])
        self.device.write(0x001B, bytes.fromhex("00000501"), 0.2)
        self.assertEqual(decode_parcels(self.device.drain_notifications(), 0x001B),
                         [(0, bytes.fromhex("02000000") + IDENTITY["did"].encode("ascii"))])
        self.assertTrue(self.device.logged_in)

    def test_ready_does_not_authorize_nus_and_verified_legacy_login_completes_the_text_flow(self):
        self.start_link()
        self.device.write(0x001B, bytes.fromhex("00000501") + b"\x12" * 16, 0.2)
        self.device.drain_notifications()
        self.subscribe({0x0001, 0x001B, protocol.NUS_TX}, 0.21)
        self.device.write(protocol.NUS_RX, b"get_prop power bright lux snm dur", 0.22)
        self.device.poll(0.241)
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertFalse(self.device.logged_in)
        establish_legacy_login(self.device, 0.3)
        self.device.write(protocol.NUS_RX, b"get_prop power bright lux snm dur", 0.5)
        self.device.poll(0.521)
        messages = self.device.drain_notifications()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][0], protocol.NUS_TX)
        self.assertEqual(json.loads(messages[0][1]), {"flag": "get_prop", "result": {
            "power": 1, "bright": 60, "lux": 1, "snm": 0, "dur": 25000,
        }})

    def test_valid_management_handshake_never_invents_a_cloud_did_or_binding(self):
        device = protocol.MiotProtocol(MAC, model=self.model.model)
        device.connect()
        device.set_notify_channels({0x001B}, 0.0)
        device.drain_notifications()
        device.write(0x001B, bytes.fromhex("000005000612"), 0.1)
        device.drain_notifications()
        device.write(0x001B, bytes.fromhex("00000501"), 0.2)
        self.assertEqual(decode_parcels(device.drain_notifications(), 0x001B), [(0, bytes.fromhex("02000000"))])
        self.assertTrue(device._channel_ready)
        self.assertFalse(device.bound)
        self.assertFalse(device.logged_in)
        self.assertIsNone(device.pending_identity)

    def test_auth_parcels_follow_the_night_light_subscribed_input_channel(self):
        self.subscribe({0x001B})
        self.device.write(0x0010, bytes.fromhex("a2000000"), 0.1)
        self.device.drain_notifications()
        private = ec.derive_private_key(9, ec.SECP256R1())
        public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        deliver_parcel(self.device, 3, public, channel=0x001B, now=0.2)
        messages = self.device.drain_notifications()
        self.assertEqual({channel for channel, _ in messages}, {0x001B})
        self.assertEqual({kind for kind, _ in decode_parcels(messages, 0x001B)}, {3, 0x0D, 0x0C})

    def test_standard_registration_and_login_result_words_stay_on_0010(self):
        self.subscribe({0x001B})
        for result in (0x11, 0x21):
            self.device._result(result)
            self.assertEqual(self.device.drain_notifications(), [(0x0010, bytes([result, 0, 0, 0]))])

    def test_disconnect_clears_link_ready_and_each_connection_can_probe_again(self):
        self.start_link()
        self.device.disconnect()
        self.device.connect(1.0)
        self.assertFalse(self.device._channel_ready)
        self.assertEqual(self.subscribe({0x001B}, 1.0), [(0x001B, bytes.fromhex("000004000612"))])


class GetterNotificationTests(unittest.TestCase):
    def setUp(self):
        self.model = models.ModelDefinition("bridge.test.alias", "Alias", 0x1234, (
            models.PropertyDefinition("Canonical", 2, 1, 1, 1),
            models.PropertyDefinition("Getter", 2, 1001, 1, 1, alias_of="2.1", notify=False),
        ))
        with patch.object(protocol, "get_model", return_value=self.model):
            self.device = protocol.MiotProtocol(MAC, {**IDENTITY, "pid": self.model.pid}, self.model.model)
        self.session = establish_login(self.device)

    def test_getter_remains_readable_but_is_omitted_from_changed_and_snapshot(self):
        self.device.set_property_values({"2.1": 42, "2.1001": 42})
        self.assertEqual(self.device.property_values, {"2.1": 42, "2.1001": 42})
        changed = decrypt_device_spec(self.session, self.device.drain_notifications())
        self.assertEqual(changed[0][4:], bytes.fromhex("040102010001102a"))
        self.device.send_snapshot()
        snapshot = decrypt_device_spec(self.session, self.device.drain_notifications())
        self.assertEqual(snapshot[0][4:], bytes.fromhex("040102010001102a"))
        get = phone_plain(2, 0x1234, bytes.fromhex("0102e903"))
        deliver_parcel(self.device, 0, encrypt_phone_spec(self.session, get), channel=0x001A, now=0.2)
        self.assertEqual(decrypt_device_spec(self.session, self.device.drain_notifications()),
                         [phone_plain(3, 0x1234, bytes.fromhex("0102e903000001102a"))])

    def test_snapshot_with_only_getter_values_emits_no_property_notification(self):
        self.device.set_property_values({"2.1001": 42})
        self.device.send_snapshot()
        self.assertEqual(self.device.drain_notifications(), [])
        self.assertEqual(self.device.properties, {(2, 1001): (1, 42)})


class ExperimentalPskTests(unittest.TestCase):
    def setUp(self):
        self.model = models.get_model("zimi.mosq.v1")
        self.device = protocol.MiotProtocol(MAC, model=self.model.model)
        self.device.connect(0.0)
        self.app_private = ec.derive_private_key(7, ec.SECP256R1())
        self.app_public = self.app_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]

    def start_handshake(self, app_random=bytes(16)):
        deliver_parcel(self.device, 0, bytes(range(0xA0, 0xBA)), now=0.0)
        notifications = self.device.drain_notifications()
        self.assertIn((0x0019, bytes.fromhex("00000100")), notifications)
        self.assertIn((0, bytes.fromhex("02000000")), decode_parcels(notifications))
        if app_random != bytes(16):
            deliver_parcel(self.device, 0x0B, app_random, now=0.1)
            self.device.drain_notifications()
        with patch.object(protocol.secrets, "token_bytes", return_value=bytes(range(16))):
            deliver_parcel(self.device, 3, self.app_public, now=0.2)
        frames = dict(decode_parcels(self.device.drain_notifications()))
        self.assertEqual(set(frames), {0x0D, 3, 0x0C, 4})
        device_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + frames[3])
        shared = self.app_private.exchange(ec.ECDH(), device_public)
        keys = HKDF(hashes.SHA256(), 64, b"smartcfg-setup-salt", b"smartcfg-setup-info").derive(shared)
        body = frames[0x0D] + app_random
        self.assertEqual(frames[0x0C], hmac.digest(keys[:32], body, "sha256"))
        signature = frames[4]
        self.assertEqual(len(signature), 64)
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        device_public.verify(der, body, ec.ECDSA(hashes.SHA256()))
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        return keys, shared, frames

    def server_public(self):
        deliver_parcel(self.device, 0, bytes(range(1, 17)), now=0.3)
        self.device.drain_notifications()

    def test_experimental_handshake_matches_independent_p256_hkdf_hmac_and_ecdsa(self):
        self.start_handshake(bytes(range(0x20, 0x30)))

    def test_late_application_random_recalculates_confirmation_and_signature(self):
        keys, _, frames = self.start_handshake()
        app_random = bytes(range(0x30, 0x40))
        deliver_parcel(self.device, 0x0B, app_random, now=0.3)
        updated = dict(decode_parcels(self.device.drain_notifications()))
        self.assertEqual(updated[0x0D], frames[0x0D])
        body = frames[0x0D] + app_random
        self.assertEqual(updated[0x0C], hmac.digest(keys[:32], body, "sha256"))
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + updated[3])
        signature = updated[4]
        public.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                      body, ec.ECDSA(hashes.SHA256()))

    def test_numeric_did_is_captured_separately_and_cannot_grant_a_standard_binding(self):
        keys, _, _ = self.start_handshake()
        self.server_public()
        deliver_parcel(self.device, 0, b"\x00123456789012", now=0.4)
        captured = self.device.pending_psk_identity
        self.assertEqual(captured["did"], "123456789012")
        self.assertEqual(captured["psk_key"], keys[:32].hex())
        self.assertNotIn("token", captured)
        self.assertNotIn("bind_key", captured)
        self.assertIsNone(self.device.pending_identity)
        self.assertFalse(self.device.bound)
        self.assertNotIn((0x0010, bytes.fromhex("11000000")), self.device.drain_notifications())
        with self.assertRaises(protocol.ProtocolError):
            self.device.commit_identity()
        with self.assertRaises(protocol.PersistenceRequired):
            self.device.beacon_object(0x1001, b"\x01", 0)

    def test_unknown_bind_result_or_wrong_stage_never_sets_any_identity(self):
        deliver_parcel(self.device, 0, b"\x00123456789012", now=0.0)
        self.assertIsNone(self.device.pending_psk_identity)
        self.start_handshake()
        deliver_parcel(self.device, 0, b"\x00123456789012", now=0.3)
        self.assertIsNone(self.device.pending_psk_identity)
        self.server_public()
        for result in (bytes(13), b"\x00not-a-device", bytes(range(13))):
            deliver_parcel(self.device, 0, result, now=0.4)
            self.assertIsNone(self.device.pending_psk_identity)
            self.assertFalse(self.device.bound)
        self.device.write(0x0010, bytes.fromhex("13000000"), 0.5)
        self.assertIsNone(self.device.pending_psk_identity)

    def test_certificate_package_cannot_impersonate_psk_numeric_did(self):
        self.start_handshake()
        self.server_public()
        deliver_parcel(self.device, 7, b"\x00123456789012", now=0.4)
        self.assertIsNone(self.device.pending_psk_identity)
        self.assertIsNone(self.device.pending_identity)

    def test_standard_identity_is_rejected_by_experimental_psk_model(self):
        for identity in ({**IDENTITY, "pid": self.model.pid},
                         {**IDENTITY, "pid": self.model.pid, "auth_scheme": "psk", "psk_key": bytes(32).hex()}):
            with self.subTest(identity=identity["pid"]), self.assertRaises(ValueError):
                protocol.MiotProtocol(MAC, identity, self.model.model)

    def test_invalid_p256_point_is_rejected_without_identity(self):
        deliver_parcel(self.device, 0, bytes(range(26)), now=0.0)
        self.device.drain_notifications()
        deliver_parcel(self.device, 3, bytes(64), now=0.1)
        self.assertEqual(self.device.last_error, "Invalid experimental PSK public key")
        self.assertIsNone(self.device.pending_psk_identity)
        self.assertFalse(self.device.bound)

    def test_login_fixture_uses_smartcfg_labels_and_validates_the_application_confirmation(self):
        setup, shared, _ = self.start_handshake()
        self.device.write(0x0010, bytes.fromhex("24000000"), 0.4)
        self.assertEqual([kind for kind, _ in decode_parcels(self.device.drain_notifications())], [3])
        deliver_parcel(self.device, 3, self.app_public, now=0.5)
        self.device.drain_notifications()
        psk_login = HKDF(hashes.SHA256(), 64, b"smartcfg-login-salt", b"smartcfg-login-info").derive(shared)
        self.assertNotEqual(psk_login[:32], setup[:32])
        app_random = bytes(range(0xA0, 0xB0))
        deliver_parcel(self.device, 0x0B, app_random, now=0.6)
        packets = decode_parcels(self.device.drain_notifications())
        device_random = next(payload for kind, payload in packets if kind == 0x0D)
        session = HKDF(hashes.SHA256(), 64, app_random + device_random, b"smartcfg-login-info").derive(psk_login[:32])
        self.device.poll(0.721)
        confirm = dict(decode_parcels(self.device.drain_notifications()))[0x0C]
        self.assertEqual(confirm, hmac.digest(session[:16], device_random + app_random, "sha256"))
        app_confirm = hmac.digest(session[16:32], app_random + device_random, "sha256")
        deliver_parcel(self.device, 0x0A, app_confirm, now=0.722)
        self.assertTrue(self.device.logged_in)
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.identity)
        self.assertIn((0x0010, bytes.fromhex("21000000")), self.device.drain_notifications())

    def test_disconnect_drops_experimental_session_key_and_rejects_unauthenticated_login(self):
        self.start_handshake()
        self.device.disconnect()
        self.device.connect(1.0)
        self.device.write(0x0010, bytes.fromhex("24000000"), 1.1)
        self.assertFalse(self.device.logged_in)
        self.assertEqual(self.device.drain_notifications(), [(0x0010, bytes.fromhex("e2000000"))])

    def test_normal_models_do_not_activate_psk_when_receiving_a_start_fixture(self):
        device = protocol.MiotProtocol(MAC)
        device.connect()
        deliver_parcel(device, 0, bytes(range(26)), now=0.0)
        self.assertIsNone(device.pending_psk_identity)
        self.assertIsNone(device.pending_identity)
        self.assertFalse(device.bound)
        self.assertIsNone(device._psk_keys)

    def test_psk_model_remains_unavailable_in_the_user_catalog(self):
        self.assertFalse(self.model.available)
        self.assertNotIn(self.model, models.AVAILABLE_MODELS)


if __name__ == "__main__":
    unittest.main()
