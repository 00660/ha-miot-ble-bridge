"""Protocol regression tests with an independent phone-side crypto oracle."""

from __future__ import annotations

import importlib.util
import hmac
from pathlib import Path
import struct
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MODULE_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "miot_ble_bridge" / "protocol.py"
SPEC = importlib.util.spec_from_file_location("miot_test_protocol", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
protocol = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(protocol)

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


def establish_login(device, now=0.0):
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


def decrypt_device_spec(session, notifications):
    packets = decode_parcels(notifications, channel=0x0010)
    replies = []
    for _, wire in packets:
        sequence = struct.unpack_from("<H", wire)[0]
        nonce = session[32:36] + bytes(4) + struct.pack("<I", sequence)
        replies.append(AESCCM(session[:16], tag_length=4).decrypt(nonce, wire[2:], None))
    return replies


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
        self.assertNotIn((0x0010, b"\x11\x00\x00\x00"), self.device.drain_notifications())
        self.device.commit_identity(pending)
        self.assertTrue(self.device.bound)
        self.assertEqual(self.device.drain_notifications(), [(0x0010, b"\x11\x00\x00\x00")])
        restarted = protocol.MiotProtocol(MAC, pending)
        self.assertTrue(restarted.bound)

    def test_certificate_without_authenticated_did_cannot_bind(self):
        self.start_registration()
        deliver_parcel(self.device, 7, bytes(163))
        self.assertFalse(self.device.bound)
        self.assertIsNone(self.device.pending_identity)
        self.assertNotIn((0x0010, b"\x11\x00\x00\x00"), self.device.drain_notifications())

    def test_failed_save_does_not_ack_registration(self):
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


if __name__ == "__main__":
    unittest.main()
