"""Controller-independent checks for vendor advertising and transport ordering."""

import asyncio
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

MODULE_PATH = Path(__file__).parents[1] / "custom_components" / "miot_ble_bridge" / "hci.py"
SPEC = importlib.util.spec_from_file_location("miot_bridge_hci_under_test", MODULE_PATH)
hci = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = hci
SPEC.loader.exec_module(hci)

CAPABILITIES = bytes.fromhex("10010028200110015f0020000100")


def complete(opcode, status=0, data=b""):
    body = struct.pack("<BHB", 1, opcode, status) + data
    return bytes((4, 0x0E, len(body))) + body


def vendor_event(instance, state, handle):
    return bytes((4, 0xFF, 5, 0x55, instance, state)) + struct.pack("<H", handle)


class FakeSocket:
    closed = False

    def close(self):
        self.closed = True


class SimulatedAdvertiser(hci.VendorAdvertiser):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.incoming = asyncio.Queue()
        self.sent = []
        self.automatic = True
        self.capability_status = 0
        self.capability_data = CAPABILITIES
        self.fake_socket = FakeSocket()

    def _open_socket(self):
        self.fake_socket.closed = False
        return self.fake_socket

    async def _async_receive(self):
        return await self.incoming.get()

    async def _async_send(self, packet):
        self.sent.append(packet)
        opcode = struct.unpack_from("<H", packet, 1)[0]
        if self.automatic:
            if opcode == hci.HCI_VENDOR_CAPABILITIES:
                response = complete(opcode, self.capability_status, self.capability_data)
            else:
                response = complete(opcode, data=packet[4:5])
            self.incoming.put_nowait(response)


class SimulatedLegacyAdvertiser(SimulatedAdvertiser, hci.LegacyAdvertiser):
    pass


class LegacyTests(unittest.IsolatedAsyncioTestCase):
    async def test_switches_addresses_only_with_advertising_disabled(self):
        events = []
        controller = SimulatedLegacyAdvertiser(event_callback=events.append)
        await controller.async_start()
        try:
            await controller.async_configure(1, "D4:3B:04:5E:2A:10", False)
            await controller.async_configure(2, "D4:3B:04:5E:2A:11", True)
            await controller.async_set_data(1, b"first", b"scan first")
            await controller.async_set_data(2, b"second", b"scan second")
            await controller.async_enable(1)
            central = hci.BluetoothEvent("connected", handle=100, role=0, status=0)
            peripheral = hci.BluetoothEvent("connected", handle=101, role=1, status=0)
            controller._dispatch_event(central)
            controller._dispatch_event(peripheral)
            self.assertEqual(events, [])
            with self.assertRaises(hci.HciError):
                await controller.async_enable(2)
            await controller.async_disable(1)
            await controller.async_enable(2)
            controller._dispatch_event(peripheral)
            controller._dispatch_event(hci.BluetoothEvent("disconnected", handle=101, status=0))
            self.assertEqual([event.instance for event in events], [2, 2])
        finally:
            await controller.async_stop()

        commands = [(struct.unpack_from("<H", packet, 1)[0], packet[4:]) for packet in controller.sent]
        opcodes, payloads = zip(*commands)
        sequence = (0x200A, 0x2005, 0x2006, 0x2008, 0x2009, 0x200A)
        self.assertEqual(opcodes, sequence * 2 + (0x200A,))
        self.assertEqual(payloads[1], bytes.fromhex("102a5e043bd4"))
        self.assertEqual(payloads[7], bytes.fromhex("112a5e043bd4"))
        self.assertEqual(payloads[2][4:6], b"\x02\x01")
        self.assertEqual(payloads[8][4:6], b"\x00\x01")
        self.assertEqual(payloads[-1], b"\x00")


class PacketTests(unittest.TestCase):
    def test_independent_static_address_parameters(self):
        actual = hci.advertising_parameters(15, "C2:A1:55:00:00:0F", False)
        self.assertEqual(actual.hex(), "01a000a00003010f000055a1c20000000000000007000f00")
        self.assertEqual(len(actual), 24)
        self.assertEqual(hci.advertising_parameters(1, "C2:A1:55:00:00:01", True)[5], 0)

    def test_legacy_data_padding_and_instance_position(self):
        data = bytes.fromhex("03030f18")
        actual = hci.advertising_data(15, data)
        self.assertEqual(actual, bytes((2, 4)) + data + bytes(27) + b"\x0f")
        self.assertEqual(len(actual), 34)
        self.assertEqual(hci.advertising_data(1, b"", scan_response=True), b"\x03\x00" + bytes(31) + b"\x01")

    def test_invalid_addresses_and_reserved_instance(self):
        for address in ("00:11:22:33:44:55", "C0:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "bad"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                hci.advertising_parameters(1, address, False)
        with self.assertRaises(ValueError):
            hci.advertising_parameters(0, "C2:A1:55:00:00:01", False)
        with self.assertRaises(ValueError):
            hci.advertising_data(1, bytes(32))
        with self.assertRaises(ValueError):
            hci.advertising_parameters(1, "C2:A1:55:00:00:01", False, interval_ms=20)

    def test_capability_response_from_actual_qca6174(self):
        caps = hci.decode_capabilities(CAPABILITIES)
        self.assertEqual(caps.usable_instances, tuple(range(1, 16)))
        self.assertEqual(caps.scan_result_storage, 10240)
        self.assertEqual(caps.version, 95)
        with self.assertRaises(hci.HciUnsupportedError):
            hci.decode_capabilities(b"\x00" + bytes(7))
        with self.assertRaises(hci.HciUnsupportedError):
            hci.decode_capabilities(bytes(4))

    def test_standard_and_enhanced_connection_events(self):
        body = b"\x01\x00" + struct.pack("<HBB", 0x123, 1, 0) + bytes.fromhex("665544332211") + bytes(7)
        event = hci.parse_hci_event(bytes((4, 0x3E, len(body))) + body)
        self.assertEqual(event.kind, "connected")
        self.assertEqual(event.handle, 0x123)
        self.assertEqual(event.address, "11:22:33:44:55:66")
        enhanced = b"\x0a" + body[1:12] + bytes(12) + body[12:]
        self.assertEqual(hci.parse_hci_event(bytes((4, 0x3E, len(enhanced))) + enhanced).address, event.address)

    def test_vendor_state_disconnect_and_malformed_events(self):
        event = hci.parse_hci_event(vendor_event(10, 0, 0x123))
        self.assertEqual((event.instance, event.state, event.handle), (10, 0, 0x123))
        self.assertIsNone(hci.parse_hci_event(vendor_event(10, 0, 0xFFFF)).handle)
        disconnected = hci.parse_hci_event(bytes.fromhex("04050400230113"))
        self.assertEqual((disconnected.handle, disconnected.reason), (0x123, 0x13))
        for packet in (b"", b"\x04", b"\x04\xff\x05\x55", b"\x04\x3e\x01\x01", b"\x01\x00\x00"):
            self.assertIsNone(hci.parse_hci_event(packet))


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.controller = SimulatedAdvertiser(command_timeout=0.1)
        await self.controller.async_start()

    async def asyncTearDown(self):
        await self.controller.async_stop()

    async def test_configure_and_cleanup_only_owned_instances(self):
        await self.controller.async_configure(10, "C2:A1:55:00:00:0A", False)
        await self.controller.async_set_data(10, bytes.fromhex("03030f18"))
        await self.controller.async_enable(10)
        await self.controller.async_stop()
        commands = self.controller.sent[1:]
        self.assertEqual([packet[4] for packet in commands], [5, 1, 4, 2, 3, 5, 5])
        self.assertEqual(commands[-1][4:], bytes((5, 0, 10)))
        self.assertTrue(self.controller.fake_socket.closed)
        self.assertTrue(all(struct.unpack_from("<H", packet, 1)[0] == 0xFD54 for packet in commands))

    async def test_wrong_reply_and_success_status_do_not_complete_command(self):
        self.controller.automatic = False
        operation = asyncio.create_task(self.controller._command(0xFD54, b"\x02", 2))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.controller.incoming.put_nowait(complete(0xFD53, data=CAPABILITIES))
        self.controller.incoming.put_nowait(complete(0xFD54, data=b"\x03"))
        self.controller.incoming.put_nowait(bytes.fromhex("040f04000154fd"))
        await asyncio.sleep(0)
        self.assertFalse(operation.done())
        self.controller.incoming.put_nowait(complete(0xFD54, data=b"\x02"))
        self.assertEqual(await operation, b"\x02")

    async def test_command_rejection_preserves_transport(self):
        self.controller.automatic = False
        operation = asyncio.create_task(self.controller._command(0xFD54, b"\x01", 1))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.controller.incoming.put_nowait(complete(0xFD54, status=0x12))
        with self.assertRaises(hci.HciCommandError) as caught:
            await operation
        self.assertEqual(caught.exception.status, 0x12)
        self.controller.automatic = True
        self.assertEqual(await self.controller._command(0xFD53), CAPABILITIES)

    async def test_error_for_another_subcommand_is_ignored(self):
        self.controller.automatic = False
        operation = asyncio.create_task(self.controller._command(0xFD54, b"\x01", 1))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.controller.incoming.put_nowait(complete(0xFD54, status=0x12, data=b"\x02"))
        await asyncio.sleep(0)
        self.assertFalse(operation.done())
        self.controller.incoming.put_nowait(complete(0xFD54, data=b"\x01"))
        await operation

    async def test_timeout_closes_transport_and_fails_queued_commands(self):
        self.controller.automatic = False
        first = asyncio.create_task(self.controller._command(0xFD54, b"\x01", 1))
        second = asyncio.create_task(self.controller._command(0xFD54, b"\x01", 1))
        results = await asyncio.gather(first, second, return_exceptions=True)
        self.assertTrue(all(isinstance(result, hci.HciError) for result in results))
        self.assertEqual(len(self.controller.sent), 2)
        self.assertTrue(self.controller.fake_socket.closed)
        with self.assertRaises(hci.HciError):
            await self.controller._command(0xFD54, b"\x01", 1)

    async def test_connection_identity_excludes_ha_central_connections(self):
        events = []
        self.controller._event_callback = events.append
        await self.controller.async_configure(3, "C2:A1:55:00:00:03", True)
        await self.controller.async_enable(3)
        self.controller._dispatch_event(hci.BluetoothEvent("connected", handle=100, role=0, status=0))
        self.controller._dispatch_event(hci.BluetoothEvent("connected", handle=101, role=1, status=0))
        self.controller._dispatch_event(hci.parse_hci_event(vendor_event(3, 0, 101)))
        self.controller._dispatch_event(hci.BluetoothEvent("disconnected", handle=101, status=0))
        self.assertEqual([event.instance for event in events], [None, 3, 3, 3])

    async def test_no_configuration_of_reserved_or_unowned_instances(self):
        with self.assertRaises(hci.HciUnsupportedError):
            await self.controller.async_configure(0, "C2:A1:55:00:00:03", True)
        with self.assertRaises(hci.HciError):
            await self.controller.async_disable(15)
        self.assertEqual(len(self.controller.sent), 1)

    async def test_only_one_pairing_target_even_with_parallel_enable(self):
        await self.controller.async_configure(1, "C2:A1:55:00:00:01", True)
        await self.controller.async_configure(2, "C2:A1:55:00:00:02", True)
        results = await asyncio.gather(
            self.controller.async_enable(1), self.controller.async_enable(2), return_exceptions=True,
        )
        self.assertEqual(sum(isinstance(result, hci.HciError) for result in results), 1)
        self.assertEqual(len(self.controller._enabled), 1)

    async def test_cancelled_shutdown_still_closes_reader_and_worker(self):
        await self.controller.async_configure(1, "C2:A1:55:00:00:01", False)
        self.controller.automatic = False
        shutdown = asyncio.create_task(self.controller.async_stop())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        shutdown.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await shutdown
        self.assertTrue(self.controller.fake_socket.closed)
        self.assertIsNone(self.controller._reader)
        self.assertIsNone(self.controller._worker)

    async def test_restart_after_timeout_joins_failed_transport(self):
        self.controller.automatic = False
        with self.assertRaises(hci.HciError):
            await self.controller._command(0xFD54, b"\x01", 1)
        self.controller.automatic = True
        await self.controller.async_start()
        self.assertEqual(await self.controller._command(0xFD53), CAPABILITIES)

    async def test_queue_is_bounded_and_cancelled_waiter_is_skipped(self):
        controller = SimulatedAdvertiser(command_timeout=0.1, queue_size=1)
        await controller.async_start()
        controller.automatic = False
        first = asyncio.create_task(controller._command(0xFD54, b"\x01", 1))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        queued = asyncio.create_task(controller._command(0xFD54, b"\x02", 2))
        await asyncio.sleep(0)
        with self.assertRaises(hci.HciQueueFullError):
            await controller._command(0xFD54, b"\x03", 3)
        queued.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await queued
        controller.incoming.put_nowait(complete(0xFD54, data=b"\x01"))
        await first
        await asyncio.sleep(0)
        self.assertEqual(len(controller.sent), 2)
        await controller.async_stop()

    async def test_unsupported_vendor_capability_closes_socket(self):
        controller = SimulatedAdvertiser()
        controller.capability_status = 1
        with self.assertRaises(hci.HciUnsupportedError):
            await controller.async_start()
        self.assertTrue(controller.fake_socket.closed)
        self.assertIsNone(controller._reader)
        self.assertIsNone(controller._worker)


if __name__ == "__main__":
    unittest.main()
