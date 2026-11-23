"""BlueZ DBus object and bounded notification tests without a real bus."""

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from dbus_fast import DBusError, Variant


MODULE_PATH = Path(__file__).parents[1] / "custom_components" / "miot_ble_bridge" / "bluez.py"
SPEC = importlib.util.spec_from_file_location("miot_bluez_under_test", MODULE_PATH)
bluez = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bluez
SPEC.loader.exec_module(bluez)


def method_body(instance, name, *args):
    function = getattr(type(instance), name)
    return getattr(function, "__wrapped__", function)(instance, *args)


class ObjectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.writer = AsyncMock()
        self.server = bluez.BlueZServer("hci0", self.writer, lambda _channel: b"sample")

    async def test_object_manager_exports_service_and_all_four_characteristics(self):
        objects = method_body(self.server.application, "GetManagedObjects")
        self.assertEqual(len(objects), 5)
        service = objects[self.server.service.path]["org.bluez.GattService1"]
        self.assertEqual(service["UUID"].value, "0000fe95-0000-1000-8000-00805f9b34fb")
        self.assertTrue(service["Primary"].value)
        for channel in (0x0010, 0x0019, 0x001A, 0x001B):
            char = self.server.characteristics[channel]
            properties = objects[char.path]["org.bluez.GattCharacteristic1"]
            self.assertEqual(properties["Service"].value, self.server.service.path)
            self.assertIn("notify", properties["Flags"].value)

    async def test_read_offset_and_invalid_offset(self):
        char = self.server.characteristics[0x0019]
        self.assertEqual(method_body(char, "ReadValue", {"offset": Variant("q", 2)}), b"mple")
        with self.assertRaises(DBusError) as raised:
            method_body(char, "ReadValue", {"offset": Variant("q", 7)})
        self.assertEqual(raised.exception.type, "org.bluez.Error.InvalidOffset")

    async def test_write_forwards_channel_bytes_and_peer(self):
        char = self.server.characteristics[0x0010]
        await method_body(char, "WriteValue", b"\xa4", {"device": Variant("o", "/test/peer")})
        self.writer.assert_awaited_once_with(0x0010, b"\xa4", "/test/peer")

    async def test_invalid_write_offset_or_length_is_rejected(self):
        char = self.server.characteristics[0x0019]
        for value, options, error in (
            (b"part", {"offset": Variant("q", 1)}, "org.bluez.Error.InvalidOffset"),
            (bytes(245), {}, "org.bluez.Error.InvalidValueLength"),
        ):
            with self.subTest(error=error), self.assertRaises(DBusError) as raised:
                await method_body(char, "WriteValue", value, options)
            self.assertEqual(raised.exception.type, error)
        self.writer.assert_not_awaited()

    async def test_queue_capacity_preserves_accepted_packets(self):
        char = self.server.characteristics[0x0019]
        accepted = [bytes((number,)) for number in range(16)]
        for value in accepted:
            self.assertTrue(char.notify(value))
        self.assertFalse(char.notify(b"overflow"))
        self.assertEqual(list(char._pending), accepted)
        emitted = []
        with patch.object(char, "emit_properties_changed", side_effect=emitted.append):
            method_body(char, "StartNotify")
            self.assertTrue(char.notify(b"next"))
        self.assertEqual(
            [change["Value"] for change in emitted if "Value" in change], accepted + [b"next"]
        )
        self.assertFalse(char._pending)

    async def test_stop_notify_clears_session_and_stale_packets(self):
        char = self.server.characteristics[0x0019]
        char.notify(b"old")
        with patch.object(char, "emit_properties_changed"):
            method_body(char, "StartNotify")
            method_body(char, "StopNotify")
        self.assertFalse(char._notifying)
        self.assertFalse(char._pending)
        self.assertEqual(char._value, b"")
        self.server.notify(0x0019, b"pending")
        self.server.reset_session()
        self.assertFalse(char._pending)


class FakeBus:
    def __init__(self, manager):
        self.manager = manager
        self.exports = []
        self.disconnected = 0

    async def connect(self):
        return self

    async def introspect(self, service, path):
        return object()

    def get_proxy_object(self, service, path, introspection):
        return SimpleNamespace(get_interface=lambda _name: self.manager)

    def export(self, path, interface):
        self.exports.append(path)

    def disconnect(self):
        self.disconnected += 1


class ServerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = bluez.BlueZServer("hci0", AsyncMock(), lambda _channel: b"")
        self.manager = SimpleNamespace(
            call_register_application=AsyncMock(),
            call_unregister_application=AsyncMock(),
        )
        self.bus = FakeBus(self.manager)

    async def test_start_exports_only_own_application_and_stop_is_idempotent(self):
        with patch.object(bluez, "MessageBus", return_value=self.bus):
            await self.server.async_start()
        self.assertEqual(len(self.bus.exports), 6)
        self.assertTrue(all(path.startswith("/org/miot_ble_bridge/hci0") for path in self.bus.exports))
        self.manager.call_register_application.assert_awaited_once_with(self.server.path, {})
        await self.server.async_stop()
        await self.server.async_stop()
        self.manager.call_unregister_application.assert_awaited_once_with(self.server.path)
        self.assertEqual(self.bus.disconnected, 1)
        self.assertIsNone(self.server.bus)

    async def test_failed_registration_disconnects_bus(self):
        self.manager.call_register_application.side_effect = DBusError("org.bluez.Error.Failed", "Injected failure")
        with patch.object(bluez, "MessageBus", return_value=self.bus), self.assertRaises(DBusError):
            await self.server.async_start()
        self.assertEqual(self.bus.disconnected, 1)
        self.assertFalse(self.server._registered)
        self.assertIsNone(self.server.bus)

    async def test_unregister_failure_still_disconnects_bus(self):
        with patch.object(bluez, "MessageBus", return_value=self.bus):
            await self.server.async_start()
        self.manager.call_unregister_application.side_effect = DBusError("org.bluez.Error.Failed", "Injected failure")
        await self.server.async_stop()
        self.assertEqual(self.bus.disconnected, 1)
        self.assertFalse(self.server._registered)
        self.assertIsNone(self.server.bus)


if __name__ == "__main__":
    unittest.main()
