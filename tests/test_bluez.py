"""BlueZ DBus object and bounded notification tests without a real bus."""

import asyncio
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

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

    async def test_object_manager_exports_auth_auxiliary_and_nus_characteristics(self):
        objects = method_body(self.server.application, "GetManagedObjects")
        self.assertEqual(len(objects), 16)
        service = objects[self.server.service.path]["org.bluez.GattService1"]
        self.assertEqual(service["UUID"].value, "0000fe95-0000-1000-8000-00805f9b34fb")
        self.assertTrue(service["Primary"].value)
        for channel in (0x0010, 0x0019, 0x001A, 0x001B):
            char = self.server.characteristics[channel]
            properties = objects[char.path]["org.bluez.GattCharacteristic1"]
            self.assertEqual(properties["Service"].value, self.server.service.path)
            self.assertIn("notify", properties["Flags"].value)
        for channel in (0x0002, 0x0004, 0x0014):
            self.assertEqual(self.server.characteristics[channel].Flags, ["read"])
        nus = objects[self.server.nus_service.path]["org.bluez.GattService1"]
        self.assertEqual(nus["UUID"].value, "6e400001-b5a3-f393-e0a9-e50e24dcca9e")
        self.assertEqual(self.server.characteristics[bluez.NUS_RX].UUID, "6e400002-b5a3-f393-e0a9-e50e24dcca9e")
        self.assertEqual(self.server.characteristics[bluez.NUS_TX].Service, self.server.nus_service.path)

    async def test_subscription_changes_report_exact_active_channels(self):
        self.server.subscription_callback = Mock()
        auth = self.server.characteristics[0x0019]
        spec = self.server.characteristics[0x001A]
        with patch.object(auth, "emit_properties_changed"), patch.object(spec, "emit_properties_changed"):
            method_body(auth, "StartNotify")
            method_body(spec, "StartNotify")
            method_body(auth, "StopNotify")
        self.assertEqual([call.args[0] for call in self.server.subscription_callback.call_args_list], [{0x0019}, {0x0019, 0x001A}, {0x001A}])
        self.assertEqual(self.server.notifying_channels, {0x001A})

    async def test_nus_input_uses_its_own_channel_and_peer(self):
        char = self.server.characteristics[bluez.NUS_RX]
        await method_body(char, "WriteValue", b"get_prop power bright", {"device": Variant("o", "/test/peer")})
        self.writer.assert_awaited_once_with(bluez.NUS_RX, b"get_prop power bright", "/test/peer")

    async def test_negotiated_mtu_is_forwarded_before_the_write(self):
        observed = []
        self.server.mtu_callback = observed.append
        char = self.server.characteristics[bluez.NUS_RX]
        await method_body(char, "WriteValue", b"get_prop power", {"mtu": Variant("q", 247)})
        self.assertEqual(observed, [247])
        self.assertEqual(self.server.att_mtu, 247)
        self.server.reset_session()
        self.assertIsNone(self.server.att_mtu)

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
        self.assertEqual(len(self.bus.exports), 17)
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


class LegacyScannerLeaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = bluez.BlueZServer("hci0", AsyncMock(), lambda _channel: b"")
        self.events = []
        self.powered = True
        self.active_advertisers = 0
        self.external_discovery = False
        self.managed_objects = {}
        self.local_entry = self.make_entry("local", "AA:BB:CC:DD:EE:00")
        self.other_entry = self.make_entry("other", "AA:BB:CC:DD:EE:01")
        self.proxy_entry = self.make_entry("proxy", self.local_entry.unique_id)
        self.proxy_entry.data["source_config_entry_id"] = "esphome-proxy"
        self.entries = {
            entry.entry_id: entry for entry in (self.local_entry, self.other_entry, self.proxy_entry)
        }
        self.hass = SimpleNamespace(
            is_stopping=False,
            config_entries=SimpleNamespace(
                async_entries=Mock(side_effect=lambda _domain: list(self.entries.values())),
                async_get_entry=Mock(side_effect=self.entries.get),
                async_unload=AsyncMock(side_effect=self.unload_entry),
                async_setup=AsyncMock(side_effect=self.setup_entry),
            ),
        )
        self.manager = SimpleNamespace(
            call_register_application=AsyncMock(),
            call_unregister_application=AsyncMock(),
            call_get=AsyncMock(side_effect=self.get_property),
            call_set=AsyncMock(side_effect=self.set_property),
            call_get_managed_objects=AsyncMock(side_effect=lambda: self.managed_objects),
        )
        self.bus = FakeBus(self.manager)
        with patch.object(bluez, "MessageBus", return_value=self.bus):
            await self.server.async_start()
        self.scanners = patch.object(
            self.server, "_local_scanner_sources", side_effect=self.local_sources,
        )
        self.scanners.start()
        self.addCleanup(self.scanners.stop)

    @staticmethod
    def make_entry(entry_id, address):
        return SimpleNamespace(
            entry_id=entry_id, unique_id=address, state=SimpleNamespace(value="loaded"),
            data={"address": address}, options={"scanning_mode": "active"}, disabled_by=None,
        )

    def local_sources(self, _hass, adapter):
        if adapter == "hci0" and self.local_entry.state.value == "loaded":
            return {self.local_entry.unique_id}
        return set()

    async def unload_entry(self, entry_id):
        self.events.append(("unload", entry_id))
        self.entries[entry_id].state.value = "not_loaded"
        return True

    async def setup_entry(self, entry_id):
        self.events.append(("setup", entry_id))
        self.entries[entry_id].state.value = "loaded"
        return True

    async def get_property(self, interface, name):
        return {
            "ActiveInstances": Variant("y", self.active_advertisers),
            "Discovering": Variant("b", self.external_discovery),
            "Powered": Variant("b", self.powered),
            "Address": Variant("s", self.local_entry.unique_id.lower()),
        }[name]

    async def set_property(self, interface, name, value):
        self.assertEqual((interface, name), ("org.bluez.Adapter1", "Powered"))
        self.events.append(("power", value.value))
        self.powered = value.value

    def connected_device(self, adapter="hci0"):
        return {
            f"/org/bluez/{adapter}/dev_11_22_33_44_55_66": {
                "org.bluez.Device1": {"Connected": Variant("b", True)},
            },
        }

    async def test_lease_only_pauses_matching_local_entry_and_preserves_configuration(self):
        original = [(entry.data.copy(), entry.options.copy(), entry.disabled_by) for entry in self.entries.values()]
        await self.server.async_require_idle_advertising(self.hass)
        self.assertTrue(self.server.local_scanning_paused)
        self.assertEqual(self.events, [("unload", "local"), ("power", False), ("power", True)])
        self.assertTrue(self.server._registered)
        self.manager.call_unregister_application.assert_not_awaited()
        self.assertEqual(self.other_entry.state.value, "loaded")
        self.assertEqual(self.proxy_entry.state.value, "loaded")
        await self.server.async_stop()
        self.assertEqual(self.events[-3:], [("power", False), ("power", True), ("setup", "local")])
        self.hass.config_entries.async_unload.assert_awaited_once_with("local")
        self.hass.config_entries.async_setup.assert_awaited_once_with("local")
        self.assertEqual(original, [(entry.data, entry.options, entry.disabled_by) for entry in self.entries.values()])
        self.assertTrue(self.powered)
        self.assertFalse(self.server.local_scanning_paused)
        self.assertEqual(self.bus.disconnected, 1)

    async def test_other_adapter_connection_does_not_block_dedicated_adapter(self):
        self.managed_objects = self.connected_device("hci1")
        await self.server.async_require_idle_advertising(self.hass)
        await self.server.async_stop()
        self.assertEqual(self.local_entry.state.value, "loaded")

    async def test_advertisement_or_connected_peer_is_rejected_before_pausing_ha(self):
        for occupancy in ("advertisement", "connection"):
            with self.subTest(occupancy=occupancy):
                self.active_advertisers = int(occupancy == "advertisement")
                self.managed_objects = self.connected_device() if occupancy == "connection" else {}
                with self.assertRaisesRegex(RuntimeError, "another client|advertisements"):
                    await self.server.async_require_idle_advertising(self.hass)
        self.hass.config_entries.async_unload.assert_not_awaited()
        self.manager.call_set.assert_not_awaited()

    async def test_external_discovery_after_unload_rolls_back_without_reset(self):
        self.external_discovery = True
        with self.assertRaisesRegex(RuntimeError, "discovery"):
            await self.server.async_require_idle_advertising(self.hass)
        self.assertEqual(self.events, [("unload", "local"), ("setup", "local")])
        self.assertFalse(self.server._legacy_entry_ids)
        self.assertIsNone(self.server._legacy_hass)

    async def test_discovery_without_ha_ownership_is_rejected(self):
        self.external_discovery = True
        with self.assertRaisesRegex(RuntimeError, "discovery"):
            await self.server.async_require_idle_advertising()
        self.manager.call_set.assert_not_awaited()

    async def test_powered_off_adapter_is_not_turned_on_by_acquisition(self):
        self.powered = False
        with self.assertRaisesRegex(RuntimeError, "must be powered"):
            await self.server.async_require_idle_advertising(self.hass)
        self.hass.config_entries.async_unload.assert_not_awaited()
        self.manager.call_set.assert_not_awaited()

    async def test_missing_or_ambiguous_scanner_owner_is_rejected(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                self.entries.pop("duplicate", None)
                self.entries.pop("local", None)
                if ambiguous:
                    self.entries["local"] = self.local_entry
                    self.entries["duplicate"] = self.make_entry("duplicate", self.local_entry.unique_id)
                with self.assertRaisesRegex(RuntimeError, "Cannot safely pause"):
                    await self.server.async_require_idle_advertising(self.hass)
        self.hass.config_entries.async_unload.assert_not_awaited()

    async def test_previously_unloaded_entry_stays_unloaded(self):
        self.local_entry.state.value = "not_loaded"
        await self.server.async_require_idle_advertising(self.hass)
        await self.server.async_stop()
        self.hass.config_entries.async_unload.assert_not_awaited()
        self.hass.config_entries.async_setup.assert_not_awaited()
        self.assertEqual(self.local_entry.state.value, "not_loaded")

    async def test_unload_failure_with_loaded_entry_preserves_running_scanner(self):
        self.hass.config_entries.async_unload.side_effect = None
        self.hass.config_entries.async_unload.return_value = False
        with self.assertRaisesRegex(RuntimeError, "Unable to pause"):
            await self.server.async_require_idle_advertising(self.hass)
        self.hass.config_entries.async_setup.assert_not_awaited()
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.assertFalse(self.server._legacy_entry_ids)

    async def test_native_failed_unload_is_reported_and_keeps_recovery_record(self):
        async def fail_unload(_entry_id):
            self.local_entry.state.value = "failed_unload"
            return False

        self.hass.config_entries.async_unload.side_effect = fail_unload
        with self.assertRaisesRegex(RuntimeError, "failed_unload"):
            await self.server.async_require_idle_advertising(self.hass)
        self.assertEqual(self.server._legacy_entry_ids, ["local"])
        self.assertIs(self.server._legacy_hass, self.hass)
        with self.assertRaisesRegex(RuntimeError, "failed_unload"):
            await self.server.async_stop()
        self.assertIsNone(self.server.bus)
        self.assertEqual(self.bus.disconnected, 1)

    async def test_cancellation_waits_for_unload_before_restoring_original_entry(self):
        entered = asyncio.Event()
        finish = asyncio.Event()

        async def unload(_entry_id):
            self.local_entry.state.value = "unload_in_progress"
            entered.set()
            await finish.wait()
            return await self.unload_entry("local")

        self.hass.config_entries.async_unload.side_effect = unload
        acquire = asyncio.create_task(self.server.async_require_idle_advertising(self.hass))
        await entered.wait()
        acquire.cancel()
        await asyncio.sleep(0)
        self.assertFalse(acquire.done())
        finish.set()
        with self.assertRaises(asyncio.CancelledError):
            await acquire
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.hass.config_entries.async_setup.assert_awaited_once_with("local")
        self.manager.call_set.assert_not_awaited()
        self.assertFalse(self.server._legacy_entry_ids)

    async def test_failed_power_down_still_restores_power_and_scanner(self):
        async def fail_power_down(interface, name, value):
            await self.set_property(interface, name, value)
            if not value.value:
                raise DBusError("org.bluez.Error.Failed", "Injected reset failure")

        self.manager.call_set.side_effect = fail_power_down
        with self.assertRaises(DBusError):
            await self.server.async_require_idle_advertising(self.hass)
        self.assertTrue(self.powered)
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.assertEqual(self.events, [("unload", "local"), ("power", False), ("power", True), ("setup", "local")])

    async def test_failed_exit_reset_restores_scanner_and_reports_error(self):
        await self.server.async_require_idle_advertising(self.hass)

        async def fail_power_down(interface, name, value):
            await self.set_property(interface, name, value)
            if not value.value:
                raise DBusError("org.bluez.Error.Failed", "Injected reset failure")

        self.manager.call_set.side_effect = fail_power_down
        with self.assertRaises(DBusError):
            await self.server.async_stop()
        self.assertTrue(self.powered)
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.assertIsNone(self.server.bus)
        self.assertEqual(self.bus.disconnected, 1)

    async def test_external_occupancy_at_stop_restores_scanner_without_resetting_peer(self):
        await self.server.async_require_idle_advertising(self.hass)
        self.managed_objects = self.connected_device()
        self.events.clear()
        with self.assertRaisesRegex(RuntimeError, "another client"):
            await self.server.async_stop()
        self.assertEqual(self.events, [("setup", "local")])
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.assertIsNone(self.server.bus)
        self.assertEqual(self.bus.disconnected, 1)

    async def test_restore_failure_is_retryable_after_bus_cleanup(self):
        await self.server.async_require_idle_advertising(self.hass)

        async def fail_setup(_entry_id):
            self.local_entry.state.value = "setup_error"
            return False

        self.hass.config_entries.async_setup.side_effect = fail_setup
        with self.assertRaisesRegex(RuntimeError, "Unable to restore"):
            await self.server.async_stop()
        self.assertEqual(self.server._legacy_entry_ids, ["local"])
        self.assertIs(self.server._legacy_hass, self.hass)
        self.assertIsNone(self.server.bus)
        self.hass.config_entries.async_setup.side_effect = self.setup_entry
        await self.server.async_stop()
        self.assertEqual(self.events[-2:], [("unload", "local"), ("setup", "local")])
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.assertFalse(self.server._legacy_entry_ids)
        self.assertIsNone(self.server._legacy_hass)
        self.assertEqual(self.bus.disconnected, 1)

    async def test_cancelled_restore_finishes_setup_and_can_clear_record_on_retry(self):
        await self.server.async_require_idle_advertising(self.hass)
        entered = asyncio.Event()
        finish = asyncio.Event()

        async def setup(_entry_id):
            self.local_entry.state.value = "setup_in_progress"
            entered.set()
            await finish.wait()
            return await self.setup_entry("local")

        self.hass.config_entries.async_setup.side_effect = setup
        stop = asyncio.create_task(self.server.async_stop())
        await entered.wait()
        stop.cancel()
        await asyncio.sleep(0)
        self.assertFalse(stop.done())
        finish.set()
        with self.assertRaises(asyncio.CancelledError):
            await stop
        self.assertEqual(self.local_entry.state.value, "loaded")
        self.assertEqual(self.server._legacy_entry_ids, ["local"])
        self.assertIsNone(self.server.bus)
        await self.server.async_stop()
        self.assertFalse(self.server._legacy_entry_ids)
        self.hass.config_entries.async_setup.assert_awaited_once_with("local")

    async def test_user_disabling_or_removing_entry_is_respected_at_stop(self):
        for remove in (False, True):
            with self.subTest(remove=remove):
                await self.server.async_require_idle_advertising(self.hass)
                if remove:
                    self.entries.pop("local")
                else:
                    self.local_entry.disabled_by = "user"
                await self.server._async_release_legacy()
                self.assertFalse(self.server._legacy_entry_ids)
                self.hass.config_entries.async_setup.assert_not_awaited()
                if remove:
                    self.assertNotIn("local", self.entries)
                else:
                    self.assertEqual(self.local_entry.disabled_by, "user")
                self.local_entry.disabled_by = None
                self.local_entry.state.value = "loaded"

    async def test_shutdown_leaves_configuration_enabled_for_next_ha_start(self):
        await self.server.async_require_idle_advertising(self.hass)
        self.hass.is_stopping = True
        await self.server.async_stop()
        self.hass.config_entries.async_setup.assert_not_awaited()
        self.assertIsNone(self.local_entry.disabled_by)
        self.assertFalse(self.server._legacy_entry_ids)

    async def test_ha_scanner_restart_during_lease_is_rejected(self):
        await self.server.async_require_idle_advertising(self.hass)
        self.local_entry.state.value = "loaded"
        with self.assertRaisesRegex(RuntimeError, "restarted"):
            await self.server.async_check_legacy_occupancy()

    async def test_incoming_during_each_dbus_query_freezes_without_misclassifying_own_peer(self):
        await self.server.async_require_idle_advertising(self.hass)
        for stage in ("ActiveInstances", "Discovering", "introspect", "objects"):
            with self.subTest(stage=stage):
                pending = False

                async def get_property(interface, name):
                    nonlocal pending
                    if name == stage:
                        pending = True
                        return Variant("y", 1) if name == "ActiveInstances" else Variant("b", True)
                    return await self.get_property(interface, name)

                async def introspect(_service, _path):
                    nonlocal pending
                    if stage == "introspect":
                        pending = True
                    return object()

                async def objects():
                    nonlocal pending
                    pending = True
                    return self.connected_device()

                with patch.object(self.manager, "call_get", AsyncMock(side_effect=get_property)), patch.object(
                    self.bus, "introspect", AsyncMock(side_effect=introspect),
                ), patch.object(self.manager, "call_get_managed_objects", AsyncMock(side_effect=objects)):
                    self.assertFalse(await self.server.async_check_legacy_occupancy(busy=lambda: pending))
        self.assertTrue(self.server._legacy_acquired)
        self.hass.config_entries.async_setup.assert_not_awaited()
        self.assertEqual(self.manager.call_set.await_count, 2)

    async def test_public_scanner_query_filters_proxy_and_other_local_adapter(self):
        class LocalScanner:
            def __init__(self, adapter, source):
                self.adapter, self.source = adapter, source

        current = Mock(return_value=(
            LocalScanner("hci0", "aa:bb:cc:dd:ee:00"),
            LocalScanner("hci1", "aa:bb:cc:dd:ee:01"),
            SimpleNamespace(adapter="hci0", source="remote-proxy"),
        ))
        with patch.dict(sys.modules, {
            "habluetooth": SimpleNamespace(HaScanner=LocalScanner),
            "homeassistant.components.bluetooth": SimpleNamespace(async_current_scanners=current),
        }):
            self.assertEqual(bluez.BlueZServer._local_scanner_sources(self.hass, "hci0"), {"AA:BB:CC:DD:EE:00"})
        current.assert_called_once_with(self.hass)


if __name__ == "__main__":
    unittest.main()
