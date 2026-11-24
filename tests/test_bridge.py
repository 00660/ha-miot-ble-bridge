"""Bridge state, durable writes and lifecycle regressions; no real Bluetooth IO."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from dbus_fast import DBusError
from homeassistant.core import HassJob, HassJobType
from test_protocol import deliver_parcel, encrypt_phone_spec, establish_login


COMPONENT = Path(__file__).parents[1] / "custom_components" / "miot_ble_bridge"
PACKAGE = "miot_bridge_runtime_under_test"
if PACKAGE not in sys.modules:
    package = ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package
bridge = importlib.import_module(f"{PACKAGE}.bridge")
spec = importlib.util.spec_from_file_location(f"{PACKAGE}.integration", COMPONENT / "__init__.py")
integration = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = integration
spec.loader.exec_module(integration)

MAC = "D4:3B:04:5E:2A:10"
IDENTITY = {
    "version": 1,
    "mac": MAC,
    "pid": 0x4683,
    "token": bytes(range(12)).hex(),
    "bind_key": bytes(range(16)).hex(),
    "dev_key": bytes(range(16, 32)).hex(),
    "did": "blt.3.bridgefixture",
    "sign": bytes(range(64)).hex(),
    "utc": 1795480000,
}


class FakeStates:
    def __init__(self):
        self.values = {}

    def get(self, entity_id):
        return self.values.get(entity_id)

    def set(self, entity_id, value, **attributes):
        self.values[entity_id] = SimpleNamespace(state=value, attributes=attributes)


class FakeBus:
    def __init__(self):
        self.listeners = []

    def async_listen(self, event_type, action):
        record = (event_type, action)
        self.listeners.append(record)
        return lambda: self.listeners.remove(record)

    def async_listen_once(self, event_type, action):
        return self.async_listen(event_type, action)


class FakeHass:
    def __init__(self, root):
        self.states = FakeStates()
        self.bus = FakeBus()
        self.data = {}
        self.loop = asyncio.get_running_loop()
        self.config = SimpleNamespace(path=lambda *parts: str(root.joinpath(*parts)))
        self.fail_writes = False
        self.services = SimpleNamespace(async_call=AsyncMock())
        self.tasks = set()
        self.config_entries = SimpleNamespace(
            async_forward_entry_setups=AsyncMock(),
            async_unload_platforms=AsyncMock(return_value=True),
        )

    async def async_add_executor_job(self, function, *args):
        if self.fail_writes and function is bridge.write_utf8_file_atomic:
            raise OSError("Injected durable write failure")
        return await asyncio.to_thread(function, *args)

    def async_create_background_task(self, coroutine, name):
        task = asyncio.create_task(coroutine, name=name)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task


class FakeEntry:
    def __init__(self, entry_id="radar-entry", *, lux=None):
        self.entry_id = entry_id
        self.data = {
            "name": "Radar",
            "presence_entity": "binary_sensor.radar",
            "illuminance_entity": lux,
            "adapter": "hci0",
        }
        self.options = {}
        self.on_unload = []

    def async_on_unload(self, function):
        self.on_unload.append(function)


class FakeAdvertiser:
    def __init__(self):
        self.usable_instances = tuple(range(1, 16))
        self.configured = []
        self.disabled = []
        self.enabled = []
        self.data = []
        self.disable_error = None
        self.started = False
        self.stopped = False

    async def async_start(self):
        self.started = True

    async def async_configure(self, instance, mac, connectable, **kwargs):
        self.configured.append((instance, mac, connectable))

    async def async_set_data(self, instance, data, scan_response=None):
        self.data.append((instance, data))

    async def async_enable(self, instance):
        self.enabled.append(instance)

    async def async_disable(self, instance):
        self.disabled.append(instance)
        if self.disable_error:
            raise self.disable_error

    async def async_stop(self):
        self.stopped = True


class FakeServer:
    def __init__(self):
        self.started = False
        self.stopped = False
        self.start_error = None
        self.disconnect_error = None
        self.notifications = []
        self.disconnected = []
        self.accept = True
        self.reset_count = 0

    async def async_start(self):
        if self.start_error:
            raise self.start_error
        self.started = True

    async def async_stop(self):
        self.stopped = True

    async def async_check_legacy_occupancy(self, *, busy=None):
        return busy is None or not busy()

    async def async_disconnect_peer(self, address):
        self.disconnected.append(address)
        if self.disconnect_error:
            raise self.disconnect_error

    def reset_session(self):
        self.reset_count += 1

    def notify(self, channel, value):
        if not self.accept:
            return False
        self.notifications.append((channel, value))
        return True


class FakeLegacyAdvertiser(bridge.LegacyAdvertiser):
    """Run legacy ownership rules and replace only the controller transport."""

    def __init__(self, event_callback):
        super().__init__(event_callback=event_callback)
        self.configured = []
        self.disabled = []
        self.enabled = []
        self.data = []
        self.commands = []
        self.command_hook = None
        self.configure_hook = None
        self.stopped = False

    async def _command(self, opcode, payload=b"", *args, **kwargs):
        self.commands.append((opcode, payload))
        if self.command_hook:
            await self.command_hook(opcode, payload)
        return b""

    async def async_configure(self, instance, mac, connectable, **kwargs):
        self.configured.append((instance, mac, connectable))
        await super().async_configure(instance, mac, connectable, **kwargs)
        if self.configure_hook:
            await self.configure_hook(instance)

    async def async_set_data(self, instance, data, scan_response=b""):
        self.data.append((instance, data))
        await super().async_set_data(instance, data, scan_response)

    async def async_enable(self, instance):
        enabled = await super().async_enable(instance)
        if enabled:
            self.enabled.append(instance)
        return enabled

    async def async_disable(self, instance):
        self.disabled.append(instance)
        await super().async_disable(instance)

    async def async_stop(self):
        self.stopped = True
        await super().async_stop()


class BridgeTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.joinpath(".storage").mkdir()
        self.hass = FakeHass(self.root)
        self.manager = bridge.BridgeManager(self.hass)
        self.manager.advertiser = FakeAdvertiser()
        self.manager.server = FakeServer()

    async def asyncTearDown(self):
        await self.manager.async_stop()
        remaining = tuple(self.hass.tasks)
        for task in remaining:
            task.cancel()
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)

    def runtime(self, *, bound=False, lux=None, entry_id="radar-entry"):
        document = {
            "version": 1,
            "mac": MAC,
            "identity": dict(IDENTITY) if bound else None,
            "counter_reserved_until": 0,
            "paired_at": None,
        }
        return bridge.RadarRuntime(
            self.hass, FakeEntry(entry_id, lux=lux), self.manager, document
        )

    def model_runtime(self, model_id, *, entry_id="model-entry", mappings=None, mac=MAC):
        model = bridge.get_model(model_id)
        entry = FakeEntry(entry_id)
        entry.data = {"name": "Model", "adapter": "hci0", "model": model_id, "property_mappings": mappings if mappings is not None else bridge.default_mappings(model, {})}
        document = {"version": 1, "mac": mac, "identity": {**IDENTITY, "mac": mac, "pid": model.pid}, "counter_reserved_until": 0, "paired_at": None}
        runtime = bridge.RadarRuntime(self.hass, entry, self.manager, document)
        runtime.sync_sources()
        return runtime

    def authenticated_request(self, runtime, items):
        captured = []
        original = runtime.protocol.on_set
        runtime.protocol.on_set = captured.append
        try:
            session = establish_login(runtime.protocol)
            body = bytes([len(items)])
            for key, value in items:
                prop = runtime.model.property_by_key[key]
                raw = prop.encode(value)
                body += bytes([prop.siid]) + prop.piid.to_bytes(2, "little") + ((prop.type_code << 12) | len(raw)).to_bytes(2, "little") + raw
            plain = runtime.protocol._spec_plain(0, 7, body)
            deliver_parcel(runtime.protocol, 0, encrypt_phone_spec(session, plain), channel=0x001A, now=0.2)
            return captured[0]
        finally:
            runtime.protocol.on_set = original


class SourceStateTests(BridgeTestCase):
    async def test_unknown_unavailable_and_removed_do_not_become_absence(self):
        for value in ("unknown", "unavailable", None):
            with self.subTest(value=value):
                runtime = self.runtime(bound=True)
                self.hass.states.set(runtime.presence_entity, "on")
                with patch.object(bridge.time, "monotonic", return_value=100):
                    runtime.sync_sources()
                runtime.update_duration(400)
                self.assertEqual(runtime._present_minutes, 5)
                if value is None:
                    self.hass.states.values.pop(runtime.presence_entity)
                else:
                    self.hass.states.set(runtime.presence_entity, value)
                runtime.sync_sources()
                self.assertIsNone(runtime._presence)
                self.assertIsNone(runtime._since)
                self.assertEqual((runtime._present_minutes, runtime._absent_minutes), (0, 0))
                self.assertNotIn(bridge._PRESENCE, runtime._objects)
                self.assertNotIn(bridge._PRESENT_MINUTES, runtime._pending_objects)
                self.assertNotIn((2, 1078), runtime.protocol.properties)
                runtime.update_duration(100000)
                self.assertEqual(runtime._absent_minutes, 0)

    async def test_offline_bound_radar_disables_broadcast(self):
        runtime = self.runtime(bound=True)
        runtime.instance = 3
        runtime._enabled = True
        self.hass.states.set(runtime.presence_entity, "unavailable")
        runtime.sync_sources()
        await self.manager._async_publish(runtime, 100)
        self.assertEqual(self.manager.advertiser.disabled, [3])
        self.assertEqual(self.manager.advertiser.data, [])
        self.assertFalse(runtime._enabled)

    async def test_same_presence_attribute_updates_preserve_duration_origin(self):
        runtime = self.runtime()
        self.hass.states.set(runtime.presence_entity, "on", distance=200)
        with patch.object(bridge.time, "monotonic", return_value=100):
            runtime.sync_sources()
        self.hass.states.set(runtime.presence_entity, "on", distance=300)
        with patch.object(bridge.time, "monotonic", return_value=190):
            runtime.sync_sources()
        self.assertEqual(runtime._since, 100)
        runtime.update_duration(220)
        self.assertEqual(runtime._present_minutes, 2)

    async def test_present_duration_emits_only_two_and_five_minutes(self):
        runtime = self.runtime()
        self.hass.states.set(runtime.presence_entity, "on")
        with patch.object(bridge.time, "monotonic", return_value=100):
            runtime.sync_sources()
        for seconds, expected in ((119.999, 0), (120, 2), (299.999, 2), (300, 5), (1800, 5)):
            with self.subTest(seconds=seconds):
                runtime.update_duration(100 + seconds)
                self.assertEqual(runtime._present_minutes, expected)
                self.assertEqual(runtime._absent_minutes, 0)
                if expected:
                    self.assertEqual(runtime._objects[bridge._PRESENT_MINUTES], expected)
                else:
                    self.assertNotIn(bridge._PRESENT_MINUTES, runtime._objects)

    async def test_absence_duration_emits_only_specified_milestones(self):
        runtime = self.runtime()
        self.hass.states.set(runtime.presence_entity, "off")
        with patch.object(bridge.time, "monotonic", return_value=100):
            runtime.sync_sources()
        for minutes, expected in ((1.99, 0), (2, 2), (5, 5), (10, 10), (30, 30), (60, 30)):
            with self.subTest(minutes=minutes):
                runtime.update_duration(100 + minutes * 60)
                self.assertEqual(runtime._absent_minutes, expected)
                self.assertEqual(runtime._present_minutes, 0)

    async def test_reversal_removes_old_duration_without_broadcasting_zero_enum(self):
        runtime = self.runtime()
        self.hass.states.set(runtime.presence_entity, "off")
        with patch.object(bridge.time, "monotonic", return_value=100):
            runtime.sync_sources()
        runtime.update_duration(1900)
        self.assertEqual(runtime._objects[bridge._ABSENT_MINUTES], 30)
        self.hass.states.set(runtime.presence_entity, "on")
        with patch.object(bridge.time, "monotonic", return_value=2000):
            runtime.sync_sources()
        self.assertEqual(runtime._since, 2000)
        self.assertEqual((runtime._present_minutes, runtime._absent_minutes), (0, 0))
        self.assertNotIn(bridge._ABSENT_MINUTES, runtime._objects)
        self.assertNotIn(bridge._ABSENT_MINUTES, runtime._pending_objects)
        self.assertNotIn(bridge._PRESENT_MINUTES, runtime._objects)
        self.assertEqual(runtime._pending_objects[0], bridge._PRESENCE)

    async def test_zero_lux_is_virtual_only_without_a_configured_source(self):
        self.hass.states.set("binary_sensor.radar", "on")
        virtual = self.runtime()
        virtual.sync_sources()
        self.assertEqual(virtual._objects[bridge._LUX], 0.0)
        self.assertIsNone(virtual.illuminance_entity)
        actual = self.runtime(lux="sensor.lux")
        for state in ("unknown", "unavailable", "nan", "inf", None):
            with self.subTest(state=state):
                if state is None:
                    self.hass.states.values.pop("sensor.lux", None)
                else:
                    self.hass.states.set("sensor.lux", state)
                actual.sync_sources()
                self.assertIsNone(actual._lux)
                self.assertNotIn(bridge._LUX, actual._objects)

    async def test_real_lux_is_normalized_to_spec_range(self):
        runtime = self.runtime(lux="sensor.lux")
        for actual, expected in (("-1", 0), ("12.49", 12), ("12.5", 13), ("2000", 1000)):
            with self.subTest(actual=actual):
                self.hass.states.set("sensor.lux", actual)
                runtime.sync_sources()
                self.assertEqual(runtime._lux, expected)


class PersistenceTests(BridgeTestCase):
    async def test_failed_write_cannot_commit_or_consume_counter_lease(self):
        runtime = self.runtime(bound=True)
        self.hass.fail_writes = True
        with self.assertRaises(OSError):
            await runtime.async_counter()
        self.assertEqual((runtime.counter.next_counter, runtime.counter.reserved_until), (0, 0))
        self.assertEqual(runtime._document["counter_reserved_until"], 0)

    async def test_successful_counter_reservation_is_saved_before_use_and_skipped_on_restart(self):
        runtime = self.runtime(bound=True)
        self.assertEqual(await runtime.async_counter(), 0)
        document = json.loads(Path(runtime._path).read_text(encoding="utf-8"))
        self.assertEqual(document["counter_reserved_until"], 1024)
        restarted = bridge.RadarRuntime(self.hass, runtime.entry, self.manager, document)
        self.assertEqual(await restarted.async_counter(), 1024)

    async def test_failed_binding_write_rejects_pending_identity(self):
        runtime = self.runtime()
        runtime.protocol._pending_identity = dict(IDENTITY)
        self.hass.fail_writes = True
        with self.assertRaises(OSError):
            await runtime.async_persist_pending_identity()
        self.assertFalse(runtime.bound)
        self.assertIsNone(runtime.protocol.pending_identity)
        self.assertIsNone(runtime._document["identity"])
        self.assertIsNone(runtime.paired_at)

    async def test_binding_stays_uncommitted_until_durable_write_finishes(self):
        runtime = self.runtime()
        runtime.protocol._pending_identity = dict(IDENTITY)
        entered = asyncio.Event()
        release = asyncio.Event()
        original_save = runtime._async_save

        async def held_save(changes):
            entered.set()
            await release.wait()
            await original_save(changes)

        with patch.object(runtime, "_async_save", side_effect=held_save):
            task = asyncio.create_task(runtime.async_persist_pending_identity())
            try:
                await asyncio.wait_for(entered.wait(), 1)
                self.assertFalse(runtime.bound)
                self.assertIsNone(runtime.paired_at)
            finally:
                release.set()
                await task
        self.assertTrue(runtime.bound)
        self.assertIsNotNone(runtime.paired_at)

    async def test_counter_write_failure_stops_encrypted_advertising(self):
        runtime = self.runtime(bound=True)
        runtime.instance = 5
        runtime._enabled = True
        self.hass.states.set(runtime.presence_entity, "on")
        runtime.sync_sources()
        self.hass.fail_writes = True
        await self.manager._async_publish(runtime, 100)
        self.assertEqual(self.manager.advertiser.data, [])
        self.assertEqual(self.manager.advertiser.disabled, [5])
        self.assertFalse(runtime._enabled)
        self.assertIsNotNone(runtime._error)
        self.assertIsNone(self.manager.failure)
        self.assertEqual(runtime.counter.next_counter, 0)


class ModelMappingTests(BridgeTestCase):
    async def test_thermometer_getter_aliases_follow_live_values_and_omit_offline_sources(self):
        runtime = self.model_runtime("miaomiaoce.sensor_ht.t2")
        runtime.property_mappings["2.1"] = {"source": "entity", "entity_id": "sensor.temperature"}
        runtime.property_mappings["2.2"] = {"source": "entity", "entity_id": "sensor.humidity"}
        self.hass.states.set("sensor.temperature", "23.5", unit_of_measurement="°C")
        self.hass.states.set("sensor.humidity", "55.6", unit_of_measurement="%")
        runtime.sync_sources()
        self.assertEqual(runtime._property_values["2.1001"], 23.5)
        self.assertEqual(runtime._property_values["3.1001"], 23.5)
        self.assertEqual(runtime._property_values["2.1008"], 55.6)
        self.assertEqual(runtime._property_values["3.1002"], 56)
        self.hass.states.set("sensor.temperature", "unavailable")
        runtime.sync_sources()
        self.assertNotIn("2.1001", runtime._property_values)
        self.assertNotIn("3.1001", runtime._property_values)
        self.assertEqual(runtime._property_values["3.1002"], 56)

    async def test_occupancy_fast_scan_does_not_accumulate_presence_duration(self):
        runtime = self.model_runtime(bridge.DEFAULT_MODEL)
        runtime.property_mappings["2.1078"] = {"source": "virtual", "value": 2}
        runtime.sync_sources()
        runtime.update_duration(100000)
        self.assertTrue(runtime._source_available)
        self.assertIsNone(runtime._since)
        self.assertEqual(runtime._objects[0x484E], 2)
        self.assertNotIn(0x4851, runtime._objects)
        self.assertNotIn(0x4852, runtime._objects)

    async def test_model_change_cannot_reuse_another_models_identity(self):
        entry = FakeEntry()
        entry.data["model"] = "xiaomi.cooler.r02p"
        document = {"version": 1, "mac": MAC, "identity": dict(IDENTITY), "counter_reserved_until": 0, "paired_at": None}
        with self.assertRaises(ValueError):
            bridge.RadarRuntime(self.hass, entry, self.manager, document)

    async def test_virtual_write_is_saved_only_for_its_own_entry(self):
        runtime = self.model_runtime("careco.nlight.o654", entry_id="light-one")
        other = self.model_runtime("careco.nlight.o654", entry_id="light-two")
        request = self.authenticated_request(runtime, [("7.2", 75)])
        self.assertEqual(await runtime._async_write_properties(request), {"7.2": 0})
        runtime.sync_sources()
        other.sync_sources()
        self.assertEqual(runtime._property_values["7.2"], 75)
        self.assertEqual(other._property_values["7.2"], 50)
        saved = json.loads(Path(runtime._path).read_text(encoding="utf-8"))
        restarted = bridge.RadarRuntime(self.hass, runtime.entry, self.manager, saved)
        restarted.sync_sources()
        self.assertEqual(restarted._property_values["7.2"], 75)
        self.assertEqual(restarted.mac, runtime.mac)
        self.assertEqual(restarted.protocol.identity, runtime.protocol.identity)

    async def test_failed_virtual_write_leaves_original_value_and_identity(self):
        runtime = self.model_runtime("careco.nlight.o654")
        identity = runtime.protocol.identity
        request = self.authenticated_request(runtime, [("7.2", 75)])
        self.hass.fail_writes = True
        self.assertEqual(await runtime._async_write_properties(request), {"7.2": 1})
        runtime.sync_sources()
        self.assertEqual(runtime._property_values["7.2"], 50)
        self.assertEqual(runtime.protocol.identity, identity)

    async def test_new_virtual_configuration_supersedes_a_saved_app_setting(self):
        runtime = self.model_runtime("careco.nlight.o654")
        request = self.authenticated_request(runtime, [("7.2", 75)])
        await runtime._async_write_properties(request)
        runtime.entry.options = {"property_mappings": {**runtime.property_mappings, "7.2": {"source": "virtual", "value": 60}}}
        reloaded = bridge.RadarRuntime(self.hass, runtime.entry, self.manager, runtime._document)
        reloaded.sync_sources()
        self.assertEqual(reloaded._property_values["7.2"], 60)

    async def test_late_request_does_not_call_ha_after_disconnect(self):
        runtime = self.model_runtime("careco.nlight.o654")
        runtime.property_mappings["7.1"] = {"source": "entity", "entity_id": "switch.test"}
        request = self.authenticated_request(runtime, [("7.1", True)])
        runtime.protocol.disconnect()
        self.assertEqual(await runtime._async_write_properties(request), {})
        self.hass.services.async_call.assert_not_awaited()

    async def test_expired_same_session_request_does_not_execute_queued_ha_control(self):
        runtime = self.model_runtime("careco.nlight.o654")
        runtime.property_mappings["7.1"] = {"source": "entity", "entity_id": "switch.test"}
        request = self.authenticated_request(runtime, [("7.1", True)])
        runtime.protocol.poll(21)
        self.assertTrue(runtime.protocol.logged_in)
        await runtime._async_handle_request(request)
        self.hass.services.async_call.assert_not_awaited()
        self.assertNotIn("virtual_values", runtime._document)

    async def test_entity_write_uses_the_mapped_service_and_reports_failures(self):
        runtime = self.model_runtime("careco.nlight.o654")
        runtime.property_mappings["7.1"] = {"source": "entity", "entity_id": "switch.test"}
        self.hass.states.set("switch.test", "off")
        request = self.authenticated_request(runtime, [("7.1", True)])
        self.assertEqual(await runtime._async_write_properties(request), {"7.1": 0})
        self.hass.services.async_call.assert_awaited_once_with("switch", "turn_on", {"entity_id": "switch.test"}, blocking=True)
        self.hass.services.async_call.side_effect = RuntimeError("Unavailable mapped service")
        request = self.authenticated_request(runtime, [("7.1", False)])
        self.assertEqual(await runtime._async_write_properties(request), {"7.1": 1})

    async def test_unavailable_temperature_is_omitted_without_replacing_other_attributes(self):
        runtime = self.model_runtime("xiaomi.cooler.r02p")
        runtime.property_mappings["3.3"] = {"source": "entity", "entity_id": "sensor.temperature"}
        self.hass.states.set("sensor.temperature", "unavailable")
        runtime.sync_sources()
        self.assertNotIn("3.3", runtime._property_values)
        self.assertNotIn(0x4C03, runtime._objects)
        self.assertIn("4.1", runtime._property_values)

    async def test_virtual_light_scene_updates_its_own_brightness_and_temperature(self):
        runtime = self.model_runtime("careco.nlight.o654")
        request = self.authenticated_request(runtime, [("7.4", 3)])
        self.assertEqual(await runtime._async_write_properties(request), {"7.4": 0})
        runtime.sync_sources()
        self.assertEqual((runtime._property_values["7.2"], runtime._property_values["7.3"]), (100, 2700))

    async def test_kettle_virtual_gear_updates_virtual_water_temperature(self):
        runtime = self.model_runtime("yunmi.kettle.v13")
        request = self.authenticated_request(runtime, [("3.3", 4)])
        self.assertEqual(await runtime._async_write_properties(request), {"3.3": 0})
        runtime.sync_sources()
        self.assertEqual(runtime._property_values["3.6"], 90)
        self.assertFalse(runtime.model.property_by_key["3.6"].writable)

    async def test_kettle_gear_does_not_replace_real_ha_water_temperature(self):
        runtime = self.model_runtime("yunmi.kettle.v13")
        runtime.property_mappings["3.6"] = {"source": "entity", "entity_id": "sensor.water"}
        self.hass.states.set("sensor.water", "42", unit_of_measurement="°C")
        runtime.sync_sources()
        request = self.authenticated_request(runtime, [("3.3", 4)])
        await runtime._async_write_properties(request)
        runtime.sync_sources()
        self.assertEqual(runtime._property_values["3.6"], 42)

    async def test_motion_event_keeps_dark_light_state(self):
        runtime = self.model_runtime("lumi.motion.bmgl01")
        runtime.property_mappings["2.1"] = {"source": "virtual", "value": 1}
        runtime.event_mappings["2.e.1"] = {"source": "entity", "entity_id": "event.motion", "trigger_value": ""}
        runtime.sync_sources()
        runtime._process_event_sources(SimpleNamespace(data={"entity_id": "event.motion", "old_state": SimpleNamespace(state="first"), "new_state": SimpleNamespace(state="second")}))
        self.assertEqual(runtime._event_objects[0], (0x000F, b"\x01\x00\x00"))

    async def test_event_csv_source_is_live_and_unknown_does_not_fall_back(self):
        runtime = self.model_runtime("yunmai.scales.ms103")
        runtime.event_mappings["8.e.2"] = {"source": "entity", "entity_id": "event.measurement", "trigger_value": "", "arguments": {"8.1": {"source": "entity", "entity_id": "sensor.result_csv"}}}
        event = SimpleNamespace(data={"entity_id": "event.measurement", "old_state": SimpleNamespace(state="first"), "new_state": SimpleNamespace(state="second")})
        csv = "0,0,0,645,0,0,1795478400,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        self.hass.states.set("sensor.result_csv", csv)
        with patch.object(runtime.protocol, "send_event") as send:
            runtime._process_event_sources(event)
            send.assert_called_once_with("8.e.2", {"8.1": csv})
            send.reset_mock()
            self.hass.states.set("sensor.result_csv", "unavailable")
            runtime._process_event_sources(event)
            send.assert_not_called()
        self.assertIn("sensor.result_csv", runtime._source_entities())

    async def test_unavailable_action_output_is_not_replaced_by_full_battery(self):
        runtime = self.model_runtime("yunmai.scales.ms103")
        runtime.property_mappings["13.10"] = {"source": "entity", "entity_id": "sensor.battery_status"}
        self.hass.states.set("sensor.battery_status", "unavailable")
        runtime.sync_sources()
        result, outputs = await runtime._async_action(SimpleNamespace(action_key="13.1", args=()))
        self.assertEqual((result, outputs), (1, {}))
        self.assertNotIn("virtual_values", runtime._document)


class ModelConnectionTests(BridgeTestCase):
    async def test_bound_night_light_uses_the_upstream_discovery_shape_and_name(self):
        runtime = self.model_runtime("MUE4094RT")
        runtime.instance = 1
        identity = runtime.protocol.identity
        await self.manager._async_publish(runtime, 100)
        self.assertEqual(runtime.protocol.hello(0)[11], 0x09)
        self.assertIn(runtime.protocol.hello(0), self.manager.advertiser.data[0][1])
        self.assertIn(b"MUE4094RT", bridge.scan_response_payload(runtime, 0))
        self.assertEqual(runtime.protocol.identity, identity)
        self.assertEqual(runtime.counter.next_counter, 0)

    async def test_control_models_rotate_but_a_connected_model_keeps_ownership(self):
        first = self.model_runtime("careco.nlight.o654", entry_id="first")
        second = self.model_runtime("xiaomi.cooler.r02p", entry_id="second", mac="D4:3B:04:5E:2A:11")
        first.instance, second.instance = 1, 2
        self.manager.targets = {first.device_id: first, second.device_id: second}
        await self.manager._async_select_connection(0)
        self.assertIs(self.manager.connection_target, first)
        await self.manager._async_select_connection(3.1)
        self.assertIs(self.manager.connection_target, second)
        await self.manager._async_process_hci_event(second, bridge.BluetoothEvent("connected", instance=2, handle=0x123, role=1, status=0))
        await self.manager._async_select_connection(20)
        self.assertIs(self.manager.connection_target, second)
        self.assertTrue(second.protocol._connected)
        self.assertFalse(first.protocol._connected)

    async def test_explicit_pairing_preempts_control_without_erasing_binding(self):
        control = self.model_runtime("careco.nlight.o654")
        control.instance = 1
        radar = self.runtime(bound=True)
        radar.instance = 2
        radar.sync_sources()
        self.manager.targets = {control.device_id: control, radar.device_id: radar}
        await self.manager._async_select_connection(0)
        await self.manager.async_start_pairing(radar)
        self.assertIsNone(self.manager.connection_target)
        self.assertIs(self.manager.pairing, radar)
        self.assertTrue(control.bound)
        self.assertTrue(radar.bound)
        await self.manager._async_select_connection(100)
        self.assertIsNone(self.manager.connection_target)

    async def test_larger_single_object_advertisement_still_fits_31_bytes(self):
        payload = bytes(range(21))
        packet = bridge.advertising_payload(payload)
        self.assertLessEqual(len(packet), 31)
        self.assertIn(b"\x16\x95\xfe"+payload, packet)
        with self.assertRaises(ValueError):
            bridge.advertising_payload(bytes(25))

    async def test_legacy_rotation_waits_for_pairing_and_resumes_after_disconnect(self):
        first = self.model_runtime("MUE4094RT", entry_id="first")
        second = self.model_runtime("MUE4094RT", entry_id="second", mac="D4:3B:04:5E:2A:11")
        first.instance, second.instance = 1, 2
        self.manager.targets = {first.device_id: first, second.device_id: second}

        with patch.object(bridge.time, "monotonic", return_value=100):
            await self.manager._async_publish_legacy(100)
        await self.manager._async_publish_legacy(101)
        self.assertEqual(self.manager.advertiser.enabled, [1])
        with patch.object(bridge.time, "monotonic", return_value=104):
            await self.manager._async_publish_legacy(104)
            await self.manager.async_start_pairing(first)
        self.assertEqual(self.manager.advertiser.enabled, [1, 2, 1])
        await self.manager._async_process_hci_event(
            first, bridge.BluetoothEvent("connected", instance=1, handle=0x123, role=1, status=0),
        )
        await self.manager._async_publish_legacy(110)
        self.assertEqual(self.manager.advertiser.enabled, [1, 2, 1])
        await self.manager._async_process_hci_event(
            first, bridge.BluetoothEvent("disconnected", instance=1, handle=0x123, status=0),
        )
        await self.manager._async_publish_legacy(111)
        self.assertEqual(self.manager.advertiser.enabled, [1, 2, 1, 1])

    async def test_legacy_late_connections_during_rotation_pin_the_original_identity(self):
        for stage in ("counter", "disable", "configure", "occupancy"):
            with self.subTest(stage=stage):
                first = self.model_runtime("miaomiaoce.sensor_ht.t2", entry_id="first")
                second = self.model_runtime("miaomiaoce.sensor_ht.t2", entry_id="second", mac="D4:3B:04:5E:2A:11")
                first.instance, second.instance = 1, 2
                self.manager.targets = {first.device_id: first, second.device_id: second}
                self.manager._legacy_target = first
                self.manager.connection_target = first
                self.manager._connection_owner = None
                self.manager.connection_handle = None
                self.manager._incoming_pending = False
                self.manager._selection_deadline = 0
                self.manager.advertiser = FakeLegacyAdvertiser(self.manager._hci_event)
                advertiser = self.manager.advertiser
                await advertiser.async_configure(first.instance, first.mac, True)
                await advertiser.async_set_data(first.instance, b"first", b"")
                await advertiser.async_enable(first.instance)
                first._enabled = True
                before = len(advertiser.commands)

                def connection():
                    advertiser._dispatch_event(bridge.BluetoothEvent("connected", handle=0x123, role=1, status=0))

                if stage == "counter":
                    original_save = second._async_save

                    async def receive_while_saving(changes):
                        self.assertEqual(advertiser._enabled, {1})
                        connection()
                        await original_save(changes)

                    second._async_save = receive_while_saving
                elif stage == "disable":
                    async def receive_while_disabling(opcode, payload):
                        if opcode == 0x200A and payload == b"\x00":
                            advertiser.command_hook = None
                            connection()

                    advertiser.command_hook = receive_while_disabling
                elif stage == "configure":
                    async def receive_while_configuring(instance):
                        if instance == 2:
                            connection()

                    advertiser.configure_hook = receive_while_configuring
                else:
                    checks = 0

                    async def receive_before_enabling(*, busy=None):
                        nonlocal checks
                        checks += 1
                        if checks == 2:
                            connection()
                        return busy is None or not busy()

                    self.manager.server.async_check_legacy_occupancy = receive_before_enabling

                async with self.manager._operation_lock:
                    await self.manager._async_publish_legacy(100)
                    self.assertIs(self.manager._connection_owner, first)
                    self.assertIs(self.manager._current_runtime(), first)
                    self.assertTrue(self.manager._incoming_pending)
                    self.assertEqual(advertiser.enabled, [1])
                    self.assertNotIn((0x2005, bytes.fromhex("112a5e043bd4")), advertiser.commands[before:])
                await asyncio.gather(*tuple(self.manager._event_tasks))
                self.assertEqual(self.manager.connection_handle, 0x123)
                self.assertIs(self.manager._connection_owner, first)
                if stage == "counter":
                    self.assertEqual(second.counter.next_counter, 0)
                self.manager.pairing = second
                self.manager._pair_deadline = 1000
                first.protocol.read = Mock(return_value=b"old connection")
                second.protocol.read = Mock(return_value=b"new pairing")
                self.assertEqual(self.manager._read_gatt(0x0013), b"old connection")
                await self.manager._async_publish_legacy(101)
                self.assertEqual(advertiser.enabled, [1])
                advertiser._dispatch_event(bridge.BluetoothEvent("disconnected", handle=0x456, status=0))
                self.assertIs(self.manager._connection_owner, first)
                advertiser._dispatch_event(bridge.BluetoothEvent("disconnected", handle=0x123, status=0))
                await asyncio.gather(*tuple(self.manager._event_tasks))
                self.assertIsNone(self.manager._connection_owner)
                self.assertIs(self.manager._current_runtime(), second)
                self.manager.pairing = None
                self.manager.server.async_check_legacy_occupancy = AsyncMock(return_value=True)
                await advertiser.async_stop()

    async def test_connection_received_while_preparing_data_preserves_queued_events(self):
        first = self.model_runtime("miaomiaoce.sensor_ht.t2", entry_id="first")
        second = self.model_runtime("miaomiaoce.sensor_ht.t2", entry_id="second", mac="D4:3B:04:5E:2A:11")
        first.instance, second.instance = 1, 2
        self.manager.targets = {first.device_id: first, second.device_id: second}
        self.manager._legacy_target = first
        self.manager.connection_target = first
        self.manager._selection_deadline = 0
        advertiser = FakeLegacyAdvertiser(self.manager._hci_event)
        self.manager.advertiser = advertiser
        await advertiser.async_configure(first.instance, first.mac, True)
        await advertiser.async_set_data(first.instance, b"first", b"")
        await advertiser.async_enable(first.instance)
        first._enabled = True
        event = (0x100A, b"\x64")
        second._event_objects.append(event)
        original_set = advertiser.async_set_data

        async def receive_while_setting_data(instance, data, scan_response=b""):
            await original_set(instance, data, scan_response)
            if instance == 2:
                advertiser._dispatch_event(bridge.BluetoothEvent("connected", handle=0x123, role=1, status=0))

        advertiser.async_set_data = receive_while_setting_data
        async with self.manager._operation_lock:
            await self.manager._async_publish_legacy(100)
            self.assertIs(self.manager._current_runtime(), first)
            self.assertEqual(advertiser.enabled, [1])
            self.assertEqual(list(second._event_objects), [event])
        await asyncio.gather(*tuple(self.manager._event_tasks))

    async def test_only_unsupported_vendor_advertising_selects_legacy(self):
        original = self.manager.advertiser
        original.async_start = AsyncMock()
        self.manager.server.async_require_idle_advertising = AsyncMock()
        with patch.object(bridge.LegacyAdvertiser, "async_start", new_callable=AsyncMock) as start:
            await self.manager._async_start_bluetooth()
            self.assertIs(self.manager.advertiser, original)
            start.assert_not_awaited()
            original.async_start.side_effect = bridge.HciError("timed out")
            with self.assertRaises(bridge.HciError):
                await self.manager._async_start_bluetooth()
            start.assert_not_awaited()
            original.async_start.side_effect = bridge.HciUnsupportedError("no vendor instances")
            await self.manager._async_start_bluetooth()
            self.assertEqual(self.manager.advertising_mode, "legacy_rotation")
            self.manager.server.async_require_idle_advertising.assert_awaited_once_with(self.hass)
            start.assert_awaited_once()


class NotificationTests(BridgeTestCase):
    async def test_backpressure_preserves_queue_head_and_order(self):
        messages = [(0x0019, b"first"), (0x0010, b"second")]
        runtime = SimpleNamespace(protocol=SimpleNamespace(drain_notifications=Mock(side_effect=[messages, []])))
        self.manager.server.accept = False
        self.manager._flush_notifications(runtime)
        self.assertEqual(list(self.manager._notifications), messages)
        self.manager.server.accept = True
        self.manager._flush_notifications(runtime)
        self.assertEqual(self.manager.server.notifications, messages)
        self.assertEqual(list(self.manager._notifications), [])

    async def test_unsubscribed_characteristic_accepts_once_and_delivers_in_order(self):
        server = bridge.BlueZServer("hci0", AsyncMock(), lambda _channel: b"")
        self.manager.server = server
        emitted = []
        char = server.characteristics[0x0019]
        with patch.object(char, "emit_properties_changed", side_effect=emitted.append):
            messages = [(0x0019, bytes((number,))) for number in range(18)]
            runtime = SimpleNamespace(protocol=SimpleNamespace(
                drain_notifications=Mock(side_effect=[messages, []])
            ))
            self.manager._flush_notifications(runtime)
            self.assertEqual(list(char._pending), [bytes((number,)) for number in range(16)])
            self.assertEqual(list(self.manager._notifications), messages[16:])
            start_notify = getattr(type(char).StartNotify, "__wrapped__", type(char).StartNotify)
            start_notify(char)
            self.manager._flush_notifications(runtime)
        values = [change["Value"] for change in emitted if "Value" in change]
        self.assertEqual(values, [bytes((number,)) for number in range(18)])
        self.assertFalse(char._pending)
        self.assertFalse(self.manager._notifications)


class LifecycleTests(BridgeTestCase):
    async def test_server_start_failure_closes_owned_advertiser(self):
        self.manager.server.start_error = DBusError("org.bluez.Error.Failed", "Injected failure")
        with self.assertRaises(DBusError):
            await self.manager.async_start()
        self.assertTrue(self.manager.advertiser.stopped)
        self.assertIsNone(self.manager._task)

    async def test_stop_cancels_loop_and_event_tasks(self):
        await self.manager.async_start()
        task = self.manager._task
        self.manager._spawn_event(asyncio.sleep(100))
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        await self.manager.async_stop()
        self.assertTrue(task.done())
        self.assertIsNone(self.manager._task)
        self.assertTrue(self.manager.advertiser.stopped)
        self.assertTrue(self.manager.server.stopped)
        self.assertFalse(self.manager._event_tasks)

    async def test_pending_legacy_connection_can_be_closed_before_event_task_runs(self):
        address = "11:22:33:44:55:66"
        for action in ("end_pairing", "remove"):
            with self.subTest(action=action):
                runtime = self.model_runtime("miaomiaoce.sensor_ht.t2")
                runtime.instance = 1
                self.manager.targets = {runtime.device_id: runtime}
                self.manager.connection_target = runtime
                self.manager._legacy_target = runtime
                self.manager.pairing = runtime if action == "end_pairing" else None
                advertiser = FakeLegacyAdvertiser(self.manager._hci_event)
                self.manager.advertiser = advertiser
                await advertiser.async_configure(1, runtime.mac, True)
                await advertiser.async_set_data(1, b"first", b"")
                await advertiser.async_enable(1)
                runtime._enabled = True
                identity = dict(runtime.protocol.identity)

                async with self.manager._operation_lock:
                    cleanup = asyncio.create_task(
                        self.manager.async_end_pairing() if action == "end_pairing"
                        else self.manager.async_remove(runtime)
                    )
                    await asyncio.sleep(0)
                    advertiser._dispatch_event(bridge.BluetoothEvent(
                        "connected", handle=0x123, role=1, status=0, address=address,
                    ))
                    self.assertTrue(self.manager._incoming_pending)
                    self.assertEqual(self.manager._peer_address, address)
                await cleanup
                await asyncio.gather(*tuple(self.manager._event_tasks))
                self.assertEqual(self.manager.server.disconnected[-1], address)
                self.assertIs(self.manager._connection_owner, runtime)
                self.assertIs(self.manager._current_runtime(), runtime)
                self.assertEqual(runtime.protocol.identity, identity)
                self.assertIsNone(self.manager.failure)
                if action == "remove":
                    self.assertNotIn(runtime.device_id, self.manager.targets)

                advertiser._dispatch_event(bridge.BluetoothEvent("disconnected", handle=0x123, status=0))
                await asyncio.gather(*tuple(self.manager._event_tasks))
                self.assertIsNone(self.manager._connection_owner)
                self.assertIsNone(self.manager.connection_handle)
                await advertiser.async_stop()

    async def test_transport_failure_during_legacy_connection_enters_recovery(self):
        runtime = self.model_runtime("miaomiaoce.sensor_ht.t2")
        runtime.instance = 1
        self.manager.targets = {runtime.device_id: runtime}
        self.manager.connection_target = runtime
        self.manager._legacy_target = runtime
        advertiser = FakeLegacyAdvertiser(self.manager._hci_event)
        self.manager.advertiser = advertiser
        server = self.manager.server
        await advertiser.async_configure(1, runtime.mac, True)
        await advertiser.async_set_data(1, b"first", b"")
        await advertiser.async_enable(1)
        advertiser._dispatch_event(bridge.BluetoothEvent(
            "connected", handle=0x123, role=1, status=0, address="11:22:33:44:55:66",
        ))
        await asyncio.gather(*tuple(self.manager._event_tasks))
        identity = dict(runtime.protocol.identity)
        mac = runtime.mac
        advertiser._fail(bridge.HciError("Injected USB removal"))
        failed = asyncio.Event()
        recovered = asyncio.Event()
        order = []
        original_failed = self.manager._failed
        original_recover = self.manager._async_recover
        original_stop_advertiser = advertiser.async_stop
        original_disconnect = server.async_disconnect_peer
        original_stop_server = server.async_stop

        def record_failure(error):
            original_failed(error)
            failed.set()

        async def record_recovery():
            await original_recover()
            recovered.set()

        async def stop_advertiser():
            order.append("advertiser")
            await original_stop_advertiser()

        async def disconnect_peer(address):
            order.append("peer")
            await original_disconnect(address)

        async def stop_server():
            order.append("server")
            await original_stop_server()

        advertiser.async_stop = stop_advertiser
        server.async_disconnect_peer = disconnect_peer
        server.async_stop = stop_server
        replacement = FakeAdvertiser()
        replacement_server = FakeServer()
        with patch.object(bridge, "VendorAdvertiser", return_value=replacement), \
                patch.object(bridge, "BlueZServer", return_value=replacement_server), \
                patch.object(self.manager, "_failed", side_effect=record_failure), \
                patch.object(self.manager, "_async_recover", side_effect=record_recovery):
            self.manager._task = asyncio.create_task(self.manager._run())
            await asyncio.wait_for(failed.wait(), 1)
            self.assertIn("Injected USB removal", self.manager.failure)
            self.manager._retry_at = 0
            self.manager.wakeup.set()
            await asyncio.wait_for(recovered.wait(), 1)
        self.assertEqual(order, ["advertiser", "peer", "server"])
        self.assertEqual(server.disconnected, ["11:22:33:44:55:66"])
        self.assertIs(self.manager.advertiser, replacement)
        self.assertTrue(replacement.started)
        self.assertTrue(replacement_server.started)
        self.assertIsNone(self.manager.failure)
        self.assertIsNone(self.manager._connection_owner)
        self.assertIsNone(self.manager.connection_handle)
        self.assertEqual(runtime.mac, mac)
        self.assertEqual(runtime.protocol.identity, identity)

    async def test_remove_cleans_target_and_subscriptions_when_disable_fails(self):
        runtime = self.runtime()
        runtime.instance = 2
        runtime.stop_subscriptions = Mock()
        self.manager.targets[runtime.device_id] = runtime
        self.manager.advertiser.disable_error = bridge.HciError("Injected disable failure")
        try:
            await self.manager.async_remove(runtime)
        except bridge.HciError:
            pass
        self.assertNotIn(runtime.device_id, self.manager.targets)
        runtime.stop_subscriptions.assert_called()

    async def test_add_subscription_failure_rolls_back_owned_target(self):
        runtime = self.runtime()
        runtime.start_subscriptions = Mock(side_effect=RuntimeError("Injected subscription failure"))
        runtime.stop_subscriptions = Mock()
        with self.assertRaises(RuntimeError):
            await self.manager.async_add(runtime)
        self.assertNotIn(runtime.device_id, self.manager.targets)
        runtime.stop_subscriptions.assert_called()

    async def test_peer_disconnect_failure_still_closes_advertiser_and_gatt(self):
        self.manager._peer_address = "11:22:33:44:55:66"
        self.manager.server.disconnect_error = DBusError("org.bluez.Error.Failed", "Injected disconnect failure")
        try:
            await self.manager.async_stop()
        except DBusError:
            pass
        self.assertTrue(self.manager.advertiser.stopped)
        self.assertTrue(self.manager.server.stopped)
        self.manager._peer_address = None

    async def test_pairing_switch_waits_for_pending_identity_write(self):
        old = self.runtime()
        old.instance = 1
        old.protocol.connect(0)
        old.protocol._pending_identity = dict(IDENTITY)
        new = self.runtime(entry_id="second-entry")
        new.instance = 2
        self.manager.pairing = old
        entered = asyncio.Event()
        release = asyncio.Event()
        original_save = old._async_save

        async def held_save(changes):
            entered.set()
            await release.wait()
            await original_save(changes)

        with patch.object(old, "_async_save", side_effect=held_save):
            writer = asyncio.create_task(self.manager._write_gatt(0x0010, b"\xa4", "/test/peer"))
            switcher = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                switcher = asyncio.create_task(self.manager.async_start_pairing(new))
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                self.assertIs(self.manager.pairing, old)
            finally:
                release.set()
                results = await asyncio.gather(
                    *(task for task in (writer, switcher) if task is not None),
                    return_exceptions=True,
                )
            for result in results:
                if isinstance(result, BaseException):
                    raise result
        self.assertIs(self.manager.pairing, new)
        self.assertTrue(old.bound)


class IntegrationTests(BridgeTestCase):
    async def test_started_sync_is_a_real_ha_callback_and_keeps_shared_manager(self):
        runtime = self.runtime()
        entry = runtime.entry
        manager = SimpleNamespace(
            adapter="hci0", targets={}, async_start=AsyncMock(),
            async_stop=AsyncMock(), async_add=AsyncMock(), async_remove=AsyncMock(),
        )

        async def add(target):
            manager.targets[target.device_id] = target

        manager.async_add.side_effect = add
        marker = Mock()

        def at_started(hass, action):
            self.assertIs(HassJob(action).job_type, HassJobType.Callback)
            action(hass)
            return marker

        self.hass.states.set(runtime.presence_entity, "on")
        with patch.object(integration, "BridgeManager", return_value=manager), patch.object(
            integration.RadarRuntime, "async_create", AsyncMock(return_value=runtime)
        ), patch.object(integration, "async_at_started", side_effect=at_started):
            self.assertTrue(await integration.async_setup_entry(self.hass, entry))
        self.assertIs(entry.runtime_data, runtime)
        self.assertIs(self.hass.data[bridge.DOMAIN]["adapters"]["hci0"], manager)
        self.assertEqual(entry.on_unload, [marker])
        self.assertTrue(runtime._presence)
        self.hass.config_entries.async_forward_entry_setups.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
