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
        self.capabilities = SimpleNamespace(usable_instances=tuple(range(1, 16)))
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
        self.accept = True
        self.reset_count = 0

    async def async_start(self):
        if self.start_error:
            raise self.start_error
        self.started = True

    async def async_stop(self):
        self.stopped = True

    async def async_disconnect_peer(self, address):
        if self.disconnect_error:
            raise self.disconnect_error

    def reset_session(self):
        self.reset_count += 1

    def notify(self, channel, value):
        if not self.accept:
            return False
        self.notifications.append((channel, value))
        return True


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
