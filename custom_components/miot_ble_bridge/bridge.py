"""Forward existing HA radar entities through independent MiOT BLE identities."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
import json
import logging
import math
from pathlib import Path
import secrets
import struct
import time
from typing import Any

from dbus_fast import DBusError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.util.file import write_utf8_file_atomic

from .bluez import BlueZServer
from .const import (
    CONF_ADAPTER,
    CONF_ILLUMINANCE_ENTITY,
    CONF_ILLUMINANCE_ENTITY_REGISTRY_ID,
    CONF_NAME,
    CONF_PRESENCE_ENTITY,
    CONF_PRESENCE_ENTITY_REGISTRY_ID,
    DEFAULT_ADAPTER,
    DOMAIN,
    PRODUCT_ID,
    STATUS_BLUETOOTH_UNAVAILABLE,
    STATUS_BOUND,
    STATUS_PAIRING,
    STATUS_SOURCE_OFFLINE,
    STATUS_UNPAIRED,
)
from .hci import BluetoothEvent, HciError, VendorAdvertiser
from .protocol import CounterLease, MiotProtocol, ProtocolError

_LOGGER = logging.getLogger(__name__)
_PRESENCE = 0x484E
_LUX = 0x4805
_ABSENT_MINUTES = 0x4852
_PRESENT_MINUTES = 0x4851
_BATTERY = 0x100A
_PAIRING_SECONDS = 300


def advertising_payload(service_data: bytes) -> bytes:
    data = b"\x02\x01\x06\x03\x03\x95\xfe" + bytes((len(service_data) + 3, 0x16, 0x95, 0xFE)) + service_data
    if len(data) > 31:
        raise ValueError("MiBeacon exceeds the legacy advertisement limit")
    return data


def scan_response_payload(runtime: RadarRuntime, counter: int) -> bytes:
    manufacturer = (
        bytes((0x8F, 0x03, 0x30, 0 if runtime.bound else 0x20))
        + struct.pack("<H", PRODUCT_ID) + bytes((counter & 0xFF,))
        + runtime.protocol.mac_air + b"\x08"
    )
    name = f"OCCS{runtime.instance:02d}".encode("ascii")
    return bytes((len(manufacturer) + 1, 0xFF)) + manufacturer + bytes((len(name) + 1, 0x09)) + name


def _new_address() -> str:
    value = bytearray(secrets.token_bytes(6))
    value[0] |= 0xC0
    return ":".join(f"{part:02X}" for part in value)


def _load_identity(path: str) -> dict[str, Any] | None:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return None
    if document.get("version") != 1 or not isinstance(document.get("mac"), str):
        raise ValueError("Stored bridge identity has an unsupported format")
    return document


class RadarRuntime:
    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, manager: BridgeManager,
        document: dict[str, Any],
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.manager = manager
        self.device_id = entry.entry_id
        config = {**entry.data, **entry.options}
        self.name = config[CONF_NAME]
        self.presence_entity = config[CONF_PRESENCE_ENTITY]
        self.illuminance_entity = config.get(CONF_ILLUMINANCE_ENTITY)
        self._presence_registry_id = config.get(CONF_PRESENCE_ENTITY_REGISTRY_ID)
        self._lux_registry_id = config.get(CONF_ILLUMINANCE_ENTITY_REGISTRY_ID)
        self._document = document
        self.mac = document["mac"]
        self.paired_at = document.get("paired_at")
        self.protocol = MiotProtocol(self.mac, document.get("identity"))
        self.counter = CounterLease(document.get("counter_reserved_until", 0))
        self.instance = 0
        self._path = hass.config.path(".storage", f"{DOMAIN}.{entry.entry_id}")
        self._storage_lock = asyncio.Lock()
        self._listeners: set[Callable[[], None]] = set()
        self._source_unsub: Callable[[], None] | None = None
        self._registry_unsub: Callable[[], None] | None = None
        self._presence: bool | None = None
        self._lux: float | None = 0.0 if self.illuminance_entity is None else None
        self._since: float | None = None
        self._absent_minutes = 0
        self._present_minutes = 0
        self._objects: dict[int, int | float] = {}
        self._pending_objects: deque[int] = deque()
        self._rotation = 0
        self._next_publication = 0.0
        self._enabled = False
        self._hello_sequence = 0
        self._last_broadcast: str | None = None
        self._error: str | None = None

    @classmethod
    async def async_create(
        cls, hass: HomeAssistant, entry: ConfigEntry, manager: BridgeManager,
    ) -> RadarRuntime:
        path = hass.config.path(".storage", f"{DOMAIN}.{entry.entry_id}")
        document = await hass.async_add_executor_job(_load_identity, path)
        if document is None:
            document = {
                "version": 1, "mac": _new_address(), "identity": None,
                "counter_reserved_until": 0, "paired_at": None,
            }
            await hass.async_add_executor_job(
                write_utf8_file_atomic, path,
                json.dumps(document, ensure_ascii=False, separators=(",", ":")), True,
            )
        runtime = cls(hass, entry, manager, document)
        runtime._resolve_sources()
        return runtime

    @property
    def bound(self) -> bool:
        return self.protocol.bound

    @property
    def status(self) -> str:
        if self._error or self.manager.failure:
            return STATUS_BLUETOOTH_UNAVAILABLE
        if self.manager.pairing is self:
            return STATUS_PAIRING
        if self._presence is None:
            return STATUS_SOURCE_OFFLINE
        return STATUS_BOUND if self.bound else STATUS_UNPAIRED

    @property
    def diagnostics(self) -> dict[str, Any]:
        return {
            "adapter": self.manager.adapter,
            "advertising_instance": self.instance,
            "source_available": self._presence is not None,
            "presence": self._presence,
            "illuminance": self._lux if self.illuminance_entity else None,
            "virtual_illuminance": self.illuminance_entity is None,
            "continuous_presence_minutes": self._present_minutes,
            "continuous_absence_minutes": self._absent_minutes,
            "next_counter": self.counter.next_counter,
            "reserved_until": self.counter.reserved_until,
            "last_broadcast": self._last_broadcast,
            "error": self._error or self.manager.failure,
        }

    def add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        self._listeners.add(listener)
        return lambda: self._listeners.discard(listener)

    @callback
    def notify_listeners(self) -> None:
        for listener in tuple(self._listeners):
            listener()

    def _resolve_sources(self) -> None:
        registry = er.async_get(self.hass)
        for item in registry.entities.values():
            if item.id == self._presence_registry_id:
                self.presence_entity = item.entity_id
            if self._lux_registry_id and item.id == self._lux_registry_id:
                self.illuminance_entity = item.entity_id

    def start_subscriptions(self) -> None:
        self._subscribe_sources()
        self._registry_unsub = self.hass.bus.async_listen(
            "entity_registry_updated", self._registry_changed,
        )

    def _subscribe_sources(self) -> None:
        if self._source_unsub is not None:
            self._source_unsub()
        entities = [self.presence_entity]
        if self.illuminance_entity:
            entities.append(self.illuminance_entity)
        self._source_unsub = async_track_state_change_event(
            self.hass, entities, self._state_changed,
        )
        self.sync_sources()

    @callback
    def _registry_changed(self, _event: Event) -> None:
        previous = (self.presence_entity, self.illuminance_entity)
        self._resolve_sources()
        if previous != (self.presence_entity, self.illuminance_entity):
            self._subscribe_sources()

    @callback
    def _state_changed(self, _event: Event) -> None:
        self.sync_sources()

    @callback
    def sync_sources(self) -> None:
        state = self.hass.states.get(self.presence_entity)
        presence = (state.state == "on") if state and state.state in ("on", "off") else None
        if presence != self._presence:
            self._presence = presence
            self._since = time.monotonic() if presence is not None else None
            self._absent_minutes = self._present_minutes = 0
        if self.illuminance_entity is None:
            self._lux = 0.0
        else:
            lux_state = self.hass.states.get(self.illuminance_entity)
            try:
                value = float(lux_state.state) if lux_state else math.nan
                self._lux = float(math.floor(min(1000.0, max(0.0, value)) + 0.5)) if math.isfinite(value) else None
            except (ValueError, TypeError):
                self._lux = None
        self.update_properties()
        self.notify_listeners()
        self.manager.wakeup.set()

    def update_properties(self) -> None:
        values: dict[int, int | float] = {_BATTERY: 100}
        if self._presence is not None:
            values[_PRESENCE] = int(self._presence)
        if self._lux is not None:
            values[_LUX] = self._lux
        if self._absent_minutes:
            values[_ABSENT_MINUTES] = self._absent_minutes
        if self._present_minutes:
            values[_PRESENT_MINUTES] = self._present_minutes
        changed = [key for key, value in values.items() if self._objects.get(key) != value]
        self._pending_objects = deque(key for key in self._pending_objects if key in values)
        for key in sorted(changed, key=lambda item: item != _PRESENCE):
            if key in self._pending_objects:
                self._pending_objects.remove(key)
            if key == _PRESENCE:
                self._pending_objects.appendleft(key)
                self._next_publication = 0.0
            else:
                self._pending_objects.append(key)
        self._objects = values
        self.protocol.set_properties(
            self._presence, self._lux, self._absent_minutes, self._present_minutes, 100,
        )

    def update_duration(self, now: float) -> None:
        if self._since is None:
            return
        minutes = (now - self._since) / 60
        milestones = (2, 5) if self._presence else (2, 5, 10, 30)
        reached = max((item for item in milestones if minutes >= item), default=0)
        previous = (self._absent_minutes, self._present_minutes)
        self._present_minutes = reached if self._presence else 0
        self._absent_minutes = reached if not self._presence else 0
        if previous != (self._absent_minutes, self._present_minutes):
            self.update_properties()
            self.notify_listeners()

    async def _async_save(self, changes: dict[str, Any]) -> None:
        async with self._storage_lock:
            document = {**self._document, **changes}
            try:
                await self.hass.async_add_executor_job(
                    write_utf8_file_atomic, self._path,
                    json.dumps(document, ensure_ascii=False, separators=(",", ":")), True,
                )
            except Exception as error:
                raise OSError("Could not durably save the MiOT identity") from error
            self._document = document

    async def async_persist_pending_identity(self) -> None:
        snapshot = self.protocol.pending_identity
        if snapshot is None:
            return
        paired_at = datetime.now(timezone.utc).isoformat()
        try:
            await self._async_save({"identity": snapshot, "paired_at": paired_at})
        except Exception:
            self.protocol.reject_identity()
            raise
        self.protocol.commit_identity(snapshot)
        self.paired_at = paired_at
        self._next_publication = 0.0
        self.notify_listeners()

    async def async_counter(self) -> int:
        reservation = self.counter.required_reservation()
        if reservation is not None:
            await self._async_save({"counter_reserved_until": reservation})
            self.counter.commit_reservation(reservation)
        return self.counter.take()

    async def async_pair(self) -> None:
        await self.manager.async_start_pairing(self)

    async def async_stop_pair(self) -> None:
        if self.manager.pairing is self:
            await self.manager.async_end_pairing()

    def stop_subscriptions(self) -> None:
        if self._source_unsub:
            self._source_unsub()
            self._source_unsub = None
        if self._registry_unsub:
            self._registry_unsub()
            self._registry_unsub = None


class BridgeManager:
    def __init__(self, hass: HomeAssistant, adapter: str = DEFAULT_ADAPTER) -> None:
        self.hass = hass
        self.adapter = adapter
        self.targets: dict[str, RadarRuntime] = {}
        self.advertiser = VendorAdvertiser(adapter, event_callback=self._hci_event)
        self.server = BlueZServer(adapter, self._write_gatt, self._read_gatt)
        self.pairing: RadarRuntime | None = None
        self.connection_handle: int | None = None
        self._peer_address: str | None = None
        self._peer_path: str | None = None
        self._pair_deadline = 0.0
        self._operation_lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._event_tasks: set[asyncio.Task] = set()
        self._notifications: deque[tuple[int, bytes]] = deque()
        self._connection_advertisement_ready = True
        self._stopping = False
        self._retry_at = 0.0
        self.failure: str | None = None
        self.wakeup = asyncio.Event()

    async def async_start(self) -> None:
        await self.advertiser.async_start()
        try:
            await self.server.async_start()
        except BaseException:
            await self.advertiser.async_stop()
            raise
        self._task = self.hass.async_create_background_task(self._run(), f"{DOMAIN} {self.adapter}")

    async def async_add(self, runtime: RadarRuntime) -> None:
        async with self._operation_lock:
            capabilities = self.advertiser.capabilities
            if capabilities is None:
                raise HciError("Bluetooth capabilities are unavailable")
            used = {target.instance for target in self.targets.values()}
            available = [slot for slot in capabilities.usable_instances if slot not in used]
            if not available:
                raise HciError("No independent Bluetooth advertising instance remains")
            if any(target.mac == runtime.mac for target in self.targets.values()):
                raise ValueError("Duplicate stored Bluetooth identities")
            runtime.instance = available[0]
            await self.advertiser.async_configure(runtime.instance, runtime.mac, False, interval_ms=400)
            self.targets[runtime.device_id] = runtime
            try:
                runtime.start_subscriptions()
            except Exception:
                runtime.stop_subscriptions()
                self.targets.pop(runtime.device_id, None)
                try:
                    await self.advertiser.async_disable(runtime.instance)
                except HciError:
                    _LOGGER.debug("Failed to clean up a rejected radar mapping", exc_info=True)
                raise
            self.wakeup.set()

    async def async_remove(self, runtime: RadarRuntime) -> None:
        async with self._operation_lock:
            try:
                if self.pairing is runtime:
                    await self._async_end_pairing()
                await self.advertiser.async_disable(runtime.instance)
            except (HciError, DBusError, TimeoutError) as error:
                self._failed(error)
            finally:
                runtime.stop_subscriptions()
                self.targets.pop(runtime.device_id, None)

    async def async_start_pairing(self, runtime: RadarRuntime) -> None:
        async with self._operation_lock:
            if self.failure or runtime._error:
                raise RuntimeError("Bluetooth bridge is unavailable; reload the integration")
            if self.pairing is not None:
                await self._async_end_pairing()
            self._notifications.clear()
            self.server.reset_session()
            self.pairing = runtime
            self._pair_deadline = time.monotonic() + _PAIRING_SECONDS
            runtime.protocol.disconnect()
            runtime._next_publication = 0.0
            await self.advertiser.async_configure(runtime.instance, runtime.mac, True, interval_ms=100)
            runtime._enabled = False
            await self._async_publish(runtime, time.monotonic())
            runtime.notify_listeners()
            self.wakeup.set()

    async def async_end_pairing(self) -> None:
        async with self._operation_lock:
            await self._async_end_pairing()

    async def _async_end_pairing(self) -> None:
        runtime = self.pairing
        if runtime is None:
            return
        peer_address = self._peer_address
        self.pairing = None
        self.connection_handle = None
        self._peer_address = self._peer_path = None
        self._pair_deadline = 0.0
        runtime.protocol.disconnect()
        self._notifications.clear()
        self.server.reset_session()
        runtime._enabled = False
        runtime._next_publication = 0.0
        runtime.notify_listeners()
        try:
            if peer_address:
                await self.server.async_disconnect_peer(peer_address)
        finally:
            await self.advertiser.async_configure(runtime.instance, runtime.mac, False, interval_ms=400)
            self.wakeup.set()

    def _spawn_event(self, coroutine) -> None:
        task = self.hass.async_create_background_task(coroutine, f"{DOMAIN} Bluetooth event")
        self._event_tasks.add(task)
        task.add_done_callback(self._event_tasks.discard)

    @callback
    def _hci_event(self, event: BluetoothEvent) -> None:
        runtime = self.pairing
        if runtime is None or self._stopping:
            return
        relevant = (event.kind == "connected" and event.role == 1) or event.kind == "disconnected" or (event.kind == "advertising" and event.instance == runtime.instance)
        if relevant:
            self._spawn_event(self._async_hci_event(runtime, event))

    async def _async_hci_event(self, runtime: RadarRuntime, event: BluetoothEvent) -> None:
        async with self._operation_lock:
            if self.pairing is not runtime or self._stopping:
                return
            try:
                await self._async_process_hci_event(runtime, event)
            except (HciError, DBusError, TimeoutError) as error:
                self._failed(error)

    async def _async_process_hci_event(self, runtime: RadarRuntime, event: BluetoothEvent) -> None:
        incoming = event.kind == "connected" and event.role == 1 and event.status == 0
        vendor_incoming = event.kind == "advertising" and event.instance == runtime.instance and event.state == 1 and event.handle is not None
        if incoming or vendor_incoming:
            if self.connection_handle is None:
                self.connection_handle = event.handle
                self._notifications.clear()
                self.server.reset_session()
                runtime.protocol.connect(time.monotonic())
                self._connection_advertisement_ready = False
                await self.advertiser.async_configure(runtime.instance, runtime.mac, False, interval_ms=100)
                runtime._enabled = False
                runtime._next_publication = 0.0
                self._connection_advertisement_ready = True
            if event.address:
                self._peer_address = event.address
        elif event.kind == "disconnected" and event.handle == self.connection_handle:
            self.connection_handle = None
            self._peer_address = self._peer_path = None
            runtime.protocol.disconnect()
            self._notifications.clear()
            self.server.reset_session()
            if runtime.bound:
                await self._async_end_pairing()
            else:
                await self.advertiser.async_configure(runtime.instance, runtime.mac, True, interval_ms=100)
                runtime._enabled = False
                runtime._next_publication = 0.0
        self.wakeup.set()

    def _read_gatt(self, channel: int) -> bytes:
        return self.pairing.protocol.read(channel) if self.pairing else b""

    async def _write_gatt(self, channel: int, value: bytes, peer_path: str | None) -> None:
        async with self._operation_lock:
            runtime = self.pairing
            if runtime is None:
                raise DBusError("org.bluez.Error.NotAuthorized", "Open the selected radar's pairing window first")
            if self._peer_path and peer_path != self._peer_path:
                raise DBusError("org.bluez.Error.NotAuthorized", "Another client owns the pairing session")
            self._peer_path = peer_path
            try:
                runtime.protocol.write(channel, value, time.monotonic())
                await runtime.async_persist_pending_identity()
                self._flush_notifications(runtime)
            except (ValueError, OSError, ProtocolError) as error:
                _LOGGER.error("MiOT exchange failed for %s: %s", runtime.name, error)
                runtime.notify_listeners()
                raise DBusError("org.bluez.Error.Failed", "MiOT exchange could not be completed") from error

    def _flush_notifications(self, runtime: RadarRuntime) -> None:
        self._notifications.extend(runtime.protocol.drain_notifications())
        if len(self._notifications) > 128:
            runtime.protocol.disconnect()
            self._notifications.clear()
            raise ProtocolError("MiOT notification queue capacity exceeded")
        while self._notifications:
            channel, value = self._notifications[0]
            if not self.server.notify(channel, value):
                break
            self._notifications.popleft()

    async def _async_publish(self, runtime: RadarRuntime, now: float) -> None:
        if runtime._error:
            return
        pairing = self.pairing is runtime
        if pairing and self.connection_handle is not None and not self._connection_advertisement_ready:
            return
        if not pairing and (not runtime.bound or runtime._presence is None):
            if runtime._enabled:
                await self.advertiser.async_disable(runtime.instance)
                runtime._enabled = False
            return
        if now < runtime._next_publication:
            return
        if not runtime.bound:
            counter = runtime._hello_sequence
            service_data = runtime.protocol.hello(counter)
            runtime._hello_sequence = (runtime._hello_sequence + 1) & 0xFF
        else:
            if runtime._pending_objects:
                object_id = runtime._pending_objects.popleft()
                value = runtime._objects.get(object_id, 0)
            else:
                objects = list(runtime._objects)
                if not objects:
                    return
                object_id = objects[runtime._rotation % len(objects)]
                runtime._rotation += 1
                value = runtime._objects[object_id]
            try:
                counter = await runtime.async_counter()
            except (OSError, ValueError, ProtocolError) as error:
                runtime._error = f"Identity persistence failed: {error}"
                runtime.notify_listeners()
                await self.advertiser.async_disable(runtime.instance)
                runtime._enabled = False
                _LOGGER.error("Encrypted advertising stopped for %s: %s", runtime.name, error)
                return
            service_data = runtime.protocol.beacon(object_id, value, counter, pairing=pairing)
        await self.advertiser.async_set_data(
            runtime.instance, advertising_payload(service_data), scan_response_payload(runtime, counter),
        )
        if not runtime._enabled:
            await self.advertiser.async_enable(runtime.instance)
            runtime._enabled = True
        runtime._next_publication = now + (0.5 if runtime._pending_objects else 1.0)
        runtime._last_broadcast = datetime.now(timezone.utc).isoformat()

    def _failed(self, error: Exception) -> None:
        if self.failure is None:
            _LOGGER.error("MiOT Bluetooth bridge %s interrupted: %s", self.adapter, error)
        self.failure = str(error)
        self._retry_at = time.monotonic() + 5
        for runtime in self.targets.values():
            runtime._enabled = False
            runtime.notify_listeners()

    async def _async_recover(self) -> None:
        async with self._operation_lock:
            self.pairing = None
            self.connection_handle = None
            self._peer_address = self._peer_path = None
            try:
                await self.advertiser.async_stop()
            except HciError:
                pass
            await self.server.async_stop()
            self.advertiser = VendorAdvertiser(self.adapter, event_callback=self._hci_event)
            self.server = BlueZServer(self.adapter, self._write_gatt, self._read_gatt)
            await self.advertiser.async_start()
            await self.server.async_start()
            for runtime in self.targets.values():
                runtime.protocol.disconnect()
                await self.advertiser.async_configure(runtime.instance, runtime.mac, False, interval_ms=400)
                runtime._next_publication = 0.0
            self.failure = None
            for runtime in self.targets.values():
                runtime.notify_listeners()

    async def _run(self) -> None:
        while not self._stopping:
            try:
                now = time.monotonic()
                if self.failure:
                    if now >= self._retry_at:
                        await self._async_recover()
                else:
                    if self.pairing and now >= self._pair_deadline:
                        await self.async_end_pairing()
                    async with self._operation_lock:
                        if self.pairing and self.connection_handle is not None:
                            runtime = self.pairing
                            runtime.protocol.poll(now)
                            await runtime.async_persist_pending_identity()
                            self._flush_notifications(runtime)
                        for runtime in tuple(self.targets.values()):
                            runtime.update_duration(now)
                            await self._async_publish(runtime, now)
            except (HciError, OSError, DBusError, ProtocolError, RuntimeError) as error:
                self._failed(error)
            self.wakeup.clear()
            try:
                await asyncio.wait_for(self.wakeup.wait(), 0.05 if self.connection_handle is not None else 0.2)
            except TimeoutError:
                pass

    async def async_stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        for task in tuple(self._event_tasks):
            task.cancel()
        await asyncio.gather(*self._event_tasks, return_exceptions=True)
        for runtime in self.targets.values():
            runtime.stop_subscriptions()
            runtime.protocol.disconnect()
        try:
            if self._peer_address:
                await self.server.async_disconnect_peer(self._peer_address)
        finally:
            try:
                await self.advertiser.async_stop()
            finally:
                await self.server.async_stop()
