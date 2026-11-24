"""Forward HA properties and actions through independent MiOT BLE identities."""

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
    CONF_NAME,
    DEFAULT_ADAPTER,
    DOMAIN,
    STATUS_BLUETOOTH_UNAVAILABLE,
    STATUS_BOUND,
    STATUS_PAIRING,
    STATUS_SOURCE_OFFLINE,
    STATUS_UNPAIRED,
)
from .hci import BluetoothEvent, HciError, VendorAdvertiser
from .mappings import action_service_call, default_mappings, property_service_call, read_entity_value
from .models import DEFAULT_MODEL, get_model
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
        data = b"\x02\x01\x06" + bytes((len(service_data) + 3, 0x16, 0x95, 0xFE)) + service_data
    if len(data) > 31:
        raise ValueError("MiBeacon exceeds the legacy advertisement limit")
    return data


def scan_response_payload(runtime: RadarRuntime, counter: int) -> bytes:
    manufacturer = (
        bytes((0x8F, 0x03, 0x30, 0 if runtime.bound else 0x20))
        + struct.pack("<H", runtime.model.pid) + bytes((counter & 0xFF,))
        + runtime.protocol.mac_air + b"\x08"
    )
    name = ("MUE4094RT" if runtime.model.auth_mode == "standard_nus" else f"MI{runtime.model.pid:04X}-{runtime.instance:02d}").encode("ascii")
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
        self.model = get_model(config.get("model", DEFAULT_MODEL))
        if not self.model.available:
            raise ValueError(self.model.unavailable_reason)
        self._legacy_config = "property_mappings" not in config
        self.property_mappings = default_mappings(self.model, config)
        self.action_mappings = {key: dict(value) for key, value in config.get("action_mappings", {}).items()}
        self.event_mappings = {key: dict(value) for key, value in config.get("event_mappings", {}).items()}
        self._presence_key = next((prop.key for prop in self.model.properties if prop.semantic == "presence"), None)
        self._lux_key = next((prop.key for prop in self.model.properties if prop.semantic == "illuminance"), None)
        self.presence_entity = self.property_mappings.get(self._presence_key, {}).get("entity_id")
        self.illuminance_entity = self.property_mappings.get(self._lux_key, {}).get("entity_id")
        self._document = document
        self.mac = document["mac"]
        self.paired_at = document.get("paired_at")
        self.protocol = MiotProtocol(self.mac, document.get("identity"), self.model.model, on_set=self._queue_request, on_action=self._queue_request)
        self.protocol.load_nus_scenes(document.get("nus_scenes", {}))
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
        self._object_payloads: dict[int, bytes] = {}
        self._pending_objects: deque[int] = deque()
        self._event_objects: deque[tuple[int, bytes]] = deque(maxlen=64)
        self._source_values: dict[str, Any] = {}
        self._property_values: dict[str, Any] = {}
        self._source_available = False
        self._request_lock = asyncio.Lock()
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
        if not self._source_available:
            return STATUS_SOURCE_OFFLINE
        return STATUS_BOUND if self.bound else STATUS_UNPAIRED

    @property
    def diagnostics(self) -> dict[str, Any]:
        return {
            "adapter": self.manager.adapter,
            "model": self.model.model,
            "battery_percentage": 100,
            "advertising_instance": self.instance,
            "att_mtu": getattr(self.manager.server, "att_mtu", None) if (self.manager.pairing or self.manager.connection_target) is self else None,
            "source_available": self._source_available,
            "presence": self._presence,
            "illuminance": self._lux if self.illuminance_entity else None,
            "virtual_illuminance": self._lux_key is not None and self.illuminance_entity is None,
            "continuous_presence_minutes": self._present_minutes,
            "continuous_absence_minutes": self._absent_minutes,
            "next_counter": self.counter.next_counter,
            "reserved_until": self.counter.reserved_until,
            "last_broadcast": self._last_broadcast,
            "error": self._error or self.manager.failure,
            "property_sources": {key: mapping.get("source") for key, mapping in self.property_mappings.items()},
            "unavailable_properties": [key for key, mapping in self.property_mappings.items() if mapping.get("source") == "entity" and key not in self._source_values],
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
        indexed = {item.id: item.entity_id for item in registry.entities.values()}
        for mapping in self._all_bindings():
            reference = mapping.get("entity_registry_id")
            if reference in indexed:
                mapping["entity_id"] = indexed[reference]
        self.presence_entity = self.property_mappings.get(self._presence_key, {}).get("entity_id")
        self.illuminance_entity = self.property_mappings.get(self._lux_key, {}).get("entity_id")

    def _all_bindings(self):
        yield from self.property_mappings.values()
        yield from self.action_mappings.values()
        for mapping in self.event_mappings.values():
            yield mapping
            for argument in mapping.get("arguments", {}).values():
                if isinstance(argument, dict):
                    yield argument

    def start_subscriptions(self) -> None:
        self._subscribe_sources()
        self._registry_unsub = self.hass.bus.async_listen(
            "entity_registry_updated", self._registry_changed,
        )

    def _subscribe_sources(self) -> None:
        if self._source_unsub is not None:
            self._source_unsub()
        entities = self._source_entities()
        self._source_unsub = async_track_state_change_event(self.hass, entities, self._state_changed) if entities else None
        self.sync_sources()

    def _source_entities(self) -> list[str]:
        return sorted({mapping["entity_id"] for mapping in self._all_bindings() if mapping.get("source") == "entity" and mapping.get("entity_id")})

    @callback
    def _registry_changed(self, _event: Event) -> None:
        previous = self._source_entities()
        self._resolve_sources()
        if previous != self._source_entities():
            self._subscribe_sources()

    @callback
    def _state_changed(self, event: Event) -> None:
        self.sync_sources()
        self._process_event_sources(event)

    @callback
    def sync_sources(self) -> None:
        values: dict[str, Any] = {}
        for prop in self.model.properties:
            if prop.alias_of is not None:
                continue
            mapping = self.property_mappings.get(prop.key, {"source": "virtual", "value": prop.default})
            try:
                if mapping.get("source") == "derived":
                    continue
                if mapping.get("source") == "entity":
                    state = self.hass.states.get(mapping["entity_id"])
                    if self._legacy_config and prop.key == "2.1005":
                        raw = float(state.state) if state else math.nan
                        value = float(math.floor(min(1000.0, max(0.0, raw)) + .5)) if math.isfinite(raw) else None
                    else:
                        value = read_entity_value(prop, state, mapping)
                else:
                    value = mapping.get("value", prop.default)
                    saved = self._document.get("virtual_values", {}).get(prop.key)
                    if saved is not None and saved.get("configured_value") == value:
                        value = saved["value"]
                    value = prop.validate(value)
                    if not value and prop.semantic == "mac":
                        value = self.mac
                    elif not value and prop.semantic == "serial_number":
                        value = self.device_id[-12:]
                if value is not None:
                    values[prop.key] = value
            except (ValueError, TypeError, KeyError, OverflowError):
                continue
        for prop in self.model.properties:
            if prop.alias_of is None or prop.alias_of not in values:
                continue
            value = values[prop.alias_of]
            if prop.type_code not in (0, 9, 10):
                value = int(math.floor(value + .5))
            values[prop.key] = prop.validate(value)
        self._source_values = values
        presence_value = values.get(self._presence_key)
        presence = bool(presence_value) if presence_value is not None else None
        if self.model.model == DEFAULT_MODEL and presence_value not in (0, 1):
            presence = None
        if presence != self._presence:
            self._presence = presence
            self._since = time.monotonic() if presence is not None else None
            self._absent_minutes = self._present_minutes = 0
        self._lux = values.get(self._lux_key)
        entity_keys = [key for key, mapping in self.property_mappings.items() if mapping.get("source") == "entity"]
        if self._presence_key is not None:
            self._source_available = presence_value is not None
        else:
            self._source_available = not entity_keys or any(key in values for key in entity_keys)
        self.update_properties()
        self.notify_listeners()
        self.manager.wakeup.set()

    def update_properties(self) -> None:
        property_values = dict(self._source_values)
        for prop in self.model.properties:
            mapping = self.property_mappings.get(prop.key, {})
            if mapping.get("source") != "derived":
                continue
            value = {
                "present_minutes": self._present_minutes,
                "absent_minutes": self._absent_minutes,
                "unix_time": int(time.time()),
            }.get(prop.derived)
            if value is not None and (value or prop.derived == "unix_time"):
                property_values[prop.key] = prop.validate(value)
        self._property_values = property_values
        values: dict[int, Any] = {}
        payloads: dict[int, bytes] = {}
        for beacon in self.model.beacons:
            keys = beacon.property_keys or (beacon.property_key,)
            if not keys or any(key not in property_values for key in keys):
                continue
            value = property_values[keys[0]]
            try:
                payload = beacon.encode_values(property_values) if beacon.property_keys else beacon.encode(value)
            except (ValueError, TypeError, KeyError, OverflowError):
                continue
            if len(payload) > 9:
                raise ValueError("Model beacon object exceeds the legacy advertisement capacity")
            values[beacon.object_id] = value
            payloads[beacon.object_id] = payload
        changed = [key for key, value in values.items() if self._objects.get(key) != value]
        changed.extend(key for key, payload in payloads.items() if key not in changed and self._object_payloads.get(key) != payload)
        self._pending_objects = deque(key for key in self._pending_objects if key in values)
        primary = {beacon.object_id for beacon in self.model.beacons if beacon.property_key == self._presence_key}
        for key in sorted(changed, key=lambda item: (item not in primary, item != _BATTERY)):
            if key in self._pending_objects:
                self._pending_objects.remove(key)
            if key in primary:
                self._pending_objects.appendleft(key)
                self._next_publication = 0.0
            else:
                self._pending_objects.append(key)
        self._objects = values
        self._object_payloads = payloads
        self.protocol.set_property_values(property_values)

    def update_duration(self, now: float) -> None:
        if self._since is None:
            if any(prop.derived == "unix_time" and self.property_mappings.get(prop.key, {}).get("source") == "derived" for prop in self.model.properties):
                self.update_properties()
            return
        minutes = (now - self._since) / 60
        kind = "present_minutes" if self._presence else "absent_minutes"
        definition = next((prop for prop in self.model.properties if prop.derived == kind and self.property_mappings.get(prop.key, {}).get("source") == "derived"), None)
        if definition is None:
            return
        if definition.choices:
            reached = max((item for item, _ in definition.choices if minutes >= item), default=0)
        else:
            reached = int(minutes)
            if definition.maximum is not None:
                reached = min(reached, int(definition.maximum))
            if definition.minimum is not None and reached < definition.minimum:
                reached = 0
        previous = (self._absent_minutes, self._present_minutes)
        self._present_minutes = reached if self._presence else 0
        self._absent_minutes = reached if not self._presence else 0
        if previous != (self._absent_minutes, self._present_minutes):
            self.update_properties()
            self.notify_listeners()

    @callback
    def _process_event_sources(self, event: Event) -> None:
        entity_id = event.data.get("entity_id")
        previous = event.data.get("old_state")
        state = event.data.get("new_state")
        if previous is None or state is None or state.state in {"unknown", "unavailable"}:
            return
        if previous.state in {"unknown", "unavailable"} and entity_id.partition(".")[0] not in {"button", "input_button", "event"}:
            return
        if previous.state == state.state:
            return
        for definition in self.model.events:
            mapping = self.event_mappings.get(definition.key)
            if not mapping or mapping.get("entity_id") != entity_id:
                continue
            trigger = mapping.get("trigger_value", "on")
            if trigger not in (None, "", "*") and str(state.state) != str(trigger):
                continue
            try:
                snapshot = dict(self._property_values)
                for key, argument in mapping.get("arguments", {}).items():
                    prop = self.model.property_by_key[key]
                    if isinstance(argument, dict) and argument.get("source") == "entity":
                        value = read_entity_value(prop, self.hass.states.get(argument["entity_id"]), argument)
                    else:
                        value = prop.validate(argument.get("value") if isinstance(argument, dict) else argument)
                    if value is None:
                        snapshot.pop(key, None)
                    else:
                        snapshot[key] = value
                required = (*definition.argument_keys, *definition.beacon_keys)
                if any(key not in snapshot for key in required):
                    continue
                arguments = {key: self.model.property_by_key[key].validate(snapshot[key]) for key in definition.argument_keys}
                self.protocol.send_event(definition.key, arguments)
                if definition.beacon_id is not None and self.bound:
                    payload = definition.encode({**snapshot, **arguments})
                    if len(payload) > 9:
                        raise ValueError("Event object exceeds the advertising capacity")
                    for _ in range(3):
                        self._event_objects.append((definition.beacon_id, payload))
                    self._next_publication = 0.0
                self.manager.wakeup.set()
            except (ValueError, TypeError, KeyError, ProtocolError):
                _LOGGER.warning("Invalid mapped event for %s (%s)", self.name, definition.key)

    def _queue_request(self, request) -> None:
        if not self.manager._stopping:
            self.manager._spawn_event(self._async_handle_request(request))

    def _request_current(self, request) -> bool:
        return self.protocol.logged_in and self.protocol.session_id == request.session_id and any(pending is request for pending in self.protocol.pending_requests) and not self.manager._stopping

    def _linked_virtual_values(self, virtual: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
        current = {key: item["value"] for key, item in virtual.items() if key in self.model.property_by_key and item.get("configured_value") == self.property_mappings.get(key, {}).get("value", self.model.property_by_key[key].default)}
        values = {**self._property_values, **current, **changes}
        linked: dict[str, Any] = {}
        if self.model.model == "careco.nlight.o654" and "7.4" in changes:
            scene = {1: (100, 5000), 2: (1, 5000), 3: (100, 2700), 4: (1, 2700)}.get(changes["7.4"])
            if scene is not None:
                linked = {"7.2": scene[0], "7.3": scene[1]}
        elif self.model.model == "yunmi.kettle.v13":
            if "3.3" in changes:
                linked["3.6"] = values.get(f"5.{int(changes['3.3'])+1}")
            for key, value in changes.items():
                if key in {f"5.{index}" for index in range(1, 6)}:
                    linked.update({"3.3": int(key.split(".")[1])-1, "3.6": value})
        for key, value in linked.items():
            prop = self.model.property_by_key[key]
            mapping = self.property_mappings.get(key, {})
            if value is not None and mapping.get("source") == "virtual":
                virtual[key] = {"configured_value": mapping.get("value", prop.default), "value": prop.validate(value)}
        return virtual

    async def _async_write_properties(self, request) -> dict[str, int]:
        results: dict[str, int] = {}
        if not self._request_current(request):
            return results
        if getattr(request, "action_key", None) == "nus_set_scene":
            values = dict(request.items)
            scene_id = str(dict(request.args)["scene_id"])
            scenes = {**self._document.get("nus_scenes", {}), scene_id: {"bright": values["2.1"], "dur": values["2.2"]}}
            try:
                await self._async_save({"nus_scenes": scenes})
                return {key: 0 for key in values}
            except OSError:
                return {key: 1 for key in values}
        virtual = dict(self._document.get("virtual_values", {}))
        virtual_keys: list[str] = []
        for key, value in request.items:
            if not self._request_current(request):
                return results
            prop = self.model.property_by_key.get(key)
            mapping = self.property_mappings.get(key, {})
            if prop is None or not prop.writable:
                results[key] = 1
                continue
            try:
                value = prop.validate(value)
                if mapping.get("source") == "virtual":
                    virtual[key] = {"configured_value": mapping.get("value", prop.default), "value": value}
                    self._linked_virtual_values(virtual, {key: value})
                    virtual_keys.append(key)
                elif mapping.get("source") == "entity":
                    state = self.hass.states.get(mapping["entity_id"])
                    if state is None or state.state in {"unknown", "unavailable"}:
                        raise ValueError("Mapped entity is unavailable")
                    domain, service, data = property_service_call(prop, value, mapping, state)
                    await self.hass.services.async_call(domain, service, data, blocking=True)
                    results[key] = 0
                else:
                    results[key] = 1
            except Exception:
                results[key] = 1
                _LOGGER.warning("Mapped property write failed for %s (%s)", self.name, key)
        if virtual_keys and self._request_current(request):
            try:
                await self._async_save({"virtual_values": virtual})
                results.update({key: 0 for key in virtual_keys})
            except OSError:
                results.update({key: 1 for key in virtual_keys})
        return results

    async def _async_action(self, request) -> tuple[int, dict[str, Any]]:
        definition = next((action for action in self.model.actions if action.key == request.action_key), None)
        if definition is None:
            return 1, {}
        if any(key not in self._property_values for key in definition.output_keys):
            return 1, {}
        mapping = self.action_mappings.get(definition.key, {"source": "virtual"})
        if mapping.get("source") == "entity":
            domain, service, data = action_service_call(mapping)
            if domain == "script":
                data["variables"] = {"miot_action": definition.key, "miot_arguments": dict(request.args)}
            await self.hass.services.async_call(domain, service, data, blocking=True)
        elif mapping.get("source") == "virtual":
            virtual = dict(self._document.get("virtual_values", {}))
            for key, value in request.args:
                prop = self.model.property_by_key[key]
                configured = self.property_mappings.get(key, {})
                if configured.get("source") == "virtual":
                    virtual[key] = {"configured_value": configured.get("value", prop.default), "value": prop.validate(value)}
            if self.model.model == "xiaomi.cooler.r02p" and definition.key == "4.1":
                for key in ("4.3", "4.6", "4.7", "4.8"):
                    prop = self.model.property_by_key[key]
                    configured = self.property_mappings.get(key, {})
                    if configured.get("source") == "virtual":
                        virtual[key] = {"configured_value": configured.get("value", prop.default), "value": prop.default}
            if request.args or virtual != self._document.get("virtual_values", {}):
                await self._async_save({"virtual_values": virtual})
        else:
            return 1, {}
        self.sync_sources()
        outputs = {}
        for key in definition.output_keys:
            prop = self.model.property_by_key[key]
            if key not in self._property_values:
                return 1, {}
            value = self._property_values[key]
            outputs[key] = prop.validate(value)
        return 0, outputs

    async def _async_handle_request(self, request) -> None:
        async with self._request_lock:
            if not self._request_current(request):
                return
            if request.kind == "set":
                results = await self._async_write_properties(request)
                async with self.manager._operation_lock:
                    if self._request_current(request):
                        self.sync_sources()
                        self.protocol.reply_set(request, results)
                        self.manager._flush_notifications(self)
            else:
                try:
                    result, outputs = await self._async_action(request)
                except Exception:
                    result, outputs = 1, {}
                    _LOGGER.warning("Mapped action failed for %s (%s)", self.name, request.action_key)
                async with self.manager._operation_lock:
                    if self._request_current(request):
                        self.protocol.reply_action(request, result, outputs)
                        self.manager._flush_notifications(self)
            self.notify_listeners()
            self.manager.wakeup.set()

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
        self.server.subscription_callback = self._notify_channels_changed
        self.server.mtu_callback = self._mtu_changed
        self.pairing: RadarRuntime | None = None
        self.connection_target: RadarRuntime | None = None
        self._connection_rotation = 0
        self._selection_deadline = 0.0
        self._incoming_pending = False
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
                elif self.connection_target is runtime:
                    await self._async_close_connection_target()
                await self.advertiser.async_disable(runtime.instance)
            except (HciError, DBusError, TimeoutError) as error:
                self._failed(error)
            finally:
                runtime.stop_subscriptions()
                runtime.protocol.disconnect()
                self.targets.pop(runtime.device_id, None)
                if self.connection_target is runtime:
                    self.connection_target = None
                    self._selection_deadline = 0.0

    async def async_start_pairing(self, runtime: RadarRuntime) -> None:
        async with self._operation_lock:
            if self.failure or runtime._error:
                raise RuntimeError("Bluetooth bridge is unavailable; reload the integration")
            if self.pairing is not None:
                await self._async_end_pairing()
            elif self.connection_target is not None:
                await self._async_close_connection_target()
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
            self._selection_deadline = 0.0
            self.wakeup.set()

    async def _async_close_connection_target(self) -> None:
        runtime = self.connection_target
        if runtime is None:
            return
        peer_address = self._peer_address
        self.connection_target = None
        self.connection_handle = None
        self._peer_address = self._peer_path = None
        runtime.protocol.disconnect()
        self._notifications.clear()
        self.server.reset_session()
        try:
            if peer_address:
                await self.server.async_disconnect_peer(peer_address)
        finally:
            await self.advertiser.async_configure(runtime.instance, runtime.mac, False, interval_ms=400)
            runtime._enabled = False
            runtime._next_publication = 0.0
            self._selection_deadline = 0.0

    async def _async_select_connection(self, now: float) -> None:
        if self.pairing is not None or self.connection_handle is not None or self._incoming_pending or now < self._selection_deadline:
            return
        candidates = [runtime for runtime in self.targets.values() if runtime.bound and runtime.model.connectable and not runtime._error]
        if not candidates:
            if self.connection_target is not None:
                await self._async_close_connection_target()
            return
        selected = candidates[self._connection_rotation % len(candidates)]
        self._connection_rotation += 1
        if selected is not self.connection_target:
            await self._async_close_connection_target()
            self.connection_target = selected
            await self.advertiser.async_configure(selected.instance, selected.mac, True, interval_ms=100)
            selected._enabled = False
            selected._next_publication = 0.0
        self._selection_deadline = now + 3.0

    def _spawn_event(self, coroutine) -> None:
        task = self.hass.async_create_background_task(coroutine, f"{DOMAIN} Bluetooth event")
        self._event_tasks.add(task)
        task.add_done_callback(self._event_tasks.discard)

    @callback
    def _hci_event(self, event: BluetoothEvent) -> None:
        runtime = self.pairing or self.connection_target
        if runtime is None or self._stopping:
            return
        if event.instance is not None and event.instance != runtime.instance:
            return
        relevant = (event.kind == "connected" and event.role == 1) or event.kind == "disconnected" or (event.kind == "advertising" and event.instance == runtime.instance)
        if relevant:
            if (event.kind == "connected" and event.status == 0 and event.role == 1) or (event.kind == "advertising" and event.state == 1 and event.handle is not None):
                self._incoming_pending = True
            self._spawn_event(self._async_hci_event(runtime, event))

    async def _async_hci_event(self, runtime: RadarRuntime, event: BluetoothEvent) -> None:
        async with self._operation_lock:
            if (self.pairing or self.connection_target) is not runtime or self._stopping:
                self._incoming_pending = False
                return
            try:
                await self._async_process_hci_event(runtime, event)
            except (HciError, DBusError, TimeoutError) as error:
                self._failed(error)
            finally:
                self._incoming_pending = False

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
                if self.pairing is runtime:
                    await self._async_end_pairing()
                else:
                    self.connection_target = None
                    self._selection_deadline = 0.0
            else:
                await self.advertiser.async_configure(runtime.instance, runtime.mac, True, interval_ms=100)
                runtime._enabled = False
                runtime._next_publication = 0.0
        self.wakeup.set()

    def _read_gatt(self, channel: int) -> bytes:
        runtime = self.pairing or self.connection_target
        return runtime.protocol.read(channel) if runtime else b""

    def _notify_channels_changed(self, channels: set[int]) -> None:
        runtime = self.pairing or self.connection_target
        if runtime is not None:
            runtime.protocol.set_notify_channels(channels)
            self.wakeup.set()

    def _mtu_changed(self, mtu: int) -> None:
        runtime = self.pairing or self.connection_target
        if runtime is not None:
            runtime.protocol.set_mtu(mtu)

    async def _write_gatt(self, channel: int, value: bytes, peer_path: str | None) -> None:
        async with self._operation_lock:
            runtime = self.pairing or self.connection_target
            if runtime is None:
                raise DBusError("org.bluez.Error.NotAuthorized", "Open the selected device's pairing window first")
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
        if (pairing or self.connection_target is runtime) and self.connection_handle is not None and not self._connection_advertisement_ready:
            return
        if not pairing and (not runtime.bound or not runtime._source_available):
            if runtime._enabled:
                await self.advertiser.async_disable(runtime.instance)
                runtime._enabled = False
            return
        if now < runtime._next_publication:
            return
        if not runtime.bound or runtime.model.auth_mode == "standard_nus":
            counter = runtime._hello_sequence
            service_data = runtime.protocol.hello(counter)
            runtime._hello_sequence = (runtime._hello_sequence + 1) & 0xFF
        else:
            if runtime._event_objects:
                object_id, object_payload = runtime._event_objects.popleft()
            elif runtime._pending_objects:
                object_id = runtime._pending_objects.popleft()
                object_payload = runtime._object_payloads[object_id]
            else:
                objects = list(runtime._objects)
                if not objects:
                    return
                object_id = objects[runtime._rotation % len(objects)]
                runtime._rotation += 1
                object_payload = runtime._object_payloads[object_id]
            try:
                counter = await runtime.async_counter()
            except (OSError, ValueError, ProtocolError) as error:
                runtime._error = f"Identity persistence failed: {error}"
                runtime.notify_listeners()
                await self.advertiser.async_disable(runtime.instance)
                runtime._enabled = False
                _LOGGER.error("Encrypted advertising stopped for %s: %s", runtime.name, error)
                return
            service_data = runtime.protocol.beacon_object(object_id, object_payload, counter, pairing=pairing or self.connection_target is runtime)
        await self.advertiser.async_set_data(
            runtime.instance, advertising_payload(service_data), scan_response_payload(runtime, counter),
        )
        if not runtime._enabled:
            await self.advertiser.async_enable(runtime.instance)
            runtime._enabled = True
        runtime._next_publication = now + (0.4 if runtime._event_objects else 0.5 if runtime._pending_objects else 1.0)
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
            self.connection_target = None
            self._selection_deadline = 0.0
            self._incoming_pending = False
            self.connection_handle = None
            self._peer_address = self._peer_path = None
            try:
                await self.advertiser.async_stop()
            except HciError:
                pass
            await self.server.async_stop()
            self.advertiser = VendorAdvertiser(self.adapter, event_callback=self._hci_event)
            self.server = BlueZServer(self.adapter, self._write_gatt, self._read_gatt)
            self.server.subscription_callback = self._notify_channels_changed
            self.server.mtu_callback = self._mtu_changed
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
                        await self._async_select_connection(now)
                        runtime = self.pairing or self.connection_target
                        if runtime and self.connection_handle is not None:
                            runtime.protocol.poll(now)
                            await runtime.async_persist_pending_identity()
                            self._flush_notifications(runtime)
                        for runtime in tuple(self.targets.values()):
                            runtime.update_duration(now)
                            await self._async_publish(runtime, now)
            except (HciError, OSError, DBusError, ProtocolError, RuntimeError, ValueError) as error:
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
