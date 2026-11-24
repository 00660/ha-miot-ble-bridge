"""BlueZ FE95 GATT server shared by the bridge's advertising identities."""

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable
import logging

from dbus_fast import BusType, DBusError, PropertyAccess, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, dbus_property, method

_LOGGER = logging.getLogger(__name__)
_GATT_SERVICE = "org.bluez.GattService1"
_GATT_CHARACTERISTIC = "org.bluez.GattCharacteristic1"
_CHANNELS = (0x0010, 0x0019, 0x001A, 0x001B)
_AUX_CHANNELS = (0x0001, 0x0002, 0x0004, 0x0013, 0x0014, 0x0016, 0x0017, 0x0018)
NUS_RX = 0x6E400002
NUS_TX = 0x6E400003
_NUS_UUID = "6e40000{}-b5a3-f393-e0a9-e50e24dcca9e"
_BASE_UUID = "0000{:04x}-0000-1000-8000-00805f9b34fb"


class _Service(ServiceInterface):
    def __init__(self, path: str, uuid: str | None = None) -> None:
        super().__init__(_GATT_SERVICE)
        self.path = path
        self.uuid = uuid or _BASE_UUID.format(0xFE95)

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> "b":
        return True

    @dbus_property(access=PropertyAccess.READ)
    def Includes(self) -> "ao":
        return []

    def properties(self) -> dict[str, Variant]:
        return {
            "UUID": Variant("s", self.UUID),
            "Primary": Variant("b", True),
            "Includes": Variant("ao", []),
        }


class _Characteristic(ServiceInterface):
    def __init__(self, server: "BlueZServer", channel: int, *, service: _Service | None = None, uuid: str | None = None) -> None:
        super().__init__(_GATT_CHARACTERISTIC)
        self.server = server
        self.channel = channel
        self.service = service or server.service
        self.uuid = uuid or _BASE_UUID.format(channel)
        self.path = f"{self.service.path}/char{channel:04x}"
        self._value = b""
        self._notifying = False
        self._pending: deque[bytes] = deque()

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return self.service.path

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        if self.channel in (0x0002, 0x0004, 0x0014):
            return ["read"]
        return ["read", "write", "write-without-response", "notify"]

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return self._value

    @dbus_property(access=PropertyAccess.READ)
    def Notifying(self) -> "b":
        return self._notifying

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        self.server.update_mtu(options)
        offset = int(options.get("offset", Variant("q", 0)).value)
        value = self.server.read_callback(self.channel)
        if offset > len(value):
            raise DBusError("org.bluez.Error.InvalidOffset", "Offset exceeds value length")
        return value[offset:]

    @method()
    async def WriteValue(self, value: "ay", options: "a{sv}"):
        self.server.update_mtu(options)
        if options.get("offset", Variant("q", 0)).value:
            raise DBusError("org.bluez.Error.InvalidOffset", "Fragmented writes are unsupported")
        if len(value) > 244:
            raise DBusError("org.bluez.Error.InvalidValueLength", "MiOT packet exceeds limit")
        device = options.get("device")
        await self.server.write_callback(
            self.channel, bytes(value), str(device.value) if device else None
        )

    @method()
    def StartNotify(self):
        self._notifying = True
        self.emit_properties_changed({"Notifying": True})
        self.server.subscription_changed()
        while self._pending:
            self._send(self._pending.popleft())

    @method()
    def StopNotify(self):
        self.clear()

    def _send(self, value: bytes) -> None:
        self._value = value
        self.emit_properties_changed({"Value": value})

    def notify(self, value: bytes) -> bool:
        if self._notifying:
            self._send(value)
            return True
        if len(self._pending) >= 16:
            return False
        self._pending.append(value)
        return True

    def clear(self) -> None:
        self._pending.clear()
        self._value = b""
        if self._notifying:
            self._notifying = False
            self.emit_properties_changed({"Notifying": False, "Value": b""})
            self.server.subscription_changed()

    def properties(self) -> dict[str, Variant]:
        return {
            "UUID": Variant("s", self.UUID),
            "Service": Variant("o", self.Service),
            "Flags": Variant("as", self.Flags),
            "Value": Variant("ay", self._value),
            "Notifying": Variant("b", self._notifying),
        }


class _Application(ServiceInterface):
    def __init__(self, server: "BlueZServer") -> None:
        super().__init__("org.freedesktop.DBus.ObjectManager")
        self.server = server

    @method()
    def GetManagedObjects(self) -> "a{oa{sa{sv}}}":
        objects = {service.path: {_GATT_SERVICE: service.properties()} for service in self.server.services}
        objects.update({
            char.path: {_GATT_CHARACTERISTIC: char.properties()}
            for char in self.server.characteristics.values()
        })
        return objects


class BlueZServer:
    def __init__(
        self,
        adapter: str,
        write_callback: Callable[[int, bytes, str | None], Awaitable[None]],
        read_callback: Callable[[int], bytes],
    ) -> None:
        self.adapter = adapter
        self.path = f"/org/miot_ble_bridge/{adapter}"
        self.write_callback = write_callback
        self.read_callback = read_callback
        self.service = _Service(f"{self.path}/service0")
        self.nus_service = _Service(f"{self.path}/service1", _NUS_UUID.format(1))
        self.services = (self.service, self.nus_service)
        self.characteristics = {ch: _Characteristic(self, ch) for ch in (*_CHANNELS, *_AUX_CHANNELS)}
        self.characteristics[NUS_RX] = _Characteristic(self, NUS_RX, service=self.nus_service, uuid=_NUS_UUID.format(2))
        self.characteristics[NUS_TX] = _Characteristic(self, NUS_TX, service=self.nus_service, uuid=_NUS_UUID.format(3))
        self.subscription_callback: Callable[[set[int]], None] | None = None
        self.mtu_callback: Callable[[int], None] | None = None
        self.att_mtu: int | None = None
        self.application = _Application(self)
        self.bus: MessageBus | None = None
        self.manager = None
        self._adapter_properties = None
        self._registered = False
        self._legacy_hass = None
        self._legacy_entry_ids: list[str] = []
        self._legacy_acquired = False
        self._legacy_powered: bool | None = None

    async def async_start(self) -> None:
        self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            introspection = await self.bus.introspect("org.bluez", f"/org/bluez/{self.adapter}")
            proxy = self.bus.get_proxy_object("org.bluez", f"/org/bluez/{self.adapter}", introspection)
            self.manager = proxy.get_interface("org.bluez.GattManager1")
            self._adapter_properties = proxy.get_interface("org.freedesktop.DBus.Properties")
            self.bus.export(self.path, self.application)
            for service in self.services:
                self.bus.export(service.path, service)
            for char in self.characteristics.values():
                self.bus.export(char.path, char)
            await asyncio.wait_for(self.manager.call_register_application(self.path, {}), 10)
            self._registered = True
        except BaseException:
            self.bus.disconnect()
            self.bus = None
            raise

    @staticmethod
    def _local_scanner_sources(hass, adapter: str) -> set[str]:
        from habluetooth import HaScanner
        from homeassistant.components.bluetooth import async_current_scanners

        return {
            scanner.source.upper() for scanner in async_current_scanners(hass)
            if isinstance(scanner, HaScanner) and scanner.adapter == adapter
        }

    @staticmethod
    async def _async_finish_entry_operation(operation: Awaitable[bool]) -> bool:
        # Let HA finish changing its entry state before cancellation rolls back.
        task = asyncio.ensure_future(operation)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            await asyncio.shield(task)
            raise

    async def _async_require_unoccupied(
        self, *, discovery: bool, busy: Callable[[], bool] | None = None,
    ) -> bool:
        if busy is not None and busy():
            return False
        active = await asyncio.wait_for(
            self._adapter_properties.call_get("org.bluez.LEAdvertisingManager1", "ActiveInstances"), 5,
        )
        if busy is not None and busy():
            return False
        if active.value:
            raise RuntimeError(f"{self.adapter} already has BlueZ advertisements on the standard advertiser")
        if discovery:
            discovering = await asyncio.wait_for(
                self._adapter_properties.call_get("org.bluez.Adapter1", "Discovering"), 5,
            )
            if busy is not None and busy():
                return False
            if discovering.value:
                raise RuntimeError(f"{self.adapter} is being used for discovery by another Bluetooth client")
        introspection = await self.bus.introspect("org.bluez", "/")
        if busy is not None and busy():
            return False
        objects = self.bus.get_proxy_object("org.bluez", "/", introspection).get_interface(
            "org.freedesktop.DBus.ObjectManager"
        )
        managed = await asyncio.wait_for(objects.call_get_managed_objects(), 5)
        if busy is not None and busy():
            return False
        prefix = f"/org/bluez/{self.adapter}/dev_"
        for path, interfaces in managed.items():
            device = interfaces.get("org.bluez.Device1", {})
            connected = device.get("Connected")
            if path.startswith(prefix) and connected is not None and connected.value:
                raise RuntimeError(f"{self.adapter} has an active Bluetooth connection owned by another client")
        return True

    async def async_require_idle_advertising(self, hass=None) -> None:
        """Acquire a dedicated legacy advertiser without stopping bluetoothd."""
        if self._legacy_acquired:
            return
        if self._legacy_entry_ids:
            await self._async_restore_scanners()
        await self._async_require_unoccupied(discovery=False)
        powered = await asyncio.wait_for(
            self._adapter_properties.call_get("org.bluez.Adapter1", "Powered"), 5,
        )
        if not powered.value:
            raise RuntimeError(f"{self.adapter} must be powered before legacy advertising starts")
        self._legacy_hass = hass
        self._legacy_powered = bool(powered.value)
        try:
            if hass is not None:
                address = await asyncio.wait_for(
                    self._adapter_properties.call_get("org.bluez.Adapter1", "Address"), 5,
                )
                sources = self._local_scanner_sources(hass, self.adapter)
                entries = [
                    entry for entry in hass.config_entries.async_entries("bluetooth")
                    if str(entry.unique_id).upper() == str(address.value).upper()
                    and not entry.data.get("source_config_entry_id")
                ]
                if len(entries) > 1 or (sources and not entries):
                    raise RuntimeError(f"Cannot safely pause the HA scanner owner for {self.adapter}")
                for entry in entries:
                    state = getattr(entry.state, "value", entry.state)
                    if state == "loaded":
                        self._legacy_entry_ids.append(entry.entry_id)
                        if not await self._async_finish_entry_operation(
                            hass.config_entries.async_unload(entry.entry_id),
                        ):
                            raise RuntimeError(f"Unable to pause the HA scanner for {self.adapter}")
                    elif state != "not_loaded":
                        raise RuntimeError(f"The HA scanner for {self.adapter} is still changing state")
            await self.async_check_legacy_occupancy()
            self._legacy_acquired = True
            await self._async_reset_legacy_adapter()
        except BaseException:
            self._legacy_acquired = False
            try:
                await self._async_restore_scanners()
            finally:
                self._legacy_powered = None
            raise

    async def async_check_legacy_occupancy(
        self, *, busy: Callable[[], bool] | None = None,
    ) -> bool:
        """Reject external users before the caller changes the legacy address."""
        if busy is not None and busy():
            return False
        if self._legacy_hass is not None and self._local_scanner_sources(self._legacy_hass, self.adapter):
            raise RuntimeError(f"The HA scanner for {self.adapter} restarted during legacy advertising")
        return await self._async_require_unoccupied(discovery=True, busy=busy)

    @property
    def local_scanning_paused(self) -> bool:
        return self._legacy_acquired and bool(self._legacy_entry_ids)

    async def _async_restore_scanners(self) -> None:
        hass = self._legacy_hass
        if hass is None:
            return
        if getattr(hass, "is_stopping", False):
            self._legacy_entry_ids.clear()
        else:
            for entry_id in tuple(self._legacy_entry_ids):
                entry = hass.config_entries.async_get_entry(entry_id)
                if entry is not None and entry.disabled_by is None:
                    state = getattr(entry.state, "value", entry.state)
                    if state in ("setup_error", "setup_retry"):
                        if not await self._async_finish_entry_operation(
                            hass.config_entries.async_unload(entry_id),
                        ):
                            raise RuntimeError(f"Unable to recover the HA scanner for {self.adapter}")
                        state = "not_loaded"
                    if state == "not_loaded":
                        if not await self._async_finish_entry_operation(
                            hass.config_entries.async_setup(entry_id),
                        ):
                            raise RuntimeError(f"Unable to restore the HA scanner for {self.adapter}")
                    elif state != "loaded":
                        raise RuntimeError(f"Cannot restore the HA scanner for {self.adapter} from state {state}")
                self._legacy_entry_ids.remove(entry_id)
        self._legacy_hass = None

    async def _async_release_legacy(self) -> None:
        try:
            if self._legacy_acquired:
                await self.async_check_legacy_occupancy()
                await self._async_reset_legacy_adapter()
        finally:
            self._legacy_acquired = False
            try:
                await self._async_restore_scanners()
            finally:
                self._legacy_powered = None

    async def _async_reset_legacy_adapter(self) -> None:
        # BlueZ retains its GATT database across Powered transitions. Reset only
        # this dedicated adapter to separate legacy/extended HCI command modes.
        try:
            await asyncio.wait_for(self._adapter_properties.call_set(
                "org.bluez.Adapter1", "Powered", Variant("b", False),
            ), 5)
        finally:
            await asyncio.wait_for(self._adapter_properties.call_set(
                "org.bluez.Adapter1", "Powered", Variant("b", self._legacy_powered),
            ), 5)

    def notify(self, channel: int, value: bytes) -> bool:
        return self.characteristics[channel].notify(value)

    @property
    def notifying_channels(self) -> set[int]:
        return {channel for channel, char in self.characteristics.items() if char._notifying}

    def subscription_changed(self) -> None:
        if self.subscription_callback is not None:
            self.subscription_callback(self.notifying_channels)

    def update_mtu(self, options: dict[str, Variant]) -> None:
        if "mtu" in options:
            self.att_mtu = int(options["mtu"].value)
            if self.mtu_callback is not None:
                self.mtu_callback(self.att_mtu)

    def reset_session(self) -> None:
        self.att_mtu = None
        for char in self.characteristics.values():
            char.clear()

    async def async_disconnect_peer(self, address: str) -> None:
        if self.bus is None:
            return
        path = f"/org/bluez/{self.adapter}/dev_{address.upper().replace(':', '_')}"
        try:
            introspection = await self.bus.introspect("org.bluez", path)
            proxy = self.bus.get_proxy_object("org.bluez", path, introspection)
            await asyncio.wait_for(proxy.get_interface("org.bluez.Device1").call_disconnect(), 5)
        except DBusError as error:
            if error.type not in ("org.freedesktop.DBus.Error.UnknownObject", "org.bluez.Error.NotConnected", "org.bluez.Error.DoesNotExist"):
                raise

    async def async_stop(self) -> None:
        if self.bus is None:
            await self._async_restore_scanners()
            return
        try:
            if self._registered and self.manager is not None:
                await asyncio.wait_for(self.manager.call_unregister_application(self.path), 5)
        except (DBusError, TimeoutError):
            _LOGGER.debug("BlueZ GATT application was already removed", exc_info=True)
        finally:
            self._registered = False
            try:
                await self._async_release_legacy()
            finally:
                self.bus.disconnect()
                self.bus = None
                self._adapter_properties = None
