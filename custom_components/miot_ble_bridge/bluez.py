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
        self._registered = False

    async def async_start(self) -> None:
        self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            introspection = await self.bus.introspect("org.bluez", f"/org/bluez/{self.adapter}")
            proxy = self.bus.get_proxy_object("org.bluez", f"/org/bluez/{self.adapter}", introspection)
            self.manager = proxy.get_interface("org.bluez.GattManager1")
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
            return
        try:
            if self._registered and self.manager is not None:
                await asyncio.wait_for(self.manager.call_unregister_application(self.path), 5)
        except (DBusError, TimeoutError):
            _LOGGER.debug("BlueZ GATT application was already removed", exc_info=True)
        finally:
            self._registered = False
            self.bus.disconnect()
            self.bus = None
