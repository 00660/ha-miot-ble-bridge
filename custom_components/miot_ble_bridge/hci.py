"""Android vendor advertising on a shared Linux Bluetooth controller.

The vendor instances have their own on-air addresses. The standard advertising
instance, scanning settings, adapter identity, and BlueZ remain untouched.
Protocol reference: source.android.com/docs/core/connect/bluetooth/hci_requirements
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import logging
import re
import socket
import struct

_LOGGER = logging.getLogger(__name__)
HCI_VENDOR_CAPABILITIES = 0xFD53
HCI_VENDOR_MULTI_ADVERTISEMENT = 0xFD54
_COMMAND_PACKET = 0x01
_EVENT_PACKET = 0x04
_COMMAND_COMPLETE = 0x0E
_COMMAND_STATUS = 0x0F
_DISCONNECTION_COMPLETE = 0x05
_LE_META = 0x3E
_VENDOR_EVENT = 0xFF


class HciError(Exception):
    """A controller or transport operation failed."""


class HciUnsupportedError(HciError):
    """Independent vendor advertising is unavailable."""


class HciQueueFullError(HciError):
    """The bounded command queue is full."""


class HciCommandError(HciError):
    """The controller rejected a command."""

    def __init__(self, opcode: int, status: int) -> None:
        self.opcode = opcode
        self.status = status
        super().__init__(f"HCI command 0x{opcode:04X} failed with status 0x{status:02X}")


@dataclass(frozen=True, slots=True)
class Capabilities:
    max_advertisements: int
    rpa_offloading: bool
    scan_result_storage: int
    max_irk_list: int
    advertisement_filtering: bool
    max_filters: int
    energy_info: bool
    version: int | None = None

    @property
    def usable_instances(self) -> tuple[int, ...]:
        # Instance zero belongs to the standard HCI/BlueZ advertiser.
        return tuple(range(1, self.max_advertisements))


@dataclass(frozen=True, slots=True)
class BluetoothEvent:
    kind: str
    instance: int | None = None
    handle: int | None = None
    address: str | None = None
    address_type: int | None = None
    role: int | None = None
    status: int | None = None
    state: int | None = None
    reason: int | None = None


@dataclass(frozen=True, slots=True)
class CommandEvent:
    opcode: int
    status: int
    data: bytes = b""
    complete: bool = True


def parse_hci_event(packet: bytes) -> BluetoothEvent | CommandEvent | None:
    """Decode complete HCI event packets; ignore reports unrelated to this bridge."""
    if len(packet) < 3 or packet[0] != _EVENT_PACKET or len(packet) != packet[2] + 3:
        return None
    event_code = packet[1]
    data = packet[3:]
    if event_code == _COMMAND_COMPLETE and len(data) >= 4:
        return CommandEvent(struct.unpack_from("<H", data, 1)[0], data[3], data[4:])
    if event_code == _COMMAND_STATUS and len(data) == 4:
        return CommandEvent(struct.unpack_from("<H", data, 2)[0], data[0], complete=False)
    if event_code == _DISCONNECTION_COMPLETE and len(data) == 4:
        return BluetoothEvent(
            "disconnected", handle=struct.unpack_from("<H", data, 1)[0],
            status=data[0], reason=data[3],
        )
    if event_code == _LE_META and data:
        if (data[0] == 0x01 and len(data) == 19) or (data[0] == 0x0A and len(data) == 31):
            return BluetoothEvent(
                "connected", handle=struct.unpack_from("<H", data, 2)[0],
                address=":".join(f"{byte:02X}" for byte in data[6:12][::-1]),
                address_type=data[5], role=data[4], status=data[1],
            )
    if event_code == _VENDOR_EVENT and len(data) == 5 and data[0] == 0x55:
        handle = struct.unpack_from("<H", data, 3)[0]
        return BluetoothEvent(
            "advertising", instance=data[1], state=data[2],
            handle=handle if handle <= 0x0EFF else None,
        )
    return None


def decode_capabilities(data: bytes) -> Capabilities:
    """Decode LE Get Vendor Capabilities return parameters without the status byte."""
    if len(data) < 8:
        raise HciUnsupportedError("Truncated LE Get Vendor Capabilities response")
    if data[0] <= 1:
        raise HciUnsupportedError("Controller does not support independent vendor advertisers")
    return Capabilities(
        max_advertisements=data[0], rpa_offloading=bool(data[1]),
        scan_result_storage=struct.unpack_from("<H", data, 2)[0],
        max_irk_list=data[4], advertisement_filtering=bool(data[5]),
        max_filters=data[6], energy_info=bool(data[7]),
        version=struct.unpack_from("<H", data, 8)[0] if len(data) >= 10 else None,
    )


def _address_bytes(mac: str) -> bytes:
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        raise ValueError("A Bluetooth address must contain six colon-separated hex bytes")
    address = bytes.fromhex(mac.replace(":", ""))
    random_part = int.from_bytes(address, "big") & ((1 << 46) - 1)
    if address[0] & 0xC0 != 0xC0 or random_part in (0, (1 << 46) - 1):
        raise ValueError("A virtual device requires a valid static random Bluetooth address")
    return address[::-1]


def advertising_parameters(
    instance: int, mac: str, connectable: bool, interval_ms: float = 100,
    tx_power: int = 0,
) -> bytes:
    """Build the 24-byte vendor Set Advertising Parameters payload."""
    if not 1 <= instance <= 254:
        raise ValueError("Advertising instance zero is reserved for BlueZ")
    minimum = 20 if connectable else 100
    if not minimum <= interval_ms <= 10240:
        raise ValueError(f"Advertising interval must be between {minimum} and 10240 ms")
    if not -70 <= tx_power <= 20:
        raise ValueError("Advertising transmit power must be between -70 and 20 dBm")
    interval = round(interval_ms / 0.625)
    return struct.pack(
        "<BHHBB6sB6sBBBb", 0x01, interval, interval, 0x00 if connectable else 0x03,
        0x01, _address_bytes(mac), 0x00, bytes(6), 0x07, 0x00, instance, tx_power,
    )


def advertising_data(instance: int, data: bytes, *, scan_response: bool = False) -> bytes:
    if not 1 <= instance <= 254:
        raise ValueError("Advertising instance zero is reserved for BlueZ")
    if len(data) > 31:
        raise ValueError("Legacy advertising and scan response data are limited to 31 bytes")
    return bytes((0x03 if scan_response else 0x02, len(data))) + data.ljust(31, b"\x00") + bytes((instance,))


@dataclass(slots=True)
class _Command:
    opcode: int
    payload: bytes
    subcommand: int | None
    result: asyncio.Future[bytes]


@dataclass(slots=True)
class _Instance:
    mac: str
    connectable: bool
    scan_response: bytes | None = None


class VendorAdvertiser:
    """Serialize vendor HCI commands without taking over the controller.

    The event callback is synchronous and must not block. It can schedule HA
    tasks when further asynchronous work is required.
    """

    def __init__(
        self, adapter: str = "hci0", *,
        event_callback: Callable[[BluetoothEvent], None] | None = None,
        command_timeout: float = 3.0, queue_size: int = 32,
    ) -> None:
        match = re.fullmatch(r"hci(\d+)", adapter)
        if match is None or int(match[1]) > 65535:
            raise ValueError("Adapter must be a Linux hci device name")
        if command_timeout <= 0 or queue_size < 1:
            raise ValueError("Command timeout and queue size must be positive")
        self.adapter = adapter
        self._adapter_index = int(match[1])
        self._event_callback = event_callback
        self._command_timeout = command_timeout
        self._queue: asyncio.Queue[_Command] = asyncio.Queue(maxsize=queue_size)
        self._socket: socket.socket | None = None
        self._reader: asyncio.Task[None] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._pending: _Command | None = None
        self._reply: asyncio.Future[CommandEvent] | None = None
        self._failure: HciError | None = None
        self._stopping = False
        self._enable_lock = asyncio.Lock()
        self._instances: dict[int, _Instance] = {}
        self._enabled: set[int] = set()
        self._handle_instances: dict[int, int] = {}
        self.capabilities: Capabilities | None = None

    def _open_socket(self) -> socket.socket:
        if not hasattr(socket, "AF_BLUETOOTH") or not hasattr(socket, "BTPROTO_HCI"):
            raise HciUnsupportedError("Raw HCI advertising requires Linux Bluetooth sockets")
        controller = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        try:
            controller.setblocking(False)
            controller.bind((self._adapter_index,))
            events_low = (1 << _DISCONNECTION_COMPLETE) | (1 << _COMMAND_COMPLETE) | (1 << _COMMAND_STATUS)
            events_high = (1 << (_LE_META - 32)) | (1 << 31)
            controller.setsockopt(0, 2, struct.pack("<IIIH", 1 << _EVENT_PACKET, events_low, events_high, 0))
        except BaseException:
            controller.close()
            raise
        return controller

    async def _async_receive(self) -> bytes:
        assert self._socket is not None
        return await asyncio.get_running_loop().sock_recv(self._socket, 512)

    async def _async_send(self, packet: bytes) -> None:
        assert self._socket is not None
        await asyncio.get_running_loop().sock_sendall(self._socket, packet)

    async def async_start(self) -> Capabilities:
        if self._socket is not None:
            if self.capabilities is not None:
                return self.capabilities
            raise HciError("HCI transport is already starting")
        await self._join_tasks()
        self._failure = None
        self._stopping = False
        self.capabilities = None
        try:
            self._socket = self._open_socket()
        except OSError as err:
            raise HciError(f"Unable to open {self.adapter} raw HCI socket: {err}") from err
        self._reader = asyncio.create_task(self._reader_loop(), name=f"miot-{self.adapter}-events")
        self._worker = asyncio.create_task(self._command_loop(), name=f"miot-{self.adapter}-commands")
        try:
            response = await self._command(HCI_VENDOR_CAPABILITIES)
            self.capabilities = decode_capabilities(response)
        except BaseException as err:
            self._fail(HciError(f"Vendor advertising initialization failed: {err}"))
            await self._join_tasks()
            if isinstance(err, HciCommandError) and err.status in (0x01, 0x11):
                raise HciUnsupportedError("Controller does not implement Android vendor advertising") from err
            raise
        return self.capabilities

    async def _command(
        self, opcode: int, payload: bytes = b"", subcommand: int | None = None,
        *, stopping_cleanup: bool = False,
    ) -> bytes:
        if self._failure is not None:
            raise self._failure
        if self._socket is None or (self._stopping and not stopping_cleanup):
            raise HciError("HCI transport is not running")
        if len(payload) > 255:
            raise ValueError("HCI command payload exceeds 255 bytes")
        result = asyncio.get_running_loop().create_future()
        command = _Command(opcode, payload, subcommand, result)
        try:
            self._queue.put_nowait(command)
        except asyncio.QueueFull as err:
            raise HciQueueFullError("HCI command queue is full") from err
        return await result

    async def _command_loop(self) -> None:
        while True:
            command = await self._queue.get()
            try:
                if command.result.cancelled():
                    continue
                self._pending = command
                self._reply = asyncio.get_running_loop().create_future()
                packet = struct.pack("<BHB", _COMMAND_PACKET, command.opcode, len(command.payload)) + command.payload
                try:
                    await self._async_send(packet)
                    reply = await asyncio.wait_for(self._reply, timeout=self._command_timeout)
                except TimeoutError:
                    error = HciError(f"HCI command 0x{command.opcode:04X} timed out; transport closed")
                    if not command.result.done():
                        command.result.set_exception(error)
                    self._fail(error)
                    return
                except OSError as err:
                    error = HciError(f"HCI command transport failed: {err}")
                    if not command.result.done():
                        command.result.set_exception(error)
                    self._fail(error)
                    return
                if not command.result.done():
                    if reply.status:
                        command.result.set_exception(HciCommandError(command.opcode, reply.status))
                    else:
                        command.result.set_result(reply.data)
            finally:
                self._pending = None
                self._reply = None
                self._queue.task_done()

    async def _reader_loop(self) -> None:
        try:
            while True:
                packet = await self._async_receive()
                if not packet:
                    raise OSError("HCI socket closed")
                event = parse_hci_event(packet)
                if isinstance(event, CommandEvent):
                    command = self._pending
                    if command is None or self._reply is None or self._reply.done() or event.opcode != command.opcode:
                        continue
                    if not event.complete and event.status == 0:
                        continue
                    if event.complete and command.subcommand is not None:
                        if event.data and event.data[0] != command.subcommand:
                            continue
                        if not event.status and not event.data:
                            continue
                    self._reply.set_result(event)
                elif isinstance(event, BluetoothEvent):
                    self._dispatch_event(event)
        except asyncio.CancelledError:
            raise
        except OSError as err:
            self._fail(HciError(f"HCI event transport failed: {err}"))

    def _dispatch_event(self, event: BluetoothEvent) -> None:
        instance = event.instance
        if event.kind == "advertising" and instance in self._instances:
            if event.handle is not None:
                self._handle_instances[event.handle] = instance
            if event.state == 0:
                self._enabled.discard(instance)
        elif event.kind == "connected" and event.status == 0 and event.role == 1:
            candidates = [slot for slot in self._enabled if self._instances[slot].connectable]
            if len(candidates) == 1:
                instance = candidates[0]
                self._handle_instances[event.handle] = instance
        elif event.kind == "disconnected" and event.status == 0:
            instance = self._handle_instances.pop(event.handle, None)
        if instance is not None and event.instance is None:
            event = BluetoothEvent(
                event.kind, instance, event.handle, event.address, event.address_type,
                event.role, event.status, event.state, event.reason,
            )
        if self._event_callback is not None:
            try:
                self._event_callback(event)
            except Exception:
                _LOGGER.exception("Bluetooth event callback failed")

    def _fail(self, error: HciError) -> None:
        if self._failure is None:
            self._failure = error
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._pending is not None and not self._pending.result.done():
            self._pending.result.set_exception(error)
        while not self._queue.empty():
            command = self._queue.get_nowait()
            if not command.result.done():
                command.result.set_exception(error)
            self._queue.task_done()
        current = asyncio.current_task()
        for task in (self._reader, self._worker):
            if task is not None and task is not current:
                task.cancel()

    async def _join_tasks(self) -> None:
        tasks = [task for task in (self._reader, self._worker) if task is not None]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._reader = None
        self._worker = None

    def _require_instance(self, instance: int) -> None:
        if self.capabilities is None or instance not in self.capabilities.usable_instances:
            raise HciUnsupportedError(f"Advertising instance {instance} is unavailable")

    async def async_configure(
        self, instance: int, mac: str, connectable: bool, interval_ms: float = 100,
        tx_power: int = 0,
    ) -> None:
        self._require_instance(instance)
        parameters = advertising_parameters(instance, mac, connectable, interval_ms, tx_power)
        normalized_mac = mac.upper()
        if any(slot != instance and config.mac == normalized_mac for slot, config in self._instances.items()):
            raise ValueError("Virtual devices must have distinct Bluetooth addresses")
        self._instances[instance] = _Instance(normalized_mac, connectable)
        await self.async_disable(instance)
        await self._command(HCI_VENDOR_MULTI_ADVERTISEMENT, parameters, 0x01)
        await self._command(HCI_VENDOR_MULTI_ADVERTISEMENT, b"\x04" + _address_bytes(mac) + bytes((instance,)), 0x04)

    async def async_set_data(self, instance: int, data: bytes, scan_response: bytes = b"") -> None:
        self._require_instance(instance)
        config = self._instances.get(instance)
        if config is None:
            raise HciError("Advertising instance must be configured before setting data")
        payload = advertising_data(instance, data)
        scan_payload = advertising_data(instance, scan_response, scan_response=True)
        await self._command(HCI_VENDOR_MULTI_ADVERTISEMENT, payload, 0x02)
        if config.scan_response != scan_response:
            await self._command(HCI_VENDOR_MULTI_ADVERTISEMENT, scan_payload, 0x03)
            config.scan_response = scan_response

    async def async_enable(self, instance: int) -> None:
        self._require_instance(instance)
        if instance not in self._instances:
            raise HciError("Advertising instance must be configured before enabling it")
        async with self._enable_lock:
            if self._instances[instance].connectable and any(
                slot != instance and self._instances[slot].connectable for slot in self._enabled
            ):
                raise HciError("Only one bridge device may be connectable at a time")
            await self._command(HCI_VENDOR_MULTI_ADVERTISEMENT, bytes((0x05, 0x01, instance)), 0x05)
            self._enabled.add(instance)

    async def async_disable(self, instance: int) -> None:
        self._require_instance(instance)
        if instance not in self._instances:
            raise HciError("Cannot disable an advertising instance not owned by this bridge")
        await self._command(
            HCI_VENDOR_MULTI_ADVERTISEMENT, bytes((0x05, 0x00, instance)), 0x05,
            stopping_cleanup=self._stopping,
        )
        self._enabled.discard(instance)

    async def async_stop(self) -> None:
        self._stopping = True
        first_error = None
        try:
            if self._socket is not None and self._failure is None:
                for instance in sorted(self._instances):
                    try:
                        await self.async_disable(instance)
                    except HciError as err:
                        first_error = first_error or err
                        _LOGGER.warning("Unable to disable bridge advertising instance %s: %s", instance, err)
        finally:
            self._fail(HciError("HCI transport stopped"))
            await self._join_tasks()
            self._enabled.clear()
            self._handle_instances.clear()
        if first_error is not None:
            raise first_error
