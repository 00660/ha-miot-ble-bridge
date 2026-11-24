"""Device properties and wire codecs ported from the upstream device examples.

Source revision: e9058f09ad2b1040d8a79d6aa2a7fb79767892a1.
The upstream miot-ble-sdk Non-Commercial License applies to this derived port.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import struct
from typing import Any, Literal, Mapping

DEFAULT_MODEL = "xiaomi.sensor_occupy.03"

BOOL, U8, I8, U16, I16, U32, I32, U64, I64, FLOAT, STRING = range(11)
_FORMATS = {BOOL: "B", U8: "B", I8: "b", U16: "H", I16: "h", U32: "I", I32: "i", U64: "Q", I64: "q", FLOAT: "f"}
_BEACON_TYPES = {"bool": BOOL, "u8": U8, "i8": I8, "u16": U16, "i16": I16, "u32": U32, "i32": I32, "u64": U64, "i64": I64, "f32": FLOAT}


def _finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and (not isinstance(value, float) or math.isfinite(value))


def _primitive(type_code: int, value: Any) -> bytes:
    if type_code == STRING:
        if not isinstance(value, str):
            raise ValueError("String property requires text")
        return value.encode("utf-8")
    if type_code not in _FORMATS:
        raise ValueError("Unknown MIoT scalar type")
    if type_code == BOOL:
        if value not in (False, True, 0, 1):
            raise ValueError("Boolean property requires true or false")
        value = int(value)
    elif type_code == FLOAT:
        if not _finite_number(value):
            raise ValueError("Float property requires a finite number")
    else:
        if not _finite_number(value) or value != int(value):
            raise ValueError("Integer property requires an integral number")
        value = int(value)
    try:
        return struct.pack("<" + _FORMATS[type_code], value)
    except (struct.error, OverflowError) as error:
        raise ValueError("MIoT scalar is outside its wire range") from error


@dataclass(frozen=True, slots=True)
class PropertyDefinition:
    name: str
    siid: int
    piid: int
    type_code: int
    default: Any
    writable: bool = False
    minimum: int | float | None = None
    maximum: int | float | None = None
    step: int | float | None = None
    choices: tuple[tuple[Any, str], ...] = ()
    unit: str | None = None
    entity_domains: tuple[str, ...] = ("sensor", "number", "input_number")
    semantic: str | None = None
    derived: Literal["present_minutes", "absent_minutes", "unix_time"] | None = None
    spec_visible: bool = True
    alias_of: str | None = None
    notify: bool = True

    @property
    def key(self) -> str:
        return f"{self.siid}.{self.piid}"

    def validate(self, value: Any) -> Any:
        _primitive(self.type_code, value)
        if self.type_code == BOOL:
            value = bool(value)
        elif self.type_code == FLOAT:
            value = float(value)
        elif self.type_code != STRING:
            value = int(value)
        if self.minimum is not None and value < self.minimum:
            raise ValueError(f"{self.key} is below its minimum")
        if self.maximum is not None and value > self.maximum:
            raise ValueError(f"{self.key} is above its maximum")
        if self.choices and value not in {choice for choice, _ in self.choices}:
            raise ValueError(f"{self.key} is not a supported choice")
        if self.step is not None:
            offset = (value - (self.minimum or 0)) / self.step
            nearest = round(offset)
            quantized = (self.minimum or 0) + nearest * self.step
            if self.type_code == FLOAT:
                # A legal decimal step acquires one float32 ULP on the wire.
                exponent = math.frexp(abs(value))[1]
                tolerance = max(self.step * 1e-6, 2 * math.ldexp(1, max(-149, exponent - 24)))
                valid = math.isclose(value, quantized, rel_tol=0, abs_tol=tolerance)
            else:
                valid = math.isclose(offset, nearest, rel_tol=0, abs_tol=1e-6)
            if not valid:
                raise ValueError(f"{self.key} does not match its step")
            if self.type_code == FLOAT:
                value = float(quantized)
        return value

    def encode(self, value: Any) -> bytes:
        return _primitive(self.type_code, self.validate(value))


def _beacon_payload(encoding: str, value: Any, scale: float = 1) -> bytes:
    if not _finite_number(value):
        raise ValueError("Beacon value requires a finite number")
    value *= scale
    if encoding == "u24":
        if value != int(value) or not 0 <= value <= 0xFFFFFF:
            raise ValueError("Beacon value is outside its unsigned 24-bit range")
        payload = int(value).to_bytes(3, "little")
    else:
        type_code = _BEACON_TYPES.get(encoding)
        if type_code is None:
            raise ValueError("Unknown beacon codec")
        if type_code not in (BOOL, FLOAT) and scale != 1:
            # The sensor examples store tenths/hundredths in integral objects.
            rounded = round(value)
            if not math.isclose(value, rounded, rel_tol=0, abs_tol=1e-6):
                raise ValueError("Beacon value exceeds the codec precision")
            value = rounded
        payload = _primitive(type_code, value)
    if len(payload) > 9:
        raise ValueError("Beacon payload exceeds the legacy advertising budget")
    return payload


@dataclass(frozen=True, slots=True)
class BeaconDefinition:
    object_id: int
    property_key: str
    encoding: str = "u8"
    scale: float = 1
    property_keys: tuple[str, ...] = ()

    def encode(self, value: Any) -> bytes:
        if self.property_keys:
            raise ValueError("Compound beacon requires a property snapshot")
        if self.encoding == "light_degree":
            if value not in (1, 2):
                raise ValueError("Light degree requires the model enum 1 or 2")
            return _beacon_payload("u8", value - 1)
        return _beacon_payload(self.encoding, value, self.scale)

    def encode_values(self, values: Mapping[str, Any]) -> bytes:
        if self.encoding == "temp_humidity" and len(self.property_keys) == 2:
            temperature, humidity = (values[key] for key in self.property_keys)
            return _beacon_payload("i16", temperature, 10) + _beacon_payload("u16", humidity, 10)
        if self.encoding == "motion_light" and len(self.property_keys) == 2:
            presence, degree = (values[key] for key in self.property_keys)
            return _beacon_payload("bool", presence) + BeaconDefinition(0, "", "light_degree").encode(degree) + b"\x00"
        if self.property_keys:
            raise ValueError("Unknown compound beacon codec")
        return self.encode(values[self.property_key])


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    key: str
    name: str
    siid: int
    aiid: int
    input_keys: tuple[str, ...] = ()
    output_keys: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EventDefinition:
    key: str
    name: str
    siid: int
    eiid: int
    argument_keys: tuple[str, ...] = ()
    beacon_id: int | None = None
    codec: str | None = None
    beacon_keys: tuple[str, ...] = ()

    def encode(self, arguments: Mapping[str, Any]) -> bytes:
        if self.beacon_id is None:
            return b""
        if self.codec == "single_button":
            return b"\x01"
        if self.codec == "empty":
            return b""
        if self.codec == "motion_light_event":
            degree = arguments["2.1"]
            return b"\x01" + BeaconDefinition(0, "", "light_degree").encode(degree) + b"\x00"
        if len(self.argument_keys) != 1 or self.codec is None:
            raise ValueError("Event requires a defined beacon codec")
        return _beacon_payload(self.codec, arguments[self.argument_keys[0]])


@dataclass(frozen=True, slots=True)
class ModelDefinition:
    model: str
    name: str
    pid: int
    properties: tuple[PropertyDefinition, ...] = ()
    beacons: tuple[BeaconDefinition, ...] = ()
    actions: tuple[ActionDefinition, ...] = ()
    events: tuple[EventDefinition, ...] = ()
    gatt_strategy: Literal["fixed_control", "prefer_source"] = "fixed_control"
    auth_mode: Literal["standard", "standard_nus", "psk"] = "standard"
    connectable: bool = False
    available: bool = True
    unavailable_reason: str | None = None
    limitations: tuple[str, ...] = ()
    source_dir: str = ""

    @property
    def property_by_key(self) -> dict[str, PropertyDefinition]:
        return {prop.key: prop for prop in self.properties}

    @property
    def beacon_by_id(self) -> dict[int, BeaconDefinition]:
        return {beacon.object_id: beacon for beacon in self.beacons}


_BINARY_DOMAINS = ("binary_sensor", "sensor", "switch", "input_boolean")
_CHOICE_DOMAINS = ("sensor", "select", "input_select", "number", "input_number")
_LIGHT_DOMAINS = ("light", "number", "input_number", "sensor")


def _p(siid: int, piid: int, name: str, type_code: int, default: Any, **kwargs: Any) -> PropertyDefinition:
    if "entity_domains" not in kwargs:
        if type_code == BOOL:
            kwargs["entity_domains"] = _BINARY_DOMAINS
        elif type_code == STRING:
            kwargs["entity_domains"] = ("sensor", "text", "input_text")
        elif kwargs.get("choices"):
            kwargs["entity_domains"] = _CHOICE_DOMAINS
    return PropertyDefinition(name, siid, piid, type_code, default, **kwargs)


_OCCUPANCY = ModelDefinition(
    DEFAULT_MODEL, "米家人体存在传感器", 0x4683,
    properties=(
        _p(2, 1078, "存在状态", U8, 0, choices=((0, "无人"), (1, "有人"), (2, "快检中")), entity_domains=_BINARY_DOMAINS, semantic="presence"),
        _p(2, 1005, "光照", FLOAT, 0.0, minimum=0, maximum=1000, step=1, unit="lx", semantic="illuminance"),
        _p(2, 1082, "无人时长", U8, 2, choices=((2, "2 分钟"), (5, "5 分钟"), (10, "10 分钟"), (30, "30 分钟")), unit="min", derived="absent_minutes"),
        _p(2, 1081, "有人时长", U8, 2, choices=((2, "2 分钟"), (5, "5 分钟")), unit="min", derived="present_minutes"),
        _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, unit="%", semantic="battery"),
    ),
    beacons=(
        BeaconDefinition(0x484E, "2.1078"), BeaconDefinition(0x4805, "2.1005", "f32"),
        BeaconDefinition(0x4852, "2.1082"), BeaconDefinition(0x4851, "2.1081"),
        BeaconDefinition(0x100A, "3.1003"),
    ),
    gatt_strategy="fixed_control", source_dir="esp32/occ_adv",
)

_CARLIGHT = ModelDefinition(
    "careco.nlight.o654", "小米汽车磁吸补光灯", 0x6266,
    properties=(
        _p(5, 1003, "电量", U8, 100, minimum=0, maximum=100, unit="%", semantic="battery"),
        _p(5, 1, "充电状态", U8, 1, choices=((0, "充电中"), (1, "未充电")), semantic="charging"),
        _p(7, 1, "灯光开关", BOOL, False, writable=True, entity_domains=_BINARY_DOMAINS + ("light",), semantic="on"),
        _p(7, 2, "亮度", U8, 50, writable=True, minimum=1, maximum=100, step=1, unit="%", entity_domains=_LIGHT_DOMAINS, semantic="brightness"),
        _p(7, 3, "色温", U16, 3900, writable=True, minimum=2700, maximum=5000, step=1, unit="K", entity_domains=_LIGHT_DOMAINS, semantic="color_temp"),
        _p(7, 4, "灯光模式", U8, 0, writable=True, choices=((0, "自定义"), (1, "前排补光"), (2, "置物格"), (3, "暖光"), (4, "夜灯")), semantic="mode"),
        _p(8, 1, "设备模式", U8, 2, writable=True, choices=((0, "关闭"), (1, "自动"), (2, "开启")), semantic="device_mode"),
        _p(8, 2, "设备状态信息", STRING, "", semantic="internal_placeholder", notify=False),
        _p(9, 1, "设备时间", U32, 0, writable=True, unit="s", derived="unix_time", semantic="time"),
    ),
    beacons=(BeaconDefinition(0x0701, "7.1", "bool"),),
    gatt_strategy="prefer_source", connectable=True, source_dir="esp32/carlight_adv",
)

_COOLER = ModelDefinition(
    "xiaomi.cooler.r02p", "小米磁吸散热背夹", 0x52AA,
    properties=(
        _p(3, 1, "散热模式", U8, 0, writable=True, choices=((0, "智能"), (1, "极寒")), semantic="mode"),
        _p(3, 2, "极限模式", BOOL, False, writable=True, semantic="extreme_limit"),
        _p(3, 3, "温度", I8, 25, minimum=-30, maximum=80, step=1, unit="°C", semantic="temperature"),
        _p(4, 1, "灯光开关", BOOL, True, writable=True, entity_domains=_BINARY_DOMAINS + ("light",), semantic="on"),
        _p(4, 2, "灯光模式", U8, 0, writable=True, choices=((0, "彩虹"), (1, "呼吸"), (2, "流光"), (3, "明亮")), semantic="light_mode"),
        _p(4, 3, "灯光颜色", U32, 0x00FF00, writable=True, minimum=0, maximum=0xFFFFFF, step=1, entity_domains=_LIGHT_DOMAINS, semantic="color"),
        _p(4, 4, "流光速度", U8, 1, writable=True, choices=((0, "1 档"), (1, "2 档"), (2, "3 档")), semantic="flow_speed"),
        _p(4, 5, "颜色组合", U8, 0, writable=True, choices=((0, "全彩"), (1, "三色"), (2, "单色")), semantic="color_combination"),
        _p(4, 6, "颜色一", U32, 0xFF0000, writable=True, minimum=0, maximum=0xFFFFFF, step=1, entity_domains=_LIGHT_DOMAINS, semantic="color"),
        _p(4, 7, "颜色二", U32, 0x00FF00, writable=True, minimum=0, maximum=0xFFFFFF, step=1, entity_domains=_LIGHT_DOMAINS, semantic="color"),
        _p(4, 8, "颜色三", U32, 0x0000FF, writable=True, minimum=0, maximum=0xFFFFFF, step=1, entity_domains=_LIGHT_DOMAINS, semantic="color"),
        _p(5, 1, "延时开关", BOOL, False, writable=True, semantic="delay"),
        _p(5, 2, "延时时长", U16, 0, writable=True, minimum=0, maximum=359, step=1, unit="min", semantic="delay_time"),
        _p(6, 1, "高亮开关", BOOL, True, writable=True, semantic="highlights"),
    ),
    beacons=(
        BeaconDefinition(0x4C01, "3.1"), BeaconDefinition(0x5001, "4.1", "bool"),
        BeaconDefinition(0x5002, "4.2"), BeaconDefinition(0x4C03, "3.3", "i8"),
    ),
    actions=(ActionDefinition("4.1", "重置颜色", 4, 1),),
    gatt_strategy="prefer_source", connectable=True, source_dir="esp32/cooler_adv",
)

_SENSOR_MODELS = (
    ModelDefinition(
        "miaomiaoce.sensor_ht.t2", "米家蓝牙温湿度计 2", 0x055B,
        properties=(
            _p(2, 1, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature"),
            _p(2, 2, "湿度", FLOAT, 58.0, minimum=0, maximum=100, step=0.1, unit="%", semantic="humidity"),
            _p(2, 3, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
            _p(2, 1001, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature", alias_of="2.1", notify=False),
            _p(3, 1001, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature", alias_of="2.1", notify=False),
            _p(3, 1, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature", alias_of="2.1", notify=False),
            _p(2, 1008, "湿度", FLOAT, 58.0, minimum=0, maximum=100, step=0.1, unit="%", semantic="humidity", alias_of="2.2", notify=False),
            _p(2, 1002, "湿度", FLOAT, 58.0, minimum=0, maximum=100, step=0.1, unit="%", semantic="humidity", alias_of="2.2", notify=False),
            _p(3, 1002, "湿度", U8, 58, minimum=0, maximum=100, step=1, unit="%", semantic="humidity", alias_of="2.2", notify=False),
            _p(2, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery", alias_of="2.3", notify=False),
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery", alias_of="2.3", notify=False),
        ),
        beacons=(BeaconDefinition(0x1004, "2.1", "i16", 10), BeaconDefinition(0x1006, "2.2", "u16", 10), BeaconDefinition(0x100A, "2.3")),
        connectable=True, source_dir="esp32/thermo_gatt",
    ),
    ModelDefinition(
        "yuemee.airmonitor.mhfd1", "米家甲醛检测仪", 0x02DF,
        properties=(
            _p(2, 3, "甲醛浓度", FLOAT, 0.08, minimum=0, maximum=2, step=0.01, unit="mg/m³", semantic="formaldehyde"),
            _p(2, 2, "温度", FLOAT, 23.5, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature"),
            _p(2, 1, "湿度", FLOAT, 45.6, minimum=0, maximum=100, step=0.1, unit="%", semantic="humidity"),
            _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x1010, "2.3", "u16", 100), BeaconDefinition(0x1004, "2.2", "i16", 10), BeaconDefinition(0x1006, "2.1", "u16", 10), BeaconDefinition(0x100A, "3.1")),
        source_dir="esp32/hcho_adv",
    ),
    ModelDefinition(
        "isa.magnet.dw2hl", "米家门窗传感器 2", 0x098B,
        properties=(
            _p(2, 2, "开合状态（0 开门，1 关门）", BOOL, True, semantic="contact"),
            _p(2, 1, "光线强弱", U8, 2, choices=((1, "暗"), (2, "亮")), entity_domains=_BINARY_DOMAINS + _CHOICE_DOMAINS, semantic="light_degree"),
            _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x1019, "2.2", "bool"), BeaconDefinition(0x1018, "2.1", "light_degree"), BeaconDefinition(0x100A, "3.1")),
        source_dir="esp32/door_adv",
    ),
    ModelDefinition(
        "xiaomi.magnet.03", "米家门窗传感器 3", 0x8C05,
        properties=(
            _p(2, 1012, "开合状态（0 开门，1 关门）", BOOL, True, semantic="contact"),
            _p(3, 1107, "电量状态", U8, 0, choices=((0, "充足"), (1, "不足")), semantic="battery_status"),
        ),
        beacons=(BeaconDefinition(0x480C, "2.1012", "bool"), BeaconDefinition(0x4C6B, "3.1107")),
        source_dir="esp32/door3_adv",
    ),
    ModelDefinition(
        "lumi.motion.bmgl01", "米家人体传感器 2", 0x0A8D,
        properties=(
            _p(0, 1, "移动状态", BOOL, False, semantic="presence", spec_visible=False),
            _p(2, 1, "光线强弱", U8, 2, choices=((1, "暗"), (2, "亮")), entity_domains=_BINARY_DOMAINS + _CHOICE_DOMAINS, semantic="light_degree"),
            _p(2, 2, "无人时长", U16, 2, choices=((2, "2 分钟"), (5, "5 分钟")), unit="min", derived="absent_minutes"),
            _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(
            BeaconDefinition(0x000F, "0.1", "motion_light", property_keys=("0.1", "2.1")),
            BeaconDefinition(0x1017, "2.2", "u32", 60), BeaconDefinition(0x100A, "3.1"),
        ),
        events=(EventDefinition("2.e.1", "有人移动", 2, 1, beacon_id=0x000F, codec="motion_light_event", beacon_keys=("2.1",)),),
        source_dir="esp32/motion_adv",
    ),
    ModelDefinition(
        "xiaomi.motion.pir1", "米家人体传感器 2S", 0x3531,
        properties=(
            _p(2, 1005, "光照", FLOAT, 50.0, minimum=0, maximum=1000, step=0.1, unit="lx", semantic="illuminance"),
            _p(2, 1024, "无人时长", U16, 120, minimum=0, maximum=1800, step=1, unit="s", semantic="no_motion_duration"),
            _p(2, 1053, "无人时长设置", U16, 2, minimum=1, maximum=30, step=1, unit="min", semantic="no_motion_time_set"),
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x4805, "2.1005", "f32"), BeaconDefinition(0x4818, "2.1024", "u16"), BeaconDefinition(0x4835, "2.1053", "u16"), BeaconDefinition(0x100A, "3.1003")),
        events=(EventDefinition("2.e.1008", "有人移动", 2, 1008, ("2.1005",), 0x4A08, "f32"),),
        limitations=("绑定期间需要保持请求配对广播。",), source_dir="esp32/pir2s_adv",
    ),
    ModelDefinition(
        "lumi.flood.bmcn01", "米家水浸传感器", 0x0863,
        properties=(
            _p(2, 1, "漏水状态", BOOL, False, semantic="moisture"),
            _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x1014, "2.1", "bool"), BeaconDefinition(0x100A, "3.1")),
        source_dir="esp32/leak_adv",
    ),
    ModelDefinition(
        "xiaomi.sensor_ht.mini", "米家温湿度计 3 mini", 0x55B5,
        properties=(
            _p(2, 1001, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature"),
            _p(2, 1002, "湿度", U8, 58, minimum=0, maximum=100, step=1, unit="%", semantic="humidity"),
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x4C01, "2.1001", "f32"), BeaconDefinition(0x4C02, "2.1002"), BeaconDefinition(0x4803, "3.1003")),
        limitations=("仅使用国区 PID 0x55B5，海外 0x5BEA 不能替代。",), source_dir="examples/thermo_t3m",
    ),
    ModelDefinition(
        "xiaomi.sensor_ht.new3pr", "米家温湿度计 3 Pro", 0x9AB9,
        properties=(
            _p(7, 1001, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature"),
            _p(7, 1002, "湿度", U8, 58, minimum=0, maximum=100, step=1, unit="%", semantic="humidity"),
            _p(8, 1029, "二氧化碳浓度", U16, 480, minimum=400, maximum=5000, step=1, unit="ppm", semantic="carbon_dioxide"),
            _p(4, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x5C01, "7.1001", "f32"), BeaconDefinition(0x5C02, "7.1002"), BeaconDefinition(0x601D, "8.1029", "u16"), BeaconDefinition(0x4803, "4.1003")),
        limitations=("真机日常使用广播，只在按键唤醒后供手机连接。",), source_dir="esp32/t3pro_adv",
    ),
    ModelDefinition(
        "mirsz.sensor_gas.ga500", "米家燃气传感器", 0x392D,
        properties=(_p(2, 1011, "燃气浓度", FLOAT, 2.5, minimum=1, maximum=100, unit="%", semantic="gas_concentration"),),
        beacons=(BeaconDefinition(0x480B, "2.1011", "f32"),), source_dir="esp32/gas_adv",
    ),
    ModelDefinition(
        "mirsz.sensor_smoke.s500", "米家烟雾传感器", 0x392E,
        properties=(_p(2, 1043, "烟雾告警", BOOL, False, semantic="smoke"),),
        beacons=(BeaconDefinition(0x482B, "2.1043", "bool"),), source_dir="esp32/smoke_adv",
    ),
    ModelDefinition(
        "xiaomi.pet_waterer.002", "米家无线宠物饮水机", 0x399A,
        properties=(
            _p(2, 1067, "缺水状态", BOOL, False, semantic="water_shortage"),
            _p(3, 1076, "滤芯余量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="filter_life"),
            _p(5, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x4843, "2.1067", "bool"), BeaconDefinition(0x4C4C, "3.1076"), BeaconDefinition(0x5403, "5.1003")),
        source_dir="esp32/petwater_adv",
    ),
    ModelDefinition(
        "yeelink.light.nl1", "米家夜灯 2 蓝牙版", 0x07F6,
        properties=(
            _p(2, 1, "无人时长", U16, 60, minimum=0, maximum=65535, step=1, unit="s", semantic="no_motion_duration"),
            _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
            _p(4, 1, "光照", FLOAT, 120.0, minimum=0, maximum=10000, unit="lx", semantic="illuminance"),
        ),
        beacons=(BeaconDefinition(0x1017, "2.1", "u32"),), source_dir="esp32/nl1_adv",
    ),
    ModelDefinition(
        "linp.senpres.ps1bb", "领普压力有无传感器", 0x3F4C,
        properties=(
            _p(2, 1060, "压力状态", BOOL, False, semantic="pressure"),
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x483C, "2.1060", "bool"), BeaconDefinition(0x4C03, "3.1003")),
        source_dir="esp32/senpres_adv",
    ),
    ModelDefinition(
        "hhcc.plantmonitor.v1", "花花草草监测仪", 0x0098,
        properties=(
            _p(2, 1, "土壤湿度", FLOAT, 45.0, minimum=0, maximum=100, step=1, unit="%", semantic="moisture"),
            _p(2, 2, "土壤肥力", U16, 480, minimum=0, maximum=5000, step=1, unit="µS/cm", semantic="conductivity"),
            _p(2, 3, "光照", FLOAT, 320.0, minimum=0, maximum=10000, step=1, unit="lx", semantic="illuminance"),
            _p(3, 2, "空气温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature"),
        ),
        beacons=(BeaconDefinition(0x1004, "3.2", "i16", 10), BeaconDefinition(0x1008, "2.1"), BeaconDefinition(0x1007, "2.3", "u24"), BeaconDefinition(0x1009, "2.2", "u16")),
        source_dir="esp32/plant_adv",
    ),
    ModelDefinition(
        "shuse.airm.ss006", "树色空气检测仪", 0x6651,
        properties=(
            _p(3, 1001, "温度", FLOAT, 25.6, minimum=-30, maximum=100, step=0.1, unit="°C", semantic="temperature"),
            _p(3, 1008, "湿度", FLOAT, 55.0, minimum=0, maximum=100, unit="%", semantic="humidity"),
            _p(3, 1028, "空气质量指数", U16, 42, minimum=0, maximum=500, step=1, semantic="aqi"),
            _p(3, 1031, "挥发性有机物", FLOAT, 0.12, minimum=0, maximum=2, unit="mg/m³", semantic="tvoc"),
            _p(3, 1029, "二氧化碳浓度", U16, 520, minimum=0, maximum=8000, step=1, unit="ppm", semantic="carbon_dioxide"),
            _p(3, 1030, "甲醛浓度", FLOAT, 0.03, minimum=0, maximum=2, unit="mg/m³", semantic="formaldehyde"),
        ),
        beacons=(BeaconDefinition(0x4C01, "3.1001", "f32"), BeaconDefinition(0x4C08, "3.1008", "f32"), BeaconDefinition(0x4C1C, "3.1028", "u16"), BeaconDefinition(0x4C1F, "3.1031", "f32"), BeaconDefinition(0x4C1D, "3.1029", "u16"), BeaconDefinition(0x4C1E, "3.1030", "f32")),
        source_dir="esp32/airm_adv",
    ),
    ModelDefinition(
        "xiaomi.sensor_smoke.yg2", "米家烟感卫士 2", 0x7ABA,
        properties=(
            _p(2, 1004, "烟感状态", U8, 1, choices=((1, "正常"), (2, "烟雾告警"), (4, "设备故障"), (5, "烟室积灰"), (6, "温度过高")), entity_domains=_BINARY_DOMAINS + _CHOICE_DOMAINS, semantic="smoke_status"),
            _p(6, 1132, "电量状态", U8, 0, choices=((0, "充足"), (1, "不足")), semantic="battery_status"),
            _p(2, 1001, "温度", FLOAT, 25.0, minimum=-40, maximum=85, step=0.1, unit="°C", semantic="temperature"),
        ),
        beacons=(BeaconDefinition(0x4804, "2.1004"), BeaconDefinition(0x5884, "6.1132"), BeaconDefinition(0x4801, "2.1001", "f32")),
        source_dir="esp32/smoke2_adv",
    ),
    ModelDefinition(
        "xiaomi.flood.oh83w", "米家水浸卫士 2", 0x6375,
        properties=(
            _p(2, 1006, "浸水状态", BOOL, False, semantic="moisture"),
            _p(2, 1123, "淋水状态", BOOL, False, semantic="moisture_top"),
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        ),
        beacons=(BeaconDefinition(0x4806, "2.1006", "bool"), BeaconDefinition(0x487B, "2.1123", "bool"), BeaconDefinition(0x4C03, "3.1003")),
        source_dir="esp32/flood2_adv",
    ),
    ModelDefinition(
        "soocare.toothbrush.1501", "米家声波电动牙刷 T501", 0x1FF3,
        properties=(
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
            _p(3, 1034, "充电状态", U8, 2, choices=((0, "充电中"), (1, "未充电"), (2, "已充满"), (3, "异常")), semantic="charging"),
            _p(4, 1041, "刷头剩余天数", U8, 120, minimum=0, maximum=180, step=1, unit="d", semantic="brush_head_life"),
        ),
        beacons=(BeaconDefinition(0x4C03, "3.1003"), BeaconDefinition(0x4C22, "3.1034"), BeaconDefinition(0x5029, "4.1041", "u16")),
        source_dir="esp32/toothbrush_adv",
    ),
    ModelDefinition(
        "xiaomi.toothbrush.24p", "米家伺服扫振电动牙刷 Pro", 0x6800,
        properties=(
            _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
            _p(3, 1034, "充电状态", U8, 2, choices=((0, "未充电"), (1, "充电中"), (2, "已充满")), semantic="charging"),
            _p(4, 1041, "刷头余量", U8, 80, minimum=0, maximum=100, step=1, unit="%", semantic="brush_head_life"),
        ),
        beacons=(BeaconDefinition(0x4C03, "3.1003"), BeaconDefinition(0x4C22, "3.1034"), BeaconDefinition(0x5029, "4.1041", "u16")),
        source_dir="esp32/brushpro_adv",
    ),
)


def _button_model(model: str, name: str, pid: int, source_dir: str, *, keys: int, event_siid: int, event_base: int, low_battery: bool = False) -> ModelDefinition:
    properties = (
        _p(3, 1020, "按键模式", U16, 1, writable=True, minimum=0, maximum=65535, step=1, semantic="button_mode"),
        _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
    )
    if low_battery:
        properties = properties[1:] + (
            _p(3, 1004, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery", alias_of="3.1003", notify=False),
            _p(3, 1005, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery", alias_of="3.1003", notify=False),
        )
    argument_keys = ()
    codec = "single_button"
    if keys > 1:
        argument_keys = (f"{event_siid}.1",)
        labels = {1: "左键", 2: "右键", 3: "左右键同时"} if keys == 2 else {key: f"按键 {key}" for key in range(1, keys + 1)}
        properties += (_p(event_siid, 1, "键位", U8, 1, choices=tuple(labels.items()), semantic="button_key"),)
        codec = "u8"
    events = tuple(
        EventDefinition(f"{event_siid}.e.{eiid}", label, event_siid, eiid, argument_keys, event_base + index, codec)
        for index, (eiid, label) in enumerate(((1012, "单击"), (1013, "双击"), (1014, "长按")))
    )
    if low_battery:
        events += (EventDefinition("3.e.1001", "低电量", 3, 1001, beacon_id=0x4C01, codec="single_button"),)
    return ModelDefinition(model, name, pid, properties, (BeaconDefinition(0x100A, "3.1003"),), events=events, source_dir=source_dir)


_BUTTON_MODELS = (
    _button_model("yeelink.remote.contrl", "米家无线开关（双键）", 0x1949, "esp32/btn2_adv", keys=2, event_siid=3, event_base=0x4E0C),
    _button_model("lumi.remote.mcn001", "米家无线开关（单键）", 0x2387, "esp32/btn1_adv", keys=1, event_siid=3, event_base=0x4E0C),
    _button_model("giot.remote.v58kwm", "V5 无线八键开关", 0x3F3A, "esp32/v5kwm_adv", keys=8, event_siid=2, event_base=0x4A0C),
    _button_model("090615.remote.btsw1", "PTX 无线开关", 0x38BB, "esp32/ptxsw1_adv", keys=1, event_siid=2, event_base=0x4E0C, low_battery=True),
)

_NIGHT_LIGHT = ModelDefinition(
    "MUE4094RT", "米家夜灯 2", 0x03DD,
    properties=(
        _p(2, 1, "亮度", U8, 60, writable=True, minimum=0, maximum=100, step=1, unit="%", entity_domains=_LIGHT_DOMAINS, semantic="brightness"),
        _p(2, 2, "亮灯时长", U32, 25000, writable=True, minimum=5000, maximum=60000, step=1, unit="ms", semantic="delay_time"),
        _p(2, 3, "开关", BOOL, True, writable=True, entity_domains=_BINARY_DOMAINS + ("light",), semantic="on"),
        _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
    ),
    beacons=(BeaconDefinition(0x100A, "3.1"),),
    auth_mode="standard_nus", connectable=True,
    limitations=("云端 model 未在上游明确，目录使用真实硬件型号。", "详情页偶发连接超时，删除后重加需要先清除本地绑定。", "控制走 NUS 文本协议；上游未提供自动化触发事件。"),
    source_dir="esp32/nightl2_adv",
)

_REPELLER = ModelDefinition(
    "zimi.mosq.v1", "米家驱蚊器智能版（实验）", 0x040A,
    properties=(
        _p(2, 1, "驱蚊片余量", U8, 76, minimum=0, maximum=100, step=1, unit="%", semantic="consumable"),
        _p(3, 1, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        _p(4, 1, "开关", BOOL, True, writable=True, semantic="on"),
    ),
    beacons=(BeaconDefinition(0x1012, "4.1", "bool"), BeaconDefinition(0x1013, "2.1"), BeaconDefinition(0x100A, "3.1")),
    auth_mode="psk", connectable=True, available=False,
    unavailable_reason="Legacy PSK 绑定仍未实机验证，暂不作为正常可用型号开放。",
    limitations=("实验协议路径；扫描形态、dev_sign 和云端 PSK 接口仍缺实测。", "上游未实现驱蚊器定时任务和 RTC。"), source_dir="esp32/wx08zm_gatt",
)

_MESH_BULB = ModelDefinition(
    "MJDP003", "米家 LED 灯泡蓝牙 Mesh 版（不可用）", 0x06EB,
    properties=(
        _p(2, 1, "开关", BOOL, False, writable=True, entity_domains=_BINARY_DOMAINS + ("light",), semantic="on"),
        _p(2, 2, "亮度", U16, 32768, writable=True, minimum=1, maximum=65535, step=1, entity_domains=_LIGHT_DOMAINS, semantic="brightness"),
        _p(2, 3, "色温", U32, 4000, writable=True, minimum=2700, maximum=6500, step=1, unit="K", entity_domains=_LIGHT_DOMAINS, semantic="color_temp"),
    ),
    beacons=(BeaconDefinition(0x1012, "2.1", "bool"),),
    available=False, unavailable_reason="该型号需要 BLE Mesh 配网与合法设备身份，上游 PID 仅推断且绑定返回 -27。",
    limitations=("保留协议研究目录，不能用普通 BLE 桥接添加或控制。",), source_dir="esp32/bulb_gatt",
)

_OUTLET = ModelDefinition(
    "sharge.plug.sj01", "闪极 100W 迷你充电器", 0x1E1C,
    properties=(
        _p(2, 1, "开关", BOOL, False, writable=True, semantic="on"),
        _p(2, 7, "开启定时", U8, 0, writable=True, minimum=0, maximum=24, step=1, unit="h", semantic="timer"),
        _p(2, 8, "关闭定时", U8, 0, writable=True, minimum=0, maximum=24, step=1, unit="h", semantic="timer_off"),
        _p(2, 9, "剩余时间", U8, 0, minimum=0, maximum=24, step=1, unit="h", semantic="remaining_time"),
    ),
    beacons=(BeaconDefinition(0x1001, "2.1", "bool"),),
    gatt_strategy="prefer_source", connectable=True, source_dir="esp32/outlet_adv",
)

_KETTLE = ModelDefinition(
    "yunmi.kettle.v13", "米家恒温电水壶 Pro", 0x1809,
    properties=(
        _p(2, 1, "工作状态", U8, 0, choices=((0, "待机"), (1, "加热"), (2, "煮沸后保温"), (3, "加热至设定温度"), (4, "冷却"), (5, "异常")), semantic="status"),
        _p(2, 2, "故障状态", U8, 0, minimum=0, maximum=4, step=1, semantic="fault"),
        _p(3, 1, "保温模式", U8, 0, writable=True, choices=((0, "煮沸后保温"), (1, "直接保温")), semantic="mode"),
        _p(3, 2, "保温开关", BOOL, False, writable=True, semantic="on"),
        _p(3, 3, "保温档位", U8, 2, writable=True, minimum=0, maximum=4, step=1, semantic="insulation_gear"),
        _p(3, 5, "保温剩余时长", U16, 3600, minimum=0, maximum=43200, step=1, unit="s", semantic="remaining_time"),
        _p(3, 6, "水温", U8, 25, minimum=0, maximum=100, step=1, unit="°C", semantic="temperature"),
        *tuple(_p(5, index, f"档位 {index} 温度", U8, value, writable=True, minimum=0, maximum=100, step=1, unit="°C", semantic="target_temperature") for index, value in enumerate((45, 55, 65, 80, 90), start=1)),
        *tuple(_p(5, index + 5, f"档位 {index} 时长", U8, value, writable=True, minimum=1, maximum=24, step=1, unit="min", semantic="keep_warm_duration") for index, value in enumerate((1, 2, 4, 8, 12), start=1)),
    ),
    beacons=(BeaconDefinition(0x4801, "2.1"), BeaconDefinition(0x4C02, "3.2", "bool"), BeaconDefinition(0x4C05, "3.5", "u16"), BeaconDefinition(0x4C06, "3.6")),
    gatt_strategy="prefer_source", connectable=True, source_dir="esp32/kettle_adv",
)

_FRAGRANCES = ((0, "无"), (1, "葡萄柚"), (2, "青玉茶"), (3, "粉丝带"))
_DIFFUSER = ModelDefinition(
    "xiaomi.diffuser.xwczxf", "米家智能香氛机杯托版", 0x39E6,
    properties=(
        _p(2, 1032, "开关", BOOL, True, writable=True, semantic="on"),
        _p(2, 1020, "香型模式", U8, 0, writable=True, choices=((0, "通道 1"), (1, "通道 2"), (2, "通道 3"), (3, "混香"), (4, "试香")), semantic="mode"),
        _p(2, 1069, "喷香时长", U16, 60, writable=True, minimum=30, maximum=150, step=30, unit="s", semantic="fragrance_out_time"),
        _p(2, 2, "顶盖状态", U8, 3, writable=True, choices=((1, "无"), (2, "初始化"), (3, "正常")), semantic="cover_status"),
        *tuple(prop for siid, remaining, fragrance in ((3, 80, 1), (4, 60, 2), (5, 40, 3)) for prop in (
            _p(siid, 1070, f"香液 {siid - 2} 余量", U8, remaining, writable=True, minimum=0, maximum=100, step=1, unit="%", semantic="fragrance_level"),
            _p(siid, 1, f"香液 {siid - 2} 名称", U8, fragrance, writable=True, choices=_FRAGRANCES, semantic="fragrance_name"),
        )),
        _p(6, 1032, "灯光开关", BOOL, True, writable=True, entity_domains=_BINARY_DOMAINS + ("light",), semantic="on"),
    ),
    # Keep the demonstrated object IDs even where they differ from the formula.
    beacons=(BeaconDefinition(0x4818, "2.1032", "bool"), BeaconDefinition(0x480C, "2.1020"), BeaconDefinition(0x4C2D, "2.1069", "u16"), BeaconDefinition(0x4C2E, "3.1070")),
    gatt_strategy="prefer_source", connectable=True, source_dir="esp32/diffuser_adv",
)

_SCALE = ModelDefinition(
    "yunmai.scales.ms103", "米家体脂秤 S400", 0x30D9,
    properties=(
        _p(2, 1001, "兼容状态值", FLOAT, 0.0, semantic="internal_placeholder", notify=False),
        _p(3, 1003, "电量", U8, 100, minimum=0, maximum=100, step=1, unit="%", semantic="battery"),
        _p(3, 1004, "体重单位", U8, 0, writable=True, choices=((0, "千克"), (1, "磅")), semantic="weight_unit"),
        _p(3, 1005, "体重", U32, 0, minimum=0, step=1, unit="0.1 kg", semantic="weight"),
        _p(3, 1006, "人体阻抗", U32, 0, minimum=0, step=1, unit="0.1 Ω", semantic="impedance"),
        _p(6, 1, "用户标识", I64, 0, minimum=0, maximum=999999999999999, step=1, semantic="user_id", spec_visible=False),
        _p(6, 8, "设备用户编号", U8, 0, minimum=0, maximum=255, step=1, semantic="device_user_id", spec_visible=False),
        _p(6, 4, "用户类型", U8, 1, choices=((1, "主用户"), (2, "虚拟用户"), (3, "访客")), semantic="user_type", spec_visible=False),
        _p(6, 6, "基准体重", U16, 0, minimum=0, maximum=3000, step=1, unit="0.1 kg", semantic="weight", spec_visible=False),
        _p(10, 1, "称重模式", U8, 0, writable=True, choices=((0, "普通"), (1, "抱婴"), (2, "平衡"), (3, "访客"), (4, "单次")), semantic="work_mode"),
        _p(13, 1, "插件版本", U16, 3, minimum=1, maximum=65535, step=1, semantic="plugin_version"),
        _p(13, 2, "同步单位", U8, 1, choices=((1, "千克"), (3, "斤")), semantic="sync_unit"),
        _p(13, 3, "时间有效", BOOL, True, semantic="time_valid"),
        _p(13, 4, "设备时间", U32, 0, unit="s", semantic="time", derived="unix_time"),
        _p(13, 5, "用户信息", STRING, "", semantic="user_info", spec_visible=False),
        _p(13, 6, "离线记录数量", U8, 0, minimum=0, maximum=255, step=1, semantic="offline_count"),
        _p(13, 7, "序列号", STRING, "", semantic="serial_number", spec_visible=False),
        _p(13, 8, "设备地址", STRING, "", semantic="mac", spec_visible=False),
        _p(13, 9, "固件版本", STRING, "1.0.0", semantic="firmware_version", spec_visible=False),
        _p(13, 10, "电量状态", U8, 0, choices=((0, "充足"), (1, "不足"), (2, "耗尽")), semantic="battery_status"),
        _p(8, 1, "称重数据", STRING, "0,0", semantic="weight_data", spec_visible=False),
        _p(11, 1, "设备用户编号", U8, 0, minimum=0, maximum=255, step=1, semantic="device_user_id", spec_visible=False),
        _p(11, 2, "复合测量指标", U32, 0, semantic="measurement_data", spec_visible=False),
        _p(11, 3, "测量时间", U32, 0, unit="s", semantic="measurement_time", derived="unix_time", spec_visible=False),
    ),
    beacons=(BeaconDefinition(0x100A, "3.1003"),),
    actions=(
        ActionDefinition("13.1", "同步信息", 13, 1, ("13.1", "13.2", "13.4", "13.3", "13.5"), ("13.6", "13.7", "13.8", "13.9", "13.10")),
        ActionDefinition("10.1", "开始测量", 10, 1),
        ActionDefinition("6.5", "更新基准体重", 6, 5, ("6.1", "6.8", "6.4", "6.6")),
    ),
    events=(
        EventDefinition("8.e.1", "称重过程", 8, 1, ("8.1",)),
        EventDefinition("8.e.2", "测量结果", 8, 2, ("8.1",)),
        EventDefinition("11.e.1022", "测量指标", 11, 1022, ("11.1", "11.2", "11.3")),
        EventDefinition("13.e.1", "同步信息", 13, 1, ("13.6", "13.7", "13.8", "13.9", "13.10")),
    ),
    gatt_strategy="prefer_source", connectable=True,
    limitations=("上游未实现抱婴称重和平衡测试。", "3.1005 按实际协议使用千克乘 10，3.1006 使用欧姆乘 10。", "同步单位和电量状态按真实 action 参数枚举处理。"), source_dir="esp32/scale_adv",
)

MODEL_CATALOG: dict[str, ModelDefinition] = {
    model.model: model
    for model in (_SCALE, _OCCUPANCY, _CARLIGHT, _COOLER, *_SENSOR_MODELS, *_BUTTON_MODELS, _NIGHT_LIGHT, _REPELLER, _MESH_BULB, _OUTLET, _KETTLE, _DIFFUSER)
}
AVAILABLE_MODELS: tuple[ModelDefinition, ...] = tuple(model for model in MODEL_CATALOG.values() if model.available)


def get_model(model: str) -> ModelDefinition:
    try:
        return MODEL_CATALOG[model]
    except (KeyError, TypeError) as error:
        raise ValueError("Unknown MIoT BLE model") from error
