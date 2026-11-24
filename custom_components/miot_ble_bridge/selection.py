"""Limit setup choices to devices and entities that can supply model values."""

from __future__ import annotations

from collections import defaultdict
import re
from types import SimpleNamespace
from typing import Any

from homeassistant.helpers import device_registry as dr, entity_registry as er

from . import models
from .mappings import _convert_unit, effective_attribute, property_service_call, read_entity_value

_CONTROL_DOMAINS = {"light", "switch", "input_boolean", "number", "input_number", "select", "input_select", "fan", "climate"}
_EVENT_DOMAINS = {"button", "input_button", "event", "binary_sensor"}
_EVENT_TRIGGER_DOMAINS = {"binary_sensor", "sensor", "event", "button", "input_button", "switch", "input_boolean", "select", "input_select", "light", "fan", "climate"}
_MAINTENANCE_BUTTON_WORDS = ("reboot", "restart", "reset", "identify", "factory", "重启", "恢复出厂", "识别")
_EVENT_SEMANTICS = (
    (("click", "press", "button", "单击", "双击", "长按"), set(), ("button", "click", "press", "hold", "single", "double", "单击", "双击", "长按", "按键", "按钮")),
    (("motion", "presence", "移动", "存在"), {"occupancy", "presence", "motion"}, ("motion", "presence", "occupancy", "has_target", "有人", "移动", "存在")),
    (("weight", "measurement", "称重", "测量"), {"weight", "timestamp"}, ("weight", "weigh", "weighing", "measurement", "scale", "body_composition", "体重", "称重", "测量")),
    (("sync", "同步"), {"timestamp"}, ("sync", "synchronized", "device_info", "同步")),
    (("low_battery", "低电"), {"battery"}, ("low_battery", "battery", "电量", "低电")),
)
_UNAVAILABLE = {"unknown", "unavailable", "none", "null", ""}
_DIAGNOSTIC_CLASSES = {"connectivity", "signal_strength", "update", "restart"}
_DIAGNOSTIC_WORDS = (
    "rssi", "wifi_signal", "signal_strength", "uptime", "last_seen", "last_restart",
    "ip_address", "wifi_ssid", "connectivity", "connection_status", "连接状态",
    "signal", "在线", "连接", "信号强度", "运行时间", "上线时间", "最近重启", "ip 地址",
)
_DEVICE_CLASSES = {
    "presence": {"occupancy", "presence", "motion"},
    "contact": {"opening", "door", "window", "garage_door"},
    "temperature": {"temperature"}, "target_temperature": {"temperature"},
    "humidity": {"humidity"}, "illuminance": {"illuminance"},
    "battery": {"battery"}, "battery_status": {"battery"},
    "charging": {"battery_charging"}, "light_degree": {"light", "illuminance"},
    "moisture": {"moisture"}, "moisture_top": {"moisture"},
    "water_shortage": {"moisture"}, "pressure": {"occupancy", "presence", "pressure"},
    "smoke": {"smoke"}, "smoke_status": {"smoke"},
    "carbon_dioxide": {"carbon_dioxide"}, "aqi": {"aqi"},
    "tvoc": {"volatile_organic_compounds", "volatile_organic_compounds_parts"},
    "gas_concentration": {"gas"}, "weight": {"weight"},
    "conductivity": {"conductivity"},
    "time": {"timestamp"}, "measurement_time": {"timestamp"},
    "no_motion_duration": {"duration"}, "no_motion_time_set": {"duration"},
    "remaining_time": {"duration"}, "keep_warm_duration": {"duration"},
    "delay_time": {"duration"}, "fragrance_out_time": {"duration"},
}
_KEYWORDS = {
    "presence": ("presence", "occupancy", "has_target", "hastarget", "motion", "radar", "有人", "存在", "人体", "雷达"),
    "contact": ("contact", "opening", "door", "window", "magnet", "门窗", "门磁", "开合"),
    "temperature": ("temperature", "temp", "温度", "水温"),
    "target_temperature": ("target_temperature", "target_temp", "temperature", "temp", "目标温度", "档位温度", "温度"),
    "humidity": ("humidity", "hum", "湿度"),
    "illuminance": ("illuminance", "lux", "light_level", "光照", "照度"),
    "light_degree": ("illuminance", "light_level", "light_detected", "光照", "照度", "明暗"),
    "battery": ("battery", "电量", "电池"), "battery_status": ("battery", "电量", "低电"),
    "charging": ("charging", "charge", "充电"),
    "pressure": ("pressure", "press_state", "压力"),
    "moisture": ("moisture", "water_leak", "flood", "soil", "漏水", "浸水", "土壤湿度"),
    "moisture_top": ("moisture", "water", "rain", "淋水", "水浸"),
    "water_shortage": ("water_shortage", "low_water", "water_level", "缺水", "水位"),
    "smoke": ("smoke", "烟雾", "烟感"), "smoke_status": ("smoke", "烟雾", "烟感"),
    "gas_concentration": ("gas", "燃气", "气体浓度"),
    "carbon_dioxide": ("carbon_dioxide", "co2", "二氧化碳"),
    "formaldehyde": ("formaldehyde", "hcho", "甲醛"),
    "tvoc": ("tvoc", "voc", "volatile_organic", "挥发性有机物"),
    "aqi": ("aqi", "air_quality", "空气质量"),
    "weight": ("weight", "weigh", "体重", "重量"),
    "impedance": ("impedance", "阻抗"),
    "conductivity": ("conductivity", "fertility", "电导", "肥力"),
    "brightness": ("brightness", "brightness_pct", "亮度"),
    "color_temp": ("color_temp", "color_temperature", "色温"),
    "color": ("rgb", "color", "颜色"),
    "mode": ("mode", "模式"), "light_mode": ("light_mode", "effect", "灯光模式", "灯效"),
    "delay": ("delay", "延时"), "delay_time": ("delay", "duration", "延时", "时长"),
    "flow_speed": ("flow_speed", "流光速度"),
    "color_combination": ("color_combination", "颜色组合"),
    "extreme_limit": ("extreme", "极限", "极寒"),
    "highlights": ("highlight", "highlights", "高亮"),
    "device_mode": ("device_mode", "设备模式"),
    "work_mode": ("work_mode", "工作模式", "称重模式"),
    "insulation_gear": ("gear", "insulation", "保温档位", "档位"),
    "keep_warm_duration": ("keep_warm", "duration", "保温时长"),
    "no_motion_duration": ("no_motion", "absence", "无人时长", "无人时间"),
    "no_motion_time_set": ("no_motion", "absence", "无人时长", "无人时间"),
    "remaining_time": ("remaining_time", "remaining", "剩余时间"),
    "brush_head_life": ("brush_head", "brush_life", "刷头"),
    "filter_life": ("filter_life", "filter_remaining", "滤芯"),
    "fragrance_level": ("fragrance", "香氛", "浓度"),
    "fragrance_name": ("fragrance", "香氛", "香型"),
    "fragrance_out_time": ("fragrance", "out_time", "出香", "香氛"),
    "time": ("timestamp", "current_time", "device_time", "设备时间"),
    "measurement_time": ("measurement_time", "weigh_time", "测量时间", "称重时间"),
    "weight_data": ("weight", "weigh", "body", "result", "csv", "体重", "称重", "测量", "结果"),
    "fault": ("fault", "error", "故障"),
}
_NUMERIC_CLASSES = set().union(*_DEVICE_CLASSES.values()) | {"current", "voltage", "power", "energy", "distance", "signal_strength", "data_size", "frequency", "speed", "enum"}


def category_options() -> list[dict[str, str]]:
    available = {model.category for model in models.AVAILABLE_MODELS}
    return [dict(option) for option in models.CATEGORY_OPTIONS if option["value"] in available]


def _entries(hass) -> list[Any]:
    registry = er.async_get(hass)
    collection = getattr(registry, "entities", None)
    if collection is None:
        collection = getattr(registry, "entries", {})
    return list(collection.values())


def _class(entry, state) -> str | None:
    value = getattr(entry, "device_class", None) or getattr(entry, "original_device_class", None)
    if not value and state is not None:
        value = state.attributes.get("device_class")
    return str(getattr(value, "value", value)).lower() if value else None


def _text(entry) -> str:
    return " ".join(str(value) for value in (entry.entity_id, getattr(entry, "name", None), getattr(entry, "original_name", None)) if value).lower()


def _word_match(text: str, keyword: str) -> bool:
    if keyword.isascii():
        return re.search(r"(?:^|[^a-z0-9])"+re.escape(keyword)+r"(?:$|[^a-z0-9])", text) is not None
    return keyword in text


def _diagnostic(entry, state, semantic: str) -> bool:
    if getattr(entry, "disabled_by", None):
        return True
    device_class = _class(entry, state)
    if device_class in _DIAGNOSTIC_CLASSES:
        return True
    if device_class == "problem" and semantic not in {"fault", "water_shortage"}:
        return True
    text = _text(entry)
    if any(_word_match(text, word) for word in _DIAGNOSTIC_WORDS):
        return True
    category = getattr(entry, "entity_category", None)
    category = getattr(category, "value", category)
    return category == "diagnostic" and semantic not in {"battery", "battery_status", "charging", "fault"}


def _supported_light_attribute(entry, state, attribute: str | None) -> bool:
    if attribute is None:
        return True
    capabilities = dict(getattr(entry, "capabilities", None) or {})
    if state is not None:
        capabilities.update(state.attributes)
    modes = capabilities.get("supported_color_modes")
    if not modes:
        return True
    modes = {str(getattr(mode, "value", mode)) for mode in modes}
    allowed = {
        "brightness": {"brightness", "color_temp", "hs", "xy", "rgb", "rgbw", "rgbww", "white"},
        "color_temp_kelvin": {"color_temp"},
        "rgb_color": {"hs", "xy", "rgb", "rgbw", "rgbww"},
    }.get(attribute)
    return allowed is not None and bool(modes & allowed)


def _semantic_score(prop, entry, state) -> int | None:
    domain = entry.entity_id.split(".", 1)[0]
    semantic = prop.semantic or ""
    device_class = _class(entry, state)
    text = _text(entry)
    if domain == "light":
        attribute = effective_attribute(prop, entry.entity_id, {}, state)
        if semantic not in {"on", "brightness", "color_temp", "color_temperature", "color"}:
            return None
        return 0 if _supported_light_attribute(entry, state, attribute) else None
    if prop.writable and semantic == "on" and domain in {"switch", "input_boolean"}:
        return 0
    if domain in {"sensor", "event"} and effective_attribute(prop, entry.entity_id, {}, state):
        return 1
    accepted = _DEVICE_CLASSES.get(semantic, set())
    if device_class in accepted and device_class not in {"duration", "timestamp"}:
        if semantic == "presence":
            if any(_word_match(text, item) for item in ("moving", "still", "运动", "静止")):
                return 3
            if device_class == "motion":
                return 2
        return 0
    if device_class in _NUMERIC_CLASSES and accepted and device_class not in accepted:
        return None
    words = _KEYWORDS.get(semantic, (semantic,) if semantic else ())
    if any(word and _word_match(text, word) for word in words):
        if semantic == "presence" and any(_word_match(text, item) for item in ("moving", "still", "运动", "静止")):
            return 3
        return 1
    if not semantic and any(_word_match(text, word) for word in ("absence", "no_motion", "无人")):
        return 1
    source_unit = state.attributes.get("unit_of_measurement") if state is not None else None
    if (semantic in {"temperature", "target_temperature"} and source_unit in {"°C", "C", "°F", "F", "K"}) or (semantic == "illuminance" and source_unit in {"lx", "lux"}) or (semantic == "weight" and source_unit in {"kg", "g", "lb"}) or (semantic == "conductivity" and source_unit in {"µS/cm", "μS/cm"}):
        return 2
    return None


def _score(hass, model, prop, entry, *, allow_other: bool) -> int | None:
    if entry.entity_id.split(".", 1)[0] not in prop.entity_domains:
        return None
    domain = entry.entity_id.split(".", 1)[0]
    state = hass.states.get(entry.entity_id)
    if _diagnostic(entry, state, prop.semantic or ""):
        return None
    if prop.writable and domain not in _CONTROL_DOMAINS:
        return None
    if not allow_other and model.category in {"sensor", "binary_sensor"} and not prop.writable and domain not in {"sensor", "binary_sensor"}:
        return None
    source_unit = state.attributes.get("unit_of_measurement") if state is not None else None
    continuous_lux = prop.semantic == "light_degree" and (_class(entry, state) == "illuminance" or source_unit in {"lx", "lux"})
    if continuous_lux and not allow_other:
        return None
    score = _semantic_score(prop, entry, state)
    if score is None and continuous_lux:
        score = 4
    if score is None and allow_other and prop.writable and domain in {"select", "input_select", "number", "input_number", "input_boolean"} and state is not None:
        source_unit = state.attributes.get("unit_of_measurement")
        if prop.unit or not source_unit:
            score = 4
    if score is None:
        return None
    mapping = {"entity_id": entry.entity_id, "source": "entity"}
    attribute = effective_attribute(prop, entry.entity_id, mapping, state)
    if state is not None and not attribute:
        unit = state.attributes.get("unit_of_measurement")
        if prop.type_code == 0 and unit:
            return None
        try:
            _convert_unit(1, unit, prop.unit)
        except (ValueError, TypeError, OverflowError):
            return None
    if prop.writable:
        probes = [prop.default, *(value for value, _ in prop.choices)]
        probes.extend(value for value in (prop.minimum, prop.maximum) if value is not None)
        try:
            for value in probes:
                property_service_call(prop, prop.validate(value), mapping, state)
        except (ValueError, TypeError, KeyError, OverflowError):
            return None
    if state is not None and str(state.state).lower() not in _UNAVAILABLE:
        try:
            read_entity_value(prop, state, mapping)
        except (ValueError, TypeError, KeyError, OverflowError):
            # A temporary value or a select's custom label is not an unsupported entity class.
            pass
    return score


def _candidate_entries(hass, device_id: str | None, allow_other: bool) -> list[Any]:
    if allow_other:
        entries = _entries(hass)
        known = {entry.entity_id for entry in entries}
        if hasattr(hass.states, "async_all"):
            for state in hass.states.async_all():
                if state.entity_id not in known:
                    entries.append(SimpleNamespace(entity_id=state.entity_id, device_id=None, name=state.attributes.get("friendly_name"), original_name=None, device_class=state.attributes.get("device_class"), original_device_class=None, disabled_by=None))
        return entries
    if not device_id:
        return []
    return list(er.async_entries_for_device(er.async_get(hass), device_id))


def eligible_entities(hass, model, prop, device_id: str | None, allow_other: bool = False) -> list[str]:
    scored = []
    for entry in _candidate_entries(hass, device_id, allow_other):
        score = _score(hass, model, prop, entry, allow_other=allow_other)
        if score is not None:
            scored.append((score, entry.entity_id))
    return [entity_id for _, entity_id in sorted(scored)]


def recommended_entity(hass, model, prop, device_id: str | None) -> str | None:
    scored = []
    for entry in _candidate_entries(hass, device_id, False):
        score = _score(hass, model, prop, entry, allow_other=False)
        if score is not None:
            scored.append((score, entry.entity_id))
    if not scored:
        return None
    best = min(score for score, _ in scored)
    best_entities = [entity_id for score, entity_id in scored if score == best]
    return best_entities[0] if len(best_entities) == 1 else None


def _event_compatible(hass, entry) -> bool:
    domain = entry.entity_id.split(".", 1)[0]
    state = hass.states.get(entry.entity_id)
    if domain not in _EVENT_DOMAINS or _diagnostic(entry, state, "button"):
        return False
    if domain in {"button", "input_button"} and any(_word_match(_text(entry), word) for word in _MAINTENANCE_BUTTON_WORDS):
        return False
    if domain in {"button", "input_button"}:
        return True
    if domain == "event":
        types = state.attributes.get("event_types", ()) if state is not None else ()
        if state is not None and state.attributes.get("event_type"):
            types = (*types, state.attributes["event_type"])
        tokens = ("button", "click", "press", "hold", "single", "double", "按键", "按钮")
        return any(_word_match(_text(entry), token) or any(_word_match(str(event_type).lower(), token) for event_type in types) for token in tokens)
    return any(_word_match(_text(entry), word) for word in ("button", "click", "press", "按键", "按钮"))


def _model_event_compatible(hass, model, entry) -> bool:
    domain = entry.entity_id.split(".", 1)[0]
    state = hass.states.get(entry.entity_id)
    if domain not in _EVENT_TRIGGER_DOMAINS or domain in {"button", "input_button"} or _diagnostic(entry, state, "event"):
        return False
    text = _text(entry)
    if state is not None:
        tokens = list(state.attributes.get("event_types") or ())
        tokens.extend((state.attributes.get("event_type", ""), str(state.state)))
        text += " " + " ".join(str(token).lower() for token in tokens)
    event_names = " ".join(event.name.lower() for event in model.events)
    device_class = _class(entry, state)
    for names, classes, words in _EVENT_SEMANTICS:
        if not any(_word_match(event_names, name) for name in names):
            continue
        if device_class in classes and device_class != "timestamp":
            return True
        if device_class in _NUMERIC_CLASSES and device_class not in classes and device_class != "enum":
            continue
        if any(_word_match(text, word) for word in words):
            return True
    return False


def eligible_event_entities(hass, model, device_id: str | None, allow_other: bool = False) -> list[str]:
    return sorted(entry.entity_id for entry in _candidate_entries(hass, device_id, allow_other)
                  if _event_compatible(hass, entry) or (allow_other and _model_event_compatible(hass, model, entry)))


def eligible_action_entities(hass, model, device_id: str | None, allow_other: bool = False) -> list[str]:
    domains = {"button", "input_button"}
    if allow_other:
        domains.update({"script", "automation"})
    entities = []
    for entry in _candidate_entries(hass, device_id, allow_other):
        domain = entry.entity_id.split(".", 1)[0]
        if domain not in domains:
            continue
        if domain in {"button", "input_button"}:
            if not _event_compatible(hass, entry):
                continue
        elif _diagnostic(entry, hass.states.get(entry.entity_id), "action"):
            continue
        entities.append(entry.entity_id)
    return sorted(entities)


def eligible_devices(hass, model) -> list[dict[str, str]]:
    groups: dict[str, list[Any]] = defaultdict(list)
    for entry in _entries(hass):
        device_id = getattr(entry, "device_id", None)
        if device_id:
            groups[device_id].append(entry)
    properties = [prop for prop in model.properties if (prop.spec_visible or prop.semantic == "presence") and not prop.alias_of and not prop.derived and prop.semantic not in {"battery", "battery_status", "charging", "internal_placeholder", "plugin_version", "offline_count", "time_valid"}]
    devices = dr.async_get(hass)
    result = []
    for device_id, entries in groups.items():
        device = devices.async_get(device_id)
        if device is None or getattr(device, "disabled_by", None):
            continue
        if model.category == "button":
            supported = any(_event_compatible(hass, entry) for entry in entries)
        else:
            supported = any(_score(hass, model, prop, entry, allow_other=False) is not None for prop in properties for entry in entries)
            if model.category == "light":
                lighting = [prop for prop in properties if prop.semantic in {"brightness", "color_temp", "color"}]
                supported = supported and (any(entry.entity_id.startswith("light.") for entry in entries) or any(_score(hass, model, prop, entry, allow_other=False) is not None for prop in lighting for entry in entries))
        if supported:
            name = getattr(device, "name_by_user", None) or getattr(device, "name", None) or device_id
            result.append({"value": device_id, "label": str(name)})
    return sorted(result, key=lambda item: (item["label"].casefold(), item["value"]))
