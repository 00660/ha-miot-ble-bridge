"""Read typed HA values and build service calls for model property mappings."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

_MISSING = {"unknown", "unavailable", "none", "null", ""}
_TRUE = {"on", "true", "yes", "open", "wet", "detected", "1"}
_FALSE = {"off", "false", "no", "closed", "dry", "clear", "0"}
_CHOICE_NAMES = (
    {"auto", "automatic", "自动"}, {"smart", "intelligent", "智能"},
    {"manual", "手动"}, {"custom", "自定义"},
    {"on", "enabled", "开启", "打开", "开机"},
    {"off", "disabled", "关闭", "关机"},
    {"open", "opened", "门开"}, {"closed", "门关"},
    {"normal", "正常"}, {"alarm", "alert", "告警", "烟雾告警"},
    {"charging", "充电", "充电中", "正在充电"},
    {"notcharging", "discharging", "未充电", "不充电"},
    {"full", "charged", "充满", "已充满", "满电", "充足"},
    {"low", "lowbattery", "不足", "低电量", "电量不足"},
    {"bright", "明亮", "亮"}, {"dark", "暗"},
    {"extreme", "maximum", "极寒"},
)


def default_mappings(model, config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Interpret existing radar entries without rewriting their config or identity."""
    if "property_mappings" in config:
        return {key: dict(value) for key, value in config["property_mappings"].items()}
    result = {
        prop.key: ({"source": "derived"} if prop.derived else {"source": "virtual", "value": prop.default})
        for prop in model.properties
    }
    if model.model == "xiaomi.sensor_occupy.03" and config.get("presence_entity"):
        result["2.1078"] = {
            "source": "entity", "entity_id": config["presence_entity"],
            "entity_registry_id": config.get("presence_entity_registry_id"),
        }
        if config.get("illuminance_entity"):
            result["2.1005"] = {
                "source": "entity", "entity_id": config["illuminance_entity"],
                "entity_registry_id": config.get("illuminance_entity_registry_id"),
            }
        else:
            result["2.1005"] = {"source": "virtual", "value": 0.0}
        result["2.1081"] = {"source": "derived"}
        result["2.1082"] = {"source": "derived"}
        result["3.1003"] = {"source": "virtual", "value": 100}
    return result


def effective_attribute(prop, entity_id: str, mapping: dict[str, Any], state=None) -> str | None:
    if mapping.get("attribute"):
        return mapping["attribute"]
    domain = entity_id.partition(".")[0]
    semantic = prop.semantic or ""
    if domain == "light":
        return {
            "brightness": "brightness", "color_temp": "color_temp_kelvin",
            "color_temperature": "color_temp_kelvin", "color": "rgb_color",
        }.get(semantic)
    if domain == "fan" and semantic in {"brightness", "percentage", "speed"}:
        return "percentage"
    if domain == "climate" and semantic in {"temperature", "target_temperature"}:
        return "temperature" if prop.writable else "current_temperature"
    if state is not None and domain in {"sensor", "event"}:
        candidates = {
            "weight_data": ("result", "result_csv", "measurement_result"),
            "temperature": ("temperature", "current_temperature"),
            "humidity": ("humidity", "relative_humidity"),
            "illuminance": ("illuminance", "lux"),
            "battery": ("battery_level", "battery"),
            "measurement_time": ("measurement_time", "timestamp"),
        }.get(semantic, ())
        if semantic != "weight_data":
            try:
                float(state.state)
                return None
            except (ValueError, TypeError):
                pass
        present = [key for key in candidates if state.attributes.get(key) is not None]
        if len(present) == 1:
            return present[0]
    return None


def _choice_name(value: Any) -> str:
    return str(value).strip().lower().replace("_", "").replace("-", "").replace(" ", "")


def _matching_choice(prop, names: set[str]) -> Any | None:
    candidates = [value for value, label in prop.choices if _choice_name(label) in names]
    return candidates[0] if len(candidates) == 1 else None


def automatic_value_map(prop, state, mapping: dict[str, Any]) -> dict[str, Any]:
    """Match explicit enum labels; never infer numeric values from option order."""
    result: dict[str, Any] = {}
    if prop.choices:
        domain = mapping["entity_id"].partition(".")[0]
        if domain in {"binary_sensor", "switch", "input_boolean"}:
            pairs = {
                "smoke_status": ({"正常"}, {"烟雾告警", "告警"}),
                "light_degree": ({"暗"}, {"亮", "明亮"}),
                "charging": ({"未充电", "不充电"}, {"充电中", "正在充电", "充电"}),
                "battery_status": ({"充足", "正常", "满电"}, {"不足", "低电量", "电量不足"}),
            }.get(prop.semantic)
            if pairs:
                off, on = (_matching_choice(prop, names) for names in pairs)
                if off is not None and on is not None:
                    result.update(off=off, on=on)
        raw_values = list(state.attributes.get("options", ())) if state is not None else []
        if state is not None:
            raw_values.append(state.state)
        for raw in raw_values:
            name = _choice_name(raw)
            group = next((names for names in _CHOICE_NAMES if name in names), {name})
            value = _matching_choice(prop, group)
            if value is not None:
                result[str(raw)] = value
    result.update(mapping.get("value_map", {}))
    return result


def _convert_unit(value: float, source: str | None, target: str | None) -> float:
    if not source or not target or source == target:
        return value
    if target in {"°C", "C", "celsius"}:
        if source in {"°F", "F", "fahrenheit"}:
            return (value - 32) * 5 / 9
        if source == "K":
            return value - 273.15
    if target in {"°F", "F", "fahrenheit"} and source in {"°C", "C", "celsius"}:
        return value * 9 / 5 + 32
    if target == "K" and source in {"°C", "C", "celsius"}:
        return value + 273.15
    seconds = {"ms": .001, "s": 1, "min": 60, "h": 3600, "d": 86400}
    if source in seconds and target in seconds:
        return value * seconds[source] / seconds[target]
    pairs = {
        ("kW", "W"): 1000, ("W", "kW"): .001,
        ("g", "kg"): .001, ("lb", "kg"): .45359237,
        ("kg", "0.1 kg"): 10, ("g", "0.1 kg"): .01,
        ("lb", "0.1 kg"): 4.5359237,
        ("Ω", "0.1 Ω"): 10,
        ("cm", "m"): .01, ("mm", "m"): .001,
        ("m", "cm"): 100, ("m", "mm"): 1000,
        ("µg/m³", "mg/m³"): .001, ("μg/m³", "mg/m³"): .001,
    }
    if (source, target) in pairs:
        return value * pairs[source, target]
    if (target, source) in pairs:
        return value / pairs[target, source]
    aliases = {"lx": "lux", "°C": "C", "mg/m3": "mg/m³", "µg/m3": "µg/m³"}
    if aliases.get(source, source) == aliases.get(target, target):
        return value
    raise ValueError("Source unit does not match the MIoT property")


def read_entity_value(prop, state, mapping: dict[str, Any]) -> Any | None:
    if state is None or str(state.state).lower() in _MISSING:
        return None
    entity_id = mapping["entity_id"]
    attribute = effective_attribute(prop, entity_id, mapping, state)
    value = state.attributes.get(attribute) if attribute else state.state
    if value is None or (isinstance(value, str) and value.lower() in _MISSING):
        return None
    value_map = automatic_value_map(prop, state, mapping)
    if str(value) in value_map:
        value = value_map[str(value)]
    elif prop.choices:
        matched = [item for item, label in prop.choices if str(value) == label]
        if matched:
            value = matched[0]
    if isinstance(value, str) and (prop.semantic in {"time", "measurement_time"} or state.attributes.get("device_class") == "timestamp") and len(value) >= 10 and value[4:5] == "-":
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp must include its time zone")
        value = int(timestamp.timestamp())
    text = str(value).lower()
    if prop.type_code == 10:
        value = str(value)
    elif prop.type_code == 0:
        if text in _TRUE:
            value = True
        elif text in _FALSE:
            value = False
        elif not isinstance(value, bool):
            raise ValueError("HA state cannot be converted to a boolean")
        if mapping.get("invert", prop.semantic == "contact" and not mapping.get("value_map")):
            value = not value
    elif attribute == "rgb_color":
        if not isinstance(value, (list, tuple)) or len(value) != 3:
            raise ValueError("HA light has no RGB color")
        value = (int(value[0]) << 16) | (int(value[1]) << 8) | int(value[2])
    else:
        if text in _TRUE:
            value = 1
        elif text in _FALSE:
            value = 0
        else:
            try:
                value = int(value) if prop.type_code != 9 and isinstance(value, (str, int)) else float(value)
            except ValueError:
                value = float(value)
        if not math.isfinite(value):
            return None
        if mapping.get("invert"):
            if value not in (0, 1):
                raise ValueError("Only binary values can be inverted")
            value = 1 - value
        if entity_id.startswith("light.") and attribute == "brightness":
            value = value * 100 / 255
            if prop.type_code != 9:
                value = int(math.floor(value + .5))
        elif not attribute:
            value = _convert_unit(value, state.attributes.get("unit_of_measurement"), prop.unit)
        if not prop.choices and (prop.step is not None or prop.type_code != 9):
            quantum = prop.step or 1
            base = prop.minimum or 0
            if not isinstance(value, int) or quantum != 1:
                rounded = math.floor((value - base) / quantum) if prop.semantic == "weight" and prop.unit == "0.1 kg" else math.floor((value - base) / quantum + .5)
                value = base + rounded * quantum
            if prop.type_code != 9:
                value = int(round(value))
    return prop.validate(value)


def property_service_call(prop, value: Any, mapping: dict[str, Any], state=None) -> tuple[str, str, dict[str, Any]]:
    """Resolve only the explicitly configured entity, never arbitrary services."""
    value = prop.validate(value)
    if mapping.get("invert"):
        if prop.type_code == 0:
            value = not value
        elif value not in (0, 1):
            raise ValueError("Only binary values can be inverted")
        else:
            value = 1 - value
    entity_id = mapping["entity_id"]
    domain = entity_id.partition(".")[0]
    attribute = effective_attribute(prop, entity_id, mapping, state)
    data: dict[str, Any] = {"entity_id": entity_id}
    if domain in {"switch", "input_boolean"}:
        if prop.type_code != 0 and value not in (0, 1):
            raise ValueError("This entity only supports a boolean value")
        return domain, "turn_on" if value else "turn_off", data
    if domain in {"number", "input_number"}:
        unit = state.attributes.get("unit_of_measurement") if state is not None else None
        data["value"] = _convert_unit(value, prop.unit, unit) if isinstance(value, (int, float)) else value
        return domain, "set_value", data
    if domain in {"select", "input_select"}:
        reverse = [key for key, item in automatic_value_map(prop, state, mapping).items() if item == value]
        if reverse:
            data["option"] = reverse[0]
        else:
            labels = [label for item, label in prop.choices if item == value]
            data["option"] = labels[0] if labels else str(value)
        return domain, "select_option", data
    if domain == "light":
        if attribute == "brightness":
            data["brightness_pct"] = value
        elif attribute in {"color_temp_kelvin", "color_temp"}:
            data["color_temp_kelvin"] = value
        elif attribute == "rgb_color":
            data["rgb_color"] = [(int(value) >> shift) & 255 for shift in (16, 8, 0)]
        elif prop.type_code == 0 or value in (0, 1):
            return domain, "turn_on" if value else "turn_off", data
        else:
            raise ValueError("Choose a supported light attribute for this property")
        return domain, "turn_on", data
    if domain == "fan":
        if attribute == "percentage":
            data["percentage"] = value
            return domain, "set_percentage", data
        if prop.type_code == 0 or value in (0, 1):
            return domain, "turn_on" if value else "turn_off", data
    if domain == "climate" and attribute == "temperature":
        data["temperature"] = value
        return domain, "set_temperature", data
    raise ValueError("Configured entity cannot accept this property")


def action_service_call(mapping: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    entity_id = mapping["entity_id"]
    domain = entity_id.partition(".")[0]
    service = {
        "button": "press", "input_button": "press", "script": "turn_on",
        "automation": "trigger",
    }.get(domain)
    if service is None:
        raise ValueError("Configured entity cannot execute this action")
    return domain, service, {"entity_id": entity_id}
