"""Configure independent HA entity mappings for a MiOT BLE device."""

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.core import HomeAssistant, callback, split_entity_id
from homeassistant.helpers import device_registry as dr, entity_registry as er, selector

from .const import (
    CONF_ADAPTER,
    CONF_ACTION_MAPPINGS,
    CONF_ARGUMENTS,
    CONF_ATTRIBUTE,
    CONF_CONFIGURE_VALUE_MAP,
    CONF_CUSTOM_ARGUMENTS,
    CONF_ENTITY_ID,
    CONF_ENTITY_REGISTRY_ID,
    CONF_EVENT_MAPPINGS,
    CONF_DEVICE_TYPE,
    CONF_USE_VIRTUAL,
    CONF_ADVANCED,
    CONF_USE_OTHER_ENTITIES,
    CONF_USE_DERIVED,
    CONF_ENABLED,
    CONF_ILLUMINANCE_ENTITY,
    CONF_ILLUMINANCE_ENTITY_REGISTRY_ID,
    CONF_NAME,
    CONF_INVERT,
    CONF_MODEL,
    CONF_MORE_VALUES,
    CONF_PRESENCE_ENTITY,
    CONF_PRESENCE_ENTITY_REGISTRY_ID,
    CONF_SOURCE_DEVICE,
    CONF_SOURCE,
    CONF_STATE_VALUE,
    CONF_PROPERTY_MAPPINGS,
    CONF_TRIGGER_VALUE,
    CONF_UNIQUE_ID,
    CONF_VALUE,
    CONF_VALUE_MAP,
    DEFAULT_ADAPTER,
    DOMAIN,
    SOURCE_DERIVED,
    SOURCE_ENTITY,
    SOURCE_MAPPED,
    SOURCE_VIRTUAL,
)
from .models import AVAILABLE_MODELS, DEFAULT_MODEL, get_model
from .mappings import (
    default_mappings,
    effective_attribute,
    property_service_call,
    read_entity_value,
)
from .selection import (
    category_options,
    eligible_devices,
    eligible_entities,
    eligible_event_entities,
    eligible_action_entities,
    recommended_entity,
)


def _mapping_schema(
    presence_entities: list[str] | None = None,
    illuminance_entities: list[str] | None = None,
) -> vol.Schema:
    presence_selector: dict[str, Any] = {"filter": {"domain": "binary_sensor"}}
    if presence_entities is not None:
        presence_selector["include_entities"] = presence_entities
    schema = {
        vol.Optional(CONF_NAME): selector.TextSelector(),
        vol.Required(CONF_PRESENCE_ENTITY): selector.EntitySelector(presence_selector),
    }
    if illuminance_entities is None or illuminance_entities:
        illuminance_selector: dict[str, Any] = {
            "filter": {"domain": "sensor", "device_class": "illuminance"}
        }
        if illuminance_entities is not None:
            illuminance_selector["include_entities"] = illuminance_entities
        schema[vol.Optional(CONF_ILLUMINANCE_ENTITY)] = selector.EntitySelector(
            illuminance_selector
        )
    schema[vol.Required(CONF_ADAPTER, default=DEFAULT_ADAPTER)] = selector.TextSelector()
    return vol.Schema(schema)


@callback
def _device_entities(
    hass: HomeAssistant, device_id: str
) -> tuple[list[str], list[str], str | None]:
    entries = er.async_entries_for_device(er.async_get(hass), device_id)
    presence_entries = [
        entry
        for entry in entries
        if split_entity_id(entry.entity_id)[0] == "binary_sensor"
    ]
    lights = [
        entry.entity_id
        for entry in entries
        if split_entity_id(entry.entity_id)[0] == "sensor"
        and (entry.device_class or entry.original_device_class) == "illuminance"
    ]

    def presence_rank(entry: er.RegistryEntry) -> tuple[int, str]:
        text = " ".join(
            (entry.entity_id, entry.name or "", entry.original_name or "")
        ).lower()
        device_class = entry.device_class or entry.original_device_class
        if device_class in {"connectivity", "problem"} or any(
            word in text for word in ("moving", "still", "运动", "静止")
        ):
            return (3, entry.entity_id)
        if device_class in {"occupancy", "presence"}:
            return (0, entry.entity_id)
        if any(
            word in text
            for word in (
                "occupancy", "presence", "hastarget", "has_target",
                "has target", "存在", "有人",
            )
        ):
            return (1, entry.entity_id)
        return (2, entry.entity_id)

    ranked = sorted(presence_entries, key=presence_rank)
    default = (
        ranked[0].entity_id if ranked and presence_rank(ranked[0])[0] < 3 else None
    )
    return [entry.entity_id for entry in presence_entries], lights, default


@callback
def _validate_mapping(
    hass: HomeAssistant, data: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    registry = er.async_get(hass)
    result: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for field, registry_field, domain in (
        (CONF_PRESENCE_ENTITY, CONF_PRESENCE_ENTITY_REGISTRY_ID, "binary_sensor"),
        (CONF_ILLUMINANCE_ENTITY, CONF_ILLUMINANCE_ENTITY_REGISTRY_ID, "sensor"),
    ):
        reference = data.get(registry_field) or data.get(field)
        if field == CONF_ILLUMINANCE_ENTITY and not reference:
            result[field] = None
            result[registry_field] = None
            continue
        entity_id = (
            er.async_resolve_entity_id(registry, reference)
            if isinstance(reference, str)
            else None
        )
        if not entity_id:
            errors[field] = "entity_not_found"
            continue
        if split_entity_id(entity_id)[0] != domain:
            errors[field] = (
                "invalid_presence_entity"
                if domain == "binary_sensor"
                else "invalid_illuminance_entity"
            )
            continue
        registry_entry = registry.async_get(entity_id)
        if registry_entry is None and hass.states.get(entity_id) is None:
            errors[field] = "entity_not_found"
            continue
        result[field] = entity_id
        result[registry_field] = registry_entry.id if registry_entry else None
        if field == CONF_PRESENCE_ENTITY:
            result[CONF_SOURCE_DEVICE] = (
                registry_entry.device_id if registry_entry else None
            )

    adapter = data.get(CONF_ADAPTER, DEFAULT_ADAPTER)
    if not isinstance(adapter, str) or re.fullmatch(r"hci[0-9]+", adapter) is None:
        errors[CONF_ADAPTER] = "invalid_adapter"
    else:
        result[CONF_ADAPTER] = adapter

    name = data.get(CONF_NAME, "")
    if not isinstance(name, str):
        errors[CONF_NAME] = "invalid_name"
    elif name := name.strip():
        result[CONF_NAME] = name
    elif presence_entity := result.get(CONF_PRESENCE_ENTITY):
        state = hass.states.get(presence_entity)
        registry_entry = registry.async_get(presence_entity)
        result[CONF_NAME] = (
            (state.attributes.get("friendly_name") if state else None)
            or (registry_entry.name if registry_entry else None)
            or (registry_entry.original_name if registry_entry else None)
            or presence_entity
        )
    return result, errors


@callback
def _already_mapped(
    hass: HomeAssistant, presence_entity: str, exclude_entry_id: str | None = None
) -> bool:
    registry = er.async_get(hass)
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.entry_id == exclude_entry_id:
            continue
        data = {**entry.data, **entry.options}
        if data.get(CONF_MODEL, DEFAULT_MODEL) != DEFAULT_MODEL:
            continue
        reference = data.get(CONF_PRESENCE_ENTITY_REGISTRY_ID) or data.get(
            CONF_PRESENCE_ENTITY
        )
        if (
            isinstance(reference, str)
            and er.async_resolve_entity_id(registry, reference) == presence_entity
        ):
            return True
    return False


_WRITABLE_DOMAINS = {
    "light", "switch", "input_boolean", "number", "input_number",
    "select", "input_select", "fan", "climate",
}
_ACTION_DOMAINS = {"button", "input_button", "script", "automation"}
_EVENT_DOMAINS = {
    "binary_sensor", "sensor", "event", "button", "input_button", "switch",
    "input_boolean", "select", "input_select", "light", "fan", "climate",
}
_VALUE_ERRORS = (ValueError, TypeError, OverflowError)


def _device_name(hass: HomeAssistant, device_id: str | None) -> str:
    device = dr.async_get(hass).async_get(device_id) if device_id else None
    return (device.name_by_user or device.name or device_id) if device else "米家桥接设备"


def _entry_device(hass: HomeAssistant, data: Mapping[str, Any]) -> str | None:
    if device_id := data.get(CONF_SOURCE_DEVICE):
        return device_id
    mapping = data.get(CONF_PROPERTY_MAPPINGS, {}).get("2.1078", {})
    reference = (
        mapping.get(CONF_ENTITY_REGISTRY_ID) or mapping.get(CONF_ENTITY_ID)
        or data.get(CONF_PRESENCE_ENTITY_REGISTRY_ID) or data.get(CONF_PRESENCE_ENTITY)
    )
    registry = er.async_get(hass)
    entity_id = er.async_resolve_entity_id(registry, reference) if isinstance(reference, str) else None
    entry = registry.async_get(entity_id) if entity_id else None
    return entry.device_id if entry else None


def _device_model_already_mapped(
    hass: HomeAssistant, device_id: str | None, model_id: str,
    exclude_entry_id: str | None = None,
) -> bool:
    if not device_id:
        return False
    return any(
        entry.entry_id != exclude_entry_id
        and (data := {**entry.data, **entry.options}).get(CONF_MODEL, DEFAULT_MODEL) == model_id
        and _entry_device(hass, data) == device_id
        for entry in hass.config_entries.async_entries(DOMAIN)
    )


def _entity_mapping(
    hass: HomeAssistant, reference: Any, domains: set[str],
) -> tuple[dict[str, Any], str | None]:
    registry = er.async_get(hass)
    entity_id = er.async_resolve_entity_id(registry, reference) if isinstance(reference, str) else None
    if not entity_id:
        return {}, "entity_not_found"
    if split_entity_id(entity_id)[0] not in domains:
        return {}, "invalid_entity_domain"
    entry = registry.async_get(entity_id)
    if entry is None and hass.states.get(entity_id) is None:
        return {}, "entity_not_found"
    if entry is not None and getattr(entry, "disabled_by", None):
        return {}, "entity_disabled"
    return {
        CONF_SOURCE: SOURCE_ENTITY,
        CONF_ENTITY_ID: entity_id,
        CONF_ENTITY_REGISTRY_ID: entry.id if entry else None,
    }, None


def _property_domains(prop: Any) -> set[str]:
    domains = set(prop.entity_domains)
    return domains & _WRITABLE_DOMAINS if prop.writable else domains


def _default_value(prop: Any) -> Any:
    for value in (prop.default, *(value for value, _ in prop.choices), prop.minimum, 0):
        try:
            return prop.validate(value)
        except _VALUE_ERRORS:
            continue
    raise ValueError("The model has no valid default for this property")


def _value_selector(prop: Any) -> Any:
    if prop.choices:
        return selector.SelectSelector({
            "options": [{"value": str(value), "label": label} for value, label in prop.choices],
            "mode": "dropdown",
        })
    if prop.type_code == 0:
        return selector.BooleanSelector()
    if prop.type_code == 10:
        return selector.TextSelector()
    config: dict[str, Any] = {"mode": "box", "step": prop.step or ("any" if prop.type_code == 9 else 1)}
    if prop.minimum is not None:
        config["min"] = prop.minimum
    if prop.maximum is not None:
        config["max"] = prop.maximum
    if prop.unit:
        config["unit_of_measurement"] = prop.unit
    return selector.NumberSelector(config)


def _selector_value(prop: Any, value: Any) -> Any:
    return str(value) if prop.choices else value


def _selected_value(prop: Any, value: Any) -> Any:
    if prop.choices:
        for candidate, _ in prop.choices:
            if str(candidate) == str(value):
                return prop.validate(candidate)
        raise ValueError("Unknown enum choice")
    return prop.validate(value)


def _validate_property_entity(hass: HomeAssistant, prop: Any, mapping: dict[str, Any], *, control: bool = True) -> None:
    value_map = mapping.get(CONF_VALUE_MAP, {})
    if not isinstance(value_map, dict) or any(not isinstance(key, str) or not key for key in value_map):
        raise ValueError("Invalid HA state mapping")
    for raw, value in value_map.items():
        value_map[raw] = prop.validate(value)
    if control and prop.writable and len(set(map(repr, value_map.values()))) != len(value_map):
        raise ValueError("Writable enum values must map to distinct HA states")
    if CONF_INVERT in mapping and not isinstance(mapping[CONF_INVERT], bool):
        raise ValueError("Invalid inversion flag")
    state = hass.states.get(mapping[CONF_ENTITY_ID])
    attribute = effective_attribute(prop, mapping[CONF_ENTITY_ID], mapping, state)
    if mapping.get(CONF_ATTRIBUTE) and state is not None and state.state not in {"unknown", "unavailable"} and attribute not in state.attributes:
        raise ValueError("The selected HA attribute does not exist")
    read_entity_value(prop, state, mapping)
    if control and prop.writable:
        probes = [_default_value(prop), *(value for value, _ in prop.choices)]
        probes.extend(value for value in (prop.minimum, prop.maximum) if value is not None)
        for value in probes:
            property_service_call(prop, prop.validate(value), mapping, state)


class _ModelMappingFlow:
    """Share the same property questions between setup and options."""

    def __init__(self) -> None:
        super().__init__()
        self._data: dict[str, Any] = {}
        self._model = get_model(DEFAULT_MODEL)
        self._properties = tuple(prop for prop in self._model.properties
                                 if (prop.spec_visible or prop.semantic == "presence")
                                 and prop.semantic != "internal_placeholder" and not prop.alias_of)
        self._property_index = 0
        self._editing_defaults = False
        self._property_draft: dict[str, Any] = {}
        self._all_entities = False
        self._map_states: list[str] = []
        self._map_index = 0
        self._action_index = 0
        self._event_index = 0
        self._event_draft: dict[str, Any] = {}
        self._argument_index = 0
        self._argument_property: Any | None = None
        self._action_draft: dict[str, Any] = {}
        self._event_source_draft: dict[str, Any] = {}

    def _current_property(self) -> Any:
        return self._argument_property or self._properties[self._property_index]

    def _mapping_target(self) -> dict[str, Any]:
        return self._event_draft.setdefault(CONF_ARGUMENTS, {}) if self._argument_property else self._data[CONF_PROPERTY_MAPPINGS]

    def _source_domains(self, prop: Any) -> set[str]:
        return set(prop.entity_domains) if self._argument_property else _property_domains(prop)

    def _prepare(self, data: Mapping[str, Any], *, prefer_entities: bool = False) -> None:
        self._data = deepcopy(dict(data))
        self._data[CONF_MODEL] = self._model.model
        self._properties = tuple(prop for prop in self._model.properties
                                 if (prop.spec_visible or prop.semantic == "presence")
                                 and prop.semantic != "internal_placeholder" and not prop.alias_of)
        mappings = deepcopy(default_mappings(self._model, self._data))
        for prop in self._model.properties:
            if prop.key not in mappings:
                mappings[prop.key] = ({CONF_SOURCE: SOURCE_DERIVED} if prop.derived else {
                    CONF_SOURCE: SOURCE_VIRTUAL, CONF_VALUE: _default_value(prop),
                })
            if prefer_entities and prop in self._properties and not self._auto_managed(prop):
                entity_id = self._recommended_entity(prop)
                mappings[prop.key] = _entity_mapping(self.hass, entity_id, _property_domains(prop))[0] if entity_id else {CONF_SOURCE: SOURCE_ENTITY}
        self._data[CONF_PROPERTY_MAPPINGS] = mappings
        self._data.setdefault(CONF_ACTION_MAPPINGS, {})
        self._data.setdefault(CONF_EVENT_MAPPINGS, {})
        self._properties = self._ordinary_properties()

    @staticmethod
    def _auto_managed(prop: Any) -> bool:
        return bool(prop.derived) or prop.semantic in {"battery", "battery_status"}

    def _public_properties(self) -> tuple[Any, ...]:
        return tuple(prop for prop in self._model.properties
                     if (prop.spec_visible or prop.semantic == "presence")
                     and prop.semantic != "internal_placeholder" and not prop.alias_of)

    def _ordinary_properties(self) -> tuple[Any, ...]:
        mappings = self._data.get(CONF_PROPERTY_MAPPINGS, {})
        result = []
        for prop in self._public_properties():
            mapping = mappings.get(prop.key, {})
            custom = mapping.get(CONF_SOURCE) == SOURCE_ENTITY or (
                mapping.get(CONF_SOURCE) == SOURCE_VIRTUAL and (
                    prop.derived or mapping.get(CONF_VALUE) != prop.default
                )
            )
            if not self._auto_managed(prop) or custom:
                result.append(prop)
        return tuple(result)

    def _eligible_entities(self, prop: Any, *, allow_other: bool = False,
                           current: Mapping[str, Any] | None = None) -> list[str]:
        ids = eligible_entities(self.hass, self._model, prop, self._data.get(CONF_SOURCE_DEVICE), allow_other=allow_other)
        if current and current.get(CONF_SOURCE) == SOURCE_ENTITY:
            mapping, error = _entity_mapping(self.hass, current.get(CONF_ENTITY_ID), self._source_domains(prop))
            if not error and mapping[CONF_ENTITY_ID] not in ids:
                try:
                    _validate_property_entity(self.hass, prop, {**current, **mapping}, control=self._argument_property is None)
                except _VALUE_ERRORS:
                    pass
                else:
                    ids = [*ids, mapping[CONF_ENTITY_ID]]
        return ids

    def _recommended_entity(self, prop: Any) -> str | None:
        return recommended_entity(self.hass, self._model, prop, self._data.get(CONF_SOURCE_DEVICE))

    def _property_entity_selector(self, prop: Any, ids: list[str]) -> Any:
        return selector.EntitySelector({"filter": {"domain": sorted(self._source_domains(prop))}, "include_entities": ids})

    def _resolved(self, mapping: Mapping[str, Any]) -> dict[str, Any]:
        result = deepcopy(dict(mapping))
        reference = result.get(CONF_ENTITY_REGISTRY_ID) or result.get(CONF_ENTITY_ID)
        if isinstance(reference, str):
            if entity_id := er.async_resolve_entity_id(er.async_get(self.hass), reference):
                result[CONF_ENTITY_ID] = entity_id
        return result

    def _question(self, step_id: str, schema: dict[Any, Any], defaults: Mapping[str, Any],
                  placeholders: dict[str, str], errors: dict[str, str] | None = None) -> ConfigFlowResult:
        return self.async_show_form(
            step_id=step_id,
            data_schema=self.add_suggested_values_to_schema(vol.Schema(schema), defaults),
            description_placeholders={"model": self._model.name, **placeholders},
            errors=errors or {},
        )

    def _property_placeholders(self) -> dict[str, str]:
        prop = self._current_property()
        index = self._argument_index if self._argument_property else self._property_index
        total = len(self._model.events[self._event_index].argument_keys) if self._argument_property else len(self._properties)
        return {
            "property": prop.name, "index": str(index + 1),
            "total": str(total), "unit": prop.unit or "无单位",
        }

    async def async_step_properties(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        self._editing_defaults = False
        self._properties = self._ordinary_properties()
        self._property_index = 0
        if not self._properties and self._model.category == "button" and self._model.events:
            return await self.async_step_events()
        return await self.async_step_property_source()

    async def async_step_default_properties(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        self._editing_defaults = True
        self._properties = tuple(prop for prop in self._public_properties() if self._auto_managed(prop))
        self._property_index = 0
        return await self.async_step_property_source()

    async def async_step_property_source(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if self._property_index >= len(self._properties):
            return await self.async_step_features()
        prop = self._properties[self._property_index]
        current = self._resolved(self._data[CONF_PROPERTY_MAPPINGS].get(prop.key, {}))
        ids = self._eligible_entities(prop)
        current_id = current.get(CONF_ENTITY_ID)
        existing_other = bool(current_id) and current.get(CONF_SOURCE) == SOURCE_ENTITY and current_id not in ids
        if existing_other and current_id in self._eligible_entities(prop, allow_other=True, current=current):
            ids = [*ids, current_id]
        defaults = {
            CONF_ENTITY_ID: current_id or self._recommended_entity(prop),
            CONF_USE_VIRTUAL: current.get(CONF_SOURCE) == SOURCE_VIRTUAL,
            CONF_ADVANCED: existing_other,
        }
        if self._editing_defaults and prop.derived:
            defaults[CONF_USE_DERIVED] = current.get(CONF_SOURCE) == SOURCE_DERIVED
        errors: dict[str, str] = {}
        if user_input is not None:
            use_virtual = user_input.get(CONF_USE_VIRTUAL, defaults[CONF_USE_VIRTUAL])
            advanced = user_input.get(CONF_ADVANCED, defaults[CONF_ADVANCED])
            use_derived = user_input.get(CONF_USE_DERIVED, defaults.get(CONF_USE_DERIVED, False))
            if any(not isinstance(value, bool) for value in (use_virtual, advanced, use_derived)):
                errors["base"] = "invalid_source"
            elif use_virtual:
                self._property_draft = {CONF_SOURCE: SOURCE_VIRTUAL}
                return await self.async_step_property_virtual()
            elif use_derived and self._editing_defaults and prop.derived:
                self._data[CONF_PROPERTY_MAPPINGS][prop.key] = {CONF_SOURCE: SOURCE_DERIVED}
                return await self._next_property()
            else:
                self._property_draft = current if current.get(CONF_SOURCE) == SOURCE_ENTITY else {CONF_SOURCE: SOURCE_ENTITY}
                self._all_entities = existing_other
                reference = user_input.get(CONF_ENTITY_ID)
                if advanced and not reference:
                    return await self.async_step_property_entity()
                mapping, error = _entity_mapping(self.hass, reference, _property_domains(prop))
                if not error and mapping[CONF_ENTITY_ID] not in ids:
                    error = "incompatible_entity"
                if error:
                    errors[CONF_ENTITY_ID if ids else "base"] = error if reference else "select_entity" if ids else "no_compatible_entity"
                else:
                    if mapping[CONF_ENTITY_ID] == current_id:
                        mapping = {**current, **mapping}
                    self._property_draft = mapping
                    if advanced:
                        return await self.async_step_property_entity()
                    try:
                        _validate_property_entity(self.hass, prop, mapping)
                    except _VALUE_ERRORS:
                        errors[CONF_ENTITY_ID] = "incompatible_entity"
                    else:
                        self._data[CONF_PROPERTY_MAPPINGS][prop.key] = mapping
                        return await self._next_property()
            defaults = {**defaults, **user_input}
        schema = {}
        if ids:
            schema[vol.Optional(CONF_ENTITY_ID)] = self._property_entity_selector(prop, ids)
        schema[vol.Optional(CONF_USE_VIRTUAL, default=defaults[CONF_USE_VIRTUAL])] = selector.BooleanSelector()
        schema[vol.Optional(CONF_ADVANCED, default=defaults[CONF_ADVANCED])] = selector.BooleanSelector()
        if self._editing_defaults and prop.derived:
            schema[vol.Optional(CONF_USE_DERIVED, default=defaults[CONF_USE_DERIVED])] = selector.BooleanSelector()
        return self._question("property_source", schema, defaults, {
            **self._property_placeholders(),
            "source_hint": "请选择这台 HA 设备的实体。" if ids else "该设备没有适合此属性的实体，可勾选虚拟值或高级设置。",
        }, errors)

    async def async_step_property_virtual(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        prop = self._properties[self._property_index]
        current = self._data[CONF_PROPERTY_MAPPINGS].get(prop.key, {})
        value = current.get(CONF_VALUE, _default_value(prop))
        errors: dict[str, str] = {}
        if user_input is not None:
            value = user_input.get(CONF_VALUE)
            try:
                normalized = _selected_value(prop, value)
            except _VALUE_ERRORS:
                errors[CONF_VALUE] = "invalid_value"
            else:
                self._data[CONF_PROPERTY_MAPPINGS][prop.key] = {CONF_SOURCE: SOURCE_VIRTUAL, CONF_VALUE: normalized}
                return await self._next_property()
        return self._question("property_virtual", {vol.Required(CONF_VALUE): _value_selector(prop)},
                              {CONF_VALUE: _selector_value(prop, value)},
                              {**self._property_placeholders(), "behavior": "由当前设备的虚拟档位联动更新水温" if self._model.model == "yunmi.kettle.v13" and prop.key == "3.6" else "可在米家修改并保存在当前设备" if prop.writable else "固定上报此值"}, errors)

    async def async_step_property_entity(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        prop = self._current_property()
        defaults = self._resolved(self._property_draft)
        allow_other = self._all_entities or self._argument_property is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            previous_allow_other = allow_other
            allow_other = user_input.get(CONF_USE_OTHER_ENTITIES, allow_other)
            self._all_entities = allow_other
            if allow_other != previous_allow_other:
                defaults = {**defaults, **user_input}
            else:
                reference = user_input.get(CONF_ENTITY_ID)
                ids = self._eligible_entities(prop, allow_other=allow_other, current=defaults)
                if not reference:
                    errors[CONF_ENTITY_ID if ids else "base"] = "select_entity" if ids else "no_compatible_entity"
                    defaults = {**defaults, **user_input}
                else:
                    mapping, error = _entity_mapping(self.hass, reference, self._source_domains(prop))
                    if not error and mapping[CONF_ENTITY_ID] not in ids:
                        error = "incompatible_entity"
                    if error:
                        errors[CONF_ENTITY_ID] = error
                    else:
                        if mapping[CONF_ENTITY_ID] == defaults.get(CONF_ENTITY_ID):
                            mapping = {**defaults, **mapping}
                        self._property_draft = mapping
                        return await self.async_step_property_details()
                    defaults = user_input
        ids = self._eligible_entities(prop, allow_other=allow_other, current=self._property_draft)
        schema = {}
        if ids:
            schema[vol.Optional(CONF_ENTITY_ID)] = self._property_entity_selector(prop, ids)
        if self._argument_property is None:
            schema[vol.Optional(CONF_USE_OTHER_ENTITIES, default=allow_other)] = selector.BooleanSelector()
            defaults[CONF_USE_OTHER_ENTITIES] = allow_other
        return self._question("property_entity", schema, defaults, self._property_placeholders(), errors)

    async def async_step_property_details(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        prop = self._current_property()
        mapping = deepcopy(self._property_draft)
        entity_id = mapping[CONF_ENTITY_ID]
        domain = split_entity_id(entity_id)[0]
        binary_enum = domain == "binary_sensor" and bool(prop.choices) and any(value not in (0, 1) for value, _ in prop.choices)
        can_map_states = bool(prop.choices) or bool(mapping.get(CONF_VALUE_MAP)) or domain in {"select", "input_select"}
        map_default = bool(mapping.get(CONF_VALUE_MAP)) or domain in {"select", "input_select"} or binary_enum
        defaults = {**mapping, CONF_CONFIGURE_VALUE_MAP: map_default}
        schema = {vol.Optional(CONF_ATTRIBUTE): selector.AttributeSelector({"entity_id": entity_id})}
        if prop.type_code == 0 or prop.semantic == "presence" or (prop.choices and all(value in (0, 1) for value, _ in prop.choices)):
            invert_default = mapping.get(CONF_INVERT, prop.semantic == "contact" and not mapping.get(CONF_VALUE_MAP))
            defaults[CONF_INVERT] = invert_default
            schema[vol.Optional(CONF_INVERT, default=invert_default)] = selector.BooleanSelector()
        if can_map_states:
            schema[vol.Optional(CONF_CONFIGURE_VALUE_MAP, default=map_default)] = selector.BooleanSelector()
        errors: dict[str, str] = {}
        if user_input is not None:
            attribute = user_input.get(CONF_ATTRIBUTE)
            if attribute and not isinstance(attribute, str):
                errors[CONF_ATTRIBUTE] = "invalid_attribute"
            else:
                if attribute:
                    mapping[CONF_ATTRIBUTE] = attribute
                else:
                    mapping.pop(CONF_ATTRIBUTE, None)
                if CONF_INVERT in user_input:
                    mapping[CONF_INVERT] = user_input[CONF_INVERT]
                configure_states = user_input.get(CONF_CONFIGURE_VALUE_MAP, map_default)
                if configure_states and can_map_states:
                    self._property_draft = mapping
                    state = self.hass.states.get(entity_id)
                    effective = effective_attribute(prop, entity_id, mapping, state)
                    options = state.attributes.get("options", []) if state else []
                    raw = state.attributes.get(effective) if state and effective else (state.state if state else None)
                    self._map_states = list(dict.fromkeys([
                        *(("off", "on") if binary_enum else ()),
                        *(str(value) for value in options), *mapping.get(CONF_VALUE_MAP, {}),
                    ]))
                    if raw is not None and str(raw) not in {"unknown", "unavailable"} and str(raw) not in self._map_states:
                        self._map_states.append(str(raw))
                    self._map_index = 0
                    return await self.async_step_property_value_map()
                if not configure_states:
                    mapping.pop(CONF_VALUE_MAP, None)
                try:
                    _validate_property_entity(self.hass, prop, mapping, control=self._argument_property is None)
                except _VALUE_ERRORS:
                    errors["base"] = "invalid_entity_value"
                else:
                    self._mapping_target()[prop.key] = mapping
                    return await self._next_property()
            defaults = user_input
        return self._question("property_details", schema, defaults, self._property_placeholders(), errors)

    async def async_step_property_value_map(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        prop = self._current_property()
        mapping = self._property_draft
        value_map = mapping.setdefault(CONF_VALUE_MAP, {})
        raw = self._map_states[self._map_index] if self._map_index < len(self._map_states) else ""
        value = value_map.get(raw, _default_value(prop))
        errors: dict[str, str] = {}
        if user_input is not None:
            raw = user_input.get(CONF_STATE_VALUE)
            value = user_input.get(CONF_VALUE)
            if not isinstance(raw, str) or not raw.strip() or raw in {"unknown", "unavailable"}:
                errors[CONF_STATE_VALUE] = "invalid_state_value"
            else:
                try:
                    normalized = _selected_value(prop, value)
                    if self._argument_property is None and prop.writable and any(key != raw and item == normalized for key, item in value_map.items()):
                        raise ValueError("Ambiguous writable enum mapping")
                except _VALUE_ERRORS:
                    errors[CONF_VALUE] = "invalid_value_map"
                else:
                    value_map[raw] = normalized
                    self._map_index += 1
                    if self._map_index < len(self._map_states) or user_input.get(CONF_MORE_VALUES):
                        return await self.async_step_property_value_map()
                    try:
                        _validate_property_entity(self.hass, prop, mapping, control=self._argument_property is None)
                    except _VALUE_ERRORS:
                        errors["base"] = "invalid_entity_value"
                        self._map_index -= 1
                    else:
                        self._mapping_target()[prop.key] = deepcopy(mapping)
                        return await self._next_property()
        schema = {vol.Required(CONF_STATE_VALUE): selector.TextSelector(), vol.Required(CONF_VALUE): _value_selector(prop)}
        if self._map_index >= len(self._map_states) - 1:
            schema[vol.Optional(CONF_MORE_VALUES, default=False)] = selector.BooleanSelector()
        return self._question("property_value_map", schema,
                              {CONF_STATE_VALUE: raw, CONF_VALUE: _selector_value(prop, value)}, self._property_placeholders(), errors)

    async def _next_property(self) -> ConfigFlowResult:
        if self._argument_property is not None:
            self._argument_property = None
            self._property_draft = {}
            return await self._next_argument()
        self._property_index += 1
        self._property_draft = {}
        return await self.async_step_property_source()

    async def async_step_features(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        options = ["settings", "finish"]
        if self._ordinary_properties():
            options.insert(0, "properties")
        if any(self._auto_managed(prop) for prop in self._public_properties()):
            options.insert(-1, "default_properties")
        if self._model.actions:
            options.insert(-1, "actions")
        if self._model.events:
            options.insert(-1, "events")
        return self.async_show_menu(step_id="features", menu_options=options,
                                    description_placeholders={"model": self._model.name})

    async def async_step_settings(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        defaults = {CONF_NAME: self._data.get(CONF_NAME, _device_name(self.hass, self._data.get(CONF_SOURCE_DEVICE))),
                    CONF_ADAPTER: self._data.get(CONF_ADAPTER, DEFAULT_ADAPTER)}
        errors: dict[str, str] = {}
        if user_input is not None:
            adapter = user_input.get(CONF_ADAPTER, defaults[CONF_ADAPTER])
            name = user_input.get(CONF_NAME, defaults[CONF_NAME])
            if not isinstance(adapter, str) or re.fullmatch(r"hci[0-9]+", adapter) is None:
                errors[CONF_ADAPTER] = "invalid_adapter"
            if not isinstance(name, str):
                errors[CONF_NAME] = "invalid_name"
            if not errors:
                self._data.update({CONF_ADAPTER: adapter, CONF_NAME: name.strip() or defaults[CONF_NAME]})
                return await self.async_step_features()
            defaults = user_input
        return self._question("settings", {vol.Optional(CONF_NAME): selector.TextSelector(),
                                           vol.Optional(CONF_ADAPTER, default=defaults[CONF_ADAPTER]): selector.TextSelector()}, defaults, {}, errors)

    async def async_step_actions(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        self._action_index = 0
        return await self.async_step_action()

    async def async_step_action(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._action_form(user_input, advanced=False)

    async def async_step_action_advanced(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._action_form(user_input, advanced=True)

    async def _action_form(self, user_input: dict[str, Any] | None, *, advanced: bool) -> ConfigFlowResult:
        if self._action_index >= len(self._model.actions):
            return await self.async_step_features()
        action = self._model.actions[self._action_index]
        current = self._resolved(self._action_draft if advanced else self._data[CONF_ACTION_MAPPINGS].get(action.key, {}))
        allow_other = bool(current.get(CONF_USE_OTHER_ENTITIES)) if advanced else False
        previous_allow_other = allow_other
        if advanced and user_input is not None:
            allow_other = bool(user_input.get(CONF_USE_OTHER_ENTITIES, allow_other))
            if allow_other != previous_allow_other:
                self._action_draft = {**current, **user_input, CONF_USE_OTHER_ENTITIES: allow_other}
                if CONF_ENTITY_ID in user_input and user_input[CONF_ENTITY_ID] != current.get(CONF_ENTITY_ID):
                    self._action_draft.pop(CONF_ENTITY_REGISTRY_ID, None)
                return await self.async_step_action_advanced()
        ids = eligible_action_entities(self.hass, self._model, self._data.get(CONF_SOURCE_DEVICE), allow_other=allow_other)
        current_id = current.get(CONF_ENTITY_ID)
        existing_other = bool(current_id) and current_id not in ids
        if existing_other and current.get(CONF_SOURCE) == SOURCE_ENTITY:
            ids = [*ids, current_id]
        defaults = {CONF_ENTITY_ID: current_id or (ids[0] if len(ids) == 1 else None),
                    CONF_USE_VIRTUAL: current.get(CONF_USE_VIRTUAL, current.get(CONF_SOURCE) == SOURCE_VIRTUAL),
                    CONF_ADVANCED: existing_other, CONF_USE_OTHER_ENTITIES: allow_other}
        errors: dict[str, str] = {}
        if user_input is not None:
            if not advanced and user_input.get(CONF_ADVANCED, defaults[CONF_ADVANCED]):
                self._action_draft = {**current, **user_input, CONF_USE_OTHER_ENTITIES: existing_other}
                if CONF_ENTITY_ID in user_input and user_input[CONF_ENTITY_ID] != current_id:
                    self._action_draft.pop(CONF_ENTITY_REGISTRY_ID, None)
                return await self.async_step_action_advanced()
            if user_input.get(CONF_USE_VIRTUAL, defaults[CONF_USE_VIRTUAL]):
                mapping = {CONF_SOURCE: SOURCE_VIRTUAL}
            else:
                mapping, error = _entity_mapping(self.hass, user_input.get(CONF_ENTITY_ID), _ACTION_DOMAINS)
                if not error and mapping[CONF_ENTITY_ID] not in ids:
                    error = "incompatible_entity"
                if error:
                    if not (advanced and CONF_USE_OTHER_ENTITIES in user_input and not user_input.get(CONF_ENTITY_ID)):
                        errors[CONF_ENTITY_ID if ids else "base"] = error
            if not errors:
                if mapping:
                    self._data[CONF_ACTION_MAPPINGS][action.key] = mapping
                    self._action_index += 1
                    self._action_draft = {}
                    return await self.async_step_action()
            defaults.update(user_input)
        schema = {}
        if ids:
            schema[vol.Optional(CONF_ENTITY_ID)] = selector.EntitySelector({"include_entities": ids, "filter": {"domain": sorted(_ACTION_DOMAINS)}})
        schema[vol.Optional(CONF_USE_VIRTUAL, default=defaults[CONF_USE_VIRTUAL])] = selector.BooleanSelector()
        field = CONF_USE_OTHER_ENTITIES if advanced else CONF_ADVANCED
        schema[vol.Optional(field, default=defaults[field])] = selector.BooleanSelector()
        return self._question("action_advanced" if advanced else "action", schema, defaults, {"action": action.name}, errors)

    async def async_step_events(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        self._event_index = 0
        return await self.async_step_event()

    async def async_step_event(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._event_form(user_input, advanced=False)

    async def async_step_event_advanced(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._event_form(user_input, advanced=True)

    async def _event_form(self, user_input: dict[str, Any] | None, *, advanced: bool) -> ConfigFlowResult:
        if self._event_index >= len(self._model.events):
            return await self.async_step_features()
        event = self._model.events[self._event_index]
        current = self._resolved(self._event_source_draft if advanced else self._data[CONF_EVENT_MAPPINGS].get(event.key, {}))
        allow_other = bool(current.get(CONF_USE_OTHER_ENTITIES)) if advanced else False
        previous_allow_other = allow_other
        if advanced and user_input is not None:
            allow_other = bool(user_input.get(CONF_USE_OTHER_ENTITIES, allow_other))
            if allow_other != previous_allow_other:
                self._event_source_draft = {**current, **user_input, CONF_USE_OTHER_ENTITIES: allow_other}
                if CONF_ENTITY_ID in user_input and user_input[CONF_ENTITY_ID] != current.get(CONF_ENTITY_ID):
                    self._event_source_draft.pop(CONF_ENTITY_REGISTRY_ID, None)
                return await self.async_step_event_advanced()
        ids = eligible_event_entities(self.hass, self._model, self._data.get(CONF_SOURCE_DEVICE), allow_other=allow_other)
        current_id = current.get(CONF_ENTITY_ID)
        existing_other = bool(current_id) and current_id not in ids
        if existing_other and current.get(CONF_SOURCE) == SOURCE_ENTITY:
            ids = [*ids, current_id]
        defaults = {**current, CONF_ENTITY_ID: current_id or (ids[0] if len(ids) == 1 else None),
                    CONF_ENABLED: current.get(CONF_ENABLED, current.get(CONF_SOURCE) == SOURCE_ENTITY or (not current and self._model.category == "button")),
                    CONF_ADVANCED: existing_other, CONF_USE_OTHER_ENTITIES: allow_other,
                    CONF_TRIGGER_VALUE: current.get(CONF_TRIGGER_VALUE, ""),
                    CONF_CUSTOM_ARGUMENTS: current.get(CONF_CUSTOM_ARGUMENTS, bool(current.get(CONF_ARGUMENTS)))}
        errors: dict[str, str] = {}
        if user_input is not None:
            if not advanced and user_input.get(CONF_ADVANCED, defaults[CONF_ADVANCED]):
                self._event_source_draft = {**current, **user_input, CONF_USE_OTHER_ENTITIES: existing_other}
                if CONF_ENTITY_ID in user_input and user_input[CONF_ENTITY_ID] != current_id:
                    self._event_source_draft.pop(CONF_ENTITY_REGISTRY_ID, None)
                return await self.async_step_event_advanced()
            if not user_input.get(CONF_ENABLED, defaults[CONF_ENABLED]):
                self._data[CONF_EVENT_MAPPINGS].pop(event.key, None)
                self._event_index += 1
                self._event_source_draft = {}
                return await self.async_step_event()
            mapping, error = _entity_mapping(self.hass, user_input.get(CONF_ENTITY_ID), _EVENT_DOMAINS)
            if not error and mapping[CONF_ENTITY_ID] not in ids:
                error = "incompatible_entity"
            trigger = user_input.get(CONF_TRIGGER_VALUE, defaults[CONF_TRIGGER_VALUE]) if advanced else defaults[CONF_TRIGGER_VALUE]
            if error:
                if not (advanced and CONF_USE_OTHER_ENTITIES in user_input and not user_input.get(CONF_ENTITY_ID)):
                    errors[CONF_ENTITY_ID if ids else "base"] = error
            elif not isinstance(trigger, str):
                errors[CONF_TRIGGER_VALUE] = "invalid_state_value"
            else:
                if split_entity_id(mapping[CONF_ENTITY_ID])[0] in {"button", "input_button", "event"} and trigger == "on":
                    trigger = ""
                mapping[CONF_TRIGGER_VALUE] = trigger
                self._event_draft = mapping
                if advanced and user_input.get(CONF_CUSTOM_ARGUMENTS, defaults[CONF_CUSTOM_ARGUMENTS]) and event.argument_keys:
                    self._event_draft[CONF_ARGUMENTS] = deepcopy(current.get(CONF_ARGUMENTS, {}))
                    self._argument_index = 0
                    return await self.async_step_event_argument()
                if current.get(CONF_ARGUMENTS) and not advanced:
                    mapping[CONF_ARGUMENTS] = deepcopy(current[CONF_ARGUMENTS])
                self._data[CONF_EVENT_MAPPINGS][event.key] = mapping
                self._event_index += 1
                self._event_source_draft = {}
                return await self.async_step_event()
            defaults.update(user_input)
        schema = {}
        if ids:
            schema[vol.Optional(CONF_ENTITY_ID)] = selector.EntitySelector({"include_entities": ids, "filter": {"domain": sorted(_EVENT_DOMAINS)}})
        schema[vol.Optional(CONF_ENABLED, default=defaults[CONF_ENABLED])] = selector.BooleanSelector()
        field = CONF_USE_OTHER_ENTITIES if advanced else CONF_ADVANCED
        schema[vol.Optional(field, default=defaults[field])] = selector.BooleanSelector()
        if advanced:
            schema[vol.Optional(CONF_TRIGGER_VALUE)] = selector.TextSelector()
        if advanced and event.argument_keys:
            schema[vol.Optional(CONF_CUSTOM_ARGUMENTS, default=defaults[CONF_CUSTOM_ARGUMENTS])] = selector.BooleanSelector()
        return self._question("event_advanced" if advanced else "event", schema, defaults, {"event": event.name}, errors)

    async def async_step_event_argument(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        event = self._model.events[self._event_index]
        key = event.argument_keys[self._argument_index]
        prop = self._model.property_by_key[key]
        arguments = self._event_draft.setdefault(CONF_ARGUMENTS, {})
        current = arguments.get(key)
        source = current.get(CONF_SOURCE, SOURCE_ENTITY) if isinstance(current, Mapping) else (SOURCE_VIRTUAL if key in arguments else SOURCE_MAPPED)
        value = current if current is not None and not isinstance(current, Mapping) else self._data[CONF_PROPERTY_MAPPINGS].get(key, {}).get(CONF_VALUE, _default_value(prop))
        errors: dict[str, str] = {}
        if user_input is not None:
            source = user_input.get(CONF_SOURCE, SOURCE_VIRTUAL if CONF_VALUE in user_input else SOURCE_MAPPED)
            value = user_input.get(CONF_VALUE)
            if source == SOURCE_MAPPED:
                arguments.pop(key, None)
                return await self._next_argument()
            if source == SOURCE_ENTITY:
                self._argument_property = prop
                self._all_entities = True
                self._property_draft = self._resolved(current) if isinstance(current, Mapping) else {CONF_SOURCE: SOURCE_ENTITY}
                return await self.async_step_property_entity()
            try:
                if source != SOURCE_VIRTUAL:
                    raise ValueError("Unsupported event argument source")
                arguments[key] = _selected_value(prop, value)
            except _VALUE_ERRORS:
                errors[CONF_VALUE] = "invalid_value"
            else:
                return await self._next_argument()
        return self._question("event_argument", {
            vol.Required(CONF_SOURCE): selector.SelectSelector({"options": [
                {"value": SOURCE_MAPPED, "label": "当前设备已映射属性（推荐）"},
                {"value": SOURCE_ENTITY, "label": "HA 实体的实时值"},
                {"value": SOURCE_VIRTUAL, "label": "固定值"},
            ]}),
            vol.Optional(CONF_VALUE): _value_selector(prop),
        }, {CONF_SOURCE: source, CONF_VALUE: _selector_value(prop, value)},
                              {"event": event.name, "property": prop.name}, errors)

    async def _next_argument(self) -> ConfigFlowResult:
        event = self._model.events[self._event_index]
        self._argument_index += 1
        if self._argument_index < len(event.argument_keys):
            return await self.async_step_event_argument()
        self._data[CONF_EVENT_MAPPINGS][event.key] = deepcopy(self._event_draft)
        self._event_index += 1
        return await self.async_step_event()

    def _validate_complete(self) -> bool:
        try:
            for prop in self._model.properties:
                mapping = self._data[CONF_PROPERTY_MAPPINGS][prop.key]
                if mapping.get(CONF_SOURCE) == SOURCE_VIRTUAL:
                    mapping[CONF_VALUE] = prop.validate(mapping[CONF_VALUE])
                elif mapping.get(CONF_SOURCE) == SOURCE_DERIVED and prop.derived:
                    continue
                elif mapping.get(CONF_SOURCE) == SOURCE_ENTITY:
                    resolved, error = _entity_mapping(self.hass, mapping.get(CONF_ENTITY_REGISTRY_ID) or mapping.get(CONF_ENTITY_ID), _property_domains(prop))
                    if error:
                        return False
                    mapping.update(resolved)
                    _validate_property_entity(self.hass, prop, mapping)
                else:
                    return False
            for key, mapping in self._data[CONF_ACTION_MAPPINGS].items():
                if key not in {action.key for action in self._model.actions}:
                    return False
                if mapping.get(CONF_SOURCE) == SOURCE_ENTITY:
                    resolved, error = _entity_mapping(self.hass, mapping.get(CONF_ENTITY_REGISTRY_ID) or mapping.get(CONF_ENTITY_ID), _ACTION_DOMAINS)
                    if error:
                        return False
                    mapping.update(resolved)
                elif mapping.get(CONF_SOURCE) != SOURCE_VIRTUAL:
                    return False
            for key, mapping in self._data[CONF_EVENT_MAPPINGS].items():
                event = next((event for event in self._model.events if event.key == key), None)
                if event is None or mapping.get(CONF_SOURCE) != SOURCE_ENTITY:
                    return False
                resolved, error = _entity_mapping(self.hass, mapping.get(CONF_ENTITY_REGISTRY_ID) or mapping.get(CONF_ENTITY_ID), _EVENT_DOMAINS)
                if error or not isinstance(mapping.get(CONF_TRIGGER_VALUE, ""), str):
                    return False
                mapping.update(resolved)
                for argument, value in mapping.get(CONF_ARGUMENTS, {}).items():
                    if argument not in event.argument_keys:
                        return False
                    prop = self._model.property_by_key[argument]
                    if isinstance(value, Mapping):
                        if value.get(CONF_SOURCE) != SOURCE_ENTITY:
                            return False
                        resolved, error = _entity_mapping(self.hass, value.get(CONF_ENTITY_REGISTRY_ID) or value.get(CONF_ENTITY_ID), set(prop.entity_domains))
                        if error:
                            return False
                        value.update(resolved)
                        _validate_property_entity(self.hass, prop, value, control=False)
                    else:
                        prop.validate(value)
        except (*_VALUE_ERRORS, KeyError):
            return False
        return True

    async def async_step_finish(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            if not self._validate_complete():
                return self.async_abort(reason="invalid_mapping")
            return await self._finish_entry()
        return self.async_show_form(step_id="finish", data_schema=vol.Schema({}), last_step=True,
                                    description_placeholders={
                                        "model": self._model.name,
                                        "device": _device_name(self.hass, self._data.get(CONF_SOURCE_DEVICE)),
                                        "name": self._data[CONF_NAME],
                                    })


class MiotBleBridgeConfigFlow(_ModelMappingFlow, ConfigFlow, domain=DOMAIN):
    """Create one independently paired config entry per HA device and model."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlowWithReload:
        return MiotBleBridgeOptionsFlow()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        categories = category_options()
        errors: dict[str, str] = {}
        if user_input is not None:
            category = user_input.get(CONF_DEVICE_TYPE)
            if category not in {item["value"] for item in categories}:
                errors[CONF_DEVICE_TYPE] = "invalid_device_type"
            else:
                self._data[CONF_DEVICE_TYPE] = category
                return await self.async_step_model()
        return self._question("user", {vol.Required(CONF_DEVICE_TYPE): selector.SelectSelector({"options": categories, "mode": "dropdown"})},
                              user_input or {}, {}, errors)

    async def async_step_model(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if CONF_DEVICE_TYPE not in self._data:
            return await self.async_step_user()
        models = [model for model in AVAILABLE_MODELS if model.category == self._data[CONF_DEVICE_TYPE]]
        if not models:
            return self.async_abort(reason="no_available_models")
        errors: dict[str, str] = {}
        if user_input is not None:
            model_id = user_input.get(CONF_MODEL)
            if model_id not in {model.model for model in models}:
                errors[CONF_MODEL] = "model_unavailable"
            else:
                self._model = get_model(model_id)
                return await self.async_step_device()
        return self._question("model", {vol.Required(CONF_MODEL): selector.SelectSelector({
            "options": [{"value": model.model, "label": model.name} for model in models],
            "mode": "dropdown",
        })}, user_input or {}, {}, errors)

    async def async_step_device(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        devices = eligible_devices(self.hass, self._model)
        options = [item for item in devices if not _device_model_already_mapped(self.hass, item["value"], self._model.model)]
        errors: dict[str, str] = {}
        if user_input is not None:
            device_id = user_input.get(CONF_SOURCE_DEVICE)
            if _device_model_already_mapped(self.hass, device_id, self._model.model):
                errors[CONF_SOURCE_DEVICE] = "device_model_already_mapped"
            elif device_id not in {item["value"] for item in options}:
                errors[CONF_SOURCE_DEVICE] = "incompatible_device"
            else:
                self._prepare({**self._data, CONF_SOURCE_DEVICE: device_id,
                               CONF_NAME: _device_name(self.hass, device_id), CONF_ADAPTER: DEFAULT_ADAPTER},
                              prefer_entities=True)
                return await self.async_step_properties()
        schema = {}
        if options:
            schema[vol.Required(CONF_SOURCE_DEVICE)] = selector.SelectSelector({"options": options, "mode": "dropdown"})
        elif not errors:
            errors["base"] = "no_compatible_device"
        return self._question("device", schema, user_input or {}, {}, errors)

    async def async_step_import(self, user_input: dict[str, Any]) -> ConfigFlowResult:
        if CONF_MODEL not in user_input and CONF_PROPERTY_MAPPINGS not in user_input:
            data, errors = _validate_mapping(self.hass, user_input)
            if errors:
                return self.async_abort(reason="invalid_mapping")
            self._model = get_model(DEFAULT_MODEL)
            self._prepare(data)
            unique_id = user_input.get(CONF_UNIQUE_ID) or data[CONF_PRESENCE_ENTITY_REGISTRY_ID] or data[CONF_PRESENCE_ENTITY]
        else:
            try:
                self._model = get_model(user_input.get(CONF_MODEL, DEFAULT_MODEL))
                if not self._model.available:
                    return self.async_abort(reason="model_unavailable")
                self._prepare(user_input)
                if not isinstance(self._data.get(CONF_NAME), str) or re.fullmatch(r"hci[0-9]+", self._data.get(CONF_ADAPTER, "")) is None:
                    raise ValueError("Invalid name or adapter")
            except (*_VALUE_ERRORS, KeyError):
                return self.async_abort(reason="invalid_mapping")
            unique_id = user_input.get(CONF_UNIQUE_ID) or f"{_entry_device(self.hass, self._data)}:{self._model.model}"
        if not self._validate_complete():
            return self.async_abort(reason="invalid_mapping")
        if _device_model_already_mapped(self.hass, _entry_device(self.hass, self._data), self._model.model):
            return self.async_abort(reason="already_configured")
        await self.async_set_unique_id(str(unique_id))
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=self._data[CONF_NAME], data=self._data)

    async def _finish_entry(self) -> ConfigFlowResult:
        device_id = self._data[CONF_SOURCE_DEVICE]
        if _device_model_already_mapped(self.hass, device_id, self._model.model):
            return self.async_abort(reason="already_configured")
        await self.async_set_unique_id(f"{device_id}:{self._model.model}")
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=self._data[CONF_NAME], data=self._data)


class MiotBleBridgeOptionsFlow(_ModelMappingFlow, OptionsFlowWithReload):
    """Keep the original model and BLE identity while replacing HA sources."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if not self._data:
            original = {**self.config_entry.data, **self.config_entry.options}
            try:
                self._model = get_model(self.config_entry.data.get(CONF_MODEL, DEFAULT_MODEL))
            except (ValueError, KeyError):
                return self.async_abort(reason="model_unavailable")
            original[CONF_MODEL] = self._model.model
            original[CONF_SOURCE_DEVICE] = _entry_device(self.hass, original)
            self._prepare(original)
        if user_input is None:
            return await self.async_step_properties()
        defaults = self._data
        errors: dict[str, str] = {}
        if user_input is not None:
            device_id = user_input.get(CONF_SOURCE_DEVICE, self._data.get(CONF_SOURCE_DEVICE))
            name = user_input.get(CONF_NAME, self._data.get(CONF_NAME, ""))
            adapter = user_input.get(CONF_ADAPTER, self._data.get(CONF_ADAPTER, DEFAULT_ADAPTER))
            if device_id and (not isinstance(device_id, str) or dr.async_get(self.hass).async_get(device_id) is None):
                errors[CONF_SOURCE_DEVICE] = "device_not_found"
            elif _device_model_already_mapped(self.hass, device_id, self._model.model, self.config_entry.entry_id):
                errors[CONF_SOURCE_DEVICE] = "device_model_already_mapped"
            if user_input.get(CONF_MODEL, self._model.model) != self._model.model:
                errors["base"] = "model_locked"
            if not isinstance(name, str):
                errors[CONF_NAME] = "invalid_name"
            if not isinstance(adapter, str) or re.fullmatch(r"hci[0-9]+", adapter) is None:
                errors[CONF_ADAPTER] = "invalid_adapter"
            if not errors:
                self._data.update({CONF_SOURCE_DEVICE: device_id, CONF_NAME: name.strip() or _device_name(self.hass, device_id), CONF_ADAPTER: adapter})
                return await self.async_step_properties()
            defaults = {**self._data, **user_input}
        return self._question("init", {
            vol.Optional(CONF_NAME): selector.TextSelector(),
            vol.Required(CONF_ADAPTER, default=DEFAULT_ADAPTER): selector.TextSelector(),
        }, defaults, {}, errors)

    async def _finish_entry(self) -> ConfigFlowResult:
        device_id = self._data.get(CONF_SOURCE_DEVICE)
        if _device_model_already_mapped(self.hass, device_id, self._model.model, self.config_entry.entry_id):
            return self.async_abort(reason="already_configured")
        updates: dict[str, Any] = {"title": self._data[CONF_NAME]}
        original_device = _entry_device(self.hass, {**self.config_entry.data, **self.config_entry.options})
        if device_id and device_id != original_device:
            updates["unique_id"] = f"{device_id}:{self._model.model}"
        self.hass.config_entries.async_update_entry(self.config_entry, **updates)
        return self.async_create_entry(title="", data=self._data)
