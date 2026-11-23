"""Configure a radar entity forwarded to a MiOT BLE virtual device."""

from collections.abc import Mapping
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
    CONF_ILLUMINANCE_ENTITY,
    CONF_ILLUMINANCE_ENTITY_REGISTRY_ID,
    CONF_NAME,
    CONF_PRESENCE_ENTITY,
    CONF_PRESENCE_ENTITY_REGISTRY_ID,
    CONF_SOURCE_DEVICE,
    CONF_UNIQUE_ID,
    DEFAULT_ADAPTER,
    DOMAIN,
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
        reference = data.get(CONF_PRESENCE_ENTITY_REGISTRY_ID) or data.get(
            CONF_PRESENCE_ENTITY
        )
        if (
            isinstance(reference, str)
            and er.async_resolve_entity_id(registry, reference) == presence_entity
        ):
            return True
    return False


class MiotBleBridgeConfigFlow(ConfigFlow, domain=DOMAIN):
    """Create one config entry per virtual radar."""

    VERSION = 1

    def __init__(self) -> None:
        self._source_device_id: str | None = None
        self._source_device_name = ""

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlowWithReload:
        return MiotBleBridgeOptionsFlow()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            device_id = user_input[CONF_SOURCE_DEVICE]
            device = dr.async_get(self.hass).async_get(device_id)
            if device is None:
                errors[CONF_SOURCE_DEVICE] = "device_not_found"
            else:
                presence, _, _ = _device_entities(self.hass, device_id)
                if not presence:
                    errors[CONF_SOURCE_DEVICE] = "no_presence_entities"
                else:
                    self._source_device_id = device_id
                    self._source_device_name = (
                        device.name_by_user or device.name or device_id
                    )
                    return await self.async_step_mapping()
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_SOURCE_DEVICE): selector.DeviceSelector()}
            ),
            errors=errors,
        )

    async def async_step_mapping(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if self._source_device_id is None:
            return await self.async_step_user()
        presence, lights, default_presence = _device_entities(
            self.hass, self._source_device_id
        )
        errors: dict[str, str] = {}
        defaults: dict[str, Any] = {
            CONF_NAME: self._source_device_name,
            CONF_ADAPTER: DEFAULT_ADAPTER,
        }
        if default_presence:
            defaults[CONF_PRESENCE_ENTITY] = default_presence
        if len(lights) == 1:
            defaults[CONF_ILLUMINANCE_ENTITY] = lights[0]
        if user_input is not None:
            data, errors = _validate_mapping(self.hass, user_input)
            if not errors and data[CONF_PRESENCE_ENTITY] not in presence:
                errors[CONF_PRESENCE_ENTITY] = "wrong_device"
            if (
                not errors
                and data[CONF_ILLUMINANCE_ENTITY] is not None
                and data[CONF_ILLUMINANCE_ENTITY] not in lights
            ):
                errors[CONF_ILLUMINANCE_ENTITY] = "wrong_device"
            if not errors:
                if _already_mapped(self.hass, data[CONF_PRESENCE_ENTITY]):
                    errors[CONF_PRESENCE_ENTITY] = "entity_already_mapped"
                else:
                    await self.async_set_unique_id(
                        data[CONF_PRESENCE_ENTITY_REGISTRY_ID]
                        or data[CONF_PRESENCE_ENTITY]
                    )
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title=data[CONF_NAME], data=data)
            defaults = user_input
        return self.async_show_form(
            step_id="mapping",
            data_schema=self.add_suggested_values_to_schema(
                _mapping_schema(presence, lights), defaults
            ),
            description_placeholders={"device": self._source_device_name},
            errors=errors,
        )

    async def async_step_import(self, user_input: dict[str, Any]) -> ConfigFlowResult:
        data, errors = _validate_mapping(self.hass, user_input)
        if errors:
            return self.async_abort(reason="invalid_mapping")
        unique_id = (
            user_input.get(CONF_UNIQUE_ID)
            or data[CONF_PRESENCE_ENTITY_REGISTRY_ID]
            or data[CONF_PRESENCE_ENTITY]
        )
        await self.async_set_unique_id(str(unique_id))
        self._abort_if_unique_id_configured()
        if _already_mapped(self.hass, data[CONF_PRESENCE_ENTITY]):
            return self.async_abort(reason="already_configured")
        return self.async_create_entry(title=data[CONF_NAME], data=data)


class MiotBleBridgeOptionsFlow(OptionsFlowWithReload):
    """Change source entities without resetting the BLE identity."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        defaults = {**self.config_entry.data, **self.config_entry.options}
        if user_input is not None:
            data, errors = _validate_mapping(self.hass, user_input)
            if not errors:
                if _already_mapped(
                    self.hass, data[CONF_PRESENCE_ENTITY], self.config_entry.entry_id
                ):
                    errors[CONF_PRESENCE_ENTITY] = "entity_already_mapped"
                else:
                    self.hass.config_entries.async_update_entry(
                        self.config_entry, title=data[CONF_NAME]
                    )
                    return self.async_create_entry(title="", data=data)
            defaults = user_input
        else:
            registry = er.async_get(self.hass)
            for field, registry_field in (
                (CONF_PRESENCE_ENTITY, CONF_PRESENCE_ENTITY_REGISTRY_ID),
                (CONF_ILLUMINANCE_ENTITY, CONF_ILLUMINANCE_ENTITY_REGISTRY_ID),
            ):
                if reference := defaults.get(registry_field):
                    if entity_id := er.async_resolve_entity_id(registry, reference):
                        defaults[field] = entity_id
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                _mapping_schema(), defaults
            ),
            errors=errors,
        )
