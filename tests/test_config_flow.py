"""Configuration regressions with local registries and no HA or Bluetooth IO."""

from __future__ import annotations

from copy import copy, deepcopy
import importlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import voluptuous as vol


COMPONENT = Path(__file__).parents[1] / "custom_components" / "miot_ble_bridge"


def install_module(name, **attributes):
    module = ModuleType(name)
    module.__dict__.update(attributes)
    module.__path__ = []
    sys.modules[name] = module
    return module


class SelectorStub:
    """Mirror selector boundaries; model validation is the real implementation."""

    def __init__(self, config=None):
        self.config = config or {}

    def __call__(self, value):
        return value


class NumberSelectorStub(SelectorStub):
    def __call__(self, value):
        value = float(value)
        if "min" in self.config and value < self.config["min"]:
            raise vol.Invalid("Value is below the minimum")
        if "max" in self.config and value > self.config["max"]:
            raise vol.Invalid("Value is above the maximum")
        return value


class SelectSelectorStub(SelectorStub):
    def __call__(self, value):
        choices = [item if isinstance(item, str) else item["value"] for item in self.config["options"]]
        return vol.In(choices)(vol.Schema(str)(value))


class AttributeSelectorStub(SelectorStub):
    def __init__(self, config):
        if not isinstance(config.get("entity_id"), str):
            raise vol.Invalid("entity_id is required")
        super().__init__(config)


class EntitySelectorStub(SelectorStub):
    def __call__(self, value):
        value = vol.Schema(str)(value)
        if "." in value and self.config.get("include_entities"):
            vol.In(self.config["include_entities"])(value)
        return value


class FlowStub:
    def __init__(self):
        self.context = {}
        self.handler = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__()

    @property
    def config_entry(self):
        return self.hass.config_entries.async_get_known_entry(self.handler)

    def add_suggested_values_to_schema(self, schema, suggested):
        result = {}
        for marker, validator in schema.schema.items():
            if isinstance(marker, vol.Marker) and marker.schema in suggested:
                marker = copy(marker)
                marker.description = {"suggested_value": suggested[marker.schema]}
            result[marker] = validator
        return vol.Schema(result)


if importlib.util.find_spec("homeassistant") is None:
    install_module("homeassistant")
    install_module("homeassistant.config_entries", ConfigEntry=SimpleNamespace,
                   ConfigFlow=FlowStub, OptionsFlowWithReload=FlowStub, ConfigFlowResult=dict)
    install_module("homeassistant.core", HomeAssistant=SimpleNamespace,
                   callback=lambda function: function, split_entity_id=lambda value: value.split(".", 1))
    install_module("homeassistant.const", STATE_UNKNOWN="unknown", STATE_UNAVAILABLE="unavailable")
    install_module("homeassistant.helpers")
    install_module("homeassistant.helpers.selector", TextSelector=SelectorStub,
                   BooleanSelector=SelectorStub, EntitySelector=EntitySelectorStub,
                   DeviceSelector=SelectorStub, NumberSelector=NumberSelectorStub,
                   SelectSelector=SelectSelectorStub, AttributeSelector=AttributeSelectorStub)
    install_module("homeassistant.helpers.device_registry", async_get=lambda hass: hass.devices)
    install_module("homeassistant.helpers.entity_registry", async_get=lambda hass: hass.registry,
                   RegistryEntry=SimpleNamespace,
                   async_resolve_entity_id=lambda registry, reference: registry.resolve(reference),
                   async_entries_for_device=lambda registry, device_id: [
                       entry for entry in registry.entries.values()
                       if entry.device_id == device_id and not entry.disabled_by
                   ])

PACKAGE = "miot_config_flow_under_test"
if PACKAGE not in sys.modules:
    package = ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package
flow = importlib.import_module(f"{PACKAGE}.config_flow")
models = importlib.import_module(f"{PACKAGE}.models")


class Registry:
    def __init__(self):
        self.entries = {}

    def add(self, entity_id, device_id="device-a", *, device_class=None, name=None, disabled=False):
        entry = SimpleNamespace(entity_id=entity_id, id=f"registry-{len(self.entries)}",
                                device_id=device_id, name=name, original_name=name,
                                device_class=device_class, original_device_class=None,
                                disabled_by="user" if disabled else None)
        self.entries[entity_id] = entry
        return entry

    def resolve(self, reference):
        if isinstance(reference, str) and "." in reference:
            return reference
        return next((entry.entity_id for entry in self.entries.values() if entry.id == reference), None)

    def async_get(self, entity_id):
        return self.entries.get(entity_id)

    def rename(self, entity_id, new_entity_id):
        entry = self.entries.pop(entity_id)
        entry.entity_id = new_entity_id
        self.entries[new_entity_id] = entry


class States:
    def __init__(self):
        self.values = {}

    def get(self, entity_id):
        return self.values.get(entity_id)

    def set(self, entity_id, state, **attributes):
        self.values[entity_id] = SimpleNamespace(state=state, attributes=attributes)


class Entries:
    def __init__(self):
        self.entries = []
        self.updates = []

    def async_entries(self, domain):
        return self.entries

    def async_get_known_entry(self, entry_id):
        return next(entry for entry in self.entries if entry.entry_id == entry_id)

    def async_update_entry(self, entry, **changes):
        self.updates.append((entry.entry_id, changes))
        entry.__dict__.update(changes)


def make_hass():
    devices = {key: SimpleNamespace(name_by_user=name, name=name) for key, name in (
        ("device-a", "餐厅设备"), ("device-b", "卧室设备"),
    )}
    return SimpleNamespace(registry=Registry(), states=States(), config_entries=Entries(),
                           devices=SimpleNamespace(async_get=devices.get))


def model_fixture(model_id, properties=(), *, actions=(), events=(), category="sensor"):
    return SimpleNamespace(model=model_id, name="测试米家设备", pid=1, available=True,
                           category=category,
                           properties=tuple(properties), property_by_key={prop.key: prop for prop in properties},
                           actions=tuple(actions), events=tuple(events))


def property_fixture(piid, **kwargs):
    parameters = {"name": "测试属性", "siid": 2, "piid": piid, "type_code": 1,
                  "default": 0, "entity_domains": ("sensor",)}
    parameters.update(kwargs)
    return models.PropertyDefinition(**parameters)


def configure_handler(handler, hass, *, entry=None):
    handler.hass = hass
    handler.handler = entry.entry_id if entry else flow.DOMAIN
    handler.async_show_form = Mock(side_effect=lambda **kwargs: {"type": "form", **kwargs})
    handler.async_show_menu = Mock(side_effect=lambda **kwargs: {"type": "menu", **kwargs})
    handler.async_create_entry = Mock(side_effect=lambda **kwargs: {"type": "create_entry", **kwargs})
    handler.async_abort = Mock(side_effect=lambda **kwargs: {"type": "abort", **kwargs})
    handler.async_set_unique_id = AsyncMock()
    handler._abort_if_unique_id_configured = Mock()
    return handler


def suggested(form, field):
    marker = next((key for key in form["data_schema"].schema if key == field), None)
    return (marker.description or {}).get("suggested_value") if marker is not None else None


def fields(form):
    return {key.schema for key in form["data_schema"].schema}


def field_selector(form, field):
    return next(value for key, value in form["data_schema"].schema.items() if key == field)


class ConfigFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hass = make_hass()
        for target, replacement in (
            ("async_get", lambda hass: hass.registry),
            ("async_resolve_entity_id", lambda registry, reference: registry.resolve(reference)),
            ("async_entries_for_device", lambda registry, device_id: [
                entry for entry in registry.entries.values()
                if entry.device_id == device_id and not entry.disabled_by
            ]),
        ):
            patcher = patch.object(flow.er, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(flow.dr, "async_get", lambda hass: hass.devices)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.presence = self.hass.registry.add("binary_sensor.presence", device_class="occupancy")
        self.lux = self.hass.registry.add("sensor.lux", device_class="illuminance")
        self.hass.states.set("binary_sensor.presence", "on")
        self.hass.states.set("sensor.lux", "12", unit_of_measurement="lx")
        self.device_choices = [
            {"value": "device-a", "label": "餐厅设备"},
            {"value": "device-b", "label": "卧室设备"},
        ]
        self.entity_choices = {}
        self.recommendations = {
            (models.DEFAULT_MODEL, "2.1078"): "binary_sensor.presence",
            (models.DEFAULT_MODEL, "2.1005"): "sensor.lux",
        }
        for target, replacement in (
            ("category_options", lambda: [dict(option) for option in models.CATEGORY_OPTIONS]),
            ("eligible_devices", lambda hass, model: list(self.device_choices)),
            ("eligible_entities", self.eligible_entities),
            ("eligible_event_entities", lambda hass, model, device_id, allow_other=False:
                self.feature_entities(hass, device_id,
                                      flow._EVENT_DOMAINS if allow_other else {"button", "input_button", "event"},
                                      allow_other)),
            ("eligible_action_entities", lambda hass, model, device_id, allow_other=False:
                self.feature_entities(hass, device_id,
                                      flow._ACTION_DOMAINS if allow_other else {"button", "input_button"},
                                      allow_other)),
            ("recommended_entity", lambda hass, model, prop, device_id:
                self.recommendations.get((model.model, prop.key))),
        ):
            patcher = patch.object(flow, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def eligible_entities(self, hass, model, prop, device_id, allow_other=False):
        key = (model.model, prop.key, device_id, allow_other)
        if key in self.entity_choices:
            return list(self.entity_choices[key])
        return [entry.entity_id for entry in hass.registry.entries.values()
                if not entry.disabled_by and entry.entity_id.split(".", 1)[0] in prop.entity_domains
                and (allow_other or entry.device_id == device_id)]

    def feature_entities(self, hass, device_id, domains, allow_other=False):
        return sorted(entry.entity_id for entry in hass.registry.entries.values()
                      if not entry.disabled_by and entry.entity_id.split(".", 1)[0] in domains
                      and (allow_other or entry.device_id == device_id))

    def handler(self, model=None, *, options_entry=None):
        handler = configure_handler(flow.MiotBleBridgeOptionsFlow() if options_entry else flow.MiotBleBridgeConfigFlow(),
                                    self.hass, entry=options_entry)
        if model:
            handler._model = model
            handler._prepare({"source_device_id": "device-a", "name": "测试设备", "adapter": "hci0"}, prefer_entities=True)
        return handler

    async def advanced_property_details(self, handler, entity_id):
        source = await handler.async_step_property_source({"entity_id": entity_id, "advanced": True})
        self.assertEqual(source["step_id"], "property_entity")
        self.assertFalse(source.get("errors"))
        return await handler.async_step_property_entity({"entity_id": entity_id})

    async def test_category_then_model_then_compatible_device_is_the_setup_order(self):
        handler = self.handler()
        category = models.get_model(models.DEFAULT_MODEL).category
        first = await handler.async_step_user()
        self.assertEqual(fields(first), {"device_type"})
        result = await handler.async_step_user({"device_type": category})
        self.assertEqual(result["step_id"], "model")
        result = await handler.async_step_model({"model": models.DEFAULT_MODEL})
        self.assertEqual(result["step_id"], "device")
        result = await handler.async_step_device({"source_device_id": "device-a"})
        self.assertEqual(result["step_id"], "property_source")
        self.assertEqual(handler._data["name"], "餐厅设备")
        self.assertEqual(handler._data["adapter"], "hci0")

    async def test_unknown_or_ineligible_device_is_rejected(self):
        handler = self.handler()
        await handler.async_step_user({"device_type": models.get_model(models.DEFAULT_MODEL).category})
        await handler.async_step_model({"model": models.DEFAULT_MODEL})
        self.device_choices = [{"value": "device-a", "label": "餐厅设备"}]
        for device_id in ("missing", "device-b"):
            result = await handler.async_step_device({"source_device_id": device_id})
            self.assertTrue(result["errors"].get("source_device_id"))

    async def test_model_selector_lists_only_available_models_of_the_selected_category(self):
        handler = self.handler()
        category = models.get_model(models.DEFAULT_MODEL).category
        await handler.async_step_user({"device_type": category})
        result = await handler.async_step_model()
        selector = field_selector(result, "model")
        available = {model.model for model in models.AVAILABLE_MODELS if model.category == category}
        self.assertEqual({item["value"] for item in selector.config["options"]}, available)
        other_category = next(model for model in models.AVAILABLE_MODELS if model.category != category)
        for model_id in ("unsupported.model", other_category.model):
            result = await handler.async_step_model({"model": model_id})
            self.assertTrue(result["errors"].get("model"))

    async def test_legacy_device_duplicate_is_detected_but_another_model_is_allowed(self):
        self.hass.config_entries.entries.append(SimpleNamespace(
            entry_id="old", unique_id="old-id", data={"presence_entity_registry_id": self.presence.id}, options={},
        ))
        self.assertTrue(flow._device_model_already_mapped(self.hass, "device-a", models.DEFAULT_MODEL))
        self.assertFalse(flow._device_model_already_mapped(self.hass, "device-a", "other.model"))
        handler = self.handler()
        await handler.async_step_user({"device_type": models.get_model(models.DEFAULT_MODEL).category})
        await handler.async_step_model({"model": models.DEFAULT_MODEL})
        result = await handler.async_step_device({"source_device_id": "device-a"})
        self.assertEqual(result["errors"]["source_device_id"], "device_model_already_mapped")

    async def test_virtual_checkbox_opens_only_the_typed_value_question(self):
        prop = property_fixture(1, minimum=0, maximum=10)
        handler = self.handler(model_fixture("fixture", (prop,)))
        first = await handler.async_step_property_source()
        self.assertEqual(first["step_id"], "property_source")
        self.assertEqual(fields(first), {"entity_id", "use_virtual", "advanced"})
        self.assertFalse(suggested(first, "use_virtual"))
        second = await handler.async_step_property_source({"use_virtual": True})
        self.assertEqual(second["step_id"], "property_virtual")
        final = await handler.async_step_property_virtual({"value": 7.0})
        self.assertEqual(final["type"], "menu")
        self.assertEqual(handler._data["property_mappings"]["2.1"], {"source": "virtual", "value": 7})

    async def test_invalid_virtual_range_enum_and_step_do_not_advance(self):
        cases = (
            (property_fixture(1, minimum=0, maximum=10), 11),
            (property_fixture(2, choices=((2, "两分钟"), (5, "五分钟")), derived="present_minutes"), "0"),
            (models.PropertyDefinition(name="温度", siid=2, piid=3, type_code=9, default=0,
                                       minimum=0, maximum=10, step=.5, unit="°C", entity_domains=("sensor",)), .3),
        )
        for prop, value in cases:
            with self.subTest(value=value):
                handler = self.handler(model_fixture("fixture", (prop,)))
                if prop.derived:
                    await handler.async_step_default_properties()
                await handler.async_step_property_source({"use_virtual": True})
                result = await handler.async_step_property_virtual({"value": value})
                self.assertEqual(result["errors"]["value"], "invalid_value")
                self.assertEqual(handler._property_index, 0)

    async def test_virtual_values_are_entry_local_and_create_no_ha_entities(self):
        prop = property_fixture(1, minimum=0, maximum=100, writable=True, entity_domains=())
        first = self.handler(model_fixture("fixture", (prop,)))
        second = self.handler(model_fixture("fixture", (prop,)))
        before = deepcopy(self.hass.states.values)
        await first.async_step_property_source({"use_virtual": True})
        await first.async_step_property_virtual({"value": 75})
        self.assertEqual(second._data["property_mappings"]["2.1"]["source"], "entity")
        self.assertNotIn("value", second._data["property_mappings"]["2.1"])
        self.assertEqual(self.hass.states.values, before)

    async def test_entity_selection_defaults_to_the_device_and_allows_explicit_other_sources(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        self.hass.registry.add("sensor.other", "device-b")
        self.hass.states.set("sensor.other", "8")
        handler = self.handler(model_fixture("fixture", (prop,)))
        form = await handler.async_step_property_source()
        selector = field_selector(form, "entity_id")
        self.assertNotIn("sensor.other", selector.config["include_entities"])
        result = await handler.async_step_property_source({"entity_id": "sensor.other"})
        self.assertTrue(result["errors"].get("entity_id"))
        advanced = await handler.async_step_property_source({"advanced": True})
        self.assertEqual(advanced["step_id"], "property_entity")
        await handler.async_step_property_entity({"use_other_entities": True})
        await handler.async_step_property_entity({"entity_id": "sensor.other", "use_other_entities": True})
        result = await handler.async_step_property_details({})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"]["2.1"]["source"], "entity")

    async def test_property_scope_toggles_with_a_prefilled_entity_refresh_before_details(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        selected = self.hass.registry.add("sensor.selected")
        self.hass.states.set(selected.entity_id, "17")
        self.hass.registry.add("sensor.other", "device-b")
        self.hass.states.set("sensor.other", "8")
        handler = self.handler(model_fixture("fixture", (prop,)))
        handler._data["property_mappings"][prop.key] = {
            "source": "entity", "entity_id": self.lux.entity_id, "entity_registry_id": self.lux.id,
        }
        original = deepcopy(handler._data["property_mappings"])
        changed = await handler.async_step_property_source({"entity_id": selected.entity_id, "advanced": True})
        self.assertEqual(changed["step_id"], "property_entity")
        self.assertEqual(suggested(changed, "entity_id"), selected.entity_id)
        form = await handler.async_step_property_source({"entity_id": "sensor.lux", "advanced": True})
        self.assertEqual(form["step_id"], "property_entity")
        for allow_other in (True, False):
            refreshed = await handler.async_step_property_entity({"entity_id": selected.entity_id,
                                                                   "use_other_entities": allow_other})
            self.assertEqual(refreshed["step_id"], "property_entity")
            self.assertFalse(refreshed.get("errors"))
            self.assertEqual(suggested(refreshed, "entity_id"), selected.entity_id)
            self.assertEqual(suggested(refreshed, "use_other_entities"), allow_other)
            self.assertEqual(refreshed["data_schema"]({})["use_other_entities"], allow_other)
            self.assertEqual("sensor.other" in field_selector(refreshed, "entity_id").config["include_entities"],
                             allow_other)
            self.assertEqual(handler._property_index, 0)
            self.assertEqual(handler._data["property_mappings"], original)
        details = await handler.async_step_property_entity({"entity_id": selected.entity_id, "use_other_entities": False})
        self.assertEqual(details["step_id"], "property_details")
        result = await handler.async_step_property_details({})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"][prop.key]["entity_id"], selected.entity_id)
        self.assertEqual(handler._data["property_mappings"][prop.key]["entity_registry_id"], selected.id)

    async def test_registered_offline_entity_is_accepted_and_uuid_is_stable(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        self.hass.states.values.pop("sensor.lux")
        handler = self.handler(model_fixture("fixture", (prop,)))
        result = await handler.async_step_property_source({"entity_id": self.lux.id})
        self.assertEqual(result["type"], "menu")
        mapping = handler._data["property_mappings"]["2.1"]
        self.assertEqual(mapping["entity_registry_id"], self.lux.id)
        self.hass.registry.rename("sensor.lux", "sensor.renamed")
        self.assertTrue(handler._validate_complete())
        self.assertEqual(mapping["entity_id"], "sensor.renamed")

    async def test_wrong_domain_is_rejected_even_though_selector_filters_are_only_ui(self):
        prop = property_fixture(1, writable=True, entity_domains=("number",))
        handler = self.handler(model_fixture("fixture", (prop,)))
        result = await handler.async_step_property_source({"entity_id": "sensor.lux"})
        self.assertIn("invalid_entity_domain", result["errors"].values())

    async def test_online_attribute_unit_and_control_are_validated_with_runtime_helpers(self):
        self.hass.registry.add("light.lamp")
        self.hass.states.set("light.lamp", "on", brightness=255)
        brightness = property_fixture(1, writable=True, minimum=0, maximum=100,
                                      semantic="brightness", unit="%", entity_domains=("light",))
        handler = self.handler(model_fixture("fixture", (brightness,)))
        form = await handler.async_step_property_source()
        self.assertNotIn("attribute", fields(form))
        result = await handler.async_step_property_source({"entity_id": "light.lamp"})
        self.assertEqual(result["type"], "menu")
        mapping = handler._data["property_mappings"]["2.1"]
        self.assertEqual(flow.read_entity_value(brightness, self.hass.states.get("light.lamp"), mapping), 100)
        delay = property_fixture(2, writable=True, minimum=0, maximum=30, semantic="delay",
                                 entity_domains=("light",))
        handler = self.handler(model_fixture("fixture", (delay,)))
        result = await handler.async_step_property_source({"entity_id": "light.lamp"})
        self.assertTrue(result["errors"])

    async def test_missing_online_attribute_and_incompatible_units_are_rejected(self):
        prop = property_fixture(1, minimum=0, maximum=100, unit="ppm")
        handler = self.handler(model_fixture("fixture", (prop,)))
        advanced = await self.advanced_property_details(handler, "sensor.lux")
        self.assertEqual(advanced["step_id"], "property_details")
        result = await handler.async_step_property_details({"attribute": "missing"})
        self.assertEqual(result["errors"]["base"], "invalid_entity_value")
        result = await handler.async_step_property_details({})
        self.assertEqual(result["errors"]["base"], "invalid_entity_value")

    async def test_select_enum_mapping_is_typed_and_bidirectional_values_are_distinct(self):
        self.hass.registry.add("select.mode")
        self.hass.states.set("select.mode", "auto", options=["auto", "sleep"])
        prop = property_fixture(1, writable=True, choices=((0, "自动"), (1, "睡眠")),
                                entity_domains=("select",))
        handler = self.handler(model_fixture("fixture", (prop,)))
        advanced = await self.advanced_property_details(handler, "select.mode")
        self.assertEqual(advanced["step_id"], "property_details")
        result = await handler.async_step_property_details({"configure_value_map": True})
        self.assertEqual(result["step_id"], "property_value_map")
        await handler.async_step_property_value_map({"state_value": "auto", "value": "0"})
        result = await handler.async_step_property_value_map({"state_value": "sleep", "value": "0"})
        self.assertEqual(result["errors"]["value"], "invalid_value_map")
        result = await handler.async_step_property_value_map({"state_value": "sleep", "value": "1"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"]["2.1"]["value_map"], {"auto": 0, "sleep": 1})

    async def test_legacy_import_preserves_unique_id_and_uses_internal_battery(self):
        handler = self.handler()
        result = await handler.async_step_import({"presence_entity": "binary_sensor.presence",
                                                  "unique_id": "original-device-identity"})
        self.assertEqual(result["type"], "create_entry")
        handler.async_set_unique_id.assert_awaited_once_with("original-device-identity")
        self.assertEqual(result["data"]["model"], models.DEFAULT_MODEL)
        mappings = result["data"]["property_mappings"]
        self.assertEqual(mappings["3.1003"], {"source": "virtual", "value": 100})
        self.assertEqual(mappings["2.1005"], {"source": "virtual", "value": 0.0})
        self.assertEqual(mappings["2.1081"], {"source": "derived"})

    async def test_select_can_map_numeric_ranges_without_a_catalog_choice_list(self):
        self.hass.registry.add("select.mode")
        self.hass.states.set("select.mode", "auto", options=["auto", "sleep"])
        prop = property_fixture(1, writable=True, minimum=0, maximum=4, step=1,
                                entity_domains=("select",))
        handler = self.handler(model_fixture("fixture", (prop,)))
        details = await self.advanced_property_details(handler, "select.mode")
        self.assertIn("configure_value_map", [key.schema for key in details["data_schema"].schema])
        await handler.async_step_property_details({"configure_value_map": True})
        await handler.async_step_property_value_map({"state_value": "auto", "value": 0.0})
        result = await handler.async_step_property_value_map({"state_value": "sleep", "value": 3.0})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"]["2.1"]["value_map"], {"auto": 0, "sleep": 3})

    async def test_smoke2_binary_source_uses_automatic_normal_and_alarm_values(self):
        model = models.get_model("xiaomi.sensor_smoke.yg2")
        prop = model.property_by_key["2.1004"]
        self.hass.registry.add("binary_sensor.smoke", device_class="smoke")
        self.hass.states.set("binary_sensor.smoke", "off")
        handler = self.handler(model)
        result = await handler.async_step_property_source({"entity_id": "binary_sensor.smoke"})
        self.assertEqual(result["step_id"], "property_source")
        self.assertEqual(handler._property_index, 1)
        self.assertNotEqual(result["step_id"], "property_value_map")
        mapping = handler._data["property_mappings"][prop.key]
        self.assertEqual(flow.read_entity_value(prop, self.hass.states.get("binary_sensor.smoke"), mapping), 1)
        self.hass.states.set("binary_sensor.smoke", "on")
        self.assertEqual(flow.read_entity_value(prop, self.hass.states.get("binary_sensor.smoke"), mapping), 2)

    async def test_unknown_or_offline_binary_enum_source_can_be_selected_without_extra_questions(self):
        model = models.get_model("xiaomi.sensor_smoke.yg2")
        self.hass.registry.add("binary_sensor.smoke", device_class="smoke")
        for state in ("unknown", "unavailable", None):
            with self.subTest(state=state):
                if state is None:
                    self.hass.states.values.pop("binary_sensor.smoke", None)
                else:
                    self.hass.states.set("binary_sensor.smoke", state)
                handler = self.handler(model)
                result = await handler.async_step_property_source({"entity_id": "binary_sensor.smoke"})
                self.assertEqual(result["step_id"], "property_source")
                self.assertEqual(handler._property_index, 1)
                mapping = handler._data["property_mappings"]["2.1004"]
                self.assertIsNone(flow.read_entity_value(model.property_by_key["2.1004"],
                                                       self.hass.states.get("binary_sensor.smoke"), mapping))

    async def test_boolean_and_zero_one_binary_enums_do_not_force_state_mapping(self):
        properties = (
            property_fixture(1, choices=((0, "正常"), (1, "告警")), entity_domains=("binary_sensor",)),
            models.PropertyDefinition(name="告警", siid=2, piid=2, type_code=0, default=False,
                                       entity_domains=("binary_sensor",)),
        )
        for prop in properties:
            with self.subTest(type_code=prop.type_code):
                handler = self.handler(model_fixture("fixture", (prop,)))
                form = await handler.async_step_property_source()
                self.assertNotIn("configure_value_map", fields(form))
                result = await handler.async_step_property_source({"entity_id": "binary_sensor.presence"})
                self.assertEqual(result["type"], "menu")

    def old_entry(self, **options):
        entry = SimpleNamespace(entry_id="original-entry", unique_id="original-id", title="餐厅设备",
                                data={"name": "餐厅设备", "adapter": "hci0",
                                      "presence_entity": "binary_sensor.presence",
                                      "presence_entity_registry_id": self.presence.id}, options=options,
                                identity={"mac": "D4:3B:04:5E:2A:10", "did": "blt.3.fixture"})
        self.hass.config_entries.entries.append(entry)
        return entry

    async def test_options_lock_model_and_do_not_mutate_original_data_or_identity(self):
        entry = self.old_entry()
        original = deepcopy(entry.__dict__)
        handler = self.handler(options_entry=entry)
        form = await handler.async_step_init()
        self.assertEqual(form["step_id"], "property_source")
        self.assertNotIn("model", [key.schema for key in form["data_schema"].schema])
        self.assertNotIn("source_device_id", fields(form))
        result = await handler.async_step_init({"model": "different.model"})
        self.assertEqual(result["errors"]["base"], "model_locked")
        self.assertEqual(entry.__dict__, original)

    async def test_options_same_device_keep_legacy_unique_id_and_changed_device_updates_metadata_only(self):
        entry = self.old_entry()
        identity = deepcopy(entry.identity)
        handler = self.handler(options_entry=entry)
        await handler.async_step_init()
        result = await handler._finish_entry()
        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(entry.unique_id, "original-id")
        handler._data["source_device_id"] = "device-b"
        await handler._finish_entry()
        self.assertEqual(entry.unique_id, f"device-b:{models.DEFAULT_MODEL}")
        self.assertEqual(entry.entry_id, "original-entry")
        self.assertEqual(entry.identity, identity)

    async def test_options_duplicate_target_is_rejected_before_property_questions(self):
        entry = self.old_entry()
        self.hass.config_entries.entries.append(SimpleNamespace(entry_id="other", unique_id="other-id",
                                                                data={"model": models.DEFAULT_MODEL,
                                                                      "source_device_id": "device-b"}, options={}))
        handler = self.handler(options_entry=entry)
        result = await handler.async_step_init({"source_device_id": "device-b"})
        self.assertEqual(result["errors"]["source_device_id"], "device_model_already_mapped")

    async def test_action_scripts_require_advanced_and_other_sources_while_domains_are_validated(self):
        action = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        model = model_fixture("fixture", actions=(action,))
        self.hass.registry.add("button.reset")
        self.hass.registry.add("script.reset", None)
        handler = self.handler(model)
        result = await handler.async_step_action({"entity_id": "sensor.lux"})
        self.assertEqual(result["errors"]["entity_id"], "invalid_entity_domain")
        result = await handler.async_step_action({"entity_id": "script.reset"})
        self.assertEqual(result["errors"]["entity_id"], "incompatible_entity")
        advanced = await handler.async_step_action({"advanced": True})
        self.assertEqual(advanced["step_id"], "action_advanced")
        await handler.async_step_action_advanced({"use_other_entities": True})
        result = await handler.async_step_action_advanced({"entity_id": "script.reset", "use_other_entities": True})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["action_mappings"]["2.1"]["entity_id"], "script.reset")

    async def test_action_scope_toggles_with_a_prefilled_entity_refresh_before_saving(self):
        action = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        original = self.hass.registry.add("button.original_reset")
        selected = self.hass.registry.add("button.reset")
        self.hass.registry.add("button.other", "device-b")
        self.hass.registry.add("script.reset", None)
        handler = self.handler(model_fixture("fixture", actions=(action,)))
        saved = {action.key: {"source": "entity", "entity_id": original.entity_id, "entity_registry_id": original.id}}
        handler._data["action_mappings"] = deepcopy(saved)
        changed = await handler.async_step_action({"entity_id": selected.entity_id, "advanced": True})
        self.assertEqual(changed["step_id"], "action_advanced")
        self.assertEqual(suggested(changed, "entity_id"), selected.entity_id)
        form = await handler.async_step_action({"entity_id": original.entity_id, "advanced": True})
        self.assertEqual(form["step_id"], "action_advanced")
        for allow_other in (True, False):
            refreshed = await handler.async_step_action_advanced({"entity_id": "button.reset",
                                                                   "use_virtual": False,
                                                                   "use_other_entities": allow_other})
            self.assertEqual(refreshed["step_id"], "action_advanced")
            self.assertFalse(refreshed.get("errors"))
            self.assertEqual(suggested(refreshed, "entity_id"), "button.reset")
            self.assertEqual(suggested(refreshed, "use_other_entities"), allow_other)
            self.assertEqual(refreshed["data_schema"]({})["use_other_entities"], allow_other)
            ids = field_selector(refreshed, "entity_id").config["include_entities"]
            self.assertEqual("button.other" in ids, allow_other)
            self.assertEqual("script.reset" in ids, allow_other)
            self.assertEqual(handler._action_index, 0)
            self.assertEqual(handler._data["action_mappings"], saved)
        result = await handler.async_step_action_advanced({"entity_id": "button.reset", "use_virtual": False,
                                                            "use_other_entities": False})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["action_mappings"][action.key]["entity_id"], "button.reset")
        self.assertEqual(handler._data["action_mappings"][action.key]["entity_registry_id"], selected.id)

    async def test_button_event_uses_timestamp_changes_and_parameters_are_validated(self):
        prop = property_fixture(1, choices=((0, "单击"), (1, "双击")))
        event = SimpleNamespace(key="2.2", name="点击", argument_keys=("2.1",))
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,), category="button"))
        await handler.async_step_property_source({"use_virtual": True})
        await handler.async_step_property_virtual({"value": "0"})
        self.hass.registry.add("input_button.click")
        await handler.async_step_event({"enabled": True, "advanced": True})
        result = await handler.async_step_event_advanced({"enabled": True, "entity_id": "input_button.click",
                                                          "trigger_value": "on", "custom_arguments": True})
        self.assertEqual(result["step_id"], "event_argument")
        result = await handler.async_step_event_argument({"value": "9"})
        self.assertEqual(result["errors"]["value"], "invalid_value")
        result = await handler.async_step_event_argument({"value": "1"})
        self.assertEqual(result["type"], "menu")
        mapping = handler._data["event_mappings"]["2.2"]
        self.assertEqual(mapping["trigger_value"], "")
        self.assertEqual(mapping["arguments"], {"2.1": 1})
        self.assertTrue(handler._validate_complete())

    async def test_disabled_events_do_not_leave_fake_event_mappings(self):
        event = SimpleNamespace(key="2.1", name="点击", argument_keys=())
        handler = self.handler(model_fixture("fixture", events=(event,), category="button"))
        result = await handler.async_step_event({"enabled": False})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"], {})

    async def test_event_argument_can_read_live_csv_without_changing_the_property_mapping(self):
        prop = models.PropertyDefinition(name="测量结果 CSV", siid=8, piid=1, type_code=10,
                                         default="", spec_visible=False, entity_domains=("sensor",))
        event = SimpleNamespace(key="8.e.1", name="测量完成", argument_keys=("8.1",))
        self.hass.registry.add("input_button.measure")
        source = self.hass.registry.add("sensor.measurement", None)
        csv = "24.50,0,17.30,65.20"
        self.hass.states.set("sensor.measurement", "ready", result=csv)
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
        await handler.async_step_event({"enabled": True, "advanced": True})
        form = await handler.async_step_event_advanced({"enabled": True, "entity_id": "input_button.measure",
                                                        "trigger_value": "", "custom_arguments": True})
        self.assertEqual(suggested(form, "source"), "mapped")
        self.assertNotIsInstance(next(key for key in form["data_schema"].schema if key == "value"), vol.Required)
        result = await handler.async_step_event_argument({"source": "entity"})
        self.assertEqual(result["step_id"], "property_entity")
        await handler.async_step_property_entity({"entity_id": source.id})
        result = await handler.async_step_property_details({"attribute": "result"})
        self.assertEqual(result["type"], "menu")
        argument = handler._data["event_mappings"]["8.e.1"]["arguments"]["8.1"]
        self.assertEqual(argument["source"], "entity")
        self.assertEqual(argument["entity_registry_id"], source.id)
        self.assertEqual(flow.read_entity_value(prop, self.hass.states.get("sensor.measurement"), argument), csv)
        self.assertEqual(handler._data["property_mappings"]["8.1"], {"source": "virtual", "value": ""})
        self.hass.registry.rename("sensor.measurement", "sensor.measurement_new")
        self.hass.states.set("sensor.measurement_new", "ready", result=csv)
        self.assertTrue(handler._validate_complete())
        self.assertEqual(argument["entity_id"], "sensor.measurement_new")

    async def test_unknown_and_registered_offline_event_arguments_remain_unavailable(self):
        prop = models.PropertyDefinition(name="测量结果 CSV", siid=8, piid=1, type_code=10,
                                         default="", spec_visible=False, entity_domains=("sensor",))
        event = SimpleNamespace(key="8.e.1", name="测量完成", argument_keys=("8.1",))
        self.hass.registry.add("input_button.measure")
        source = self.hass.registry.add("sensor.measurement", None)
        for state in ("unknown", "unavailable", None):
            with self.subTest(state=state):
                if state is None:
                    self.hass.states.values.pop("sensor.measurement", None)
                else:
                    self.hass.states.set("sensor.measurement", state)
                handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
                await handler.async_step_event({"enabled": True, "advanced": True})
                await handler.async_step_event_advanced({"enabled": True, "entity_id": "input_button.measure",
                                                         "trigger_value": "", "custom_arguments": True})
                await handler.async_step_event_argument({"source": "entity"})
                await handler.async_step_property_entity({"entity_id": source.id})
                result = await handler.async_step_property_details({})
                self.assertEqual(result["type"], "menu")
                argument = handler._data["event_mappings"]["8.e.1"]["arguments"]["8.1"]
                self.assertIsNone(flow.read_entity_value(prop, self.hass.states.get("sensor.measurement"), argument))
                self.assertTrue(handler._validate_complete())

    async def test_event_argument_can_return_to_the_mapped_property_without_an_override(self):
        prop = property_fixture(1, choices=((0, "单击"), (1, "双击")))
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=("2.1",))
        self.hass.registry.add("input_button.click")
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
        handler._data["event_mappings"][event.key] = {
            "source": "entity", "entity_id": "input_button.click", "trigger_value": "",
            "arguments": {"2.1": 1},
        }
        await handler.async_step_event({"advanced": True})
        form = await handler.async_step_event_advanced({"enabled": True, "entity_id": "input_button.click",
                                                        "trigger_value": "", "custom_arguments": True})
        self.assertEqual(suggested(form, "source"), "virtual")
        await handler.async_step_event_argument({"source": "mapped"})
        self.assertNotIn("2.1", handler._data["event_mappings"][event.key]["arguments"])

    async def test_ha_event_entities_default_to_timestamp_changes(self):
        self.hass.registry.add("event.remote")
        self.hass.states.set("event.remote", "2026-11-24T10:00:00+08:00", event_type="single_press")
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=())
        handler = self.handler(model_fixture("fixture", events=(event,), category="button"))
        await handler.async_step_event({"entity_id": "event.remote"})
        self.assertEqual(handler._data["event_mappings"][event.key]["trigger_value"], "")

    async def test_button_without_ordinary_properties_opens_an_enabled_event_question(self):
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=())
        self.hass.registry.add("input_button.click")
        self.hass.registry.add("event.other", "device-b")
        handler = self.handler(model_fixture("fixture", events=(event,), category="button"))
        form = await handler.async_step_properties()
        self.assertEqual(form["step_id"], "event")
        self.assertEqual(fields(form), {"entity_id", "enabled", "advanced"})
        self.assertEqual(field_selector(form, "entity_id").config["include_entities"], ["input_button.click"])
        self.assertEqual(suggested(form, "entity_id"), "input_button.click")
        self.assertTrue(suggested(form, "enabled"))
        self.assertFalse(suggested(form, "advanced"))
        self.assertEqual(form["data_schema"]({}), {"enabled": True, "advanced": False})
        self.assertNotIsInstance(next(key for key in form["data_schema"].schema if key == "entity_id"), vol.Required)
        result = await handler.async_step_event({"entity_id": "input_button.click"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"][event.key]["trigger_value"], "")

    async def test_basic_event_sources_are_device_limited_and_other_entities_require_advanced(self):
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=())
        self.hass.registry.add("input_button.click")
        self.hass.registry.add("event.other", "device-b")
        handler = self.handler(model_fixture("fixture", events=(event,), category="button"))
        result = await handler.async_step_event({"entity_id": "event.other"})
        self.assertEqual(result["errors"]["entity_id"], "incompatible_entity")
        advanced = await handler.async_step_event({"enabled": True, "advanced": True})
        self.assertEqual(advanced["step_id"], "event_advanced")
        self.assertEqual(fields(advanced), {"entity_id", "enabled", "use_other_entities", "trigger_value"})
        self.assertEqual(field_selector(advanced, "entity_id").config["include_entities"], ["input_button.click"])
        expanded = await handler.async_step_event_advanced({"enabled": True, "use_other_entities": True})
        self.assertEqual(expanded["step_id"], "event_advanced")
        self.assertIn("event.other", field_selector(expanded, "entity_id").config["include_entities"])
        result = await handler.async_step_event_advanced({"enabled": True, "entity_id": "event.other",
                                                          "use_other_entities": True, "trigger_value": ""})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"][event.key]["entity_id"], "event.other")

    async def test_event_scope_toggles_with_a_prefilled_entity_refresh_before_saving(self):
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=())
        original = self.hass.registry.add("input_button.original_click")
        selected = self.hass.registry.add("input_button.click")
        self.hass.registry.add("event.other", "device-b")
        handler = self.handler(model_fixture("fixture", events=(event,), category="button"))
        saved = {event.key: {"source": "entity", "entity_id": original.entity_id, "entity_registry_id": original.id,
                             "trigger_value": ""}}
        handler._data["event_mappings"] = deepcopy(saved)
        changed = await handler.async_step_event({"enabled": True, "entity_id": selected.entity_id, "advanced": True})
        self.assertEqual(changed["step_id"], "event_advanced")
        self.assertEqual(suggested(changed, "entity_id"), selected.entity_id)
        form = await handler.async_step_event({"enabled": True, "entity_id": original.entity_id, "advanced": True})
        self.assertEqual(form["step_id"], "event_advanced")
        for allow_other in (True, False):
            refreshed = await handler.async_step_event_advanced({"enabled": True, "entity_id": "input_button.click",
                                                                  "use_other_entities": allow_other})
            self.assertEqual(refreshed["step_id"], "event_advanced")
            self.assertFalse(refreshed.get("errors"))
            self.assertEqual(suggested(refreshed, "entity_id"), "input_button.click")
            self.assertTrue(suggested(refreshed, "enabled"))
            self.assertEqual(suggested(refreshed, "use_other_entities"), allow_other)
            self.assertEqual(refreshed["data_schema"]({})["use_other_entities"], allow_other)
            self.assertEqual("event.other" in field_selector(refreshed, "entity_id").config["include_entities"],
                             allow_other)
            self.assertEqual(handler._event_index, 0)
            self.assertEqual(handler._data["event_mappings"], saved)
        result = await handler.async_step_event_advanced({"enabled": True, "entity_id": "input_button.click",
                                                           "use_other_entities": False})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"][event.key]["entity_id"], "input_button.click")
        self.assertEqual(handler._data["event_mappings"][event.key]["entity_registry_id"], selected.id)

    async def test_non_button_events_start_disabled_and_require_explicit_enabling(self):
        event = SimpleNamespace(key="2.e.1", name="测量完成", argument_keys=())
        self.hass.registry.add("input_button.measure")
        handler = self.handler(model_fixture("fixture", events=(event,)))
        form = await handler.async_step_event()
        self.assertFalse(suggested(form, "enabled"))
        self.assertFalse(form["data_schema"]({})["enabled"])
        self.assertFalse(suggested(form, "advanced"))
        result = await handler.async_step_event({"enabled": True, "entity_id": "input_button.measure"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"][event.key]["entity_id"], "input_button.measure")

    async def test_no_event_candidate_omits_the_picker_without_creating_a_fake_source(self):
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=())
        handler = self.handler(model_fixture("fixture", events=(event,), category="button"))
        form = await handler.async_step_event()
        self.assertEqual(fields(form), {"enabled", "advanced"})
        self.assertTrue(suggested(form, "enabled"))
        result = await handler.async_step_event({"enabled": True})
        self.assertEqual(result["step_id"], "event")
        self.assertTrue(result["errors"])
        self.assertEqual(handler._event_index, 0)
        self.assertEqual(handler._data["event_mappings"], {})

    async def test_advanced_event_keeps_the_enabled_choice_from_the_basic_question(self):
        event = SimpleNamespace(key="2.e.1", name="测量完成", argument_keys=())
        self.hass.registry.add("input_button.measure")
        handler = self.handler(model_fixture("fixture", events=(event,)))
        form = await handler.async_step_event({"enabled": True, "advanced": True})
        self.assertEqual(form["step_id"], "event_advanced")
        self.assertTrue(suggested(form, "enabled"))
        self.assertTrue(form["data_schema"]({})["enabled"])

    async def test_basic_event_preserves_saved_arguments_without_asking_for_them(self):
        prop = property_fixture(1, choices=((0, "单击"), (1, "双击")), spec_visible=False)
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=(prop.key,))
        source = self.hass.registry.add("input_button.click")
        mapping = {"source": "entity", "entity_id": source.entity_id, "entity_registry_id": source.id,
                   "trigger_value": "", "arguments": {prop.key: 1}}
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,), category="button"))
        handler._data["event_mappings"][event.key] = deepcopy(mapping)
        form = await handler.async_step_event()
        self.assertNotIn("custom_arguments", fields(form))
        result = await handler.async_step_event({"entity_id": source.entity_id})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"][event.key], mapping)
        self.assertEqual(handler._event_index, 1)

    async def test_actions_start_with_optional_entities_and_unchecked_virtual_and_advanced(self):
        first = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        second = SimpleNamespace(key="2.2", name="备用动作", input_keys=(), output_keys=())
        self.hass.registry.add("button.reset")
        self.hass.registry.add("button.other", "device-b")
        handler = self.handler(model_fixture("fixture", actions=(first, second)))
        form = await handler.async_step_action()
        self.assertEqual(fields(form), {"entity_id", "use_virtual", "advanced"})
        self.assertEqual(field_selector(form, "entity_id").config["include_entities"], ["button.reset"])
        self.assertEqual(form["data_schema"]({}), {"use_virtual": False, "advanced": False})
        self.assertFalse(suggested(form, "use_virtual"))
        self.assertFalse(suggested(form, "advanced"))
        self.assertNotIsInstance(next(key for key in form["data_schema"].schema if key == "entity_id"), vol.Required)
        result = await handler.async_step_action({"entity_id": "button.reset"})
        self.assertEqual(result["step_id"], "action")
        self.assertEqual(handler._action_index, 1)
        self.assertEqual(handler._data["action_mappings"][first.key]["entity_id"], "button.reset")
        result = await handler.async_step_action({"use_virtual": True})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["action_mappings"][second.key], {"source": "virtual"})

    async def test_saved_virtual_actions_remain_checked(self):
        action = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        handler = self.handler(model_fixture("fixture", actions=(action,)))
        handler._data["action_mappings"][action.key] = {"source": "virtual"}
        form = await handler.async_step_action()
        self.assertTrue(suggested(form, "use_virtual"))
        self.assertTrue(form["data_schema"]({})["use_virtual"])
        result = await handler.async_step_action({"use_virtual": True})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["action_mappings"][action.key], {"source": "virtual"})

    async def test_action_advanced_keeps_the_virtual_choice_from_the_basic_question(self):
        action = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        handler = self.handler(model_fixture("fixture", actions=(action,)))
        form = await handler.async_step_action({"use_virtual": True, "advanced": True})
        self.assertEqual(form["step_id"], "action_advanced")
        self.assertTrue(suggested(form, "use_virtual"))
        default_input = form["data_schema"]({})
        self.assertTrue(default_input["use_virtual"])
        result = await handler.async_step_action_advanced(default_input)
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["action_mappings"][action.key], {"source": "virtual"})

    async def test_no_action_candidate_omits_the_picker_and_leaves_virtual_unchecked(self):
        action = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        handler = self.handler(model_fixture("fixture", actions=(action,)))
        form = await handler.async_step_action()
        self.assertEqual(fields(form), {"use_virtual", "advanced"})
        self.assertFalse(suggested(form, "use_virtual"))
        self.assertFalse(suggested(form, "advanced"))
        result = await handler.async_step_action({})
        self.assertEqual(result["step_id"], "action")
        self.assertTrue(result["errors"])
        self.assertEqual(handler._action_index, 0)
        self.assertEqual(handler._data["action_mappings"], {})

    async def test_final_duplicate_guard_handles_an_entry_created_during_the_wizard(self):
        handler = self.handler()
        handler._prepare({"source_device_id": "device-a", "name": "设备", "adapter": "hci0"})
        self.hass.config_entries.entries.append(SimpleNamespace(entry_id="raced", data={"source_device_id": "device-a",
                                                                "model": models.DEFAULT_MODEL}, options={}))
        result = await handler._finish_entry()
        self.assertEqual(result["reason"], "already_configured")
        handler.async_create_entry.assert_not_called()

    async def test_hidden_metadata_is_not_asked_or_automatically_mapped_but_motion_presence_is(self):
        serial = models.PropertyDefinition(name="SN", siid=1, piid=1, type_code=10, default="runtime",
                                           semantic="sn", spec_visible=False, entity_domains=("sensor",))
        presence = property_fixture(2, name="移动状态", spec_visible=False, semantic="presence",
                                    entity_domains=("binary_sensor",), minimum=0, maximum=1)
        placeholder = models.PropertyDefinition(name="兼容空值", siid=8, piid=2, type_code=10, default="",
                                                semantic="internal_placeholder", spec_visible=True)
        self.recommendations[("fixture", presence.key)] = "binary_sensor.presence"
        handler = self.handler(model_fixture("fixture", (serial, presence, placeholder)))
        handler._prepare(handler._data, prefer_entities=True)
        form = await handler.async_step_properties()
        self.assertEqual(form["description_placeholders"]["property"], "移动状态")
        self.assertEqual(form["description_placeholders"]["total"], "1")
        self.assertEqual(handler._data["property_mappings"]["1.1"], {"source": "virtual", "value": "runtime"})
        self.assertEqual(handler._data["property_mappings"]["8.2"], {"source": "virtual", "value": ""})
        self.assertEqual(handler._data["property_mappings"]["2.2"]["entity_id"], "binary_sensor.presence")

    async def test_all_available_models_can_complete_the_public_virtual_property_wizard(self):
        for model in models.AVAILABLE_MODELS:
            with self.subTest(model=model.model):
                handler = self.handler(model)
                self.assertEqual(handler._properties, tuple(
                    prop for prop in model.properties
                    if (prop.spec_visible or prop.semantic == "presence")
                    and prop.semantic != "internal_placeholder" and not prop.alias_of
                    and not prop.derived and prop.semantic not in {"battery", "battery_status"}
                ))
                await handler.async_step_properties()
                for prop in handler._properties:
                    await handler.async_step_property_source({"use_virtual": True})
                    await handler.async_step_property_virtual({"value": flow._selector_value(prop, flow._default_value(prop))})
                self.assertEqual(handler._property_index, len(handler._properties))
                self.assertTrue(handler._validate_complete())

    async def test_getter_aliases_are_not_asked_or_automatically_mapped(self):
        canonical = property_fixture(1, name="公开属性", minimum=0, maximum=100)
        alias = property_fixture(2, name="兼容 getter", alias_of="2.1", notify=False, spec_visible=True)
        self.recommendations[("fixture", canonical.key)] = "sensor.lux"
        handler = self.handler(model_fixture("fixture", (canonical, alias)))
        handler._prepare(handler._data, prefer_entities=True)
        form = await handler.async_step_properties()
        self.assertEqual(handler._properties, (canonical,))
        self.assertEqual(form["description_placeholders"]["total"], "1")
        self.assertEqual(handler._data["property_mappings"]["2.2"], {"source": "virtual", "value": 0})
        self.assertEqual(handler._data["property_mappings"]["2.1"]["entity_id"], "sensor.lux")

    async def test_real_entity_and_unchecked_boxes_are_the_new_ordinary_defaults(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        self.recommendations[("fixture", prop.key)] = "sensor.lux"
        handler = self.handler(model_fixture("fixture", (prop,)))
        form = await handler.async_step_property_source()
        self.assertEqual(fields(form), {"entity_id", "use_virtual", "advanced"})
        self.assertEqual(suggested(form, "entity_id"), "sensor.lux")
        self.assertEqual(handler._data["property_mappings"][prop.key]["source"], "entity")
        for field in ("use_virtual", "advanced"):
            self.assertFalse(suggested(form, field))
            marker = next(key for key in form["data_schema"].schema if key == field)
            self.assertFalse(marker.default())
        self.assertNotIsInstance(next(key for key in form["data_schema"].schema if key == "entity_id"), vol.Required)
        self.assertFalse(form["data_schema"]({"use_virtual": True})["advanced"])

    async def test_no_compatible_entity_does_not_select_virtual_or_show_an_unfiltered_picker(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        self.entity_choices[("fixture", prop.key, "device-a", False)] = []
        handler = self.handler(model_fixture("fixture", (prop,)))
        form = await handler.async_step_property_source()
        self.assertNotIn("entity_id", fields(form))
        self.assertFalse(suggested(form, "use_virtual"))
        self.assertFalse(suggested(form, "advanced"))
        self.assertEqual(handler._data["property_mappings"][prop.key], {"source": "entity"})
        result = await handler.async_step_property_source({})
        self.assertEqual(result["errors"]["base"], "no_compatible_entity")
        self.assertEqual(handler._property_index, 0)
        result = await handler.async_step_property_source({"use_virtual": True})
        self.assertEqual(result["step_id"], "property_virtual")

    async def test_one_entity_submission_moves_directly_to_the_next_property(self):
        first = property_fixture(1, minimum=0, maximum=100)
        second = property_fixture(2, minimum=0, maximum=100)
        handler = self.handler(model_fixture("fixture", (first, second)))
        result = await handler.async_step_property_source({"entity_id": "sensor.lux"})
        self.assertEqual(result["step_id"], "property_source")
        self.assertEqual(handler._property_index, 1)
        self.assertEqual(handler._data["property_mappings"][first.key]["entity_id"], "sensor.lux")
        self.assertNotIn("attribute", fields(result))
        self.assertNotIn("configure_value_map", fields(result))
        self.assertTrue(all(call.kwargs["step_id"] == "property_source" for call in handler.async_show_form.call_args_list))

    async def test_only_explicit_advanced_opens_attribute_configuration(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        handler = self.handler(model_fixture("fixture", (prop,)))
        normal = await handler.async_step_property_source()
        self.assertNotIn("attribute", fields(normal))
        advanced = await handler.async_step_property_source({"entity_id": "sensor.lux", "advanced": True})
        self.assertEqual(advanced["step_id"], "property_entity")
        self.assertIn("use_other_entities", fields(advanced))
        self.assertEqual(suggested(advanced, "entity_id"), "sensor.lux")
        self.assertNotIn("attribute", fields(advanced))
        details = await handler.async_step_property_entity(advanced["data_schema"]({"entity_id": "sensor.lux"}))
        self.assertEqual(details["step_id"], "property_details")
        self.assertIn("attribute", fields(details))
        self.assertEqual(handler._property_index, 0)

    async def test_off_light_can_use_automatic_brightness_without_an_attribute_question(self):
        self.hass.registry.add("light.off_lamp")
        self.hass.states.set("light.off_lamp", "off")
        prop = property_fixture(1, writable=True, minimum=0, maximum=100,
                                semantic="brightness", unit="%", entity_domains=("light",))
        handler = self.handler(model_fixture("fixture", (prop,)))
        result = await handler.async_step_property_source({"entity_id": "light.off_lamp"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"][prop.key]["entity_id"], "light.off_lamp")
        self.assertNotIn("attribute", handler._data["property_mappings"][prop.key])

    async def test_light_advanced_defaults_keep_automatic_attributes_implicit(self):
        self.hass.registry.add("light.lamp")
        brightness = property_fixture(1, writable=True, minimum=0, maximum=100,
                                      semantic="brightness", unit="%", entity_domains=("light",))
        color_temp = next(prop for model in models.AVAILABLE_MODELS for prop in model.properties
                          if prop.semantic == "color_temp")
        for prop, expected in ((brightness, 100), (color_temp, 4000)):
            for lamp_state in ("off", "on"):
                with self.subTest(semantic=prop.semantic, state=lamp_state):
                    attributes = {"brightness": 255, "color_temp_kelvin": 4000} if lamp_state == "on" else {}
                    self.hass.states.set("light.lamp", lamp_state, **attributes)
                    handler = self.handler(model_fixture("fixture", (prop,)))
                    form = await self.advanced_property_details(handler, "light.lamp")
                    self.assertEqual(form["step_id"], "property_details")
                    submitted = form["data_schema"]({})
                    if (attribute := suggested(form, "attribute")) is not None:
                        submitted["attribute"] = attribute
                    result = await handler.async_step_property_details(submitted)
                    self.assertFalse(result.get("errors"))
                    self.assertEqual(result["type"], "menu")
                    self.assertIsNone(suggested(form, "attribute"))
                    mapping = handler._data["property_mappings"][prop.key]
                    self.assertNotIn("attribute", mapping)
                    self.assertEqual(flow.read_entity_value(prop, self.hass.states.get("light.lamp"), mapping),
                                     expected if lamp_state == "on" else None)
                    if lamp_state == "off":
                        explicit = self.handler(model_fixture("fixture", (prop,)))
                        await self.advanced_property_details(explicit, "light.lamp")
                        attribute = flow.effective_attribute(prop, "light.lamp", {}, self.hass.states.get("light.lamp"))
                        rejected = await explicit.async_step_property_details({"attribute": attribute})
                        self.assertEqual(rejected["errors"]["base"], "invalid_entity_value")
                        self.assertEqual(explicit._property_index, 0)

    async def test_options_preserve_existing_virtual_values_and_their_checkbox(self):
        entry = self.old_entry(property_mappings={"2.1078": {"source": "virtual", "value": 1}})
        original = deepcopy(entry.__dict__)
        handler = self.handler(options_entry=entry)
        form = await handler.async_step_init()
        self.assertEqual(form["step_id"], "property_source")
        self.assertTrue(suggested(form, "use_virtual"))
        value_form = await handler.async_step_property_source({"use_virtual": True})
        self.assertEqual(suggested(value_form, "value"), "1")
        self.assertEqual(entry.__dict__, original)

    async def test_options_keep_saved_advanced_keys_when_the_entity_is_unchanged(self):
        mapping = {"source": "entity", "entity_id": "binary_sensor.presence",
                   "entity_registry_id": self.presence.id, "attribute": "detected",
                   "invert": True, "value_map": {"on": 1, "off": 0}}
        self.hass.states.set("binary_sensor.presence", "on", detected="on")
        entry = self.old_entry(property_mappings={"2.1078": deepcopy(mapping)})
        handler = self.handler(options_entry=entry)
        form = await handler.async_step_init()
        self.assertFalse(suggested(form, "advanced"))
        result = await handler.async_step_property_source({"entity_id": self.presence.id})
        self.assertEqual(result["step_id"], "property_source")
        self.assertEqual(handler._data["property_mappings"]["2.1078"], mapping)
        self.assertEqual(entry.options["property_mappings"]["2.1078"], mapping)

    async def test_changing_the_entity_discards_the_previous_attribute_invert_and_value_map(self):
        mapping = {"source": "entity", "entity_id": "binary_sensor.presence",
                   "entity_registry_id": self.presence.id, "attribute": "detected",
                   "invert": True, "value_map": {"on": 1, "off": 0}}
        self.hass.registry.add("binary_sensor.new_presence", device_class="occupancy")
        self.hass.states.set("binary_sensor.new_presence", "off")
        entry = self.old_entry(property_mappings={"2.1078": deepcopy(mapping)})
        handler = self.handler(options_entry=entry)
        await handler.async_step_init()
        result = await handler.async_step_property_source({"entity_id": "binary_sensor.new_presence"})
        self.assertEqual(result["step_id"], "property_source")
        updated = handler._data["property_mappings"]["2.1078"]
        self.assertEqual(updated["entity_id"], "binary_sensor.new_presence")
        for field in ("attribute", "invert", "value_map"):
            self.assertNotIn(field, updated)
        self.assertEqual(entry.options["property_mappings"]["2.1078"], mapping)

    async def test_automatic_battery_and_duration_defaults_are_skipped_but_editable(self):
        handler = self.handler(models.get_model(models.DEFAULT_MODEL))
        await handler.async_step_properties()
        keys = {prop.key for prop in handler._properties}
        self.assertNotIn("3.1003", keys)
        self.assertNotIn("2.1081", keys)
        self.assertNotIn("2.1082", keys)
        self.assertEqual(handler._data["property_mappings"]["3.1003"], {"source": "virtual", "value": 100})
        self.assertEqual(handler._data["property_mappings"]["2.1081"], {"source": "derived"})
        menu = await handler.async_step_features()
        self.assertIn("default_properties", menu["menu_options"])
        advanced = await handler.async_step_default_properties()
        self.assertIn("use_derived", fields(advanced))
        self.assertTrue(suggested(advanced, "use_derived"))

    async def test_existing_duration_entity_mapping_remains_a_question_and_is_not_replaced(self):
        source = self.hass.registry.add("sensor.duration", device_class="duration")
        self.hass.states.set("sensor.duration", "2", unit_of_measurement="min")
        mapping = {"source": "entity", "entity_id": source.entity_id, "entity_registry_id": source.id}
        entry = self.old_entry(property_mappings={"2.1081": deepcopy(mapping)})
        handler = self.handler(options_entry=entry)
        await handler.async_step_init()
        self.assertIn("2.1081", {prop.key for prop in handler._properties})
        self.assertEqual(handler._data["property_mappings"]["2.1081"], mapping)

    async def test_both_contact_models_automatically_convert_open_and_closed_states(self):
        source = self.hass.registry.add("binary_sensor.door", device_class="door")
        for model_id in ("isa.magnet.dw2hl", "xiaomi.magnet.03"):
            with self.subTest(model=model_id):
                model = models.get_model(model_id)
                prop = next(prop for prop in model.properties if prop.semantic == "contact")
                self.hass.states.set(source.entity_id, "on")
                handler = self.handler(model)
                result = await handler.async_step_property_source({"entity_id": source.entity_id})
                self.assertFalse(result.get("errors"))
                mapping = handler._data["property_mappings"][prop.key]
                self.assertNotIn("invert", mapping)
                self.assertFalse(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), mapping))
                self.hass.states.set(source.entity_id, "off")
                self.assertTrue(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), mapping))

    async def test_contact_advanced_defaults_preserve_the_automatic_polarity(self):
        model = models.get_model("isa.magnet.dw2hl")
        prop = next(prop for prop in model.properties if prop.semantic == "contact")
        source = self.hass.registry.add("binary_sensor.door", device_class="door")
        self.hass.states.set(source.entity_id, "on")
        handler = self.handler(model)
        form = await self.advanced_property_details(handler, source.entity_id)
        self.assertEqual(form["step_id"], "property_details")
        self.assertTrue(suggested(form, "invert"))
        default_input = form["data_schema"]({})
        self.assertTrue(default_input["invert"])
        result = await handler.async_step_property_details(default_input)
        self.assertFalse(result.get("errors"))
        mapping = handler._data["property_mappings"][prop.key]
        self.assertFalse(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), mapping))
        self.hass.states.set(source.entity_id, "off")
        self.assertTrue(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), mapping))

    async def test_contact_options_keep_explicit_inversion_in_the_advanced_defaults(self):
        model = models.get_model("isa.magnet.dw2hl")
        prop = next(prop for prop in model.properties if prop.semantic == "contact")
        source = self.hass.registry.add("binary_sensor.door", device_class="door")
        self.hass.states.set(source.entity_id, "on")
        for invert in (False, True):
            with self.subTest(invert=invert):
                mapping = {"source": "entity", "entity_id": source.entity_id, "entity_registry_id": source.id,
                           "invert": invert}
                entry = self.old_entry(property_mappings={prop.key: deepcopy(mapping)})
                entry.entry_id = f"contact-invert-{invert}"
                entry.data.update({"model": model.model, "source_device_id": "device-a"})
                handler = self.handler(options_entry=entry)
                await handler.async_step_init()
                form = await self.advanced_property_details(handler, source.entity_id)
                self.assertEqual(suggested(form, "invert"), invert)
                default_input = form["data_schema"]({})
                self.assertEqual(default_input["invert"], invert)
                await handler.async_step_property_details(default_input)
                self.assertEqual(handler._data["property_mappings"][prop.key], mapping)
                self.assertEqual(entry.options["property_mappings"][prop.key], mapping)

    async def test_contact_options_keep_a_saved_value_map_without_automatic_double_inversion(self):
        model = models.get_model("isa.magnet.dw2hl")
        prop = next(prop for prop in model.properties if prop.semantic == "contact")
        source = self.hass.registry.add("binary_sensor.door", device_class="door")
        self.hass.states.set(source.entity_id, "on")
        value_map = {"on": True, "off": False}
        mapping = {"source": "entity", "entity_id": source.entity_id, "entity_registry_id": source.id,
                   "value_map": deepcopy(value_map)}
        entry = self.old_entry(property_mappings={prop.key: deepcopy(mapping)})
        entry.data.update({"model": model.model, "source_device_id": "device-a"})
        handler = self.handler(options_entry=entry)
        await handler.async_step_init()
        form = await self.advanced_property_details(handler, source.entity_id)
        self.assertFalse(suggested(form, "invert"))
        default_input = form["data_schema"]({})
        self.assertFalse(default_input["invert"])
        result = await handler.async_step_property_details(default_input)
        for _ in value_map:
            if result.get("step_id") != "property_value_map":
                break
            result = await handler.async_step_property_value_map({"state_value": suggested(result, "state_value"),
                                                                   "value": suggested(result, "value")})
            self.assertFalse(result.get("errors"))
        self.assertNotEqual(result.get("step_id"), "property_value_map")
        saved = handler._data["property_mappings"][prop.key]
        self.assertEqual(saved["value_map"], value_map)
        self.assertFalse(saved.get("invert", False))
        self.assertTrue(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), saved))
        self.hass.states.set(source.entity_id, "off")
        self.assertFalse(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), saved))
        self.assertEqual(entry.options["property_mappings"][prop.key], mapping)

    async def test_feature_settings_change_metadata_without_resetting_selected_mappings(self):
        first = property_fixture(1, minimum=0, maximum=100)
        second = property_fixture(2, minimum=0, maximum=100)
        self.hass.registry.add("sensor.selected")
        self.hass.states.set("sensor.selected", "17")
        self.recommendations[("fixture", first.key)] = "sensor.lux"
        handler = self.handler(model_fixture("fixture", (first, second)))
        await handler.async_step_property_source({"entity_id": "sensor.selected"})
        await handler.async_step_property_source({"use_virtual": True})
        features = await handler.async_step_property_virtual({"value": 37})
        self.assertEqual(features["step_id"], "features")
        self.assertIn("settings", features["menu_options"])
        mappings = deepcopy(handler._data["property_mappings"])
        settings = await handler.async_step_settings()
        self.assertEqual(settings["step_id"], "settings")
        result = await handler.async_step_settings({"name": "客厅设备", "adapter": "hci1"})
        self.assertEqual(result["step_id"], "features")
        self.assertEqual(handler._data["name"], "客厅设备")
        self.assertEqual(handler._data["adapter"], "hci1")
        self.assertEqual(handler._data["property_mappings"], mappings)
        self.assertEqual(handler._property_index, 2)

    async def test_options_keep_an_explicit_attribute_source_excluded_by_new_recommendations(self):
        prop = models.PropertyDefinition(name="温度", siid=2, piid=1, type_code=9, default=0,
                                         semantic="temperature", minimum=-40, maximum=125,
                                         unit="°C", entity_domains=("sensor",))
        model = model_fixture("fixture", (prop,))
        source = self.hass.registry.add("sensor.power", device_class="power")
        self.hass.registry.add("sensor.other_power", "device-b", device_class="power")
        self.hass.states.set(source.entity_id, "12", unit_of_measurement="W", temperature=25)
        self.hass.states.set("sensor.other_power", "13", unit_of_measurement="W", temperature=26)
        mapping = {"source": "entity", "entity_id": source.entity_id, "entity_registry_id": source.id,
                   "attribute": "temperature"}
        self.assertEqual(flow.read_entity_value(prop, self.hass.states.get(source.entity_id), mapping), 25)
        self.entity_choices[(model.model, prop.key, "device-a", False)] = []
        self.entity_choices[(model.model, prop.key, "device-a", True)] = []
        entry = self.old_entry(property_mappings={prop.key: deepcopy(mapping)})
        entry.data.update({"model": model.model, "source_device_id": "device-a"})
        original = deepcopy(entry.__dict__)
        handler = self.handler(options_entry=entry)
        with patch.object(flow, "get_model", return_value=model):
            await handler.async_step_init()
        advanced = await handler.async_step_property_source({"advanced": True})
        self.assertEqual(advanced["step_id"], "property_entity")
        self.assertIn("entity_id", fields(advanced))
        self.assertEqual(field_selector(advanced, "entity_id").config["include_entities"], [source.entity_id])
        rejected = await handler.async_step_property_entity({"entity_id": "sensor.other_power"})
        self.assertEqual(rejected["errors"]["entity_id"], "incompatible_entity")
        details = await handler.async_step_property_entity({"entity_id": source.id})
        self.assertEqual(details["step_id"], "property_details")
        self.assertEqual(suggested(details, "attribute"), "temperature")
        result = await handler.async_step_property_details({"attribute": "temperature"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"][prop.key], mapping)
        self.assertEqual(entry.__dict__, original)


class TranslationTests(unittest.TestCase):
    def test_translations_match_and_have_no_bom(self):
        original = COMPONENT.joinpath("strings.json").read_bytes()
        chinese = COMPONENT.joinpath("translations", "zh-Hans.json").read_bytes()
        self.assertFalse(original.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(original, chinese)
        document = json.loads(original.decode("utf-8"))
        for step in ("property_source", "property_virtual", "property_entity", "property_details",
                     "property_value_map", "features", "action", "action_advanced", "event",
                     "event_advanced", "event_argument", "finish"):
            self.assertIn(step, document["config"]["step"])
            self.assertIn(step, document["options"]["step"])
        self.assertIn("default_properties", document["config"]["step"]["features"]["menu_options"])
        self.assertIn("default_properties", document["options"]["step"]["features"]["menu_options"])


if __name__ == "__main__":
    unittest.main()
