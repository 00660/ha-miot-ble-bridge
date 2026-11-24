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
    install_module("homeassistant.helpers")
    install_module("homeassistant.helpers.selector", TextSelector=SelectorStub,
                   BooleanSelector=SelectorStub, EntitySelector=SelectorStub,
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


def model_fixture(model_id, properties=(), *, actions=(), events=()):
    return SimpleNamespace(model=model_id, name="测试米家设备", pid=1, available=True,
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

    def handler(self, model=None, *, options_entry=None):
        handler = configure_handler(flow.MiotBleBridgeOptionsFlow() if options_entry else flow.MiotBleBridgeConfigFlow(),
                                    self.hass, entry=options_entry)
        if model:
            handler._model = model
            handler._prepare({"source_device_id": "device-a", "name": "测试设备", "adapter": "hci0"})
        return handler

    async def test_device_without_presence_can_start_model_selection(self):
        handler = self.handler()
        result = await handler.async_step_user({"source_device_id": "device-b"})
        self.assertEqual(result["step_id"], "model")

    async def test_unknown_device_returns_field_error(self):
        result = await self.handler().async_step_user({"source_device_id": "missing"})
        self.assertEqual(result["errors"], {"source_device_id": "device_not_found"})

    async def test_model_selector_lists_available_catalog_only(self):
        handler = self.handler()
        await handler.async_step_user({"source_device_id": "device-a"})
        result = await handler.async_step_model()
        selector = next(iter(result["data_schema"].schema.values()))
        available = {item.model if hasattr(item, "model") else item for item in models.AVAILABLE_MODELS}
        self.assertEqual({item["value"] for item in selector.config["options"]}, available)
        result = await handler.async_step_model({"model": "unsupported.model"})
        self.assertEqual(result["errors"]["model"], "model_unavailable")

    async def test_legacy_device_duplicate_is_detected_but_another_model_is_allowed(self):
        self.hass.config_entries.entries.append(SimpleNamespace(
            entry_id="old", unique_id="old-id", data={"presence_entity_registry_id": self.presence.id}, options={},
        ))
        self.assertTrue(flow._device_model_already_mapped(self.hass, "device-a", models.DEFAULT_MODEL))
        self.assertFalse(flow._device_model_already_mapped(self.hass, "device-a", "other.model"))
        handler = self.handler()
        await handler.async_step_user({"source_device_id": "device-a"})
        result = await handler.async_step_model({"model": models.DEFAULT_MODEL})
        self.assertEqual(result["errors"]["model"], "device_model_already_mapped")

    async def test_property_sources_are_separate_questions(self):
        prop = property_fixture(1, minimum=0, maximum=10)
        handler = self.handler(model_fixture("fixture", (prop,)))
        first = await handler.async_step_property_source()
        self.assertEqual(first["step_id"], "property_source")
        second = await handler.async_step_property_source({"source": "virtual"})
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
                await handler.async_step_property_source({"source": "virtual"})
                result = await handler.async_step_property_virtual({"value": value})
                self.assertEqual(result["errors"]["value"], "invalid_value")
                self.assertEqual(handler._property_index, 0)

    async def test_virtual_values_are_entry_local_and_create_no_ha_entities(self):
        prop = property_fixture(1, minimum=0, maximum=100, writable=True, entity_domains=())
        first = self.handler(model_fixture("fixture", (prop,)))
        second = self.handler(model_fixture("fixture", (prop,)))
        before = deepcopy(self.hass.states.values)
        await first.async_step_property_source({"source": "virtual"})
        await first.async_step_property_virtual({"value": 75})
        self.assertEqual(second._data["property_mappings"]["2.1"]["value"], 0)
        self.assertEqual(self.hass.states.values, before)

    async def test_entity_selection_defaults_to_the_device_and_allows_explicit_other_sources(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        self.hass.registry.add("sensor.other", "device-b")
        self.hass.states.set("sensor.other", "8")
        handler = self.handler(model_fixture("fixture", (prop,)))
        form = await handler.async_step_property_source({"source": "entity"})
        selector = next(iter(form["data_schema"].schema.values()))
        self.assertNotIn("sensor.other", selector.config["include_entities"])
        result = await handler.async_step_property_entity({"entity_id": "sensor.other"})
        self.assertEqual(result["errors"]["entity_id"], "wrong_device")
        await handler.async_step_property_source({"source": "other_entity"})
        await handler.async_step_property_entity({"entity_id": "sensor.other"})
        result = await handler.async_step_property_details({})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"]["2.1"]["source"], "entity")

    async def test_registered_offline_entity_is_accepted_and_uuid_is_stable(self):
        prop = property_fixture(1, minimum=0, maximum=100)
        self.hass.states.values.pop("sensor.lux")
        handler = self.handler(model_fixture("fixture", (prop,)))
        await handler.async_step_property_source({"source": "entity"})
        await handler.async_step_property_entity({"entity_id": self.lux.id})
        result = await handler.async_step_property_details({})
        self.assertEqual(result["type"], "menu")
        mapping = handler._data["property_mappings"]["2.1"]
        self.assertEqual(mapping["entity_registry_id"], self.lux.id)
        self.hass.registry.rename("sensor.lux", "sensor.renamed")
        self.assertTrue(handler._validate_complete())
        self.assertEqual(mapping["entity_id"], "sensor.renamed")

    async def test_wrong_domain_is_rejected_even_though_selector_filters_are_only_ui(self):
        prop = property_fixture(1, writable=True, entity_domains=("number",))
        handler = self.handler(model_fixture("fixture", (prop,)))
        await handler.async_step_property_source({"source": "other_entity"})
        result = await handler.async_step_property_entity({"entity_id": "sensor.lux"})
        self.assertEqual(result["errors"]["entity_id"], "invalid_entity_domain")

    async def test_online_attribute_unit_and_control_are_validated_with_runtime_helpers(self):
        self.hass.registry.add("light.lamp")
        self.hass.states.set("light.lamp", "on", brightness=255)
        brightness = property_fixture(1, writable=True, minimum=0, maximum=100,
                                      semantic="brightness", unit="%", entity_domains=("light",))
        handler = self.handler(model_fixture("fixture", (brightness,)))
        await handler.async_step_property_source({"source": "entity"})
        form = await handler.async_step_property_entity({"entity_id": "light.lamp"})
        self.assertEqual(suggested(form, "attribute"), "brightness")
        result = await handler.async_step_property_details({"attribute": "brightness"})
        self.assertEqual(result["type"], "menu")
        delay = property_fixture(2, writable=True, minimum=0, maximum=30, semantic="delay",
                                 entity_domains=("light",))
        handler = self.handler(model_fixture("fixture", (delay,)))
        await handler.async_step_property_source({"source": "entity"})
        await handler.async_step_property_entity({"entity_id": "light.lamp"})
        result = await handler.async_step_property_details({})
        self.assertEqual(result["errors"]["base"], "invalid_entity_value")

    async def test_missing_online_attribute_and_incompatible_units_are_rejected(self):
        prop = property_fixture(1, minimum=0, maximum=100, unit="ppm")
        handler = self.handler(model_fixture("fixture", (prop,)))
        await handler.async_step_property_source({"source": "entity"})
        await handler.async_step_property_entity({"entity_id": "sensor.lux"})
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
        await handler.async_step_property_source({"source": "entity"})
        await handler.async_step_property_entity({"entity_id": "select.mode"})
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
        await handler.async_step_property_source({"source": "entity"})
        details = await handler.async_step_property_entity({"entity_id": "select.mode"})
        self.assertIn("configure_value_map", [key.schema for key in details["data_schema"].schema])
        await handler.async_step_property_details({"configure_value_map": True})
        await handler.async_step_property_value_map({"state_value": "auto", "value": 0.0})
        result = await handler.async_step_property_value_map({"state_value": "sleep", "value": 3.0})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["property_mappings"]["2.1"]["value_map"], {"auto": 0, "sleep": 3})

    async def test_smoke2_binary_source_requires_explicit_off_and_on_enum_questions(self):
        model = models.get_model("xiaomi.sensor_smoke.yg2")
        prop = model.property_by_key["2.1004"]
        self.hass.registry.add("binary_sensor.smoke", device_class="smoke")
        self.hass.states.set("binary_sensor.smoke", "off")
        handler = self.handler(model)
        await handler.async_step_property_source({"source": "entity"})
        details = await handler.async_step_property_entity({"entity_id": "binary_sensor.smoke"})
        self.assertTrue(suggested(details, "configure_value_map"))
        marker = next(key for key in details["data_schema"].schema if key == "configure_value_map")
        self.assertTrue(marker.default())
        first = await handler.async_step_property_details({})
        self.assertEqual(suggested(first, "state_value"), "off")
        self.assertEqual(handler._property_draft["value_map"], {})
        second = await handler.async_step_property_value_map({"state_value": "off", "value": "1"})
        self.assertEqual(suggested(second, "state_value"), "on")
        await handler.async_step_property_value_map({"state_value": "on", "value": "2"})
        mapping = handler._data["property_mappings"][prop.key]
        self.assertEqual(mapping["value_map"], {"off": 1, "on": 2})
        self.assertEqual(flow.read_entity_value(prop, self.hass.states.get("binary_sensor.smoke"), mapping), 1)
        self.hass.states.set("binary_sensor.smoke", "on")
        self.assertEqual(flow.read_entity_value(prop, self.hass.states.get("binary_sensor.smoke"), mapping), 2)

    async def test_unknown_or_offline_binary_enum_source_still_offers_both_states(self):
        model = models.get_model("xiaomi.sensor_smoke.yg2")
        self.hass.registry.add("binary_sensor.smoke", device_class="smoke")
        for state in ("unknown", "unavailable", None):
            with self.subTest(state=state):
                if state is None:
                    self.hass.states.values.pop("binary_sensor.smoke", None)
                else:
                    self.hass.states.set("binary_sensor.smoke", state)
                handler = self.handler(model)
                await handler.async_step_property_source({"source": "entity"})
                await handler.async_step_property_entity({"entity_id": "binary_sensor.smoke"})
                await handler.async_step_property_details({})
                self.assertEqual(handler._map_states, ["off", "on"])
                await handler.async_step_property_value_map({"state_value": "off", "value": "1"})
                await handler.async_step_property_value_map({"state_value": "on", "value": "2"})
                self.assertTrue(handler._validate_complete())
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
                await handler.async_step_property_source({"source": "entity"})
                form = await handler.async_step_property_entity({"entity_id": "binary_sensor.presence"})
                self.assertFalse(suggested(form, "configure_value_map"))

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
        self.assertNotIn("model", [key.schema for key in form["data_schema"].schema])
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

    async def test_action_entities_are_limited_to_buttons_scripts_and_automations(self):
        action = SimpleNamespace(key="2.1", name="重置", input_keys=(), output_keys=())
        model = model_fixture("fixture", actions=(action,))
        handler = self.handler(model)
        result = await handler.async_step_action({"source": "entity", "entity_id": "sensor.lux"})
        self.assertEqual(result["errors"]["entity_id"], "invalid_entity_domain")
        self.hass.registry.add("script.reset", None)
        result = await handler.async_step_action({"source": "entity", "entity_id": "script.reset"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["action_mappings"]["2.1"]["entity_id"], "script.reset")

    async def test_button_event_uses_timestamp_changes_and_parameters_are_validated(self):
        prop = property_fixture(1, choices=((0, "单击"), (1, "双击")))
        event = SimpleNamespace(key="2.2", name="点击", argument_keys=("2.1",))
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
        self.hass.registry.add("input_button.click", None)
        result = await handler.async_step_event({"source": "entity", "entity_id": "input_button.click",
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
        handler = self.handler(model_fixture("fixture", events=(event,)))
        result = await handler.async_step_event({"source": "disabled"})
        self.assertEqual(result["type"], "menu")
        self.assertEqual(handler._data["event_mappings"], {})

    async def test_event_argument_can_read_live_csv_without_changing_the_property_mapping(self):
        prop = models.PropertyDefinition(name="测量结果 CSV", siid=8, piid=1, type_code=10,
                                         default="", spec_visible=False, entity_domains=("sensor",))
        event = SimpleNamespace(key="8.e.1", name="测量完成", argument_keys=("8.1",))
        self.hass.registry.add("input_button.measure", None)
        source = self.hass.registry.add("sensor.measurement", None)
        csv = "24.50,0,17.30,65.20"
        self.hass.states.set("sensor.measurement", "ready", result=csv)
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
        form = await handler.async_step_event({"source": "entity", "entity_id": "input_button.measure",
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
        self.hass.registry.add("input_button.measure", None)
        source = self.hass.registry.add("sensor.measurement", None)
        for state in ("unknown", "unavailable", None):
            with self.subTest(state=state):
                if state is None:
                    self.hass.states.values.pop("sensor.measurement", None)
                else:
                    self.hass.states.set("sensor.measurement", state)
                handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
                await handler.async_step_event({"source": "entity", "entity_id": "input_button.measure",
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
        self.hass.registry.add("input_button.click", None)
        handler = self.handler(model_fixture("fixture", (prop,), events=(event,)))
        handler._data["event_mappings"][event.key] = {
            "source": "entity", "entity_id": "input_button.click", "trigger_value": "",
            "arguments": {"2.1": 1},
        }
        form = await handler.async_step_event({"source": "entity", "entity_id": "input_button.click",
                                               "trigger_value": "", "custom_arguments": True})
        self.assertEqual(suggested(form, "source"), "virtual")
        await handler.async_step_event_argument({"source": "mapped"})
        self.assertNotIn("2.1", handler._data["event_mappings"][event.key]["arguments"])

    async def test_ha_event_entities_default_to_timestamp_changes(self):
        self.hass.registry.add("event.remote", None)
        self.hass.states.set("event.remote", "2026-11-24T10:00:00+08:00", event_type="single_press")
        event = SimpleNamespace(key="2.e.1", name="点击", argument_keys=())
        handler = self.handler(model_fixture("fixture", events=(event,)))
        await handler.async_step_event({"source": "entity", "entity_id": "event.remote", "trigger_value": "on"})
        self.assertEqual(handler._data["event_mappings"][event.key]["trigger_value"], "")

    async def test_final_duplicate_guard_handles_an_entry_created_during_the_wizard(self):
        handler = self.handler()
        await handler.async_step_user({"source_device_id": "device-a"})
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
                ))
                await handler.async_step_properties()
                for prop in handler._properties:
                    if prop.derived:
                        await handler.async_step_property_source({"source": "derived"})
                    else:
                        await handler.async_step_property_source({"source": "virtual"})
                        await handler.async_step_property_virtual({"value": flow._selector_value(prop, flow._default_value(prop))})
                self.assertEqual(handler._property_index, len(handler._properties))
                self.assertTrue(handler._validate_complete())

    async def test_getter_aliases_are_not_asked_or_automatically_mapped(self):
        canonical = property_fixture(1, name="公开属性", minimum=0, maximum=100)
        alias = property_fixture(2, name="兼容 getter", alias_of="2.1", notify=False, spec_visible=True)
        handler = self.handler(model_fixture("fixture", (canonical, alias)))
        handler._prepare(handler._data, prefer_entities=True)
        form = await handler.async_step_properties()
        self.assertEqual(handler._properties, (canonical,))
        self.assertEqual(form["description_placeholders"]["total"], "1")
        self.assertEqual(handler._data["property_mappings"]["2.2"], {"source": "virtual", "value": 0})
        self.assertEqual(handler._data["property_mappings"]["2.1"]["entity_id"], "sensor.lux")


class TranslationTests(unittest.TestCase):
    def test_translations_match_and_have_no_bom(self):
        original = COMPONENT.joinpath("strings.json").read_bytes()
        chinese = COMPONENT.joinpath("translations", "zh-Hans.json").read_bytes()
        self.assertFalse(original.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(original, chinese)
        document = json.loads(original.decode("utf-8"))
        for step in ("property_source", "property_virtual", "property_entity", "property_details",
                     "property_value_map", "features", "action", "event", "event_argument", "finish"):
            self.assertIn(step, document["config"]["step"])
            self.assertIn(step, document["options"]["step"])


if __name__ == "__main__":
    unittest.main()
