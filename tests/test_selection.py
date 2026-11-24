"""Selection stays device-scoped and does not promote diagnostic entities."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


COMPONENT = Path(__file__).parents[1]/"custom_components"/"miot_ble_bridge"
PACKAGE = "miot_selection_under_test"
if PACKAGE not in sys.modules:
    package = ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package

try:
    import homeassistant.helpers.device_registry
    import homeassistant.helpers.entity_registry
except ModuleNotFoundError:
    modules = {name: ModuleType(name) for name in ("homeassistant", "homeassistant.helpers", "homeassistant.helpers.device_registry", "homeassistant.helpers.entity_registry")}
    for module in modules.values():
        module.__path__ = []
    modules["homeassistant.helpers.device_registry"].async_get = lambda hass: hass.devices
    modules["homeassistant.helpers.entity_registry"].async_get = lambda hass: hass.registry
    modules["homeassistant.helpers.entity_registry"].async_entries_for_device = lambda registry, device_id: [entry for entry in registry.entities.values() if entry.device_id == device_id]
    with patch.dict(sys.modules, modules):
        selection = importlib.import_module(f"{PACKAGE}.selection")
else:
    selection = importlib.import_module(f"{PACKAGE}.selection")
models = importlib.import_module(f"{PACKAGE}.models")


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.registry = SimpleNamespace(entities={})
        self.device_values = {}
        self.states = {}
        self.hass = SimpleNamespace(registry=self.registry, devices=SimpleNamespace(async_get=self.device_values.get), states=SimpleNamespace(get=self.states.get))
        for target, name, replacement in (
            (selection.er, "async_get", lambda hass: hass.registry),
            (selection.er, "async_entries_for_device", lambda registry, device_id: [entry for entry in registry.entities.values() if entry.device_id == device_id]),
            (selection.dr, "async_get", lambda hass: hass.devices),
        ):
            patcher = patch.object(target, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.occupancy = models.get_model(models.DEFAULT_MODEL)
        self.presence = self.occupancy.property_by_key["2.1078"]
        self.lux = self.occupancy.property_by_key["2.1005"]
        self.thermo = models.get_model("miaomiaoce.sensor_ht.t2")
        self.temperature = self.thermo.property_by_key["2.1"]

    def add(self, entity_id, *, device_id="radar", device_class=None, name=None, value="unknown", entity_category=None, disabled=False, **attributes):
        entry = SimpleNamespace(entity_id=entity_id, device_id=device_id, id=entity_id, name=name, original_name=name,
                                device_class=device_class, original_device_class=None,
                                entity_category=entity_category, disabled_by="user" if disabled else None,
                                capabilities={})
        self.registry.entities[entity_id] = entry
        if device_id:
            self.device_values.setdefault(device_id, SimpleNamespace(name_by_user=None, name=device_id, disabled_by=None))
        self.states[entity_id] = SimpleNamespace(state=value, attributes=attributes)
        return entry

    def test_presence_accepts_old_esphome_target_without_device_class(self):
        self.add("binary_sensor.has_target", value="on")
        self.add("binary_sensor.radar_connectivity", device_class="connectivity", value="on")
        self.assertEqual(selection.eligible_entities(self.hass, self.occupancy, self.presence, "radar"), ["binary_sensor.has_target"])
        self.assertEqual(selection.recommended_entity(self.hass, self.occupancy, self.presence, "radar"), "binary_sensor.has_target")

    def test_overall_presence_is_preferred_to_moving_and_still_parts(self):
        self.add("binary_sensor.has_target", device_class="occupancy", value="on")
        self.add("binary_sensor.moving", device_class="motion", value="on")
        self.add("binary_sensor.still", device_class="occupancy", value="off")
        self.assertEqual(selection.recommended_entity(self.hass, self.occupancy, self.presence, "radar"), "binary_sensor.has_target")

    def test_unclassified_temperature_can_use_unambiguous_units(self):
        self.add("sensor.t", value="unknown", unit_of_measurement="°C")
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), ["sensor.t"])

    def test_unique_standard_temperature_attribute_is_a_selectable_source(self):
        self.add("sensor.device", value="ready", temperature=25)
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), ["sensor.device"])
        self.assertEqual(selection.recommended_entity(self.hass, self.thermo, self.temperature, "radar"), "sensor.device")
        self.assertEqual(selection.eligible_devices(self.hass, self.thermo), [{"value": "radar", "label": "radar"}])

    def test_ambiguous_standard_attributes_do_not_supply_a_default_temperature(self):
        self.add("sensor.device", value="ready", temperature=25, current_temperature=30)
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), [])

    def test_numeric_sensor_state_does_not_select_its_auxiliary_temperature(self):
        self.add("sensor.device", device_class="illuminance", value="30", unit_of_measurement="lx", temperature=25)
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), [])

    def test_continuous_lux_is_hidden_from_basic_light_degree_and_available_for_manual_mapping(self):
        model = models.get_model("lumi.motion.bmgl01")
        prop = model.property_by_key["2.1"]
        for device_class in (None, "illuminance"):
            with self.subTest(device_class=device_class):
                self.add("sensor.illuminance", device_class=device_class, value="30", unit_of_measurement="lx")
                self.assertEqual(selection.eligible_entities(self.hass, model, prop, "radar"), [])
                self.assertIsNone(selection.recommended_entity(self.hass, model, prop, "radar"))
                self.assertEqual(selection.eligible_entities(self.hass, model, prop, "radar", allow_other=True), ["sensor.illuminance"])

    def test_binary_light_sensor_automatically_supplies_dark_and_bright_choices(self):
        model = models.get_model("lumi.motion.bmgl01")
        prop = model.property_by_key["2.1"]
        self.add("binary_sensor.light_detected", device_class="light", value="on")
        self.assertEqual(selection.eligible_entities(self.hass, model, prop, "radar"), ["binary_sensor.light_detected"])
        self.assertEqual(selection.read_entity_value(prop, self.states["binary_sensor.light_detected"], {"entity_id": "binary_sensor.light_detected"}), 2)

    def test_device_scope_does_not_include_other_room_or_templates(self):
        self.add("binary_sensor.presence", device_class="occupancy", value="on")
        self.add("binary_sensor.other_presence", device_id="bedroom", device_class="occupancy", value="off")
        self.add("binary_sensor.template_presence", device_id=None, device_class="occupancy", value="on")
        self.assertEqual(selection.eligible_entities(self.hass, self.occupancy, self.presence, "radar"), ["binary_sensor.presence"])
        advanced = selection.eligible_entities(self.hass, self.occupancy, self.presence, "radar", allow_other=True)
        self.assertEqual(set(advanced), {"binary_sensor.presence", "binary_sensor.other_presence", "binary_sensor.template_presence"})

    def test_lux_is_not_recommended_as_temperature_even_when_it_is_the_only_sensor(self):
        self.add("sensor.lux", device_class="illuminance", value="12", unit_of_measurement="lx")
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), [])
        self.assertIsNone(selection.recommended_entity(self.hass, self.thermo, self.temperature, "radar"))
        self.assertEqual(selection.eligible_devices(self.hass, self.thermo), [])

    def test_unknown_and_offline_registered_temperature_are_still_selectable(self):
        for value in ("unknown", "unavailable"):
            with self.subTest(value=value):
                self.add("sensor.temperature", device_class="temperature", value=value, unit_of_measurement="°C")
                self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), ["sensor.temperature"])
                self.assertEqual(selection.eligible_devices(self.hass, self.thermo), [{"value": "radar", "label": "radar"}])
                self.assertEqual(selection.recommended_entity(self.hass, self.thermo, self.temperature, "radar"), "sensor.temperature")

    def test_unsupported_domains_and_diagnostics_are_not_candidates(self):
        self.add("sensor.temperature", device_class="temperature", value="22", unit_of_measurement="°C")
        self.add("sensor.rssi", device_class="signal_strength", value="-65", unit_of_measurement="dBm")
        self.add("sensor.uptime", value="123", unit_of_measurement="s")
        self.add("binary_sensor.problem", device_class="problem", value="on")
        self.add("sensor.chip_temperature", device_class="temperature", entity_category="diagnostic", value="55", unit_of_measurement="°C")
        self.add("camera.temperature", value="idle")
        self.add("sensor.disabled_temperature", device_class="temperature", disabled=True, value="25", unit_of_measurement="°C")
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), ["sensor.temperature"])

    def test_incompatible_units_are_hidden_and_fahrenheit_is_supported(self):
        self.add("sensor.temperature_invalid", device_class="temperature", value="42", unit_of_measurement="W")
        self.add("sensor.temperature_f", device_class="temperature", value="77", unit_of_measurement="°F")
        self.assertEqual(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar"), ["sensor.temperature_f"])

    def test_ambiguous_equally_ranked_temperature_does_not_get_an_arbitrary_default(self):
        self.add("sensor.temperature_one", device_class="temperature", value="20", unit_of_measurement="°C")
        self.add("sensor.temperature_two", device_class="temperature", value="21", unit_of_measurement="°C")
        self.assertIsNone(selection.recommended_entity(self.hass, self.thermo, self.temperature, "radar"))
        self.assertEqual(len(selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar")), 2)

    def test_switch_only_device_is_not_a_sensor_or_full_light(self):
        self.add("switch.socket", device_id="socket", value="on")
        self.assertEqual(selection.eligible_devices(self.hass, self.occupancy), [])
        light = models.get_model("careco.nlight.o654")
        self.assertEqual(selection.eligible_devices(self.hass, light), [])
        outlet = models.get_model("sharge.plug.sj01")
        self.assertEqual(selection.eligible_devices(self.hass, outlet), [{"value": "socket", "label": "socket"}])

    def test_only_onoff_light_does_not_claim_brightness_or_color_temperature(self):
        light = models.get_model("careco.nlight.o654")
        self.add("light.simple", value="on", supported_color_modes=["onoff"])
        self.add("light.adjustable", value="off", supported_color_modes=["color_temp"])
        self.assertEqual(selection.eligible_entities(self.hass, light, light.property_by_key["7.2"], "radar"), ["light.adjustable"])
        self.assertEqual(selection.eligible_entities(self.hass, light, light.property_by_key["7.3"], "radar"), ["light.adjustable"])
        self.assertEqual(set(selection.eligible_entities(self.hass, light, light.property_by_key["7.1"], "radar")), {"light.simple", "light.adjustable"})

    def test_button_device_requires_an_actual_event_source_not_rssi(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("sensor.button_rssi", device_id="diagnostic", device_class="signal_strength", value="-70", unit_of_measurement="dBm")
        self.add("event.click", device_id="remote", value="unknown")
        self.assertEqual(selection.eligible_devices(self.hass, model), [{"value": "remote", "label": "remote"}])

    def test_maintenance_buttons_do_not_make_a_device_a_wireless_remote(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("button.restart", device_id="maintenance", value="unknown")
        self.add("button.identify", device_id="maintenance", value="unknown")
        self.assertEqual(selection.eligible_devices(self.hass, model), [])

    def test_unrelated_event_entities_do_not_make_a_device_a_wireless_remote(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("event.measurement", device_id="scale", value="unknown", event_types=["measurement_complete"])
        self.add("event.action", device_id="remote", value="unknown", event_types=["single_press", "double_press"])
        self.assertEqual(selection.eligible_devices(self.hass, model), [{"value": "remote", "label": "remote"}])

    def test_event_choices_are_device_scoped_and_only_include_button_sources(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("button.key")
        self.add("input_button.key")
        self.add("event.action", event_types=["single_press", "double_press"])
        self.add("binary_sensor.key_pressed", name="Button pressed", value="on")
        self.add("event.other_click", device_id="other")
        self.add("binary_sensor.presence", device_class="occupancy", value="on")
        self.add("event.measurement", event_types=["measurement_complete"])
        self.add("sensor.click", value="single")
        self.add("script.click", value="off")
        expected = ["binary_sensor.key_pressed", "button.key", "event.action", "input_button.key"]
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar"), expected)
        self.assertEqual(selection.eligible_event_entities(self.hass, model, None), [])

    def test_advanced_event_choices_allow_other_devices_and_unregistered_templates(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("event.click", device_id="other")
        template = SimpleNamespace(entity_id="binary_sensor.template_button", state="on", attributes={})
        camera = SimpleNamespace(entity_id="camera.button", state="idle", attributes={})
        self.states[template.entity_id] = template
        self.states[camera.entity_id] = camera
        self.hass.states.async_all = lambda: [template, camera]
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar"), [])
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar", allow_other=True),
                         ["binary_sensor.template_button", "event.click"])

    def test_event_and_action_choices_hide_disabled_diagnostics_and_maintenance_buttons(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("button.key")
        self.add("button.restart")
        self.add("button.identify")
        self.add("input_button.factory_reset")
        self.add("button.disabled_key", disabled=True)
        self.add("button.diagnostic_key", entity_category="diagnostic")
        self.add("event.disabled_click", disabled=True)
        self.add("event.diagnostic_click", entity_category="diagnostic")
        self.add("binary_sensor.button_connectivity", device_class="connectivity", value="on")
        for allow_other in (False, True):
            with self.subTest(allow_other=allow_other):
                self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar", allow_other), ["button.key"])
                self.assertEqual(selection.eligible_action_entities(self.hass, model, "radar", allow_other), ["button.key"])

    def test_action_choices_only_offer_local_buttons_until_advanced_mode(self):
        model = models.get_model("careco.nlight.o654")
        self.add("button.start")
        self.add("input_button.start")
        self.add("button.other_start", device_id="other")
        self.add("script.scene", value="off")
        self.add("automation.scene", value="on")
        self.add("switch.start", value="on")
        self.add("event.start")
        self.assertEqual(selection.eligible_action_entities(self.hass, model, "radar"),
                         ["button.start", "input_button.start"])
        self.assertEqual(selection.eligible_action_entities(self.hass, model, "radar", allow_other=True),
                         ["automation.scene", "button.other_start", "button.start", "input_button.start", "script.scene"])
        self.assertEqual(selection.eligible_action_entities(self.hass, model, None), [])

    def test_advanced_action_choices_allow_unregistered_scripts_but_not_disabled_automations(self):
        model = models.get_model("careco.nlight.o654")
        self.add("automation.disabled", disabled=True)
        self.add("script.diagnostic", entity_category="diagnostic")
        script = SimpleNamespace(entity_id="script.scene", state="off", attributes={})
        self.states[script.entity_id] = script
        self.hass.states.async_all = lambda: [script]
        self.assertEqual(selection.eligible_action_entities(self.hass, model, None, allow_other=True), ["script.scene"])

    def test_offline_registered_button_events_and_actions_remain_selectable(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("button.key", value="unavailable")
        self.add("event.click", value="unavailable")
        del self.states["event.click"]
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar"), ["button.key", "event.click"])
        self.assertEqual(selection.eligible_action_entities(self.hass, model, "radar"), ["button.key"])

    def test_advanced_scale_events_accept_measurement_sources_and_reject_unrelated_numeric_classes(self):
        model = models.get_model("yunmai.scales.ms103")
        self.add("event.result", device_id="scale", event_types=["measurement_complete"])
        self.add("sensor.weight", device_id="scale", device_class="weight", value="65", unit_of_measurement="kg")
        self.add("sensor.measurement_time", device_id="scale", device_class="timestamp", value="2026-11-24T12:00:00+08:00")
        self.add("sensor.scale_temperature", device_id="scale", device_class="temperature", value="25", unit_of_measurement="°C")
        self.add("event.weather", device_id="weather", event_types=["rain"])
        self.add("camera.measurement", device_id="camera", value="idle")
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "scale"), [])
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "scale", allow_other=True),
                         ["event.result", "sensor.measurement_time", "sensor.weight"])

    def test_advanced_motion_events_require_presence_evidence(self):
        model = models.get_model("lumi.motion.bmgl01")
        self.add("binary_sensor.presence", device_class="occupancy", value="on")
        self.add("event.target", event_types=["motion_detected"])
        self.add("switch.has_target", value="on")
        self.add("sensor.motion_temperature", device_class="temperature", value="25", unit_of_measurement="°C")
        self.add("light.ceiling", value="on")
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar"), [])
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar", allow_other=True),
                         ["binary_sensor.presence", "event.target", "switch.has_target"])

    def test_advanced_button_state_sensors_do_not_include_button_device_temperature(self):
        model = models.get_model("lumi.remote.mcn001")
        self.add("sensor.action", value="single")
        self.add("select.action", value="double")
        self.add("sensor.button_temperature", device_class="temperature", value="25", unit_of_measurement="°C")
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar"), [])
        self.assertEqual(selection.eligible_event_entities(self.hass, model, "radar", allow_other=True),
                         ["select.action", "sensor.action"])

    def test_advanced_templates_can_be_unregistered_without_opening_other_domains(self):
        self.hass.states.async_all = lambda: [SimpleNamespace(entity_id="sensor.template_temperature", state="25", attributes={"device_class": "temperature", "unit_of_measurement": "°C"}), SimpleNamespace(entity_id="camera.template_camera", state="idle", attributes={})]
        entities = selection.eligible_entities(self.hass, self.thermo, self.temperature, "radar", allow_other=True)
        self.assertEqual(entities, ["sensor.template_temperature"])

    def test_advanced_custom_select_is_allowed_but_not_recommended_for_a_real_device(self):
        model = models.get_model("xiaomi.cooler.r02p")
        prop = model.property_by_key["3.1"]
        self.add("select.custom_setting", value="manual", options=["manual", "automatic"])
        self.assertEqual(selection.eligible_entities(self.hass, model, prop, "radar"), [])
        self.assertEqual(selection.eligible_entities(self.hass, model, prop, "radar", allow_other=True), ["select.custom_setting"])
        self.assertIsNone(selection.recommended_entity(self.hass, model, prop, "radar"))

    def test_numeric_pressure_does_not_match_a_binary_pressure_presence_state(self):
        model = models.get_model("linp.senpres.ps1bb")
        prop = model.property_by_key["2.1060"]
        self.add("sensor.pressure", device_class="pressure", value="101325", unit_of_measurement="Pa")
        self.assertEqual(selection.eligible_entities(self.hass, model, prop, "radar"), [])

    def test_disabled_device_is_not_offered(self):
        self.add("binary_sensor.presence", device_class="occupancy", value="on")
        self.device_values["radar"].disabled_by = "user"
        self.assertEqual(selection.eligible_devices(self.hass, self.occupancy), [])

    def test_large_install_only_offers_matching_device_and_its_local_entities(self):
        for device in range(100):
            for diagnostic in range(30):
                self.add(f"sensor.d{device}_rssi_{diagnostic}", device_id=f"device-{device}", device_class="signal_strength", value="-70", unit_of_measurement="dBm")
        self.add("binary_sensor.real_presence", device_id="actual-radar", device_class="occupancy", value="on")
        self.add("sensor.real_lux", device_id="actual-radar", device_class="illuminance", value="12", unit_of_measurement="lx")
        self.assertEqual(selection.eligible_devices(self.hass, self.occupancy), [{"value": "actual-radar", "label": "actual-radar"}])
        self.assertEqual(selection.eligible_entities(self.hass, self.occupancy, self.lux, "actual-radar"), ["sensor.real_lux"])

    def test_categories_only_include_real_available_model_groups(self):
        self.assertEqual({option["value"] for option in selection.category_options()}, {model.category for model in models.AVAILABLE_MODELS})
        self.assertEqual(len(selection.category_options()), 6)


if __name__ == "__main__":
    unittest.main()
