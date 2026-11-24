"""Model values are converted without changing or inventing HA entities."""

import importlib
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest

COMPONENT = Path(__file__).parents[1]/"custom_components"/"miot_ble_bridge"
PACKAGE = "miot_mapping_under_test"
if PACKAGE not in sys.modules:
    package = ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package
models = importlib.import_module(f"{PACKAGE}.models")
mappings = importlib.import_module(f"{PACKAGE}.mappings")


def state(value, **attributes):
    return SimpleNamespace(state=value, attributes=attributes)


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.light = models.get_model("careco.nlight.o654")
        self.cooler = models.get_model("xiaomi.cooler.r02p")

    def test_light_brightness_uses_percentage_in_both_directions(self):
        prop = self.light.property_by_key["7.2"]
        mapping = {"source": "entity", "entity_id": "light.test"}
        self.assertEqual(mappings.read_entity_value(prop, state("on", brightness=128), mapping), 50)
        self.assertEqual(mappings.property_service_call(prop, 50, mapping), ("light", "turn_on", {"entity_id": "light.test", "brightness_pct": 50}))

    def test_color_temperature_uses_kelvin(self):
        prop = self.light.property_by_key["7.3"]
        mapping = {"source": "entity", "entity_id": "light.test"}
        self.assertEqual(mappings.read_entity_value(prop, state("on", color_temp_kelvin=4000), mapping), 4000)
        self.assertEqual(mappings.property_service_call(prop, 4000, mapping)[2]["color_temp_kelvin"], 4000)

    def test_temperature_unit_conversion_precedes_range_validation(self):
        prop = self.cooler.property_by_key["3.3"]
        mapping = {"source": "entity", "entity_id": "sensor.temperature"}
        self.assertEqual(mappings.read_entity_value(prop, state("68", unit_of_measurement="°F"), mapping), 20)
        with self.assertRaises(ValueError):
            mappings.read_entity_value(prop, state("20", unit_of_measurement="W"), mapping)

    def test_temperature_control_converts_back_to_the_ha_unit(self):
        prop = models.get_model("yunmi.kettle.v13").property_by_key["5.1"]
        mapping = {"source": "entity", "entity_id": "input_number.temperature"}
        source = state("77", unit_of_measurement="°F")
        self.assertEqual(mappings.read_entity_value(prop, source, mapping), 25)
        self.assertEqual(mappings.property_service_call(prop, 25, mapping, source)[2]["value"], 77)

    def test_duration_units_are_converted_in_both_directions(self):
        prop = models.get_model("xiaomi.diffuser.xwczxf").property_by_key["2.1069"]
        mapping = {"source": "entity", "entity_id": "number.duration"}
        source = state("1", unit_of_measurement="min")
        self.assertEqual(mappings.read_entity_value(prop, source, mapping), 60)
        self.assertEqual(mappings.property_service_call(prop, 90, mapping, source)[2]["value"], 1.5)

    def test_measurement_timestamp_preserves_the_source_time(self):
        prop = models.get_model("yunmai.scales.ms103").property_by_key["11.3"]
        mapping = {"source": "entity", "entity_id": "sensor.measurement_time"}
        self.assertEqual(mappings.read_entity_value(prop, state("2026-11-24T00:00:00+00:00", device_class="timestamp"), mapping), 1795478400)
        with self.assertRaises(ValueError):
            mappings.read_entity_value(prop, state("2026-11-24T00:00:00"), mapping)

    def test_scale_weight_keeps_the_sdk_tenths_truncation(self):
        prop = models.get_model("yunmai.scales.ms103").property_by_key["3.1005"]
        self.assertEqual(mappings.read_entity_value(prop, state("64.55", unit_of_measurement="kg"), {"entity_id": "sensor.weight"}), 645)

    def test_integer_source_does_not_lose_uint64_precision(self):
        value = (1 << 64)-1
        prop = models.PropertyDefinition("Exact integer", 2, 1, models.U64, 0, minimum=0, maximum=value, step=1)
        self.assertEqual(mappings.read_entity_value(prop, state(str(value)), {"entity_id": "sensor.integer"}), value)

    def test_boolean_inverse_is_used_when_reading_and_writing(self):
        prop = self.light.property_by_key["7.1"]
        mapping = {"source": "entity", "entity_id": "switch.test", "invert": True}
        self.assertIs(mappings.read_entity_value(prop, state("off"), mapping), True)
        self.assertEqual(mappings.property_service_call(prop, False, mapping), ("switch", "turn_on", {"entity_id": "switch.test"}))

    def test_door_contact_automatically_uses_the_model_closed_boolean(self):
        for model_id, key in (("isa.magnet.dw2hl", "2.2"), ("xiaomi.magnet.03", "2.1012")):
            prop = models.get_model(model_id).property_by_key[key]
            mapping = {"source": "entity", "entity_id": "binary_sensor.door"}
            for raw, expected in (("on", False), ("off", True), ("open", False), ("closed", True), (True, False), (False, True)):
                with self.subTest(model=model_id, raw=raw):
                    self.assertIs(mappings.read_entity_value(prop, state(raw, device_class="door"), mapping), expected)
            self.assertEqual(mapping, {"source": "entity", "entity_id": "binary_sensor.door"})

    def test_door_contact_preserves_explicit_old_inverse_and_value_map(self):
        prop = models.get_model("isa.magnet.dw2hl").property_by_key["2.2"]
        mapping = {"entity_id": "binary_sensor.door"}
        self.assertIs(mappings.read_entity_value(prop, state("on"), {**mapping, "invert": False}), True)
        self.assertIs(mappings.read_entity_value(prop, state("on"), {**mapping, "invert": True}), False)
        self.assertIs(mappings.read_entity_value(prop, state("on"), {**mapping, "value_map": {"on": False, "off": True}}), False)
        self.assertIs(mappings.read_entity_value(prop, state("on"), {**mapping, "value_map": {"on": True, "off": False}}), True)

    def test_select_value_map_is_reversed_for_mijia_writes(self):
        prop = self.cooler.property_by_key["3.1"]
        mapping = {"source": "entity", "entity_id": "select.cooling", "value_map": {"auto": 0, "maximum": 1}}
        self.assertEqual(mappings.read_entity_value(prop, state("maximum"), mapping), 1)
        self.assertEqual(mappings.property_service_call(prop, 1, mapping), ("select", "select_option", {"entity_id": "select.cooling", "option": "maximum"}))

    def test_smoke_enum_is_automatic_without_an_attribute_or_manual_map(self):
        prop = models.get_model("xiaomi.sensor_smoke.yg2").property_by_key["2.1004"]
        mapping = {"source": "entity", "entity_id": "binary_sensor.smoke"}
        self.assertEqual(mappings.read_entity_value(prop, state("off", device_class="smoke"), mapping), 1)
        self.assertEqual(mappings.read_entity_value(prop, state("on", device_class="smoke"), mapping), 2)
        self.assertEqual(mapping, {"source": "entity", "entity_id": "binary_sensor.smoke"})

    def test_known_select_labels_are_automatic_and_bidirectional(self):
        prop = self.cooler.property_by_key["3.1"]
        mapping = {"source": "entity", "entity_id": "select.cooling"}
        source = state("extreme", options=["intelligent", "extreme"])
        self.assertEqual(mappings.read_entity_value(prop, source, mapping), 1)
        self.assertEqual(mappings.property_service_call(prop, 0, mapping, source)[2]["option"], "intelligent")

    def test_saved_enum_mapping_overrides_automatic_inference(self):
        prop = models.get_model("xiaomi.sensor_smoke.yg2").property_by_key["2.1004"]
        mapping = {"entity_id": "binary_sensor.smoke", "value_map": {"on": 1, "off": 2}}
        self.assertEqual(mappings.read_entity_value(prop, state("on"), mapping), 1)
        self.assertEqual(mappings.read_entity_value(prop, state("off"), mapping), 2)

    def test_numeric_sensor_uses_its_state_and_does_not_choose_an_unrelated_attribute(self):
        prop = self.cooler.property_by_key["3.3"]
        mapping = {"entity_id": "sensor.temperature"}
        source = state("20", temperature=75, unit_of_measurement="°C")
        self.assertIsNone(mappings.effective_attribute(prop, mapping["entity_id"], mapping, source))
        self.assertEqual(mappings.read_entity_value(prop, source, mapping), 20)

    def test_unique_temperature_attribute_is_automatic(self):
        prop = self.cooler.property_by_key["3.3"]
        mapping = {"entity_id": "sensor.device"}
        source = state("ready", temperature=25)
        self.assertEqual(mappings.effective_attribute(prop, mapping["entity_id"], mapping, source), "temperature")
        self.assertEqual(mappings.read_entity_value(prop, source, mapping), 25)

    def test_event_result_attribute_is_automatic_and_explicit_overrides_still_work(self):
        prop = models.get_model("yunmai.scales.ms103").property_by_key["8.1"]
        mapping = {"entity_id": "sensor.result"}
        source = state("2026-11-24T00:00:00+00:00", result="645,1", alternate="0,6")
        self.assertEqual(mappings.effective_attribute(prop, mapping["entity_id"], mapping, source), "result")
        self.assertEqual(mappings.read_entity_value(prop, source, mapping), "645,1")
        self.assertEqual(mappings.read_entity_value(prop, source, {**mapping, "attribute": "alternate"}), "0,6")

    def test_unknown_select_option_is_not_assigned_an_index(self):
        prop = self.cooler.property_by_key["3.1"]
        source = state("vendor_special", options=["vendor_special", "other_special"])
        with self.assertRaises(ValueError):
            mappings.read_entity_value(prop, source, {"entity_id": "select.cooling"})

    def test_unknown_source_is_omitted_even_with_cached_attributes(self):
        prop = self.light.property_by_key["7.2"]
        mapping = {"source": "entity", "entity_id": "light.test"}
        for value in ("unknown", "unavailable"):
            self.assertIsNone(mappings.read_entity_value(prop, state(value, brightness=255), mapping))

    def test_light_delay_cannot_be_misinterpreted_as_power(self):
        prop = self.cooler.property_by_key["5.2"]
        with self.assertRaises(ValueError):
            mappings.property_service_call(prop, 10, {"source": "entity", "entity_id": "light.test"})

    def test_action_only_calls_the_selected_entity(self):
        self.assertEqual(mappings.action_service_call({"entity_id": "input_button.test"}), ("input_button", "press", {"entity_id": "input_button.test"}))
        with self.assertRaises(ValueError):
            mappings.action_service_call({"entity_id": "sensor.test"})

    def test_legacy_radar_uses_private_virtual_lux_and_fixed_battery(self):
        model = models.get_model(models.DEFAULT_MODEL)
        result = mappings.default_mappings(model, {"presence_entity": "binary_sensor.radar"})
        self.assertEqual(result["2.1005"], {"source": "virtual", "value": 0.0})
        self.assertEqual(result["3.1003"], {"source": "virtual", "value": 100})
        self.assertEqual(result["2.1081"], {"source": "derived"})
        self.assertEqual(result["2.1082"], {"source": "derived"})


if __name__ == "__main__":
    unittest.main()
