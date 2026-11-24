"""Catalog coverage and independent wire vectors from upstream device examples."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import unittest

MODEL_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "miot_ble_bridge" / "models.py"
SPEC = importlib.util.spec_from_file_location("miot_models_under_test", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
models = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = models
SPEC.loader.exec_module(models)

EXPECTED_MODELS = {
    "yunmai.scales.ms103": 0x30D9,
    "miaomiaoce.sensor_ht.t2": 0x055B,
    "MUE4094RT": 0x03DD,
    "zimi.mosq.v1": 0x040A,
    "yeelink.remote.contrl": 0x1949,
    "lumi.remote.mcn001": 0x2387,
    "giot.remote.v58kwm": 0x3F3A,
    "yuemee.airmonitor.mhfd1": 0x02DF,
    "isa.magnet.dw2hl": 0x098B,
    "xiaomi.magnet.03": 0x8C05,
    "lumi.motion.bmgl01": 0x0A8D,
    "xiaomi.motion.pir1": 0x3531,
    "xiaomi.sensor_occupy.03": 0x4683,
    "lumi.flood.bmcn01": 0x0863,
    "xiaomi.sensor_ht.mini": 0x55B5,
    "xiaomi.sensor_ht.new3pr": 0x9AB9,
    "mirsz.sensor_gas.ga500": 0x392D,
    "mirsz.sensor_smoke.s500": 0x392E,
    "xiaomi.pet_waterer.002": 0x399A,
    "yeelink.light.nl1": 0x07F6,
    "linp.senpres.ps1bb": 0x3F4C,
    "hhcc.plantmonitor.v1": 0x0098,
    "shuse.airm.ss006": 0x6651,
    "MJDP003": 0x06EB,
    "xiaomi.sensor_smoke.yg2": 0x7ABA,
    "xiaomi.flood.oh83w": 0x6375,
    "sharge.plug.sj01": 0x1E1C,
    "soocare.toothbrush.1501": 0x1FF3,
    "xiaomi.toothbrush.24p": 0x6800,
    "careco.nlight.o654": 0x6266,
    "090615.remote.btsw1": 0x38BB,
    "yunmi.kettle.v13": 0x1809,
    "xiaomi.diffuser.xwczxf": 0x39E6,
    "xiaomi.cooler.r02p": 0x52AA,
}


class CatalogTests(unittest.TestCase):
    def test_all_34_upstream_pids_have_distinct_real_model_keys(self):
        self.assertEqual({key: value.pid for key, value in models.MODEL_CATALOG.items()}, EXPECTED_MODELS)
        self.assertEqual(len({model.pid for model in models.MODEL_CATALOG.values()}), 34)
        self.assertEqual(models.DEFAULT_MODEL, "xiaomi.sensor_occupy.03")

    def test_unverified_psk_and_mesh_are_excluded_from_normal_choices(self):
        available = {model.model for model in models.AVAILABLE_MODELS}
        self.assertEqual(len(available), 32)
        self.assertNotIn("zimi.mosq.v1", available)
        self.assertNotIn("MJDP003", available)
        for key in ("zimi.mosq.v1", "MJDP003"):
            model = models.get_model(key)
            self.assertFalse(model.available)
            self.assertTrue(model.unavailable_reason)
            self.assertTrue(model.limitations)
        self.assertEqual(models.get_model("zimi.mosq.v1").auth_mode, "psk")
        self.assertEqual(models.get_model("MUE4094RT").auth_mode, "standard_nus")

    def test_daily_phone_controls_are_connectable_without_promoting_all_sensors(self):
        connected = {model.model for model in models.AVAILABLE_MODELS if model.connectable}
        self.assertEqual(connected, {
            "yunmai.scales.ms103", "miaomiaoce.sensor_ht.t2", "MUE4094RT",
            "sharge.plug.sj01", "careco.nlight.o654", "yunmi.kettle.v13",
            "xiaomi.diffuser.xwczxf", "xiaomi.cooler.r02p",
        })
        self.assertFalse(models.get_model("xiaomi.sensor_ht.new3pr").connectable)
        self.assertEqual(models.get_model(models.DEFAULT_MODEL).gatt_strategy, "fixed_control")
        for key in connected - {"miaomiaoce.sensor_ht.t2", "MUE4094RT"}:
            self.assertEqual(models.get_model(key).gatt_strategy, "prefer_source")

    def test_every_model_has_valid_defaults_and_noncolliding_definitions(self):
        for model in models.MODEL_CATALOG.values():
            with self.subTest(model=model.model):
                self.assertTrue(model.source_dir)
                self.assertEqual(len(model.property_by_key), len(model.properties))
                self.assertEqual(len(model.beacon_by_id), len(model.beacons))
                self.assertEqual(len({action.key for action in model.actions}), len(model.actions))
                self.assertEqual(len({event.key for event in model.events}), len(model.events))
                for prop in model.properties:
                    value = prop.validate(prop.default)
                    self.assertIsInstance(prop.encode(value), bytes)
                    self.assertIn(prop.derived, (None, "present_minutes", "absent_minutes", "unix_time"))
                    if prop.semantic == "battery":
                        self.assertEqual(value, 100)
                    self.assertTrue(prop.entity_domains)
                    self.assertIsInstance(prop.notify, bool)
                    if prop.alias_of:
                        self.assertIn(prop.alias_of, model.property_by_key)
                        self.assertIsNone(model.property_by_key[prop.alias_of].alias_of)
                        self.assertTrue(prop.spec_visible)
                        self.assertFalse(prop.notify)
                        self.assertFalse(prop.writable)
                for action in model.actions:
                    self.assertEqual(action.key, f"{action.siid}.{action.aiid}")
                    self.assertTrue(set(action.input_keys + action.output_keys) <= model.property_by_key.keys())
                for event in model.events:
                    self.assertEqual(event.key, f"{event.siid}.e.{event.eiid}")
                    self.assertTrue(set(event.argument_keys) <= model.property_by_key.keys())
                    self.assertTrue(set(event.beacon_keys) <= model.property_by_key.keys())

    def test_all_default_beacons_and_events_fit_one_object(self):
        for model in models.MODEL_CATALOG.values():
            values = {prop.key: prop.validate(prop.default) for prop in model.properties}
            with self.subTest(model=model.model):
                for beacon in model.beacons:
                    self.assertTrue(set(beacon.property_keys or (beacon.property_key,)) <= values.keys())
                    payload = beacon.encode_values(values)
                    self.assertLessEqual(len(payload), 9)
                for event in model.events:
                    self.assertLessEqual(len(event.encode(values)), 9)

    def test_control_profiles_include_source_tables_and_compatibility_reads(self):
        for key, count in {"careco.nlight.o654": 9, "xiaomi.cooler.r02p": 14, "yunmi.kettle.v13": 17, "xiaomi.diffuser.xwczxf": 11, "sharge.plug.sj01": 4}.items():
            self.assertEqual(len(models.get_model(key).properties), count)
        placeholder = models.get_model("careco.nlight.o654").property_by_key["8.2"]
        self.assertEqual(placeholder.type_code, models.STRING)
        self.assertEqual(placeholder.encode(placeholder.default), b"")
        self.assertTrue(placeholder.spec_visible)
        self.assertFalse(placeholder.writable)
        self.assertFalse(placeholder.notify)
        self.assertTrue(models.get_model("yunmi.kettle.v13").property_by_key["3.3"].writable)
        for piid in range(6, 11):
            self.assertEqual(models.get_model("yunmi.kettle.v13").property_by_key[f"5.{piid}"].unit, "min")
        self.assertTrue(all(prop.writable for prop in models.get_model("xiaomi.diffuser.xwczxf").properties))

    def test_s400_action_types_and_order_include_identity_outputs(self):
        model = models.get_model("yunmai.scales.ms103")
        sync = next(action for action in model.actions if action.key == "13.1")
        self.assertEqual(sync.input_keys, ("13.1", "13.2", "13.4", "13.3", "13.5"))
        self.assertEqual(sync.output_keys, ("13.6", "13.7", "13.8", "13.9", "13.10"))
        self.assertEqual([model.property_by_key[key].type_code for key in sync.input_keys], [models.U16, models.U8, models.U32, models.BOOL, models.STRING])
        self.assertEqual([model.property_by_key[key].type_code for key in sync.output_keys], [models.U8, models.STRING, models.STRING, models.STRING, models.U8])
        self.assertEqual(model.property_by_key["13.10"].semantic, "battery_status")
        self.assertEqual(model.property_by_key["13.10"].default, 0)
        result = next(event for event in model.events if event.key == "8.e.2")
        self.assertEqual(result.argument_keys, ("8.1",))
        self.assertFalse(model.property_by_key["8.1"].spec_visible)

    def test_internal_motion_input_does_not_replace_the_real_light_property(self):
        model = models.get_model("lumi.motion.bmgl01")
        self.assertEqual(model.property_by_key["0.1"].semantic, "presence")
        self.assertFalse(model.property_by_key["0.1"].spec_visible)
        self.assertEqual(model.property_by_key["2.1"].choices, ((1, "暗"), (2, "亮")))
        self.assertTrue(model.property_by_key["2.1"].spec_visible)

    def test_unknown_models_are_rejected(self):
        with self.assertRaises(ValueError):
            models.get_model("xiaomi.invented.model")

    def test_thermometer_getter_aliases_refer_to_live_canonical_values(self):
        model = models.get_model("miaomiaoce.sensor_ht.t2")
        self.assertEqual(
            {prop.key: (prop.alias_of, prop.type_code) for prop in model.properties if prop.alias_of},
            {
                "2.1001": ("2.1", models.FLOAT), "3.1001": ("2.1", models.FLOAT),
                "3.1": ("2.1", models.FLOAT), "2.1008": ("2.2", models.FLOAT),
                "2.1002": ("2.2", models.FLOAT), "3.1002": ("2.2", models.U8),
                "2.1003": ("2.3", models.U8), "3.1003": ("2.3", models.U8),
            },
        )
        self.assertEqual({prop.key for prop in model.properties if prop.notify}, {"2.1", "2.2", "2.3"})
        self.assertEqual(model.property_by_key["2.1001"].encode(25.6), bytes.fromhex("cdcccc41"))
        self.assertEqual(model.property_by_key["3.1002"].encode(58), b"\x3a")
        self.assertEqual(model.property_by_key["3.1003"].encode(100), b"\x64")

    def test_ptx_battery_get_aliases_do_not_allow_arbitrary_unknown_gets(self):
        model = models.get_model("090615.remote.btsw1")
        self.assertEqual(
            {prop.key: prop.alias_of for prop in model.properties if prop.alias_of},
            {"3.1004": "3.1003", "3.1005": "3.1003"},
        )
        for key in ("3.1004", "3.1005"):
            prop = model.property_by_key[key]
            self.assertEqual(prop.type_code, models.U8)
            self.assertEqual(prop.encode(87), b"\x57")
            self.assertFalse(prop.notify)
        self.assertNotIn("3.9999", model.property_by_key)

    def test_s400_getter_placeholder_is_readable_without_measurement_notifications(self):
        placeholder = models.get_model("yunmai.scales.ms103").property_by_key["2.1001"]
        self.assertEqual(placeholder.type_code, models.FLOAT)
        self.assertEqual(placeholder.encode(placeholder.default), b"\x00" * 4)
        self.assertEqual(placeholder.semantic, "internal_placeholder")
        self.assertTrue(placeholder.spec_visible)
        self.assertFalse(placeholder.writable)
        self.assertFalse(placeholder.notify)

    def test_t3pro_requests_not_implemented_by_source_remain_unknown(self):
        model = models.get_model("xiaomi.sensor_ht.new3pr")
        self.assertEqual(set(model.property_by_key), {"7.1001", "7.1002", "8.1029", "4.1003"})
        for key in ("5.1026", "8.1", "7.1", "6.1027"):
            self.assertNotIn(key, model.property_by_key)


class PropertyValidationTests(unittest.TestCase):
    def test_primitive_golden_vectors_have_no_spec_header(self):
        vectors = (
            (models.BOOL, False, "00"), (models.BOOL, True, "01"),
            (models.U8, 255, "ff"), (models.I8, -30, "e2"),
            (models.U16, 0x1234, "3412"), (models.I16, -53, "cbff"),
            (models.U32, 645, "85020000"), (models.I32, -1, "ffffffff"),
            (models.U64, 0x1122334455667788, "8877665544332211"),
            (models.I64, -1, "ffffffffffffffff"),
            (models.FLOAT, 25.6, "cdcccc41"), (models.STRING, "米家", "e7b1b3e5aeb6"),
        )
        for type_code, value, expected in vectors:
            with self.subTest(type=type_code, value=value):
                definition = models.PropertyDefinition("value", 2, 1, type_code, value)
                self.assertEqual(definition.encode(value).hex(), expected)

    def test_nonfinite_fractional_and_out_of_wire_range_values_are_rejected(self):
        vectors = (
            (models.BOOL, 2), (models.BOOL, "on"),
            (models.U8, -1), (models.U8, 256), (models.U8, 1.5),
            (models.I8, -129), (models.I8, 128),
            (models.U16, 65536), (models.U32, 1 << 32),
            (models.U64, 1 << 64), (models.U64, 1 << 10000),
            (models.I64, -(1 << 63) - 1),
            (models.FLOAT, float("nan")), (models.FLOAT, float("inf")),
            (models.FLOAT, 1e100), (models.STRING, 123),
        )
        for type_code, value in vectors:
            with self.subTest(type=type_code):
                definition = models.PropertyDefinition("value", 2, 1, type_code, 0)
                with self.assertRaises(ValueError):
                    definition.validate(value)

    def test_sensor_bounds_choices_and_config_steps_are_enforced(self):
        for model in models.MODEL_CATALOG.values():
            for prop in model.properties:
                if prop.minimum is not None:
                    with self.subTest(model=model.model, property=prop.key, side="min"):
                        with self.assertRaises(ValueError):
                            prop.validate(prop.minimum - (prop.step or 1))
                if prop.maximum is not None:
                    with self.subTest(model=model.model, property=prop.key, side="max"):
                        with self.assertRaises(ValueError):
                            prop.validate(prop.maximum + (prop.step or 1))
                for value, _ in prop.choices:
                    self.assertEqual(prop.validate(value), value)
        fragrance = models.get_model("xiaomi.diffuser.xwczxf").property_by_key["2.1069"]
        self.assertEqual(fragrance.validate(150), 150)
        with self.assertRaises(ValueError):
            fragrance.validate(61)
        self.assertEqual(models.get_model("xiaomi.cooler.r02p").property_by_key["3.3"].validate(-30), -30)

    def test_float32_rounding_preserves_legal_decimal_steps(self):
        temperature = models.get_model("miaomiaoce.sensor_ht.t2").property_by_key["2.1"]
        decoded = struct.unpack("<f", bytes.fromhex("cdcccc41"))[0]
        value = temperature.validate(decoded)
        self.assertAlmostEqual(value, 25.6)
        self.assertEqual(temperature.encode(decoded), bytes.fromhex("cdcccc41"))
        self.assertEqual(models.get_model("miaomiaoce.sensor_ht.t2").beacon_by_id[0x1004].encode(value), b"\x00\x01")
        with self.assertRaises(ValueError):
            temperature.validate(25.65)
        with self.assertRaises(ValueError):
            models.get_model(models.DEFAULT_MODEL).property_by_key["2.1005"].validate(42.25)

    def test_battery_enums_cannot_be_mistaken_for_percentages(self):
        for key, property_key in (("xiaomi.magnet.03", "3.1107"), ("xiaomi.sensor_smoke.yg2", "6.1132"), ("yunmai.scales.ms103", "13.10")):
            prop = models.get_model(key).property_by_key[property_key]
            self.assertEqual(prop.validate(0), 0)
            with self.assertRaises(ValueError):
                prop.validate(100)
        status = models.get_model("xiaomi.sensor_smoke.yg2").property_by_key["2.1004"]
        with self.assertRaises(ValueError):
            status.validate(0)

    def test_same_property_id_does_not_imply_the_same_charging_enum(self):
        t501 = models.get_model("soocare.toothbrush.1501").property_by_key["3.1034"]
        pro = models.get_model("xiaomi.toothbrush.24p").property_by_key["3.1034"]
        self.assertEqual(dict(t501.choices)[0], "充电中")
        self.assertEqual(dict(pro.choices)[0], "未充电")
        self.assertEqual(dict(t501.choices)[2], "已充满")
        self.assertEqual(dict(pro.choices)[2], "已充满")
        self.assertEqual(t501.validate(3), 3)
        with self.assertRaises(ValueError):
            pro.validate(3)


class BeaconVectorTests(unittest.TestCase):
    def test_legacy_scaled_and_new_float_beacons_match_upstream_vectors(self):
        vectors = (
            ("miaomiaoce.sensor_ht.t2", 0x1004, 25.6, "0001"),
            ("miaomiaoce.sensor_ht.t2", 0x1006, 58.0, "4402"),
            ("yuemee.airmonitor.mhfd1", 0x1010, .08, "0800"),
            ("yuemee.airmonitor.mhfd1", 0x1004, -5.3, "cbff"),
            ("yuemee.airmonitor.mhfd1", 0x1006, 45.6, "c801"),
            ("xiaomi.sensor_ht.mini", 0x4C01, 25.6, "cdcccc41"),
            ("xiaomi.sensor_ht.mini", 0x4C02, 58, "3a"),
            ("xiaomi.sensor_ht.new3pr", 0x601D, 480, "e001"),
            ("hhcc.plantmonitor.v1", 0x1007, 1234, "d20400"),
            ("hhcc.plantmonitor.v1", 0x1009, 1600, "4006"),
            ("shuse.airm.ss006", 0x4C1E, .03, "8fc2f53c"),
            ("xiaomi.cooler.r02p", 0x4C03, -30, "e2"),
            ("soocare.toothbrush.1501", 0x5029, 120, "7800"),
            ("xiaomi.toothbrush.24p", 0x5029, 80, "5000"),
            ("yeelink.light.nl1", 0x1017, 60, "3c000000"),
            ("careco.nlight.o654", 0x0701, True, "01"),
            ("sharge.plug.sj01", 0x1001, False, "00"),
            ("zimi.mosq.v1", 0x1012, True, "01"),
            ("zimi.mosq.v1", 0x1013, 76, "4c"),
        )
        for key, object_id, value, expected in vectors:
            with self.subTest(model=key, object=f"{object_id:04X}"):
                self.assertEqual(models.get_model(key).beacon_by_id[object_id].encode(value).hex(), expected)

    def test_occupancy_vectors_preserve_the_existing_4683_behavior(self):
        model = models.get_model(models.DEFAULT_MODEL)
        self.assertEqual({item.object_id: item.property_key for item in model.beacons}, {0x484E: "2.1078", 0x4805: "2.1005", 0x4852: "2.1082", 0x4851: "2.1081", 0x100A: "3.1003"})
        self.assertEqual(model.beacon_by_id[0x484E].encode(2), b"\x02")
        self.assertEqual(model.beacon_by_id[0x4805].encode(0), b"\x00" * 4)
        self.assertEqual(model.beacon_by_id[0x100A].encode(100), b"\x64")

    def test_mini_mapping_keeps_the_measured_oid_exception(self):
        model = models.get_model("xiaomi.sensor_ht.mini")
        self.assertEqual({item.object_id: item.property_key for item in model.beacons}, {0x4C01: "2.1001", 0x4C02: "2.1002", 0x4803: "3.1003"})

    def test_motion_composite_contains_current_presence_and_light_degree(self):
        model = models.get_model("lumi.motion.bmgl01")
        beacon = model.beacon_by_id[0x000F]
        self.assertEqual(beacon.encode_values({"0.1": True, "2.1": 2}), b"\x01\x01\x00")
        self.assertEqual(beacon.encode_values({"0.1": False, "2.1": 1}), b"\x00\x00\x00")
        self.assertEqual(model.beacon_by_id[0x1017].encode(2), b"\x78\x00\x00\x00")
        event = model.events[0]
        self.assertEqual(event.argument_keys, ())
        self.assertEqual(event.beacon_keys, ("2.1",))
        self.assertEqual(event.encode({"2.1": 1}), b"\x01\x00\x00")
        self.assertEqual(event.encode({"2.1": 2}), b"\x01\x01\x00")
        with self.assertRaises(KeyError):
            event.encode({})
        door = models.get_model("isa.magnet.dw2hl").beacon_by_id[0x1018]
        self.assertEqual(door.encode(1), b"\x00")
        self.assertEqual(door.encode(2), b"\x01")

    def test_u24_and_compound_payloads_preserve_width_and_precision(self):
        beacon = models.BeaconDefinition(0x1007, "2.3", "u24")
        self.assertEqual(beacon.encode(0x123456), b"\x56\x34\x12")
        self.assertEqual(beacon.encode(0xFFFFFF), b"\xff\xff\xff")
        for value in (-1, 0x1000000, 1.5):
            with self.assertRaises(ValueError):
                beacon.encode(value)
        combined = models.BeaconDefinition(0x100D, "2.1", "temp_humidity", property_keys=("2.1", "2.2"))
        self.assertEqual(combined.encode_values({"2.1": -5.3, "2.2": 45.6}), bytes.fromhex("cbffc801"))
        with self.assertRaises(ValueError):
            combined.encode(123)

    def test_button_events_use_model_specific_service_and_key_payload(self):
        single = models.get_model("lumi.remote.mcn001")
        self.assertEqual([event.beacon_id for event in single.events], [0x4E0C, 0x4E0D, 0x4E0E])
        self.assertTrue(all(event.encode({}) == b"\x01" for event in single.events))
        double = models.get_model("yeelink.remote.contrl")
        self.assertEqual(double.events[0].encode({"3.1": 2}), b"\x02")
        eight = models.get_model("giot.remote.v58kwm")
        self.assertEqual([event.beacon_id for event in eight.events], [0x4A0C, 0x4A0D, 0x4A0E])
        self.assertEqual(eight.events[2].encode({"2.1": 8}), b"\x08")
        ptx = models.get_model("090615.remote.btsw1")
        self.assertEqual(ptx.events[0].key, "2.e.1012")
        self.assertEqual(ptx.events[-1].beacon_id, 0x4C01)
        self.assertEqual(ptx.events[-1].encode({}), b"\x01")

    def test_pir_event_contains_light_float_and_s400_has_no_beacon_payload(self):
        pir = models.get_model("xiaomi.motion.pir1")
        event = next(event for event in pir.events if event.key == "2.e.1008")
        self.assertEqual(event.beacon_id, 0x4A08)
        self.assertEqual(event.encode({"2.1005": 50}), bytes.fromhex("00004842"))
        for event in models.get_model("yunmai.scales.ms103").events:
            self.assertEqual(event.encode({}), b"")


if __name__ == "__main__":
    unittest.main()
