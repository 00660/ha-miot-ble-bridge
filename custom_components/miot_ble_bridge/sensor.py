"""State diagnostics for MiOT BLE virtual radars."""

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, MANUFACTURER


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([MiotForwardingStatusSensor(entry)])


class MiotForwardingStatusSensor(SensorEntity):
    """Expose bridge status while keeping binding material private."""

    _attr_has_entity_name = True
    _attr_translation_key = "forwarding_status"
    _attr_name = "转发状态"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:bluetooth-transfer"
    _attr_should_poll = False

    def __init__(self, entry: ConfigEntry) -> None:
        self._runtime = entry.runtime_data
        self._attr_unique_id = f"{entry.entry_id}_forwarding_status"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=self._runtime.name,
            manufacturer=MANUFACTURER,
            model=self._runtime.model.model,
        )

    @property
    def native_value(self) -> str:
        return self._runtime.status

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "mac": self._runtime.mac,
            "presence_entity": self._runtime.presence_entity,
            "illuminance_entity": self._runtime.illuminance_entity,
            "bound": self._runtime.bound,
            "paired_at": self._runtime.paired_at,
            "model": self._runtime.model.model,
            "product_id": f"0x{self._runtime.model.pid:04X}",
            "property_entities": {key: value.get("entity_id") for key, value in self._runtime.property_mappings.items() if value.get("source") == "entity"},
            "diagnostics": self._runtime.diagnostics,
        }

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self._runtime.add_listener(self.async_write_ha_state))
