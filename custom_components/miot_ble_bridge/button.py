"""Pairing controls for MiOT BLE virtual radars."""

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, MANUFACTURER, MODEL


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities(
        [
            MiotPairingButton(entry, start_pairing=True),
            MiotPairingButton(entry, start_pairing=False),
        ]
    )


class MiotPairingButton(ButtonEntity):
    """Control the pairing window without erasing stored keys."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.CONFIG
    _attr_should_poll = False

    def __init__(self, entry: ConfigEntry, *, start_pairing: bool) -> None:
        self._runtime = entry.runtime_data
        self._start_pairing = start_pairing
        self._attr_translation_key = (
            "start_pairing" if start_pairing else "stop_pairing"
        )
        self._attr_name = "开始米家配对" if start_pairing else "结束配对"
        self._attr_icon = (
            "mdi:bluetooth-connect" if start_pairing else "mdi:stop-circle-outline"
        )
        self._attr_unique_id = f"{entry.entry_id}_{self._attr_translation_key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=self._runtime.name,
            manufacturer=MANUFACTURER,
            model=MODEL,
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self._runtime.add_listener(self.async_write_ha_state))

    async def async_press(self) -> None:
        if self._start_pairing:
            await self._runtime.async_pair()
        else:
            await self._runtime.async_stop_pair()
