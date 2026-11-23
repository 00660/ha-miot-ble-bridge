"""Home Assistant radar entities bridged to Xiaomi BLE occupancy sensors."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.start import async_at_started

from .bridge import BridgeManager, RadarRuntime
from .const import CONF_ADAPTER, DEFAULT_ADAPTER, DOMAIN

_LOGGER = logging.getLogger(__name__)
_PLATFORMS = (Platform.BUTTON, Platform.SENSOR)


async def async_setup(hass: HomeAssistant, _config: dict) -> bool:
    data = hass.data.setdefault(DOMAIN, {"adapters": {}, "lock": asyncio.Lock()})

    async def stop(_event) -> None:
        for manager in tuple(data["adapters"].values()):
            try:
                await manager.async_stop()
            except Exception:
                _LOGGER.exception("Could not finish MiOT bridge shutdown")

    data["stop_unsub"] = hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data.setdefault(DOMAIN, {"adapters": {}, "lock": asyncio.Lock()})
    adapter = entry.options.get(CONF_ADAPTER, entry.data.get(CONF_ADAPTER, DEFAULT_ADAPTER))
    async with data["lock"]:
        manager = data["adapters"].get(adapter)
        created = manager is None
        if created:
            manager = BridgeManager(hass, adapter)
        runtime = None
        try:
            if created:
                await manager.async_start()
            runtime = await RadarRuntime.async_create(hass, entry, manager)
            await manager.async_add(runtime)
        except Exception as error:
            if created:
                try:
                    await manager.async_stop()
                except Exception:
                    _LOGGER.debug("Bridge setup cleanup failed", exc_info=True)
            raise ConfigEntryNotReady(str(error)) from error
        data["adapters"][adapter] = manager
        entry.runtime_data = runtime
    @callback
    def sync_sources(_hass: HomeAssistant) -> None:
        runtime.sync_sources()

    entry.async_on_unload(async_at_started(hass, sync_sources))
    try:
        await hass.config_entries.async_forward_entry_setups(entry, _PLATFORMS)
    except Exception:
        async with data["lock"]:
            await manager.async_remove(runtime)
            if not manager.targets:
                await manager.async_stop()
                data["adapters"].pop(adapter, None)
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if not await hass.config_entries.async_unload_platforms(entry, _PLATFORMS):
        return False
    data = hass.data[DOMAIN]
    runtime: RadarRuntime = entry.runtime_data
    manager = runtime.manager
    async with data["lock"]:
        await manager.async_remove(runtime)
        if not manager.targets:
            await manager.async_stop()
            data["adapters"].pop(manager.adapter, None)
    return True
