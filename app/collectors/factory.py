"""Factory that builds collectors and enforces the live/offline policy.

The single choke point for outbound-collection safety: when
``ENABLE_LIVE_COLLECTORS`` is false, every collector is offline (serves bundled
samples) regardless of any configured key. Provider API keys are read from
settings and injected here so collectors never touch configuration directly.
"""

from __future__ import annotations

import functools

from app.collectors.common import OfflineFirstCollector
from app.collectors.providers import COLLECTOR_CLASSES
from app.collectors.registry import get_info, is_supported
from app.config import Settings, get_settings
from app.core.exceptions import ValidationError

# Map collector name → settings attribute holding its provider key.
_KEY_PROVIDERS = {
    "abuseipdb": "abuseipdb",
    "otx": "otx",
}


class CollectorFactory:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def live_enabled(self) -> bool:
        return self._settings.enable_live_collectors

    def available(self) -> list[str]:
        return list(COLLECTOR_CLASSES.keys())

    def build(self, name: str) -> OfflineFirstCollector:
        name = name.lower()
        if not is_supported(name) or name not in COLLECTOR_CLASSES:
            raise ValidationError(f"Unsupported collector: {name}")
        info = get_info(name)
        api_key = ""
        if info and info.requires_key:
            provider = _KEY_PROVIDERS.get(name, name)
            api_key = self._settings.provider_key(provider)
        return COLLECTOR_CLASSES[name](self._settings, api_key=api_key)


@functools.lru_cache(maxsize=1)
def get_collector_factory() -> CollectorFactory:
    return CollectorFactory()
