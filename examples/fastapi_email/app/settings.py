"""Application settings for the FastAPI email reference app."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from pydantic import SecretStr

from mit_utils.email import (
    DEFAULT_TIMEOUT as DIMAIL_DEFAULT_TIMEOUT,
    GRAPH_BASE_URL,
    GRAPH_DEFAULT_TIMEOUT,
)


class SettingsError(RuntimeError):
    """Raised when reference app configuration is invalid."""


@dataclass(frozen=True)
class Settings:
    dimail_api_key: Optional[SecretStr]
    dimail_host: Optional[str]
    dimail_timeout: int
    graph_tenant_id: Optional[str]
    graph_client_id: Optional[str]
    graph_client_secret: Optional[SecretStr]
    graph_sender_email: Optional[str]
    graph_timeout: int
    graph_base_url: str

    @property
    def has_dimail_api_key(self) -> bool:
        return bool(self.dimail_api_key and self.dimail_api_key.get_secret_value())

    @property
    def has_graph_config(self) -> bool:
        return bool(
            self.graph_tenant_id
            and self.graph_client_id
            and self.graph_client_secret
            and self.graph_client_secret.get_secret_value()
            and self.graph_sender_email
        )


def _read_timeout(env_name: str, default: int) -> int:
    raw_timeout = os.getenv(env_name)
    if raw_timeout is None or raw_timeout == "":
        return default

    try:
        timeout = int(raw_timeout)
    except ValueError as error:
        raise SettingsError("%s must be an integer." % env_name) from error

    if timeout <= 0:
        raise SettingsError("%s must be greater than zero." % env_name)
    return timeout


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    dimail_api_key = os.getenv("DIMAIL_API_KEY")
    graph_client_secret = os.getenv("MS_GRAPH_CLIENT_SECRET")
    return Settings(
        dimail_api_key=SecretStr(dimail_api_key) if dimail_api_key else None,
        dimail_host=os.getenv("DIMAIL_HOST") or None,
        dimail_timeout=_read_timeout("DIMAIL_TIMEOUT", DIMAIL_DEFAULT_TIMEOUT),
        graph_tenant_id=os.getenv("MS_GRAPH_TENANT_ID") or None,
        graph_client_id=os.getenv("MS_GRAPH_CLIENT_ID") or None,
        graph_client_secret=SecretStr(graph_client_secret) if graph_client_secret else None,
        graph_sender_email=os.getenv("MS_GRAPH_SENDER_EMAIL") or None,
        graph_timeout=_read_timeout("MS_GRAPH_TIMEOUT", GRAPH_DEFAULT_TIMEOUT),
        graph_base_url=os.getenv("MS_GRAPH_BASE_URL") or GRAPH_BASE_URL,
    )
