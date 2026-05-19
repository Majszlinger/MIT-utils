"""Email automation helpers."""

from .dimail import (
    DEFAULT_HOST as DIMAIL_DEFAULT_HOST,
    DEFAULT_TIMEOUT as DIMAIL_DEFAULT_TIMEOUT,
    ENV_API_KEY,
    ENV_HOST as DIMAIL_ENV_HOST,
    DimailAPIError,
    DimailClient,
    DimailConfigError,
    request_dimail,
)

DEFAULT_HOST = DIMAIL_DEFAULT_HOST
DEFAULT_TIMEOUT = DIMAIL_DEFAULT_TIMEOUT
ENV_HOST = DIMAIL_ENV_HOST

_GRAPH_EXPORTS = (
    "ENV_CLIENT_ID",
    "ENV_CLIENT_SECRET",
    "ENV_TENANT_ID",
    "GRAPH_BASE_URL",
    "GRAPH_DEFAULT_TIMEOUT",
    "GRAPH_SCOPE",
    "GraphAPIError",
    "GraphConfigError",
    "GraphEmailClient",
    "get_access_token",
    "send_graph_email",
)

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_TIMEOUT",
    "DIMAIL_DEFAULT_HOST",
    "DIMAIL_DEFAULT_TIMEOUT",
    "ENV_API_KEY",
    "ENV_HOST",
    "DIMAIL_ENV_HOST",
    "DimailAPIError",
    "DimailClient",
    "DimailConfigError",
    "request_dimail",
    *_GRAPH_EXPORTS,
]


def __getattr__(name: str):
    """Load Microsoft Graph helpers lazily so Dimail can work without extras."""

    if name not in _GRAPH_EXPORTS:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))

    from . import graph

    if name == "GRAPH_DEFAULT_TIMEOUT":
        return graph.DEFAULT_TIMEOUT
    return getattr(graph, name)
