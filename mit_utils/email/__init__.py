"""Email automation helpers."""

from .dimail import (
    DEFAULT_HOST as DIMAIL_DEFAULT_HOST,
    DEFAULT_TIMEOUT as DIMAIL_DEFAULT_TIMEOUT,
    ENV_API_KEY,
    ENV_HOST as DIMAIL_ENV_HOST,
    DimailAPIError,
    DimailClient,
    DimailConfigError,
    list_dimail_subscribers_csv,
    request_dimail,
)
from .bulk import (
    BulkEmailResult,
    DEFAULT_DELAY_SECONDS as BULK_DEFAULT_DELAY_SECONDS,
    ENV_DELAY_SECONDS as BULK_ENV_DELAY_SECONDS,
    send_emails_generator,
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

_GMAIL_EXPORTS = (
    "ENV_DELEGATED_SUBJECT",
    "ENV_SENDER_EMAIL",
    "ENV_SERVICE_ACCOUNT_FILE",
    "ENV_SERVICE_ACCOUNT_INFO_BASE64",
    "ENV_TIMEOUT",
    "GMAIL_API_SERVICE_NAME",
    "GMAIL_API_VERSION",
    "GMAIL_DEFAULT_TIMEOUT",
    "GMAIL_SEND_SCOPE",
    "GmailAPIError",
    "GmailConfigError",
    "GmailEmailClient",
    "send_gmail_email",
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
    "BulkEmailResult",
    "BULK_DEFAULT_DELAY_SECONDS",
    "BULK_ENV_DELAY_SECONDS",
    "list_dimail_subscribers_csv",
    "request_dimail",
    "send_emails_generator",
    *_GRAPH_EXPORTS,
    *_GMAIL_EXPORTS,
]


def __getattr__(name: str):
    """Load optional email-provider helpers lazily so extras stay optional."""

    if name not in _GRAPH_EXPORTS and name not in _GMAIL_EXPORTS:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))

    if name in _GRAPH_EXPORTS:
        from . import graph

        if name == "GRAPH_DEFAULT_TIMEOUT":
            return graph.DEFAULT_TIMEOUT
        return getattr(graph, name)

    from . import gmail

    if name == "GMAIL_DEFAULT_TIMEOUT":
        return gmail.DEFAULT_TIMEOUT
    return getattr(gmail, name)
