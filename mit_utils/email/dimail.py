"""Small Python wrapper for the Dimail/ninjaMail API.

This module is meant for application code, not exploration. It validates the
parts of the response that Dimail documents as reliable and raises a typed
error with a compact raw body when the API returns malformed/non-JSON output.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


DEFAULT_HOST = "https://admin.dimail.hu"
DEFAULT_TIMEOUT = 15
ENV_API_KEY = "DIMAIL_API_KEY"
ENV_HOST = "DIMAIL_HOST"

Id = Union[int, str]

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_TIMEOUT",
    "ENV_API_KEY",
    "ENV_HOST",
    "DimailClient",
    "DimailAPIError",
    "DimailConfigError",
    "list_dimail_subscribers_csv",
    "request_dimail",
]

_NON_JSON = object()


class DimailAPIError(RuntimeError):
    """Raised when Dimail returns an error, invalid JSON, or bad HTTP response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        raw_body: str = "",
        payload: Any = None,
    ) -> None:
        """Store Dimail failure details on the exception."""

        super().__init__(message)
        self.status_code = status_code
        self.raw_body = raw_body
        self.payload = payload


class DimailConfigError(RuntimeError):
    """Raised when required Dimail configuration is missing."""


def _resolve_api_key(api_key: Optional[str]) -> str:
    """Resolve the Dimail API key from an argument or environment variable."""

    resolved = api_key or os.getenv(ENV_API_KEY)
    if not resolved:
        raise DimailConfigError("Missing Dimail API key. Set %s or pass api_key." % ENV_API_KEY)
    return resolved


def _resolve_host(host: Optional[str]) -> str:
    """Resolve the Dimail API host from an argument, environment, or default."""

    return host or os.getenv(ENV_HOST) or DEFAULT_HOST


def _api_url(
    host: str,
    endpoint: str,
    query: Mapping[str, Any],
    *,
    bare_query_flags: Optional[Iterable[str]] = None,
    trailing_slash: bool = True,
) -> str:
    """Build a Dimail endpoint URL with the supplied query parameters."""

    clean_host = host.rstrip("/")
    clean_endpoint = endpoint.strip("/")
    path_suffix = "/" if trailing_slash else ""
    encoded_parts = []
    encoded_query = urlencode(query, doseq=True)
    if encoded_query:
        encoded_parts.append(encoded_query)
    for flag in bare_query_flags or ():
        if flag:
            encoded_parts.append(quote(str(flag), safe=""))

    query_string = "&".join(encoded_parts)
    if query_string:
        return "%s/a/%s%s?%s" % (clean_host, clean_endpoint, path_suffix, query_string)
    return "%s/a/%s%s" % (clean_host, clean_endpoint, path_suffix)


def _decode_response_body(raw_body: bytes) -> str:
    """Decode a Dimail response body without failing on invalid bytes."""

    return raw_body.decode("utf-8", errors="replace")


def _parse_json(text: str) -> Any:
    """Parse Dimail JSON, normalizing its empty response variants."""

    stripped = text.strip()
    if stripped == "":
        return None
    if stripped.lower() in {"false", "none", "null"}:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return _NON_JSON


def _decode_csv_bytes(raw_body: bytes) -> str:
    """Decode Dimail's CSV export using likely Central European encodings."""

    for encoding in ("utf-8-sig", "utf-8", "cp1250", "latin-1"):
        try:
            return raw_body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_body.decode("utf-8", errors="replace")


def _csv_dialect(text: str) -> csv.Dialect:
    """Detect the delimiter used by Dimail's subscriber CSV export."""

    try:
        return csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        return csv.excel


def _parse_subscribers_csv(raw_body: bytes) -> List[Dict[str, str]]:
    """Parse Dimail's headerless subscriber CSV into email/name dictionaries."""

    text = _decode_csv_bytes(raw_body)
    dialect = _csv_dialect(text)
    subscribers: List[Dict[str, str]] = []

    for values in csv.reader(text.splitlines(), dialect=dialect):
        if not values or all(not str(value).strip() for value in values):
            continue

        email = str(values[0]).strip() if len(values) >= 1 else ""
        name = str(values[1]).strip() if len(values) >= 2 else ""

        if email:
            subscribers.append({"email": email, "name": name})

    return subscribers


def _subscriber_export_url(host: str, list_id: Id, api_key: str) -> str:
    """Build the support-provided subscriber CSV export URL."""

    clean_host = host.rstrip("/")
    clean_list_id = quote(str(list_id), safe="")
    return "%s/a/clients/%s?%s&download" % (
        clean_host,
        clean_list_id,
        urlencode({"key": api_key}),
    )


def request_dimail(
    endpoint: str,
    data: Optional[Mapping[str, Any]] = None,
    *,
    api_key: Optional[str] = None,
    host: Optional[str] = None,
    method: str = "POST",
    timeout: int = DEFAULT_TIMEOUT,
    bare_query_flags: Optional[Iterable[str]] = None,
    trailing_slash: bool = True,
) -> Any:
    """Send a raw Dimail API request and return the parsed payload.

    Use this when a newly discovered endpoint or response shape is not wrapped
    yet. Feature helpers below are preferred for normal app code. Empty,
    ``null``, ``false``, and Dimail's non-JSON ``False``/``None`` variants are
    treated as empty API responses and raise ``DimailAPIError`` with the raw
    body attached. ``bare_query_flags`` supports Dimail endpoints that expect a
    query flag without ``=value``, such as newsletter listing's ``&get``.
    """

    if not endpoint or not endpoint.strip("/"):
        raise ValueError("endpoint is required.")

    method = method.upper()
    if method not in {"GET", "POST"}:
        raise ValueError("method must be 'GET' or 'POST'.")

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero.")

    data = data or {}
    resolved_api_key = _resolve_api_key(api_key)
    resolved_host = _resolve_host(host)

    if method == "GET":
        url = _api_url(
            resolved_host,
            endpoint,
            {"key": resolved_api_key, **data},
            bare_query_flags=bare_query_flags,
            trailing_slash=trailing_slash,
        )
        body = None
    else:
        url = _api_url(
            resolved_host,
            endpoint,
            {"key": resolved_api_key},
            bare_query_flags=bare_query_flags,
            trailing_slash=trailing_slash,
        )
        body = urlencode(data, doseq=True).encode("utf-8")

    request = Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            text = _decode_response_body(response.read())
            payload = _parse_json(text)
            if payload is _NON_JSON:
                raise DimailAPIError(
                    "Dimail returned a non-JSON response.",
                    status_code=response.status,
                    raw_body=text,
                )
            if payload is None:
                raise DimailAPIError(
                    "Dimail returned an empty response.",
                    status_code=response.status,
                    raw_body=text,
                    payload=payload,
                )
            return payload
    except HTTPError as error:
        text = _decode_response_body(error.read())
        payload = _parse_json(text)
        if payload is _NON_JSON:
            payload = None
        raise DimailAPIError(
            "Dimail returned HTTP %s." % error.code,
            status_code=error.code,
            raw_body=text,
            payload=payload,
        ) from error
    except URLError as error:
        raise DimailAPIError("Dimail request failed: %s" % error.reason) from error


def list_dimail_subscribers_csv(
    list_id: Id,
    *,
    api_key: Optional[str] = None,
    host: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[Dict[str, str]]:
    """Return subscribers for a Dimail list via the CSV export workaround.

    Dimail does not currently expose a JSON subscriber-listing endpoint. Their
    supported workaround is a CSV download at ``/a/clients/<list_id>?key=...&download``.
    This helper keeps the CSV fully in memory and returns dictionaries with
    stable ``email`` and ``name`` keys.
    """

    if not list_id:
        raise ValueError("list_id is required.")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero.")

    resolved_api_key = _resolve_api_key(api_key)
    resolved_host = _resolve_host(host)
    url = _subscriber_export_url(resolved_host, list_id, resolved_api_key)
    request = Request(url, method="GET", headers={"Accept": "text/csv,*/*"})

    try:
        with urlopen(request, timeout=timeout) as response:
            return _parse_subscribers_csv(response.read())
    except HTTPError as error:
        text = _decode_response_body(error.read())
        payload = _parse_json(text)
        if payload is _NON_JSON:
            payload = None
        raise DimailAPIError(
            "Dimail returned HTTP %s." % error.code,
            status_code=error.code,
            raw_body=text,
            payload=payload,
        ) from error
    except URLError as error:
        raise DimailAPIError("Dimail request failed: %s" % error.reason) from error


def _expect_status(data: Any, expected_statuses: Iterable[str]) -> Dict[str, Any]:
    """Return a Dimail payload after validating its ``status`` field."""

    expected = set(expected_statuses)

    if not isinstance(data, dict):
        raise DimailAPIError("Dimail returned a payload without a status field.", payload=data)

    status = data.get("status")
    if status not in expected:
        expected_text = ", ".join(sorted(expected))
        raise DimailAPIError(
            "Dimail returned status %r; expected one of: %s." % (status, expected_text),
            payload=data,
        )

    return data


def _collection(data: Any, label: str) -> List[Any]:
    """Normalize Dimail list-like responses to a Python list."""

    if data is None:
        raise DimailAPIError("Dimail returned an empty %s response." % label, payload=data)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if all(str(key).isdigit() for key in data):
            return [data[key] for key in sorted(data, key=lambda value: int(value))]
        return [data]

    raise DimailAPIError("Dimail returned a %s payload that is not a collection." % label, payload=data)


class DimailClient:
    """Synchronous client for the Dimail/ninjaMail API."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        host: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Create a reusable Dimail API client.

        Args:
            api_key: Dimail API key. Falls back to ``DIMAIL_API_KEY``.
            host: Dimail API host. Falls back to ``DIMAIL_HOST`` or the public
                default host.
            timeout: HTTP timeout in seconds.
        """

        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

        self.api_key = api_key
        self.host = host
        self.timeout = timeout

    def request(
        self,
        endpoint: str,
        data: Optional[Mapping[str, Any]] = None,
        *,
        method: str = "POST",
        bare_query_flags: Optional[Iterable[str]] = None,
        trailing_slash: bool = True,
    ) -> Any:
        """Send a raw request using this client's configuration."""

        return request_dimail(
            endpoint,
            data,
            api_key=self.api_key,
            host=self.host,
            method=method,
            timeout=self.timeout,
            bare_query_flags=bare_query_flags,
            trailing_slash=trailing_slash,
        )

    def list_lists(self) -> List[Dict[str, Any]]:
        """Return mailing lists visible to the configured API key."""

        payload = self.request("list", {"get": "1"})
        return _collection(payload, "list")

    def create_list(self, name: str) -> Dict[str, Any]:
        """Create a mailing list with the given name."""

        payload = self.request("list", {"new": "1", "name": name})
        return _expect_status(payload, {"success"})

    def remove_list(self, list_id: Id) -> Dict[str, Any]:
        """Remove a mailing list by ID."""

        payload = self.request("list", {"remove": "1", "id": list_id})
        return _expect_status(payload, {"success"})

    def subscribe(
        self,
        list_id: Id,
        email: str,
        *,
        name: str = "",
        activated: bool = True,
        force_name_change: bool = False,
    ) -> Dict[str, Any]:
        """Subscribe an email address to a mailing list."""

        payload = self.request(
            "subscribe",
            {
                "list": list_id,
                "name": name,
                "email": email,
                "activated": "1" if activated else "0",
                "forcenamechange": "1" if force_name_change else "0",
            },
        )
        return _expect_status(payload, {"success"})

    def unsubscribe(self, list_id: Id, email: str) -> Dict[str, Any]:
        """Unsubscribe an email address from a mailing list."""

        payload = self.request("unsubscribe", {"list": list_id, "email": email})
        return _expect_status(payload, {"success"})

    def list_subscribers(self, list_id: Id) -> List[Dict[str, str]]:
        """Return subscribers from a mailing list as ``email``/``name`` dictionaries."""

        return list_dimail_subscribers_csv(
            list_id,
            api_key=self.api_key,
            host=self.host,
            timeout=self.timeout,
        )

    def list_newsletters(self) -> List[Dict[str, Any]]:
        """Return newsletters visible to the configured API key."""

        payload = self.request(
            "newsletter",
            method="GET",
            bare_query_flags=["get"],
            trailing_slash=False,
        )
        return _collection(payload, "newsletter")

    def create_newsletter(
        self,
        subject: str,
        html_message: str,
        *,
        text_message: str = "",
    ) -> Dict[str, Any]:
        """Create a newsletter with HTML and optional plain-text content."""

        payload = self.request(
            "newsletter",
            {
                "new": "1",
                "subject": subject,
                "message": html_message,
                "message_text": text_message,
            },
        )
        return _expect_status(payload, {"success"})

    def update_newsletter(
        self,
        newsletter_id: Id,
        subject: str,
        html_message: str,
        *,
        text_message: str = "",
    ) -> Dict[str, Any]:
        """Update an existing newsletter's subject and content."""

        payload = self.request(
            "newsletter",
            {
                "new": "1",
                "id": newsletter_id,
                "subject": subject,
                "message": html_message,
                "message_text": text_message,
            },
        )
        return _expect_status(payload, {"success"})

    def send_newsletter(self, newsletter_id: Id, *, start: int = 0) -> Dict[str, Any]:
        """Queue a newsletter for sending."""

        payload = self.request("newsletter", {"send": "1", "id": newsletter_id, "start": start})
        return _expect_status(payload, {"success", "already_queued"})

    def create_campaign(self, name: str) -> Dict[str, Any]:
        """Create a campaign with the given name."""

        payload = self.request("campaign", {"new": "1", "name": name})
        return _expect_status(payload, {"success"})

    def remove_campaign(self, campaign_id: Id) -> Dict[str, Any]:
        """Remove a campaign by ID."""

        payload = self.request("campaign", {"remove": "1", "id": campaign_id})
        return _expect_status(payload, {"success"})

    def update_campaign_lists(self, campaign_id: Id, list_ids: Iterable[Id]) -> Dict[str, Any]:
        """Replace the mailing lists attached to a campaign."""

        payload = self.request("campaign", {"update": "1", "id": campaign_id, "lists[]": list(list_ids)})
        return _expect_status(payload, {"success"})

    def attach_campaign_to_newsletter(
        self,
        campaign_id: Id,
        newsletter_id: Id,
        *,
        campaign_field: str = "campaign",
    ) -> Dict[str, Any]:
        """Attach a campaign to a newsletter."""

        payload = self.request(
            "campaign",
            {"relations": "1", campaign_field: campaign_id, "newsletter": newsletter_id},
        )
        return _expect_status(payload, {"success"})

    def send_email(
        self,
        to: str,
        subject: str,
        html_message: str,
        *,
        text_message: str = "",
    ) -> Dict[str, Any]:
        """Queue a transactional email through Dimail."""

        payload = self.request(
            "send",
            {
                "to": to,
                "subject": subject,
                "message": html_message,
                "message_text": text_message,
            },
        )
        return _expect_status(payload, {"message_queued"})

    def check_email_status(self, send_id: Id) -> Dict[str, Any]:
        """Return the delivery status for a queued transactional email."""

        payload = self.request("send", {"just_asking": send_id}, method="GET")
        return _expect_status(payload, {"success", "failed"})

    def get_statistics(self, newsletter_id: Id, *, statistics_type: int = 1) -> Any:
        """Return statistics for a newsletter."""

        payload = self.request("statistics", {"newsletter": newsletter_id, "type": statistics_type})
        if payload is None:
            raise DimailAPIError("Dimail returned an empty statistics response.", payload=payload)
        return payload

    def create_login_token(self, rkey: str) -> Dict[str, Any]:
        """Create a Dimail login token for the given remote key."""

        payload = self.request("login", {"rkey": rkey})
        return _expect_status(payload, {"success"})
