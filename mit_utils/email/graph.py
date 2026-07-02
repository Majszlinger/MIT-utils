"""Synchronous Microsoft Graph email helpers."""

from __future__ import annotations

import base64
import mimetypes
import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import quote


GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEFAULT_TIMEOUT = 10
ENV_TENANT_ID = "MS_GRAPH_TENANT_ID"
ENV_CLIENT_ID = "MS_GRAPH_CLIENT_ID"
ENV_CLIENT_SECRET = "MS_GRAPH_CLIENT_SECRET"
DEFAULT_ATTACHMENT_CONTENT_TYPE = "application/octet-stream"

Recipient = Union[str, Dict[str, Any]]

__all__ = [
    "DEFAULT_TIMEOUT",
    "ENV_CLIENT_ID",
    "ENV_CLIENT_SECRET",
    "ENV_TENANT_ID",
    "GRAPH_BASE_URL",
    "GRAPH_SCOPE",
    "GraphAPIError",
    "GraphConfigError",
    "GraphEmailClient",
    "get_access_token",
    "send_graph_email",
]

_msal_apps: Dict[Tuple[str, str], Any] = {}


class GraphConfigError(RuntimeError):
    """Raised when required Microsoft Graph configuration is missing."""


class GraphAPIError(RuntimeError):
    """Raised when Microsoft Graph returns an unsuccessful response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        response_text: str = "",
        payload: Any = None,
    ) -> None:
        """Store Graph failure details on the exception.

        Args:
            message: Human-readable error message.
            status_code: HTTP status returned by Microsoft Graph, if available.
            response_text: Raw response body text.
            payload: Parsed JSON response body when Graph returned JSON.
        """

        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text
        self.payload = payload


def _load_httpx() -> Any:
    """Import httpx lazily so the email extra stays optional."""

    try:
        import httpx
    except ImportError as error:
        raise GraphConfigError('Microsoft Graph email requires the "email" extra: pip install "mit_utils[email]".') from error
    return httpx


def _load_msal() -> Any:
    """Import MSAL lazily so Graph token support stays optional."""

    try:
        import msal
    except ImportError as error:
        raise GraphConfigError('Microsoft Graph token acquisition requires the "email" extra: pip install "mit_utils[email]".') from error
    return msal


def _resolve_setting(value: Optional[str], env_name: str, label: str) -> str:
    """Resolve a setting from an explicit value or environment variable.

    Args:
        value: Explicit value passed by the caller.
        env_name: Environment variable to read when ``value`` is empty.
        label: Human-readable setting name used in error messages.

    Returns:
        The resolved setting value.

    Raises:
        GraphConfigError: If neither the argument nor environment variable is
            set.
    """

    resolved = value or os.getenv(env_name)
    if not resolved:
        raise GraphConfigError("Missing Microsoft Graph %s. Set %s or pass it directly." % (label, env_name))
    return resolved


def _get_msal_app(
    *,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> Any:
    """Return a cached MSAL confidential client application.

    MSAL keeps an in-memory token cache on the app instance. Reusing the same
    instance lets MSAL return cached tokens when possible instead of requesting
    a fresh token every time.

    Args:
        tenant_id: Azure tenant ID. Falls back to ``MS_GRAPH_TENANT_ID``.
        client_id: Azure app registration client ID. Falls back to
            ``MS_GRAPH_CLIENT_ID``.
        client_secret: Azure app registration client secret. Falls back to
            ``MS_GRAPH_CLIENT_SECRET``.

    Returns:
        A configured MSAL ``ConfidentialClientApplication``.

    Raises:
        GraphConfigError: If required configuration is missing.
    """

    resolved_tenant_id = _resolve_setting(tenant_id, ENV_TENANT_ID, "tenant ID")
    resolved_client_id = _resolve_setting(client_id, ENV_CLIENT_ID, "client ID")
    resolved_client_secret = _resolve_setting(client_secret, ENV_CLIENT_SECRET, "client secret")
    cache_key = (resolved_tenant_id, resolved_client_id)

    if cache_key not in _msal_apps:
        msal = _load_msal()
        _msal_apps[cache_key] = msal.ConfidentialClientApplication(
            resolved_client_id,
            authority="https://login.microsoftonline.com/%s" % resolved_tenant_id,
            client_credential=resolved_client_secret,
        )

    return _msal_apps[cache_key]


def get_access_token(
    *,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    scopes: Optional[Sequence[str]] = None,
) -> str:
    """Return a cached or newly acquired Microsoft Graph app access token.

    MSAL handles token cache reuse and expiration checks for client credentials.

    Args:
        tenant_id: Azure tenant ID. Falls back to ``MS_GRAPH_TENANT_ID``.
        client_id: Azure app registration client ID. Falls back to
            ``MS_GRAPH_CLIENT_ID``.
        client_secret: Azure app registration client secret. Falls back to
            ``MS_GRAPH_CLIENT_SECRET``.
        scopes: Graph scopes to request. Defaults to
            ``["https://graph.microsoft.com/.default"]`` for app permissions.

    Returns:
        A bearer token that can be used with Microsoft Graph.

    Raises:
        GraphConfigError: If configuration is missing or Azure AD does not
            return an access token.
    """

    result = _get_msal_app(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    ).acquire_token_for_client(scopes=list(scopes or [GRAPH_SCOPE]))

    if "access_token" in result:
        return result["access_token"]

    error_description = result.get("error_description") or result.get("error") or "unknown error"
    raise GraphConfigError("Could not acquire Microsoft Graph token: %s" % error_description)


def _recipient(email_address: str) -> Dict[str, Dict[str, str]]:
    """Build the Microsoft Graph recipient shape from an email address."""

    if not email_address:
        raise ValueError("recipient email address is required.")
    return {"emailAddress": {"address": email_address}}


def _validate_recipient_dict(recipient: Dict[str, Any]) -> Dict[str, Any]:
    """Validate that a dictionary already matches Graph's recipient shape."""

    email_address = recipient.get("emailAddress")
    if not isinstance(email_address, dict) or not email_address.get("address"):
        raise ValueError("Graph recipient dictionaries must include emailAddress.address.")
    return recipient


def _normalize_recipients(recipients: Union[Recipient, Iterable[Recipient]]) -> List[Dict[str, Any]]:
    """Convert one or more recipients into Graph's expected list format.

    Args:
        recipients: A single email string, a Graph recipient dict, or an
            iterable containing either shape.

    Returns:
        A list of Graph recipient dictionaries.
    """

    if isinstance(recipients, str):
        return [_recipient(recipients)]

    if recipients is None:
        raise ValueError("at least one recipient is required.")

    if isinstance(recipients, dict):
        return [_validate_recipient_dict(recipients)]

    normalized = []
    try:
        iterator = iter(recipients)
    except TypeError as error:
        raise ValueError("recipients must be an email string, Graph recipient dictionary, or iterable.") from error

    for recipient in iterator:
        if isinstance(recipient, str):
            normalized.append(_recipient(recipient))
        elif isinstance(recipient, dict):
            normalized.append(_validate_recipient_dict(recipient))
        else:
            raise ValueError("recipients must be email strings or Graph recipient dictionaries.")

    if not normalized:
        raise ValueError("at least one recipient is required.")
    return normalized


def _message_payload(
    *,
    to_recipients: Union[Recipient, Iterable[Recipient]],
    subject: str,
    body: str,
    body_content_type: str,
    cc_recipients: Optional[Union[Recipient, Iterable[Recipient]]] = None,
    bcc_recipients: Optional[Union[Recipient, Iterable[Recipient]]] = None,
    attachments: Optional[Iterable[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build the ``message`` object for the Graph ``sendMail`` request.

    Args:
        to_recipients: Required recipient or recipients.
        subject: Email subject line.
        body: Email body content.
        body_content_type: Graph body content type, usually ``Text`` or
            ``HTML``.
        cc_recipients: Optional CC recipient or recipients.
        bcc_recipients: Optional BCC recipient or recipients.
        attachments: Optional file attachments.

    Returns:
        A dictionary matching Microsoft Graph's ``message`` payload shape.
    """

    message = {
        "subject": subject,
        "body": {"contentType": body_content_type, "content": body},
        "toRecipients": _normalize_recipients(to_recipients),
    }

    if cc_recipients:
        message["ccRecipients"] = _normalize_recipients(cc_recipients)
    if bcc_recipients:
        message["bccRecipients"] = _normalize_recipients(bcc_recipients)
    graph_attachments = _graph_attachments(attachments)
    if graph_attachments:
        message["attachments"] = graph_attachments

    return message


def _normalize_attachments(
    attachments: Optional[Iterable[Mapping[str, Any]]],
) -> List[Dict[str, Any]]:
    if attachments is None:
        return []

    normalized = []
    for attachment in attachments:
        if not isinstance(attachment, Mapping):
            raise ValueError("attachments must contain mapping objects.")

        filename = attachment.get("filename")
        if not isinstance(filename, str) or not filename:
            raise ValueError("attachment filename is required.")

        content = attachment.get("content")
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise ValueError("attachment content must be bytes-like.")
        content_bytes = bytes(content)

        content_type = attachment.get("content_type") or mimetypes.guess_type(filename)[0]
        if not isinstance(content_type, str) or not content_type:
            content_type = DEFAULT_ATTACHMENT_CONTENT_TYPE

        normalized.append(
            {
                "filename": filename,
                "content": content_bytes,
                "content_type": content_type,
            }
        )
    return normalized


def _graph_attachments(attachments: Optional[Iterable[Mapping[str, Any]]]) -> List[Dict[str, str]]:
    return [
        {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": attachment["filename"],
            "contentType": attachment["content_type"],
            "contentBytes": base64.b64encode(attachment["content"]).decode("ascii"),
        }
        for attachment in _normalize_attachments(attachments)
    ]


def send_graph_email(
    access_token: str,
    sender_email: str,
    recipient_email: str,
    subject: str,
    body: str,
    *,
    body_content_type: str = "Text",
    attachments: Optional[Iterable[Mapping[str, Any]]] = None,
    save_to_sent_items: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    """Send a single email through Microsoft Graph using an existing token.

    This function mirrors the simple helper you already had in the app. Use it
    when the app already gets the access token elsewhere, such as in a FastAPI
    dependency.

    Args:
        access_token: Bearer token authorized for Graph ``sendMail``.
        sender_email: Mailbox that sends the message.
        recipient_email: Recipient email address.
        subject: Email subject line.
        body: Email body content.
        body_content_type: ``Text`` or ``HTML``.
        attachments: Optional file attachments.
        save_to_sent_items: Whether Graph should save the email in Sent Items.
        timeout: HTTP timeout in seconds.

    Raises:
        GraphAPIError: If Microsoft Graph rejects the send request.
    """

    client = GraphEmailClient(access_token=access_token, timeout=timeout)
    client.send_email(
        sender_email=sender_email,
        to_recipients=recipient_email,
        subject=subject,
        body=body,
        body_content_type=body_content_type,
        attachments=attachments,
        save_to_sent_items=save_to_sent_items,
    )


class GraphEmailClient:
    """Small synchronous client for Microsoft Graph ``sendMail``.

    The class is optional. It is useful when an app sends more than one email
    and wants to keep Graph configuration/token handling in one object.
    Function-only usage remains available through ``get_access_token`` and
    ``send_graph_email``.
    """

    def __init__(
        self,
        *,
        access_token: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        graph_base_url: str = GRAPH_BASE_URL,
    ) -> None:
        """Create a reusable Microsoft Graph email client.

        Args:
            access_token: Existing bearer token. When provided, token
                acquisition is skipped.
            tenant_id: Azure tenant ID. Falls back to ``MS_GRAPH_TENANT_ID``
                when the client needs to acquire a token.
            client_id: Azure app registration client ID. Falls back to
                ``MS_GRAPH_CLIENT_ID``.
            client_secret: Azure app registration client secret. Falls back to
                ``MS_GRAPH_CLIENT_SECRET``.
            timeout: HTTP timeout in seconds.
            graph_base_url: Graph API base URL. Override mainly for tests or
                sovereign cloud environments.
        """

        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")
        if not graph_base_url:
            raise ValueError("graph_base_url is required.")

        self.access_token = access_token
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.graph_base_url = graph_base_url.rstrip("/")

    def get_access_token(self) -> str:
        """Return this client's token, acquiring it through MSAL if needed.

        Returns:
            A bearer token authorized for Microsoft Graph.

        Raises:
            GraphConfigError: If token acquisition configuration is missing or
                Azure AD does not return an access token.
        """

        if self.access_token:
            return self.access_token

        self.access_token = get_access_token(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        return self.access_token

    def send_email(
        self,
        *,
        sender_email: str,
        to_recipients: Union[Recipient, Iterable[Recipient]],
        subject: str,
        body: str,
        body_content_type: str = "Text",
        save_to_sent_items: bool = True,
        cc_recipients: Optional[Union[Recipient, Iterable[Recipient]]] = None,
        bcc_recipients: Optional[Union[Recipient, Iterable[Recipient]]] = None,
        attachments: Optional[Iterable[Mapping[str, Any]]] = None,
    ) -> None:
        """Send an email through Microsoft Graph.

        Args:
            sender_email: Mailbox that sends the message.
            to_recipients: Recipient email, Graph recipient dict, or iterable of
                either.
            subject: Email subject line.
            body: Email body content.
            body_content_type: ``Text`` or ``HTML``.
            save_to_sent_items: Whether Graph should save the email in Sent
                Items.
            cc_recipients: Optional CC recipient or recipients.
            bcc_recipients: Optional BCC recipient or recipients.
            attachments: Optional file attachments.

        Raises:
            ValueError: If ``body_content_type`` is not ``Text`` or ``HTML``.
            GraphConfigError: If the client must acquire a token and required
                configuration is missing.
            GraphAPIError: If Microsoft Graph rejects the send request.
        """

        if not sender_email:
            raise ValueError("sender_email is required.")

        token = self.get_access_token()
        if not token:
            raise GraphConfigError("Missing Microsoft Graph access token.")

        if body_content_type not in {"Text", "HTML"}:
            raise ValueError("body_content_type must be 'Text' or 'HTML'.")

        url = "%s/users/%s/sendMail" % (self.graph_base_url, quote(sender_email, safe=""))
        headers = {
            "Authorization": "Bearer %s" % token,
            "Content-Type": "application/json",
        }
        payload = {
            "message": _message_payload(
                to_recipients=to_recipients,
                subject=subject,
                body=body,
                body_content_type=body_content_type,
                cc_recipients=cc_recipients,
                bcc_recipients=bcc_recipients,
                attachments=attachments,
            ),
            "saveToSentItems": save_to_sent_items,
        }

        httpx = _load_httpx()
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as error:
            raise GraphAPIError("Microsoft Graph request failed: %s" % error) from error

        if response.status_code != 202:
            payload = None
            try:
                payload = response.json()
            except ValueError:
                pass
            raise GraphAPIError(
                "Microsoft Graph sendMail failed with HTTP %s." % response.status_code,
                status_code=response.status_code,
                response_text=response.text,
                payload=payload,
            )
