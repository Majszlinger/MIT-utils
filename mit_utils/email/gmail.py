"""Synchronous Gmail API email helper using service account delegation."""

from __future__ import annotations

import base64
import html
import json
import mimetypes
import os
import re
from email.message import EmailMessage
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union


GMAIL_API_SERVICE_NAME = "gmail"
GMAIL_API_VERSION = "v1"
GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
DEFAULT_TIMEOUT = 10
ENV_SERVICE_ACCOUNT_FILE = "GOOGLE_APPLICATION_CREDENTIALS"
ENV_SERVICE_ACCOUNT_INFO = "GOOGLE_SERVICE_ACCOUNT_INFO"
ENV_SENDER_EMAIL = "GMAIL_SENDER_EMAIL"
ENV_DELEGATED_SUBJECT = "GMAIL_DELEGATED_SUBJECT"
ENV_TIMEOUT = "GMAIL_TIMEOUT"
BODY_CONTENT_TYPES = {"Text", "HTML"}
DEFAULT_ATTACHMENT_CONTENT_TYPE = "application/octet-stream"

__all__ = [
    "DEFAULT_TIMEOUT",
    "ENV_DELEGATED_SUBJECT",
    "ENV_SENDER_EMAIL",
    "ENV_SERVICE_ACCOUNT_FILE",
    "ENV_SERVICE_ACCOUNT_INFO",
    "ENV_TIMEOUT",
    "GMAIL_API_SERVICE_NAME",
    "GMAIL_API_VERSION",
    "GMAIL_SEND_SCOPE",
    "GmailAPIError",
    "GmailConfigError",
    "GmailEmailClient",
    "send_gmail_email",
]


class GmailConfigError(RuntimeError):
    """Raised when required Gmail API configuration is missing."""


class GmailAPIError(RuntimeError):
    """Raised when Gmail API returns an unsuccessful response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        response_text: str = "",
        payload: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text
        self.payload = payload


def _load_google_modules() -> Tuple[Any, Any, Any, Any, Any, Any]:
    """Import Google client libraries lazily so the email extra stays optional."""

    try:
        import google_auth_httplib2
        import httplib2
        from google.auth.exceptions import GoogleAuthError
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
    except ImportError as error:
        raise GmailConfigError(
            'Gmail API email requires the "email" extra: pip install "mit_utils[email]".'
        ) from error

    return (
        google_auth_httplib2,
        httplib2,
        GoogleAuthError,
        service_account,
        build,
        HttpError,
    )


def _resolve_setting(value: Optional[str], env_name: str, label: str) -> str:
    resolved = value or os.getenv(env_name)
    if not resolved:
        raise GmailConfigError("Missing Gmail %s. Set %s or pass it directly." % (label, env_name))
    return resolved


def _resolve_timeout(timeout: Optional[int]) -> int:
    if timeout is None:
        raw_timeout = os.getenv(ENV_TIMEOUT)
        if raw_timeout:
            try:
                timeout = int(raw_timeout)
            except ValueError as error:
                raise GmailConfigError("%s must be an integer." % ENV_TIMEOUT) from error
        else:
            timeout = DEFAULT_TIMEOUT

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero.")
    return timeout


def _load_service_account_info(service_account_info: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(service_account_info, dict):
        return service_account_info

    try:
        parsed = json.loads(service_account_info)
    except ValueError as error:
        raise GmailConfigError("Gmail service account info must be valid JSON.") from error

    if not isinstance(parsed, dict):
        raise GmailConfigError("Gmail service account info must decode to a JSON object.")
    return parsed


def _validate_body_content_type(body_content_type: str) -> str:
    if body_content_type not in BODY_CONTENT_TYPES:
        raise ValueError("body_content_type must be 'Text' or 'HTML'.")
    return body_content_type


def _html_to_text(html_body: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html_body)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(div|h[1-6]|li|p|tr)\s*>", "\n\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    lines = []
    for raw_line in text.splitlines():
        line = " ".join(raw_line.split())
        if line or (lines and lines[-1]):
            lines.append(line)
    return "\n".join(lines).strip()


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
        maintype, _, subtype = content_type.partition("/")
        if not maintype or not subtype:
            content_type = DEFAULT_ATTACHMENT_CONTENT_TYPE
            maintype, subtype = "application", "octet-stream"

        normalized.append(
            {
                "filename": filename,
                "content": content_bytes,
                "content_type": content_type,
                "maintype": maintype,
                "subtype": subtype,
            }
        )
    return normalized


def _create_credentials(
    *,
    service_account_file: Optional[str] = None,
    service_account_info: Optional[Union[str, Dict[str, Any]]] = None,
    delegated_subject: Optional[str] = None,
) -> Any:
    (
        _google_auth_httplib2,
        _httplib2,
        GoogleAuthError,
        service_account,
        _build,
        _HttpError,
    ) = _load_google_modules()

    subject = delegated_subject or os.getenv(ENV_DELEGATED_SUBJECT)
    raw_info = service_account_info or os.getenv(ENV_SERVICE_ACCOUNT_INFO)

    try:
        if raw_info:
            credentials = service_account.Credentials.from_service_account_info(
                _load_service_account_info(raw_info),
                scopes=[GMAIL_SEND_SCOPE],
            )
        else:
            credentials = service_account.Credentials.from_service_account_file(
                _resolve_setting(service_account_file, ENV_SERVICE_ACCOUNT_FILE, "service account file"),
                scopes=[GMAIL_SEND_SCOPE],
            )

        if subject:
            credentials = credentials.with_subject(subject)
        return credentials
    except (GoogleAuthError, ValueError, OSError) as error:
        raise GmailConfigError("Could not create Gmail service account credentials: %s" % error) from error


def _build_email_message(
    *,
    sender_email: str,
    to_email: str,
    subject: str,
    body: str,
    body_content_type: str = "Text",
    text_body: Optional[str] = None,
    attachments: Optional[Iterable[Mapping[str, Any]]] = None,
) -> EmailMessage:
    if not sender_email:
        raise ValueError("sender_email is required.")
    if not to_email:
        raise ValueError("to_email is required.")
    if not isinstance(subject, str):
        raise ValueError("subject must be a string.")
    if not isinstance(body, str):
        raise ValueError("body must be a string.")
    if text_body is not None and not isinstance(text_body, str):
        raise ValueError("text_body must be a string.")

    resolved_body_content_type = _validate_body_content_type(body_content_type)
    message = EmailMessage()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject
    if resolved_body_content_type == "HTML":
        message.set_content(text_body if text_body is not None else _html_to_text(body))
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    for attachment in _normalize_attachments(attachments):
        message.add_attachment(
            attachment["content"],
            maintype=attachment["maintype"],
            subtype=attachment["subtype"],
            filename=attachment["filename"],
        )
    return message


def _message_payload(message: EmailMessage) -> Dict[str, str]:
    return {"raw": base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")}


def _parse_http_error(error: Any) -> Tuple[Optional[int], str, Any]:
    status_code = getattr(getattr(error, "resp", None), "status", None)
    content = getattr(error, "content", b"")
    if isinstance(content, bytes):
        response_text = content.decode("utf-8", errors="replace")
    else:
        response_text = str(content or "")

    payload = None
    if response_text:
        try:
            payload = json.loads(response_text)
        except ValueError:
            pass
    return status_code, response_text, payload


def send_gmail_email(
    *,
    to_email: str,
    subject: str,
    body: str,
    body_content_type: str = "Text",
    text_body: Optional[str] = None,
    attachments: Optional[Iterable[Mapping[str, Any]]] = None,
    sender_email: Optional[str] = None,
    service_account_file: Optional[str] = None,
    service_account_info: Optional[Union[str, Dict[str, Any]]] = None,
    delegated_subject: Optional[str] = None,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Send a simple text or HTML email through Gmail API."""

    client = GmailEmailClient(
        service_account_file=service_account_file,
        service_account_info=service_account_info,
        delegated_subject=delegated_subject,
        timeout=timeout,
    )
    return client.send_email(
        sender_email=sender_email,
        to_email=to_email,
        subject=subject,
        body=body,
        body_content_type=body_content_type,
        text_body=text_body,
        attachments=attachments,
    )


class GmailEmailClient:
    """Small synchronous client for Gmail API ``users.messages.send``."""

    def __init__(
        self,
        *,
        service_account_file: Optional[str] = None,
        service_account_info: Optional[Union[str, Dict[str, Any]]] = None,
        delegated_subject: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self.service_account_file = service_account_file
        self.service_account_info = service_account_info
        self.delegated_subject = delegated_subject
        self._delegated_subject_configured = delegated_subject is not None
        self.timeout = _resolve_timeout(timeout)
        self._credentials = None
        self._service = None

    def _get_credentials(self) -> Any:
        if self._credentials is None:
            self._credentials = _create_credentials(
                service_account_file=self.service_account_file,
                service_account_info=self.service_account_info,
                delegated_subject=self.delegated_subject,
            )
        return self._credentials

    def _get_service(self) -> Any:
        if self._service is None:
            google_auth_httplib2, httplib2, _GoogleAuthError, _service_account, build, _HttpError = (
                _load_google_modules()
            )
            http = google_auth_httplib2.AuthorizedHttp(
                self._get_credentials(),
                http=httplib2.Http(timeout=self.timeout),
            )
            self._service = build(
                GMAIL_API_SERVICE_NAME,
                GMAIL_API_VERSION,
                http=http,
                cache_discovery=False,
            )
        return self._service

    def send_email(
        self,
        *,
        to_email: str,
        subject: str,
        body: str,
        body_content_type: str = "Text",
        text_body: Optional[str] = None,
        attachments: Optional[Iterable[Mapping[str, Any]]] = None,
        sender_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a simple text or HTML email through Gmail API."""

        resolved_sender = _resolve_setting(sender_email, ENV_SENDER_EMAIL, "sender email")
        if not self._delegated_subject_configured and not os.getenv(ENV_DELEGATED_SUBJECT):
            if self.delegated_subject != resolved_sender:
                self.delegated_subject = resolved_sender
                self._credentials = None
                self._service = None

        message = _build_email_message(
            sender_email=resolved_sender,
            to_email=to_email,
            subject=subject,
            body=body,
            body_content_type=body_content_type,
            text_body=text_body,
            attachments=attachments,
        )

        _google_auth_httplib2, _httplib2, _GoogleAuthError, _service_account, _build, HttpError = (
            _load_google_modules()
        )

        try:
            return (
                self._get_service()
                .users()
                .messages()
                .send(userId=resolved_sender, body=_message_payload(message))
                .execute()
            )
        except HttpError as error:
            status_code, response_text, payload = _parse_http_error(error)
            raise GmailAPIError(
                "Gmail send failed with HTTP %s." % (status_code or "unknown"),
                status_code=status_code,
                response_text=response_text,
                payload=payload,
            ) from error
