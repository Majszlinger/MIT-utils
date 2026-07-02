"""Simple bulk email generator for Graph and Gmail."""

from __future__ import annotations

import asyncio
import functools
import os
from typing import Any, AsyncGenerator, Dict, Iterable, List, Optional


DEFAULT_DELAY_SECONDS = 0.0
ENV_DELAY_SECONDS = "BULK_EMAIL_DELAY_SECONDS"
BulkEmailResult = Dict[str, Any]

__all__ = [
    "DEFAULT_DELAY_SECONDS",
    "ENV_DELAY_SECONDS",
    "BulkEmailResult",
    "send_emails_generator",
]


def _normalize_provider(provider: str) -> str:
    normalized = provider.lower().strip()
    if normalized not in {"graph", "gmail"}:
        raise ValueError("provider must be 'graph' or 'gmail'.")
    return normalized


def _normalize_target_email_addresses(target_email_addresses: Iterable[str]) -> List[str]:
    if isinstance(target_email_addresses, str):
        emails = [target_email_addresses]
    else:
        emails = list(target_email_addresses)

    if not emails:
        raise ValueError("target_email_addresses must contain at least one email address.")

    for email in emails:
        if not isinstance(email, str) or not email:
            raise ValueError("target_email_addresses must contain non-empty email strings.")
    return emails


def _resolve_delay_seconds(delay_seconds: Optional[float]) -> float:
    if delay_seconds is None:
        raw_delay = os.getenv(ENV_DELAY_SECONDS)
        if raw_delay:
            try:
                delay_seconds = float(raw_delay)
            except ValueError as error:
                raise ValueError("%s must be a number." % ENV_DELAY_SECONDS) from error
        else:
            delay_seconds = DEFAULT_DELAY_SECONDS

    try:
        resolved_delay = float(delay_seconds)
    except (TypeError, ValueError) as error:
        raise ValueError("delay_seconds must be a number.") from error

    if resolved_delay < 0:
        raise ValueError("delay_seconds must be zero or greater.")
    return resolved_delay


def _payload(*, provider: str, to_email: str, subject: str, body: str) -> Dict[str, str]:
    return {
        "provider": provider,
        "to": to_email,
        "subject": subject,
        "body": body,
    }


def _send_email_sync(
    *,
    provider: str,
    client: Any,
    sender_email: Optional[str],
    to_email: str,
    subject: str,
    body: str,
) -> Any:
    if provider == "graph":
        return client.send_email(
            sender_email=sender_email,
            to_recipients=to_email,
            subject=subject,
            body=body,
        )

    return client.send_email(
        sender_email=sender_email,
        to_email=to_email,
        subject=subject,
        body=body,
    )


async def _send_email_in_executor(
    *,
    provider: str,
    client: Any,
    sender_email: Optional[str],
    to_email: str,
    subject: str,
    body: str,
) -> Any:
    loop = asyncio.get_running_loop()
    send_call = functools.partial(
        _send_email_sync,
        provider=provider,
        client=client,
        sender_email=sender_email,
        to_email=to_email,
        subject=subject,
        body=body,
    )
    return await loop.run_in_executor(None, send_call)


async def send_emails_generator(
    provider: str,
    target_email_addresses: Iterable[str],
    subject: str,
    body: str,
    *,
    delay_seconds: Optional[float] = None,
) -> AsyncGenerator[BulkEmailResult, None]:
    """Send simple emails one by one and yield the result of each attempt."""

    normalized_provider = _normalize_provider(provider)
    emails = _normalize_target_email_addresses(target_email_addresses)
    resolved_delay_seconds = _resolve_delay_seconds(delay_seconds)

    if normalized_provider == "graph":
        from .graph import GraphEmailClient

        client = GraphEmailClient()
        sender_email = os.getenv("MS_GRAPH_SENDER_EMAIL")
    else:
        from .gmail import GmailEmailClient

        client = GmailEmailClient()
        sender_email = os.getenv("GMAIL_SENDER_EMAIL")

    last_index = len(emails) - 1
    for index, to_email in enumerate(emails):
        email_payload = _payload(
            provider=normalized_provider,
            to_email=to_email,
            subject=subject,
            body=body,
        )
        try:
            response = await _send_email_in_executor(
                provider=normalized_provider,
                client=client,
                sender_email=sender_email,
                to_email=to_email,
                subject=subject,
                body=body,
            )
            yield {
                "status": "success",
                "payload": email_payload,
                "response": response,
            }
        except Exception as error:
            yield {
                "status": "error",
                "payload": email_payload,
                "error": str(error),
            }

        if resolved_delay_seconds and index < last_index:
            await asyncio.sleep(resolved_delay_seconds)
