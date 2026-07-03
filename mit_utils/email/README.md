# Email Module

Email utilities supporting **Dimail/ninjaMail**, **Microsoft Graph**, and **Gmail API** providers.

## Installation

```bash
pip install "mit_utils[email] @ git+https://github.com/Majszlinger/MIT-utils.git"
```

This installs `httpx`, `msal`, and the Google API client libraries as dependencies.

---

## Dimail Integration (`dimail.py`)

A comprehensive Python wrapper for the [Dimail/ninjaMail](https://admin.dimail.hu) API.

### Configuration

```bash
DIMAIL_API_KEY=your-api-key
DIMAIL_HOST=https://admin.dimail.hu   # optional, defaults to this
```

### DimailClient

```python
from mit_utils.email import DimailClient

client = DimailClient()
# Or pass values directly:
# client = DimailClient(api_key="your-key", host="https://admin.dimail.hu")
```

#### Subscriber Management

```python
# Subscribe
client.subscribe(
    list_id="newsletter-123",
    email="user@example.com",
    name="John Doe",
    activated=True,
)

# Unsubscribe
client.unsubscribe(list_id="newsletter-123", email="user@example.com")

# List subscribers (CSV export)
subscribers = client.list_subscribers("newsletter-123")
# Returns: [{"email": "user@example.com", "name": "John Doe"}, ...]
```

#### Newsletter Management

```python
# Create a newsletter
newsletter = client.create_newsletter(
    subject="Monthly Update",
    html_message="<h1>Hello!</h1>",
    text_message="Hello!",
)

# Update a newsletter
client.update_newsletter(
    newsletter_id="newsletter-456",
    subject="Monthly Update",
    html_message="<h1>Updated!</h1>",
    text_message="Updated!",
)

# Send a newsletter
client.send_newsletter(newsletter_id="newsletter-456", start=0)

# List newsletters
newsletters = client.list_newsletters()
```

#### List Management

```python
# Create a list
client.create_list(name="New Newsletter")

# List all lists
lists = client.list_lists()

# Remove a list
client.remove_list(list_id="newsletter-123")
```

#### Campaign Management

```python
# Create a campaign
client.create_campaign(name="Summer Campaign")

# Replace lists attached to a campaign
client.update_campaign_lists(
    campaign_id="campaign-456",
    list_ids=["newsletter-123", "newsletter-789"],
)

# Attach a campaign to a newsletter
client.attach_campaign_to_newsletter(
    campaign_id="campaign-456",
    newsletter_id="newsletter-456",
)

# Remove a campaign
client.remove_campaign(campaign_id="campaign-456")
```

#### One-Off Email

```python
# Queue a transactional email
send_payload = client.send_email(
    to="user@example.com",
    subject="Welcome",
    html_message="<p>Hello!</p>",
    text_message="Hello!",
)

# Check queued email status
client.check_email_status(send_payload.get("id"))
```

#### Login Token

```python
# Generate a login token
token = client.create_login_token(rkey="user-recovery-key")
```

#### Raw API Requests

For endpoints not yet wrapped:

```python
from mit_utils.email import request_dimail

# GET request
data = request_dimail(
    "newsletter",
    method="GET",
    bare_query_flags=["get"],
    trailing_slash=False,
)

# POST request
data = request_dimail(
    "subscribe",
    data={"list": "newsletter-123", "email": "user@example.com"},
)
```

### Error Handling

```python
from mit_utils.email import DimailAPIError, DimailConfigError

try:
    client.subscribe("newsletter-123", email="user@example.com")
except DimailConfigError as e:
    # Missing API key or configuration
    print(f"Configuration error: {e}")
except DimailAPIError as e:
    # API returned an error
    print(f"API error: {e}")
    print(f"Status code: {e.status_code}")
    print(f"Raw body: {e.raw_body}")
    print(f"Payload: {e.payload}")
```

---

## Microsoft Graph Integration (`graph.py`)

Send emails through Microsoft Graph with automatic token acquisition and caching via MSAL.

### Configuration

```bash
MS_GRAPH_TENANT_ID=your-tenant-id
MS_GRAPH_CLIENT_ID=your-client-id
MS_GRAPH_CLIENT_SECRET=your-client-secret
MS_GRAPH_SENDER_EMAIL=noreply@example.com
```

### Quick Send

```python
from mit_utils.email.graph import get_access_token, send_graph_email

token = get_access_token()
send_graph_email(
    access_token=token,
    sender_email="noreply@example.com",
    recipient_email="user@example.com",
    subject="Welcome!",
    body="<h1>Welcome aboard!</h1>",
    body_content_type="HTML",
)
```

### GraphEmailClient

For apps that send multiple emails, use the reusable client:

```python
from mit_utils.email import GraphEmailClient

# Option 1: Client acquires its own token
client = GraphEmailClient()

# Option 2: Provide an existing token
client = GraphEmailClient(access_token=existing_token)

# Send an email
client.send_email(
    sender_email="noreply@example.com",
    to_recipients=["user@example.com"],
    subject="Update",
    body="Please see the attached report.",
    body_content_type="Text",
    attachments=[
        {
            "filename": "report.txt",
            "content": b"Report contents",
            "content_type": "text/plain",
        }
    ],
    save_to_sent_items=True,
)

# Send with CC and BCC
client.send_email(
    sender_email="noreply@example.com",
    to_recipients=["user@example.com"],
    cc_recipients=["manager@example.com"],
    bcc_recipients=["archive@example.com"],
    subject="Report",
    body="<h1>Monthly Report</h1>",
    body_content_type="HTML",
)
```

### Token Acquisition

```python
from mit_utils.email.graph import get_access_token

# Uses environment variables
token = get_access_token()

# Or pass credentials directly
token = get_access_token(
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-client-secret",
    scopes=["https://graph.microsoft.com/.default"],
)
```

Tokens are cached in-memory via MSAL, so subsequent calls return cached tokens until they expire.

### Error Handling

```python
from mit_utils.email import GraphAPIError, GraphConfigError

try:
    client.send_email(
        sender_email="noreply@example.com",
        to_recipients=["user@example.com"],
        subject="Test",
        body="Hello!",
    )
except GraphConfigError as e:
    # Missing configuration or token acquisition failed
    print(f"Configuration error: {e}")
except GraphAPIError as e:
    # Graph API returned an error
    print(f"API error: {e}")
    print(f"Status code: {e.status_code}")
    print(f"Response: {e.response_text}")
    print(f"Payload: {e.payload}")
```

---

## Gmail API Integration (`gmail.py`)

Send emails through Gmail API with a Google service account and Workspace
domain-wide delegation. Gmail sending is intentionally simple: one recipient,
a string subject, and a string text or HTML body. HTML sends are delivered as
multipart alternative messages with a plain-text fallback.

### Configuration

```bash
GMAIL_SENDER_EMAIL=info@example.com
GMAIL_DELEGATED_SUBJECT=info@example.com
GOOGLE_SERVICE_ACCOUNT_INFO_BASE64=base64-encoded-service-account-json
# or use a credentials file:
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
# GMAIL_TIMEOUT=10
```

Base64-encoding the JSON avoids shell, `.env`, Windows/Linux newline, and
escape-sequence issues around the service account `private_key`. It is still a
secret, not encryption. For example:

```bash
# Linux/macOS
base64 < service-account.json | tr -d '\n'

# PowerShell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw service-account.json)))
```

The service account must have domain-wide delegation enabled, and Google
Workspace Admin Console must authorize the service account client ID for:

```text
https://www.googleapis.com/auth/gmail.send
```

### Quick Send

```python
from mit_utils.email.gmail import send_gmail_email

send_gmail_email(
    to_email="user@example.com",
    subject="Welcome!",
    body="<h1>Welcome aboard!</h1><p>Thanks for joining.</p>",
    body_content_type="HTML",
    text_body="Welcome aboard!\n\nThanks for joining.",
)
```

### GmailEmailClient

For apps that send multiple emails, use the reusable client:

```python
from mit_utils.email import GmailEmailClient

client = GmailEmailClient()
client.send_email(
    to_email="user@example.com",
    subject="Update",
    body="<p>Please see the attached report.</p>",
    body_content_type="HTML",
    text_body="Please see the attached report.",
    attachments=[
        {
            "filename": "report.txt",
            "content": b"Report contents",
            "content_type": "text/plain",
        }
    ],
)
```

You can pass `sender_email`, `service_account_file`,
`service_account_info_base64`, `delegated_subject`, or `timeout` directly when
a test or integration should not read from environment variables. For HTML
emails, pass `body_content_type="HTML"` and optionally `text_body`; when
`text_body` is omitted, a simple fallback is generated from the HTML.

### Attachments

Graph, Gmail, and bulk sends accept regular file attachments as bytes:

```python
attachments = [
    {
        "filename": "report.pdf",
        "content": report_bytes,
        "content_type": "application/pdf",  # optional
    }
]
```

`filename` and bytes-like `content` are required. If `content_type` is omitted,
MIT-utils infers it from the filename and falls back to
`application/octet-stream`.

### Error Handling

```python
from mit_utils.email import GmailAPIError, GmailConfigError, GmailEmailClient

client = GmailEmailClient()

try:
    client.send_email(
        to_email="user@example.com",
        subject="Test",
        body="Hello!",
    )
except GmailConfigError as e:
    print(f"Configuration error: {e}")
except GmailAPIError as e:
    print(f"API error: {e}")
    print(f"Status code: {e.status_code}")
    print(f"Response: {e.response_text}")
    print(f"Payload: {e.payload}")
```

---

## Bulk Email Generator (`bulk.py`)

Use `send_emails_generator` when an app needs to send the same simple email to
many recipients and record progress as each attempt finishes. The utility
library does not write to a database; it yields a uniform result object so your
app can store success, failure, and completion state wherever it belongs.

The Graph and Gmail clients are synchronous for direct use, but the bulk
generator offloads each provider send to the event loop's executor. Sends remain
sequential for predictable ordering, and callers can pace requests with either
the `delay_seconds` argument or the `BULK_EMAIL_DELAY_SECONDS` environment
variable. In an async web backend, still run bulk sends outside the request
path, in a worker, or behind your own background job wrapper.

```bash
BULK_EMAIL_DELAY_SECONDS=0.2
```

### Send One Message To Many Recipients

```python
from mit_utils.email import send_emails_generator

async for result in send_emails_generator(
    provider="gmail",
    target_email_addresses=["user1@example.com", "user2@example.com"],
    subject="System update",
    body="<h1>System update</h1><p>Hello from MIT-utils</p>",
    body_content_type="HTML",
    text_body="System update\n\nHello from MIT-utils",
    attachments=[
        {
            "filename": "notice.txt",
            "content": b"Shared attachment for every recipient.",
            "content_type": "text/plain",
        }
    ],
    delay_seconds=0.2,
):
    if result["status"] == "success":
        print("sent", result["payload"]["to"])
    else:
        print("failed", result["payload"]["to"], result["error"])
```

Use `provider="gmail"` to send the same payload through Gmail.

Each yielded result has this shape:

```python
{
    "status": "success",  # or "error"
    "payload": {
        "provider": "gmail",
        "to": "user@example.com",
        "subject": "System update",
        "body": "Hello from MIT-utils",
        "body_content_type": "Text",
        "attachments": ["notice.txt"],
    },
    "response": {},       # only on success; Graph returns None
    "error": "...",       # only on error
}
```

The generator is done when the `async for` loop finishes. Use that moment to
mark the parent job as complete in your application.

### Backend Job Consumer

Keep queue, database, and job-state logic in the consuming backend. The utility
only sends one message at a time and yields a result for each recipient.

```python
from typing import List

from mit_utils.email import send_emails_generator


async def process_email_job(
    *,
    job_id: str,
    recipients: List[str],
    subject: str,
    body: str,
    provider: str,
) -> None:
    async for result in send_emails_generator(
        provider=provider,
        target_email_addresses=recipients,
        subject=subject,
        body=body,
    ):
        if result["status"] == "success":
            await record_email_success(job_id=job_id, result=result)
        else:
            await record_email_failure(job_id=job_id, result=result)

    await mark_email_job_done(job_id)
```

---

## API Reference

### DimailClient

| Method                              | Description                                    |
|-------------------------------------|------------------------------------------------|
| `request(endpoint, data, ...)`      | Send a raw Dimail request with this client     |
| `subscribe(list_id, email, ...)`    | Subscribe an email to a list                   |
| `unsubscribe(list_id, email)`       | Unsubscribe an email from a list               |
| `list_subscribers(list_id)`         | Get subscribers via CSV export                 |
| `create_newsletter(subject, html_message, ...)` | Create a newsletter                |
| `update_newsletter(newsletter_id, ...)` | Update a newsletter                         |
| `send_newsletter(newsletter_id, start=0)` | Queue a newsletter send                    |
| `list_newsletters()`                | List newsletters                               |
| `create_list(name)`                 | Create a new mailing list                      |
| `list_lists()`                      | List all mailing lists                         |
| `remove_list(list_id)`              | Remove a mailing list                          |
| `create_campaign(name)`             | Create a new campaign                          |
| `remove_campaign(campaign_id)`      | Remove a campaign                              |
| `update_campaign_lists(...)`        | Replace lists attached to a campaign           |
| `attach_campaign_to_newsletter(...)` | Attach a campaign to a newsletter             |
| `send_email(to, subject, html_message, ...)` | Queue a transactional email           |
| `check_email_status(send_id)`       | Check a queued transactional email             |
| `get_statistics(newsletter_id, ...)` | Get newsletter statistics                     |
| `create_login_token(rkey)`          | Generate a login token                         |

### GraphEmailClient

| Method                              | Description                                    |
|-------------------------------------|------------------------------------------------|
| `send_email(sender_email, ...)`     | Send a text or HTML email with optional attachments via Graph |

### GmailEmailClient

| Method                              | Description                                    |
|-------------------------------------|------------------------------------------------|
| `send_email(to_email, subject, body, ...)` | Send a text or HTML email with optional attachments via Gmail API |

### Bulk Email

| Function                            | Description                                    |
|-------------------------------------|------------------------------------------------|
| `send_emails_generator(...)`        | Send one text or HTML subject/body and optional attachments to many recipients, offload provider calls, and yield per-recipient results |

### Standalone Functions

| Function                            | Description                                    |
|-------------------------------------|------------------------------------------------|
| `get_access_token()`                | Acquire and cache a Graph access token         |
| `send_graph_email(...)`             | Send a single email with an existing token     |
| `send_gmail_email(...)`             | Send a single email via Gmail API              |
| `list_dimail_subscribers_csv(...)`  | Get Dimail subscribers through CSV export      |
| `request_dimail(endpoint, ...)`     | Send a raw Dimail API request                  |
