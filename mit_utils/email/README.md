# Email Module

Email utilities supporting **Dimail/ninjaMail** and **Microsoft Graph** providers.

## Installation

```bash
pip install "mit_utils[email] @ git+https://github.com/Majszlinger/MIT-utils.git"
```

This installs `httpx` and `msal` as dependencies.

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

# Update subscriber
client.update_subscriber(
    list_id="newsletter-123",
    email="user@example.com",
    name="Jane Doe",
)

# List subscribers (CSV export)
subscribers = client.list_subscribers_csv("newsletter-123")
# Returns: [{"email": "user@example.com", "name": "John Doe"}, ...]
```

#### Newsletter Management

```python
# Create a newsletter
client.create_newsletter(
    list_id="newsletter-123",
    subject="Monthly Update",
    html_message="<h1>Hello!</h1>",
    text_message="Hello!",
)

# Send a newsletter
client.send_newsletter(list_id="newsletter-123", start=0)

# List newsletters
newsletters = client.list_newsletters(list_id="newsletter-123")
```

#### List Management

```python
# Create a list
client.create_list(name="New Newsletter")

# List all lists
lists = client.list_lists()
```

#### Campaign Management

```python
# Create a campaign
client.create_campaign(name="Summer Campaign")

# Link lists to a campaign
client.add_lists_to_campaign(
    campaign_id="campaign-456",
    list_ids=["newsletter-123", "newsletter-789"],
)

# Send a campaign
client.send_campaign(campaign_id="campaign-456")
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
data = request_dimail("newsletters", method="GET")

# POST request
data = request_dimail("subscribers", data={"email": "user@example.com"})
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

## FastAPI Integration Example

See the [examples/fastapi_email](../../examples/fastapi_email/) directory for a complete FastAPI reference app with:

- Dimail subscriber management endpoints
- Dimail newsletter and campaign endpoints
- Microsoft Graph email sending endpoint
- Health check endpoint
- Pydantic settings with environment variable support

### Quick Example

```python
from fastapi import FastAPI, HTTPException
from mit_utils.email import DimailClient, GraphEmailClient

app = FastAPI()
dimail = DimailClient()
graph = GraphEmailClient()


@app.post("/api/subscribe")
async def subscribe(email: str, name: str, list_id: str):
    try:
        dimail.subscribe(list_id, email=email, name=name)
        return {"ok": True, "message": f"Subscribed {email}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/send-email")
async def send_email(to: str, subject: str, body: str):
    try:
        graph.send_email(
            sender_email="noreply@example.com",
            to_recipients=[to],
            subject=subject,
            body=body,
            body_content_type="HTML",
        )
        return {"ok": True, "message": f"Email sent to {to}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

---

## API Reference

### DimailClient

| Method                              | Description                                    |
|-------------------------------------|------------------------------------------------|
| `subscribe(list_id, email, ...)`    | Subscribe an email to a list                   |
| `unsubscribe(list_id, email)`       | Unsubscribe an email from a list               |
| `update_subscriber(list_id, ...)`   | Update subscriber details                      |
| `list_subscribers_csv(list_id)`     | Get subscribers via CSV export                 |
| `create_newsletter(list_id, ...)`   | Create a newsletter                            |
| `send_newsletter(list_id, start)`   | Send a newsletter                              |
| `list_newsletters(list_id)`         | List newsletters for a list                    |
| `create_list(name)`                 | Create a new mailing list                      |
| `list_lists()`                      | List all mailing lists                         |
| `create_campaign(name)`             | Create a new campaign                          |
| `add_lists_to_campaign(...)`        | Link lists to a campaign                       |
| `send_campaign(campaign_id)`        | Send a campaign                                |
| `create_login_token(rkey)`          | Generate a login token                         |

### GraphEmailClient

| Method                              | Description                                    |
|-------------------------------------|------------------------------------------------|
| `send_email(sender_email, ...)`     | Send an email via Graph                        |

### Standalone Functions

| Function                            | Description                                    |
|-------------------------------------|------------------------------------------------|
| `get_access_token()`                | Acquire and cache a Graph access token         |
| `send_graph_email(...)`             | Send a single email with an existing token     |
| `request_dimail(endpoint, ...)`     | Send a raw Dimail API request                  |
