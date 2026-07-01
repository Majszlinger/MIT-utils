# MIT-utils

A utility bundle for Python development, providing ready-to-use modules for **authentication**, **email sending**, and more. Designed to be installed as optional extras so your project only pulls in the dependencies it needs.

---

## Table of Contents

- [Installation](#installation)
- [Modules Overview](#modules-overview)
  - [Authentication (`auth`)](#authentication-auth)
  - [Email (`email`)](#email-email)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
  - [Auth0 Authentication in FastAPI](#auth0-authentication-in-fastapi)
  - [Custom JWT Authentication](#custom-jwt-authentication)
  - [Role & Permission Checks](#role--permission-checks)
  - [Dimail Email Integration](#dimail-email-integration)
  - [Microsoft Graph Email Integration](#microsoft-graph-email-integration)
- [Project Structure](#project-structure)
- [License](#license)

---

## Installation

Install the package directly from the GitHub repository. Use **optional extras** to pull in only the dependencies you need:

```bash
# Install everything
pip install "mit_utils[auth,email] @ git+https://github.com/Majszlinger/MIT-utils.git"

# Install only authentication utilities (Auth0 + JWT)
pip install "mit_utils[auth] @ git+https://github.com/Majszlinger/MIT-utils.git"

# Install only email utilities (Dimail + Microsoft Graph)
pip install "mit_utils[email] @ git+https://github.com/Majszlinger/MIT-utils.git"

# Install core package with no extras
pip install "mit_utils @ git+https://github.com/Majszlinger/MIT-utils.git"
```

### Extras Breakdown

| Extra    | Installs                                      | Provides                              |
|----------|-----------------------------------------------|---------------------------------------|
| `auth`   | `pyjwt`, `fastapi`, `cryptography`            | Auth0 & JWT authentication helpers    |
| `email`  | `httpx`, `msal`                               | Dimail & Microsoft Graph email clients|

---

## Modules Overview

### Authentication (`auth`)

The `mit_utils.authentication` module provides two authentication strategies:

| Class            | File                      | Purpose                                                    |
|------------------|---------------------------|------------------------------------------------------------|
| `Auth0_Auth`     | `auth0_auth.py`           | Full Auth0 integration — token verification, M2M tokens, Management API, permission/role checks |
| `JWT_Auth`       | `jwt_auth.py`             | Generic JWT token generation and validation with support for HS* and RS* algorithms |

**Key features of `Auth0_Auth`:**
- OAuth2 bearer token verification via JWKS
- FastAPI dependency factories (`get_payload`, `has_permission`, `has_group_permission`)
- Machine-to-Machine (M2M) token caching
- Auth0 Management API wrappers (POST, GET, PATCH, DELETE)
- User info retrieval

**Key features of `JWT_Auth`:**
- Token generation with configurable expiration
- Token validation with proper error handling
- Support for HMAC (HS256/384/512) and asymmetric (RS256/384/512, ES256/384/512) algorithms
- PEM and SSH private key loading

### Email (`email`)

The `mit_utils.email` module provides two email providers:

| Class / Function      | File      | Purpose                                                    |
|-----------------------|-----------|------------------------------------------------------------|
| `DimailClient`        | `dimail.py` | Full Dimail/ninjaMail API client — subscribe, unsubscribe, manage lists, newsletters, campaigns |
| `GraphEmailClient`    | `graph.py`  | Microsoft Graph email client — send emails via Graph API with token caching |
| `send_graph_email`    | `graph.py`  | Simple function to send a single email through Graph       |
| `get_access_token`    | `graph.py`  | Acquire and cache Microsoft Graph access tokens via MSAL   |

**Key features of `DimailClient`:**
- Subscriber management (subscribe, unsubscribe, update)
- List and newsletter management
- Campaign creation and sending
- CSV subscriber export parsing
- Raw API request helper for unsupported endpoints

**Key features of `GraphEmailClient`:**
- MSAL-based token acquisition with in-memory caching
- Support for To, CC, and BCC recipients
- HTML and plain text body types
- Configurable save-to-sent-items behavior

---

## Quick Start

### Auth0 in FastAPI (30 seconds)

```python
from mit_utils.authentication.auth0_auth import Auth0_Auth
from fastapi import FastAPI, Depends

app = FastAPI()
auth = Auth0_Auth()  # reads AUTH0_DOMAIN and AUTH0_AUDIENCE from env

@app.get("/protected", dependencies=[Depends(auth.bearer_scheme)])
async def protected_route(payload: dict = Depends(auth.get_payload())):
    return {"user": payload.get("email")}
```

### Send an email via Microsoft Graph

```python
from mit_utils.email.graph import get_access_token, send_graph_email

token = get_access_token()  # reads MS_GRAPH_* from env
send_graph_email(
    access_token=token,
    sender_email="noreply@example.com",
    recipient_email="user@example.com",
    subject="Hello!",
    body="This is a test email.",
    body_content_type="HTML",
)
```

---

## Detailed Usage

### Auth0 Authentication in FastAPI

#### 1. Environment Variables

Set these in your environment or `.env` file:

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://your-api-identifier
AUTH0_CLIENT_ID=your-m2m-client-id        # optional, for Management API
AUTH0_CLIENT_SECRET=your-m2m-client-secret # optional, for Management API
```

#### 2. Create an Auth Handler Singleton

A common pattern is to wrap `Auth0_Auth` in a singleton handler that provides reusable FastAPI dependencies:

```python
from mit_utils.authentication.auth0_auth import Auth0_Auth
from fastapi import Depends


def singleton(cls):
    """Simple singleton decorator."""
    instances = {}
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return get_instance


@singleton
class AuthHandler:

    def __init__(self):
        self.auth = Auth0_Auth()

    def get_user(self):
        """Returns a dependency function that extracts the user payload from the token."""
        def _inner(payload: dict = Depends(self.auth.get_payload())):
            return payload
        return _inner
```

#### 3. Secure an Endpoint

```python
from fastapi import FastAPI, Depends
from auth_handler import authHandler

app = FastAPI()

@app.get(
    "/api/users/me",
    dependencies=[Depends(authHandler.auth.bearer_scheme)],
)
async def get_current_user(user: dict = Depends(authHandler.get_user())):
    return {"email": user.get("email"), "name": user.get("name")}
```

### Custom JWT Authentication

If you have a custom `User` model, you can deserialize the payload into it:

```python
from mit_utils.authentication.auth0_auth import Auth0_Auth
from fastapi import Depends, HTTPException


@singleton
class AuthHandler:

    def __init__(self):
        self.auth = Auth0_Auth()

    def get_user(self):
        """Returns a dependency that deserializes the payload into a User object."""
        def _inner(payload: dict = Depends(self.auth.get_payload())):
            return User.from_payload(payload)  # your custom deserialization
        return _inner
```

### Role & Permission Checks

#### Permission Check (any one of)

```python
@app.get(
    "/api/admin",
    dependencies=[
        Depends(authHandler.auth.bearer_scheme),
        Depends(authHandler.auth.has_permission(["read:admin", "write:admin"])),
    ],
)
async def admin_route(payload: dict = Depends(authHandler.get_user())):
    return {"message": "Welcome, admin!"}
```

#### Custom Role Check

For role-based access control using a custom `User` model:

```python
from typing import List
from fastapi import Depends, HTTPException


@singleton
class AuthHandler:
    # ... __init__ and get_user as above ...

    def has_role(self, allowed_roles: List[str]):
        """Returns a dependency that checks if the user has one of the allowed roles."""
        def _inner(user: User = Depends(self.get_user())):
            try:
                user_entity_types = [entity.type for entity in user.connected_entities]
                if not any(
                    entity_type in allowed_roles for entity_type in user_entity_types
                ):
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error_code": "AuthorizationError",
                            "message": f"Insufficient permissions, user needs to be one of: {', '.join(allowed_roles)}",
                        },
                    )
                return user
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error_code": "AuthorizationError",
                        "message": "Error during authorization check",
                    },
                )
        return _inner
```

Use it on specific endpoints:

```python
@app.get(
    "/api/management/reports",
    dependencies=[
        Depends(authHandler.auth.bearer_scheme),
        Depends(authHandler.has_role(["management", "sales", "recommenders", "tender_writers"])),
    ],
)
async def get_reports(user: User = Depends(authHandler.has_role(["management", "sales"]))):
    return {"reports": [], "user": user.email}
```

#### Group Permission Check (all required)

```python
@app.get(
    "/api/super-admin",
    dependencies=[
        Depends(authHandler.auth.bearer_scheme),
        Depends(authHandler.auth.has_group_permission(["read:all", "write:all", "delete:all"])),
    ],
)
async def super_admin_route(payload: dict = Depends(authHandler.get_user())):
    return {"message": "Full access granted"}
```

### Dimail Email Integration

#### Environment Variables

```bash
DIMAIL_API_KEY=your-api-key
DIMAIL_HOST=https://admin.dimail.hu   # optional, defaults to this
```

#### Using DimailClient

```python
from mit_utils.email import DimailClient

client = DimailClient()  # reads DIMAIL_API_KEY from env

# Subscribe a user
client.subscribe("newsletter-123", email="user@example.com", name="John Doe")

# Unsubscribe
client.unsubscribe("newsletter-123", email="user@example.com")

# List subscribers (CSV export)
subscribers = client.list_subscribers_csv("newsletter-123")

# Create a newsletter
client.create_newsletter("newsletter-123", subject="Hello", html_message="<h1>Hi!</h1>")

# Send a newsletter
client.send_newsletter("newsletter-123", start=0)
```

### Microsoft Graph Email Integration

#### Environment Variables

```bash
MS_GRAPH_TENANT_ID=your-tenant-id
MS_GRAPH_CLIENT_ID=your-client-id
MS_GRAPH_CLIENT_SECRET=your-client-secret
MS_GRAPH_SENDER_EMAIL=noreply@example.com
```

#### Using GraphEmailClient

```python
from mit_utils.email import GraphEmailClient

# Option 1: Let the client acquire its own token
client = GraphEmailClient()
client.send_email(
    sender_email="noreply@example.com",
    to_recipients=["user@example.com"],
    subject="Welcome!",
    body="<h1>Welcome aboard!</h1>",
    body_content_type="HTML",
)

# Option 2: Provide an existing token
client = GraphEmailClient(access_token=existing_token)
client.send_email(
    sender_email="noreply@example.com",
    to_recipients=["user@example.com"],
    cc_recipients=["manager@example.com"],
    subject="Update",
    body="Please see the attached report.",
)
```

#### Simple Function Call

```python
from mit_utils.email.graph import get_access_token, send_graph_email

token = get_access_token()
send_graph_email(
    access_token=token,
    sender_email="noreply@example.com",
    recipient_email="user@example.com",
    subject="Hello from MIT-utils!",
    body="This email was sent using mit_utils.",
    body_content_type="HTML",
)
```

---

## Project Structure

```
mit_utils/
├── __init__.py
├── authentication/
│   ├── __init__.py
│   ├── auth0_auth.py      # Auth0 OAuth2 + Management API
│   ├── jwt_auth.py         # Generic JWT generation & validation
│   └── auth_test.py        # Auth0 test utilities
├── email/
│   ├── __init__.py
│   ├── dimail.py           # Dimail/ninjaMail API client
│   └── graph.py            # Microsoft Graph email client
└── aws/
    └── __init__.py          # AWS utilities (placeholder)

examples/
└── fastapi_email/           # Reference FastAPI app with Dimail + Graph
    ├── app/
    │   ├── main.py          # Full FastAPI routes
    │   └── settings.py      # Pydantic settings
    ├── Dockerfile
    └── requirements.txt
```

---

## License

See [LICENSE](LICENSE) for details.