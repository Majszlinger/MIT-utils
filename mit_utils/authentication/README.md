# Authentication Module

Authentication utilities for FastAPI applications, supporting **Auth0** and **generic JWT** strategies.

## Installation

```bash
pip install "mit_utils[auth] @ git+https://github.com/Majszlinger/MIT-utils.git"
```

This installs `pyjwt`, `fastapi`, and `cryptography` as dependencies. The
Auth0 helper also imports `requests`; install it in the consuming app if it is
not already available there.

## Quick Comparison

| Feature                    | `Auth0_Auth`              | `JWT_Auth`                    |
|----------------------------|---------------------------|-------------------------------|
| Token verification         | Yes, JWKS-based           | Yes, symmetric and asymmetric |
| Token generation           | No                        | Yes                           |
| FastAPI dependencies       | Yes, built-in factories   | No, manual wiring             |
| Permission checks          | Yes, `has_permission`     | No                            |
| M2M tokens                 | Yes, cached               | No                            |
| Management API             | Yes, request wrappers     | No                            |
| User info endpoint         | Yes                       | No                            |

---

## Auth0 Authentication (`Auth0_Auth`)

### Configuration

Set these environment variables:

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://your-api-identifier
AUTH0_CLIENT_ID=your-m2m-client-id        # optional, for Management API access
AUTH0_CLIENT_SECRET=your-m2m-client-secret # optional, for Management API access
```

### Basic Usage

```python
from mit_utils.authentication.auth0_auth import Auth0_Auth

auth = Auth0_Auth()
# Or pass values directly:
# auth = Auth0_Auth(domain="my-tenant.auth0.com", audience="https://api.example.com")
```

### FastAPI Integration

#### Protect an Endpoint

```python
from fastapi import FastAPI, Depends
from mit_utils.authentication.auth0_auth import Auth0_Auth

app = FastAPI()
auth = Auth0_Auth()

@app.get("/protected", dependencies=[Depends(auth.bearer_scheme)])
async def protected_route(payload: dict = Depends(auth.get_payload())):
    return {"user": payload.get("email"), "sub": payload.get("sub")}
```

#### Recommended: Singleton Auth Handler

Wrap the auth instance in a singleton for reuse across your application:

```python
from mit_utils.authentication.auth0_auth import Auth0_Auth
from fastapi import Depends


def singleton(cls):
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
        """Returns a dependency function that extracts the user payload."""
        def _inner(payload: dict = Depends(self.auth.get_payload())):
            return payload
        return _inner
```

Then use it in your routes:

```python
from auth_handler import authHandler

@app.get(
    "/api/users/me",
    dependencies=[Depends(authHandler.auth.bearer_scheme)],
)
async def get_me(user: dict = Depends(authHandler.get_user())):
    return user
```

#### Custom User Deserialization

If you have a `User` model, deserialize the payload into it:

```python
@singleton
class AuthHandler:

    def __init__(self):
        self.auth = Auth0_Auth()

    def get_user(self):
        def _inner(payload: dict = Depends(self.auth.get_payload())):
            return User.from_payload(payload)  # your custom method
        return _inner
```

### Permission Checks

#### Any Permission (OR logic)

Validates that the user has **at least one** of the specified permissions:

```python
@app.get(
    "/api/reports",
    dependencies=[
        Depends(authHandler.auth.bearer_scheme),
        Depends(authHandler.auth.has_permission(["read:reports", "admin:reports"])),
    ],
)
async def get_reports(payload: dict = Depends(authHandler.get_user())):
    return {"reports": []}
```

#### All Permissions (AND logic)

Validates that the user has **all** of the specified permissions:

```python
@app.get(
    "/api/super-admin",
    dependencies=[
        Depends(authHandler.auth.bearer_scheme),
        Depends(authHandler.auth.has_group_permission(["read:all", "write:all", "delete:all"])),
    ],
)
async def super_admin(payload: dict = Depends(authHandler.get_user())):
    return {"message": "Full access"}
```

### Role-Based Access Control

For role checks against a custom `User` model:

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

Usage on endpoints:

```python
@app.get(
    "/api/management/reports",
    dependencies=[
        Depends(authHandler.auth.bearer_scheme),
        Depends(authHandler.has_role(["management", "sales", "recommenders", "tender_writers"])),
    ],
)
async def get_management_reports(user: User = Depends(authHandler.has_role(["management"]))):
    return {"reports": [], "user": user.email}
```

### Machine-to-Machine (M2M) Tokens

Get a cached M2M token for server-to-server Auth0 API calls:

```python
token = auth.get_m2m_token()
```

The token is cached and automatically refreshed when it expires (with a 30-second buffer).

### Auth0 Management API

Convenience wrappers for the Auth0 Management API (requires M2M credentials):

```python
# Create a user
response = auth.post_to_mgmt_api("users", json_data={
    "email": "user@example.com",
    "connection": "Username-Password-Authentication",
})

# Get a user
response = auth.get_from_mgmt_api("users/auth0|123456")

# Update a user
response = auth.patch_to_mgmt_api("users/auth0|123456", json_data={
    "user_metadata": {"role": "admin"},
})

# Delete a user
response = auth.delete_from_mgmt_api("users/auth0|123456")
```

### User Info

Fetch user profile from Auth0's `/userinfo` endpoint:

```python
user_info = auth.get_userinfo(token)
```

---

## Generic JWT Authentication (`JWT_Auth`)

### Configuration

```bash
JWT_SECRET_KEY=my_secret_key          # For HS* algorithms, or path to PEM/SSH key for RS*/ES*
JWT_SIGN_ALGORITHM=HS256              # Optional, defaults to HS256
JWT_SECRET_PASSWORD=                  # Optional, for encrypted private keys
```

### Token Generation

```python
from mit_utils.authentication.jwt_auth import JWT_Auth

jwt_auth = JWT_Auth()

token = jwt_auth.generate_jwt_token(
    payload={"sub": "user123", "role": "admin"},
    expires_in_minutes=60,
)
```

### Token Validation

```python
try:
    payload = jwt_auth.validate_jwt_token(token)
    print(payload["sub"])  # "user123"
except HTTPException as e:
    print(e.detail)  # "Token has expired" or "Invalid token"
```

### Asymmetric Keys (RS256, ES256, etc.)

```python
jwt_auth = JWT_Auth(
    secret_key="/path/to/private-key.pem",
    sign_algorithm="RS256",
    secret_password="optional-key-password",
)
```

Supported algorithms: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.

---

## API Reference

### `Auth0_Auth`

| Method / Property          | Description                                                    |
|----------------------------|----------------------------------------------------------------|
| `bearer_scheme`            | OAuth2 bearer token scheme for FastAPI `dependencies`          |
| `get_payload()`            | Returns a FastAPI dependency that decodes and verifies the JWT |
| `has_permission(perms)`    | Returns a dependency checking for **any** of the permissions   |
| `has_group_permission(perms)` | Returns a dependency checking for **all** of the permissions |
| `verify_token(token)`      | Manually verify a JWT token and return the payload             |
| `get_userinfo(token)`      | Fetch user info from Auth0 `/userinfo` endpoint                |
| `get_m2m_token()`          | Get a cached M2M access token                                  |
| `post_to_mgmt_api(endpoint, json_data)` | POST to Auth0 Management API                     |
| `get_from_mgmt_api(endpoint)` | GET from Auth0 Management API                              |
| `patch_to_mgmt_api(endpoint, json_data)` | PATCH on Auth0 Management API                    |
| `delete_from_mgmt_api(endpoint)` | DELETE from Auth0 Management API                        |

### `JWT_Auth`

| Method                     | Description                                                    |
|----------------------------|----------------------------------------------------------------|
| `generate_jwt_token(payload, expires_in_minutes)` | Generate a signed JWT token          |
| `validate_jwt_token(token)` | Decode and validate a JWT, raising `HTTPException` on failure |
