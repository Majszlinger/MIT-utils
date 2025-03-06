import requests
import os
import jwt
import json
from functools import wraps
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt.algorithms import RSAAlgorithm




class Auth0_Auth:
    def __init__(self, domain: str = None, audience: str = None, client_id: str = None, client_secret: str = None):
        self.domain = domain or os.getenv("AUTH0_DOMAIN")
        self.audience = audience or os.getenv("AUTH0_AUDIENCE")
        self.client_id = client_id or os.getenv("AUTH0_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("AUTH0_CLIENT_SECRET")
        # self.token = self.get_token()
        self.bearer_scheme = self.create_bearer_scheme()

    def create_bearer_scheme(self):
        return HTTPBearer()

    def set_token(self):
        self.token = self.get_token()
        return self.token
    
    def get_token(self):
        url = f"https://{self.domain}/oauth/token"
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": self.audience,
            "grant_type": "client_credentials"
        }
        response = requests.post(url, data=payload)
        response.raise_for_status()
        return response.json()["access_token"]
    
    def get_public_key(self):
        url = f"https://{self.domain}/.well-known/jwks.json"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    
    def verify_token(self, token: str):
        jwks = self.get_public_key()
        unverified_header = jwt.get_unverified_header(token)

        # Find the matching key
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = key
                break
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Convert the JWKS to a proper public key
        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(rsa_key))
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid key format")

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=f"https://{self.domain}/"
        )

        return payload
    
    def get_payload(self):
        async def _get_payload(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> dict:
            token = credentials.credentials
            return self.verify_token(token)
        return _get_payload