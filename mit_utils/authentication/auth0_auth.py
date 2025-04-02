import requests
import os
import jwt
import json
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2AuthorizationCodeBearer
from jwt.algorithms import RSAAlgorithm




class Auth0_Auth:
    def __init__(self, domain: str = None, audience: str = None, client_id: str = None, client_secret: str = None):
        self.domain = domain or os.getenv("AUTH0_DOMAIN")
        self.audience = audience or os.getenv("AUTH0_AUDIENCE")
        self.client_id = client_id or os.getenv("AUTH0_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("AUTH0_CLIENT_SECRET")
        # self.token = self.get_token()
        # self.bearer_scheme = self.create_bearer_scheme()
        self.bearer_scheme = self.create_oauth2_scheme()

    def create_bearer_scheme(self):
        return HTTPBearer()
    

    # def create_oauth2_scheme_with_org(self):
    #     oauth2_scheme = OAuth2AuthorizationCodeBearer(
    #         authorizationUrl=f"https://{self.domain}/authorize?organization={self.org_id}&audience={self.audience}",
    #         tokenUrl=f"https://{self.domain}/oauth/token",
    #         scopes={
    #         "openid": "Basic user identity",
    #         "profile": "Access profile info",
    #         "email": "Access email address",
    #     },
    #     )
    #     return oauth2_scheme



    def create_oauth2_scheme(self):
        oauth2_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=f"https://{self.domain}/authorize?audience={self.audience}",
            tokenUrl=f"https://{self.domain}/oauth/token",
            scopes={
            "openid": "Basic user identity",
            "profile": "Access profile info",
            "email": "Access email address",
        },
            
        )
        return oauth2_scheme

    def set_token(self):
        self.token = self.get_token()
        return self.token
    
    
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
        async def _get_payload(credentials: HTTPAuthorizationCredentials = Depends(self.bearer_scheme),
                               bearer_credentials:HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> dict:
            """
            Extracts the payload from the provided bearer token.
            Args:
                credentials (HTTPAuthorizationCredentials): The bearer token credentials 
                extracted from the request using the default bearer scheme.
                bearer_credentials (HTTPAuthorizationCredentials): An additional bearer 
                token dependency added for Swagger authentication purposes. Note that 
                `credentials` are populated regardless of whether this parameter is used.
            Returns:
                dict: The decoded payload of the bearer token.
            """
            token = credentials
            return self.verify_token(token)
        return _get_payload