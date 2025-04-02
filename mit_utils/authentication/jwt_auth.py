import jwt
import logging
import os
import datetime
from typing import Any, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import UnsupportedAlgorithm


JWT_SIGN_ALGORITHM = os.getenv("JWT_SIGN_ALGORITHM", "HS256")
# JWT secret key for signing tokens
#If assymetric key is used, the path to the private key file should be provided
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "my_secret_key") 
JWT_SECRET_PASSWORD = os.getenv("JWT_SECRET_PASSWORD", None)
VALID_ALGORITHMS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]



class JWT_Auth:
    def __init__(self, secret_key: str = JWT_SECRET_KEY, sign_algorithm: str = JWT_SIGN_ALGORITHM, secret_password: str = JWT_SECRET_PASSWORD):

        if self.validate_algorithm(sign_algorithm):
            self.sign_algorithm = sign_algorithm
        else:
            raise ValueError(f"Unsupported signing algorithm: {sign_algorithm}")
        self.secret_key = self.__load_secret_key(secret_key, secret_password)
    
    def validate_algorithm(self,algorithm: str) -> bool:
        """
        Validates if the provided algorithm is a supported JWT signing algorithm.

        Parameters
        ----------
        algorithm : str
            The JWT signing algorithm to validate.

        Returns
        -------
        bool
            True if the algorithm is valid, False otherwise.
        """
        return algorithm in VALID_ALGORITHMS

    def __load_secret_key(self, secret_key: str,secret_password:str=None) -> None:
        """
        Load the secret key for signing JWT tokens.

        Parameters
        ----------
        secret_key : str
            The path to the secret key file or the secret key string itself.

        Returns
        -------
        None

        Raises
        ------
        ValueError
            If the provided key is invalid.
        UnsupportedAlgorithm
            If the provided key uses an unsupported algorithm.
        Exception
            If there is an error loading the key file.

        Notes
        -----
        This method supports both HMAC (HS*) and RSA/EC (non-HS*) algorithms.
        For HMAC algorithms, the secret key is directly assigned.
        For RSA/EC algorithms, the method attempts to load the key as a PEM or SSH private key.
        """
        if self.sign_algorithm.startswith("HS"):
            self.secret_key = secret_key
        else:
            try:
                with open(secret_key, "rb") as key_file:
                    self.secret_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=secret_password,
                    )
            except (ValueError, UnsupportedAlgorithm):
                # If PEM fails, try SSH
                with open(secret_key, "rb") as key_file:
                    self.secret_key = serialization.load_ssh_private_key(
                        key_file.read(),
                        password=secret_password,
                    )
            except Exception as e:
                logging.error(f"Failed to load key file: {e}")
                raise e


        
    def generate_jwt_token(self, payload: Dict[str, Any], expires_in_minutes: int = 60) -> str:
        """
        Generates a JWT token with the given payload and expiration time.
        """
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_in_minutes)
        payload["exp"] = expiration
        token = jwt.encode(payload, self.secret_key, algorithm=self.sign_algorithm)
        return token

    def validate_jwt_token(self, token: str) -> Dict[str, Any]:
        """
        Validates the given JWT token and returns its payload if valid.
        Raises jwt.exceptions.InvalidTokenError if token is invalid or expired.
        """
        header_data = jwt.get_unverified_header(token)
        decoded = jwt.decode(token, self.secret_key, algorithms=[header_data["alg"]])
        return decoded