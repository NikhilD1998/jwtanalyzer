import base64
import json
from typing import Tuple


class JWTParser:
    @staticmethod
    def _base64url_decode(data: str) -> dict:
        """
        Decodes a Base64URL encoded JWT segment into a Python dictionary.
        """
        padding = '=' * (-len(data) % 4)
        decoded = base64.urlsafe_b64decode(data + padding)
        return json.loads(decoded.decode("utf-8"))

    @classmethod
    def decode(cls, token: str) -> Tuple[dict, dict]:
        """
        Returns:
            (header, payload)
        """
        parts = token.strip().split(".")

        if len(parts) != 3:
            raise ValueError("Invalid JWT format.")

        header = cls._base64url_decode(parts[0])
        payload = cls._base64url_decode(parts[1])

        return header, payload