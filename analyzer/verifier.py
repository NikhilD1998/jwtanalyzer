import jwt


class JWTVerifier:

    @staticmethod
    def verify_hs256(token: str, secret: str) -> dict:
        """
        Verify an HS256 JWT using the provided secret.
        """

        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=["HS256"]
            )

            return {
                "status": "PASS",
                "message": "Signature is valid.",
                "payload": payload
            }

        except jwt.ExpiredSignatureError:
            return {
                "status": "FAIL",
                "message": "Token has expired."
            }

        except jwt.InvalidSignatureError:
            return {
                "status": "FAIL",
                "message": "Invalid signature."
            }

        except jwt.InvalidTokenError as e:
            return {
                "status": "FAIL",
                "message": str(e)
            }