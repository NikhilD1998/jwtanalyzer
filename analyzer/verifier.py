import jwt

from analyzer.parser import JWTParser


class JWTVerifier:

    SUPPORTED_ALGORITHMS = {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
    }

    @staticmethod
    def verify(token: str, key: str):

        header, _, _ = JWTParser.decode(token)

        algorithm = header.get("alg")

        if algorithm not in JWTVerifier.SUPPORTED_ALGORITHMS:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "key_type": "Unknown",
                "message": f"Unsupported algorithm: {algorithm}"
            }

        try:

            payload = jwt.decode(
                token,
                key,
                algorithms=[algorithm]
            )

            return {
                "status": "PASS",
                "name": "Signature",
                "algorithm": algorithm,
                "key_type": (
                    "Shared Secret"
                    if algorithm.startswith("HS")
                    else "RSA Public Key"
                ),
                "message": f"Valid {algorithm} signature.",
                "payload": payload,
            }

        except jwt.ExpiredSignatureError:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "key_type": (
                    "Shared Secret"
                    if algorithm.startswith("HS")
                    else "RSA Public Key"
                ),
                "message": "Token has expired."
            }

        except jwt.InvalidSignatureError:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "key_type": (
                    "Shared Secret"
                    if algorithm.startswith("HS")
                    else "RSA Public Key"
                ),
                "message": "Invalid signature."
            }

        except jwt.InvalidTokenError as e:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "key_type": (
                    "Shared Secret"
                    if algorithm.startswith("HS")
                    else "RSA Public Key"
                ),
                "message": str(e)
            }