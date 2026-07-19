import jwt

from analyzer.parser import JWTParser


class JWTVerifier:

    SUPPORTED_ALGORITHMS = {
        "HS256": "symmetric",
        "HS384": "symmetric",
        "HS512": "symmetric",

        "RS256": "asymmetric",
        "RS384": "asymmetric",
        "RS512": "asymmetric",
    }

    @staticmethod
    def verify(token: str, key: str) -> dict:

        header, _, _ = JWTParser.decode(token)

        algorithm = header.get("alg")

        if algorithm not in JWTVerifier.SUPPORTED_ALGORITHMS:
            return {
                "status": "FAIL",
                "name": "Signature",
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
                "message": f"Valid {algorithm} signature.",
                "payload": payload
            }

        except jwt.ExpiredSignatureError:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "message": "Token has expired."
            }

        except jwt.InvalidSignatureError:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "message": "Invalid signature."
            }

        except jwt.InvalidTokenError as e:
            return {
                "status": "FAIL",
                "name": "Signature",
                "algorithm": algorithm,
                "message": str(e)
            }