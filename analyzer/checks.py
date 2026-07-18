from datetime import datetime, timezone


class JWTChecks:
    @staticmethod
    def check_algorithm(header: dict):
        alg = header.get("alg")

        if alg is None:
            return {
                "status": "FAIL",
                "message": "Algorithm claim missing."
            }

        if alg.lower() == "none":
            return {
                "status": "FAIL",
                "message": "Unsigned JWT detected (alg=none)."
            }

        return {
            "status": "PASS",
            "message": f"Algorithm: {alg}"
        }

    @staticmethod
    def check_exp(payload: dict):
        exp = payload.get("exp")

        if exp is None:
            return {
                "status": "WARN",
                "message": "exp claim missing."
            }

        exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)

        if exp_time < datetime.now(timezone.utc):
            return {
                "status": "FAIL",
                "message": f"Token expired on {exp_time} UTC"
            }

        return {
            "status": "PASS",
            "message": f"Expires on {exp_time} UTC"
        }

    @staticmethod
    def check_iat(payload: dict):
        if "iat" not in payload:
            return {
                "status": "WARN",
                "message": "iat claim missing."
            }

        issued = datetime.fromtimestamp(
            payload["iat"],
            tz=timezone.utc
        )

        return {
            "status": "PASS",
            "message": f"Issued at {issued} UTC"
        }

    @staticmethod
    def check_nbf(payload: dict):
        nbf = payload.get("nbf")

        if nbf is None:
            return {
                "status": "WARN",
                "message": "nbf claim missing."
            }

        nbf_time = datetime.fromtimestamp(
            nbf,
            tz=timezone.utc
        )

        if nbf_time > datetime.now(timezone.utc):
            return {
                "status": "FAIL",
                "message": f"Token cannot be used before {nbf_time} UTC"
            }

        return {
            "status": "PASS",
            "message": "nbf check passed."
        }