from datetime import datetime, timezone


class JWTChecks:

    @staticmethod
    def _result(name, status, severity, message, recommendation):
        return {
            "name": name,
            "status": status,
            "severity": severity,
            "message": message,
            "recommendation": recommendation,
        }

    @staticmethod
    def check_algorithm(header: dict):
        alg = header.get("alg")

        if alg is None:
            return JWTChecks._result(
                "Algorithm",
                "FAIL",
                "HIGH",
                "Algorithm claim is missing.",
                "Specify a secure signing algorithm."
            )

        if alg.lower() == "none":
            return JWTChecks._result(
                "Algorithm",
                "FAIL",
                "CRITICAL",
                "Unsigned JWT detected (alg=none).",
                "Never accept unsigned JWTs."
            )

        return JWTChecks._result(
            "Algorithm",
            "PASS",
            "INFO",
            f"Using {alg}.",
            "No action required."
        )

    @staticmethod
    def check_exp(payload: dict):
        exp = payload.get("exp")

        if exp is None:
            return JWTChecks._result(
                "Expiration",
                "WARN",
                "MEDIUM",
                "exp claim missing.",
                "Include an expiration time."
            )

        exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)

        if exp_time < datetime.now(timezone.utc):
            return JWTChecks._result(
                "Expiration",
                "FAIL",
                "HIGH",
                f"Expired on {exp_time}.",
                "Generate a new token."
            )

        return JWTChecks._result(
            "Expiration",
            "PASS",
            "INFO",
            f"Expires on {exp_time}.",
            "No action required."
        )

    @staticmethod
    def check_iat(payload: dict):
        iat = payload.get("iat")

        if iat is None:
            return JWTChecks._result(
                "Issued At",
                "WARN",
                "LOW",
                "iat claim missing.",
                "Include an issued-at timestamp."
            )

        issued = datetime.fromtimestamp(iat, tz=timezone.utc)

        if issued > datetime.now(timezone.utc):
            return JWTChecks._result(
                "Issued At",
                "FAIL",
                "MEDIUM",
                "iat is in the future.",
                "Verify server time."
            )

        return JWTChecks._result(
            "Issued At",
            "PASS",
            "INFO",
            f"Issued at {issued}.",
            "No action required."
        )

    @staticmethod
    def check_nbf(payload: dict):
        nbf = payload.get("nbf")

        if nbf is None:
            return JWTChecks._result(
                "Not Before",
                "WARN",
                "LOW",
                "nbf claim missing.",
                "Add nbf if delayed activation is required."
            )

        nbf_time = datetime.fromtimestamp(nbf, tz=timezone.utc)

        if nbf_time > datetime.now(timezone.utc):
            return JWTChecks._result(
                "Not Before",
                "FAIL",
                "MEDIUM",
                f"Token is not valid before {nbf_time}.",
                "Wait until the activation time."
            )

        return JWTChecks._result(
            "Not Before",
            "PASS",
            "INFO",
            "Token is active.",
            "No action required."
        )
    
    @staticmethod
    def check_subject(payload: dict):
        sub = payload.get("sub")

        if not sub:
            return JWTChecks._result(
                "Subject",
                "WARN",
                "MEDIUM",
                "sub claim missing.",
                "Include a subject identifier."
            )

        return JWTChecks._result(
            "Subject",
            "PASS",
            "INFO",
            f"Subject: {sub}",
            "No action required."
        )
    
    @staticmethod
    def check_issuer(payload: dict):
        iss = payload.get("iss")

        if not iss:
            return JWTChecks._result(
                "Issuer",
                "WARN",
                "MEDIUM",
                "iss claim missing.",
                "Specify the token issuer."
            )

        return JWTChecks._result(
            "Issuer",
            "PASS",
            "INFO",
            f"Issuer: {iss}",
            "No action required."
        )
    
    @staticmethod
    def check_audience(payload: dict):
        aud = payload.get("aud")

        if not aud:
            return JWTChecks._result(
                "Audience",
                "WARN",
                "MEDIUM",
                "aud claim missing.",
                "Restrict the token to an intended audience."
            )

        return JWTChecks._result(
            "Audience",
            "PASS",
            "INFO",
            f"Audience: {aud}",
            "No action required."
        )
    
    @staticmethod
    def check_jti(payload: dict):
        jti = payload.get("jti")

        if not jti:
            return JWTChecks._result(
                "JWT ID",
                "WARN",
                "LOW",
                "jti claim missing.",
                "Include a unique token identifier to help prevent replay attacks."
            )

        return JWTChecks._result(
            "JWT ID",
            "PASS",
            "INFO",
            f"JWT ID: {jti}",
            "No action required."
        )
    
    @staticmethod
    def check_type(header: dict):
        typ = header.get("typ")

        if typ is None:
            return JWTChecks._result(
                "Token Type",
                "WARN",
                "LOW",
                "typ header missing.",
                "Include the token type."
            )

        if typ.upper() != "JWT":
            return JWTChecks._result(
                "Token Type",
                "FAIL",
                "MEDIUM",
                f"Unexpected type: {typ}",
                "Use typ='JWT'."
            )

        return JWTChecks._result(
            "Token Type",
            "PASS",
            "INFO",
            "Token type is JWT.",
            "No action required."
        )
    
    @staticmethod
    def check_sensitive_claims(payload: dict):
        sensitive_claims = {
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "credit_card",
            "card_number",
            "ssn",
            "private_key",
            "token"
        }

        found = [
            key for key in payload.keys()
            if key.lower() in sensitive_claims
        ]

        if found:
            return JWTChecks._result(
                "Sensitive Claims",
                "FAIL",
                "HIGH",
                f"Sensitive claims found: {', '.join(found)}",
                "Do not store secrets inside JWTs."
            )

        return JWTChecks._result(
            "Sensitive Claims",
            "PASS",
            "INFO",
            "No sensitive claims detected.",
            "No action required."
        )
    
    @staticmethod
    def check_privileged_token(payload: dict):

        role = str(payload.get("role", "")).lower()

        admin = payload.get("admin")

        privileged_roles = {
            "admin",
            "administrator",
            "root",
            "superadmin",
            "superuser"
        }

        if admin is True or role in privileged_roles:
            return JWTChecks._result(
                "Privileges",
                "WARN",
                "MEDIUM",
                "Privileged token detected.",
                "Review administrative tokens carefully."
            )

        return JWTChecks._result(
            "Privileges",
            "PASS",
            "INFO",
            "Standard user token.",
            "No action required."
        )
    
    @staticmethod
    def check_token_lifetime(payload: dict):

        exp = payload.get("exp")
        iat = payload.get("iat")

        if exp is None or iat is None:
            return JWTChecks._result(
                "Token Lifetime",
                "WARN",
                "LOW",
                "Cannot calculate token lifetime.",
                "Include both exp and iat claims."
            )

        lifetime = exp - iat

        hours = lifetime / 3600

        if hours > 24:
            return JWTChecks._result(
                "Token Lifetime",
                "WARN",
                "MEDIUM",
                f"Token valid for {hours:.1f} hours.",
                "Consider shorter expiration times."
            )

        return JWTChecks._result(
            "Token Lifetime",
            "PASS",
            "INFO",
            f"Token lifetime: {hours:.1f} hours.",
            "No action required."
        )
    
    @staticmethod
    def check_token_size(token: str):

        size = len(token.encode())

        if size > 4096:
            return JWTChecks._result(
                "Token Size",
                "FAIL",
                "HIGH",
                f"Token size is {size} bytes.",
                "Reduce payload size."
            )

        if size > 2048:
            return JWTChecks._result(
                "Token Size",
                "WARN",
                "MEDIUM",
                f"Large token ({size} bytes).",
                "Consider reducing claims."
            )

        return JWTChecks._result(
            "Token Size",
            "PASS",
            "INFO",
            f"{size} bytes.",
            "No action required."
        )