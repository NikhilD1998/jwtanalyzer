from analyzer.parser import JWTParser
from analyzer.checks import JWTChecks


class JWTAnalyzer:

    @staticmethod
    def analyze(token: str):
        header, payload = JWTParser.decode(token)

        checks = [
            JWTChecks.check_algorithm(header),
            JWTChecks.check_type(header),

            JWTChecks.check_subject(payload),
            JWTChecks.check_issuer(payload),
            JWTChecks.check_audience(payload),
            JWTChecks.check_jti(payload),

            JWTChecks.check_exp(payload),
            JWTChecks.check_iat(payload),
            JWTChecks.check_nbf(payload),
        ]

        return {
            "header": header,
            "payload": payload,
            "checks": checks,
        }