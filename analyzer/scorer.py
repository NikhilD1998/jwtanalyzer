class JWTScorer:

    CHECK_WEIGHTS = {

        "Algorithm": 40,

        "Signature": 40,

        "Expiration": 20,

        "Sensitive Claims": 20,

        "Privileges": 8,

        "Audience": 5,

        "Issuer": 5,

        "JWT ID": 3,

        "Not Before": 2,

        "Token Lifetime": 2,

        "Token Size": 2,

        "Subject": 1,

        "Token Type": 1,
    }

    @staticmethod
    def calculate(checks):

        score = 100

        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        findings = []

        for check in checks:

            if check["status"] == "PASS":
                continue

            summary[check["severity"]] += 1
            findings.append(check)

            score -= JWTScorer.CHECK_WEIGHTS.get(check["name"], 5)

        score = max(score, 0)

        if score >= 90:
            risk = "LOW"

        elif score >= 75:
            risk = "MEDIUM"

        elif score >= 50:
            risk = "HIGH"

        else:
            risk = "CRITICAL"

        return {
            "score": score,
            "risk": risk,
            "summary": summary,
            "findings": findings
        }