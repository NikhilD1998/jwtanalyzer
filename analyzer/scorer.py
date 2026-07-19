class JWTScorer:

    SEVERITY_SCORES = {
        "CRITICAL": 50,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0
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

            severity = check["severity"]

            if check["status"] != "PASS":

                score -= JWTScorer.SEVERITY_SCORES[severity]

                summary[severity] += 1

                findings.append(check)

        score = max(score, 0)

        if score >= 90:
            risk = "LOW"

        elif score >= 70:
            risk = "MEDIUM"

        elif score >= 40:
            risk = "HIGH"

        else:
            risk = "CRITICAL"

        return {
            "score": score,
            "risk": risk,
            "summary": summary,
            "findings": findings
        }