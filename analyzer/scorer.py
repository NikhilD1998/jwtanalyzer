class JWTScorer:

    @staticmethod
    def calculate(checks):
        score = 100

        for check in checks:

            if check["status"] == "FAIL":
                score -= 25

            elif check["status"] == "WARN":
                score -= 10

        score = max(score, 0)

        if score >= 90:
            risk = "LOW"

        elif score >= 70:
            risk = "MEDIUM"

        elif score >= 50:
            risk = "HIGH"

        else:
            risk = "CRITICAL"

        return {
            "score": score,
            "risk": risk
        }