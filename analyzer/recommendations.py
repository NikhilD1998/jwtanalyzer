class RecommendationEngine:

    @staticmethod
    def generate(findings):

        recommendations = []

        for finding in findings:

            rec = finding.get("recommendation")

            if rec and rec not in recommendations:
                recommendations.append(rec)

        return recommendations