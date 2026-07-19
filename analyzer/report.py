import json
from pathlib import Path


class ReportGenerator:

    @staticmethod
    def export_json(result, filename):

        Path(filename).write_text(
            json.dumps(result, indent=4, default=str),
            encoding="utf-8"
        )

    @staticmethod
    def export_markdown(result, filename):

        security = result["security"]

        md = []

        md.append("# JWT Security Analysis\n")

        md.append(f"## Security Score\n")
        md.append(f"- **Score:** {security['score']}/100")
        md.append(f"- **Risk:** {security['risk']}\n")

        md.append("## Findings\n")

        for finding in security["findings"]:
            md.append(f"### {finding['name']}")
            md.append(f"- Status: {finding['status']}")
            md.append(f"- Severity: {finding['severity']}")
            md.append(f"- Issue: {finding['message']}")
            md.append(f"- Recommendation: {finding['recommendation']}\n")

        md.append("## Recommendations\n")

        for rec in result["recommendations"]:
            md.append(f"- {rec}")

        Path(filename).write_text(
            "\n".join(md),
            encoding="utf-8"
        )