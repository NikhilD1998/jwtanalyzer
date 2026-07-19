from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON


class Renderer:

    def __init__(self):
        self.console = Console()

    def render(self, result):

        self.render_header(result["header"])
        self.render_payload(result["payload"])
        self.render_checks(result["checks"])
        self.render_score(result["security"])
        self.render_findings(result["security"]["findings"])


    def render_header(self, header):

        self.console.print(
            Panel.fit(
                JSON.from_data(header),
                title="JWT Header",
                border_style="cyan"
            )
        )

    def render_payload(self, payload):

        table = Table(title="JWT Claims")

        table.add_column("Claim", style="cyan")
        table.add_column("Value", style="green")

        for key, value in payload.items():
            table.add_row(str(key), str(value))

        self.console.print(table)

    def render_checks(self, checks):

        table = Table(title="Security Checks")

        table.add_column("Check", style="cyan")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Message")

        colors = {
            "PASS": "green",
            "WARN": "yellow",
            "FAIL": "red"
        }

        for check in checks:

            table.add_row(
                check["name"],
                f"[{colors[check['status']]}]{check['status']}[/{colors[check['status']]}]",
                check["severity"],
                check["message"]
            )

        self.console.print(table)

    def render_score(self, security):

        score = security["score"]

        if score >= 90:
            color = "green"

        elif score >= 70:
            color = "yellow"

        else:
            color = "red"

        panel = f"""
    Score      : {score}/100
    Risk Level : {security['risk']}

    Critical Findings : {security['summary']['CRITICAL']}
    High Findings     : {security['summary']['HIGH']}
    Medium Findings   : {security['summary']['MEDIUM']}
    Low Findings      : {security['summary']['LOW']}
    """

        self.console.print(
            Panel.fit(
                panel.strip(),
                title="Security Score",
                border_style=color
            )
        )

    def render_findings(self, findings):

        if not findings:
            return

        table = Table(title="Security Findings")

        table.add_column("Check", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Issue")
        table.add_column("Recommendation", style="green")

        for finding in findings:

            table.add_row(
                finding["name"],
                finding["severity"],
                finding["message"],
                finding["recommendation"]
            )

        self.console.print(table)