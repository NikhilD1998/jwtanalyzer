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

        if "security" in result:
            self.render_score(result["security"])

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

        self.console.print(
            Panel.fit(
                f"[bold {color}]Score : {score}/100[/bold {color}]\n"
                f"Risk  : {security['risk']}",
                title="Security Score",
                border_style=color
            )
        )