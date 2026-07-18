import typer
from rich.console import Console
from rich.json import JSON

from analyzer.parser import JWTParser
from analyzer.checks import JWTChecks

app = typer.Typer()
console = Console()

STATUS_COLORS = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}


decode_app = typer.Typer()
verify_app = typer.Typer()
analyze_app = typer.Typer()

app.add_typer(decode_app, name="decode")
app.add_typer(verify_app, name="verify")
app.add_typer(analyze_app, name="analyze")


@decode_app.callback(invoke_without_command=True)
def decode(token: str):
    try:
        header, payload = JWTParser.decode(token)

        console.print("\n[bold cyan]Header[/bold cyan]")
        console.print(JSON.from_data(header))

        console.print("\n[bold green]Payload[/bold green]")
        console.print(JSON.from_data(payload))

        console.print("\n[bold yellow]Security Checks[/bold yellow]")

        checks = [
            JWTChecks.check_algorithm(header),
            JWTChecks.check_exp(payload),
            JWTChecks.check_iat(payload),
            JWTChecks.check_nbf(payload),
        ]

        for result in checks:
            console.print(
                f"[{STATUS_COLORS[result['status']]}]{result['status']:5}[/{STATUS_COLORS[result['status']]}] {result['message']}"
            )

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


if __name__ == "__main__":
    app()