import argparse

from rich.console import Console
from rich.json import JSON

from analyzer.parser import JWTParser
from analyzer.verifier import JWTVerifier
from analyzer.analyzer import JWTAnalyzer

console = Console()

STATUS_COLORS = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}


def decode_jwt(token: str):
    """
    Decode a JWT without performing security analysis.
    """
    try:
        header, payload = JWTParser.decode(token)

        console.print("\n[bold cyan]Header[/bold cyan]")
        console.print(JSON.from_data(header))

        console.print("\n[bold green]Payload[/bold green]")
        console.print(JSON.from_data(payload))

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


def analyze_jwt(token: str):
    """
    Run all security checks on a JWT.
    """
    try:
        result = JWTAnalyzer.analyze(token)

        console.print("\n[bold cyan]Header[/bold cyan]")
        console.print(JSON.from_data(result["header"]))

        console.print("\n[bold green]Payload[/bold green]")
        console.print(JSON.from_data(result["payload"]))

        console.print("\n[bold yellow]Security Checks[/bold yellow]")

        for check in result["checks"]:
            color = STATUS_COLORS[check["status"]]

            console.print(
                f"[{color}]{check['status']:<5}[/{color}] {check['message']}"
            )

        if "security" in result:
            console.print("\n[bold magenta]Security Score[/bold magenta]")
            console.print(
                f"Score : {result['security']['score']}/100"
            )
            console.print(
                f"Risk  : {result['security']['risk']}"
            )

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


def verify_jwt(token: str, secret: str):
    """
    Verify JWT signature using an HS256 secret.
    """
    result = JWTVerifier.verify_hs256(token, secret)

    color = STATUS_COLORS[result["status"]]

    console.print(
        f"[{color}]{check['status']:<5}[/{color}] "
        f"{check['name']:<15} "
        f"{check['message']}"
    )

    if result["status"] == "PASS":
        console.print("\n[bold green]Verified Payload[/bold green]")
        console.print(JSON.from_data(result["payload"]))


def main():
    parser = argparse.ArgumentParser(
        prog="jwt-analyzer",
        description="JWT Analyzer CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # Decode
    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode a JWT"
    )
    decode_parser.add_argument(
        "token",
        help="JWT Token"
    )

    # Analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze JWT security"
    )
    analyze_parser.add_argument(
        "token",
        help="JWT Token"
    )

    # Verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify JWT Signature"
    )
    verify_parser.add_argument(
        "token",
        help="JWT Token"
    )
    verify_parser.add_argument(
        "--secret",
        "-s",
        required=True,
        help="Secret Key"
    )

    args = parser.parse_args()

    if args.command == "decode":
        decode_jwt(args.token)

    elif args.command == "analyze":
        analyze_jwt(args.token)

    elif args.command == "verify":
        verify_jwt(args.token, args.secret)


if __name__ == "__main__":
    main()