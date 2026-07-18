import argparse

from rich.console import Console
from rich.json import JSON

from analyzer.parser import JWTParser
from analyzer.checks import JWTChecks
from analyzer.verifier import JWTVerifier

console = Console()

STATUS_COLORS = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}


def decode_jwt(token: str):
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
            color = STATUS_COLORS[result["status"]]

            console.print(
                f"[{color}]{result['status']:<5}[/{color}] {result['message']}"
            )

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


def verify_jwt(token: str, secret: str):
    result = JWTVerifier.verify_hs256(token, secret)

    color = STATUS_COLORS[result["status"]]

    console.print(
        f"\n[{color}]{result['status']}[/{color}] {result['message']}"
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

    # Decode Command
    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode a JWT"
    )
    decode_parser.add_argument(
        "token",
        help="JWT Token"
    )

    # Verify Command
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

    elif args.command == "verify":
        verify_jwt(args.token, args.secret)


if __name__ == "__main__":
    main()