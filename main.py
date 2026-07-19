import argparse

from rich.console import Console
from rich.json import JSON

from analyzer.parser import JWTParser
from analyzer.verifier import JWTVerifier
from analyzer.analyzer import JWTAnalyzer
from analyzer.renderer import Renderer
from analyzer.report import ReportGenerator
from analyzer.utils import FileUtils
from pathlib import Path
from rich.panel import Panel
from rich.table import Table


console = Console()

STATUS_COLORS = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}


def decode_jwt(token: str):

    try:

        header, payload, _ = JWTParser.decode(token)

        Renderer().render_header(header)
        Renderer().render_payload(payload)

    except Exception as e:
        console.print(f"[red]{e}[/red]")


def analyze_jwt(token: str, json_file=None, md_file=None):

    try:

        result = JWTAnalyzer.analyze(token)

        Renderer().render(result)

        if json_file:
            ReportGenerator.export_json(result, json_file)
            console.print(f"\n[green]JSON report saved to {json_file}[/green]")

        if md_file:
            ReportGenerator.export_markdown(result, md_file)
            console.print(f"\n[green]Markdown report saved to {md_file}[/green]")

    except Exception as e:
        console.print(f"[red]{e}[/red]")


def verify_jwt(token: str, secret: str):
    """
    Verify JWT signature using an HS256 secret.
    """
    result = JWTVerifier.verify(token, secret)

    color = STATUS_COLORS[result["status"]]

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", justify="right")
    table.add_column()

    table.add_row("Algorithm", result["algorithm"])
    table.add_row("Key Type", result["key_type"])
    table.add_row("Status", f"[{color}]{result['status']}[/{color}]")
    table.add_row("Message", result["message"])

    console.print(
        Panel(
            table,
            title="[bold]Signature Verification[/bold]",
            border_style=color,
        )
    )

    if result["status"] == "PASS":
        console.print()
        console.print("[bold green]Verified Payload[/bold green]")
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
    
    group = decode_parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "token",
        nargs="?",
        help="JWT Token"
    )

    group.add_argument(
        "--file",
        "-f",
        help="Read JWT from file"
    )

    # Analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze JWT security"
    )
    
    group = analyze_parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "token",
        nargs="?",
        help="JWT Token"
    )

    group.add_argument(
        "--file",
        "-f",
        help="Read JWT from file"
    )

    analyze_parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export analysis as JSON"
    )

    analyze_parser.add_argument(
        "--md",
        metavar="FILE",
        help="Export analysis as Markdown"
    )

    # Verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify JWT Signature"
    )
    
    group = verify_parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "token",
        nargs="?",
        help="JWT Token"
    )

    group.add_argument(
        "--file",
        "-f",
        help="Read JWT from file"
    )
    verify_parser.add_argument(
        "--key",
        "-k",
        required=True,
        help="Secret or PEM key file"
    )

    args = parser.parse_args()

    token = None

    if hasattr(args, "file") and args.file:
        token = FileUtils.read_token(args.file)
    elif hasattr(args, "token"):
        token = args.token

    if args.command == "decode":
        decode_jwt(token)

    elif args.command == "analyze":
        analyze_jwt(
            token,
            json_file=args.json,
            md_file=args.md
        )

    elif args.command == "verify":
        path = Path(args.key)

        if path.exists():
            key = path.read_text(encoding="utf-8")
        else:
            key = args.key

        verify_jwt(token, key)


if __name__ == "__main__":
    main()