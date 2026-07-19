import argparse

from rich.console import Console
from rich.json import JSON

from analyzer.parser import JWTParser
from analyzer.verifier import JWTVerifier
from analyzer.analyzer import JWTAnalyzer
from analyzer.renderer import Renderer
from analyzer.report import ReportGenerator
from analyzer.utils import FileUtils

console = Console()

STATUS_COLORS = {
    "PASS": "green",
    "WARN": "yellow",
    "FAIL": "red",
}


def decode_jwt(token: str):

    try:

        header, payload = JWTParser.decode(token)

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

    console.print(
        f"[{color}]{result['status']:<5}[/{color}] "
        f"{result['name']:<15} "
        f"{result['message']}"
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
        "--secret",
        "-s",
        required=True,
        help="Secret Key"
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
        verify_jwt(token, args.secret)


if __name__ == "__main__":
    main()