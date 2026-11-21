"""Command-line interface entrypoint for Secret Sentry."""

import argparse
import sys
import os

from secret_sentry.scanner import scan_directory
from secret_sentry.reporter import format_terminal, format_json, format_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentry",
        description="Secret Sentry: Zero-exfiltration local secret scanning CLI for files and repositories.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    scan_cmd = subparsers.add_parser("scan", help="Scan a directory or file for exposed credentials")
    scan_cmd.add_argument("path", nargs="?", default=".", help="Target path to scan (default: current directory)")
    scan_cmd.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Report output format (default: text)",
    )
    scan_cmd.add_argument(
        "--output",
        "-o",
        help="Write output report to file",
    )
    scan_cmd.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colored output",
    )
    scan_cmd.add_argument(
        "--strict",
        action="store_true",
        default=True,
        help="Exit with code 1 if any secrets are detected (default: True)",
    )
    return parser


def main(argv=None) -> int:
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        summary = scan_directory(args.path)

        if args.format == "json":
            out = format_json(summary)
        elif args.format == "markdown":
            out = format_markdown(summary)
        else:
            out = format_terminal(summary, use_color=not args.no_color)

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out + "\n")
                print(f"Report written to: {args.output}")
            except Exception as e:
                sys.stderr.write(f"Failed to write output to {args.output}: {e}\n")
                return 2
        else:
            print(out)

        if not summary.is_clean and args.strict:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
