"""Reporting and visualization formatting for Secret Sentry."""

import json
from secret_sentry.models import ScanSummary

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_GRAY = "\033[90m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


def format_terminal(summary: ScanSummary, use_color: bool = True) -> str:
    lines = []
    c_bold = COLOR_BOLD if use_color else ""
    c_reset = COLOR_RESET if use_color else ""
    c_red = COLOR_RED if use_color else ""
    c_green = COLOR_GREEN if use_color else ""
    c_gray = COLOR_GRAY if use_color else ""

    lines.append(f"{c_bold}Secret Sentry Local Credential Scan{c_reset}")
    lines.append(f"{c_gray}Target:{c_reset} {summary.target_path}")
    lines.append(f"{c_gray}Files Scanned:{c_reset} {summary.files_scanned} ({summary.files_skipped} binary/skipped)")
    lines.append(f"{c_gray}Timestamp:{c_reset} {summary.scan_timestamp}\n")

    if summary.is_clean:
        lines.append(f"{c_green}[✓] Zero exposed secrets or credentials detected.{c_reset}\n")
        return "\n".join(lines)

    lines.append(f"{c_red}{c_bold}[!] {summary.total_findings} Exposed Secret(s) Found:{c_reset}")
    lines.append("-" * 75)

    for idx, f in enumerate(summary.findings, 1):
        lines.append(f"{idx}. {c_bold}[{f.rule_id}] {f.rule_name}{c_reset}")
        lines.append(f"   Location:  {f.file_path}:{f.line_number}")
        lines.append(f"   Redacted:  {c_red}{f.redacted_secret}{c_reset}")
        lines.append(f"   Context:   {f.raw_match_snippet}")
        lines.append(f"   Entropy:   {f.entropy_score:.2f} bits")
        lines.append("")

    lines.append("-" * 75)
    lines.append(f"{c_bold}Status: FAILED - Secrets detected in codebase!{c_reset}\n")
    return "\n".join(lines)


def format_json(summary: ScanSummary) -> str:
    data = {
        "target_path": summary.target_path,
        "files_scanned": summary.files_scanned,
        "files_skipped": summary.files_skipped,
        "scan_timestamp": summary.scan_timestamp,
        "is_clean": summary.is_clean,
        "total_findings": summary.total_findings,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "file": f.file_path,
                "line": f.line_number,
                "redacted_secret": f.redacted_secret,
                "snippet": f.raw_match_snippet,
                "entropy": f.entropy_score,
            }
            for f in summary.findings
        ],
    }
    return json.dumps(data, indent=2)


def format_markdown(summary: ScanSummary) -> str:
    lines = [
        "# Secret Sentry Scan Report",
        f"- **Target:** `{summary.target_path}`",
        f"- **Files Scanned:** {summary.files_scanned}",
        f"- **Total Secrets:** {summary.total_findings}",
        f"- **Timestamp:** {summary.scan_timestamp}",
        "",
    ]
    if summary.is_clean:
        lines.append("✅ **Clean**: No secrets or credentials were detected.")
        return "\n".join(lines)

    lines.append("## Detected Credentials")
    lines.append("| ID | Type | File | Line | Redacted Secret | Entropy |")
    lines.append("|---|---|---|---|---|---|")
    for f in summary.findings:
        lines.append(
            f"| {f.rule_id} | {f.rule_name} | `{f.file_path}` | {f.line_number} | `{f.redacted_secret}` | {f.entropy_score} |"
        )
    return "\n".join(lines)
