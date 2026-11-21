"""Filesystem traversal and file scanning engine for Secret Sentry."""

import os
from datetime import datetime, timezone
from typing import List, Set
from secret_sentry.models import ScanSummary, SecretFinding
from secret_sentry.detector import scan_line

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
}

BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".woff", ".woff2", ".ttf"
}

MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit


def is_binary_content(sample_bytes: bytes) -> bool:
    """Heuristic check: if null bytes exist in the first 1024 bytes, treat as binary."""
    return b"\x00" in sample_bytes


def scan_file(file_path: str) -> List[SecretFinding]:
    """Scans a single text file for leaked credentials."""
    findings: List[SecretFinding] = []
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
            return []

        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if is_binary_content(chunk):
                return []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                line_findings = scan_line(line, idx, file_path)
                findings.extend(line_findings)
    except Exception:
        # Gracefully handle unreadable or locked files
        pass

    return findings


def scan_directory(target_path: str) -> ScanSummary:
    """Recursively scans a directory or single file for exposed credentials."""
    abs_path = os.path.abspath(target_path)
    findings: List[SecretFinding] = []
    files_scanned = 0
    files_skipped = 0

    if os.path.isfile(abs_path):
        files_scanned = 1
        findings = scan_file(abs_path)
    elif os.path.isdir(abs_path):
        for root, dirs, files in os.walk(abs_path):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS and not d.startswith(".git")]

            for file_name in files:
                _, ext = os.path.splitext(file_name)
                if ext.lower() in BINARY_EXTENSIONS:
                    files_skipped += 1
                    continue

                full_path = os.path.join(root, file_name)
                f_findings = scan_file(full_path)
                files_scanned += 1
                findings.extend(f_findings)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return ScanSummary(
        target_path=abs_path,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        total_findings=len(findings),
        findings=findings,
        scan_timestamp=now_str,
        is_clean=len(findings) == 0,
    )
