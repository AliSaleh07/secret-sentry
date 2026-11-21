"""Data models for Secret Sentry detection findings and summaries."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class SecretFinding:
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    redacted_secret: str
    raw_match_snippet: str
    entropy_score: float = 0.0


@dataclass
class ScanSummary:
    target_path: str
    files_scanned: int
    files_skipped: int
    total_findings: int
    findings: List[SecretFinding] = field(default_factory=list)
    scan_timestamp: str = ""
    is_clean: bool = True
