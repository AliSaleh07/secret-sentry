"""Secret detection patterns, validation logic, and allowlist filters."""

import re
from typing import List, Dict, Any, Optional
from secret_sentry.models import SecretFinding
from secret_sentry.entropy import calculate_shannon_entropy, mask_secret

IGNORED_PATTERNS = [
    re.compile(r"EXAMPLE", re.IGNORECASE),
    re.compile(r"DUMMY", re.IGNORECASE),
    re.compile(r"TEST_KEY", re.IGNORECASE),
    re.compile(r"PLACEHOLDER", re.IGNORECASE),
    re.compile(r"YOUR_.*_HERE", re.IGNORECASE),
    re.compile(r"x{8,}", re.IGNORECASE),
    re.compile(r"0{8,}"),
]

RULES = [
    {
        "id": "SEC-001",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-002",
        "name": "GitHub Token",
        "pattern": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{70,255})\b"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-003",
        "name": "Slack Token",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48})\b"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-004",
        "name": "Private Key",
        "pattern": re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-005",
        "name": "Stripe Live API Key",
        "pattern": re.compile(r"\b([rs]k_live_[0-9a-zA-Z]{24,99})\b"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-006",
        "name": "Google Cloud API Key",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-007",
        "name": "Database Connection String with Credentials",
        "pattern": re.compile(r"\b(?:postgres|mysql|mongodb)://[^:]+:([A-Za-z0-9!#\$%&'\*\+\-\/=\?\^_`\{\|\}~]{6,})@"),
        "min_entropy": 2.5,
    },
    {
        "id": "SEC-008",
        "name": "Generic High-Entropy Secret",
        "pattern": re.compile(r"""(?:api_key|secret|token|password|auth_token)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']""", re.IGNORECASE),
        "min_entropy": 3.8,
    },
]


def is_allowlisted(secret: str) -> bool:
    """Checks if candidate secret is an obvious placeholder or dummy test string."""
    return any(p.search(secret) for p in IGNORED_PATTERNS)


def scan_line(line: str, line_num: int, file_path: str) -> List[SecretFinding]:
    """Scans an individual line against all configured secret detection rules."""
    findings: List[SecretFinding] = []

    for rule in RULES:
        for match in rule["pattern"].finditer(line):
            secret_value = match.group(1) if match.groups() else match.group(0)

            if is_allowlisted(secret_value):
                continue

            entropy = calculate_shannon_entropy(secret_value)
            if entropy < rule["min_entropy"]:
                continue

            masked = mask_secret(secret_value)
            # Create a sanitized snippet around the match
            start = max(0, match.start() - 20)
            end = min(len(line), match.end() + 20)
            snippet = line[start:end].replace(secret_value, masked).strip()

            findings.append(
                SecretFinding(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    file_path=file_path,
                    line_number=line_num,
                    redacted_secret=masked,
                    raw_match_snippet=snippet,
                    entropy_score=entropy,
                )
            )

    return findings
