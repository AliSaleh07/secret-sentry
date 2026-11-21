"""Shannon entropy calculation and safe credential redaction utilities."""

import math
from collections import Counter


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy (in bits per symbol) of a given string."""
    if not data:
        return 0.0

    length = len(data)
    freqs = Counter(data)
    entropy = 0.0

    for count in freqs.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def mask_secret(secret: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """Safely masks a secret, preserving minimal surrounding context for developer identification."""
    clean = secret.strip()
    if len(clean) <= (visible_prefix + visible_suffix):
        return "*" * len(clean)

    prefix = clean[:visible_prefix]
    suffix = clean[-visible_suffix:]
    masked_middle = "*" * (len(clean) - visible_prefix - visible_suffix)
    return f"{prefix}{masked_middle}{suffix}"
