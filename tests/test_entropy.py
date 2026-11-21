"""Unit tests for Shannon entropy calculation and masking."""

import pytest
from secret_sentry.entropy import calculate_shannon_entropy, mask_secret


def test_entropy_zero_for_empty():
    assert calculate_shannon_entropy("") == 0.0


def test_entropy_low_for_repeated_chars():
    entropy = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert entropy == 0.0


def test_entropy_high_for_random_tokens():
    random_token = "4f8a9b2c1d0e7f6a5b4c3d2e1f0a9b8c"
    entropy = calculate_shannon_entropy(random_token)
    assert entropy > 3.5


def test_mask_secret():
    secret = "AKIA1234567890ABCDEF"
    masked = mask_secret(secret, 4, 4)
    assert masked.startswith("AKIA")
    assert masked.endswith("CDEF")
    assert "*" in masked
    assert len(masked) == len(secret)


def test_mask_short_secret():
    assert mask_secret("short") == "*****"
