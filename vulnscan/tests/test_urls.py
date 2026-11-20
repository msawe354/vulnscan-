"""Тесты нормализации и валидации URL."""

from __future__ import annotations

import pytest

from vulnscan.utils.urls import (
    InvalidTargetError,
    is_https,
    join_url,
    normalize_target,
    same_origin,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com"),
        ("example.com/app?x=1", "https://example.com/app?x=1"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("https://example.com/path#section", "https://example.com/path"),
        ("  https://example.com  ", "https://example.com"),
    ],
)
def test_normalize_target_valid(raw: str, expected: str) -> None:
    assert normalize_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "ftp://example.com", "https://", "http://example.com:99999"],
)
def test_normalize_target_invalid(raw: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_target(raw)


def test_is_https() -> None:
    assert is_https("https://example.com") is True
    assert is_https("http://example.com") is False


def test_join_url_keeps_base_prefix() -> None:
    assert join_url("https://example.com/app", "admin") == "https://example.com/app/admin"
    assert join_url("https://example.com/app/", "/admin") == "https://example.com/app/admin"


def test_same_origin() -> None:
    assert same_origin("https://example.com/a", "https://example.com/b") is True
    assert same_origin("https://example.com", "http://example.com") is False
    assert same_origin("https://example.com", "https://api.example.com") is False
