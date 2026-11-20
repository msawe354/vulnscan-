"""Тесты анализа security-заголовков (без сетевых запросов)."""

from __future__ import annotations

from vulnscan.checks.headers import analyze_headers
from vulnscan.models import Severity

HTTPS_URL = "https://example.com"

SECURE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def test_secure_headers_produce_no_findings() -> None:
    assert analyze_headers(SECURE_HEADERS, HTTPS_URL) == []


def test_missing_headers_are_reported() -> None:
    findings = analyze_headers({"server": "nginx/1.25.3"}, HTTPS_URL)
    titles = " ".join(item.title for item in findings)

    assert "Content-Security-Policy" in titles
    assert "Strict-Transport-Security" in titles
    assert "X-Frame-Options" in titles
    assert "X-Content-Type-Options" in titles
    assert any(item.severity is Severity.MEDIUM for item in findings)


def test_http_target_is_high_severity() -> None:
    findings = analyze_headers(SECURE_HEADERS, "http://example.com")
    assert any(item.severity is Severity.HIGH for item in findings)
    assert any("HTTP" in item.title for item in findings)


def test_unsafe_inline_csp_is_flagged() -> None:
    headers = {
        **SECURE_HEADERS,
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
    }
    findings = analyze_headers(headers, HTTPS_URL)

    assert len(findings) == 1
    assert "unsafe-inline" in findings[0].title
    assert findings[0].severity is Severity.LOW


def test_short_hsts_max_age_is_flagged() -> None:
    headers = {**SECURE_HEADERS, "Strict-Transport-Security": "max-age=600"}
    findings = analyze_headers(headers, HTTPS_URL)
    assert any("max-age" in item.title for item in findings)


def test_invalid_x_frame_options_is_flagged() -> None:
    headers = {**SECURE_HEADERS, "X-Frame-Options": "ALLOW-FROM https://evil.test"}
    findings = analyze_headers(headers, HTTPS_URL)
    assert any("X-Frame-Options" in item.title for item in findings)


def test_csp_frame_ancestors_replaces_x_frame_options() -> None:
    headers = {key: value for key, value in SECURE_HEADERS.items() if key != "X-Frame-Options"}
    findings = analyze_headers(headers, HTTPS_URL)
    assert not any("X-Frame-Options" in item.title for item in findings)


def test_server_version_leak_is_info() -> None:
    headers = {**SECURE_HEADERS, "Server": "Apache/2.4.49"}
    findings = analyze_headers(headers, HTTPS_URL)

    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "Apache/2.4.49" in (findings[0].evidence or "")
