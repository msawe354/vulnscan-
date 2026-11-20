"""Тесты словаря путей, soft-404 и проверки директорий (без сети)."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from vulnscan.checks.directories import (
    DirectoriesCheck,
    ProbeResult,
    is_soft_404,
    load_wordlist,
)
from vulnscan.http_client import HttpResult
from vulnscan.models import Severity


def test_load_wordlist_skips_comments_and_duplicates(tmp_path: Path) -> None:
    wordlist = tmp_path / "list.txt"
    wordlist.write_text(
        "# comment\n\n/admin\n.env\n/admin\n  /.git/config  \n",
        encoding="utf-8",
    )

    assert load_wordlist(wordlist) == ["admin", ".env", ".git/config"]


def test_load_wordlist_handles_utf8_bom(tmp_path: Path) -> None:
    wordlist = tmp_path / "bom.txt"
    wordlist.write_bytes("\ufeff.env\nadmin\n".encode("utf-8"))

    assert load_wordlist(wordlist) == [".env", "admin"]


def test_load_wordlist_missing_file(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        load_wordlist(tmp_path / "nope.txt")


def test_soft_404_detects_identical_baseline() -> None:
    baseline = HttpResult(url="https://x/nope", status_code=200, body="<h1>Not found</h1>")
    probe = ProbeResult(
        path="admin",
        url="https://x/admin",
        status=200,
        length=15,
        body="<h1>Not found</h1>",
    )
    assert is_soft_404(probe, [baseline]) is True

    real = ProbeResult(path=".env", url="https://x/.env", status=200, length=40, body="SECRET=1")
    assert is_soft_404(real, [baseline]) is False


def test_severity_mapping() -> None:
    assert DirectoriesCheck._severity_for(".env") is Severity.HIGH
    assert DirectoriesCheck._severity_for("backup.zip") is Severity.HIGH
    assert DirectoriesCheck._severity_for("admin") is Severity.MEDIUM
    assert DirectoriesCheck._severity_for("robots.txt") is Severity.INFO


class PathClient:
    """Фейковый клиент: 200 только для заранее заданных путей."""

    def __init__(self, existing: dict[str, str], *, soft_404: str | None = None) -> None:
        self.existing = existing
        self.soft_404 = soft_404

    def get(self, url: str, **kwargs) -> HttpResult:
        path = urlparse(url).path.lstrip("/")
        if self.soft_404 is not None:
            return HttpResult(url=url, status_code=200, body=self.soft_404)
        if path.startswith("vulnscan-"):
            return HttpResult(url=url, status_code=404, body="not found")
        if path in self.existing:
            return HttpResult(url=url, status_code=200, body=self.existing[path])
        return HttpResult(url=url, status_code=404, body="not found")


def test_directories_check_finds_sensitive_file() -> None:
    client = PathClient({".env": "DB_PASSWORD=hunter2\nAPP_KEY=secret"})
    check = DirectoriesCheck(client, paths=[".env", "admin"], threads=2)

    findings = check.run("https://example.com")
    high = [item for item in findings if item.severity is Severity.HIGH]

    assert len(high) == 1
    assert high[0].extra["path"] == ".env"
    assert "/.env" in (high[0].url or "")


def test_directories_check_ignores_soft_404() -> None:
    client = PathClient({}, soft_404="<html><body>Page not found</body></html>")
    check = DirectoriesCheck(client, paths=[".env", "admin", "backup.zip"], threads=2)

    assert check.run("https://example.com") == []
