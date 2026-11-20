"""Тесты разбора форм и детектора отражённого XSS (без сети)."""

from __future__ import annotations

import html as html_module

from vulnscan.checks.xss import (
    XssCheck,
    build_payload,
    parse_forms,
    reflection_context,
)
from vulnscan.http_client import HttpResult
from vulnscan.models import Severity

PAGE = """
<html><body>
  <form action="/search" method="get">
    <input type="text" name="q" value="">
    <input type="hidden" name="lang" value="ru">
    <input type="submit" value="Go">
  </form>
</body></html>
"""

PASSWORD_PAGE = """
<html><body>
  <form action="/login" method="post">
    <input type="text" name="user">
    <input type="password" name="password">
  </form>
</body></html>
"""


class EchoClient:
    """Фейковый клиент: отражает параметры запроса в HTML."""

    def __init__(self, page: str, *, escape: bool = False) -> None:
        self.page = page
        self.escape = escape
        self.submitted = 0

    def get(self, url: str, **kwargs) -> HttpResult:
        params = kwargs.get("params")
        if not params:
            return HttpResult(url=url, status_code=200, body=self.page)
        self.submitted += 1
        value = next(iter(params.values()), "")
        rendered = html_module.escape(value, quote=True) if self.escape else value
        body = f"<html><body><p>Results for: {rendered}</p></body></html>"
        return HttpResult(url=url, status_code=200, body=body)

    def post(self, url: str, **kwargs) -> HttpResult:
        return self.get(url, **kwargs)


# --------------------------------------------------------------------- parsing
def test_parse_forms_resolves_action_and_fields() -> None:
    forms = parse_forms(PAGE, "https://example.com/")

    assert len(forms) == 1
    form = forms[0]
    assert form.action == "https://example.com/search"
    assert form.method == "GET"
    assert [item.name for item in form.injectable_fields] == ["q"]


def test_password_form_is_marked_forbidden() -> None:
    forms = parse_forms(PASSWORD_PAGE, "https://example.com/")
    assert forms[0].has_forbidden_fields is True


def test_build_payload_is_inert() -> None:
    payload = build_payload("abc123")
    assert "vscanabc123" in payload
    assert "<script" not in payload.lower()
    assert "javascript:" not in payload.lower()


# ------------------------------------------------------------------- detection
def test_reflection_context_detects_script() -> None:
    payload = "vscanX\"'><"
    body = f'<html><script>var q = "{payload}";</script></html>'
    assert reflection_context(body, payload) == "script"


def test_reflection_context_detects_text_and_absence() -> None:
    payload = "vscanX\"'><"
    assert reflection_context(f"<p>{payload}</p>", payload) == "text"
    assert reflection_context("<p>clean</p>", payload) is None


# ------------------------------------------------------------------ end-to-end
def test_xss_check_finds_raw_reflection() -> None:
    client = EchoClient(PAGE)
    findings = XssCheck(client, max_forms=5).run("https://example.com/")

    high = [item for item in findings if item.severity is Severity.HIGH]
    assert len(high) == 1
    assert high[0].extra["field"] == "q"
    assert high[0].extra["form_action"] == "https://example.com/search"
    assert client.submitted == 1


def test_xss_check_reports_encoded_reflection_as_info() -> None:
    client = EchoClient(PAGE, escape=True)
    findings = XssCheck(client, max_forms=5).run("https://example.com/")

    assert not any(item.severity in {Severity.HIGH, Severity.CRITICAL} for item in findings)
    assert any(item.severity is Severity.INFO for item in findings)


def test_xss_check_skips_password_forms() -> None:
    client = EchoClient(PASSWORD_PAGE)
    findings = XssCheck(client, max_forms=5).run("https://example.com/")

    assert client.submitted == 0
    assert not any(item.severity is Severity.HIGH for item in findings)
