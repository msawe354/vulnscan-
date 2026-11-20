"""Поиск отражённого XSS (Reflected XSS) в HTML-формах.

Принципы безопасности:
  * пейлоад **не содержит** исполняемого JavaScript: только маркер и символы
    ``"'>``, которые нужны, чтобы выйти из контекста атрибута/текста;
  * проверяются только формы, ведущие на тот же origin, что и целевая страница
    (нельзя «сканировать» чужие сайты через форму-жертву);
  * формы с полями ``password``/``file`` пропускаются: туда нельзя отправлять
    произвольные данные;
  * количество форм и полей ограничено, чтобы не устроить нагрузочный тест.

Находка формулируется как «возможный Reflected XSS»: сканер фиксирует факт
неэкранированного отражения, а ручная верификация всё равно рекомендуется.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from vulnscan.checks.base import BaseCheck
from vulnscan.models import Finding, Severity
from vulnscan.utils.urls import same_origin

#: Типы input, в которые безопасно (и осмысленно) подставлять пейлоад.
INJECTABLE_INPUT_TYPES = {"text", "search", "email", "url", "tel", "textarea", ""}

#: Типы input, которые полностью исключают форму из проверки.
FORBIDDEN_INPUT_TYPES = {"password", "file"}


@dataclass(slots=True)
class FormField:
    """Поле формы."""

    name: str
    value: str = ""
    kind: str = "text"


@dataclass(slots=True)
class HtmlForm:
    """Разобранная HTML-форма."""

    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)
    page_url: str = ""

    @property
    def has_forbidden_fields(self) -> bool:
        """True, если в форме есть поля с паролем или загрузкой файла."""
        return any(item.kind.lower() in FORBIDDEN_INPUT_TYPES for item in self.fields)

    @property
    def injectable_fields(self) -> list[FormField]:
        """Поля, в которые можно подставить тестовое значение."""
        return [
            item
            for item in self.fields
            if item.kind.lower() in INJECTABLE_INPUT_TYPES and item.name
        ]


def parse_forms(html: str, page_url: str) -> list[HtmlForm]:
    """Извлекает формы и их поля из HTML-документа.

    Args:
        html: Исходный HTML страницы.
        page_url: URL страницы — используется для резолва относительного ``action``.

    Returns:
        Список форм. ``action`` всегда абсолютный URL.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms: list[HtmlForm] = []

    for form_tag in soup.find_all("form"):
        action = (form_tag.get("action") or "").strip()
        resolved_action = urljoin(page_url, action) if action else page_url
        method = (form_tag.get("method") or "get").strip().upper()
        if method not in {"GET", "POST"}:
            method = "GET"

        fields: list[FormField] = []
        for element in form_tag.find_all(["input", "textarea", "select"]):
            name = (element.get("name") or "").strip()
            if not name:
                continue

            if element.name == "textarea":
                fields.append(FormField(name=name, value=element.text.strip(), kind="textarea"))
                continue

            if element.name == "select":
                selected = element.find("option", selected=True) or element.find("option")
                value = (selected.get("value") or selected.text.strip()) if selected else ""
                fields.append(FormField(name=name, value=value, kind="select"))
                continue

            kind = (element.get("type") or "text").strip().lower()
            value = element.get("value") or ""
            if kind in {"checkbox", "radio"} and not element.has_attr("checked"):
                continue  # не отправляем невыбранные переключатели
            fields.append(FormField(name=name, value=value, kind=kind))

        forms.append(
            HtmlForm(action=resolved_action, method=method, fields=fields, page_url=page_url)
        )
    return forms


def build_payload(token: str) -> str:
    """Формирует инертный (без JS) пейлоад с уникальным маркером.

    Пейлоад содержит только маркер и символы выхода из контекста — никакого
    исполняемого кода, поэтому запрос безопасен для тестируемого приложения.
    """
    return f"vscan{token}\"'><"


def reflection_context(body: str, payload: str) -> str | None:
    """Возвращает контекст отражения пейлоада или ``None``, если отражения нет.

    Контексты:
      * ``"script"`` — пейлоад внутри ``<script>`` (наиболее опасно);
      * ``"attribute"`` — внутри тега (например, ``value="..."``);
      * ``"text"`` — в текстовом узле.
    """
    index = body.find(payload)
    if index == -1:
        return None

    prefix = body[:index].lower()
    last_open = prefix.rfind("<script")
    last_close = prefix.rfind("</script")
    if last_open > last_close:
        return "script"

    last_tag_start = prefix.rfind("<")
    last_tag_end = prefix.rfind(">")
    if last_tag_start > last_tag_end:
        return "attribute"
    return "text"


def _is_encoded_reflection(body: str, marker: str) -> bool:
    """True, если маркер отражён, но специальные символы рядом экранированы."""
    index = body.find(marker)
    if index == -1:
        return False
    window = body[max(0, index - 120) : index + len(marker) + 120]
    return any(entity in window for entity in ("&quot;", "&#x27;", "&#39;", "&apos;"))


class XssCheck(BaseCheck):
    """Проверяет формы на отражение тестового пейлоада без экранирования."""

    slug = "xss"
    name = "Reflected XSS в формах"

    def __init__(
        self,
        client,
        *,
        max_forms: int = 10,
        max_fields_per_form: int = 5,
    ) -> None:
        super().__init__(client)
        self.max_forms = max(1, max_forms)
        self.max_fields_per_form = max(1, max_fields_per_form)
        self.tested_requests = 0
        self.skipped_forms = 0

    # ------------------------------------------------------------------ public
    def run(self, target: str) -> list[Finding]:
        page = self.client.get(target, follow_redirects=True)
        if not page.ok:
            return [
                self._error_finding(
                    f"Не удалось загрузить страницу для анализа форм: {page.error}",
                    url=target,
                )
            ]

        forms = parse_forms(page.body, page.url)
        if not forms:
            return [
                Finding(
                    check=self.slug,
                    title="HTML-формы не найдены",
                    severity=Severity.INFO,
                    description=(
                        "На странице нет форм — проверка отражённого XSS через формы "
                        "не применима. Параметры URL стоит проверить вручную."
                    ),
                    url=page.url,
                )
            ]

        findings: list[Finding] = []
        tested: set[tuple[str, str]] = set()

        for form in forms[: self.max_forms]:
            if not same_origin(form.action, page.url):
                self.skipped_forms += 1
                continue
            if form.has_forbidden_fields:
                self.skipped_forms += 1
                continue

            for form_field in form.injectable_fields[: self.max_fields_per_form]:
                key = (form.action, form_field.name)
                if key in tested:
                    continue
                tested.add(key)

                finding = self._test_field(form, form_field)
                if finding is not None:
                    findings.append(finding)

        if not findings:
            findings.append(
                Finding(
                    check=self.slug,
                    title="Отражённый XSS в формах не обнаружен",
                    severity=Severity.INFO,
                    description=(
                        f"Проверено форм: {min(len(forms), self.max_forms)}, "
                        f"уникальных полей: {len(tested)}. Отражения пейлоада без "
                        "экранирования не найдено. Это не гарантирует отсутствие XSS: "
                        "проверка покрывает только простые формы без JS-навигации."
                    ),
                    url=page.url,
                )
            )
        return findings

    # ------------------------------------------------------------------ internals
    def _test_field(self, form: HtmlForm, target_field: FormField) -> Finding | None:
        token = secrets.token_hex(4)
        payload = build_payload(token)

        data = {
            item.name: (payload if item.name == target_field.name else item.value)
            for item in form.fields
            if item.name
        }

        if form.method == "POST":
            response = self.client.post(form.action, data=data, follow_redirects=True)
        else:
            response = self.client.get(form.action, params=data, follow_redirects=True)
        self.tested_requests += 1

        if not response.ok:
            return None

        context = reflection_context(response.body, payload)
        if context is None:
            if _is_encoded_reflection(response.body, f"vscan{token}"):
                return Finding(
                    check=self.slug,
                    title="Ввод отражается, но специальные символы экранируются",
                    severity=Severity.INFO,
                    description=(
                        f"Поле «{target_field.name}» отражается на странице в "
                        "экранированном виде (кавычки заменены HTML-сущностями). "
                        "Это хороший признак, однако контекст отражения стоит "
                        "проверить вручную (например, внутри JS-строк)."
                    ),
                    url=response.url,
                    evidence=_snippet(response.body, f"vscan{token}"),
                    extra={"field": target_field.name, "form_action": form.action},
                )
            return None

        severity = Severity.CRITICAL if context == "script" else Severity.HIGH
        context_note = {
            "script": "внутри блока <script>",
            "attribute": "внутри HTML-атрибута",
            "text": "в текстовом узле страницы",
        }[context]

        return Finding(
            check=self.slug,
            title=f"Возможный Reflected XSS в поле «{target_field.name}»",
            severity=severity,
            description=(
                f"Пейлоад, отправленный в поле «{target_field.name}», вернулся на "
                f"странице без экранирования ({context_note}). Символы \"'> "
                "позволяют выйти из текущего контекста и внедрить произвольную "
                "разметку — при наличии JavaScript это приводит к выполнению кода "
                "в браузере жертвы. Требуется ручная верификация."
            ),
            url=response.url,
            evidence=_snippet(response.body, payload),
            remediation=(
                "Экранируйте вывод контекстно (HTML-entities для текста и атрибутов), "
                "валидируйте вход по allowlist, включите CSP без 'unsafe-inline'. "
                "Не доверяйте параметрам URL при формировании HTML."
            ),
            extra={
                "field": target_field.name,
                "form_action": form.action,
                "form_method": form.method,
                "context": context,
            },
        )


def _snippet(body: str, needle: str, radius: int = 90) -> str:
    """Возвращает фрагмент ответа вокруг найденного маркера."""
    index = body.find(needle)
    if index == -1:
        return needle
    start = max(0, index - radius)
    end = min(len(body), index + len(needle) + radius)
    fragment = " ".join(body[start:end].split())
    return f"…{fragment}…"
