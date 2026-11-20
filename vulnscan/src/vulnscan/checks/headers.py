"""Проверка HTTP-заголовков безопасности.

Модуль полностью отделён от сетевого слоя: функция :func:`analyze_headers`
принимает обычный словарь заголовков, поэтому её легко покрыть unit-тестами
без реального HTTP.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from vulnscan.checks.base import BaseCheck
from vulnscan.models import Finding, Severity
from vulnscan.utils.urls import is_https

HSTS_MIN_MAX_AGE = 15_552_000  # 180 дней — рекомендуемый минимум
_MAX_EVIDENCE = 200

HSTS_PATTERN = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

#: Заголовки, которые выдают версии ПО и облегчают фингерпринтинг.
FINGERPRINT_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")


def _short(value: str, limit: int = _MAX_EVIDENCE) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else f"{value[:limit]}…"


def analyze_headers(headers: Mapping[str, str], url: str) -> list[Finding]:
    """Анализирует заголовки ответа и возвращает находки.

    Args:
        headers: Заголовки ответа (регистр ключей не важен).
        url: URL, к которому относится ответ.

    Returns:
        Список находок. Пустой список означает, что все проверяемые
        заголовки настроены корректно.
    """
    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    findings: list[Finding] = []
    csp = normalized.get("content-security-policy")
    csp_lower = (csp or "").lower()

    # ------------------------------------------------------------ CSP
    if csp is None:
        findings.append(
            Finding(
                check="headers",
                title="Отсутствует Content-Security-Policy (CSP)",
                severity=Severity.MEDIUM,
                description=(
                    "CSP не задан, поэтому браузер не ограничивает источники скриптов, "
                    "стилей и фреймов. Любая инъекция HTML/JS (XSS, внедрение через "
                    "сторонние виджеты) выполнится в контексте сайта и получит доступ "
                    "к cookie и DOM."
                ),
                url=url,
                remediation=(
                    "Добавьте заголовок, например: "
                    "Content-Security-Policy: default-src 'self'; "
                    "script-src 'self'; object-src 'none'; base-uri 'self'; "
                    "frame-ancestors 'none'. Начинайте с режима Report-Only, чтобы "
                    "не сломать существующую функциональность."
                ),
            )
        )
    elif "unsafe-inline" in csp_lower:
        findings.append(
            Finding(
                check="headers",
                title="CSP разрешает 'unsafe-inline'",
                severity=Severity.LOW,
                description=(
                    "Директива 'unsafe-inline' сводит защиту CSP от XSS к минимуму: "
                    "инлайн-скрипты и обработчики событий снова выполняются."
                ),
                url=url,
                evidence=_short(csp),
                remediation=(
                    "Уберите 'unsafe-inline' из script-src/style-src. Используйте "
                    "nonce или hash для легитимных инлайн-скриптов."
                ),
            )
        )

    # ------------------------------------------------------------ HSTS
    if is_https(url):
        hsts = normalized.get("strict-transport-security")
        if hsts is None:
            findings.append(
                Finding(
                    check="headers",
                    title="Отсутствует Strict-Transport-Security (HSTS)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Без HSTS браузер не запоминает требование использовать HTTPS. "
                        "Пользователь, впервые открывший сайт по http:// или попавший на "
                        "подменённый ответ, уязвим к SSL-stripping и краже сессии."
                    ),
                    url=url,
                    remediation=(
                        "Добавьте: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains. Включайте includeSubDomains только после "
                        "проверки, что все поддомены работают по HTTPS."
                    ),
                )
            )
        else:
            match = HSTS_PATTERN.search(hsts)
            max_age = int(match.group(1)) if match else 0
            if max_age < HSTS_MIN_MAX_AGE:
                findings.append(
                    Finding(
                        check="headers",
                        title="Слишком короткий max-age в HSTS",
                        severity=Severity.LOW,
                        description=(
                            f"max-age={max_age} меньше рекомендуемых 180 дней "
                            f"({HSTS_MIN_MAX_AGE} секунд): защита действует слишком "
                            "короткое время и легко «перебивается» при атаке."
                        ),
                        url=url,
                        evidence=_short(hsts),
                        remediation="Увеличьте max-age минимум до 15552000, лучше — до 31536000.",
                    )
                )
            if "includesubdomains" not in hsts.lower():
                findings.append(
                    Finding(
                        check="headers",
                        title="HSTS не покрывает поддомены",
                        severity=Severity.INFO,
                        description=(
                            "Без директивы includeSubDomains поддомены можно "
                            "использовать для downgrade-атак на основную сессию."
                        ),
                        url=url,
                        evidence=_short(hsts),
                        remediation="Добавьте includeSubDomains после проверки всех поддоменов.",
                    )
                )
    else:
        findings.append(
            Finding(
                check="headers",
                title="Соединение установлено по HTTP без шифрования",
                severity=Severity.HIGH,
                description=(
                    "Трафик передаётся открытым текстом: логины, cookie и содержимое "
                    "страниц могут быть перехвачены или изменены в сети (MITM). "
                    "HSTS в таком режиме не защищает, так как заголовок тоже "
                    "передаётся по HTTP."
                ),
                url=url,
                remediation=(
                    "Настройте HTTPS с валидным сертификатом и редирект с http:// на "
                    "https:// (301), затем включите HSTS."
                ),
            )
        )

    # ------------------------------------------------------------ X-Frame-Options
    xfo = normalized.get("x-frame-options")
    csp_has_frame_ancestors = "frame-ancestors" in csp_lower
    if xfo is None:
        if not csp_has_frame_ancestors:
            findings.append(
                Finding(
                    check="headers",
                    title="Отсутствует X-Frame-Options",
                    severity=Severity.MEDIUM,
                    description=(
                        "Страницу можно встроить в iframe на чужом сайте и невидимо "
                        "наложить на неё элементы управления — классический clickjacking "
                        "(кража кликов, подтверждение действий от имени пользователя)."
                    ),
                    url=url,
                    remediation=(
                        "Добавьте X-Frame-Options: DENY (или SAMEORIGIN, если фреймы "
                        "нужны) либо директиву CSP frame-ancestors 'none'."
                    ),
                )
            )
    else:
        value = xfo.split(",")[0].strip().lower()
        if value not in {"deny", "sameorigin"}:
            findings.append(
                Finding(
                    check="headers",
                    title="Некорректное значение X-Frame-Options",
                    severity=Severity.LOW,
                    description=(
                        f"Значение {xfo!r} не поддерживается современными браузерами "
                        "(ALLOW-FROM устарел). Защита от clickjacking фактически "
                        "отсутствует."
                    ),
                    url=url,
                    evidence=_short(xfo),
                    remediation="Используйте DENY или SAMEORIGIN, либо CSP frame-ancestors.",
                )
            )

    # ------------------------------------------------------------ X-Content-Type-Options
    xcto = normalized.get("x-content-type-options")
    if xcto is None:
        findings.append(
            Finding(
                check="headers",
                title="Отсутствует X-Content-Type-Options",
                severity=Severity.LOW,
                description=(
                    "Браузер может «угадать» MIME-тип (MIME sniffing) и исполнить "
                    "загруженный файл как HTML/JS, даже если сервер отдал его как "
                    "text/plain или изображение."
                ),
                url=url,
                remediation="Добавьте X-Content-Type-Options: nosniff ко всем ответам.",
            )
        )
    elif xcto.lower() != "nosniff":
        findings.append(
            Finding(
                check="headers",
                title="Некорректное значение X-Content-Type-Options",
                severity=Severity.LOW,
                description=(
                    f"Ожидалось 'nosniff', получено {xcto!r}: защита от MIME sniffing не работает."
                ),
                url=url,
                evidence=_short(xcto),
                remediation="Установите X-Content-Type-Options: nosniff.",
            )
        )

    # ------------------------------------------------------------ Referrer-Policy
    if "referrer-policy" not in normalized:
        findings.append(
            Finding(
                check="headers",
                title="Отсутствует Referrer-Policy",
                severity=Severity.LOW,
                description=(
                    "Полный URL страницы (включая чувствительные параметры и пути "
                    "админки) может утекать во внешние ресурсы через заголовок Referer."
                ),
                url=url,
                remediation="Добавьте Referrer-Policy: strict-origin-when-cross-origin.",
            )
        )

    # ------------------------------------------------------------ Permissions-Policy
    if "permissions-policy" not in normalized:
        findings.append(
            Finding(
                check="headers",
                title="Отсутствует Permissions-Policy",
                severity=Severity.INFO,
                description=(
                    "Мощные API браузера (камера, микрофон, геолокация) доступны "
                    "встроенным фреймам и сторонним скриптам без явного ограничения."
                ),
                url=url,
                remediation=(
                    "Добавьте Permissions-Policy, например: "
                    "geolocation=(), microphone=(), camera=()."
                ),
            )
        )

    # ------------------------------------------------------------ Утечка версий ПО
    leaked = {name: normalized[name] for name in FINGERPRINT_HEADERS if normalized.get(name)}
    if leaked:
        details = "; ".join(f"{name}: {_short(value, 80)}" for name, value in leaked.items())
        findings.append(
            Finding(
                check="headers",
                title="Заголовки раскрывают версии ПО",
                severity=Severity.INFO,
                description=(
                    "Сервер сообщает технологический стек и версии. Это упрощает "
                    "подбор эксплойтов под известные уязвимости (CVE)."
                ),
                url=url,
                evidence=details,
                remediation=(
                    "Уберите или обезличьте заголовки Server / X-Powered-By на уровне "
                    "веб-сервера и приложения."
                ),
            )
        )

    # Cookie-флаги проверяются отдельно в HeadersCheck: в Mapping они уже схлопнуты.
    return findings


def _analyze_cookies(set_cookies: list[str] | None, url: str) -> list[Finding]:
    """Проверяет флаги Secure/HttpOnly/SameSite у Set-Cookie (если переданы)."""
    findings: list[Finding] = []
    https = is_https(url)

    for raw in set_cookies or []:
        name = raw.split("=", 1)[0].strip() or "<без имени>"
        lowered = raw.lower()
        problems: list[str] = []

        if https and "secure" not in lowered:
            problems.append("нет Secure")
        if "httponly" not in lowered:
            problems.append("нет HttpOnly")
        if "samesite" not in lowered:
            problems.append("нет SameSite")

        if problems:
            findings.append(
                Finding(
                    check="headers",
                    title=f"Небезопасные атрибуты cookie «{name}»",
                    severity=Severity.LOW,
                    description=(
                        "Cookie без защитных флагов (" + ", ".join(problems) + ") "
                        "может быть прочитана из JavaScript при XSS, отправлена по "
                        "HTTP или приложена к межсайтовому запросу (CSRF)."
                    ),
                    url=url,
                    evidence=_short(raw),
                    remediation=(
                        "Установите Secure; HttpOnly; SameSite=Lax (или Strict) для "
                        "сессионных cookie."
                    ),
                )
            )
    return findings


class HeadersCheck(BaseCheck):
    """Скачивает главную страницу и анализирует заголовки ответа."""

    slug = "headers"
    name = "HTTP-заголовки безопасности"

    def run(self, target: str) -> list[Finding]:
        response = self.client.get(target, follow_redirects=True)
        if not response.ok:
            return [
                self._error_finding(
                    f"Не удалось получить ответ от {target}: {response.error}", url=target
                )
            ]

        findings = analyze_headers(response.headers, response.url)
        findings.extend(_analyze_cookies(response.set_cookies, response.url))

        if response.redirect_chain:
            findings.append(
                Finding(
                    check=self.slug,
                    title="Обнаружена цепочка редиректов",
                    severity=Severity.INFO,
                    description=(
                        "Итоговый URL отличается от запрошенного. Убедитесь, что "
                        "редиректы ведут только на доверенные хосты."
                    ),
                    url=response.url,
                    evidence=" -> ".join([*response.redirect_chain, response.url]),
                )
            )
        return findings
