"""Поиск чувствительных файлов и директорий по словарю.

Ключевая сложность таких проверок — ложные срабатывания на «мягких» 404
(soft-404), когда сервер отдаёт 200 и страницу-заглушку для любого пути.
Поэтому перед перебором снимаются baseline-ответы на заведомо несуществующие
пути, а найденные страницы сравниваются с ними по статусу и содержимому.
"""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from vulnscan.checks.base import BaseCheck
from vulnscan.http_client import HttpResult
from vulnscan.models import Finding, Severity
from vulnscan.utils.urls import join_url, same_origin

#: Пути, которые почти всегда означают утечку секретов или исходников.
HIGH_RISK_MARKERS = (
    ".git/",
    ".svn/",
    ".hg/",
    ".env",
    ".ds_store",
    "id_rsa",
    ".ssh/",
    "backup",
    ".sql",
    ".dump",
    ".bak",
    ".old",
    "config.php",
    "wp-config",
    "credentials",
    ".aws/",
    "docker-compose",
)

#: Пути, доступ к которым сам по себе не критичен, но полезен атакующему.
INFO_PATHS = ("robots.txt", "sitemap.xml", "humans.txt", "security.txt", ".well-known/")

#: Статусы, означающие «объект существует, но доступ ограничен».
PROTECTED_STATUSES = {401, 403}

#: Статусы, которые считаем успешным обнаружением.
FOUND_STATUSES = {200, 204}


@dataclass(slots=True)
class ProbeResult:
    """Сырой результат проверки одного пути."""

    path: str
    url: str
    status: int
    length: int
    location: str | None = None
    body: str = ""


def is_soft_404(result: ProbeResult, baselines: list[HttpResult]) -> bool:
    """Определяет, является ли ответ «заглушкой» вместо реального ресурса.

    Сравнивает найденный ответ с baseline-ответами на заведомо несуществующие
    пути: совпадение статуса и содержимого (или высокая степень схожести)
    означает, что сервер отдаёт одну и ту же страницу для любого URL.
    """
    for baseline in baselines:
        if baseline.status_code != result.status:
            continue
        if baseline.body.strip() == result.body.strip():
            return True
        left = baseline.body[:4000]
        right = result.body[:4000]
        if left and right and SequenceMatcher(None, left, right).quick_ratio() > 0.95:
            return True
    return False


def load_wordlist(path: str | Path | None = None) -> list[str]:
    """Читает словарь путей из файла.

    Формат: по одному пути на строку, ``#`` — комментарий, пустые строки
    игнорируются. Дубликаты удаляются с сохранением порядка.

    Если ``path`` не указан, используется встроенный словарь из пакета.
    """
    if path is None:
        from importlib.resources import files

        raw = files("vulnscan").joinpath("data/common.txt").read_text(encoding="utf-8-sig")
    else:
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Файл словаря не найден: {file_path}")
        # utf-8-sig: словари, сохранённые в Windows-редакторах, часто имеют BOM.
        raw = file_path.read_text(encoding="utf-8-sig", errors="replace")

    seen: set[str] = set()
    paths: list[str] = []
    for line in raw.splitlines():
        candidate = line.strip().lstrip("\ufeff")
        if not candidate or candidate.startswith("#"):
            continue
        candidate = candidate.lstrip("/")
        if candidate and candidate not in seen:
            seen.add(candidate)
            paths.append(candidate)
    return paths


class DirectoriesCheck(BaseCheck):
    """Перебирает пути из словаря и сообщает о доступных ресурсах."""

    slug = "directories"
    name = "Открытые файлы и директории"

    def __init__(
        self,
        client,
        *,
        paths: list[str] | None = None,
        threads: int = 10,
        max_paths: int | None = None,
    ) -> None:
        super().__init__(client)
        self.paths = paths if paths is not None else load_wordlist()
        if max_paths is not None:
            self.paths = self.paths[:max_paths]
        self.threads = max(1, threads)

    # ------------------------------------------------------------------ public
    def run(self, target: str) -> list[Finding]:
        if not self.paths:
            return [self._error_finding("Словарь путей пуст — проверка пропущена", url=target)]

        baselines = self._fetch_baselines(target)
        findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe, target, path): path for path in self.paths}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    continue
                if result is None:
                    continue
                if is_soft_404(result, baselines):
                    continue
                finding = self._build_finding(result)
                if finding is not None:
                    findings.append(finding)

        return self._deduplicate(findings)

    # ------------------------------------------------------------------ probing
    def _probe(self, target: str, path: str) -> ProbeResult | None:
        url = join_url(target, path)
        response = self.client.get(url, follow_redirects=False, max_bytes=64 * 1024)
        if not response.ok or response.status_code is None:
            return None
        return ProbeResult(
            path=path,
            url=response.url,
            status=response.status_code,
            length=len(response.body),
            location=response.header("location"),
            body=response.body,
        )

    def _fetch_baselines(self, target: str) -> list[HttpResult]:
        """Снимает ответы на несуществующие пути (похожий на файл и на папку)."""
        token = secrets.token_hex(6)
        candidates = (
            f"vulnscan-{token}.html",
            f"vulnscan-{token}/",
            f"vulnscan-{token}.php",
        )
        baselines: list[HttpResult] = []
        for candidate in candidates:
            response = self.client.get(join_url(target, candidate), follow_redirects=False)
            if response.ok:
                baselines.append(response)
        return baselines

    # ------------------------------------------------------------------ findings
    def _build_finding(self, result: ProbeResult) -> Finding | None:
        lowered = result.path.lower()

        if result.status in PROTECTED_STATUSES:
            return Finding(
                check=self.slug,
                title=f"Защищённый ресурс доступен: /{result.path}",
                severity=Severity.LOW,
                description=(
                    f"Сервер отвечает {result.status}: объект существует, но доступ "
                    "ограничен. Само по себе это не уязвимость, однако подтверждает "
                    "наличие скрытой функциональности (админка, бэкапы, API)."
                ),
                url=result.url,
                evidence=f"HTTP {result.status}",
                remediation=(
                    "Убедитесь, что ресурс действительно должен быть доступен извне. "
                    "Скрывайте служебные пути на периметре (VPN, allowlist)."
                ),
                extra={"path": result.path, "status": result.status},
            )

        if result.status in FOUND_STATUSES:
            severity = self._severity_for(lowered)
            title = f"Доступен ресурс: /{result.path}"
            description = (
                f"Ресурс /{result.path} отдаёт HTTP {result.status} и не является "
                "заглушкой soft-404. "
            )
            if severity in {Severity.CRITICAL, Severity.HIGH}:
                description += (
                    "Такие файлы часто содержат секреты, дампы БД, исходный код или "
                    "резервные копии — их наличие в открытом доступе критично."
                )
            else:
                description += (
                    "Проверьте, не раскрывает ли страница служебную информацию, "
                    "панель управления или данные пользователей."
                )

            evidence = f"HTTP {result.status}, {result.length} байт"
            if lowered.endswith("robots.txt") and result.body:
                disallow = [
                    line.strip()
                    for line in result.body.splitlines()
                    if line.strip().lower().startswith("disallow:")
                ][:5]
                if disallow:
                    evidence += " | " + "; ".join(disallow)

            return Finding(
                check=self.slug,
                title=title,
                severity=severity,
                description=description,
                url=result.url,
                evidence=evidence,
                remediation=(
                    "Закройте доступ на уровне веб-сервера (deny/return 404), "
                    "удалите файлы из webroot, храните секреты в переменных окружения "
                    "или в secret manager."
                ),
                extra={"path": result.path, "status": result.status},
            )

        if (
            result.status in {301, 302, 303, 307, 308}
            and result.location
            and not same_origin(result.url, join_url(result.url, result.location))
        ):
            return Finding(
                check=self.slug,
                title=f"Редирект на внешний хост: /{result.path}",
                severity=Severity.LOW,
                description=(
                    "Путь перенаправляет на другой домен. Если редирект управляется "
                    "параметром запроса, это может быть open redirect."
                ),
                url=result.url,
                evidence=f"HTTP {result.status} -> {result.location}",
                remediation="Разрешайте редиректы только на доверенные хосты (allowlist).",
                extra={"path": result.path, "status": result.status},
            )

        if result.status >= 500:
            return Finding(
                check=self.slug,
                title=f"Ошибка сервера на /{result.path}",
                severity=Severity.INFO,
                description=(
                    f"Сервер вернул {result.status}. Иногда так проявляются скрытые "
                    "эндпоинты; полезно проверить логи приложения."
                ),
                url=result.url,
                evidence=f"HTTP {result.status}",
                extra={"path": result.path, "status": result.status},
            )

        return None

    @staticmethod
    def _severity_for(path: str) -> Severity:
        if any(marker in path for marker in HIGH_RISK_MARKERS):
            return Severity.HIGH
        if path.endswith((".zip", ".tar", ".gz", ".rar", ".7z", ".sql")):
            return Severity.HIGH
        if any(path.startswith(prefix) for prefix in INFO_PATHS):
            return Severity.INFO
        return Severity.MEDIUM

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Убирает дубликаты по (URL, статус), сохраняя порядок."""
        seen: set[tuple[str | None, object]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.url, finding.extra.get("status"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
