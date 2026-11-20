"""Доменные модели сканера.

Модуль намеренно не зависит от `httpx`, `rich` и прочих библиотек: это чистые
структуры данных, которые легко тестировать и сериализовать.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Уровень критичности находки.

    Наследование от ``str`` позволяет без проблем сериализовать значение в JSON.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Числовой вес для сортировки: чем меньше, тем критичнее."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """Разбирает строку уровня (регистронезависимо)."""
        try:
            return cls(name.strip().lower())
        except ValueError as exc:
            raise ValueError(f"Неизвестный уровень критичности: {name!r}") from exc


# Порядок важен: используется и для сортировки, и для фильтра --fail-on.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(slots=True)
class Finding:
    """Одна обнаруженная проблема."""

    check: str
    """Машинное имя проверки, например ``headers`` или ``xss``."""

    title: str
    """Короткое человекочитаемое название находки."""

    severity: Severity
    description: str
    """Что именно обнаружено и как это эксплуатируется."""

    url: str | None = None
    evidence: str | None = None
    """Фрагмент ответа/заголовка, подтверждающий находку (обрезается)."""

    remediation: str | None = None
    """Как исправить."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Произвольные дополнительные данные (например, имя формы или поля)."""

    def to_dict(self) -> dict[str, Any]:
        """Приводит находку к JSON-совместимому словарю."""
        data: dict[str, Any] = {
            "check": self.check,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
        }
        if self.url:
            data["url"] = self.url
        if self.evidence:
            data["evidence"] = self.evidence
        if self.remediation:
            data["remediation"] = self.remediation
        if self.extra:
            data["extra"] = self.extra
        return data


@dataclass(slots=True)
class ScanReport:
    """Результат полного сканирования."""

    target: str
    started_at: datetime
    finished_at: datetime | None = None
    tool_version: str = "1.0.0"
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ helpers
    def add(self, *findings: Finding) -> None:
        """Добавляет одну или несколько находок."""
        self.findings.extend(findings)

    def finish(self) -> None:
        """Фиксирует время окончания сканирования."""
        self.finished_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return max(0.0, (end - self.started_at).total_seconds())

    @property
    def sorted_findings(self) -> list[Finding]:
        """Находки от самых критичных к информационным (стабильная сортировка)."""
        return sorted(self.findings, key=lambda item: item.severity.rank)

    def counts_by_severity(self) -> dict[str, int]:
        """Счётчик находок по уровням (включая нулевые значения)."""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def has_at_least(self, severity: Severity) -> bool:
        """True, если есть хотя бы одна находка не ниже указанного уровня."""
        return any(item.severity.rank <= severity.rank for item in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Полное представление отчёта для JSON-файла."""
        return {
            "tool": {"name": "vulnscan", "version": self.tool_version},
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at or datetime.now(timezone.utc)).isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts_by_severity(),
            },
            "stats": self.stats,
            "findings": [finding.to_dict() for finding in self.sorted_findings],
        }
