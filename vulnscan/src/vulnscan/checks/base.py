"""Базовые абстракции для проверок (checks)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vulnscan.http_client import HttpClient
from vulnscan.models import Finding, Severity


class BaseCheck(ABC):
    """Контракт проверки: получить клиент — вернуть список находок.

    Проверка не должна бросать исключения наружу: любая внутренняя ошибка
    превращается в ``Finding`` уровня INFO с описанием проблемы, чтобы один
    сломанный модуль не обнулял весь отчёт.
    """

    #: Машинное имя проверки (попадает в JSON).
    slug: str = "base"
    #: Человекочитаемое имя для консоли.
    name: str = "Базовая проверка"

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    @abstractmethod
    def run(self, target: str) -> list[Finding]:
        """Выполняет проверку и возвращает находки."""

    # ------------------------------------------------------------------ helpers
    def _error_finding(self, message: str, *, url: str | None = None) -> Finding:
        """Формирует находку о невозможности выполнить проверку."""
        return Finding(
            check=self.slug,
            title=f"Проверка «{self.name}» не выполнена",
            severity=Severity.INFO,
            description=message,
            url=url,
        )
