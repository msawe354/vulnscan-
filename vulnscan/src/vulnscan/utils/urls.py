"""Утилиты для работы с URL: валидация и нормализация пользовательского ввода."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse, urlunparse

ALLOWED_SCHEMES = ("http", "https")


class InvalidTargetError(ValueError):
    """Целевой URL не может быть просканирован."""


def normalize_target(raw: str) -> str:
    """Нормализует и валидирует цель сканирования.

    Правила:
      * пустая строка -> ошибка;
      * схема не указана -> подставляется ``https://``;
      * разрешены только ``http`` и ``https``;
      * хост обязателен, порт (если указан) должен быть валидным;
      * фрагмент (``#...``) отбрасывается, т.к. не передаётся на сервер.

    >>> normalize_target("example.com")
    'https://example.com'
    >>> normalize_target("http://localhost:8000/app")
    'http://localhost:8000/app'
    """
    value = (raw or "").strip()
    if not value:
        raise InvalidTargetError("Целевой URL не может быть пустым")

    if "://" not in value:
        value = f"https://{value}"

    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port  # может бросить ValueError при некорректном порте
    except ValueError as exc:
        raise InvalidTargetError(f"Некорректный URL: {exc}") from exc

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidTargetError(
            f"Неподдерживаемая схема {parsed.scheme!r}. Разрешены только http и https"
        )
    if not hostname:
        raise InvalidTargetError("В URL отсутствует имя хоста")
    if port is not None and not 1 <= port <= 65535:
        raise InvalidTargetError(f"Некорректный порт: {port}")

    # Отбрасываем фрагмент, но сохраняем путь и query.
    cleaned = parsed._replace(scheme=parsed.scheme.lower(), fragment="")
    return urlunparse(cleaned)


def is_https(url: str) -> bool:
    """Проверяет, используется ли HTTPS."""
    return urlparse(url).scheme.lower() == "https"


def join_url(base: str, path: str) -> str:
    """Склеивает базовый URL и относительный путь, сохраняя префикс пути."""
    if path.startswith(("http://", "https://")):
        return path
    base_with_slash = base if base.endswith("/") else f"{base}/"
    return urljoin(base_with_slash, path.lstrip("/"))


def origin(url: str) -> tuple[str, str, int | None]:
    """Возвращает (scheme, host, port) для проверки принадлежности одному origin."""
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def same_origin(first: str, second: str) -> bool:
    """True, если оба URL принадлежат одному origin (scheme + host + port)."""
    return origin(first) == origin(second)
