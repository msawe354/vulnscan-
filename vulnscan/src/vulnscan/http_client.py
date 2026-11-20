"""Обёртка над ``httpx.Client``.

Задачи модуля:
  * единая точка настройки таймаутов, User-Agent, TLS-проверки и задержек;
  * никогда не «ронять» сканер из-за сетевой ошибки — вместо исключения
    возвращается :class:`HttpResult` с заполненным ``error``;
  * ограничение объёма читаемого тела ответа (защита от гигантских страниц);
  * учёт количества запросов для статистики отчёта.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_USER_AGENT = "vulnscan/1.0 (+educational-security-scanner)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 512 * 1024  # 512 KiB — достаточно для анализа HTML


@dataclass(slots=True)
class HttpResult:
    """Результат одного HTTP-запроса в «плоском» виде."""

    url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    truncated: bool = False
    set_cookies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Запрос завершился без сетевой ошибки и есть статус-код."""
        return self.error is None and self.status_code is not None

    def header(self, name: str, default: str | None = None) -> str | None:
        """Регистронезависимый доступ к заголовку ответа."""
        return self.headers.get(name.lower(), default)


class HttpClient:
    """Тонкая синхронная обёртка над httpx с ретраями и вежливой задержкой."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = True,
        delay: float = 0.0,
        retries: int = 1,
        proxy: str | None = None,
        max_bytes: int | None = DEFAULT_MAX_BYTES,
    ) -> None:
        self._max_bytes = max_bytes
        self._delay = max(0.0, delay)
        self._retries = max(0, retries)
        self.request_count = 0

        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout),
            "verify": verify_tls,
            "follow_redirects": False,
            "headers": {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8",
                "Connection": "close",
            },
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        self._client = httpx.Client(**client_kwargs)

    # ------------------------------------------------------------------ context
    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Закрывает пул соединений."""
        self._client.close()

    # ------------------------------------------------------------------ requests
    def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool = False,
        max_bytes: int | None = None,
        **kwargs: Any,
    ) -> HttpResult:
        """Выполняет запрос и возвращает :class:`HttpResult`.

        Сетевые ошибки (таймаут, DNS, TLS, обрыв соединения) перехватываются и
        попадают в ``HttpResult.error`` — вызывающий код не обязан использовать
        try/except.
        """
        started = time.perf_counter()
        last_error: str | None = None

        for attempt in range(self._retries + 1):
            try:
                result = self._send(
                    method,
                    url,
                    follow_redirects=follow_redirects,
                    max_bytes=self._max_bytes if max_bytes is None else max_bytes,
                    **kwargs,
                )
                result.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                self._sleep_between_requests()
                return result
            except httpx.TimeoutException:
                last_error = f"таймаут запроса ({self._client.timeout.connect}s)"
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            except Exception as exc:
                last_error = f"непредвиденная ошибка: {type(exc).__name__}: {exc}"

            if attempt < self._retries:
                time.sleep(0.4 * (attempt + 1))

        elapsed = round((time.perf_counter() - started) * 1000, 2)
        self._sleep_between_requests()
        return HttpResult(url=url, elapsed_ms=elapsed, error=last_error or "неизвестная ошибка")

    def get(self, url: str, **kwargs: Any) -> HttpResult:
        """GET-запрос."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResult:
        """POST-запрос."""
        return self.request("POST", url, **kwargs)

    # ------------------------------------------------------------------ internals
    def _send(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool,
        max_bytes: int | None,
        **kwargs: Any,
    ) -> HttpResult:
        request = self._client.build_request(method, url, **kwargs)
        self.request_count += 1

        response = self._client.send(request, stream=True, follow_redirects=follow_redirects)
        try:
            body, truncated = self._read_body(response, max_bytes)
            headers = {key.lower(): value for key, value in response.headers.items()}
            return HttpResult(
                url=str(response.url),
                status_code=response.status_code,
                headers=headers,
                body=body,
                truncated=truncated,
                redirect_chain=[str(item.url) for item in response.history],
                set_cookies=response.headers.get_list("set-cookie"),
            )
        finally:
            response.close()

    @staticmethod
    def _read_body(response: httpx.Response, max_bytes: int | None) -> tuple[str, bool]:
        """Читает тело ответа, обрезая его до ``max_bytes`` байт."""
        chunks: list[bytes] = []
        total = 0
        truncated = False

        for chunk in response.iter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if max_bytes is not None and total >= max_bytes:
                truncated = True
                break

        raw = b"".join(chunks)
        encoding = response.encoding or "utf-8"
        try:
            text = raw.decode(encoding, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        return text, truncated

    def _sleep_between_requests(self) -> None:
        if self._delay > 0:
            time.sleep(self._delay)
