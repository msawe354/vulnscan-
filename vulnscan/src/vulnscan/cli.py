"""CLI-интерфейс сканера.

Коды возврата:
  * ``0`` — сканирование завершено, находок уровня ``--fail-on`` и выше нет;
  * ``1`` — ошибка запуска (некорректный URL, недоступный словарь, сбой);
  * ``2`` — найдены проблемы уровня ``--fail-on`` и выше (удобно для CI).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from vulnscan import __version__
from vulnscan.checks import DirectoriesCheck, HeadersCheck, XssCheck
from vulnscan.checks.base import BaseCheck
from vulnscan.checks.directories import load_wordlist
from vulnscan.http_client import DEFAULT_USER_AGENT, HttpClient
from vulnscan.models import Finding, ScanReport, Severity
from vulnscan.reporting import print_report, write_json_report
from vulnscan.utils.urls import InvalidTargetError, normalize_target

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Базовый сканер веб-уязвимостей: заголовки, открытые пути, Reflected XSS.",
)

console = Console()

ETHICS_NOTICE = (
    "Инструмент предназначен только для аудита [bold]собственных[/bold] ресурсов "
    "или ресурсов, на которые есть письменное разрешение."
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vulnscan {__version__}")
        raise typer.Exit(code=0)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Целевой URL, например https://example.com"),
    json_out: Path | None = typer.Option(
        None, "--json", "-j", help="Сохранить отчёт в JSON-файл", show_default=False
    ),
    wordlist: Path | None = typer.Option(
        None, "--wordlist", "-w", help="Свой словарь путей (по умолчанию встроенный)"
    ),
    timeout: float = typer.Option(10.0, "--timeout", "-t", min=1.0, max=120.0, help="Таймаут, сек"),
    threads: int = typer.Option(10, "--threads", min=1, max=50, help="Потоков для перебора путей"),
    delay: float = typer.Option(
        0.0, "--delay", min=0.0, max=10.0, help="Пауза между запросами, сек (вежливый режим)"
    ),
    max_paths: int | None = typer.Option(
        None, "--max-paths", min=1, help="Ограничить число проверяемых путей"
    ),
    max_forms: int = typer.Option(10, "--max-forms", min=1, max=100, help="Максимум форм для XSS"),
    no_xss: bool = typer.Option(False, "--no-xss", help="Пропустить проверку форм на XSS"),
    no_directories: bool = typer.Option(False, "--no-directories", help="Пропустить перебор путей"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Не проверять TLS-сертификат"),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Прокси, например http://127.0.0.1:8080"
    ),
    user_agent: str = typer.Option(DEFAULT_USER_AGENT, "--user-agent", help="Свой User-Agent"),
    fail_on: Severity = typer.Option(
        Severity.HIGH, "--fail-on", case_sensitive=False, help="Порог для exit code 2"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Показывать детали INFO-находок"),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Показать версию"
    ),
) -> None:
    """Запускает сканирование указанного URL и печатает отчёт."""
    del version  # обрабатывается в callback

    console.print(
        Panel(ETHICS_NOTICE, title="[bold yellow]Этика[/bold yellow]", border_style="yellow")
    )

    try:
        normalized = normalize_target(target)
    except InvalidTargetError as exc:
        console.print(f"[bold red]Ошибка:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc

    paths: list[str] | None = None
    if not no_directories:
        try:
            paths = load_wordlist(wordlist)
        except (FileNotFoundError, OSError) as exc:
            console.print(f"[bold red]Ошибка словаря:[/bold red] {escape(str(exc))}")
            raise typer.Exit(code=1) from exc
        if max_paths is not None:
            paths = paths[:max_paths]

    report = ScanReport(
        target=normalized,
        started_at=datetime.now(timezone.utc),
        tool_version=__version__,
    )

    client = HttpClient(
        timeout=timeout,
        user_agent=user_agent,
        verify_tls=not insecure,
        delay=delay,
        proxy=proxy,
    )

    try:
        _preflight(client, normalized)
        _run_checks(
            client=client,
            report=report,
            paths=paths,
            threads=threads,
            max_forms=max_forms,
            with_xss=not no_xss,
            with_directories=not no_directories,
            verbose=verbose,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Сканирование прервано пользователем.[/yellow]")
        raise typer.Exit(code=130) from None
    finally:
        client.close()

    report.finish()
    report.stats["requests"] = client.request_count

    print_report(report, console, show_details=True, verbose=verbose)

    if json_out is not None:
        try:
            written = write_json_report(report, json_out)
        except OSError as exc:
            console.print(f"[bold red]Не удалось сохранить JSON:[/bold red] {escape(str(exc))}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]JSON-отчёт сохранён:[/green] {escape(str(written))}")

    if report.has_at_least(fail_on):
        raise typer.Exit(code=2)


def _preflight(client: HttpClient, target: str) -> None:
    """Проверяет доступность цели до запуска проверок.

    Отдельный запрос нужен, чтобы отличить «сайт недоступен» (код 1 и понятное
    сообщение) от «сайт доступен, но проблем не найдено» (код 0).
    """
    with console.status("[cyan]Проверка доступности цели…[/cyan]", spinner="dots"):
        probe = client.get(target, follow_redirects=True)

    if probe.ok:
        return

    hint = ""
    if "таймаут" in (probe.error or ""):
        hint = " Увеличьте --timeout или проверьте доступность хоста."
    elif "SSL" in (probe.error or "") or "certificate" in (probe.error or "").lower():
        hint = " Для самоподписанного сертификата используйте --insecure."

    console.print(
        Panel(
            f"Не удалось подключиться к [bold]{escape(target)}[/bold]\n"
            f"Причина: {escape(probe.error or 'неизвестная ошибка')}\n"
            f"{escape(hint)}",
            title="[bold red]Цель недоступна[/bold red]",
            border_style="red",
        )
    )
    raise typer.Exit(code=1)


def _run_checks(
    *,
    client: HttpClient,
    report: ScanReport,
    paths: list[str] | None,
    threads: int,
    max_forms: int,
    with_xss: bool,
    with_directories: bool,
    verbose: bool,
) -> None:
    """Последовательно запускает проверки, изолируя сбои каждой из них."""
    checks: list[BaseCheck] = [HeadersCheck(client)]

    directories_check: DirectoriesCheck | None = None
    if with_directories and paths is not None:
        directories_check = DirectoriesCheck(client, paths=paths, threads=threads)
        checks.append(directories_check)

    xss_check: XssCheck | None = None
    if with_xss:
        xss_check = XssCheck(client, max_forms=max_forms)
        checks.append(xss_check)

    for check in checks:
        with console.status(f"[cyan]{check.name}…[/cyan]", spinner="dots"):
            try:
                findings = check.run(report.target)
            except Exception as exc:
                findings = [
                    Finding(
                        check=check.slug,
                        title=f"Внутренняя ошибка проверки «{check.name}»",
                        severity=Severity.INFO,
                        description=f"{type(exc).__name__}: {exc}",
                        url=report.target,
                    )
                ]
        report.add(*findings)
        console.print(f"  [green]OK[/green] {check.name}: находок {len(findings)}")
        if verbose:
            for finding in findings:
                console.print(f"    [dim]- {escape(finding.title)}[/dim]")

    report.stats["checks"] = [check.slug for check in checks]
    if directories_check is not None:
        report.stats["paths_checked"] = len(directories_check.paths)
    if xss_check is not None:
        report.stats["xss_requests"] = xss_check.tested_requests
        report.stats["xss_skipped_forms"] = xss_check.skipped_forms


if __name__ == "__main__":  # pragma: no cover
    app()
