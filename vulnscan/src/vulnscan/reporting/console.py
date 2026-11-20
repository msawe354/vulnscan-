"""Формирование консольного отчёта с помощью ``rich``.

Все динамические строки (URL, заголовки, фрагменты ответов) экранируются через
``rich.markup.escape``: содержимое чужого сайта не должно интерпретироваться как
разметка rich.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnscan.models import Finding, ScanReport, Severity

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def _badge(severity: Severity) -> Text:
    """Цветной бейдж уровня критичности."""
    return Text(f" {SEVERITY_LABEL[severity]} ", style=SEVERITY_STYLE[severity])


def print_report(
    report: ScanReport,
    console: Console | None = None,
    *,
    show_details: bool = True,
    verbose: bool = False,
) -> None:
    """Печатает полный отчёт: шапка, сводка, таблица и детали находок."""
    console = console or Console()

    _print_header(report, console)
    _print_summary(report, console)

    if not report.findings:
        console.print(
            Panel(
                "[bold green]Проблем не обнаружено.[/bold green]\n"
                "Помните: это базовый сканер, а не гарантия безопасности.",
                border_style="green",
                title="Результат",
            )
        )
        return

    _print_findings_table(report, console)
    if show_details:
        _print_details(report, console, verbose=verbose)
    _print_verdict(report, console)


# ---------------------------------------------------------------------- header
def _print_header(report: ScanReport, console: Console) -> None:
    duration = report.duration_seconds
    requests = report.stats.get("requests", "—")
    body = (
        f"[bold]Цель:[/bold] {escape(report.target)}\n"
        f"[bold]Начало:[/bold] {report.started_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        f"[bold]Длительность:[/bold] {duration:.2f} c   "
        f"[bold]HTTP-запросов:[/bold] {requests}\n"
        f"[bold]Версия:[/bold] vulnscan {escape(report.tool_version)}"
    )
    console.print(
        Panel(
            body,
            title="[bold cyan]vulnscan — базовый сканер веб-уязвимостей[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


# --------------------------------------------------------------------- summary
def _print_summary(report: ScanReport, console: Console) -> None:
    counts = report.counts_by_severity()
    table = Table(title="Сводка по уровням критичности", box=box.SIMPLE_HEAVY, title_justify="left")
    table.add_column("Уровень", style="bold")
    table.add_column("Количество", justify="right")
    table.add_column("", justify="left")

    for severity in Severity:
        count = counts[severity.value]
        table.add_row(
            _badge(severity),
            str(count),
            "#" * count if count else "",
        )
    table.add_row("[bold]Всего[/bold]", f"[bold]{len(report.findings)}[/bold]", "")
    console.print(table)


# --------------------------------------------------------------------- table
def _print_findings_table(report: ScanReport, console: Console) -> None:
    table = Table(
        title="Находки",
        box=box.SIMPLE,
        show_lines=True,
        title_justify="left",
        expand=True,
    )
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Уровень", width=10)
    table.add_column("Проверка", width=14, style="magenta")
    table.add_column("Находка", overflow="fold")
    table.add_column("URL", overflow="fold", style="dim")

    for index, finding in enumerate(report.sorted_findings, start=1):
        table.add_row(
            str(index),
            _badge(finding.severity),
            escape(finding.check),
            escape(finding.title),
            escape(finding.url or "—"),
        )
    console.print(table)


# --------------------------------------------------------------------- details
def _print_details(report: ScanReport, console: Console, *, verbose: bool) -> None:
    console.print("\n[bold cyan]Детали находок[/bold cyan]")
    for index, finding in enumerate(report.sorted_findings, start=1):
        if finding.severity is Severity.INFO and not verbose:
            continue
        _print_finding(index, finding, console)


def _print_finding(index: int, finding: Finding, console: Console) -> None:
    title = Text()
    title.append(f"{index}. ", style="bold")
    title.append(f"[{SEVERITY_LABEL[finding.severity]}] ", style=SEVERITY_STYLE[finding.severity])
    title.append(finding.title, style="bold")
    console.print(title)

    if finding.url:
        console.print(f"   [dim]URL:[/dim] {escape(finding.url)}")
    console.print(f"   [bold]Риск:[/bold] {escape(finding.description)}")
    if finding.evidence:
        console.print(f"   [bold]Подтверждение:[/bold] [yellow]{escape(finding.evidence)}[/yellow]")
    if finding.remediation:
        console.print(
            f"   [bold]Как исправить:[/bold] [green]{escape(finding.remediation)}[/green]"
        )
    console.print()


# --------------------------------------------------------------------- verdict
def _print_verdict(report: ScanReport, console: Console) -> None:
    counts = report.counts_by_severity()
    critical_or_high = counts[Severity.CRITICAL.value] + counts[Severity.HIGH.value]

    if critical_or_high:
        style, message = "bold red", "Обнаружены критичные проблемы — требуется вмешательство."
    elif counts[Severity.MEDIUM.value]:
        style, message = "bold yellow", "Есть проблемы среднего уровня — запланируйте исправление."
    else:
        style, message = "bold cyan", "Критичных проблем не найдено, есть замечания."

    console.print(
        Panel(
            f"{message}\n"
            f"CRITICAL: {counts['critical']} | HIGH: {counts['high']} | "
            f"MEDIUM: {counts['medium']} | LOW: {counts['low']} | INFO: {counts['info']}",
            border_style=style.replace("bold ", ""),
            title="[bold]Итог[/bold]",
        )
    )
