"""Сохранение отчёта в JSON."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.models import ScanReport


def write_json_report(report: ScanReport, destination: str | Path) -> Path:
    """Сериализует отчёт в JSON-файл (UTF-8, с отступами).

    Родительские каталоги создаются автоматически.

    Returns:
        Путь к записанному файлу.
    """
    path = Path(destination).expanduser()
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    payload = report.to_dict()
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
