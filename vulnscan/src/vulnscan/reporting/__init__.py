"""Модули вывода отчётов."""

from vulnscan.reporting.console import print_report
from vulnscan.reporting.json_report import write_json_report

__all__ = ["print_report", "write_json_report"]
