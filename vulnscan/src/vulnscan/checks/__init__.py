"""Проверки сканера."""

from vulnscan.checks.directories import DirectoriesCheck
from vulnscan.checks.headers import HeadersCheck
from vulnscan.checks.xss import XssCheck

__all__ = ["DirectoriesCheck", "HeadersCheck", "XssCheck"]
