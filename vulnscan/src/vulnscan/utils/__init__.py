"""Вспомогательные утилиты пакета ``vulnscan``."""

from vulnscan.utils.urls import (
    InvalidTargetError,
    is_https,
    join_url,
    normalize_target,
    origin,
    same_origin,
)

__all__ = [
    "InvalidTargetError",
    "is_https",
    "join_url",
    "normalize_target",
    "origin",
    "same_origin",
]
