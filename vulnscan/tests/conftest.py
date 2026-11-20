"""Общие настройки тестов.

Тесты не ходят в интернет: проверки принимают либо обычный словарь заголовков,
либо фейковый клиент с интерфейсом ``HttpClient``.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
