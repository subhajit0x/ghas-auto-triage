"""Load optional alert → Jira / Jira finding id mapping."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_mapping(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data or not isinstance(data, dict):
        return []
    m = data.get("mappings")
    return list(m) if isinstance(m, list) else []


def find_row(
    mappings: list[dict[str, Any]],
    kind: str,
    number: int,
) -> dict[str, Any] | None:
    for row in mappings:
        if str(row.get("kind", "")).lower() == kind.lower() and int(row.get("number", -1)) == number:
            return row
    return None
