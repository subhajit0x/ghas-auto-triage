"""Local dedup so we do not re-apply Jira/Jira updates every run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Set


def load_processed(path: Path) -> Set[str]:
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(data, list):
        return {str(x) for x in data}
    if isinstance(data, dict) and "keys" in data:
        return {str(x) for x in data["keys"]}
    return set()


def save_processed(path: Path, keys: Set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(keys), indent=2), encoding="utf-8")


def key_for(kind: str, number: int) -> str:
    return f"{kind}:{number}"
