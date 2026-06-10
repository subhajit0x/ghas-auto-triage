"""JSONL triage history + human feedback on disk (committed on branch by CI)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class TriageMemoryStore:
    """Append-only JSONL files under the repo root (persisted via git on main)."""

    def __init__(
        self,
        *,
        repo_root: Path,
        history_rel: str,
        feedback_rel: str,
        max_history_lines: int = 15_000,
        max_feedback_lines: int = 3_000,
    ) -> None:
        self.repo_root = repo_root
        self.history_path = (repo_root / history_rel).resolve() if history_rel else None
        self.feedback_path = (repo_root / feedback_rel).resolve() if feedback_rel else None
        self.max_history_lines = max(1, max_history_lines)
        self.max_feedback_lines = max(1, max_feedback_lines)

    @classmethod
    def from_config(cls, config: dict[str, Any], repo_root: Path) -> TriageMemoryStore:
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        ms_cfg = config.get("memory_store", {}) if isinstance(config.get("memory_store", {}), dict) else {}
        history_rel = str(agent_cfg.get("triage_history_file", ".triage_history.jsonl")).strip()
        feedback_rel = str(agent_cfg.get("human_feedback_file", ".human_feedback.jsonl")).strip()
        return cls(
            repo_root=repo_root,
            history_rel=history_rel,
            feedback_rel=feedback_rel,
            max_history_lines=int(ms_cfg.get("max_history_lines", 15_000)),
            max_feedback_lines=int(ms_cfg.get("max_feedback_lines", 3_000)),
        )

    @staticmethod
    def _append_jsonl(path: Path | None, row: dict[str, Any]) -> None:
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, default=str) + "\n")
        except OSError as exc:
            log.warning("memory jsonl append %s: %s", path, exc)

    @staticmethod
    def _load_jsonl(path: Path | None, tail: int) -> list[dict[str, Any]]:
        if path is None or not path.is_file():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[-tail:]
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                out.append(row)
        return out

    @staticmethod
    def _trim_file(path: Path | None, max_lines: int) -> int:
        """Keep the newest max_lines rows; return final line count."""
        if path is None or not path.is_file():
            return 0
        try:
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except OSError:
            return 0
        if len(lines) <= max_lines:
            return len(lines)
        kept = lines[-max_lines:]
        try:
            path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        except OSError as exc:
            log.warning("memory jsonl trim %s: %s", path, exc)
            return len(lines)
        return len(kept)

    def append_history(self, row: dict[str, Any]) -> None:
        self._append_jsonl(self.history_path, row)

    def load_history_rows(self, limit: int = 2000) -> list[dict[str, Any]]:
        return self._load_jsonl(self.history_path, limit)

    def append_feedback(self, row: dict[str, Any]) -> None:
        self._append_jsonl(self.feedback_path, row)

    def load_feedback_rows(self, limit: int = 500) -> list[dict[str, Any]]:
        return self._load_jsonl(self.feedback_path, limit)

    def trim_to_limits(self) -> dict[str, int]:
        """Cap file size before git commit."""
        return {
            "history_lines": self._trim_file(self.history_path, self.max_history_lines),
            "feedback_lines": self._trim_file(self.feedback_path, self.max_feedback_lines),
        }

    def stats(self) -> dict[str, int]:
        return {
            "history_lines": len(self._load_jsonl(self.history_path, self.max_history_lines + 1)),
            "feedback_lines": len(self._load_jsonl(self.feedback_path, self.max_feedback_lines + 1)),
        }
