"""Global Memory: cross-repo CVE consensus from triage_history.jsonl.

The global memory is the bot's institutional knowledge. When the same package
or CVE was triaged previously across other repos, that consensus must inform
the current verdict so the bot does not contradict itself across the org.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghas_llm.integrations.memory_store import TriageMemoryStore


@dataclass
class GlobalMemorySnapshot:
    package: str = ""
    cve_id: str = ""
    repos_seen: list[str] = field(default_factory=list)
    routing_counts: dict[str, int] = field(default_factory=dict)
    examples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def consensus_routing(self) -> str:
        if not self.routing_counts:
            return ""
        sorted_routes = sorted(
            self.routing_counts.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )
        top, top_count = sorted_routes[0]
        total = sum(self.routing_counts.values())
        if total >= 3 and top_count / max(1, total) >= 0.6:
            return top
        return ""

    @property
    def consensus_strength(self) -> int:
        return sum(self.routing_counts.values())


class GlobalMemory:
    name = "global_memory"

    def __init__(
        self,
        repo_root: Path,
        history_rel: str,
        store: TriageMemoryStore | None = None,
    ) -> None:
        self.path = (repo_root / history_rel).resolve() if history_rel else None
        self.store = store

    def _load_rows(self, limit: int = 2000) -> list[dict[str, Any]]:
        if self.store is not None:
            return self.store.load_history_rows(limit)
        if not self.path or not self.path.is_file():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            return []
        rows: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def query(
        self,
        *,
        package: str,
        cve_id: str,
        max_examples: int = 5,
        current_repo: str = "",
    ) -> GlobalMemorySnapshot:
        snap = GlobalMemorySnapshot(package=package, cve_id=cve_id)
        seen_repos: set[str] = set()
        examples: list[dict[str, Any]] = []
        for row in self._load_rows(2000):
            if not isinstance(row, dict):
                continue
            row_repo = str(row.get("repository", "") or "")
            if current_repo and row_repo == current_repo:
                continue
            row_pkg = str(row.get("package", "") or "")
            row_cve = str(row.get("cve_id", "") or "")
            if package and row_pkg.lower() != package.lower():
                if cve_id and row_cve.lower() != cve_id.lower():
                    continue
            elif cve_id and row_cve.lower() != cve_id.lower():
                if package and row_pkg.lower() != package.lower():
                    continue
            routing = str(row.get("routing", "") or "")
            if not routing:
                continue
            snap.routing_counts[routing] = snap.routing_counts.get(routing, 0) + 1
            if row_repo and row_repo not in seen_repos:
                seen_repos.add(row_repo)
                snap.repos_seen.append(row_repo)
            if len(examples) < max_examples:
                examples.append(
                    {
                        "jira_key": row.get("jira_key", ""),
                        "repository": row_repo,
                        "routing": routing,
                        "tier": row.get("tier", ""),
                        "package": row_pkg,
                        "cve_id": row_cve,
                    },
                )
        snap.examples = examples
        return snap


def format_global_memory(snap: GlobalMemorySnapshot) -> str:
    if not snap.routing_counts:
        return "Global memory: no prior org-wide history for this package/CVE.\n"
    counts = ", ".join(f"{k}={v}" for k, v in sorted(snap.routing_counts.items()))
    consensus = snap.consensus_routing or "no clear consensus"
    lines = [
        f"Global memory for {snap.package or snap.cve_id}: "
        f"{snap.consensus_strength} prior triages across "
        f"{len(snap.repos_seen)} repos ({counts}); consensus={consensus}.",
    ]
    for ex in snap.examples[:5]:
        lines.append(
            f"- {ex.get('jira_key', '?')} {ex.get('repository', '')}: "
            f"routing={ex.get('routing', '')} tier={ex.get('tier', '')}",
        )
    return "\n".join(lines) + "\n"
