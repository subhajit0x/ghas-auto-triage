"""Human feedback worker.

Learns from comments humans leave after the bot. This is intentionally
regex-first; no LLM is needed unless a future implementation wants to classify
ambiguous prose.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ghas_llm.agentic_triage import VulnSignature

if TYPE_CHECKING:
    from ghas_llm.integrations.memory_store import TriageMemoryStore


@dataclass(frozen=True)
class HumanFeedback:
    jira_key: str
    repository: str
    kind: str
    number: int
    package: str
    human_text: str
    cve_id: str = ""
    extracted_reason: str = ""
    paths_or_functions: list[str] | None = None
    human_author: str = ""
    human_verdict_guess: str = "unknown"
    created: str = ""


class HumanFeedbackAgent:
    name = "human_feedback_agent"

    def __init__(
        self,
        repo_root: Path,
        config: dict[str, Any],
        *,
        memory_store: TriageMemoryStore | None = None,
    ) -> None:
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        rel = str(agent_cfg.get("human_feedback_file", ".human_feedback.jsonl"))
        self.path = (repo_root / rel).resolve()
        if memory_store is not None:
            self.store = memory_store
        else:
            from ghas_llm.integrations.memory_store import TriageMemoryStore

            self.store = TriageMemoryStore.from_config(config, repo_root)

    def record(
        self,
        *,
        jira_key: str,
        repository: str,
        kind: str,
        number: int,
        signature: VulnSignature | None,
        human_text: str,
        human_author: str = "",
        created: str = "",
    ) -> HumanFeedback:
        feedback = HumanFeedback(
            jira_key=jira_key,
            repository=repository,
            kind=kind,
            number=number,
            package=(signature.package if signature else ""),
            cve_id=(signature.cve_id if signature else ""),
            human_text=human_text.strip()[:4000],
            extracted_reason=extract_reason(human_text),
            paths_or_functions=extract_paths_or_functions(human_text),
            human_author=human_author,
            human_verdict_guess=guess_human_verdict(human_text),
            created=created,
        )
        row = {"ts": time.time(), **feedback.__dict__}
        self.store.append_feedback(row)
        return feedback

    def relevant_examples(
        self,
        *,
        signature: VulnSignature,
        repository: str,
        max_examples: int = 2,
    ) -> str:
        rows = self._load_rows()
        if not rows:
            return ""
        terms = {
            t.lower()
            for t in [signature.package, signature.ecosystem, signature.cve_id, repository]
            if t
        }
        scored: list[tuple[int, dict[str, Any]]] = []
        for row in rows:
            text = " ".join(
                str(row.get(k, ""))
                for k in ("repository", "package", "human_text", "human_verdict_guess")
            ).lower()
            score = sum(1 for term in terms if term and term in text)
            if score:
                scored.append((score, row))
        scored.sort(key=lambda x: x[0], reverse=True)
        snippets = []
        for _, row in scored[:max_examples]:
            snippets.append(
                "- "
                f"{row.get('jira_key', '?')} {row.get('repository', '')} "
                f"human={row.get('human_verdict_guess', 'unknown')}: "
                f"{str(row.get('extracted_reason') or row.get('human_text', ''))[:350]}",
            )
        if not snippets:
            return ""
        return "Relevant human feedback examples:\n" + "\n".join(snippets)

    def _load_rows(self) -> list[dict[str, Any]]:
        return self.store.load_feedback_rows(500)


def guess_human_verdict(text: str) -> str:
    low = (text or "").lower()
    if re.search(r"\b(false positive|not exploitable|safe to close|noise)\b", low):
        return "false_positive"
    if re.search(r"\b(fixed|resolved|patched|withdrawn|closed)\b", low):
        return "closed"
    if re.search(r"\b(true positive|valid because|fix|upgrade|remediate|action needed|vulnerable)\b", low):
        return "in_progress"
    if re.search(r"\b(needs review|investigate|not sure|unclear|manual)\b", low):
        return "leave_open"
    return "unknown"


def extract_reason(text: str) -> str:
    """Pull the actionable reason from terse human comments without an LLM."""
    raw = (text or "").strip()
    if not raw:
        return ""
    patterns = (
        r"(?:false positive|not reachable|safe to close|fixed|valid|withdrawn)\s+because\s+(.+)",
        r"(?:why closed|why false positive)\s*[:\-]\s*(.+)",
        r"(?:reason)\s*[:\-]\s*(.+)",
    )
    low = raw.lower()
    for pat in patterns:
        m = re.search(pat, low, re.IGNORECASE | re.DOTALL)
        if m:
            return raw[m.start(1) : m.end(1)].strip()[:800]
    return raw[:800] if guess_human_verdict(raw) != "unknown" else ""


def extract_paths_or_functions(text: str) -> list[str]:
    hits = re.findall(
        r"([\w./-]+\.(?:py|js|ts|tsx|java|go|rb|rs|yml|yaml|json|toml|xml))|`([^`]{2,120})`",
        text or "",
    )
    out: list[str] = []
    for path_hit, tick_hit in hits:
        val = (path_hit or tick_hit).strip()
        val = val.strip()
        if val and val not in out:
            out.append(val)
    return out[:5]

