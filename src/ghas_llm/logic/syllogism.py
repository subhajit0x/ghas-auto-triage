"""Human-only Jira comment formatter.

Internal state (tier, negative proof, prosecutor/critic, scores) belongs in the
JSON run summary and triage history. Jira receives only a hidden bot marker and
a short professional human conclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ghas_llm.core.preflight import TruthTable


_BANNED_PATTERNS = (
    re.compile(r"^\s*Repository tier:.*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Negative proofs:.*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Evidence\s*\(Major Premise\):\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Impact\s*\(Minor Premise\):\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Conclusion:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Critic note:.*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Confidence score:.*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Confidence:\s*(low|medium|high)\b.*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*Risk(?: score)?:\s*\d+\s*/\s*10.*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*\(Note:\s*draft contained.*\)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bP[0-3]\b"),
)

_CONCLUSION_RE = re.compile(r"Conclusion:\s*(.+?)(?:\n|$)", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class CertifiedComment:
    body: str
    routing: str


@dataclass(frozen=True)
class HumanComment:
    body: str
    routing: str


def strip_internal_metadata(text: str) -> str:
    """Remove all internal-only meta-talk from the comment text."""
    cleaned = text or ""
    for pat in _BANNED_PATTERNS:
        cleaned = pat.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def build_human_comment(*, routing: str, human_conclusion: str) -> HumanComment:
    body = strip_internal_metadata(human_conclusion)
    body = re.sub(r"\s+", " ", body).strip()
    return HumanComment(body=body, routing=routing)


def _conclusion_line(routing: str, payload: dict[str, str]) -> str:
    if routing == "false_positive":
        return f"Conclusion: False positive for this repo — {payload.get('reason', 'no reachable usage found')}."
    if routing == "in_progress":
        pkg = payload.get("package", "the package")
        version = payload.get("fixed_version", "the fixed version")
        path = payload.get("path", "")
        suffix = f"; relevant paths include {path}" if path else ""
        return f"Conclusion: Action needed — upgrade {pkg} to {version}{suffix}."
    return f"Conclusion: Needs human review — {payload.get('reason', 'evidence is incomplete')}."


def build_certified_comment(
    *,
    routing: str,
    truth_table: TruthTable,
    major_premise: str,
    minor_premise: str,
    conclusion_payload: dict[str, str] | None = None,
    extra_negative_proofs: list[str] | None = None,
    drafted_conclusion: str = "",
) -> CertifiedComment:
    """Backward-compatible wrapper that returns human-only text."""
    negatives: list[str] = []
    if truth_table.negative_proof_complete:
        negatives.append(
            f"vulnerable API symbols searched and not found "
            f"(direct_hits={truth_table.direct_code_hits}, "
            f"test_only_hits={truth_table.test_only_hits})",
        )
    if extra_negative_proofs:
        negatives.extend(extra_negative_proofs)
    if not negatives:
        negatives.append("no negative proof recorded")

    conclusion_line = drafted_conclusion or _conclusion_line(
        routing,
        conclusion_payload or {},
    )

    return CertifiedComment(body=strip_internal_metadata(conclusion_line), routing=routing)


def routing_from_conclusion(text: str) -> str:
    match = _CONCLUSION_RE.search(text or "")
    line = (match.group(1).strip() if match else (text or "")).lower()
    if "false positive" in line or "safe to close" in line:
        return "false_positive"
    if "action needed" in line or "upgrade" in line or "remediate" in line:
        return "in_progress"
    if "needs human review" in line or "needs review" in line:
        return "leave_open"
    return ""
