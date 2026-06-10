from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Verdict = Literal["true_positive", "false_positive", "needs_review"]
Confidence = Literal["high", "medium", "low"]
Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
Priority = Literal["immediate", "next_sprint", "backlog", "no_action"]
AlertKind = Literal["dependabot", "code_scanning", "secret_scanning"]


@dataclass
class TriageVerdict:
    verdict: Verdict
    confidence: Confidence
    reasoning: str
    code_usage: str
    exploitability: str
    suggested_action: str
    severity_assessment: Severity = "unknown"
    priority: Priority = "next_sprint"
    raw_response: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_llm_json(cls, data: dict[str, Any]) -> TriageVerdict:
        v = str(data.get("verdict", "true_positive")).lower()
        if v not in ("true_positive", "false_positive", "needs_review"):
            v = "true_positive"
        c = str(data.get("confidence", "low")).lower()
        if c not in ("high", "medium", "low"):
            c = "low"
        sa = str(data.get("severity_assessment", "unknown")).lower()
        if sa not in ("critical", "high", "medium", "low", "info", "unknown"):
            sa = "unknown"
        pr = str(data.get("priority", "next_sprint")).lower()
        if pr not in ("immediate", "next_sprint", "backlog", "no_action"):
            pr = "next_sprint"
        return cls(
            verdict=v,  # type: ignore[arg-type]
            confidence=c,  # type: ignore[arg-type]
            reasoning=str(data.get("reasoning", "")),
            code_usage=str(data.get("code_usage", "")),
            exploitability=str(data.get("exploitability", "")),
            suggested_action=str(data.get("suggested_action", "")),
            severity_assessment=sa,  # type: ignore[arg-type]
            priority=pr,  # type: ignore[arg-type]
            raw_response=data,
        )


@dataclass
class AlertResult:
    kind: AlertKind
    number: int
    skipped: bool
    skip_reason: str | None
    verdict: TriageVerdict | None
    dry_run: bool
    actions: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
