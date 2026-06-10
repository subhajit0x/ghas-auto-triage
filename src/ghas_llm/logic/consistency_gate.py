"""Consistency gate for daily autonomous triage runs."""

from __future__ import annotations

import re
from dataclasses import dataclass


_CONCLUSION_RE = re.compile(r"Conclusion:\s*(.+?)(?:\n|$)", re.IGNORECASE | re.DOTALL)
_BOT_MARKER_RE = re.compile(
    r"<!--\s*ghas-triage-agent\s+v=\d+\s+kind=[a-z_]+\s+number=\d+(?:\s+routing=(?P<routing>[a-z_]+))?\s*-->",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ConsistencyDecision:
    routing: str
    comment: str
    changed: bool = False
    reason: str = ""


def extract_conclusion(text: str) -> str:
    match = _CONCLUSION_RE.search(text or "")
    return (match.group(1).strip() if match else "").strip()


def routing_from_comment(text: str) -> str:
    marker = _BOT_MARKER_RE.search(text or "")
    if marker and marker.group("routing"):
        return marker.group("routing").strip().lower()
    conclusion = (extract_conclusion(text) or text or "").lower()
    if "false positive" in conclusion or "safe to close" in conclusion:
        return "false_positive"
    if "action needed" in conclusion or "upgrade" in conclusion or "remediate" in conclusion:
        return "in_progress"
    if "needs human review" in conclusion or "needs review" in conclusion:
        return "leave_open"
    return ""


def apply_consistency_gate(
    *,
    prior_comment: str,
    new_comment: str,
    routing: str,
    confidence: str,
    reproducible: bool,
) -> ConsistencyDecision:
    """Prevent unexplained bot reversals.

    Strong high-confidence evidence may reverse prior automation. Weak or medium
    evidence that conflicts with the prior conclusion is routed to human review.
    """
    prior_routing = routing_from_comment(prior_comment)
    if not prior_routing or prior_routing == routing or routing == "leave_open":
        return ConsistencyDecision(routing=routing, comment=new_comment)

    strong_change = confidence == "high" and (routing != "in_progress" or reproducible)
    if strong_change:
        return ConsistencyDecision(
            routing=routing,
            comment=new_comment,
            changed=True,
            reason="high_confidence_reversal",
        )

    prior_conclusion = extract_conclusion(prior_comment) or "previous automated conclusion"
    guarded = (
        f"Automated triage found a possible conflict with the previous result ({prior_conclusion}). "
        "Please review the dependency path before closing or upgrading this ticket."
    )
    return ConsistencyDecision(
        routing="leave_open",
        comment=guarded,
        changed=True,
        reason="conflicting_prior_comment",
    )

