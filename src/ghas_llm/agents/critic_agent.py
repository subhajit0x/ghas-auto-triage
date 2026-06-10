"""Second-pass critic for Final Judge output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ghas_llm.agentic_triage import AgenticVerdict
from ghas_llm.llm_triage import _parse_json_object, build_openai_client


_CRITIC_SYSTEM = """You are a strict AppSec review critic.

Audit a GHAS triage verdict for hallucinated paths, unsupported claims,
contradictions with the evidence matrix, and unsafe confidence. Return one JSON
object only:
{
  "approve": true|false,
  "reason": "short reason",
  "downgrade_to": null|"needs_review"
}

Downgrade to needs_review if:
- the Jira comment cites files/functions not present in evidence,
- the verdict says action needed without reproducible evidence,
- the verdict says false positive while production reachability is unclear,
- confidence_score is below the configured production floor,
- prior/human feedback contradicts the verdict and the evidence is not strong.
"""


@dataclass(frozen=True)
class CriticDecision:
    approve: bool
    reason: str = ""
    downgrade_to: str | None = None


class CriticAgent:
    name = "critic_agent"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        critic_cfg = agent_cfg.get("critic", {}) if isinstance(agent_cfg.get("critic", {}), dict) else {}
        self.enabled = bool(critic_cfg.get("enabled", False))

    def review(
        self,
        *,
        verdict: AgenticVerdict,
        evidence_payload: str,
        min_confidence: int,
    ) -> CriticDecision:
        if not self.enabled:
            return CriticDecision(approve=True)

        if verdict.confidence_score < min_confidence and verdict.routing != "leave_open":
            return CriticDecision(
                approve=False,
                reason=f"confidence_score {verdict.confidence_score} below floor {min_confidence}",
                downgrade_to="needs_review",
            )

        g = self.config.get("global", {}).get("llm", {})
        model = str(g.get("critic_model", g.get("model", "gpt-5.4-mini")))
        user = (
            f"Production confidence floor: {min_confidence}\n\n"
            f"Routing: {verdict.routing}\n"
            f"Confidence score: {verdict.confidence_score}\n"
            f"Impact: {verdict.impact}\n"
            f"Reproducible: {verdict.reproducible}\n"
            f"Comment:\n{verdict.jira_comment}\n\n"
            f"Evidence:\n{evidence_payload[:12000]}"
        )
        try:
            client = build_openai_client(self.config)
            resp = client.chat.completions.create(
                model=model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": _CRITIC_SYSTEM},
                    {"role": "user", "content": user},
                ],
            )
            data = _parse_json_object((resp.choices[0].message.content or "").strip())
            downgrade = data.get("downgrade_to")
            if downgrade not in (None, "needs_review"):
                downgrade = None
            return CriticDecision(
                approve=bool(data.get("approve", False)),
                reason=str(data.get("reason", "") or "")[:500],
                downgrade_to=downgrade,
            )
        except Exception as exc:  # noqa: BLE001
            return CriticDecision(
                approve=False,
                reason=f"critic failed: {type(exc).__name__}: {exc}",
                downgrade_to="needs_review",
            )


def apply_critic_decision(verdict: AgenticVerdict, decision: CriticDecision) -> AgenticVerdict:
    """Silent critic application.

    The critic NEVER mutates ``verdict.jira_comment`` — that text is rebuilt by
    the orchestrator using the syllogism formatter so no internal meta-talk
    leaks into Jira. This function only updates internal routing fields.
    """
    if decision.approve and not decision.downgrade_to:
        return verdict
    if decision.downgrade_to != "needs_review":
        return verdict
    verdict.routing = "leave_open"
    verdict.impact = "critic_downgrade"
    verdict.confidence = "low"
    verdict.reproducible = False
    verdict.priority = "P3"
    verdict.evidence_against.append(decision.reason or "critic downgrade")
    return verdict

