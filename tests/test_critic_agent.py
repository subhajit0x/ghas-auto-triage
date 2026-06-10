from __future__ import annotations

from ghas_llm.agentic_triage import AgenticVerdict
from ghas_llm.agents.critic_agent import CriticAgent, CriticDecision, apply_critic_decision


def test_critic_disabled_approves() -> None:
    critic = CriticAgent({"agent": {"critic": {"enabled": False}}})
    decision = critic.review(
        verdict=AgenticVerdict(routing="in_progress", confidence_score=10),
        evidence_payload="",
        min_confidence=70,
    )
    assert decision.approve


def test_critic_downgrades_below_confidence_floor() -> None:
    critic = CriticAgent({"agent": {"critic": {"enabled": True}}})
    decision = critic.review(
        verdict=AgenticVerdict(routing="in_progress", confidence_score=30),
        evidence_payload="",
        min_confidence=70,
    )
    assert decision.downgrade_to == "needs_review"


def test_apply_critic_decision_silent_routing_only() -> None:
    """The critic must never mutate the Jira comment or leak meta-talk.

    Routing fields update but ``jira_comment`` is left untouched — the
    orchestrator rebuilds the Jira text via the syllogism formatter.
    """
    original_comment = "Action needed.\n\nConclusion: Action needed — upgrade package."
    verdict = AgenticVerdict(
        routing="in_progress",
        impact="direct_vulnerable_usage",
        confidence="high",
        reproducible=True,
        jira_comment=original_comment,
        priority="P1",
    )
    decision = CriticDecision(approve=False, reason="unsupported path", downgrade_to="needs_review")
    out = apply_critic_decision(verdict, decision)
    assert out.routing == "leave_open"
    assert out.impact == "critic_downgrade"
    assert out.jira_comment == original_comment
    assert "Critic note" not in out.jira_comment
    assert "unsupported path" in (out.evidence_against[-1] if out.evidence_against else "")

