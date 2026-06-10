from __future__ import annotations

from unittest.mock import MagicMock

from ghas_llm.agentic_triage import AgenticVerdict
from ghas_llm.agents.prosecutor_agent import ProsecutorAgent, ProsecutorReport
from ghas_llm.core.preflight import TruthTable


def _table(**kwargs) -> TruthTable:
    base = {"repo": "example-org/app", "tier": "tier_3_internal"}
    base.update(kwargs)
    return TruthTable(**base)


def test_prosecutor_disabled_uphold() -> None:
    p = ProsecutorAgent({"agent": {"prosecutor": {"enabled": False}}})
    out = p.review(
        verdict=AgenticVerdict(routing="false_positive"),
        truth_table=_table(),
        evidence_payload="",
    )
    assert out.uphold


def test_prosecutor_overrides_when_truth_table_force_disagrees() -> None:
    p = ProsecutorAgent({"agent": {"prosecutor": {"enabled": True}}})
    table = _table(force_verdict="false_positive", force_reason="zero usage")
    out = p.review(
        verdict=AgenticVerdict(routing="in_progress"),
        truth_table=table,
        evidence_payload="",
    )
    assert not out.uphold
    assert out.alternate_decision == "false_positive"


def test_prosecutor_overrides_when_action_needed_has_no_hits() -> None:
    p = ProsecutorAgent({"agent": {"prosecutor": {"enabled": True}}})
    table = _table(direct_code_hits=0)
    out = p.review(
        verdict=AgenticVerdict(routing="in_progress", reproducible=False),
        truth_table=table,
        evidence_payload="",
    )
    assert not out.uphold
    assert out.alternate_decision == "false_positive"


def test_prosecutor_uphold_when_no_deterministic_flaw() -> None:
    config = {"agent": {"prosecutor": {"enabled": True}}}
    p = ProsecutorAgent(config)
    table = _table(direct_code_hits=2)
    fake_oai = MagicMock()
    fake_oai.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content='{"uphold": true, "attack_holes": []}'))],
    )
    from unittest.mock import patch

    with patch("ghas_llm.agents.prosecutor_agent.build_openai_client", return_value=fake_oai):
        out = p.review(
            verdict=AgenticVerdict(routing="in_progress", reproducible=True),
            truth_table=table,
            evidence_payload="evidence...",
        )
    assert isinstance(out, ProsecutorReport)
    assert out.uphold is True
