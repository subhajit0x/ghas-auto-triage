from __future__ import annotations

from ghas_llm.core.preflight import TruthTable
from ghas_llm.logic.syllogism import (
    build_certified_comment,
    routing_from_conclusion,
    strip_internal_metadata,
)


def _table(**kwargs) -> TruthTable:
    base = {
        "repo": "example-org/app",
        "tier": "tier_3_internal",
        "tier_reason": "internal active repo without exposure signal",
    }
    base.update(kwargs)
    return TruthTable(**base)


def test_strip_internal_metadata_removes_meta_lines() -> None:
    body = (
        "Major finding.\n"
        "Critic note: looks suspicious.\n"
        "Confidence score: 30/100.\n"
        "Confidence: low — may be wrong.\n"
        "Risk score: 4/10.\n"
        "Pretty body.\n"
        "P1 escalation.\n"
        "(Note: draft contained hedging language — flagged for human review.)"
    )
    cleaned = strip_internal_metadata(body)
    assert "Critic note" not in cleaned
    assert "Confidence" not in cleaned
    assert "Risk" not in cleaned
    assert "P1" not in cleaned
    assert "draft contained" not in cleaned
    assert "Major finding." in cleaned
    assert "Pretty body." in cleaned


def test_build_certified_comment_false_positive_format() -> None:
    table = _table(negative_proof_complete=True, direct_code_hits=0, test_only_hits=2)
    out = build_certified_comment(
        routing="false_positive",
        truth_table=table,
        major_premise="CVE affects pkg foo via API bar.",
        minor_premise="example-org/app has zero matches for bar in production code.",
        conclusion_payload={"reason": "no reachable usage"},
    )
    assert "Repository tier:" not in out.body
    assert "Negative proofs" not in out.body
    assert "Evidence (Major Premise):" not in out.body
    assert "Impact (Minor Premise):" not in out.body
    assert out.body.strip() == "False positive for this repo — no reachable usage."


def test_build_certified_comment_action_needed_includes_path() -> None:
    table = _table()
    out = build_certified_comment(
        routing="in_progress",
        truth_table=table,
        major_premise="CVE affects pkg foo.",
        minor_premise="example-org/app uses foo in src/x.py.",
        conclusion_payload={
            "package": "foo",
            "fixed_version": "1.2.3",
            "path": "src/x.py",
        },
    )
    assert "Action needed" in out.body
    assert "upgrade foo to 1.2.3" in out.body
    assert "relevant paths include src/x.py" in out.body


def test_routing_from_conclusion() -> None:
    assert routing_from_conclusion("Conclusion: False positive for this repo — none.") == "false_positive"
    assert routing_from_conclusion("Conclusion: Action needed — upgrade foo.") == "in_progress"
    assert routing_from_conclusion("Conclusion: Needs human review — gap.") == "leave_open"
    assert routing_from_conclusion("nothing") == ""
