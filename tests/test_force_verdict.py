from __future__ import annotations

from ghas_llm.agentic_triage import (
    EvidenceMatrix,
    ExtraContext,
    RepoProfile,
    VulnSignature,
    final_verdict,
)
from ghas_llm.agents.org_hunter_agent import OrgHunterFindings
from ghas_llm.core.preflight import build_truth_table


def test_force_verdict_short_circuits_llm_for_active_repo_zero_hits() -> None:
    config = {"global": {"llm": {"model": "gpt-5.4-mini"}}}
    profile = RepoProfile(
        full_name="example-org/app",
        is_internal=True,
        push_date_known=True,
        days_since_last_push=20,
    )
    sig = VulnSignature(package="rustls-webpki", vulnerable_apis=["verify_chain"], severity="high")
    matrix = EvidenceMatrix(
        repo_active=True,
        direct_code_hits=0,
        api_symbols_hit_in_search=False,
    )
    extras = ExtraContext()
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=OrgHunterFindings(target="example-org/app"),
    )
    assert table.force_verdict == "false_positive"

    verdict = final_verdict(
        config,
        alert_kind="dependabot",
        sig=sig,
        profile=profile,
        matches=[],
        blame=[],
        org_repos=0,
        matrix=matrix,
        extras=extras,
        truth_table=table,
        truth_table_summary="ttable",
        org_hunter_summary="org",
        global_memory_summary="memory",
    )

    assert verdict.deterministic_short_circuit
    assert verdict.routing == "false_positive"
    assert verdict.force_verdict == "false_positive"
    assert "Repository tier" not in verdict.jira_comment
    assert "Negative proofs" not in verdict.jira_comment
    assert "Evidence (Major Premise)" not in verdict.jira_comment
    assert "Conclusion:" not in verdict.jira_comment
    assert "rustls-webpki" in verdict.jira_comment
    assert "verify_chain" in verdict.jira_comment
    assert "repo-specific false positive" in verdict.jira_comment
    assert "Critic note" not in verdict.jira_comment
    assert "Confidence" not in verdict.jira_comment
