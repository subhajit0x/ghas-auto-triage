from __future__ import annotations

from ghas_llm.agentic_triage import (
    EvidenceMatrix,
    ExtraContext,
    RepoProfile,
    VulnSignature,
)
from ghas_llm.agents.org_hunter_agent import OrgHunterFindings, OrgRepoReference
from ghas_llm.core.preflight import build_truth_table, format_truth_table


def _profile(**kwargs) -> RepoProfile:
    base = {
        "full_name": "example-org/app",
        "is_internal": True,
        "push_date_known": True,
        "days_since_last_push": 30,
    }
    base.update(kwargs)
    return RepoProfile(**base)


def test_force_verdict_for_active_repo_with_zero_reachability() -> None:
    profile = _profile()
    matrix = EvidenceMatrix(
        repo_active=True,
        direct_code_hits=0,
        api_symbols_hit_in_search=False,
    )
    extras = ExtraContext()
    sig = VulnSignature(package="rustls-webpki", vulnerable_apis=["verify_chain"])
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=OrgHunterFindings(target="example-org/app"),
    )
    assert table.force_verdict == "false_positive"
    assert table.negative_proof_complete
    assert table.tier in {"tier_2_supporting", "tier_3_internal"}


def test_force_verdict_for_archived_repo() -> None:
    profile = _profile(archived=True, days_since_last_push=900)
    matrix = EvidenceMatrix(repo_active=False, direct_code_hits=0)
    extras = ExtraContext()
    sig = VulnSignature(package="x", vulnerable_apis=["foo"])
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=OrgHunterFindings(target="example-org/app"),
    )
    assert table.force_verdict == "false_positive"
    assert table.tier == "tier_4_archived"


def test_external_deploy_promotes_tier_when_local_files_missing() -> None:
    profile = _profile()
    matrix = EvidenceMatrix(
        repo_active=True,
        direct_code_hits=2,
        api_symbols_hit_in_search=True,
        cross_validated=False,
    )
    extras = ExtraContext()
    hunter = OrgHunterFindings(
        target="example-org/app",
        references=[OrgRepoReference(repo="example-org/infra-deploy", path="helm/values.yaml", hint="Helm chart")],
        deploy_kinds=["Helm chart"],
        queries_run=1,
    )
    sig = VulnSignature(package="x", vulnerable_apis=["foo"])
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=hunter,
    )
    assert table.org_external_deploy_evidence
    assert table.tier == "tier_2_supporting"
    assert table.hosted_hint == "kubernetes"


def test_tier_floor_overrides_from_config() -> None:
    profile = _profile()
    matrix = EvidenceMatrix(repo_active=True, direct_code_hits=1)
    extras = ExtraContext()
    sig = VulnSignature(package="x", vulnerable_apis=["foo"])
    config = {
        "agent": {
            "production_trust": {
                "tier_floors": {
                    "tier_3_internal": {"post": 50, "transition": 80},
                },
            },
        },
    }
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=OrgHunterFindings(target="example-org/app"),
        config=config,
    )
    assert table.confidence_floor_post == 50
    assert table.confidence_floor_transition == 80


def test_format_truth_table_includes_force_section() -> None:
    profile = _profile(archived=True)
    matrix = EvidenceMatrix(repo_active=False, direct_code_hits=0)
    extras = ExtraContext()
    sig = VulnSignature(package="x", vulnerable_apis=["foo"])
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=OrgHunterFindings(target="example-org/app"),
    )
    text = format_truth_table(table)
    assert "PRE-FLIGHT TRUTH TABLE" in text
    assert "FORCE VERDICT" in text


def test_hosted_hint_from_serverless_runtime() -> None:
    profile = _profile()
    matrix = EvidenceMatrix(repo_active=True)
    extras = ExtraContext(runtime_path="serverless.yml", exposure_hint="serverless runtime")
    sig = VulnSignature(package="x", vulnerable_apis=["foo"])
    table = build_truth_table(
        profile=profile,
        matrix=matrix,
        extras=extras,
        sig=sig,
        hunter=OrgHunterFindings(target="example-org/app"),
    )
    assert table.hosted_hint == "serverless"
    assert table.hosted_source == "serverless.yml"
