"""Pre-Flight Truth Table.

Deterministic state computed BEFORE any LLM call. The truth table maps:
- Repo tier (criticality / blast radius proxy)
- File existence (manifest, lockfile, Dockerfile, CI, runtime, README)
- Negative proof requirement (vulnerable APIs searched and not found)
- Force-verdict signal (deterministic FP/TP override that bypasses the judge)
- Recommended confidence floor for posting / auto-transition

The judge is allowed to weigh evidence; it is NOT allowed to invent a verdict
that contradicts a force_verdict signal from this table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ghas_llm.agentic_triage import (
    EvidenceMatrix,
    ExtraContext,
    RepoProfile,
    VulnSignature,
)
from ghas_llm.agents.org_hunter_agent import OrgHunterFindings


@dataclass
class TruthTable:
    repo: str = ""
    tier: str = "tier_3_internal"
    tier_reason: str = ""
    has_manifest: bool = False
    has_lockfile: bool = False
    has_dockerfile: bool = False
    has_ci: bool = False
    has_runtime: bool = False
    has_readme: bool = False
    package_in_manifest: bool = False
    package_in_lockfile: bool = False
    package_in_dockerfile: bool = False
    package_in_ci: bool = False
    advisory_has_apis: bool = False
    direct_code_hits: int = 0
    test_only_hits: int = 0
    org_repos_affected: int = 0
    repo_active: bool = False
    repo_archived: bool = False
    repo_age_days: int = 0
    org_external_deploy_evidence: bool = False
    org_external_deploy_kinds: list[str] = field(default_factory=list)
    hosted_hint: str = "unknown"
    hosted_source: str = ""
    negative_proof_complete: bool = False
    force_verdict: str = ""
    force_reason: str = ""
    confidence_floor_post: int = 70
    confidence_floor_transition: int = 90
    notes: list[str] = field(default_factory=list)


def _classify_tier(
    profile: RepoProfile,
    extras: ExtraContext,
    matrix: EvidenceMatrix,
    hunter: OrgHunterFindings,
) -> tuple[str, str]:
    if profile.archived:
        return "tier_4_archived", "repo archived"
    exposure = (extras.exposure_hint or "").lower()
    if "api" in exposure or "customer" in exposure:
        return "tier_1_critical", f"runtime exposure detected: {extras.exposure_hint}"
    if hunter.has_external_deploy_evidence and any(
        kind.lower() in {"helm chart", "argocd application", "terraform module", "kustomize overlay"}
        for kind in hunter.deploy_kinds
    ):
        return "tier_2_supporting", "deployed via external infra repo"
    if matrix.cross_validated and matrix.repo_active:
        return "tier_2_supporting", "cross-validated dependency in an active repo"
    if profile.is_internal and matrix.repo_active:
        return "tier_3_internal", "internal active repo without exposure signal"
    if not matrix.repo_active:
        return "tier_3_internal", "low activity"
    return "tier_3_internal", "default"


_FLOOR_BY_TIER = {
    "tier_1_critical": (80, 95),
    "tier_2_supporting": (75, 90),
    "tier_3_internal": (65, 85),
    "tier_4_archived": (55, 75),
}


def build_truth_table(
    *,
    profile: RepoProfile,
    matrix: EvidenceMatrix,
    extras: ExtraContext,
    sig: VulnSignature,
    hunter: OrgHunterFindings,
    config: dict[str, Any] | None = None,
) -> TruthTable:
    table = TruthTable(
        repo=profile.full_name,
        has_manifest=bool(extras.manifest_path),
        has_lockfile=bool(extras.lockfile_path),
        has_dockerfile=bool(extras.dockerfile_excerpt),
        has_ci=bool(extras.ci_workflow_path),
        has_runtime=bool(extras.runtime_path),
        has_readme=bool(extras.readme_excerpt),
        package_in_manifest=bool(extras.package_pinned_in_manifest),
        package_in_lockfile=bool(getattr(extras, "lockfile_has_package", False)),
        package_in_dockerfile=bool(extras.package_in_dockerfile),
        package_in_ci=bool(extras.package_in_ci),
        advisory_has_apis=bool(sig.vulnerable_apis),
        direct_code_hits=int(matrix.direct_code_hits or 0),
        test_only_hits=int(matrix.test_only_hits or 0),
        org_repos_affected=int(matrix.org_wide_hit_repos or 0),
        repo_active=bool(matrix.repo_active),
        repo_archived=bool(matrix.repo_archived),
        repo_age_days=int(profile.days_since_last_push or 0),
        org_external_deploy_evidence=hunter.has_external_deploy_evidence,
        org_external_deploy_kinds=list(hunter.deploy_kinds),
        hosted_hint=_hosted_hint(extras, hunter),
        hosted_source=_hosted_source(extras, hunter),
    )

    table.tier, table.tier_reason = _classify_tier(profile, extras, matrix, hunter)

    table.negative_proof_complete = (
        table.advisory_has_apis
        and table.direct_code_hits == 0
        and matrix.api_symbols_hit_in_search is False
    )

    if profile.archived and table.direct_code_hits == 0:
        table.force_verdict = "false_positive"
        table.force_reason = "archived repo with no direct usage"
    elif (
        table.advisory_has_apis
        and table.direct_code_hits == 0
        and (matrix.repo_active or table.repo_age_days >= 180)
    ):
        table.force_verdict = "false_positive"
        table.force_reason = (
            "absence of evidence: vulnerable APIs were searched and produced "
            "zero non-test matches in an active repo"
        )

    floors = _FLOOR_BY_TIER.get(table.tier, (70, 90))
    if config:
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        trust = agent_cfg.get("production_trust", {}) if isinstance(agent_cfg.get("production_trust", {}), dict) else {}
        per_tier = trust.get("tier_floors", {}) if isinstance(trust.get("tier_floors", {}), dict) else {}
        if isinstance(per_tier.get(table.tier), dict):
            cfg_floor = per_tier[table.tier]
            floors = (
                int(cfg_floor.get("post", floors[0])),
                int(cfg_floor.get("transition", floors[1])),
            )
    table.confidence_floor_post, table.confidence_floor_transition = floors

    if not table.has_manifest:
        table.notes.append("no local manifest")
    if not table.has_dockerfile:
        table.notes.append("no local Dockerfile")
    if not table.has_ci:
        table.notes.append("no local CI workflow")
    if hunter.has_external_deploy_evidence:
        table.notes.append("external deploy evidence available via org search")
    if table.negative_proof_complete:
        table.notes.append("negative proof complete (vulnerable API not found)")

    return table


def format_truth_table(table: TruthTable) -> str:
    parts = [
        f"PRE-FLIGHT TRUTH TABLE for {table.repo}",
        f"Tier: {table.tier} ({table.tier_reason})",
        (
            "Files: manifest="
            f"{table.has_manifest} lockfile={table.has_lockfile} "
            f"docker={table.has_dockerfile} ci={table.has_ci} "
            f"runtime={table.has_runtime}"
        ),
        (
            f"Package presence: manifest={table.package_in_manifest} "
            f"lockfile={table.package_in_lockfile} docker={table.package_in_dockerfile} "
            f"ci={table.package_in_ci}"
        ),
        (
            f"Reachability: advisory_apis={table.advisory_has_apis} "
            f"direct_hits={table.direct_code_hits} test_only={table.test_only_hits} "
            f"negative_proof_complete={table.negative_proof_complete}"
        ),
        (
            f"Activity: active={table.repo_active} archived={table.repo_archived} "
            f"age_days={table.repo_age_days}"
        ),
        (
            f"Org-wide deploy evidence: {table.org_external_deploy_evidence} "
            f"({', '.join(table.org_external_deploy_kinds) or 'none'})"
        ),
        f"Hosted hint: {table.hosted_hint} source={table.hosted_source or 'unknown'}",
        f"Confidence floors: post>={table.confidence_floor_post} transition>={table.confidence_floor_transition}",
    ]
    if table.force_verdict:
        parts.append(f"FORCE VERDICT: {table.force_verdict} — {table.force_reason}")
    if table.notes:
        parts.append("Notes: " + "; ".join(table.notes))
    return "\n".join(parts) + "\n"


def _hosted_hint(extras: ExtraContext, hunter: OrgHunterFindings) -> str:
    exposure = (extras.exposure_hint or "").lower()
    runtime = (extras.runtime_path or "").lower()
    if "serverless" in runtime or "api gateway" in exposure or "lambda" in exposure:
        return "serverless"
    if getattr(hunter, "hosted_hint", "unknown") != "unknown":
        return hunter.hosted_hint
    kinds = " ".join(getattr(hunter, "deploy_kinds", []) or []).lower()
    if "serverless" in kinds or "sam" in kinds or "cloudformation" in kinds:
        return "serverless"
    if "helm" in kinds or "argocd" in kinds or "kubernetes" in kinds or "kustomize" in kinds:
        return "kubernetes"
    if "terraform" in kinds:
        return "terraform"
    if extras.ci_workflow_path:
        return "github_actions"
    return "unknown"


def _hosted_source(extras: ExtraContext, hunter: OrgHunterFindings) -> str:
    if extras.runtime_path:
        return extras.runtime_path
    return getattr(hunter, "hosted_source", "") or ""
