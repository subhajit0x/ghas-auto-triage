"""Deterministic evidence worker.

This module names the evidence-gathering worker explicitly while reusing the
well-tested GitHub API logic from agentic_triage.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from ghas_llm.agentic_triage import (
    BlameInfo,
    CodeMatch,
    EvidenceMatrix,
    ExtraContext,
    RepoProfile,
    VulnSignature,
    compute_evidence_matrix,
    find_code_reachability,
    gather_blame,
    gather_extra_context,
    gather_repo_profile,
    org_wide_impact,
)
from ghas_llm.github_api import GitHubClient


@dataclass(frozen=True)
class EvidenceBundle:
    profile: RepoProfile
    matches: list[CodeMatch]
    blame: list[BlameInfo]
    org_repos: int
    extras: ExtraContext
    matrix: EvidenceMatrix


class EvidenceAgent:
    name = "evidence_agent"

    def __init__(self, client: GitHubClient, config: dict) -> None:
        self.client = client
        self.config = config
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        self.max_search_queries = int(agent_cfg.get("max_code_search_queries", 12))
        self.max_code_matches = int(agent_cfg.get("max_code_matches", 16))
        self.enable_org_wide = bool(agent_cfg.get("enable_org_wide_search", True))

    def collect(
        self,
        *,
        owner: str,
        repo: str,
        branch: str,
        org: str,
        alert_kind: str,
        alert: dict,
        signature: VulnSignature,
    ) -> EvidenceBundle:
        profile = gather_repo_profile(self.client, owner, repo, org)
        branch = branch or profile.default_branch
        matches: list[CodeMatch] = []
        blame: list[BlameInfo] = []
        org_repos = 0

        if alert_kind == "dependabot":
            matches = find_code_reachability(
                self.client,
                owner,
                repo,
                signature,
                max_matches=self.max_code_matches,
                max_queries=self.max_search_queries,
            )
            if matches:
                blame = gather_blame(self.client, owner, repo, branch, matches)
            if self.enable_org_wide:
                org_repos = org_wide_impact(self.client, org, signature)
        elif alert_kind == "code_scanning":
            inst = alert.get("most_recent_instance") or {}
            loc = inst.get("location") or {}
            path = str(loc.get("path", "") or "")
            if path:
                matches = [CodeMatch(path=path)]
                signature.vulnerable_apis = signature.vulnerable_apis or [
                    str((alert.get("rule") or {}).get("id", "code_scanning_finding")),
                ]
                blame = gather_blame(self.client, owner, repo, branch, matches)
        elif alert_kind == "secret_scanning":
            for raw in (alert.get("locations") or [])[:3]:
                if not isinstance(raw, dict):
                    continue
                details = raw.get("details") or {}
                path = str(details.get("path", "") or "")
                if path:
                    matches.append(CodeMatch(path=path))
            signature.vulnerable_apis = signature.vulnerable_apis or ["secret"]
            if matches:
                blame = gather_blame(self.client, owner, repo, branch, matches)

        extras = gather_extra_context(self.client, owner, repo, branch, signature)
        matrix = compute_evidence_matrix(profile, matches, blame, org_repos, signature, extras)
        return EvidenceBundle(
            profile=profile,
            matches=matches,
            blame=blame,
            org_repos=org_repos,
            extras=extras,
            matrix=matrix,
        )

