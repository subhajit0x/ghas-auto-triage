"""Org-wide discovery worker.

When a target repo is missing local Dockerfile/manifest/CI evidence, the bot
must not give up. Many example-org services keep deployment logic in a separate
infra/deploy/terraform/helm repo. This agent searches the entire GitHub org
for references to the target repo so the Final Judge can reason about how the
code is actually built and deployed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ghas_llm.github_api import GitHubAPIError, GitHubClient

log = logging.getLogger(__name__)


_DEPLOY_HINTS = (
    ("dockerfile", "Dockerfile"),
    ("jenkinsfile", "Jenkinsfile"),
    ("workflow", "GitHub Actions workflow"),
    (".tf", "Terraform module"),
    ("helm", "Helm chart"),
    ("kustomization", "Kustomize overlay"),
    ("argocd", "ArgoCD application"),
    ("serverless", "Serverless config"),
    ("serverless.yml", "Serverless config"),
    ("serverless.yaml", "Serverless config"),
    ("template.yaml", "AWS SAM template"),
    ("template.yml", "AWS SAM template"),
    ("sam.yaml", "AWS SAM template"),
    ("sam.yml", "AWS SAM template"),
    ("cloudformation", "CloudFormation template"),
    ("k8s", "Kubernetes manifest"),
    ("kubernetes", "Kubernetes manifest"),
    ("values.yaml", "Helm chart"),
    ("buildspec", "AWS CodeBuild buildspec"),
    ("pipeline", "Pipeline definition"),
    ("skaffold", "Skaffold config"),
    ("ansible", "Ansible playbook"),
)


@dataclass
class OrgRepoReference:
    repo: str
    path: str
    hint: str = ""
    url: str = ""


@dataclass
class OrgHunterFindings:
    target: str = ""
    references: list[OrgRepoReference] = field(default_factory=list)
    deploy_kinds: list[str] = field(default_factory=list)
    queries_run: int = 0
    truncated: bool = False
    error: str = ""
    hosted_hint: str = "unknown"
    hosted_source: str = ""

    @property
    def has_external_deploy_evidence(self) -> bool:
        return bool(self.deploy_kinds)


class OrgHunterAgent:
    """Cross-repo discovery agent."""

    name = "org_hunter_agent"

    def __init__(
        self,
        client: GitHubClient,
        config: dict[str, Any],
    ) -> None:
        self.client = client
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        hunter_cfg = agent_cfg.get("org_hunter", {}) if isinstance(agent_cfg.get("org_hunter", {}), dict) else {}
        self.enabled = bool(hunter_cfg.get("enabled", True))
        self.max_results = int(hunter_cfg.get("max_results", 10))
        self.max_queries = int(hunter_cfg.get("max_queries", 4))
        self.per_query = int(hunter_cfg.get("per_query", 6))
        self.delay_s = float(hunter_cfg.get("delay_s", 0.25))

    def discover(
        self,
        *,
        owner: str,
        repo: str,
        org: str,
    ) -> OrgHunterFindings:
        target = f"{owner}/{repo}"
        out = OrgHunterFindings(target=target)
        if not self.enabled:
            return out
        if not org:
            return out

        queries = [
            f'org:{org} "{target}"',
            f'org:{org} "{repo}" filename:Dockerfile',
            f'org:{org} "{repo}" filename:values.yaml',
            f'org:{org} "{repo}" path:helm',
            f'org:{org} "{repo}" path:terraform',
            f'org:{org} "{repo}" filename:serverless.yml',
            f'org:{org} "{repo}" filename:template.yaml',
            f'org:{org} "{repo}" filename:cloudformation.yaml',
            f'org:{org} "{repo}" path:k8s',
            f'org:{org} "{repo}" filename:Jenkinsfile',
        ][: self.max_queries]

        seen: set[tuple[str, str]] = set()

        for q in queries:
            out.queries_run += 1
            try:
                time.sleep(self.delay_s)
                resp = self.client.get(
                    "/search/code",
                    {"q": q, "per_page": str(self.per_query)},
                )
            except GitHubAPIError as exc:
                if exc.status in (403, 422, 429):
                    log.warning("org hunter skipped (%s): %s", exc.status, q[:120])
                    continue
                out.error = f"{type(exc).__name__}: {exc}"
                continue
            items = resp.get("items", []) if isinstance(resp, dict) else []
            for it in items:
                if not isinstance(it, dict):
                    continue
                rp = it.get("repository") or {}
                full = str(rp.get("full_name", "") or "")
                path = str(it.get("path", "") or "")
                if not full or not path:
                    continue
                if full == target:
                    continue
                if (full, path) in seen:
                    continue
                seen.add((full, path))
                hint = _classify_path(path)
                out.references.append(
                    OrgRepoReference(
                        repo=full,
                        path=path,
                        hint=hint,
                        url=str(it.get("html_url", "") or ""),
                    ),
                )
                if hint and hint not in out.deploy_kinds:
                    out.deploy_kinds.append(hint)
                if out.hosted_hint == "unknown":
                    out.hosted_hint = _hosted_hint_from_path(path, hint)
                    out.hosted_source = f"{full}:{path}" if out.hosted_hint != "unknown" else ""
                if len(out.references) >= self.max_results:
                    out.truncated = True
                    return out
        return out


def _classify_path(path: str) -> str:
    low = path.lower()
    for needle, label in _DEPLOY_HINTS:
        if needle in low:
            return label
    return ""


def _hosted_hint_from_path(path: str, hint: str = "") -> str:
    low = f"{path} {hint}".lower()
    if "serverless" in low or "sam " in low or "template.yaml" in low or "template.yml" in low:
        return "serverless"
    if "helm" in low or "argocd" in low or "k8s" in low or "kubernetes" in low or "values.yaml" in low:
        return "kubernetes"
    if "terraform" in low or low.endswith(".tf"):
        return "terraform"
    if "workflow" in low or ".github/workflows" in low:
        return "github_actions"
    return "unknown"


def format_org_hunter_findings(findings: OrgHunterFindings) -> str:
    """Render findings for the LLM payload (plain text)."""
    if not findings.target:
        return "Org-wide discovery: (skipped)\n"
    if not findings.references and not findings.error:
        return (
            f"Org-wide discovery for {findings.target}: 0 external references found "
            f"in {findings.queries_run} queries. The repo appears to be deployed and "
            "consumed only from within itself.\n"
        )
    if findings.error and not findings.references:
        return (
            f"Org-wide discovery for {findings.target}: search error "
            f"({findings.error}). Treat external deploy evidence as unknown.\n"
        )
    lines = [
        f"Org-wide discovery for {findings.target}: "
        f"{len(findings.references)} external references "
        f"(queries={findings.queries_run}, deploy hints={', '.join(findings.deploy_kinds) or 'none'}, "
        f"hosted_hint={findings.hosted_hint}).",
    ]
    for ref in findings.references[:10]:
        suffix = f" ({ref.hint})" if ref.hint else ""
        lines.append(f"- {ref.repo}: {ref.path}{suffix}")
    return "\n".join(lines) + "\n"
