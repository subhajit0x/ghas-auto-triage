from __future__ import annotations

from unittest.mock import MagicMock

from ghas_llm.agents.org_hunter_agent import (
    OrgHunterAgent,
    OrgHunterFindings,
    format_org_hunter_findings,
)
from ghas_llm.github_api import GitHubAPIError


def _hunter(config: dict | None = None) -> tuple[OrgHunterAgent, MagicMock]:
    client = MagicMock()
    agent = OrgHunterAgent(client, config or {})
    return agent, client


def test_org_hunter_disabled_returns_empty_findings() -> None:
    agent, client = _hunter({"agent": {"org_hunter": {"enabled": False}}})
    out = agent.discover(owner="example-org", repo="app", org="example-org")
    assert out.references == []
    assert out.queries_run == 0
    client.get.assert_not_called()


def test_org_hunter_classifies_deploy_kinds() -> None:
    agent, client = _hunter()
    client.get.side_effect = [
        {
            "items": [
                {
                    "repository": {"full_name": "example-org/infra-deploy"},
                    "path": "helm/charts/app/values.yaml",
                    "html_url": "https://github.com/example-org/infra-deploy/values.yaml",
                },
                {
                    "repository": {"full_name": "example-org/infra-deploy"},
                    "path": "terraform/services/app.tf",
                    "html_url": "https://github.com/example-org/infra-deploy/app.tf",
                },
                # self-reference must be filtered out
                {
                    "repository": {"full_name": "example-org/app"},
                    "path": "README.md",
                    "html_url": "",
                },
            ]
        },
        {"items": []},
        {"items": []},
        {"items": []},
    ]
    out = agent.discover(owner="example-org", repo="app", org="example-org")
    assert len(out.references) == 2
    assert "Helm chart" in out.deploy_kinds
    assert "Terraform module" in out.deploy_kinds
    assert all(ref.repo == "example-org/infra-deploy" for ref in out.references)
    assert out.has_external_deploy_evidence


def test_org_hunter_swallows_rate_limits() -> None:
    agent, client = _hunter({"agent": {"org_hunter": {"max_queries": 2}}})
    client.get.side_effect = [GitHubAPIError(403, "rate limited", ""), {"items": []}]
    out = agent.discover(owner="example-org", repo="app", org="example-org")
    assert out.references == []
    assert out.error == ""
    assert out.queries_run == 2


def test_format_org_hunter_findings_human_readable() -> None:
    findings = OrgHunterFindings(
        target="example-org/app",
        references=[],
        queries_run=4,
    )
    text = format_org_hunter_findings(findings)
    assert "Org-wide discovery for example-org/app" in text
    assert "0 external references" in text
