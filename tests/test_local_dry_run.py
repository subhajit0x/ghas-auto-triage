from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghas_llm.agentic_triage import (
    AgenticVerdict,
    BlameInfo,
    CodeMatch,
    EvidenceMatrix,
    ExtraContext,
    RepoProfile,
    VulnSignature,
)
from ghas_llm.local_dry_run import (
    _alert_ref_from_issue,
    _print_verdict,
    _resolve_github_token,
    _run_one,
    main,
)


def _verdict() -> AgenticVerdict:
    profile = RepoProfile(
        full_name="example-org/app", visibility="private", is_internal=True,
        push_date_known=True, days_since_last_push=4,
    )
    sig = VulnSignature(
        package="lodash", ecosystem="npm", severity="high",
        vulnerable_apis=["template"], cve_id="CVE-2020-8203",
        fixed_version="4.17.21",
    )
    matrix = EvidenceMatrix(
        reproducible=True, confidence_label="high", direct_code_hits=2, repo_active=True,
    )
    return AgenticVerdict(
        routing="in_progress", impact="direct_vulnerable_usage",
        confidence="high", reproducible=True,
        jira_comment="lodash template() is used in src/render.ts.\n\nConclusion: Reproducible — upgrade lodash to 4.17.21 in src/render.ts; risk 8/10, P1.",
        profile=profile, signature=sig, matrix=matrix,
        matches=[CodeMatch(path="src/render.ts")],
        blame=[BlameInfo(path="src/render.ts", last_commit_sha="abc12345", last_author_login="alice")],
        org_repos_affected=3,
        evidence_for=["template() called in src/render.ts"],
        evidence_against=["search may have missed an alias"],
        exploitation_path="HTTP body -> render.ts:42 -> lodash.template -> RCE",
        blast_radius="customer_facing",
        risk_score=8,
        priority="P1",
    )


def test_resolve_github_token_prefers_ghas_triage_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GHAS_TRIAGE_GITHUB_TOKEN", "ghp_org")
    monkeypatch.setenv("GHAS_LLM_GITHUB_TOKEN", "ghp_xxx")
    assert _resolve_github_token({}) == "ghp_org"


def test_resolve_github_token_uses_ghas_when_no_ghas_triage_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GHAS_TRIAGE_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GHAS_LLM_GITHUB_TOKEN", "ghp_xxx")
    assert _resolve_github_token({}) == "ghp_xxx"


def test_resolve_github_token_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ("GHAS_TRIAGE_GITHUB_TOKEN", "GHAS_LLM_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(SystemExit):
        _resolve_github_token({})


def test_alert_ref_from_issue_extracts_owner_repo_kind_number() -> None:
    issue = {
        "fields": {
            "customfield_10206": {"value": "dependabot"},
            "customfield_10204": {"value": "example-org/analytics-mage-infra"},
            "description": "Alert https://github.com/example-org/analytics-mage-infra/security/dependabot/91",
        },
    }
    jira_cfg = {
        "tool_custom_field": "customfield_10206",
        "asset_custom_field": "customfield_10204",
    }
    ref = _alert_ref_from_issue(issue, jira_cfg)
    assert ref is not None
    kind, number, (owner, repo) = ref
    assert kind == "dependabot"
    assert number == 91
    assert owner == "example-org"
    assert repo == "analytics-mage-infra"


def test_alert_ref_from_issue_returns_none_when_unparseable() -> None:
    issue = {"fields": {"customfield_10206": "", "customfield_10204": "not-a-repo"}}
    jira_cfg = {
        "tool_custom_field": "customfield_10206",
        "asset_custom_field": "customfield_10204",
    }
    assert _alert_ref_from_issue(issue, jira_cfg) is None


def test_print_verdict_includes_risk_priority_and_comment(capsys: pytest.CaptureFixture) -> None:
    _print_verdict("example-org/app dependabot #91", _verdict())
    out = capsys.readouterr().out
    assert "example-org/app" in out
    assert "Risk: 8/10" in out
    assert "Priority: P1" in out
    assert "Blast: customer_facing" in out
    assert "HTTP body -> render.ts:42" in out
    assert "Conclusion: Reproducible" in out


def test_run_one_calls_agentic_triage_and_returns_summary() -> None:
    fake_client = MagicMock()
    fake_client.get_repo.return_value = {"default_branch": "main"}
    with patch("ghas_llm.local_dry_run.fetch_github_alert", return_value={"x": 1}), \
         patch("ghas_llm.local_dry_run.agentic_triage", return_value=_verdict()):
        out = _run_one(
            {}, fake_client, owner="example-org", repo="app", kind="dependabot",
            number=91, org="example-org",
        )
    assert out["routing"] == "in_progress"
    assert out["risk_score"] == 8
    assert out["priority"] == "P1"
    assert out["blast_radius"] == "customer_facing"
    assert out["exploitation_path"].startswith("HTTP body")
    assert out["matches"] == ["src/render.ts"]


def test_run_one_handles_alert_fetch_error() -> None:
    from ghas_llm.github_api import GitHubAPIError

    fake_client = MagicMock()
    fake_client.get_repo.return_value = {"default_branch": "main"}
    with patch("ghas_llm.local_dry_run.fetch_github_alert", side_effect=GitHubAPIError(404, "not found", "")):
        out = _run_one(
            {}, fake_client, owner="example-org", repo="app", kind="dependabot",
            number=91, org="example-org",
        )
    assert "fetch_alert" in out["error"]


_CFG_PATH = str(Path(__file__).resolve().parent.parent / "ghas_llm.yaml")


def test_main_repo_kind_number_writes_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHAS_LLM_GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    out_file = tmp_path / "result.json"

    fake_client = MagicMock()
    fake_client.get_repo.return_value = {"default_branch": "main"}
    with patch("ghas_llm.local_dry_run.GitHubClient", return_value=fake_client), \
         patch("ghas_llm.local_dry_run.fetch_github_alert", return_value={"x": 1}), \
         patch("ghas_llm.local_dry_run.agentic_triage", return_value=_verdict()):
        rc = main([
            "--config", _CFG_PATH,
            "--repo", "example-org/app",
            "--kind", "dependabot",
            "--number", "91",
            "--out", str(out_file),
        ])
    assert rc == 0
    saved = json.loads(out_file.read_text())
    assert saved[0]["routing"] == "in_progress"
    assert saved[0]["priority"] == "P1"


def test_main_requires_one_of_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHAS_LLM_GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    fake_client = MagicMock()
    with patch("ghas_llm.local_dry_run.GitHubClient", return_value=fake_client):
        with pytest.raises(SystemExit):
            main(["--config", _CFG_PATH])
