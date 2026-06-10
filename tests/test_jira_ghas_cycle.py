from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from ghas_llm.jira_ghas_cycle import (
    _comments_substantively_same,
    _dependabot_fast_path,
    _format_brief_jira_comment,
    _format_triage_comment,
    _parse_alert_number,
    _parse_asset,
    _resolve_github_token_for_jira_first,
    build_jira_github_jql,
    run_jira_first_ghas_cycle,
    tool_string_to_kind,
)
from ghas_llm.agentic_triage import AgenticVerdict, EvidenceMatrix
from ghas_llm.agents.comment_scanner_agent import build_bot_marker
from ghas_llm.models import TriageVerdict


def _agentic_test_config(*, dry: bool) -> dict:
    return {
        "global": {
            "dry_run": dry,
            "github": {"token_env": "GHAS_TRIAGE_GITHUB_TOKEN"},
            "llm": {"api_key_env": "OPENAI_API_KEY"},
        },
        "agent": {
            "agentic_mode": True,
            "require_code_validation": True,
            "max_context_chars": 1000,
            "production_trust": {"min_confidence_for_action": 70},
        },
        "integrations": {
            "jira": {
                "enabled": True,
                "base_url": "https://test.atlassian.net",
                "email_env": "JIRA_EMAIL",
                "api_token_env": "JIRA_API_TOKEN",
                "triage_project": "VM",
                "tool_custom_field": "customfield_10206",
                "asset_custom_field": "customfield_10204",
            },
            "github": {},
        },
    }


def test_tool_string_to_kind() -> None:
    assert tool_string_to_kind("github:dependabot", "github:") == "dependabot"
    assert tool_string_to_kind("github:code-scanning", "github:") == "code_scanning"
    assert tool_string_to_kind("github:secret-scanning", "github:") == "secret_scanning"
    assert tool_string_to_kind("dependabot", "") == "dependabot"
    assert tool_string_to_kind("code-scanning", "") == "code_scanning"
    assert tool_string_to_kind("secret-scanning", "") == "secret_scanning"
    assert tool_string_to_kind("Dependabot", "") == "dependabot"
    assert tool_string_to_kind("terraform", "github:") is None
    assert tool_string_to_kind("Security Hub", "") is None


def test_parse_asset() -> None:
    assert _parse_asset("org/my-repo") == ("org", "my-repo")
    assert _parse_asset("bad") is None


def test_parse_alert_number_from_url() -> None:
    desc = "See https://github.com/org/r/security/dependabot/1 or /dependabot/alerts/42"
    assert _parse_alert_number({}, desc, "") == 42


def test_build_jira_github_jql_default() -> None:
    jql = build_jira_github_jql({"triage_project": "VM", "tool_custom_field": "customfield_1"})
    assert 'project = "VM"' in jql
    assert "customfield_1" in jql
    assert "dependabot" in jql
    assert "code-scanning" in jql
    assert "secret-scanning" in jql
    assert "ORDER BY" in jql


def test_build_jira_github_jql_override() -> None:
    jql = build_jira_github_jql({"jira_github_issues_jql": "project = X AND key = SEC-1"})
    assert jql == "project = X AND key = SEC-1"


def test_resolve_github_token_prefers_ghas_triage_token(monkeypatch) -> None:
    monkeypatch.setenv("GHAS_TRIAGE_GITHUB_TOKEN", "pat-org")
    monkeypatch.setenv("GHAS_LLM_GITHUB_TOKEN", "pat-old")
    token, source = _resolve_github_token_for_jira_first(
        {"global": {"github": {"aws_secret_name": "your-org/github/ghas-triage"}}},
    )
    assert token == "pat-org"
    assert source == "env:GHAS_TRIAGE_GITHUB_TOKEN"


def test_resolve_github_token_uses_ghas_when_no_ghas_triage_token(monkeypatch) -> None:
    monkeypatch.delenv("GHAS_TRIAGE_GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GHAS_LLM_GITHUB_TOKEN", "pat-old")
    token, source = _resolve_github_token_for_jira_first(
        {"global": {"github": {"aws_secret_name": "your-org/github/ghas-triage"}}},
    )
    assert token == "pat-old"
    assert source == "env:GHAS_LLM_GITHUB_TOKEN"


def test_resolve_github_token_uses_configured_env(monkeypatch) -> None:
    monkeypatch.delenv("GHAS_TRIAGE_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GHAS_LLM_GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("MY_GH_PAT", "pat")
    token, source = _resolve_github_token_for_jira_first(
        {"global": {"github": {"token_env": "MY_GH_PAT"}}},
    )
    assert token == "pat"
    assert source == "env:MY_GH_PAT"


def test_build_jira_github_jql_status_categories() -> None:
    jql = build_jira_github_jql({
        "triage_project": "VM",
        "tool_custom_field": "customfield_1",
        "include_status_categories": ["To Do", "In Progress"],
    })
    assert "statusCategory" in jql
    assert "To Do" in jql
    assert "In Progress" in jql
    assert "status IN" not in jql


def test_format_brief_jira_comment_truncates() -> None:
    long_body = "x" * 5000
    out = _format_brief_jira_comment("dependabot", 1, long_body, "o/r", max_chars=500)
    assert len(out) <= 500
    assert "dependabot #1" not in out
    assert "[GHAS-LLM]" not in out
    assert "ghas-triage-agent" not in out


def test_format_triage_comment() -> None:
    tv = TriageVerdict(
        verdict="true_positive",
        confidence="high",
        reasoning="vulnerable path called",
        code_usage="used in handler.py",
        exploitability="external input",
        suggested_action="upgrade to 2.0",
        severity_assessment="high",
        priority="immediate",
    )
    body = _format_triage_comment("dependabot", 99, tv, "org/repo")
    assert "dependabot #99" in body
    assert "TRUE POSITIVE" in body
    assert "vulnerable path called" in body
    assert "org/repo" in body


@patch("ghas_llm.jira_ghas_cycle.format_recent_commit_authors", return_value="")
@patch("ghas_llm.jira_ghas_cycle.build_context_github_api", return_value=("### API context\n", None))
@patch("ghas_llm.jira_ghas_cycle._get_triage_issue_property", return_value={})
@patch("ghas_llm.jira_ghas_cycle.get_issue_comments", return_value=[])
@patch("ghas_llm.jira_ghas_cycle._latest_bot_comment_for_alert", return_value="")
@patch("ghas_llm.jira_ghas_cycle.add_comment_plain")
@patch("ghas_llm.jira_ghas_cycle.triage_with_openai")
@patch("ghas_llm.jira_ghas_cycle.search_jira_github_tool_issues")
@patch("ghas_llm.jira_ghas_cycle.GitHubClient")
def test_run_jira_first_happy_path(
    mock_gh_cls: MagicMock, mock_search: MagicMock, mock_llm: MagicMock, mock_comment: MagicMock,
    _mock_prior: MagicMock, _mock_comments: MagicMock, _mock_prop: MagicMock, _mock_api: MagicMock, _mock_authors: MagicMock,
) -> None:
    mock_search.return_value = [
        {
            "key": "SEC-55",
            "fields": {
                "summary": "CVE in dep",
                "description": "body /dependabot/alerts/99 end",
                "status": {"name": "Open"},
                "customfield_10206": "dependabot",
                "customfield_10204": "acme/app",
            },
        }
    ]
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.get_repo.return_value = {"default_branch": "main"}
    mock_gh.get_dependabot_alert.return_value = {
        "number": 99,
        "dependency": {"package": {"name": "x", "ecosystem": "npm"}},
        "security_vulnerability": {"severity": "high"},
    }
    mock_llm.return_value = TriageVerdict(
        verdict="true_positive",
        confidence="high",
        reasoning="r",
        code_usage="c",
        exploitability="e",
        suggested_action="s",
        severity_assessment="high",
        priority="immediate",
    )

    os.environ["GITHUB_TOKEN"] = "t"
    os.environ["JIRA_EMAIL"] = "a@b.c"
    os.environ["JIRA_API_TOKEN"] = "j"
    config = {
        "global": {"dry_run": False, "github": {"token_env": "GITHUB_TOKEN"}, "llm": {"api_key_env": "OPENAI_API_KEY"}},
        "agent": {"require_code_validation": True, "max_context_chars": 1000},
        "integrations": {
            "jira": {
                "enabled": True,
                "base_url": "https://test.atlassian.net",
                "email_env": "JIRA_EMAIL",
                "api_token_env": "JIRA_API_TOKEN",
                "triage_project": "VM",
                "tool_custom_field": "customfield_10206",
                "asset_custom_field": "customfield_10204",
            },
            "github": {},
        },
    }
    try:
        out = run_jira_first_ghas_cycle(config, Path("/tmp"))
    finally:
        del os.environ["GITHUB_TOKEN"]
        del os.environ["JIRA_EMAIL"]
        del os.environ["JIRA_API_TOKEN"]

    assert out["summary"]["processed"] == 1
    assert out["summary"]["mode"] == "jira_first"
    mock_gh.get_dependabot_alert.assert_called_once_with("acme", "app", 99)
    mock_comment.assert_called_once()
    r = out["results"][0]
    assert r.get("jira_key") == "SEC-55"
    assert r["routing"] == "in_progress"
    assert r["actions"]["jira_comment"] == "posted"


@patch("ghas_llm.jira_ghas_cycle.triage_with_openai")
@patch("ghas_llm.jira_ghas_cycle.search_jira_github_tool_issues")
@patch("ghas_llm.jira_ghas_cycle.GitHubClient")
def test_run_jira_first_dry_run_no_comment(
    mock_gh_cls: MagicMock, mock_search: MagicMock, mock_llm: MagicMock,
) -> None:
    mock_search.return_value = [
        {
            "key": "SEC-10",
            "fields": {
                "summary": "test",
                "description": "/code-scanning/alerts/5",
                "status": {"name": "Open"},
                "customfield_10206": "code-scanning",
                "customfield_10204": "org/repo",
            },
        }
    ]
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.get_repo.return_value = {"default_branch": "main"}
    mock_gh.get_code_scanning_alert.return_value = {
        "number": 5,
        "rule": {"id": "js/xss", "description": "xss"},
    }
    mock_llm.return_value = TriageVerdict(
        verdict="false_positive", confidence="high",
        reasoning="r", code_usage="c", exploitability="e", suggested_action="s",
        severity_assessment="low", priority="no_action",
    )

    os.environ["GITHUB_TOKEN"] = "t"
    os.environ["JIRA_EMAIL"] = "a@b.c"
    os.environ["JIRA_API_TOKEN"] = "j"
    config = {
        "global": {"dry_run": True, "github": {"token_env": "GITHUB_TOKEN"}, "llm": {"api_key_env": "OPENAI_API_KEY"}},
        "agent": {"require_code_validation": False, "max_context_chars": 1000},
        "integrations": {
            "jira": {
                "enabled": True,
                "base_url": "https://test.atlassian.net",
                "email_env": "JIRA_EMAIL",
                "api_token_env": "JIRA_API_TOKEN",
                "triage_project": "VM",
                "tool_custom_field": "customfield_10206",
                "asset_custom_field": "customfield_10204",
            },
            "github": {},
        },
    }
    try:
        out = run_jira_first_ghas_cycle(config, Path("/tmp"))
    finally:
        del os.environ["GITHUB_TOKEN"]
        del os.environ["JIRA_EMAIL"]
        del os.environ["JIRA_API_TOKEN"]

    assert out["summary"]["processed"] == 1
    r = out["results"][0]
    assert r["actions"]["jira_comment"] == "skipped_dry_run"


def test_run_jira_first_disabled() -> None:
    config = {
        "global": {},
        "integrations": {"jira": {"enabled": False}},
    }
    out = run_jira_first_ghas_cycle(config, Path("/tmp"))
    assert "error" in out["summary"]


@patch("ghas_llm.jira_ghas_cycle.search_jira_github_tool_issues")
@patch("ghas_llm.jira_ghas_cycle.GitHubClient")
def test_run_jira_first_skips_non_ghas(mock_gh_cls: MagicMock, mock_search: MagicMock) -> None:
    mock_search.return_value = [
        {
            "key": "SEC-1",
            "fields": {
                "summary": "terraform issue",
                "description": "not ghas",
                "status": {"name": "Open"},
                "customfield_10206": "terraform",
                "customfield_10204": "org/repo",
            },
        }
    ]
    mock_gh_cls.return_value = MagicMock()

    os.environ["GITHUB_TOKEN"] = "t"
    os.environ["JIRA_EMAIL"] = "a@b.c"
    os.environ["JIRA_API_TOKEN"] = "j"
    config = {
        "global": {"dry_run": True, "github": {"token_env": "GITHUB_TOKEN"}, "llm": {"api_key_env": "OPENAI_API_KEY"}},
        "agent": {},
        "integrations": {
            "jira": {
                "enabled": True,
                "base_url": "https://test.atlassian.net",
                "email_env": "JIRA_EMAIL",
                "api_token_env": "JIRA_API_TOKEN",
                "triage_project": "VM",
                "tool_custom_field": "customfield_10206",
                "asset_custom_field": "customfield_10204",
            },
            "github": {},
        },
    }
    try:
        out = run_jira_first_ghas_cycle(config, Path("/tmp"))
    finally:
        del os.environ["GITHUB_TOKEN"]
        del os.environ["JIRA_EMAIL"]
        del os.environ["JIRA_API_TOKEN"]

    assert out["summary"]["skipped"] == 1
    assert out["results"][0]["skip_reason"] == "tool_not_ghas"


def test_comments_substantively_same() -> None:
    a = "dependabot #1 — o/r\n\nFoo bar.\n\nConclusion: No change needed."
    b = "dependabot #1 — o/r\n\nFoo bar baz.\n\nConclusion: No change needed."
    assert _comments_substantively_same(a, b) is True


@patch("ghas_llm.jira_ghas_cycle.run_agentic_triage")
@patch("ghas_llm.jira_ghas_cycle._get_triage_issue_property", return_value={})
@patch("ghas_llm.jira_ghas_cycle.get_issue_comments")
@patch("ghas_llm.jira_ghas_cycle.add_comment_plain")
@patch("ghas_llm.jira_ghas_cycle.search_jira_github_tool_issues")
@patch("ghas_llm.jira_ghas_cycle.GitHubClient")
def test_run_jira_first_bot_only_unchanged_skips_comment(
    mock_gh_cls: MagicMock,
    mock_search: MagicMock,
    mock_comment: MagicMock,
    mock_comments: MagicMock,
    _mock_prop: MagicMock,
    mock_agentic: MagicMock,
) -> None:
    bot_body = f"{build_bot_marker('dependabot', 9)}\n" + _format_brief_jira_comment(
        "dependabot",
        9,
        "Checked repo.\n\nConclusion: False positive for this repo — no usage.",
        "acme/app",
    )
    mock_comments.return_value = [{"body": bot_body, "author": {"displayName": "Bot"}}]
    mock_search.return_value = [{
        "key": "SEC-9",
        "fields": {
            "summary": "CVE",
            "description": "/dependabot/alerts/9",
            "customfield_10206": "dependabot",
            "customfield_10204": "acme/app",
        },
    }]
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.get_repo.return_value = {"default_branch": "main"}
    mock_gh.get_dependabot_alert.return_value = {
        "number": 9,
        "dependency": {"package": {"name": "x", "ecosystem": "npm"}},
    }
    mock_agentic.return_value = AgenticVerdict(
        routing="false_positive",
        impact="no_direct_usage",
        confidence="high",
        confidence_score=90,
        jira_comment="Checked repo.\n\nConclusion: False positive for this repo — no usage.",
        matrix=EvidenceMatrix(confidence_label="high"),
    )
    os.environ["GHAS_TRIAGE_GITHUB_TOKEN"] = "t"
    os.environ["JIRA_EMAIL"] = "a@b.c"
    os.environ["JIRA_API_TOKEN"] = "j"
    try:
        out = run_jira_first_ghas_cycle(_agentic_test_config(dry=False), Path("/tmp"))
    finally:
        del os.environ["GHAS_TRIAGE_GITHUB_TOKEN"]
        del os.environ["JIRA_EMAIL"]
        del os.environ["JIRA_API_TOKEN"]

    assert out["summary"]["validations_unchanged"] == 1
    assert out["results"][0]["actions"]["jira_comment"] == "skipped_redundant_same_analysis"
    mock_comment.assert_not_called()


@patch("ghas_llm.jira_ghas_cycle.HumanFeedbackAgent.record")
@patch("ghas_llm.jira_ghas_cycle.run_agentic_triage")
@patch("ghas_llm.jira_ghas_cycle._get_triage_issue_property", return_value={})
@patch("ghas_llm.jira_ghas_cycle.get_issue_comments")
@patch("ghas_llm.jira_ghas_cycle.add_comment_plain")
@patch("ghas_llm.jira_ghas_cycle.search_jira_github_tool_issues")
@patch("ghas_llm.jira_ghas_cycle.GitHubClient")
def test_run_jira_first_human_after_bot_learns_and_skips(
    mock_gh_cls: MagicMock,
    mock_search: MagicMock,
    mock_comment: MagicMock,
    mock_comments: MagicMock,
    _mock_prop: MagicMock,
    mock_agentic: MagicMock,
    mock_record: MagicMock,
) -> None:
    bot_body = f"{build_bot_marker('dependabot', 10)}\ndependabot #10 — acme/app\n\nConclusion: Needs human review — unclear."
    mock_comments.return_value = [
        {"body": "This is used in prod, please fix.", "author": {"displayName": "Alice"}, "created": "today"},
        {"body": bot_body, "author": {"displayName": "Bot"}, "created": "yesterday"},
    ]
    mock_search.return_value = [{
        "key": "SEC-10",
        "fields": {
            "summary": "CVE",
            "description": "/dependabot/alerts/10",
            "customfield_10206": "dependabot",
            "customfield_10204": "acme/app",
        },
    }]
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.get_repo.return_value = {"default_branch": "main"}
    mock_gh.get_dependabot_alert.return_value = {
        "number": 10,
        "dependency": {"package": {"name": "x", "ecosystem": "npm"}},
    }
    os.environ["GHAS_TRIAGE_GITHUB_TOKEN"] = "t"
    os.environ["JIRA_EMAIL"] = "a@b.c"
    os.environ["JIRA_API_TOKEN"] = "j"
    try:
        out = run_jira_first_ghas_cycle(_agentic_test_config(dry=False), Path("/tmp"))
    finally:
        del os.environ["GHAS_TRIAGE_GITHUB_TOKEN"]
        del os.environ["JIRA_EMAIL"]
        del os.environ["JIRA_API_TOKEN"]

    assert out["summary"]["human_replies_learned"] == 1
    assert out["results"][0]["human_feedback_learned"] is True
    mock_record.assert_called_once()
    mock_agentic.assert_not_called()
    mock_comment.assert_not_called()


def test_comment_has_no_hidden_markers() -> None:
    body = _format_brief_jira_comment("dependabot", 1, "Some text.\nConclusion: ok.", "o/r")
    assert "<!-- ghas-triage-agent" not in body
    assert "[GHAS-LLM]" not in body
    assert "dependabot #1" not in body
    assert "Conclusion:" not in body


def test_dependabot_fast_path_fixed_and_withdrawn() -> None:
    from ghas_llm.agentic_triage import VulnSignature

    fixed = _dependabot_fast_path(
        {"state": "fixed"},
        VulnSignature(package="lodash"),
        "acme/app",
    )
    assert fixed and fixed[0] == "fixed"
    assert "fixed" in fixed[1].lower()

    withdrawn = _dependabot_fast_path(
        {"security_advisory": {"withdrawn_at": "2026-01-01T00:00:00Z"}},
        VulnSignature(package="lodash"),
        "acme/app",
    )
    assert withdrawn and withdrawn[0] == "withdrawn"
    assert "withdrawn" in withdrawn[1].lower()
