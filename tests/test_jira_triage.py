from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from ghas_llm.integrations.jira_integration import JiraError
from ghas_llm.jira_triage import _get_jira_auth, extract_issue_context, triage_jira_issues


def test_extract_issue_context_basic():
    issue = {
        "key": "SEC-123",
        "fields": {
            "summary": "Critical CVE in prod",
            "description": "A vuln was found in dependency X",
            "status": {"name": "Open"},
            "priority": {"name": "High"},
            "labels": ["security", "cve"],
            "assignee": {"displayName": "Alice"},
            "created": "2025-01-01T00:00:00Z",
            "updated": "2025-06-01T00:00:00Z",
        },
    }
    ctx = extract_issue_context(issue)
    assert "SEC-123" in ctx
    assert "Critical CVE in prod" in ctx
    assert "Open" in ctx
    assert "High" in ctx
    assert "Alice" in ctx
    assert "security" in ctx


def test_extract_issue_context_no_assignee():
    issue = {
        "key": "SEC-99",
        "fields": {
            "summary": "Something",
            "description": None,
            "status": {"name": "In Progress"},
            "priority": None,
            "labels": [],
            "assignee": None,
            "created": "",
            "updated": "",
        },
    }
    ctx = extract_issue_context(issue)
    assert "unassigned" in ctx
    assert "SEC-99" in ctx


def test_get_jira_auth_prefers_env_vars() -> None:
    os.environ["JIRA_EMAIL"] = "user@test.com"
    os.environ["JIRA_API_TOKEN"] = "tok123"
    try:
        base, auth = _get_jira_auth({"base_url": "https://x.atlassian.net"})
        assert base == "https://x.atlassian.net"
        assert "Basic" in auth
    finally:
        del os.environ["JIRA_EMAIL"]
        del os.environ["JIRA_API_TOKEN"]


@patch("ghas_llm.jira_triage._get_jira_secret_from_aws")
def test_get_jira_auth_falls_back_to_aws(mock_aws: MagicMock) -> None:
    mock_aws.return_value = {"email": "bot@example.com", "token": "aws-tok"}
    for k in ("JIRA_EMAIL", "JIRA_API_TOKEN"):
        os.environ.pop(k, None)
    cfg = {
        "base_url": "https://x.atlassian.net",
        "aws_secret_name": "your-org/jira/ghas-triage",
        "aws_secret_region": "us-east-2",
    }
    base, auth = _get_jira_auth(cfg)
    assert base == "https://x.atlassian.net"
    assert "Basic" in auth
    mock_aws.assert_called_once_with("your-org/jira/ghas-triage", "us-east-2")


def test_get_jira_auth_raises_when_nothing_configured() -> None:
    for k in ("JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_SECRET_NAME"):
        os.environ.pop(k, None)
    with pytest.raises(JiraError, match="missing Jira credentials"):
        _get_jira_auth({"base_url": "https://x.atlassian.net"})


def test_triage_jira_disabled():
    config = {"integrations": {"jira": {"enabled": False}}}
    result = triage_jira_issues(config)
    assert result["jira_triage"] == "disabled"


def test_triage_jira_not_enabled():
    config = {
        "integrations": {
            "jira": {
                "enabled": True,
                "triage_existing_issues": False,
            }
        }
    }
    result = triage_jira_issues(config)
    assert result["jira_triage"] == "triage_existing_issues not enabled"


@patch("ghas_llm.jira_triage.search_open_issues")
@patch("ghas_llm.llm_triage.triage_with_openai")
def test_triage_jira_end_to_end(mock_triage: MagicMock, mock_search: MagicMock) -> None:
    from ghas_llm.models import TriageVerdict
    mock_search.return_value = [
        {
            "key": "SEC-10",
            "fields": {
                "summary": "Log4j in prod service",
                "description": "CVE-2021-44228",
                "status": {"name": "Open"},
                "priority": {"name": "Critical"},
                "labels": [],
                "assignee": None,
                "created": "2025-01-01",
                "updated": "2025-01-02",
            },
        }
    ]
    mock_triage.return_value = TriageVerdict(
        verdict="true_positive",
        confidence="high",
        reasoning="Log4j is critical",
        code_usage="used in backend",
        exploitability="remote",
        suggested_action="patch immediately",
        severity_assessment="critical",
        priority="immediate",
    )
    config = {
        "integrations": {
            "jira": {
                "enabled": True,
                "triage_existing_issues": True,
                "base_url": "https://test.atlassian.net",
                "email_env": "JIRA_EMAIL",
                "api_token_env": "JIRA_API_TOKEN",
                "triage_project": "VM",
                "triage_max_results": 10,
            }
        },
        "global": {"llm": {"api_key_env": "OPENAI_API_KEY"}},
    }
    result = triage_jira_issues(config)
    assert result["jira_triage"] == "completed"
    assert result["issues_triaged"] == 1
    assert result["results"][0]["jira_key"] == "SEC-10"
    assert result["results"][0]["verdict"]["verdict"] == "true_positive"
