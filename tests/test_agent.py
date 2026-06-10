from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from ghas_llm.agent import run_triage_cycle


MOCK_LLM_RESPONSE = json.dumps({
    "verdict": "true_positive",
    "confidence": "high",
    "reasoning": "urllib3 < 2.0 is used in production code",
    "code_usage": "HTTP client in api_client.py",
    "exploitability": "any network request can trigger SSRF",
    "suggested_action": "upgrade urllib3 to >= 2.0.0",
    "severity_assessment": "high",
    "priority": "immediate",
})


def _mock_openai_client():
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=MOCK_LLM_RESPONSE))]
    )
    return client


@patch("ghas_llm.llm_triage.build_openai_client")
@patch("ghas_llm.agent.GitHubClient")
def test_full_triage_cycle_dry_run(mock_gh_cls: MagicMock, mock_llm: MagicMock) -> None:
    mock_llm.return_value = _mock_openai_client()
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.list_dependabot_alerts.return_value = [
        {"number": 1, "dependency": {"package": {"ecosystem": "pip", "name": "urllib3"}},
         "security_vulnerability": {"severity": "high"}, "manifest_path": "requirements.txt"},
    ]
    mock_gh.list_code_scanning_alerts.return_value = []
    mock_gh.list_secret_scanning_alerts.return_value = []

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "requirements.txt").write_text("urllib3==1.26.5\n")
        config = {
            "global": {"dry_run": True, "max_alerts_per_kind": 5,
                       "github": {"token_env": "GITHUB_TOKEN"},
                       "llm": {"api_key_env": "OPENAI_API_KEY"}},
            "alerts": {"dependabot": True, "code_scanning": True, "secret_scanning": True},
            "agent": {"require_code_validation": True, "min_confidence_for_status_change": "high",
                      "max_context_chars": 24000},
            "dedup": {"enabled": False},
            "integrations": {"github": {"post_triage_comments": True, "comment_marker": "<!-- ghas-llm -->"}},
        }
        os.environ["GITHUB_TOKEN"] = "ghp_test"
        os.environ["OPENAI_API_KEY"] = "sk-test"
        try:
            result = run_triage_cycle(config, "test-org/test-repo", repo_root)
        finally:
            del os.environ["GITHUB_TOKEN"]
            del os.environ["OPENAI_API_KEY"]

    assert result["summary"]["processed"] == 1
    assert result["summary"]["errors"] == 0
    assert result["summary"]["dry_run"] is True
    r = result["results"][0]
    assert r["verdict"]["verdict"] == "true_positive"
    assert r["verdict"]["severity_assessment"] == "high"
    assert r["verdict"]["priority"] == "immediate"
    assert r["actions"]["github_alert_comment"] == "skipped_dry_run"


@patch("ghas_llm.llm_triage.build_openai_client")
@patch("ghas_llm.agent.GitHubClient")
def test_triage_cycle_dedup_persistence(mock_gh_cls: MagicMock, mock_llm: MagicMock) -> None:
    mock_llm.return_value = _mock_openai_client()
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.list_dependabot_alerts.return_value = [
        {"number": 42, "dependency": {"package": {"ecosystem": "pip", "name": "x"}},
         "security_vulnerability": {"severity": "low"}, "manifest_path": "req.txt"},
    ]
    mock_gh.list_code_scanning_alerts.return_value = []
    mock_gh.list_secret_scanning_alerts.return_value = []
    mock_gh.list_dependabot_alert_comments.return_value = []

    test_dir = Path(__file__).resolve().parent / "_test_dedup_tmp"
    test_dir.mkdir(exist_ok=True)
    repo_root = test_dir
    (repo_root / "req.txt").write_text("x==1.0\n")
    dedup_file = test_dir / "dedup.json"
    if dedup_file.exists():
        dedup_file.unlink()
    config = {
        "global": {"dry_run": False, "max_alerts_per_kind": 5,
                   "github": {"token_env": "GITHUB_TOKEN"},
                   "llm": {"api_key_env": "OPENAI_API_KEY"}},
        "alerts": {"dependabot": True, "code_scanning": True, "secret_scanning": True},
        "agent": {"require_code_validation": True, "min_confidence_for_status_change": "high",
                  "max_context_chars": 24000},
        "dedup": {"enabled": True, "skip_triage_if_processed": True,
                  "state_file": str(dedup_file)},
        "integrations": {"github": {"post_triage_comments": True, "comment_marker": "<!-- ghas-llm -->"}},
    }
    os.environ["GITHUB_TOKEN"] = "ghp_test"
    os.environ["OPENAI_API_KEY"] = "sk-test"
    try:
        run_triage_cycle(config, "o/r", repo_root)
    finally:
        del os.environ["GITHUB_TOKEN"]
        del os.environ["OPENAI_API_KEY"]

    assert dedup_file.is_file()
    saved = json.loads(dedup_file.read_text())
    assert "dependabot:42" in saved
    import shutil
    shutil.rmtree(test_dir, ignore_errors=True)


@patch("ghas_llm.llm_triage.build_openai_client")
@patch("ghas_llm.agent.GitHubClient")
def test_triage_handles_api_errors(mock_gh_cls: MagicMock, mock_llm: MagicMock) -> None:
    mock_llm.return_value = _mock_openai_client()
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    from ghas_llm.github_api import GitHubAPIError
    mock_gh.list_dependabot_alerts.side_effect = GitHubAPIError(403, "forbidden", "no access")
    mock_gh.list_code_scanning_alerts.return_value = []
    mock_gh.list_secret_scanning_alerts.return_value = []

    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            "global": {"dry_run": True, "max_alerts_per_kind": 5,
                       "github": {"token_env": "GITHUB_TOKEN"},
                       "llm": {"api_key_env": "OPENAI_API_KEY"}},
            "alerts": {"dependabot": True, "code_scanning": True, "secret_scanning": True},
            "agent": {"require_code_validation": True, "min_confidence_for_status_change": "high"},
            "dedup": {"enabled": False},
            "integrations": {},
        }
        os.environ["GITHUB_TOKEN"] = "ghp_test"
        os.environ["OPENAI_API_KEY"] = "sk-test"
        try:
            result = run_triage_cycle(config, "o/r", Path(tmpdir))
        finally:
            del os.environ["GITHUB_TOKEN"]
            del os.environ["OPENAI_API_KEY"]

    assert result["summary"]["errors"] >= 1


MOCK_FP_RESPONSE = json.dumps({
    "verdict": "false_positive",
    "confidence": "high",
    "reasoning": "not used in production",
    "code_usage": "only in test fixtures",
    "exploitability": "none",
    "suggested_action": "dismiss",
    "severity_assessment": "low",
    "priority": "no_action",
})


def _mock_fp_openai_client():
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=MOCK_FP_RESPONSE))]
    )
    return client


@patch("ghas_llm.llm_triage.build_openai_client")
@patch("ghas_llm.agent.GitHubClient")
def test_auto_resolve_in_triage_cycle(mock_gh_cls: MagicMock, mock_llm: MagicMock) -> None:
    mock_llm.return_value = _mock_fp_openai_client()
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.list_dependabot_alerts.return_value = [
        {"number": 10, "dependency": {"package": {"ecosystem": "pip", "name": "old-pkg"}},
         "security_vulnerability": {"severity": "low"}, "manifest_path": "req.txt"},
    ]
    mock_gh.list_code_scanning_alerts.return_value = []
    mock_gh.list_secret_scanning_alerts.return_value = []
    mock_gh.list_dependabot_alert_comments.return_value = []
    mock_gh.dismiss_dependabot_alert.return_value = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "req.txt").write_text("old-pkg==0.1\n")
        config = {
            "global": {"dry_run": False, "max_alerts_per_kind": 5,
                       "github": {"token_env": "GITHUB_TOKEN"},
                       "llm": {"api_key_env": "OPENAI_API_KEY"}},
            "alerts": {"dependabot": True, "code_scanning": True, "secret_scanning": True},
            "agent": {"require_code_validation": True, "min_confidence_for_status_change": "high",
                      "max_context_chars": 24000,
                      "auto_resolve_enabled": True, "auto_resolve_min_confidence": "high"},
            "dedup": {"enabled": False},
            "integrations": {"github": {"post_triage_comments": True, "comment_marker": "<!-- ghas-llm -->"}},
        }
        os.environ["GITHUB_TOKEN"] = "ghp_test"
        os.environ["OPENAI_API_KEY"] = "sk-test"
        try:
            result = run_triage_cycle(config, "test-org/test-repo", repo_root)
        finally:
            del os.environ["GITHUB_TOKEN"]
            del os.environ["OPENAI_API_KEY"]

    assert result["summary"]["processed"] == 1
    assert result["summary"]["auto_resolved"] == 1
    r = result["results"][0]
    assert r["actions"]["auto_resolve"] == "dismissed"
    mock_gh.dismiss_dependabot_alert.assert_called_once()


@patch("ghas_llm.llm_triage.build_openai_client")
@patch("ghas_llm.agent.GitHubClient")
def test_auto_resolve_skipped_dry_run(mock_gh_cls: MagicMock, mock_llm: MagicMock) -> None:
    mock_llm.return_value = _mock_fp_openai_client()
    mock_gh = MagicMock()
    mock_gh_cls.return_value = mock_gh
    mock_gh.list_dependabot_alerts.return_value = [
        {"number": 20, "dependency": {"package": {"ecosystem": "pip", "name": "x"}},
         "security_vulnerability": {"severity": "low"}, "manifest_path": "req.txt"},
    ]
    mock_gh.list_code_scanning_alerts.return_value = []
    mock_gh.list_secret_scanning_alerts.return_value = []

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        (repo_root / "req.txt").write_text("x==0.1\n")
        config = {
            "global": {"dry_run": True, "max_alerts_per_kind": 5,
                       "github": {"token_env": "GITHUB_TOKEN"},
                       "llm": {"api_key_env": "OPENAI_API_KEY"}},
            "alerts": {"dependabot": True, "code_scanning": True, "secret_scanning": True},
            "agent": {"require_code_validation": True, "min_confidence_for_status_change": "high",
                      "max_context_chars": 24000,
                      "auto_resolve_enabled": True, "auto_resolve_min_confidence": "high"},
            "dedup": {"enabled": False},
            "integrations": {"github": {"post_triage_comments": True, "comment_marker": "<!-- ghas-llm -->"}},
        }
        os.environ["GITHUB_TOKEN"] = "ghp_test"
        os.environ["OPENAI_API_KEY"] = "sk-test"
        try:
            result = run_triage_cycle(config, "test-org/test-repo", repo_root)
        finally:
            del os.environ["GITHUB_TOKEN"]
            del os.environ["OPENAI_API_KEY"]

    assert result["summary"]["auto_resolved"] == 0
    r = result["results"][0]
    assert r["actions"]["auto_resolve"] == "skipped_dry_run"
    mock_gh.dismiss_dependabot_alert.assert_not_called()
