from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from ghas_llm.cli import main


@patch("ghas_llm.cli.load_config")
@patch("ghas_llm.jira_ghas_cycle.run_jira_first_ghas_cycle")
def test_jira_first_flag(mock_run: MagicMock, mock_cfg: MagicMock, capsys, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    mock_cfg.return_value = {
        "integrations": {"jira": {"enabled": True, "base_url": "https://x.atlassian.net"}},
        "global": {"github": {"token_env": "GITHUB_TOKEN"}, "llm": {"api_key_env": "OPENAI_API_KEY"}},
    }
    mock_run.return_value = {"summary": {"mode": "jira_first", "processed": 0}, "results": []}
    rc = main(["--jira-first"])
    assert rc == 0
    mock_run.assert_called_once()
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["mode"] == "jira_first"


@patch("ghas_llm.cli.load_config")
def test_triage_jira_flag(mock_cfg: MagicMock, capsys) -> None:
    mock_cfg.return_value = {
        "integrations": {"jira": {"enabled": False}},
        "global": {"llm": {"api_key_env": "OPENAI_API_KEY"}},
    }
    rc = main(["--triage-jira"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["jira_triage"] == "disabled"


@patch("ghas_llm.cli.load_config")
@patch("ghas_llm.cli.run_triage_cycle")
def test_scan_org_flag(mock_cycle: MagicMock, mock_cfg: MagicMock, capsys, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    mock_cfg.return_value = {
        "global": {"github": {"token_env": "GITHUB_TOKEN"}, "llm": {"api_key_env": "OPENAI_API_KEY"}},
    }
    mock_cycle.return_value = {"summary": {"processed": 1}, "results": []}

    mock_client_instance = MagicMock()
    mock_client_instance.list_org_repos_with_security.return_value = [
        {"full_name": "myorg/repo-a", "private": False, "default_branch": "main", "security_and_analysis": {}},
    ]
    with patch("ghas_llm.cli.GitHubClient", return_value=mock_client_instance):
        rc = main(["--scan-org", "myorg"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, list)
    assert len(out) == 1
    assert out[0]["repo"] == "myorg/repo-a"
