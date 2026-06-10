from __future__ import annotations

import os
from pathlib import Path

from ghas_llm.config import load_config


def test_load_config_env_dry_run_override(tmp_path: Path) -> None:
    p = tmp_path / "ghas_llm.yaml"
    p.write_text(
        "global:\n  dry_run: true\nintegrations:\n  jira:\n    enabled: true\n",
        encoding="utf-8",
    )
    os.environ["GHAS_LLM_DRY_RUN"] = "false"
    try:
        cfg = load_config(p)
        assert cfg["global"]["dry_run"] is False
    finally:
        del os.environ["GHAS_LLM_DRY_RUN"]


def test_load_config_env_jira_enabled_override(tmp_path: Path) -> None:
    p = tmp_path / "ghas_llm.yaml"
    p.write_text(
        "global:\n  dry_run: true\nintegrations:\n  jira:\n    enabled: true\n",
        encoding="utf-8",
    )
    os.environ["GHAS_LLM_JIRA_ENABLED"] = "false"
    try:
        cfg = load_config(p)
        assert cfg["integrations"]["jira"]["enabled"] is False
    finally:
        del os.environ["GHAS_LLM_JIRA_ENABLED"]


def test_load_config_env_jira_jql_override_requires_allow_flag(tmp_path: Path) -> None:
    p = tmp_path / "ghas_llm.yaml"
    p.write_text(
        "global:\n  dry_run: true\nintegrations:\n  jira:\n    enabled: true\n",
        encoding="utf-8",
    )
    os.environ["GHAS_LLM_JIRA_JQL"] = 'project = VM AND key = "SEC-9999"'
    try:
        cfg = load_config(p)
        assert "jira_github_issues_jql" not in cfg["integrations"]["jira"]
    finally:
        del os.environ["GHAS_LLM_JIRA_JQL"]


def test_load_config_env_jira_jql_override_when_allowed(tmp_path: Path) -> None:
    p = tmp_path / "ghas_llm.yaml"
    p.write_text(
        "global:\n  dry_run: true\nintegrations:\n  jira:\n    enabled: true\n",
        encoding="utf-8",
    )
    os.environ["GHAS_LLM_JIRA_JQL"] = 'project = VM AND key = "SEC-9999"'
    os.environ["GHAS_LLM_ALLOW_JIRA_JQL_OVERRIDE"] = "true"
    try:
        cfg = load_config(p)
        assert cfg["integrations"]["jira"]["jira_github_issues_jql"] == 'project = VM AND key = "SEC-9999"'
    finally:
        del os.environ["GHAS_LLM_JIRA_JQL"]
        del os.environ["GHAS_LLM_ALLOW_JIRA_JQL_OVERRIDE"]
