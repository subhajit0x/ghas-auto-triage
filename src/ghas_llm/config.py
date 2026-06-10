from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def default_config_path() -> Path:
    env = os.environ.get("GHAS_LLM_CONFIG")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parent.parent.parent / "ghas_llm.yaml"


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Allow CI/local overrides without editing YAML (see README)."""
    dry = os.environ.get("GHAS_LLM_DRY_RUN", "").strip().lower()
    if dry in ("1", "true", "yes"):
        data.setdefault("global", {})["dry_run"] = True
    elif dry in ("0", "false", "no"):
        data.setdefault("global", {})["dry_run"] = False

    jira_en = os.environ.get("GHAS_LLM_JIRA_ENABLED", "").strip().lower()
    if jira_en in ("1", "true", "yes"):
        data.setdefault("integrations", {}).setdefault("jira", {})["enabled"] = True
    elif jira_en in ("0", "false", "no"):
        data.setdefault("integrations", {}).setdefault("jira", {})["enabled"] = False

    allow_jql_override = os.environ.get("GHAS_LLM_ALLOW_JIRA_JQL_OVERRIDE", "").strip().lower()
    jira_jql = os.environ.get("GHAS_LLM_JIRA_JQL", "").strip()
    if jira_jql and allow_jql_override in ("1", "true", "yes"):
        data.setdefault("integrations", {}).setdefault("jira", {})["jira_github_issues_jql"] = jira_jql

    triage_limit = os.environ.get("GHAS_LLM_TRIAGE_MAX_RESULTS", "").strip()
    if triage_limit:
        try:
            data.setdefault("integrations", {}).setdefault("jira", {})["triage_max_results"] = int(
                triage_limit,
            )
        except ValueError:
            pass

    auto_transition = os.environ.get("GHAS_LLM_AUTO_TRANSITION", "").strip().lower()
    if auto_transition in ("1", "true", "yes"):
        data.setdefault("agent", {})["auto_transition"] = True
    elif auto_transition in ("0", "false", "no"):
        data.setdefault("agent", {})["auto_transition"] = False

    return data


def load_config(path: Path | None = None) -> dict[str, Any]:
    p = path or default_config_path()
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid config (expected mapping): {p}")
    return _apply_env_overrides(data)
