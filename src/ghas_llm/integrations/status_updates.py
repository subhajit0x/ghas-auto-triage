from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ghas_llm.integrations import jira_integration, mapping
from ghas_llm.models import TriageVerdict


def _rank(c: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(c.lower(), 0)


def _meets_min(actual: str, minimum: str) -> bool:
    return _rank(actual) >= _rank(minimum)


def _triage_note(kind: str, number: int, tv: TriageVerdict) -> str:
    sev = getattr(tv, "severity_assessment", "unknown")
    pri = getattr(tv, "priority", "")
    return (
        f"[GHAS-LLM] {kind} #{number}\n\n"
        f"Verdict: {tv.verdict} | Confidence: {tv.confidence} | Severity: {sev} | Priority: {pri}\n\n"
        f"Reasoning: {tv.reasoning}\n\n"
        f"Code usage: {tv.code_usage}\n\n"
        f"Exploitability: {tv.exploitability}\n\n"
        f"Action: {tv.suggested_action}"
    )


def apply_jira_updates(
    *,
    config: dict[str, Any],
    integrations_cfg: dict[str, Any],
    dry_run: bool,
    owner: str,
    repo_name: str,
    kind: str,
    number: int,
    tv: TriageVerdict,
    min_confidence: str,
    mapping_path: Path | None,
    jira_issue_key: str | None = None,
) -> dict[str, Any]:
    actions: dict[str, Any] = {}
    if dry_run:
        actions["note"] = "dry_run: no Jira writes"
        return actions

    maps = mapping.load_mapping(mapping_path)
    row = mapping.find_row(maps, kind, number)

    jira_cfg = integrations_cfg.get("jira") or {}
    meets = _meets_min(tv.confidence, min_confidence)

    st_fp = str(jira_cfg.get("status_false_positive", "false_positive"))
    st_tp = str(jira_cfg.get("status_true_positive", "opened"))
    comment_each = bool(jira_cfg.get("comment_each_triage", True))

    issue_key = (jira_issue_key or (row or {}).get("jira_key") or "").strip()

    if jira_cfg.get("enabled"):
        base = str(jira_cfg.get("base_url", "")).rstrip("/")
        email = os.environ.get(str(jira_cfg.get("email_env", "JIRA_EMAIL")), "")
        token = os.environ.get(str(jira_cfg.get("api_token_env", "JIRA_API_TOKEN")), "")

        if base and email and token and issue_key:
            auth = jira_integration.basic_auth_header(email, token)
            if comment_each:
                try:
                    jira_integration.add_comment_plain(
                        base, auth, issue_key, _triage_note(kind, number, tv)
                    )
                    actions["jira_comment"] = True
                except jira_integration.JiraError as e:
                    actions["jira_comment_error"] = str(e)

            if meets:
                target = st_fp if tv.verdict == "false_positive" else st_tp
                try:
                    jira_integration.transition_to_status_name(base, auth, issue_key, target)
                    actions["jira"] = {"issue": issue_key, "status": target}
                except jira_integration.JiraError as e:
                    actions["jira_transition_error"] = str(e)
        elif jira_cfg.get("enabled"):
            actions["jira_skipped"] = "missing base_url, credentials, or jira_key in mapping file"

    return actions
