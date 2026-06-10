from __future__ import annotations

from typing import Any

from ghas_llm.github_api import GitHubAPIError, GitHubClient
from ghas_llm.models import TriageVerdict


def _marker_in_comments(comments: list[Any], marker: str) -> bool:
    for c in comments:
        body = (c.get("body") if isinstance(c, dict) else None) or ""
        if marker in body:
            return True
    return False


def format_triage_comment_body(marker: str, kind: str, number: int, tv: TriageVerdict) -> str:
    priority_emoji = {
        "immediate": "🔴",
        "next_sprint": "🟡",
        "backlog": "🔵",
        "no_action": "⚪",
    }.get(tv.priority, "")
    return (
        f"{marker}\n"
        "### GHAS-LLM triage\n"
        f"**Alert:** `{kind}` #{number}\n"
        f"**Verdict:** `{tv.verdict}` | **Confidence:** `{tv.confidence}`\n"
        f"**Severity (assessed):** `{tv.severity_assessment}` | "
        f"**Priority:** {priority_emoji} `{tv.priority}`\n\n"
        f"**Reasoning:** {tv.reasoning}\n\n"
        f"**Code usage:** {tv.code_usage}\n\n"
        f"**Exploitability:** {tv.exploitability}\n\n"
        f"**Suggested action:** {tv.suggested_action}\n"
    )


def post_triage_comment_on_github_alert(
    client: GitHubClient,
    owner: str,
    repo: str,
    kind: str,
    number: int,
    tv: TriageVerdict,
    *,
    marker: str,
    dry_run: bool,
) -> dict[str, Any]:
    if dry_run:
        return {"github_alert_comment": "skipped_dry_run", "would_post": True}

    body = format_triage_comment_body(marker, kind, number, tv)

    try:
        if kind == "dependabot":
            existing = client.list_dependabot_alert_comments(owner, repo, number)
            if _marker_in_comments(existing, marker):
                return {"github_alert_comment": "skipped_already_triaged"}
            client.create_dependabot_alert_comment(owner, repo, number, body)
            return {"github_alert_comment": "created"}

        if kind == "code_scanning":
            existing = client.list_code_scanning_alert_comments(owner, repo, number)
            if _marker_in_comments(existing, marker):
                return {"github_alert_comment": "skipped_already_triaged"}
            client.create_code_scanning_alert_comment(owner, repo, number, body)
            return {"github_alert_comment": "created"}

        if kind == "secret_scanning":
            existing = client.list_secret_scanning_alert_comments(owner, repo, number)
            if _marker_in_comments(existing, marker):
                return {"github_alert_comment": "skipped_already_triaged"}
            try:
                client.create_secret_scanning_alert_comment(owner, repo, number, body)
                return {"github_alert_comment": "created"}
            except GitHubAPIError as e:
                if e.status in (403, 404):
                    return {
                        "github_alert_comment": "not_available",
                        "detail": "Secret alert comments may require Human Review.",
                    }
                raise
    except GitHubAPIError as e:
        return {"github_alert_comment": "error", "github_error": str(e), "status": e.status}

    return {"github_alert_comment": "unknown_kind"}
