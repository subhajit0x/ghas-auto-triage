from __future__ import annotations

from typing import Any

from ghas_llm.github_api import GitHubAPIError, GitHubClient
from ghas_llm.models import TriageVerdict


DISMISS_REASONS = {
    "dependabot": {
        "false_positive": "inaccurate",
        "no_action": "no_bandwidth",
        "default": "not_used",
    },
    "code_scanning": {
        "false_positive": "false positive",
        "no_action": "won't fix",
        "default": "used in tests",
    },
}


def _build_comment(tv: TriageVerdict, kind: str, number: int) -> str:
    return (
        f"Auto-resolved by GHAS-LLM agent.\n"
        f"Verdict: {tv.verdict} | Confidence: {tv.confidence} | "
        f"Severity: {tv.severity_assessment} | Priority: {tv.priority}\n"
        f"Reasoning: {tv.reasoning[:500]}\n"
        f"Suggested: {tv.suggested_action[:300]}"
    )


def should_auto_resolve(tv: TriageVerdict, agent_cfg: dict[str, Any]) -> bool:
    if not agent_cfg.get("auto_resolve_enabled"):
        return False
    if tv.verdict != "false_positive":
        return False
    min_conf = str(agent_cfg.get("auto_resolve_min_confidence", "high")).lower()
    rank = {"low": 0, "medium": 1, "high": 2}
    return rank.get(tv.confidence, 0) >= rank.get(min_conf, 2)


def auto_resolve_alert(
    client: GitHubClient,
    owner: str,
    repo: str,
    kind: str,
    number: int,
    tv: TriageVerdict,
    *,
    dry_run: bool,
) -> dict[str, Any]:
    if dry_run:
        return {"auto_resolve": "skipped_dry_run", "would_dismiss": True}

    comment = _build_comment(tv, kind, number)
    try:
        if kind == "dependabot":
            reasons = DISMISS_REASONS["dependabot"]
            reason = reasons.get(tv.verdict, reasons["default"])
            client.dismiss_dependabot_alert(owner, repo, number, reason, comment)
            return {"auto_resolve": "dismissed", "reason": reason}

        if kind == "code_scanning":
            reasons = DISMISS_REASONS["code_scanning"]
            reason = reasons.get(tv.verdict, reasons["default"])
            client.dismiss_code_scanning_alert(owner, repo, number, reason, comment)
            return {"auto_resolve": "dismissed", "reason": reason}

        if kind == "secret_scanning":
            client.resolve_secret_scanning_alert(owner, repo, number, "false_positive", comment)
            return {"auto_resolve": "resolved", "resolution": "false_positive"}

    except GitHubAPIError as e:
        return {"auto_resolve": "error", "status": e.status, "detail": str(e)}

    return {"auto_resolve": "unknown_kind"}
