"""Jira-first triage: poll Jira for GHAS tickets, fetch alerts from GitHub (read-only), LLM triage, comment on Jira."""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


from ghas_llm.context_builder import (
    build_context,
    locations_from_code_scanning,
    locations_from_secret_scanning,
    paths_from_dependabot,
)
from ghas_llm.agentic_triage import (
    VulnSignature,
    agentic_triage as run_agentic_triage,
    load_previous_run_hint,
)
from ghas_llm.agents.comment_scanner_agent import (
    CommentScannerAgent,
    strip_bot_marker,
)
from ghas_llm.agents.human_feedback_agent import HumanFeedbackAgent
from ghas_llm.context_github_api import (
    build_context_github_api,
    format_recent_commit_authors,
    format_repo_metadata_block,
)
from ghas_llm.github_api import GitHubAPIError, GitHubClient
from ghas_llm.integrations.jira_integration import (
    JiraError,
    _request,
    add_comment_plain,
    basic_auth_header,
    get_issue_property,
    get_issue_comments,
    set_issue_property,
    transition_to_status_name,
)
from ghas_llm.integrations.memory_store import TriageMemoryStore
from ghas_llm.integrations.slack_notify import maybe_notify_slack
from ghas_llm.jira_triage import _get_jira_auth
from ghas_llm.logic.consistency_gate import apply_consistency_gate
from ghas_llm.logic.human_comment import (
    humanize,
    render_fixed_comment,
    render_missing_alert_comment,
    render_withdrawn_comment,
)
from ghas_llm.logic.syllogism import strip_internal_metadata
from ghas_llm.llm_triage import (
    brief_structured_review_with_openai,
    summarize_alert_for_llm,
    triage_with_openai,
)
from ghas_llm.models import AlertResult, TriageVerdict


def _env_field(jira_cfg: dict[str, Any], key: str, default: str) -> str:
    env_name = jira_cfg.get(f"{key}_env")
    if env_name:
        v = os.environ.get(str(env_name), "").strip()
        if v:
            return v
    return str(jira_cfg.get(key, default) or default)


def _field_value(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, dict):
        return str(raw.get("value") or raw.get("name") or raw.get("id") or "")
    return str(raw).strip()


def _flatten_description(desc: Any) -> str:
    """Extract all text + link hrefs from Jira Cloud ADF or plain string."""
    if desc is None:
        return ""
    if isinstance(desc, str):
        return desc
    if not isinstance(desc, dict):
        return str(desc)[:8000]

    def walk(node: Any) -> list[str]:
        out: list[str] = []
        if isinstance(node, dict):
            if node.get("type") == "text" and "text" in node:
                out.append(str(node["text"]))
                for mark in node.get("marks") or []:
                    if isinstance(mark, dict) and mark.get("type") == "link":
                        href = (mark.get("attrs") or {}).get("href", "")
                        if href:
                            out.append(str(href))
            if node.get("type") == "inlineCard":
                url = (node.get("attrs") or {}).get("url", "")
                if url:
                    out.append(str(url))
            for v in node.values():
                out.extend(walk(v))
        elif isinstance(node, list):
            for item in node:
                out.extend(walk(item))
        return out

    return "\n".join(walk(desc))[:8000]


_ALERT_NUM_PATTERNS = (
    re.compile(r"/dependabot/alerts/(\d+)", re.I),
    re.compile(r"/code-scanning/alerts/(\d+)", re.I),
    re.compile(r"/secret-scanning/alerts/(\d+)", re.I),
    re.compile(r"github_issue_id\s*[=:]\s*(\d+)", re.I),
    re.compile(r"alert\s*#?\s*(\d+)", re.I),
)

_GITHUB_ISSUE_ID_RE = re.compile(
    r"github\.com/[^/]+/[^/]+/security/(?:dependabot|code-scanning|secret-scanning)/(\d+)",
    re.I,
)


def _parse_alert_number(fields: dict[str, Any], desc_plain: str, id_field: str) -> int | None:
    if id_field:
        v = _field_value(fields.get(id_field))
        if v.isdigit():
            return int(v)
    for pat in _ALERT_NUM_PATTERNS:
        m = pat.search(desc_plain)
        if m:
            return int(m.group(1))
    m = _GITHUB_ISSUE_ID_RE.search(desc_plain)
    if m:
        return int(m.group(1))
    summary = str(fields.get("summary", ""))
    for pat in _ALERT_NUM_PATTERNS:
        m = pat.search(summary)
        if m:
            return int(m.group(1))
    return None


def tool_string_to_kind(tool_s: str, prefix: str) -> str | None:
    t = tool_s.lower().strip().replace("-", "_").replace(" ", "_")
    if t.startswith("github:"):
        t = t.split(":", 1)[1].strip().replace("-", "_").replace(" ", "_")
    elif prefix and t.startswith(prefix.lower().rstrip(":") + ":"):
        t = t[len(prefix.rstrip(":")) + 1:].strip().replace("-", "_").replace(" ", "_")
    if "dependabot" in t:
        return "dependabot"
    if "code" in t and "scan" in t:
        return "code_scanning"
    if "secret" in t and "scan" in t:
        return "secret_scanning"
    return None


def format_jira_issue_block(issue: dict[str, Any]) -> str:
    fields = issue.get("fields") or {}
    key = issue.get("key", "?")
    summary = str(fields.get("summary", ""))
    desc = _flatten_description(fields.get("description"))
    status = (fields.get("status") or {}).get("name", "")
    priority = (fields.get("priority") or {}).get("name", "")
    assignee = (fields.get("assignee") or {}).get("displayName", "unassigned")
    lines = [
        f"Jira issue: {key}",
        f"Summary: {summary}",
        f"Status: {status} | Priority: {priority} | Assignee: {assignee}",
    ]
    if desc:
        lines.append(f"Description:\n{desc[:4000]}")
    return "\n".join(lines)


def _parse_asset(asset_s: str) -> tuple[str, str] | None:
    s = asset_s.strip()
    if "/" not in s:
        return None
    owner, _, name = s.partition("/")
    if not owner or not name:
        return None
    return owner.strip(), name.strip()


def fetch_github_alert(
    client: GitHubClient, owner: str, repo: str, kind: str, number: int,
) -> dict[str, Any]:
    if kind == "dependabot":
        return client.get_dependabot_alert(owner, repo, number)
    if kind == "code_scanning":
        return client.get_code_scanning_alert(owner, repo, number)
    if kind == "secret_scanning":
        return client.get_secret_scanning_alert(owner, repo, number)
    return {}


def _build_status_clause(jira_cfg: dict[str, Any]) -> str:
    """Build the status filter. Prefer statusCategory — literal status names like 'Open'
    often miss issues whose workflow uses 'To Do', 'Backlog', etc.
    """
    categories = jira_cfg.get("include_status_categories")
    if isinstance(categories, list) and categories:
        parts = []
        for c in categories:
            s = str(c).strip()
            if s:
                parts.append(f'statusCategory = "{s}"')
        if parts:
            return "(" + " OR ".join(parts) + ")"

    included = jira_cfg.get("include_statuses") or []
    excluded = jira_cfg.get("exclude_statuses") or [
        "Done", "Closed", "Resolved", "False Positive",
    ]
    if included:
        return "status IN (" + ", ".join(f'"{s}"' for s in included) + ")"
    return "status NOT IN (" + ", ".join(f'"{s}"' for s in excluded) + ")"


def build_jira_github_jql(jira_cfg: dict[str, Any]) -> str:
    override = (jira_cfg.get("jira_github_issues_jql") or "").strip()
    if override:
        return override
    project = str(jira_cfg.get("triage_project", "VM"))
    tool_field = _env_field(jira_cfg, "tool_custom_field", "customfield_10206")

    stat_clause = _build_status_clause(jira_cfg)

    tool_values = jira_cfg.get("tool_values") or [
        "dependabot", "code-scanning", "secret-scanning",
    ]
    tool_clauses = " OR ".join(f'{tool_field} ~ "{v}"' for v in tool_values)
    order = str(jira_cfg.get("jql_order_by", "updated ASC")).strip()
    suffix = f" ORDER BY {order}" if order else ""
    return (
        f'project = "{project}" AND {stat_clause} '
        f"AND ({tool_clauses}){suffix}"
    )


def search_jira_github_tool_issues(jira_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    base, auth = _get_jira_auth(jira_cfg)
    jql = build_jira_github_jql(jira_cfg)
    configured_limit = int(jira_cfg.get("triage_max_results", jira_cfg.get("max_issues", 50)))
    fetch_all = configured_limit <= 0
    page_size = 100 if fetch_all else min(max(configured_limit, 1), 100)
    tool_field = _env_field(jira_cfg, "tool_custom_field", "customfield_10206")
    asset_field = _env_field(jira_cfg, "asset_custom_field", "customfield_10204")
    id_field = (jira_cfg.get("github_alert_id_custom_field") or "").strip()
    fields_list = [
        "summary", "description", "status", "priority", "created", "updated", "assignee",
        tool_field, asset_field,
    ]
    if id_field:
        fields_list.append(id_field)
    url = f"{base}/rest/api/3/search/jql"
    body: dict[str, Any] = {"jql": jql, "maxResults": page_size, "fields": fields_list}
    all_issues: list[dict[str, Any]] = []
    while True:
        result = _request("POST", url, auth_header=auth, json_body=body)
        if not isinstance(result, dict):
            break
        for i in result.get("issues") or []:
            if isinstance(i, dict):
                all_issues.append(i)
        token = result.get("nextPageToken")
        if not token or (not fetch_all and len(all_issues) >= configured_limit):
            break
        body["nextPageToken"] = token
    return all_issues if fetch_all else all_issues[:configured_limit]


_DEDUP_PATTERN = re.compile(r"Conclusion:\s", re.I)


def _extract_conclusion(text: str) -> str:
    m = re.search(r"Conclusion:\s*(.+?)(?:\n|$)", text, re.I | re.S)
    return (m.group(1).strip() if m else "").strip()


def _latest_bot_comment_for_alert(
    jira_base: str, jira_auth: str, issue_key: str, kind: str, number: int,
) -> str:
    """Most recent review comment body for this alert, or empty."""
    needle = f"{kind} #{number}"
    try:
        comments = get_issue_comments(jira_base, jira_auth, issue_key, max_results=50)
    except JiraError:
        return ""
    for c in comments:
        if not isinstance(c, dict):
            continue
        body = strip_bot_marker(str(c.get("body") or ""))
        if needle in body and _DEDUP_PATTERN.search(body):
            return body
    return ""


def _comments_substantively_same(prev: str, new: str, threshold: float = 0.88) -> bool:
    if not prev or not new:
        return False
    a = _extract_conclusion(prev) or strip_bot_marker(prev)
    b = _extract_conclusion(new) or strip_bot_marker(new)
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio() >= threshold


def _routing_from_comment(text: str) -> str:
    """Infer prior bot routing from the last posted conclusion."""
    conclusion = (_extract_conclusion(text) or text).lower()
    if "false positive" in conclusion or "safe to close" in conclusion:
        return "false_positive"
    if "action needed" in conclusion or "upgrade" in conclusion or "remediate" in conclusion:
        return "in_progress"
    if "needs human review" in conclusion or "needs review" in conclusion:
        return "leave_open"
    return ""


def _reconcile_with_prior_comment(
    *,
    prior_comment: str,
    new_comment: str,
    routing: str,
    confidence: str,
    reproducible: bool,
) -> tuple[str, str, bool]:
    """Avoid unexplained reversals across daily runs.

    If today's result contradicts yesterday and the new evidence is not strong, post a
    needs-review comment instead of flipping from "false positive" to "action needed"
    (or the reverse). Strong findings may update the conclusion, but the comment must
    explicitly say it is correcting prior automation.
    """
    decision = apply_consistency_gate(
        prior_comment=prior_comment,
        new_comment=new_comment,
        routing=routing,
        confidence=confidence,
        reproducible=reproducible,
    )
    return decision.routing, decision.comment, decision.changed


def _format_fetch_error_comment(kind: str, number: int, repo: str, error: str) -> str:
    if kind == "dependabot" and "404" in (error or ""):
        return render_missing_alert_comment(repo)
    return _format_brief_jira_comment(
        kind,
        number,
        (
            f"Automated triage could not fetch this GitHub alert from {repo}: {error}. "
            "This usually means the alert number/repository in Jira is stale or the configured PAT cannot read "
            "that repository's security alerts.\n\n"
            "Conclusion: Needs human review — verify the Jira repo/alert mapping and PAT access before triage."
        ),
        repo,
        routing="leave_open",
    )


def _minimal_signature_from_alert(alert: dict[str, Any]) -> VulnSignature:
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    sv = alert.get("security_vulnerability") or {}
    adv = alert.get("security_advisory") or {}
    sig = VulnSignature(
        package=str(pkg.get("name", "") or ""),
        ecosystem=str(pkg.get("ecosystem", "") or "").lower(),
        severity=str(sv.get("severity", "") or "").lower(),
        affected_versions=str(sv.get("vulnerable_version_range", "") or ""),
        cve_id=str(adv.get("cve_id", "") or ""),
    )
    fv = sv.get("first_patched_version")
    if isinstance(fv, dict):
        sig.fixed_version = str(fv.get("identifier", "") or "")
    elif isinstance(fv, str):
        sig.fixed_version = fv
    return sig


def _format_brief_jira_comment(
    kind: str,
    number: int,
    body: str,
    repo: str,
    max_chars: int = 280,
    routing: str = "",
) -> str:
    rest = humanize(strip_internal_metadata((body or "").strip()), max_chars=max_chars)
    cap = max(200, max_chars)
    if len(rest) > cap:
        rest = rest[: max(0, cap - 2)] + "…"
    return rest


JIRA_TRIAGE_PROPERTY_KEY = "ghas-triage.agent.state"


def _comment_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()[:16]


def _alert_state_payload(
    *,
    kind: str,
    number: int,
    routing: str,
    repository: str,
    comment_body: str,
    package: str = "",
    cve_id: str = "",
    comment_result: Any = None,
    human_memory_version: str = "",
) -> dict[str, Any]:
    created = ""
    comment_id = ""
    if isinstance(comment_result, dict):
        created = str(comment_result.get("created") or "")
        comment_id = str(comment_result.get("id") or "")
    return {
        "v": 1,
        "kind": kind,
        "number": int(number),
        "repository": repository,
        "routing": routing,
        "package": package,
        "cve_id": cve_id,
        "comment_hash": _comment_hash(comment_body),
        "comment_body": comment_body[:4000],
        "comment_created": created,
        "comment_id": comment_id,
        "last_human_memory_version": human_memory_version,
        "updated_at": time.time(),
    }


def _get_triage_issue_property(jira_base: str, jira_auth: str, issue_key: str) -> dict[str, Any]:
    try:
        state = get_issue_property(jira_base, jira_auth, issue_key, JIRA_TRIAGE_PROPERTY_KEY)
    except Exception as exc:  # noqa: BLE001
        log.warning("issue property read %s failed: %s", issue_key, exc)
        return {}
    return state if isinstance(state, dict) else {}


def _set_triage_issue_property(
    jira_base: str,
    jira_auth: str,
    issue_key: str,
    payload: dict[str, Any],
) -> None:
    try:
        set_issue_property(jira_base, jira_auth, issue_key, JIRA_TRIAGE_PROPERTY_KEY, payload)
    except Exception as exc:  # noqa: BLE001
        log.warning("issue property write %s failed: %s", issue_key, exc)


def _dependabot_fast_path(alert: dict[str, Any], sig: VulnSignature, repo: str) -> tuple[str, str] | None:
    state = str(alert.get("state") or "").strip().lower()
    advisory = alert.get("security_advisory") if isinstance(alert.get("security_advisory"), dict) else {}
    withdrawn_at = str(advisory.get("withdrawn_at") or "").strip()
    if state == "fixed":
        return "fixed", render_fixed_comment(sig.package)
    if withdrawn_at or state in {"withdrawn", "auto_dismissed"}:
        return "withdrawn", render_withdrawn_comment(sig.package)
    return None


def _transition_target_for_routing(
    routing: str,
    current_status: str,
    transition_targets: dict[str, Any],
    *,
    allow_false_positive_in_progress: bool = False,
) -> str:
    status = (current_status or "").strip().lower().replace(" ", "_")
    route = (routing or "").strip().lower()
    is_in_progress = status in {"in_progress", "in-progress"}
    is_openish = not is_in_progress and status not in {"closed", "done", "resolved", "false_positive"}

    if route in {"fixed", "withdrawn", "missing_alert"}:
        return str(transition_targets.get(route) or transition_targets.get("fixed") or "Closed")
    if is_in_progress:
        if route == "false_positive" and allow_false_positive_in_progress:
            return str(transition_targets.get("false_positive") or "false_positive")
        return ""
    if is_openish and route == "in_progress":
        return str(transition_targets.get("action_needed") or transition_targets.get("in_progress") or "IN_PROGRESS")
    if is_openish and route == "false_positive":
        return str(transition_targets.get("false_positive") or "false_positive")
    return ""


def _format_triage_comment(kind: str, number: int, tv: Any, repo: str) -> str:
    verdict_label = {
        "true_positive": "TRUE POSITIVE - this vulnerability impacts us",
        "false_positive": "FALSE POSITIVE - this vulnerability does NOT impact us",
        "needs_review": "NEEDS REVIEW - insufficient context for automated decision",
    }.get(tv.verdict, tv.verdict.upper())
    sev = getattr(tv, "severity_assessment", "unknown")
    pri = getattr(tv, "priority", "")
    priority_label = {
        "immediate": "Fix immediately",
        "next_sprint": "Schedule for next sprint",
        "backlog": "Backlog",
        "no_action": "No action required",
    }.get(pri, pri)

    return (
        f"{kind} #{number} ({repo})\n\n"
        f"VERDICT: {verdict_label}\n"
        f"Confidence: {tv.confidence} | Severity: {sev} | Priority: {priority_label}\n\n"
        f"WHY: {tv.reasoning}\n\n"
        f"CODE USAGE: {tv.code_usage}\n\n"
        f"EXPLOITABILITY: {tv.exploitability}\n\n"
        f"RECOMMENDED ACTION: {tv.suggested_action}"
    )


VERDICT_TO_JIRA_STATUS: dict[str, str] = {
    "false_positive": "false_positive",
    "in_progress": "IN_PROGRESS",
}


_DEFAULT_TIER_TRANSITION_FLOORS = {
    "tier_1_critical": 95,
    "tier_2_supporting": 90,
    "tier_3_internal": 85,
    "tier_4_archived": 75,
}


def _tier_floor_for_transition(tier: str, agent_cfg: dict[str, Any]) -> int:
    trust = agent_cfg.get("production_trust", {}) if isinstance(agent_cfg.get("production_trust", {}), dict) else {}
    tier_floors = trust.get("tier_floors", {}) if isinstance(trust.get("tier_floors", {}), dict) else {}
    cfg_tier = tier_floors.get(tier) if isinstance(tier_floors.get(tier), dict) else None
    if cfg_tier and "transition" in cfg_tier:
        try:
            return int(cfg_tier["transition"])
        except (TypeError, ValueError):
            pass
    return int(_DEFAULT_TIER_TRANSITION_FLOORS.get(tier, 90))


def _resolve_github_token_for_jira_first(config: dict[str, Any]) -> tuple[str, str]:
    """Prefer workflow/local PAT env vars over AWS fallback.

    The repo's default GITHUB_TOKEN cannot read alerts/code in other private repos.
    """
    github_cfg = config.get("global", {}).get("github", {})
    configured_env = str(github_cfg.get("token_env", "GHAS_TRIAGE_GITHUB_TOKEN"))
    # GHAS_TRIAGE_GITHUB_TOKEN = org PAT (fine-grained token name ghas-triage-github-token).
    env_names = [
        "GHAS_TRIAGE_GITHUB_TOKEN",
        "GHAS_LLM_GITHUB_TOKEN",
        configured_env,
        "GH_TOKEN",
    ]
    seen: set[str] = set()
    for env_name in env_names:
        if not env_name or env_name in seen:
            continue
        seen.add(env_name)
        token = os.environ.get(env_name, "").strip()
        if token:
            return token, f"env:{env_name}"

    aws_gh_secret = str(github_cfg.get("aws_secret_name", "")).strip()
    if aws_gh_secret:
        try:
            import boto3
            sm = boto3.client("secretsmanager", region_name="us-east-2")
            raw = sm.get_secret_value(SecretId=aws_gh_secret).get("SecretString", "")
            data = json.loads(raw or "{}")
            for key in (
                "GHAS_TRIAGE_GITHUB_TOKEN",
                "GHAS_LLM_GITHUB_TOKEN",
                "GITHUB_TOKEN",
                "token",
            ):
                token = str(data.get(key, "")).strip()
                if token:
                    return token, f"aws:{aws_gh_secret}:{key}"
        except Exception as exc:  # noqa: BLE001
            log.warning("could not fetch GitHub token from AWS SM %s: %s", aws_gh_secret, exc)

    return "", "missing"


def run_jira_first_ghas_cycle(
    config: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    integrations_cfg = config.get("integrations") or {}
    jira_cfg = integrations_cfg.get("jira") or {}

    if not jira_cfg.get("enabled"):
        return {"summary": {"error": "jira.enabled must be true for --jira-first"}, "results": []}

    dry = bool(config.get("global", {}).get("dry_run", True))
    agent_cfg = config.get("agent", {})
    require_ctx = bool(agent_cfg.get("require_code_validation", True))
    max_ctx = int(agent_cfg.get("max_context_chars", 24000))
    prefix = str(jira_cfg.get("github_tool_prefix", ""))

    api_ver = str(config.get("global", {}).get("github", {}).get("api_version", "2022-11-28"))
    token, token_source = _resolve_github_token_for_jira_first(config)

    if not token:
        return {
            "summary": {
                "error": "missing GitHub token (GHAS_TRIAGE_GITHUB_TOKEN/GHAS_LLM_GITHUB_TOKEN/GITHUB_TOKEN/AWS)",
            },
            "results": [],
        }

    os.environ["GITHUB_TOKEN"] = token

    client = GitHubClient(token, api_version=api_ver)
    tool_field = _env_field(jira_cfg, "tool_custom_field", "customfield_10206")
    asset_field = _env_field(jira_cfg, "asset_custom_field", "customfield_10204")
    id_field = (jira_cfg.get("github_alert_id_custom_field") or "").strip()

    effective_jql = build_jira_github_jql(jira_cfg)
    log.info("jira-first JQL: %s", effective_jql)
    try:
        issues = search_jira_github_tool_issues(jira_cfg)
    except JiraError as e:
        return {"summary": {"error": str(e), "mode": "jira_first", "jql": effective_jql}, "results": []}

    jira_base, jira_auth = _get_jira_auth(jira_cfg)

    comment_style = str(agent_cfg.get("jira_comment_style", "structured")).strip().lower()
    fail_if_clone = bool(agent_cfg.get("fail_if_clone_unavailable", False))
    auto_transition = bool(agent_cfg.get("auto_transition", False))
    transition_targets = (
        agent_cfg.get("transition_targets", {})
        if isinstance(agent_cfg.get("transition_targets", {}), dict)
        else {}
    )
    prefer_api_ctx = bool(agent_cfg.get("prefer_github_api_context", True))
    clone_fallback = bool(agent_cfg.get("clone_context_fallback", True))
    agentic_mode = bool(agent_cfg.get("agentic_mode", False))
    dedup_comments = bool(agent_cfg.get("dedup_comments", False))
    history_rel = str(agent_cfg.get("triage_history_file", ".triage_history.jsonl")).strip()
    memory_store = TriageMemoryStore.from_config(config, repo_root)
    org_for_search = str(
        config.get("global", {}).get("github", {}).get("org", "example-org"),
    ).strip()
    repo_branch_cache: dict[tuple[str, str], str] = {}
    repo_meta_cache: dict[tuple[str, str], dict[str, Any]] = {}

    def _repo_meta(owner_r: str, name_r: str) -> dict[str, Any]:
        key = (owner_r, name_r)
        if key in repo_meta_cache:
            return repo_meta_cache[key]
        try:
            meta = client.get_repo(owner_r, name_r)
            if isinstance(meta, dict):
                repo_meta_cache[key] = meta
                return meta
        except GitHubAPIError:
            pass
        repo_meta_cache[key] = {}
        return {}

    def _default_branch(owner_r: str, name_r: str) -> str:
        return str(_repo_meta(owner_r, name_r).get("default_branch", "") or "").strip()

    results: list[dict[str, Any]] = []
    comment_scanner = CommentScannerAgent()
    human_feedback = HumanFeedbackAgent(repo_root, config, memory_store=memory_store)
    triage_cache: dict[tuple[str, str, str, str], Any] = {}

    def _count_skip(reason: str) -> None:
        summary["skipped"] += 1
        skip_reasons = summary.setdefault("skip_reasons", {})
        if isinstance(skip_reasons, dict):
            skip_reasons[reason] = int(skip_reasons.get(reason, 0)) + 1

    summary: dict[str, Any] = {
        "mode": "jira_first",
        "dry_run": dry,
        "jql": effective_jql,
        "github_token_source": token_source,
        "jira_issues_seen": len(issues),
        "processed": 0,
        "skipped": 0,
        "skipped_redundant_comment": 0,
        "transitioned": 0,
        "errors": 0,
        "triage_exceptions": 0,
        "comment_state_counts": {"no_bot_comment": 0, "bot_only": 0, "human_after_bot": 0},
        "validations_unchanged": 0,
        "validations_drift_posted": 0,
        "validations_conflict_review": 0,
        "human_replies_learned": 0,
        "critic_downgrades": 0,
        "skip_reasons": {},
        "tier_breakdown": {},
        "memory_history_lines": 0,
        "memory_feedback_lines": 0,
    }

    for issue in issues:
        key = str(issue.get("key", ""))
        fields = issue.get("fields") or {}
        if not isinstance(fields, dict):
            fields = {}
        tool_s = _field_value(fields.get(tool_field))
        asset_s = _field_value(fields.get(asset_field))
        desc_plain = _flatten_description(fields.get("description"))
        current_status = str((fields.get("status") or {}).get("name", "") or "")

        kind = tool_string_to_kind(tool_s, prefix)
        parsed = _parse_asset(asset_s)
        alert_num = _parse_alert_number(fields, desc_plain, id_field)

        if not kind:
            results.append({"jira_key": key, "skipped": True, "skip_reason": "tool_not_ghas", "tool": tool_s})
            _count_skip("tool_not_ghas")
            continue
        if not parsed:
            results.append({"jira_key": key, "skipped": True, "skip_reason": "asset_not_owner_repo", "asset": asset_s})
            _count_skip("asset_not_owner_repo")
            continue
        if alert_num is None:
            results.append({"jira_key": key, "skipped": True, "skip_reason": "alert_number_not_found"})
            _count_skip("alert_number_not_found")
            continue

        owner, repo_name = parsed
        repo_full = f"{owner}/{repo_name}"

        prior_comment = ""
        comment_state = None
        stored_triage_state: dict[str, Any] = {}
        issue_comments: list[dict[str, Any]] = []
        if not dry:
            try:
                issue_comments = get_issue_comments(jira_base, jira_auth, key, max_results=100)
            except JiraError:
                issue_comments = []
            stored_triage_state = _get_triage_issue_property(jira_base, jira_auth, key)
            if (
                stored_triage_state
                and (
                    str(stored_triage_state.get("kind") or "") != kind
                    or int(stored_triage_state.get("number") or 0) != int(alert_num)
                )
            ):
                stored_triage_state = {}
            comment_state = comment_scanner.classify(
                issue_comments,
                kind=kind,
                number=alert_num,
                stored_state=stored_triage_state,
            )
            prior_comment = comment_state.prior_bot_comment
            if comment_state.state in summary["comment_state_counts"]:
                summary["comment_state_counts"][comment_state.state] += 1
        else:
            summary["comment_state_counts"]["no_bot_comment"] += 1

        try:
            alert = fetch_github_alert(client, owner, repo_name, kind, alert_num)
            if not alert:
                raise GitHubAPIError(404, "empty alert", "")
        except GitHubAPIError as e:
            jira_actions: dict[str, Any] = {}
            comment_body = _format_fetch_error_comment(kind, alert_num, repo_full, str(e))
            if dry:
                jira_actions["jira_comment"] = "skipped_dry_run"
            elif prior_comment and _comments_substantively_same(prior_comment, comment_body, threshold=0.95):
                jira_actions["jira_comment"] = "skipped_redundant_fetch_error"
                summary["skipped_redundant_comment"] += 1
            else:
                try:
                    posted = add_comment_plain(jira_base, jira_auth, key, comment_body)
                    if kind == "dependabot" and getattr(e, "status", 0) == 404:
                        _set_triage_issue_property(
                            jira_base,
                            jira_auth,
                            key,
                            _alert_state_payload(
                                kind=kind,
                                number=alert_num,
                                routing="missing_alert",
                                repository=repo_full,
                                comment_body=comment_body,
                                comment_result=posted,
                            ),
                        )
                    jira_actions["jira_comment"] = "posted_fetch_error"
                except JiraError as jira_exc:
                    jira_actions["jira_comment_error"] = str(jira_exc)
            if kind == "dependabot" and getattr(e, "status", 0) == 404 and auto_transition and not dry:
                target = _transition_target_for_routing("missing_alert", current_status, transition_targets)
                if target:
                    try:
                        transition_to_status_name(jira_base, jira_auth, key, target)
                        jira_actions["jira_transition"] = target
                        summary["transitioned"] += 1
                    except JiraError as jira_exc:
                        jira_actions["jira_transition_error"] = str(jira_exc)
            results.append(
                {
                    "jira_key": key,
                    "kind": kind,
                    "number": alert_num,
                    "repository": repo_full,
                    "error": str(e),
                    "actions": jira_actions,
                    "brief_comment": comment_body,
                },
            )
            summary["errors"] += 1
            continue

        minimal_sig = _minimal_signature_from_alert(alert)
        if kind == "dependabot":
            fast = _dependabot_fast_path(alert, minimal_sig, repo_full)
            if fast:
                routing, comment_body = fast
                jira_actions: dict[str, Any] = {}
                if dry:
                    jira_actions["jira_comment"] = "skipped_dry_run"
                elif prior_comment and _comments_substantively_same(prior_comment, comment_body, threshold=0.95):
                    jira_actions["jira_comment"] = "skipped_redundant_fast_path"
                    summary["skipped_redundant_comment"] += 1
                else:
                    try:
                        posted = add_comment_plain(jira_base, jira_auth, key, comment_body)
                        _set_triage_issue_property(
                            jira_base,
                            jira_auth,
                            key,
                            _alert_state_payload(
                                kind=kind,
                                number=alert_num,
                                routing=routing,
                                repository=repo_full,
                                package=minimal_sig.package,
                                cve_id=minimal_sig.cve_id,
                                comment_body=comment_body,
                                comment_result=posted,
                            ),
                        )
                        jira_actions["jira_comment"] = "posted_fast_path"
                    except JiraError as jira_exc:
                        jira_actions["jira_comment_error"] = str(jira_exc)
                if auto_transition and not dry:
                    target = _transition_target_for_routing(routing, current_status, transition_targets)
                    if target:
                        try:
                            transition_to_status_name(jira_base, jira_auth, key, target)
                            jira_actions["jira_transition"] = target
                            summary["transitioned"] += 1
                        except JiraError as jira_exc:
                            jira_actions["jira_transition_error"] = str(jira_exc)
                            log.warning("transition %s -> %s failed: %s", key, target, jira_exc)
                row_fast: dict[str, Any] = asdict(
                    AlertResult(kind, alert_num, False, None, None, dry, jira_actions),  # type: ignore[arg-type]
                ) | {
                    "jira_key": key,
                    "repository": repo_full,
                    "routing": routing,
                    "impact": "dependabot_fast_path",
                    "package": minimal_sig.package,
                    "cve_id": minimal_sig.cve_id,
                    "comment_state": comment_state.state if comment_state else "no_bot_comment",
                    "brief_comment": comment_body,
                }
                results.append(row_fast)
                summary["processed"] += 1
                memory_store.append_history(
                    {
                        "ts": time.time(),
                        "jira_key": key,
                        "kind": kind,
                        "number": alert_num,
                        "repository": repo_full,
                        "routing": routing,
                        "package": minimal_sig.package,
                        "cve_id": minimal_sig.cve_id,
                        "jira_comment_status": jira_actions.get("jira_comment", ""),
                        "fast_path": True,
                    },
                )
                continue

        try:
            branch = _default_branch(owner, repo_name)

            if agentic_mode:
                jira_actions: dict[str, Any] = {}
                if comment_state and comment_state.state == "human_after_bot":
                    learned = 0
                    for human_comment in comment_state.human_comments_after_bot or [
                        {
                            "body": comment_state.latest_human_comment,
                            "author": comment_state.latest_human_author,
                            "created": comment_state.latest_human_ts,
                        },
                    ]:
                        feedback = human_feedback.record(
                            jira_key=key,
                            repository=repo_full,
                            kind=kind,
                            number=alert_num,
                            signature=minimal_sig,
                            human_text=str(human_comment.get("body") or ""),
                            human_author=str(human_comment.get("author") or ""),
                            created=str(human_comment.get("created") or ""),
                        )
                        learned += 1 if feedback.extracted_reason or feedback.human_verdict_guess != "unknown" else 0
                    summary["human_replies_learned"] += learned
                    jira_actions["jira_comment"] = "skipped_human_after_bot"
                    results.append(
                        asdict(AlertResult(kind, alert_num, False, None, None, dry, jira_actions))  # type: ignore[arg-type]
                        | {
                            "jira_key": key,
                            "repository": repo_full,
                            "routing": comment_state.prior_bot_routing or "leave_open",
                            "comment_state": comment_state.state,
                            "human_feedback_learned": True,
                        },
                    )
                    _count_skip("human_after_bot")
                    continue

                prev_hint = ""
                if history_rel:
                    prev_hint = load_previous_run_hint(
                        repo_root, history_rel, key, memory_store=memory_store,
                    )
                if prior_comment:
                    prior_conclusion = _extract_conclusion(prior_comment) or prior_comment[:500]
                    prev_hint = (
                        f"{prev_hint.strip()}\n"
                        f"Latest Jira bot conclusion: {prior_conclusion}"
                    ).strip()
                human_feedback_context = human_feedback.relevant_examples(
                    signature=minimal_sig,
                    repository=repo_full,
                )
                try:
                    triage_key = (
                        repo_full,
                        kind,
                        minimal_sig.package,
                        minimal_sig.cve_id or str(alert_num),
                    )
                    if triage_key in triage_cache:
                        av = triage_cache[triage_key]
                    else:
                        av = run_agentic_triage(
                            config,
                            client,
                            owner=owner,
                            repo=repo_name,
                            branch=branch,
                            org=org_for_search,
                            alert_kind=kind,
                            alert=alert,
                            previous_run_hint=prev_hint,
                            human_feedback_context=human_feedback_context,
                            repo_root=repo_root,
                            memory_store=memory_store,
                        )
                        triage_cache[triage_key] = av
                    if av.impact in {"critic_downgrade", "confidence_floor"}:
                        summary["critic_downgrades"] += 1
                except Exception as triage_exc:  # noqa: BLE001
                    log.exception("agentic triage failed for %s", key)
                    summary["triage_exceptions"] += 1
                    err_txt = str(triage_exc)[:1800]
                    comment_body = _format_brief_jira_comment(
                        kind,
                        alert_num,
                        f"Automated triage failed ({type(triage_exc).__name__}): {err_txt}\n\n"
                        f"Conclusion: Needs human review — triage pipeline error.",
                        repo_full,
                        routing="leave_open",
                    )
                    routing = "leave_open"
                    if dry:
                        jira_actions["jira_comment"] = "skipped_dry_run"
                    else:
                        try:
                            posted = add_comment_plain(jira_base, jira_auth, key, comment_body)
                            _set_triage_issue_property(
                                jira_base,
                                jira_auth,
                                key,
                                _alert_state_payload(
                                    kind=kind,
                                    number=alert_num,
                                    routing=routing,
                                    repository=repo_full,
                                    package=minimal_sig.package,
                                    cve_id=minimal_sig.cve_id,
                                    comment_body=comment_body,
                                    comment_result=posted,
                                ),
                            )
                            jira_actions["jira_comment"] = "posted_error_notice"
                        except JiraError as e:
                            jira_actions["jira_comment_error"] = str(e)
                    row_err: dict[str, Any] = asdict(
                        AlertResult(kind, alert_num, False, None, None, dry, jira_actions),  # type: ignore[arg-type]
                    ) | {
                        "jira_key": key,
                        "repository": repo_full,
                        "routing": routing,
                        "error": f"agentic_triage: {triage_exc!s}",
                        "brief_comment": comment_body,
                    }
                    results.append(row_err)
                    summary["processed"] += 1
                    summary["errors"] += 1
                    memory_store.append_history(
                        {
                            "ts": time.time(),
                            "jira_key": key,
                            "kind": kind,
                            "number": alert_num,
                            "repository": repo_full,
                            "routing": routing,
                            "jira_comment_status": jira_actions.get("jira_comment", ""),
                            "error": "triage_exception",
                        },
                    )
                    continue

                routing = av.routing
                comment_body = _format_brief_jira_comment(
                    kind, alert_num, av.jira_comment, repo_full, routing=routing,
                )
                routing, comment_body, reconciled = _reconcile_with_prior_comment(
                    prior_comment=prior_comment,
                    new_comment=comment_body,
                    routing=routing,
                    confidence=av.confidence,
                    reproducible=av.reproducible,
                )

                post_comment = True
                if not dry and comment_state and comment_state.state == "bot_only":
                    if _comments_substantively_same(prior_comment, comment_body):
                        post_comment = False
                        summary["validations_unchanged"] += 1
                        summary["skipped_redundant_comment"] += 1
                    elif reconciled and routing == "leave_open":
                        summary["validations_conflict_review"] += 1
                    else:
                        summary["validations_drift_posted"] += 1
                elif dedup_comments and not dry and prior_comment and _comments_substantively_same(
                    prior_comment, comment_body,
                ):
                    post_comment = False
                    summary["skipped_redundant_comment"] += 1

                if dry:
                    jira_actions["jira_comment"] = "skipped_dry_run"
                elif not post_comment:
                    jira_actions["jira_comment"] = "skipped_redundant_same_analysis"
                else:
                    try:
                        posted = add_comment_plain(jira_base, jira_auth, key, comment_body)
                        _set_triage_issue_property(
                            jira_base,
                            jira_auth,
                            key,
                            _alert_state_payload(
                                kind=kind,
                                number=alert_num,
                                routing=routing,
                                repository=repo_full,
                                package=av.signature.package if av.signature else minimal_sig.package,
                                cve_id=av.signature.cve_id if av.signature else minimal_sig.cve_id,
                                comment_body=comment_body,
                                comment_result=posted,
                            ),
                        )
                        jira_actions["jira_comment"] = "posted"
                    except JiraError as e:
                        jira_actions["jira_comment_error"] = str(e)

                if auto_transition and not dry:
                    target = _transition_target_for_routing(routing, current_status, transition_targets)
                    tier_floor_for_transition = _tier_floor_for_transition(av.tier, agent_cfg)
                    if target and av.confidence_score >= tier_floor_for_transition:
                        try:
                            transition_to_status_name(jira_base, jira_auth, key, target)
                            jira_actions["jira_transition"] = target
                            summary["transitioned"] += 1
                        except JiraError as e:
                            jira_actions["jira_transition_error"] = str(e)
                            log.warning("transition %s -> %s failed: %s", key, target, e)
                    elif target:
                        jira_actions["jira_transition_skipped"] = (
                            f"confidence {av.confidence_score} below tier {av.tier} floor "
                            f"{tier_floor_for_transition}"
                        )

                row: dict[str, Any] = asdict(
                    AlertResult(kind, alert_num, False, None, None, dry, jira_actions),  # type: ignore[arg-type]
                ) | {
                    "jira_key": key,
                    "repository": repo_full,
                    "routing": routing,
                    "impact": "prior_comment_conflict" if reconciled and routing == "leave_open" else av.impact,
                    "confidence": av.confidence,
                    "confidence_score": av.confidence_score,
                    "tier": av.tier,
                    "tier_reason": av.tier_reason,
                    "force_verdict": av.force_verdict,
                    "force_reason": av.force_reason,
                    "reproducible": av.reproducible,
                    "reconciled_with_prior_comment": reconciled,
                    "comment_state": comment_state.state if comment_state else "no_bot_comment",
                    "matrix": asdict(av.matrix) if av.matrix else None,
                    "matches": [m.path for m in av.matches[:8]],
                    "blame_authors": av.matrix.blame_authors if av.matrix else [],
                    "org_repos_affected": av.org_repos_affected,
                    "prosecutor_uphold": av.prosecutor_uphold,
                    "prosecutor_attack_holes": av.prosecutor_attack_holes,
                    "deep_dive_count": av.deep_dive_count,
                    "deterministic_short_circuit": av.deterministic_short_circuit,
                    "org_hunter_summary": av.org_hunter_summary,
                    "global_memory_summary": av.global_memory_summary,
                    "brief_comment": comment_body,
                }
                results.append(row)
                summary["processed"] += 1
                tier_breakdown = summary.setdefault("tier_breakdown", {})
                if isinstance(tier_breakdown, dict):
                    tier_breakdown[av.tier] = int(tier_breakdown.get(av.tier, 0)) + 1
                memory_store.append_history(
                    {
                        "ts": time.time(),
                        "jira_key": key,
                        "kind": kind,
                        "number": alert_num,
                        "repository": repo_full,
                        "routing": routing,
                        "tier": av.tier,
                        "force_verdict": av.force_verdict,
                        "package": av.signature.package if av.signature else "",
                        "cve_id": av.signature.cve_id if av.signature else "",
                        "confidence_score": av.confidence_score,
                        "deep_dive_count": av.deep_dive_count,
                        "prosecutor_uphold": av.prosecutor_uphold,
                        "org_hunter_kinds": [
                            line.strip("- ").split(":", 1)[0]
                            for line in (av.org_hunter_summary or "").splitlines()
                            if line.startswith("- ")
                        ][:5],
                        "jira_comment_status": jira_actions.get("jira_comment", ""),
                        "dedup_skipped": not post_comment and not dry,
                        "comment_state": comment_state.state if comment_state else "no_bot_comment",
                    },
                )
                continue

            meta = _repo_meta(owner, repo_name)
            extra_repo = format_repo_metadata_block(meta)
            clone_err: str | None = None
            ctx = ""
            if kind == "dependabot":
                paths = paths_from_dependabot(alert)
                locs: list[tuple[str | None, int | None, int | None]] = []
            elif kind == "code_scanning":
                paths = []
                locs = locations_from_code_scanning(alert)
            else:
                paths = []
                locs = locations_from_secret_scanning(alert)

            if prefer_api_ctx:
                api_ctx, api_err = build_context_github_api(
                    client,
                    owner,
                    repo_name,
                    branch,
                    paths=paths,
                    locations=locs,
                    dependabot_alert=alert if kind == "dependabot" else None,
                    max_chars=max_ctx,
                )
                ctx = api_ctx
                if api_err:
                    clone_err = api_err
                author_blk = format_recent_commit_authors(
                    client, owner, repo_name, branch, paths, locs,
                )
                if author_blk:
                    ctx = f"{ctx}\n\n{author_blk}" if ctx else author_blk

            if clone_fallback and not (ctx or "").strip():
                if kind == "dependabot":
                    ctx2, ce = build_context(
                        repo_root,
                        paths=paths,
                        locations=[],
                        max_chars=max_ctx,
                        clone_owner=owner,
                        clone_repo=repo_name,
                        clone_branch=branch,
                        dependabot_alert=alert,
                    )
                elif kind == "code_scanning":
                    ctx2, ce = build_context(
                        repo_root,
                        paths=[],
                        locations=locs,
                        max_chars=max_ctx,
                        clone_owner=owner,
                        clone_repo=repo_name,
                        clone_branch=branch,
                    )
                else:
                    ctx2, ce = build_context(
                        repo_root,
                        paths=[],
                        locations=locs,
                        max_chars=max_ctx,
                        clone_owner=owner,
                        clone_repo=repo_name,
                        clone_branch=branch,
                    )
                if (ctx2 or "").strip():
                    ctx = f"{ctx}\n\n=== Clone / local context ===\n{ctx2}" if (ctx or "").strip() else ctx2
                if ce:
                    clone_err = ce or clone_err

            if fail_if_clone and clone_err and not (ctx or "").strip():
                results.append(
                    {
                        "jira_key": key,
                        "kind": kind,
                        "number": alert_num,
                        "error": clone_err,
                        "repository": repo_full,
                    },
                )
                summary["errors"] += 1
                continue

            if require_ctx and not (ctx or "").strip():
                ctx = "(no file context available)"
            if clone_err:
                ctx = f"{ctx}\n\n(Context note: {clone_err})"

            jira_ctx = format_jira_issue_block(issue)
            summary_json = summarize_alert_for_llm(kind, alert)
            combined = f"{jira_ctx}\n\n--- GitHub alert ---\n{summary_json}"
            extra_block = extra_repo

            jira_actions: dict[str, Any] = {}
            routing = "leave_open"
            comment_body = ""
            tv_out: TriageVerdict | None = None

            if comment_style == "brief_conclusion":
                bsr = brief_structured_review_with_openai(
                    config,
                    alert_kind=kind,
                    alert_summary=combined,
                    file_context=ctx,
                    extra_context=extra_block,
                )
                routing = bsr.routing
                comment_body = _format_brief_jira_comment(
                    kind, alert_num, bsr.jira_comment, repo_full, routing=routing,
                )
            else:
                tv_out = triage_with_openai(
                    config,
                    alert_kind=kind,
                    alert_summary=combined,
                    file_context=ctx,
                )
                comment_body = _format_triage_comment(kind, alert_num, tv_out, repo_full)
                routing = "false_positive" if tv_out.verdict == "false_positive" else (
                    "in_progress" if tv_out.verdict == "true_positive" else "leave_open"
                )

            post_comment = True
            if dedup_comments and not dry and prior_comment and _comments_substantively_same(
                prior_comment, comment_body,
            ):
                post_comment = False
                summary["skipped_redundant_comment"] += 1

            if dry:
                jira_actions["jira_comment"] = "skipped_dry_run"
            elif not post_comment:
                jira_actions["jira_comment"] = "skipped_redundant_same_analysis"
            else:
                try:
                    posted = add_comment_plain(jira_base, jira_auth, key, comment_body)
                    _set_triage_issue_property(
                        jira_base,
                        jira_auth,
                        key,
                        _alert_state_payload(
                            kind=kind,
                            number=alert_num,
                            routing=routing,
                            repository=repo_full,
                            package=minimal_sig.package,
                            cve_id=minimal_sig.cve_id,
                            comment_body=comment_body,
                            comment_result=posted,
                        ),
                    )
                    jira_actions["jira_comment"] = "posted"
                except JiraError as e:
                    jira_actions["jira_comment_error"] = str(e)

            if auto_transition and not dry:
                target = _transition_target_for_routing(routing, current_status, transition_targets)
                if target:
                    try:
                        transition_to_status_name(jira_base, jira_auth, key, target)
                        jira_actions["jira_transition"] = target
                        summary["transitioned"] += 1
                    except JiraError as e:
                        jira_actions["jira_transition_error"] = str(e)
                        log.warning("transition %s -> %s failed: %s", key, target, e)

            row: dict[str, Any] = (
                asdict(AlertResult(kind, alert_num, False, None, tv_out, dry, jira_actions))  # type: ignore[arg-type]
                | {"jira_key": key, "repository": repo_full, "routing": routing}
            )
            if comment_style == "brief_conclusion":
                row["brief_comment"] = comment_body
            results.append(row)
            summary["processed"] += 1
        except Exception as e:  # noqa: BLE001
            results.append(
                asdict(AlertResult(kind, alert_num, False, None, None, dry, error=str(e)))  # type: ignore[arg-type]
                | {"jira_key": key},
            )
            summary["errors"] += 1

    trim_counts = memory_store.trim_to_limits()
    mem_stats = memory_store.stats()
    summary["memory_history_lines"] = mem_stats["history_lines"]
    summary["memory_feedback_lines"] = mem_stats["feedback_lines"]
    summary["memory_trimmed_to"] = trim_counts

    slack_meta = maybe_notify_slack(
        integrations_cfg=integrations_cfg,
        repo=f"jira:{jira_cfg.get('triage_project', 'VM')}",
        summary=summary,
        results=results,
    )
    for k, v in slack_meta.items():
        if k.startswith("slack"):
            summary[k] = v

    return {"summary": summary, "results": results}
