from __future__ import annotations

import json
import os
from typing import Any

from ghas_llm.integrations.jira_integration import JiraError, _request, basic_auth_header


def _get_jira_secret_from_aws(secret_name: str, region: str = "us-east-2") -> dict[str, str]:
    """Pull Jira creds from AWS Secrets Manager (same as existing Jira Lambdas)."""
    import boto3
    from botocore.exceptions import ClientError

    client = boto3.client("secretsmanager", region_name=region)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise JiraError(f"AWS Secrets Manager error for {secret_name!r}: {e}") from e
    raw = resp.get("SecretString", "")
    if not raw:
        raise JiraError(f"Empty secret for {secret_name!r}")
    data = json.loads(raw)
    return {"email": str(data.get("email", "")), "token": str(data.get("token", ""))}


def _get_jira_auth(jira_cfg: dict[str, Any]) -> tuple[str, str]:
    base = str(jira_cfg.get("base_url", "")).rstrip("/")

    email = os.environ.get(str(jira_cfg.get("email_env", "JIRA_EMAIL")), "").strip()
    token = os.environ.get(str(jira_cfg.get("api_token_env", "JIRA_API_TOKEN")), "").strip()

    if not email or not token:
        secret_name = os.environ.get("JIRA_SECRET_NAME", "").strip() or jira_cfg.get("aws_secret_name", "")
        if secret_name:
            region = str(jira_cfg.get("aws_secret_region", "us-east-2"))
            creds = _get_jira_secret_from_aws(secret_name, region)
            email = email or creds["email"]
            token = token or creds["token"]

    if not base or not email or not token:
        raise JiraError(
            "missing Jira credentials: set JIRA_EMAIL + JIRA_API_TOKEN env vars, "
            "or set JIRA_SECRET_NAME (or jira.aws_secret_name in YAML) to an AWS Secrets Manager secret "
            "like 'your-org/jira/ghas-triage'"
        )
    auth = basic_auth_header(email, token)
    return base, auth


def search_open_issues(jira_cfg: dict[str, Any], jql_extra: str = "") -> list[dict[str, Any]]:
    base, auth = _get_jira_auth(jira_cfg)
    project = str(jira_cfg.get("triage_project", "VM"))
    max_results = int(jira_cfg.get("triage_max_results", 50))
    jql = f'project = "{project}" AND status NOT IN (Done, Closed, Resolved, "False Positive")'
    if jql_extra:
        jql += f" AND ({jql_extra})"
    url = f"{base}/rest/api/3/search/jql"
    body: dict[str, Any] = {
        "jql": jql,
        "maxResults": max_results,
        "fields": ["summary", "description", "status", "labels", "priority",
                    "created", "updated", "assignee", "customfield_10001"],
    }
    all_issues: list[dict[str, Any]] = []
    while True:
        result = _request("POST", url, auth_header=auth, json_body=body)
        if not isinstance(result, dict):
            break
        for i in result.get("issues") or []:
            if isinstance(i, dict):
                all_issues.append(i)
        token = result.get("nextPageToken")
        if not token or len(all_issues) >= max_results:
            break
        body["nextPageToken"] = token
    return all_issues


def extract_issue_context(issue: dict[str, Any]) -> str:
    fields = issue.get("fields") or {}
    key = issue.get("key", "?")
    summary = fields.get("summary", "")
    desc = fields.get("description", "")
    if isinstance(desc, dict):
        desc = str(desc.get("content", ""))[:3000]
    elif isinstance(desc, str):
        desc = desc[:3000]
    else:
        desc = ""
    status = (fields.get("status") or {}).get("name", "")
    priority = (fields.get("priority") or {}).get("name", "")
    labels = fields.get("labels") or []
    assignee = (fields.get("assignee") or {}).get("displayName", "unassigned")
    created = fields.get("created", "")
    updated = fields.get("updated", "")

    parts = [
        f"Jira issue: {key}",
        f"Summary: {summary}",
        f"Status: {status} | Priority: {priority} | Assignee: {assignee}",
        f"Labels: {', '.join(str(l) for l in labels[:10])}",
        f"Created: {created} | Updated: {updated}",
    ]
    if desc:
        parts.append(f"Description:\n{desc}")
    return "\n".join(parts)


def triage_jira_issues(
    config: dict[str, Any],
) -> dict[str, Any]:
    from ghas_llm.llm_triage import triage_with_openai

    jira_cfg = (config.get("integrations") or {}).get("jira") or {}
    if not jira_cfg.get("enabled"):
        return {"jira_triage": "disabled"}
    if not jira_cfg.get("triage_existing_issues"):
        return {"jira_triage": "triage_existing_issues not enabled"}

    try:
        issues = search_open_issues(jira_cfg)
    except JiraError as e:
        return {"jira_triage": "error", "detail": str(e)}

    results: list[dict[str, Any]] = []
    for issue in issues:
        key = issue.get("key", "")
        ctx = extract_issue_context(issue)
        try:
            tv = triage_with_openai(
                config,
                alert_kind="jira_vulnerability",
                alert_summary=ctx,
                file_context="(Jira issue — no repo file context; evaluate from issue metadata)",
            )
            from dataclasses import asdict
            results.append({
                "jira_key": key,
                "verdict": asdict(tv),
            })
        except Exception as e:  # noqa: BLE001
            results.append({"jira_key": key, "error": str(e)})

    return {"jira_triage": "completed", "issues_triaged": len(results), "results": results}
