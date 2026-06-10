"""Jira Cloud: transition issue status (no GitHub changes)."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class JiraError(Exception):
    pass


def _request(
    method: str,
    url: str,
    *,
    auth_header: str,
    json_body: dict[str, Any] | None = None,
) -> Any:
    data: bytes | None = None
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": auth_header,
    }
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw.strip():
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace") if e.fp else ""
        raise JiraError(f"HTTP {e.code}: {err}") from e


def basic_auth_header(email: str, api_token: str) -> str:
    raw = f"{email}:{api_token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def transition_to_status_name(
    base_url: str,
    auth_header: str,
    issue_key: str,
    target_status_name: str,
) -> dict[str, Any]:
    """Move issue by matching target against transition name or to.status.name (case-insensitive)."""
    base = base_url.rstrip("/")
    enc = urllib.parse.quote(issue_key, safe="")
    transitions_url = f"{base}/rest/api/3/issue/{enc}/transitions"
    tr = _request("GET", transitions_url, auth_header=auth_header)
    if not isinstance(tr, dict) or "transitions" not in tr:
        raise JiraError("unexpected transitions response")

    target_lower = target_status_name.strip().lower().replace(" ", "_")
    tid: str | None = None
    matched_name: str = target_status_name

    for t in tr["transitions"]:
        if not isinstance(t, dict):
            continue
        to_block = t.get("to") or {}
        to_name = (to_block.get("name") or "").strip().lower().replace(" ", "_")
        tr_name = (t.get("name") or "").strip().lower().replace(" ", "_")
        if to_name == target_lower or tr_name == target_lower:
            tid = str(t.get("id", ""))
            matched_name = t.get("name") or to_block.get("name") or target_status_name
            break

    if not tid:
        names = []
        for t in tr.get("transitions", []):
            if isinstance(t, dict):
                names.append(t.get("name") or (t.get("to") or {}).get("name") or "")
        raise JiraError(
            f"no transition to status {target_status_name!r}; available: {names}"
        )

    post_url = f"{base}/rest/api/3/issue/{enc}/transitions"
    _request(
        "POST",
        post_url,
        auth_header=auth_header,
        json_body={"transition": {"id": tid}},
    )
    return {"issue": issue_key, "transition_id": tid, "status": matched_name}


def add_comment_plain(
    base_url: str,
    auth_header: str,
    issue_key: str,
    body: str,
) -> Any:
    """Append a plain-text comment (REST v2)."""
    base = base_url.rstrip("/")
    enc = urllib.parse.quote(issue_key, safe="")
    url = f"{base}/rest/api/2/issue/{enc}/comment"
    return _request("POST", url, auth_header=auth_header, json_body={"body": body[:32000]})


def get_issue_comments(
    base_url: str,
    auth_header: str,
    issue_key: str,
    max_results: int = 100,
) -> list[dict[str, Any]]:
    """Fetch existing comments on an issue (REST v2)."""
    base = base_url.rstrip("/")
    enc = urllib.parse.quote(issue_key, safe="")
    url = f"{base}/rest/api/2/issue/{enc}/comment?maxResults={max_results}&orderBy=-created"
    result = _request("GET", url, auth_header=auth_header)
    if isinstance(result, dict):
        return result.get("comments", [])
    return []


def set_issue_property(
    base_url: str,
    auth_header: str,
    issue_key: str,
    property_key: str,
    value: dict[str, Any],
) -> None:
    """Store machine-readable issue state outside visible Jira comments."""
    base = base_url.rstrip("/")
    enc = urllib.parse.quote(issue_key, safe="")
    prop = urllib.parse.quote(property_key, safe="")
    url = f"{base}/rest/api/3/issue/{enc}/properties/{prop}"
    _request("PUT", url, auth_header=auth_header, json_body=value)


def get_issue_property(
    base_url: str,
    auth_header: str,
    issue_key: str,
    property_key: str,
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    enc = urllib.parse.quote(issue_key, safe="")
    prop = urllib.parse.quote(property_key, safe="")
    url = f"{base}/rest/api/3/issue/{enc}/properties/{prop}"
    try:
        result = _request("GET", url, auth_header=auth_header)
    except JiraError as exc:
        if "HTTP 404" in str(exc):
            return {}
        raise
    if isinstance(result, dict) and isinstance(result.get("value"), dict):
        return result["value"]
    return {}
