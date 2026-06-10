"""Build LLM context from GitHub REST API (no git clone). Reduces clone/API rate pressure."""

from __future__ import annotations

import base64
import logging
import re
import time
import urllib.parse
from typing import Any

from ghas_llm.github_api import GitHubAPIError, GitHubClient

log = logging.getLogger(__name__)


def _decode_content(item: dict[str, Any]) -> str:
    enc = item.get("encoding", "")
    raw = item.get("content", "")
    if enc == "base64" and isinstance(raw, str):
        try:
            return base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="replace")
        except (ValueError, OSError):
            return "(decode error)"
    return ""


def get_file_via_api(
    client: GitHubClient, owner: str, repo: str, path: str, ref: str,
) -> str:
    path_enc = urllib.parse.quote(path.replace("\\", "/").lstrip("/"), safe="/")
    try:
        r = client.get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/contents/{path_enc}",
            {"ref": ref} if ref else None,
        )
        if isinstance(r, dict) and r.get("type") == "file":
            return _decode_content(r)
    except GitHubAPIError as e:
        if e.status == 404:
            log.debug("contents API optional file missing %s/%s %s", owner, repo, path)
        else:
            log.warning("contents API %s/%s %s: %s", owner, repo, path, e)
    return ""


def dependabot_usage_hints_api(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    alert: dict,
    max_chars: int = 3500,
) -> str:
    """Lightweight code search for package references (1–2 queries, bounded)."""
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    eco = str(pkg.get("ecosystem", "")).lower()
    name = str(pkg.get("name", "")).strip()
    if not name:
        return ""
    repo_q = f"repo:{owner}/{repo}"
    queries: list[str] = []
    if eco == "pip":
        mod = re.escape(name.lower().replace("-", "_"))
        queries.append(f"{repo_q} language:Python import {mod}")
        if "pillow" in name.lower():
            queries.append(f"{repo_q} language:Python import PIL")
    elif eco in ("npm", "yarn", "pnpm"):
        qn = re.escape(name)
        queries.append(f"{repo_q} {qn}")
    else:
        queries.append(f"{repo_q} {name}")
    parts: list[str] = []
    for q in queries[:2]:
        try:
            time.sleep(0.4)
            r = client.get("/search/code", {"q": q, "per_page": "5"})
            items = r.get("items", []) if isinstance(r, dict) else []
            for it in items[:5]:
                if not isinstance(it, dict):
                    continue
                pth = it.get("path", "")
                html = it.get("html_url", "")
                parts.append(f"- match: {pth} ({html})")
            if parts:
                break
        except GitHubAPIError as e:
            log.warning("code search skipped: %s", e)
    if not parts:
        return f"(No code search hits for {name!r} in {owner}/{repo}; may be transitive or manifest-only.)"
    out = "=== Code search (GitHub API, limited) ===\n" + "\n".join(parts[:20])
    return out[:max_chars]


def build_context_github_api(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    *,
    paths: list[str],
    locations: list[tuple[str | None, int | None, int | None]],
    dependabot_alert: dict | None,
    max_chars: int,
) -> tuple[str, str | None]:
    """Fetch file snippets via Contents API; optional code search for Dependabot usage."""
    err: str | None = None
    parts: list[str] = []
    ref_use = ref or "HEAD"
    for rel, start, end in locations:
        if not rel:
            continue
        rel = rel.replace("\\", "/").lstrip("/")
        text = get_file_via_api(client, owner, repo, rel, ref_use)
        if not text:
            parts.append(f"### File: {rel}\n(unable to fetch via API)\n")
            continue
        lines = text.splitlines()
        if start is not None and end is not None:
            a = max(0, int(start) - 6)
            b = min(len(lines), int(end) + 6)
            chunk = "\n".join(f"{i+1:5}|{lines[i]}" for i in range(a, b))
        else:
            chunk = "\n".join(f"{i+1:5}|{line}" for i, line in enumerate(lines[:400]))
        parts.append(f"### File: {rel}\n```\n{chunk}\n```\n")
        if sum(len(p) for p in parts) >= max_chars:
            break
    for rel in paths:
        rel = rel.replace("\\", "/").lstrip("/")
        if not rel:
            continue
        text = get_file_via_api(client, owner, repo, rel, ref_use)
        if not text:
            parts.append(f"### Manifest: {rel}\n(unable to fetch via API)\n")
            continue
        chunk = "\n".join(f"{i+1:5}|{line}" for i, line in enumerate(text.splitlines()[:500]))
        parts.append(f"### Manifest / lockfile: {rel}\n```\n{chunk}\n```\n")
        if sum(len(p) for p in parts) >= max_chars:
            break
    out = "\n".join(parts)
    if dependabot_alert and paths:
        hints = dependabot_usage_hints_api(client, owner, repo, ref_use, dependabot_alert, max_chars=max_chars // 2)
        if hints:
            out = out + "\n\n" + hints
    if len(out) > max_chars:
        out = out[: max_chars - 80] + "\n... [truncated]\n"
    if not out.strip():
        err = "GitHub API context empty (no file content retrieved)"
    return out, err


def format_repo_metadata_block(meta: dict[str, Any]) -> str:
    """Fork status and default branch for the LLM."""
    if not meta:
        return ""
    lines = [
        f"Repository: {meta.get('full_name', '')}",
        f"Default branch: {meta.get('default_branch', '')}",
        f"Fork: {meta.get('fork', False)}",
    ]
    if meta.get("fork") and isinstance(meta.get("parent"), dict):
        p = meta["parent"]
        lines.append(f"Parent repo: {p.get('full_name', '')}")
    return "\n".join(lines)


def format_recent_commit_authors(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    paths: list[str],
    locations: list[tuple[str | None, int | None, int | None]],
    max_paths: int = 3,
) -> str:
    """Last commit touching key files (proxy for blame); author login and email if public."""
    seen: set[str] = set()
    lines_out: list[str] = []
    candidates: list[str] = []
    for rel, _, _ in locations:
        if rel:
            candidates.append(str(rel).replace("\\", "/").lstrip("/"))
    for p in paths:
        p = str(p).replace("\\", "/").lstrip("/")
        if p:
            candidates.append(p)
    for path in candidates[:max_paths]:
        if path in seen:
            continue
        seen.add(path)
        try:
            time.sleep(0.25)
            r = client.get(
                f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/commits",
                {"path": path, "sha": ref or "", "per_page": "1"},
            )
            if not isinstance(r, list) or not r:
                continue
            c0 = r[0]
            if not isinstance(c0, dict):
                continue
            commit = c0.get("commit") or {}
            author = commit.get("author") or {}
            gh_author = c0.get("author") or {}
            login = gh_author.get("login", "")
            email = author.get("email", "")
            name = author.get("name", "")
            lines_out.append(
                f"- {path}: last commit by {name or login} "
                f"(GitHub: @{login}) email={email or 'n/a'}",
            )
        except GitHubAPIError:
            continue
    if not lines_out:
        return ""
    return "=== Recent commit authors (file history, not full blame) ===\n" + "\n".join(lines_out)
