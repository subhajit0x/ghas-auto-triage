"""Agentic triage: gather GitHub-side evidence, score with a deterministic matrix, then ask gpt-5.4-mini for the final verdict via a self-questioning JSON pass.

Per alert:
  1. Repo profile        — visibility, fork, archived, activity, contributor count
  2. Advisory parse     — extract vulnerable APIs / trigger surface (gpt-5.4-mini)
  3. Code reachability  — GitHub code search for the APIs in this repo
  4. Blame              — last commit author per matched file (commits API)
  5. Org-wide impact    — distinct repos in the org importing the package
  6. Extra context      — README excerpt + ecosystem manifest excerpt
  7. Evidence matrix    — deterministic score (no LLM)
  8. Final verdict      — gpt-5.4-mini, JSON output with self-questioning structure

GitHub-only data sources. No clone. Token budget per ticket is kept under ~6k
total (advisory parse + final verdict).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghas_llm.context_github_api import get_file_via_api
from ghas_llm.github_api import GitHubAPIError, GitHubClient
from ghas_llm.llm_triage import (
    _normalize_brief_comment,
    _parse_json_object,
    build_openai_client,
)
from ghas_llm.logic.human_comment import (
    humanize,
    render_action_needed_comment,
    render_false_positive_comment,
    render_needs_review_comment,
)
from ghas_llm.logic.judge_prompt import JUDGE_SYSTEM_PROMPT

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data classes                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class RepoProfile:
    full_name: str
    visibility: str = "unknown"
    is_fork: bool = False
    parent_full_name: str = ""
    archived: bool = False
    default_branch: str = ""
    primary_language: str = ""
    topics: list[str] = field(default_factory=list)
    stars: int = 0
    last_push_iso: str = ""
    days_since_last_push: int = 0
    push_date_known: bool = False
    contributor_count: int = 0
    is_internal: bool = False
    profile_fetch_failed: bool = False

    @property
    def activity_label(self) -> str:
        if not self.push_date_known:
            return "activity unknown (could not read repo metadata)"
        if self.archived:
            return "archived"
        d = self.days_since_last_push
        if d <= 30:
            return f"actively maintained (last commit {d} days ago)"
        if d <= 180:
            return f"recently active (last commit {d} days ago)"
        if d <= 365:
            return f"slow / stale (last commit {d} days ago)"
        return f"likely abandoned (last commit {d} days ago)"


@dataclass
class VulnSignature:
    package: str = ""
    ecosystem: str = ""
    cve_id: str = ""
    severity: str = ""
    affected_versions: str = ""
    fixed_version: str = ""
    vulnerable_apis: list[str] = field(default_factory=list)
    trigger_summary: str = ""
    non_default_required: bool = False


@dataclass
class CodeMatch:
    path: str
    url: str = ""


@dataclass
class BlameInfo:
    path: str
    last_commit_sha: str = ""
    last_author_login: str = ""
    last_author_email: str = ""
    last_commit_date: str = ""
    last_commit_message: str = ""


@dataclass
class ExtraContext:
    readme_excerpt: str = ""
    manifest_path: str = ""
    manifest_excerpt: str = ""
    package_pinned_in_manifest: bool = False
    dockerfile_excerpt: str = ""
    package_in_dockerfile: bool = False
    ci_workflow_path: str = ""
    ci_workflow_excerpt: str = ""
    package_in_ci: bool = False
    lockfile_path: str = ""
    lockfile_excerpt: str = ""
    lockfile_has_package: bool = False
    runtime_path: str = ""
    runtime_excerpt: str = ""
    exposure_hint: str = ""


@dataclass
class EvidenceMatrix:
    repo_active: bool = False
    repo_internal: bool = True
    repo_public: bool = False
    repo_archived: bool = False
    direct_code_hits: int = 0
    test_only_hits: int = 0
    blame_authors: list[str] = field(default_factory=list)
    org_wide_hit_repos: int = 0
    reproducible: bool = False
    package_in_manifest: bool = False
    lockfile_pinned: bool = False
    cross_validated: bool = False
    api_symbols_hit_in_search: bool = False
    confidence_score: float = 0.0
    confidence_label: str = "low"


@dataclass
class AgenticVerdict:
    routing: str = "leave_open"
    impact: str = "insufficient_evidence"
    confidence: str = "low"
    reproducible: bool = False
    jira_comment: str = ""
    profile: RepoProfile | None = None
    signature: VulnSignature | None = None
    matrix: EvidenceMatrix | None = None
    matches: list[CodeMatch] = field(default_factory=list)
    blame: list[BlameInfo] = field(default_factory=list)
    org_repos_affected: int = 0
    extras: ExtraContext | None = None
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    exploitation_path: str = ""
    blast_radius: str = "unknown"
    risk_score: int = 0
    confidence_score: int = 0
    priority: str = ""
    tier: str = "tier_3_internal"
    tier_reason: str = ""
    force_verdict: str = ""
    force_reason: str = ""
    major_premise: str = ""
    minor_premise: str = ""
    truth_table_summary: str = ""
    org_hunter_summary: str = ""
    global_memory_summary: str = ""
    prosecutor_uphold: bool = True
    prosecutor_attack_holes: list[str] = field(default_factory=list)
    deep_dive_count: int = 0
    deterministic_short_circuit: bool = False


# --------------------------------------------------------------------------- #
# Step 1 — Repo profile                                                       #
# --------------------------------------------------------------------------- #


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def gather_repo_profile(
    client: GitHubClient, owner: str, repo: str, org: str,
) -> RepoProfile:
    profile = RepoProfile(full_name=f"{owner}/{repo}")
    profile.is_internal = owner.lower() == (org or "").lower()

    try:
        meta = client.get_repo(owner, repo)
    except GitHubAPIError as e:
        log.warning("get_repo %s/%s failed: %s", owner, repo, e)
        profile.profile_fetch_failed = True
        return profile
    if not isinstance(meta, dict) or not meta:
        profile.profile_fetch_failed = True
        return profile

    profile.full_name = str(meta.get("full_name", profile.full_name))
    if meta.get("visibility"):
        profile.visibility = str(meta["visibility"]).lower()
    elif "private" in meta:
        profile.visibility = "private" if meta.get("private") else "public"

    profile.is_fork = bool(meta.get("fork", False))
    parent = meta.get("parent") if isinstance(meta.get("parent"), dict) else {}
    profile.parent_full_name = str(parent.get("full_name", "") or "")
    profile.archived = bool(meta.get("archived", False))
    profile.default_branch = str(meta.get("default_branch", "") or "")
    profile.primary_language = str(meta.get("language", "") or "")
    profile.topics = list(meta.get("topics", []) or [])
    profile.stars = int(meta.get("stargazers_count", 0) or 0)

    pushed = str(meta.get("pushed_at", "") or "")
    dt = _parse_iso(pushed) or _parse_iso(str(meta.get("updated_at", "") or ""))
    if dt is not None:
        profile.last_push_iso = pushed or str(meta.get("updated_at", "") or "")
        profile.days_since_last_push = max(
            0, (datetime.now(timezone.utc) - dt).days,
        )
        profile.push_date_known = True

    try:
        time.sleep(0.2)
        c = client.get(
            f"/repos/{owner}/{repo}/contributors",
            {"per_page": "30", "anon": "true"},
        )
        if isinstance(c, list):
            profile.contributor_count = len(c)
    except GitHubAPIError as e:
        if e.status not in (403, 404):
            log.warning("contributors %s/%s: %s", owner, repo, e)

    return profile


# --------------------------------------------------------------------------- #
# Step 2 — Advisory parse                                                     #
# --------------------------------------------------------------------------- #


_VULN_EXTRACT_SYSTEM = (
    "You parse a security advisory and return ONE JSON object only.\n"
    "Keys:\n"
    '  "vulnerable_apis": list of up to 6 specific symbols (function/class/method '
    "names) an attacker can reach to trigger the bug. Empty list if the advisory "
    "is generic and names no specific symbol.\n"
    '  "trigger_summary": one short sentence about what input/call path triggers the bug.\n'
    '  "non_default_required": true if exploitation needs a non-default configuration, else false.\n'
    "Be precise. Never invent function names that are not in the advisory text."
)


def _llm_json(client: Any, model: str, system: str, user: str) -> dict[str, Any]:
    """Call chat.completions and best-effort parse a JSON object.

    Tries response_format=json_object first; falls back to plain mode for models
    that do not support response_format. One retry on parse failure.
    """
    last_err: Exception | None = None
    for attempt in range(2):
        try:
            try:
                resp = client.chat.completions.create(
                    model=model,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
            except Exception:  # noqa: BLE001
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
            text = (resp.choices[0].message.content or "").strip()
            return _parse_json_object(text)
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            log.warning("json parse/call attempt %s failed: %s", attempt + 1, exc)
    raise last_err if last_err else RuntimeError("llm json failed")


def load_previous_run_hint(
    repo_root: Path,
    history_rel: str,
    jira_key: str,
    *,
    memory_store: Any | None = None,
) -> str:
    """One line for the model: last routing for this Jira key from triage history."""
    if not jira_key:
        return ""
    last: dict[str, Any] | None = None
    if memory_store is not None:
        for row in memory_store.load_history_rows(400):
            if str(row.get("jira_key", "")) == jira_key:
                last = row
    elif (history_rel or "").strip():
        path = (repo_root / history_rel).resolve()
        if path.is_file():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                lines = []
            for line in lines[-400:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(row.get("jira_key", "")) == jira_key:
                    last = row
    if not last:
        return ""
    r = str(last.get("routing", "") or "")
    st = str(last.get("jira_comment_status", "") or "")
    return (
        f"Earlier automated run on this ticket: routing was {r!r}, comment outcome was {st!r}. "
        "Stay consistent if evidence unchanged; update the narrative if discovery differs."
    )


def sanitize_stakeholder_comment(text: str) -> str:
    """Strip internal scoring / priority labels that should not appear in Jira."""
    if not (text or "").strip():
        return text
    t = text
    t = re.sub(r"\b[Pp][0-3]\b", "", t)
    t = re.sub(r"[Rr]isk\s*:?\s*\d+\s*/\s*10", "", t)
    t = re.sub(r"\(\s*risk[^)]{0,40}\)", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(blast\s*radius|customer_?facing|internal_?only|single_service|multi_service)\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(medium|high|low)\s+confidence\b", "likely impact", t, flags=re.IGNORECASE)
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _compact_truth_table(summary: str) -> str:
    lines = [ln.strip() for ln in (summary or "").splitlines() if ln.strip()]
    keep = [
        ln
        for ln in lines
        if ln.startswith(("PRE-FLIGHT", "Files:", "Reachability:", "Hosted hint:", "FORCE VERDICT"))
    ]
    return "\n".join(keep[:5]) or summary[:600]


def extract_vuln_signature(config: dict[str, Any], alert: dict[str, Any]) -> VulnSignature:
    sig = VulnSignature()
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    sig.package = str(pkg.get("name", "") or "")
    sig.ecosystem = str(pkg.get("ecosystem", "") or "").lower()

    sv = alert.get("security_vulnerability") or {}
    sig.severity = str(sv.get("severity", "") or "").lower()
    sig.affected_versions = str(sv.get("vulnerable_version_range", "") or "")
    fv = sv.get("first_patched_version")
    if isinstance(fv, dict):
        sig.fixed_version = str(fv.get("identifier", "") or "")
    elif isinstance(fv, str):
        sig.fixed_version = fv

    adv = alert.get("security_advisory") or {}
    sig.cve_id = str(adv.get("cve_id", "") or "")
    summary = str(adv.get("summary", "") or "")
    desc = str(adv.get("description", "") or "")[:3500]

    extract_model = str(
        config.get("global", {}).get("llm", {}).get("extract_model", "gpt-5.4-mini"),
    )
    user = (
        f"Package: {sig.ecosystem}/{sig.package}\n"
        f"CVE: {sig.cve_id}\n"
        f"Severity: {sig.severity}\n"
        f"Affected versions: {sig.affected_versions}\n"
        f"Fixed in: {sig.fixed_version}\n"
        f"Summary: {summary}\n"
        f"Description: {desc}"
    )
    for attempt in range(2):
        try:
            oai = build_openai_client(config)
            data = _llm_json(oai, extract_model, _VULN_EXTRACT_SYSTEM, user)
            apis = data.get("vulnerable_apis") or []
            if isinstance(apis, list):
                sig.vulnerable_apis = [str(a)[:80] for a in apis if a][:6]
            sig.trigger_summary = str(data.get("trigger_summary", "") or "")[:300]
            sig.non_default_required = bool(data.get("non_default_required", False))
            break
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln signature extraction attempt %s failed: %s", attempt + 1, exc)
            if attempt == 1:
                break
            time.sleep(0.5)
    return sig


# --------------------------------------------------------------------------- #
# Step 3 — Code reachability                                                  #
# --------------------------------------------------------------------------- #


def is_test_path(path: str) -> bool:
    p = path.lower()
    if p.startswith((
        "test/", "tests/", "spec/", "examples/", "example/",
        "samples/", "sample/", "fixtures/",
    )):
        return True
    return any(
        x in p
        for x in (
            "/test/", "/tests/", "_test.", ".test.",
            "/spec/", "/__tests__", "/fixtures/",
            "/samples/", "/sample/", "/examples/", "/example/",
        )
    )


def _deep_search_queries(owner: str, repo: str, sig: VulnSignature) -> list[str]:
    """Build many GitHub code-search queries (deduped) for in-repo reachability."""
    rq = f"repo:{owner}/{repo}"
    out: list[str] = []
    seen_q: set[str] = set()

    def add(q: str) -> None:
        q = q.strip()
        if q and q not in seen_q:
            seen_q.add(q)
            out.append(q)

    for api in (sig.vulnerable_apis or [])[:6]:
        if api and len(api) >= 3:
            add(f'{rq} "{api}"')

    pkg = (sig.package or "").strip()
    eco = (sig.ecosystem or "").lower()

    if pkg:
        if eco == "pip":
            mod = pkg.lower().replace("-", "_")
            alt = pkg.lower().replace("_", "-")
            add(f"{rq} language:Python from {mod}")
            add(f"{rq} language:Python import {mod}")
            if alt != mod:
                add(f"{rq} language:Python import {alt}")
            add(f'{rq} filename:requirements.txt "{pkg}"')
            add(f'{rq} filename:pyproject.toml "{pkg}"')
            add(f"{rq} language:Python {pkg}")
        elif eco in ("npm", "yarn", "pnpm"):
            add(f'{rq} "{pkg}"')
            add(f'{rq} filename:package.json "{pkg}"')
            add(f'{rq} path:/ "{pkg}"')
        elif eco in ("maven", "gradle"):
            add(f'{rq} "{pkg}"')
            add(f'{rq} filename:pom.xml "{pkg}"')
        elif eco in ("rubygems",):
            add(f'{rq} "{pkg}"')
            add(f'{rq} filename:Gemfile "{pkg}"')
        elif eco == "go":
            add(f'{rq} filename:go.mod "{pkg}"')
        elif eco == "cargo":
            add(f'{rq} filename:Cargo.toml "{pkg}"')
        else:
            add(f'{rq} "{pkg}"')

    return out[:18]


def find_code_reachability(
    client: GitHubClient,
    owner: str,
    repo: str,
    sig: VulnSignature,
    max_matches: int = 8,
    max_queries: int = 8,
) -> list[CodeMatch]:
    """Multiple GitHub code searches across filenames, imports, and advisory APIs."""
    queries = _deep_search_queries(owner, repo, sig)[:max_queries]
    seen: set[str] = set()
    matches: list[CodeMatch] = []
    for q in queries:
        try:
            time.sleep(0.12)
            r = client.get("/search/code", {"q": q, "per_page": "12"})
        except GitHubAPIError as e:
            if e.status in (403, 422, 429):
                log.warning("code search skipped (%s): %s", e.status, q[:120])
                continue
            log.warning("code search error %s: %s", q[:120], e)
            continue
        items = r.get("items", []) if isinstance(r, dict) else []
        for it in items:
            if not isinstance(it, dict):
                continue
            path = str(it.get("path", "") or "")
            if not path or path in seen:
                continue
            seen.add(path)
            matches.append(CodeMatch(path=path, url=str(it.get("html_url", "") or "")))
            if len(matches) >= max_matches:
                return matches
    return matches


# --------------------------------------------------------------------------- #
# Step 4 — Blame (file history proxy)                                         #
# --------------------------------------------------------------------------- #


def gather_blame(
    client: GitHubClient,
    owner: str,
    repo: str,
    branch: str,
    matches: list[CodeMatch],
    max_paths: int = 5,
) -> list[BlameInfo]:
    seen: set[str] = set()
    out: list[BlameInfo] = []
    candidates = [m for m in matches if not is_test_path(m.path)] or matches
    for m in candidates[: max_paths * 2]:
        if m.path in seen:
            continue
        seen.add(m.path)
        try:
            time.sleep(0.25)
            r = client.get(
                f"/repos/{owner}/{repo}/commits",
                {"path": m.path, "sha": branch or "", "per_page": "1"},
            )
        except GitHubAPIError:
            continue
        if not isinstance(r, list) or not r:
            continue
        c0 = r[0] if isinstance(r[0], dict) else {}
        commit = c0.get("commit") or {}
        author = commit.get("author") or {}
        gh_author = c0.get("author") or {}
        msg = str(commit.get("message", "") or "")
        first_line = msg.splitlines()[0] if msg else ""
        out.append(
            BlameInfo(
                path=m.path,
                last_commit_sha=str(c0.get("sha", "") or "")[:8],
                last_author_login=str(gh_author.get("login", "") or ""),
                last_author_email=str(author.get("email", "") or ""),
                last_commit_date=str(author.get("date", "") or ""),
                last_commit_message=first_line[:140],
            ),
        )
        if len(out) >= max_paths:
            break
    return out


# --------------------------------------------------------------------------- #
# Step 5 — Org-wide impact                                                    #
# --------------------------------------------------------------------------- #


def org_wide_impact(
    client: GitHubClient,
    org: str,
    sig: VulnSignature,
    max_repos: int = 30,
) -> int:
    if not sig.package or not org:
        return 0
    base = f"org:{org}"
    queries: list[str] = []
    if sig.ecosystem == "pip":
        mod = sig.package.lower().replace("-", "_")
        queries.append(f"{base} language:Python import {mod}")
    elif sig.ecosystem in ("npm", "yarn", "pnpm"):
        queries.append(f'{base} "{sig.package}"')
    else:
        queries.append(f'{base} "{sig.package}"')

    repos: set[str] = set()
    for q in queries[:1]:
        try:
            time.sleep(0.5)
            r = client.get("/search/code", {"q": q, "per_page": "30"})
        except GitHubAPIError as e:
            if e.status in (403, 422, 429):
                log.warning("org search skipped (%s): %s", e.status, q)
                continue
            log.warning("org search error %s: %s", q, e)
            continue
        items = r.get("items", []) if isinstance(r, dict) else []
        for it in items:
            if not isinstance(it, dict):
                continue
            rp = it.get("repository") or {}
            fn = str(rp.get("full_name", "") or "")
            if fn:
                repos.add(fn)
                if len(repos) >= max_repos:
                    break
    return len(repos)


# --------------------------------------------------------------------------- #
# Step 6 — Extra context (README + manifest)                                  #
# --------------------------------------------------------------------------- #


_MANIFEST_BY_ECOSYSTEM: dict[str, list[str]] = {
    "pip": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "npm": ["package.json"],
    "yarn": ["package.json"],
    "pnpm": ["package.json"],
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts"],
    "go": ["go.mod"],
    "rubygems": ["Gemfile", "Gemfile.lock"],
    "composer": ["composer.json"],
    "cargo": ["Cargo.toml"],
}


def _short_excerpt_around(text: str, needle: str, span: int = 200, max_len: int = 800) -> str:
    if not text:
        return ""
    if not needle:
        return text[:max_len]
    lo = text.lower().find(needle.lower())
    if lo < 0:
        return text[:max_len]
    s = max(0, lo - span)
    e = min(len(text), lo + len(needle) + span)
    return text[s:e]


_CI_CANDIDATES = (
    ".github/workflows/ci.yml",
    ".github/workflows/ci.yaml",
    ".github/workflows/build.yml",
    ".github/workflows/deploy.yml",
    ".github/workflows/test.yml",
    ".github/workflows/main.yml",
)
_DOCKER_CANDIDATES = ("Dockerfile", "docker/Dockerfile", "deploy/Dockerfile")
_RUNTIME_CANDIDATES = (
    "serverless.yml",
    "serverless.yaml",
    "template.yaml",
    "template.yml",
    "sam.yaml",
    "sam.yml",
    "cloudformation.yaml",
    "cloudformation.yml",
)


def _runtime_exposure_hint(path: str, content: str) -> str:
    low = content.lower()
    if "httpapi" in low or "http:" in low or "apigateway" in low or "api gateway" in low:
        return f"{path} defines HTTP/API Gateway exposure"
    if "schedule:" in low or "eventbridge" in low or "cloudwatch" in low:
        return f"{path} appears event/schedule driven"
    if "sqs" in low or "sns" in low or "kinesis" in low:
        return f"{path} appears queue/event driven"
    if path.lower().startswith("serverless"):
        return f"{path} indicates serverless runtime"
    return ""


def gather_extra_context(
    client: GitHubClient,
    owner: str,
    repo: str,
    branch: str,
    sig: VulnSignature,
) -> ExtraContext:
    out = ExtraContext()
    try:
        readme = get_file_via_api(client, owner, repo, "README.md", branch)
        if not readme:
            for alt in ("README.rst", "README.txt", "readme.md", "Readme.md"):
                readme = get_file_via_api(client, owner, repo, alt, branch)
                if readme:
                    break
        if readme:
            out.readme_excerpt = readme[:1500].strip()
    except Exception as exc:  # noqa: BLE001
        log.warning("readme fetch %s/%s failed: %s", owner, repo, exc)

    candidates = _MANIFEST_BY_ECOSYSTEM.get(sig.ecosystem, [])
    for manifest in candidates:
        try:
            content = get_file_via_api(client, owner, repo, manifest, branch)
        except Exception as exc:  # noqa: BLE001
            log.warning("manifest fetch %s/%s/%s failed: %s", owner, repo, manifest, exc)
            content = ""
        if not content:
            continue
        out.manifest_path = manifest
        if sig.package and sig.package.lower() in content.lower():
            out.package_pinned_in_manifest = True
            out.manifest_excerpt = _short_excerpt_around(content, sig.package, span=120, max_len=600)
        else:
            out.manifest_excerpt = content[:600].strip()
        break

    for path in _DOCKER_CANDIDATES:
        try:
            content = get_file_via_api(client, owner, repo, path, branch)
        except Exception:  # noqa: BLE001
            content = ""
        if not content:
            continue
        present = bool(sig.package) and sig.package.lower() in content.lower()
        out.dockerfile_excerpt = (
            _short_excerpt_around(content, sig.package, span=80, max_len=400)
            if present
            else content[:400].strip()
        )
        out.package_in_dockerfile = present
        break

    for path in _CI_CANDIDATES:
        try:
            content = get_file_via_api(client, owner, repo, path, branch)
        except Exception:  # noqa: BLE001
            content = ""
        if not content:
            continue
        out.ci_workflow_path = path
        present = bool(sig.package) and sig.package.lower() in content.lower()
        out.ci_workflow_excerpt = (
            _short_excerpt_around(content, sig.package, span=80, max_len=400)
            if present
            else content[:400].strip()
        )
        out.package_in_ci = present
        break

    lock_candidates = (
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
    )
    if sig.package:
        for lf in lock_candidates:
            try:
                content = get_file_via_api(client, owner, repo, lf, branch)
            except Exception:  # noqa: BLE001
                content = ""
            if not content or sig.package.lower() not in content.lower():
                continue
            out.lockfile_path = lf
            out.lockfile_has_package = True
            out.lockfile_excerpt = _short_excerpt_around(content, sig.package, span=100, max_len=500)
            break

    for runtime_path in _RUNTIME_CANDIDATES:
        try:
            content = get_file_via_api(client, owner, repo, runtime_path, branch)
        except Exception:  # noqa: BLE001
            content = ""
        if not content:
            continue
        out.runtime_path = runtime_path
        out.runtime_excerpt = content[:700].strip()
        out.exposure_hint = _runtime_exposure_hint(runtime_path, content)
        break

    return out


# --------------------------------------------------------------------------- #
# Step 7 — Deterministic evidence matrix                                      #
# --------------------------------------------------------------------------- #


def compute_evidence_matrix(
    profile: RepoProfile,
    matches: list[CodeMatch],
    blame: list[BlameInfo],
    org_repos: int,
    sig: VulnSignature,
    extras: ExtraContext | None = None,
) -> EvidenceMatrix:
    m = EvidenceMatrix()
    if profile.archived:
        m.repo_active = False
    elif not profile.push_date_known:
        m.repo_active = True
    else:
        m.repo_active = profile.days_since_last_push <= 180
    m.repo_internal = profile.is_internal and not profile.is_fork
    m.repo_public = profile.visibility == "public"
    m.repo_archived = profile.archived

    test_hits = sum(1 for x in matches if is_test_path(x.path))
    direct_hits = max(0, len(matches) - test_hits)
    m.direct_code_hits = direct_hits
    m.test_only_hits = test_hits
    m.blame_authors = sorted({b.last_author_login for b in blame if b.last_author_login})[:5]
    m.org_wide_hit_repos = org_repos
    m.package_in_manifest = bool(extras and extras.package_pinned_in_manifest)
    m.lockfile_pinned = bool(extras and getattr(extras, "lockfile_has_package", False))
    m.api_symbols_hit_in_search = direct_hits > 0 and bool(sig.vulnerable_apis)
    m.cross_validated = bool(
        direct_hits > 0
        and (
            m.package_in_manifest
            or m.lockfile_pinned
            or (extras and (extras.package_in_dockerfile or extras.package_in_ci))
        ),
    )

    m.reproducible = direct_hits > 0 and bool(sig.vulnerable_apis)

    score = 0.0
    if m.reproducible:
        score += 0.50
    if direct_hits >= 2:
        score += 0.10
    if direct_hits >= 4:
        score += 0.05
    if m.repo_active:
        score += 0.10
    if profile.archived:
        score -= 0.40
    if not sig.vulnerable_apis:
        score -= 0.20
    if sig.severity in ("critical", "high"):
        score += 0.10
    if sig.non_default_required:
        score -= 0.10
    if test_hits and not direct_hits:
        score -= 0.10
    if m.package_in_manifest:
        score += 0.05
    if m.lockfile_pinned:
        score += 0.03
    if m.cross_validated:
        score += 0.07

    score = max(0.0, min(1.0, score))
    m.confidence_score = round(score, 2)
    if score >= 0.70:
        m.confidence_label = "high"
    elif score >= 0.45:
        m.confidence_label = "medium"
    else:
        m.confidence_label = "low"
    return m


# --------------------------------------------------------------------------- #
# Step 8 — Final verdict (gpt-5.4-mini, self-questioning JSON)                #
# --------------------------------------------------------------------------- #


_FINAL_SYSTEM = JUDGE_SYSTEM_PROMPT


def _final_user_payload(
    alert_kind: str,
    sig: VulnSignature,
    profile: RepoProfile,
    matches: list[CodeMatch],
    blame: list[BlameInfo],
    org_repos: int,
    matrix: EvidenceMatrix,
    extras: ExtraContext,
    previous_run_hint: str = "",
    skills_context: str = "",
    human_feedback_context: str = "",
    truth_table_summary: str = "",
    org_hunter_summary: str = "",
    global_memory_summary: str = "",
) -> str:
    match_lines = "\n".join(f"- {m.path}" for m in matches[:3]) or "  (none)"
    blame_lines = (
        "\n".join(
            f"- {b.path}: last commit {b.last_commit_sha} by @{b.last_author_login or 'unknown'} "
            f"<{b.last_author_email or 'n/a'}> on {b.last_commit_date or 'n/a'}: "
            f"{b.last_commit_message or '(no message)'}"
            for b in blame[:2]
        )
        or "  (none)"
    )
    readme = (
            f"README excerpt:\n{extras.readme_excerpt[:500]}\n"
        if extras.readme_excerpt
        else "README excerpt: (not fetched)\n"
    )
    manifest = (
            f"Manifest {extras.manifest_path} (package {'IS' if extras.package_pinned_in_manifest else 'is NOT'} pinned here):\n{extras.manifest_excerpt[:500]}\n"
        if extras.manifest_excerpt
        else "Manifest: (not fetched)\n"
    )
    lockf = ""
    if extras.lockfile_path:
        lockf = (
            f"Lockfile {extras.lockfile_path} (package entry "
            f"{'found' if extras.lockfile_has_package else 'not found'}):\n"
            f"{extras.lockfile_excerpt[:350]}\n"
        )
    dockerfile = (
        f"Dockerfile (package {'IS' if extras.package_in_dockerfile else 'is NOT'} referenced here):\n{extras.dockerfile_excerpt[:300]}\n"
        if extras.dockerfile_excerpt
        else "Dockerfile: (not fetched)\n"
    )
    ci = (
        f"CI workflow {extras.ci_workflow_path} (package {'IS' if extras.package_in_ci else 'is NOT'} referenced here):\n{extras.ci_workflow_excerpt[:300]}\n"
        if extras.ci_workflow_excerpt
        else "CI workflow: (not fetched)\n"
    )
    runtime = (
        f"Runtime/deploy {extras.runtime_path} ({extras.exposure_hint or 'exposure unclear'}):\n{extras.runtime_excerpt[:350]}\n"
        if extras.runtime_excerpt
        else "Runtime/deploy config: (not fetched)\n"
    )
    profile_note = (
        "(repo metadata could not be read — treat profile fields as unknown)"
        if profile.profile_fetch_failed
        else ""
    )
    continuity = ""
    if (previous_run_hint or "").strip():
        continuity = f"Continuity / prior run:\n{previous_run_hint.strip()}\n\n"
    skills = (
        f"{skills_context.strip()}\n\n"
        if (skills_context or "").strip()
        else "External Skills: (not available)\n\n"
    )
    human_feedback = (
        f"{human_feedback_context.strip()}\n\n"
        if (human_feedback_context or "").strip()
        else "Relevant human feedback examples: (none)\n\n"
    )
    truth_block = (
        f"{_compact_truth_table(truth_table_summary)}\n\n"
        if (truth_table_summary or "").strip()
        else "Pre-Flight Truth Table: (not available)\n\n"
    )
    hunter_block = (
        f"{org_hunter_summary.strip()}\n\n"
        if (org_hunter_summary or "").strip()
        else "Org-wide deploy discovery: (not run)\n\n"
    )
    memory_block = (
        f"{global_memory_summary.strip()}\n\n"
        if (global_memory_summary or "").strip()
        else "Global memory: (no prior history loaded)\n\n"
    )
    return (
        f"{continuity}"
        f"{truth_block}"
        f"{hunter_block}"
        f"{memory_block}"
        f"Alert kind: {alert_kind}\n"
        f"Advisory: {sig.cve_id or '(no CVE)'} severity={sig.severity or '?'} — "
        f"{sig.ecosystem}/{sig.package}\n"
        f"Affected: {sig.affected_versions or '?'}    Fixed in: {sig.fixed_version or '?'}\n"
        f"Trigger: {sig.trigger_summary or '(advisory does not name a specific surface)'}\n"
        f"Vulnerable APIs (extracted): {', '.join(sig.vulnerable_apis) or '(none)'}\n"
        f"Non-default config required: {sig.non_default_required}\n\n"
        f"Repo: {profile.full_name}    visibility={profile.visibility}    "
        f"fork={profile.is_fork} (parent={profile.parent_full_name or 'n/a'})    "
        f"archived={profile.archived}    language={profile.primary_language or 'n/a'}    "
        f"contributors={profile.contributor_count}    internal_to_org={profile.is_internal}\n"
        f"Activity: {profile.activity_label} {profile_note}\n\n"
        f"{readme}\n"
        f"{manifest}\n"
        f"{lockf}"
        f"{dockerfile}\n"
        f"{ci}\n"
        f"{runtime}\n"
        f"Code matches in repo ({len(matches)} paths from deep search; tests may be included):\n{match_lines}\n\n"
        f"Blame (last commit per touched file):\n{blame_lines}\n\n"
        f"Org-wide repos referencing this package (GitHub search): {org_repos}\n\n"
        f"{skills}"
        f"{human_feedback}"
        "Internal validation summary (do NOT copy numbers or labels into stakeholder_comment):\n"
        f"  reproducible={matrix.reproducible}  cross_validated={matrix.cross_validated}  "
        f"lockfile={matrix.lockfile_pinned}  "
        f"direct_non_test={matrix.direct_code_hits}  test_only={matrix.test_only_hits}  "
        f"confidence_band={matrix.confidence_label}\n"
    )


_BAD_HEDGE = re.compile(r"\bif\s+(?:it\s+is\s+)?(?:being\s+)?used\b", re.IGNORECASE)


def _decision_to_routing(decision: str, matrix: EvidenceMatrix, sig: VulnSignature, profile: RepoProfile) -> tuple[str, str]:
    """Map LLM decision to (routing, impact). Apply hard safety overrides."""
    d = (decision or "").strip().lower()

    if matrix.reproducible and matrix.confidence_label == "high":
        if d == "reproducible":
            return ("in_progress", "direct_vulnerable_usage")
        return ("leave_open", "model_disagrees_with_high_confidence_match")

    if not matrix.reproducible and sig.vulnerable_apis and not profile.archived:
        return ("false_positive", "no_direct_usage")

    if not sig.vulnerable_apis:
        return ("leave_open", "insufficient_advisory_signal")

    return ("leave_open", "insufficient_evidence")


def _format_paths(paths: list[str], max_items: int = 3) -> str:
    trimmed = [p for p in paths if p][:max_items]
    if not trimmed:
        return "none found"
    more = "" if len(paths) <= max_items else f" and {len(paths) - max_items} more"
    return ", ".join(trimmed) + more


def _short_deterministic_comment(
    *,
    sig: VulnSignature,
    profile: RepoProfile,
    matches: list[CodeMatch],
    blame: list[BlameInfo],
    extras: ExtraContext,
    matrix: EvidenceMatrix,
    decision: str,
) -> str:
    """Fast human-readable comment for clear cases; avoids a final LLM call."""
    paths = [m.path for m in matches if not is_test_path(m.path)]
    authors = sorted({f"@{b.last_author_login}" for b in blame if b.last_author_login})
    owner_txt = f" Last touched by {_format_paths(authors, 2)}." if authors else ""
    declared = []
    if extras.manifest_path:
        declared.append(extras.manifest_path)
    if extras.lockfile_path:
        declared.append(extras.lockfile_path)
    if extras.dockerfile_excerpt:
        declared.append("Dockerfile")
    if extras.ci_workflow_path:
        declared.append(extras.ci_workflow_path)
    if extras.runtime_path:
        declared.append(extras.runtime_path)
    declared_txt = _format_paths(declared, 3) if declared else "dependency files"
    pkg = sig.package or "the package"
    fixed = sig.fixed_version or "the fixed version"
    exposure = f" {extras.exposure_hint}." if extras.exposure_hint else ""

    if decision == "false_positive":
        api_txt = _format_paths(sig.vulnerable_apis, 3)
        return (
            f"Checked {profile.full_name} ({profile.visibility}, {profile.activity_label}) against the advisory for {pkg}. "
            f"The dependency is visible in {declared_txt}, but repo search did not find the vulnerable API/symbol path ({api_txt}) in application code.{exposure} "
            f"No reachable usage was found in this repo, so this looks safe to close as noise.{owner_txt}\n\n"
            f"Conclusion: False positive for this repo — vulnerable function path was not found in code."
        )

    if decision == "needs_review":
        return (
            f"Checked {profile.full_name} ({profile.visibility}, {profile.activity_label}) for {pkg}. "
            f"The advisory does not name a specific vulnerable function or the repo evidence is incomplete, so automation cannot prove reachability.{exposure} "
            f"Please review the dependency path and upgrade to {fixed} if the affected code path is confirmed.\n\n"
            "Conclusion: Needs human review — advisory or repo evidence is not specific enough."
        )

    return (
        f"Checked {profile.full_name} ({profile.visibility}, {profile.activity_label}) for {pkg}. "
        f"Repo search found relevant code paths: {_format_paths(paths)}.{owner_txt}{exposure} "
        f"Upgrade {pkg} to {fixed} in the dependency files and verify the affected flow after deployment.\n\n"
        f"Conclusion: Action needed — upgrade {pkg} to {fixed}; relevant paths include {_format_paths(paths, 1)}."
    )


def _make_force_verdict_judgment(
    *,
    sig: VulnSignature,
    profile: RepoProfile,
    matches: list[CodeMatch],
    blame: list[BlameInfo],
    extras: ExtraContext,
    matrix: EvidenceMatrix,
    decision: str,
    force_reason: str,
) -> tuple[str, str, str, list[str], list[str], str]:
    """Build (major_premise, minor_premise, human_conclusion, evidence_for,
    evidence_against, exploitation_path) for a force_verdict short-circuit.
    """
    pkg = sig.package or "the package"
    cve = sig.cve_id or "no CVE id"
    sev = sig.severity or "severity unknown"
    apis = ", ".join(sig.vulnerable_apis[:4]) or "no specific symbols"
    direct = matrix.direct_code_hits if matrix else 0
    test_only = matrix.test_only_hits if matrix else 0
    paths = [m.path for m in matches if not is_test_path(m.path)]
    authors = sorted({f"@{b.last_author_login}" for b in blame if b.last_author_login})

    major = (
        f"{cve} affects {sig.ecosystem}/{pkg} ({sev}); "
        f"vulnerable surface: {apis}."
    )

    if decision == "false_positive":
        minor = (
            f"{profile.full_name} ({profile.activity_label}) shows {direct} non-test "
            f"matches and {test_only} test-only matches for the vulnerable surface; "
            f"{force_reason}."
        )
        human_conclusion = (
            f"{pkg} was checked for {apis} in {profile.full_name}, and no reachable calls were found. "
            "This is safe to close as a repo-specific false positive."
        )
        return (
            major,
            minor,
            human_conclusion,
            [
                f"{direct} non-test matches for vulnerable APIs in this repo",
                f"force_verdict: {force_reason}",
            ],
            [
                "manifest/CI evidence may be incomplete",
            ],
            "no reachable path found",
        )

    if decision == "reproducible":
        minor = (
            f"{profile.full_name} ({profile.activity_label}) has {direct} non-test "
            f"matches at: {_format_paths(paths, 3)}. "
            f"{('Last touched by ' + _format_paths(authors, 2) + '.') if authors else ''}"
        )
        human_conclusion = (
            f"Upgrade {pkg} to {sig.fixed_version or 'the fixed version'} in {profile.full_name}. "
            f"The vulnerable surface is reachable through {_format_paths(paths, 3)}, so please plan the upgrade and re-test the affected flow."
        )
        return (
            major,
            minor,
            human_conclusion,
            [
                f"{direct} non-test matches in {_format_paths(paths, 3)}",
                f"force_verdict: {force_reason}",
            ],
            [
                "exposure/blast radius may need manual confirmation",
            ],
            "direct reachability via " + (paths[0] if paths else "code search"),
        )

    minor = (
        f"{profile.full_name} ({profile.activity_label}) lacks the evidence required "
        "to make an automated decision."
    )
    human_conclusion = (
        "Automated triage could not make a reliable decision from the available advisory and repo evidence. "
        "Please review the dependency path manually before closing or upgrading this ticket."
    )
    return (
        major,
        minor,
        human_conclusion,
        [],
        ["force_verdict could not produce a decision"],
        "",
    )


def _render_agentic_human_comment(
    *,
    routing: str,
    sig: VulnSignature,
    human_conclusion: str,
    matches: list[CodeMatch],
    truth_table: Any = None,
    extras: ExtraContext | None = None,
) -> str:
    paths = [m.path for m in matches if not is_test_path(m.path)]
    hosted_hint = str(getattr(truth_table, "hosted_hint", "") or "")
    source_path = paths[0] if paths else str(getattr(truth_table, "hosted_source", "") or "")
    if routing == "false_positive":
        reason = human_conclusion or f"{sig.package or 'the package'} does not reach the vulnerable advisory path"
        return render_false_positive_comment(sig.package, "", reason=reason, path_or_signal=source_path)
    if routing == "in_progress":
        return render_action_needed_comment(
            sig.package,
            sig.fixed_version,
            path=source_path,
            hosted_hint=hosted_hint,
        )
    gap = human_conclusion or "the exact vulnerable path could not be confirmed from GitHub data"
    if extras and extras.exposure_hint:
        gap = f"{gap} ({extras.exposure_hint})"
    return render_needs_review_comment(sig.package, gap)


def final_verdict(
    config: dict[str, Any],
    *,
    alert_kind: str,
    sig: VulnSignature,
    profile: RepoProfile,
    matches: list[CodeMatch],
    blame: list[BlameInfo],
    org_repos: int,
    matrix: EvidenceMatrix,
    extras: ExtraContext,
    previous_run_hint: str = "",
    skills_context: str = "",
    human_feedback_context: str = "",
    truth_table: Any = None,
    truth_table_summary: str = "",
    org_hunter_summary: str = "",
    global_memory_summary: str = "",
) -> AgenticVerdict:
    """Run the Final Judge.

    If the Pre-Flight Truth Table sets force_verdict, the LLM call is skipped
    entirely and a deterministic syllogism judgment is produced. Otherwise the
    LLM is called with the full context and required to return the new strict
    JSON contract (human_conclusion plus internal routing fields).
    """
    g = config.get("global", {}).get("llm", {})
    model = str(g.get("judge_model", g.get("model", "gpt-5.4-mini")))
    user = _final_user_payload(
        alert_kind, sig, profile, matches, blame, org_repos, matrix, extras,
        previous_run_hint=previous_run_hint,
        skills_context=skills_context,
        human_feedback_context=human_feedback_context,
        truth_table_summary=truth_table_summary,
        org_hunter_summary=org_hunter_summary,
        global_memory_summary=global_memory_summary,
    )

    confidence_score = int(round(float(matrix.confidence_score or 0) * 100))
    blast_radius = "unknown"
    priority = "P3"

    if truth_table is not None and getattr(truth_table, "force_verdict", ""):
        decision = truth_table.force_verdict
        force_reason = truth_table.force_reason or "deterministic pre-flight rule"
        major, minor, human_conclusion, ev_for, ev_against, exploitation = _make_force_verdict_judgment(
            sig=sig,
            profile=profile,
            matches=matches,
            blame=blame,
            extras=extras,
            matrix=matrix,
            decision=decision,
            force_reason=force_reason,
        )
        routing = "false_positive" if decision == "false_positive" else (
            "in_progress" if decision == "reproducible" else "leave_open"
        )
        human_body = _render_agentic_human_comment(
            routing=routing,
            sig=sig,
            human_conclusion=human_conclusion,
            matches=matches,
            truth_table=truth_table,
            extras=extras,
        )
        confidence_score = max(confidence_score, 85 if decision != "needs_review" else confidence_score)
        return AgenticVerdict(
            routing=routing,
            impact=("forced_" + decision),
            confidence="high" if decision != "needs_review" else "low",
            reproducible=(decision == "reproducible"),
            jira_comment=human_body,
            profile=profile,
            signature=sig,
            matrix=matrix,
            matches=matches,
            blame=blame,
            org_repos_affected=org_repos,
            extras=extras,
            evidence_for=ev_for,
            evidence_against=ev_against,
            exploitation_path=exploitation,
            blast_radius=blast_radius,
            risk_score=(2 if decision == "false_positive" else 6 if decision == "reproducible" else 3),
            confidence_score=confidence_score,
            priority=("P2" if decision == "reproducible" else "P3"),
            tier=truth_table.tier,
            tier_reason=truth_table.tier_reason,
            force_verdict=decision,
            force_reason=force_reason,
            major_premise=major,
            minor_premise=minor,
            truth_table_summary=truth_table_summary,
            org_hunter_summary=org_hunter_summary,
            global_memory_summary=global_memory_summary,
            deterministic_short_circuit=True,
        )

    if (
        (human_feedback_context or "").strip()
        and sig.package
        and sig.package.lower() in human_feedback_context.lower()
        and "human=false_positive" in human_feedback_context.lower()
    ):
        routing = "false_positive"
        comment = render_false_positive_comment(
            sig.package,
            profile.full_name,
            reason="Prior human triage for this package/CVE marked the same pattern as not reachable",
            path_or_signal="",
        )
        return AgenticVerdict(
            routing=routing,
            impact="human_memory_match",
            confidence="high",
            reproducible=False,
            jira_comment=comment,
            profile=profile,
            signature=sig,
            matrix=matrix,
            matches=matches,
            blame=blame,
            org_repos_affected=org_repos,
            extras=extras,
            evidence_for=["strong matching human feedback memory"],
            exploitation_path="no reachable path found",
            confidence_score=max(confidence_score, 85),
            priority="P3",
            tier=getattr(truth_table, "tier", "tier_3_internal"),
            tier_reason=getattr(truth_table, "tier_reason", ""),
            truth_table_summary=truth_table_summary,
            org_hunter_summary=org_hunter_summary,
            global_memory_summary=global_memory_summary,
            deterministic_short_circuit=True,
        )

    decision = ""
    evidence_for: list[str] = []
    evidence_against: list[str] = []
    exploitation_path = ""
    major_premise = ""
    minor_premise = ""
    human_conclusion = ""
    try:
        oai = build_openai_client(config)
        data = _llm_json(oai, model, _FINAL_SYSTEM, user)
        decision = str(data.get("decision", "") or "").strip().lower()
        ef = data.get("evidence_for") or []
        ea = data.get("evidence_against") or []
        if isinstance(ef, list):
            evidence_for = [str(x)[:200] for x in ef][:5]
        if isinstance(ea, list):
            evidence_against = [str(x)[:200] for x in ea][:5]
        exploitation_path = str(data.get("exploitation_path", "") or "").strip()[:400]
        blast_radius = str(data.get("blast_radius", "unknown") or "unknown").strip().lower()
        if blast_radius not in {"single_service", "multi_service", "customer_facing", "internal_only", "unknown"}:
            blast_radius = "unknown"
        try:
            confidence_score = int(data.get("confidence_score", confidence_score))
        except (TypeError, ValueError):
            pass
        confidence_score = max(0, min(100, confidence_score))
        priority = str(data.get("priority", "") or "").strip().upper()
        if priority not in {"P0", "P1", "P2", "P3"}:
            priority = "P3"
        major_premise = str(data.get("major_premise", "") or "").strip()[:600]
        minor_premise = str(data.get("minor_premise", "") or "").strip()[:600]
        human_conclusion = str(
            data.get("human_conclusion", "") or data.get("conclusion_summary", "") or "",
        ).strip()[:800]
    except Exception as exc:  # noqa: BLE001
        log.warning("final verdict LLM call failed: %s", exc)
        decision = "needs_review"
        human_conclusion = "Automated triage could not finish cleanly. Please re-run the job or review this alert manually before changing the ticket."

    if decision not in {"false_positive", "reproducible", "needs_review"}:
        decision = "needs_review"

    if decision == "false_positive":
        if not exploitation_path:
            exploitation_path = "no reachable path found"

    routing, impact = _decision_to_routing(decision, matrix, sig, profile)

    comment = _render_agentic_human_comment(
        routing=routing,
        sig=sig,
        human_conclusion=human_conclusion,
        matches=matches,
        truth_table=truth_table,
        extras=extras,
    )

    return AgenticVerdict(
        routing=routing,
        impact=impact,
        confidence=matrix.confidence_label,
        reproducible=matrix.reproducible,
        jira_comment=comment,
        profile=profile,
        signature=sig,
        matrix=matrix,
        matches=matches,
        blame=blame,
        org_repos_affected=org_repos,
        extras=extras,
        evidence_for=evidence_for,
        evidence_against=evidence_against,
        exploitation_path=exploitation_path,
        blast_radius=blast_radius,
        risk_score=(2 if routing == "false_positive" else 6 if routing == "in_progress" else 3),
        confidence_score=confidence_score,
        priority=priority,
        tier=getattr(truth_table, "tier", "tier_3_internal"),
        tier_reason=getattr(truth_table, "tier_reason", ""),
        major_premise=major_premise,
        minor_premise=minor_premise,
        truth_table_summary=truth_table_summary,
        org_hunter_summary=org_hunter_summary,
        global_memory_summary=global_memory_summary,
    )


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #


def agentic_triage(
    config: dict[str, Any],
    client: GitHubClient,
    *,
    owner: str,
    repo: str,
    branch: str,
    org: str,
    alert_kind: str,
    alert: dict[str, Any],
    previous_run_hint: str = "",
    human_feedback_context: str = "",
    repo_root: Path | None = None,
    memory_store: Any | None = None,
) -> AgenticVerdict:
    """Autonomous triage orchestrator.

    Pipeline:
    1. AdvisoryAgent (LLM)        — extract vulnerable signature.
    2. EvidenceAgent (det.)       — repo profile, reachability, blame, manifests.
    3. OrgHunterAgent (det.)      — cross-repo deploy/build references.
    4. KnowledgeManager (det.)    — external skills snippets.
    5. GlobalMemory (det.)        — cross-repo CVE/package consensus.
    6. Pre-Flight Truth Table     — tier, file existence, force_verdict.
    7. Final Judge (LLM)          — strict JSON syllogism (or skipped on force).
    8. ProsecutorAgent (LLM)      — adversarial peer review of the verdict.
    9. Silent CriticAgent         — internal-only audit, no Jira leakage.
    10. Recursive Deep Dive       — re-collect evidence + re-judge if low conf.
    """
    from ghas_llm.agents.advisory_agent import AdvisoryAgent
    from ghas_llm.agents.critic_agent import CriticAgent
    from ghas_llm.agents.evidence_agent import EvidenceAgent
    from ghas_llm.agents.knowledge_agent import KnowledgeManager, format_skill_hits
    from ghas_llm.agents.org_hunter_agent import OrgHunterAgent, format_org_hunter_findings
    from ghas_llm.agents.prosecutor_agent import ProsecutorAgent
    from ghas_llm.core.preflight import build_truth_table, format_truth_table
    from ghas_llm.logic.global_memory import GlobalMemory, format_global_memory
    from ghas_llm.logic.syllogism import build_human_comment, strip_internal_metadata

    agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
    history_rel = str(agent_cfg.get("triage_history_file", ".triage_history.jsonl")).strip()
    deep_dive_cfg = (
        agent_cfg.get("recursive_deep_dive", {})
        if isinstance(agent_cfg.get("recursive_deep_dive", {}), dict)
        else {}
    )
    deep_dive_enabled = bool(deep_dive_cfg.get("enabled", True))
    deep_dive_max = int(deep_dive_cfg.get("max_iterations", 1))

    sig = AdvisoryAgent(config).extract(alert)

    def _collect_evidence(extra_query_boost: int = 0) -> Any:
        ev_agent = EvidenceAgent(client, config)
        if extra_query_boost:
            ev_agent.max_search_queries = ev_agent.max_search_queries + extra_query_boost
            ev_agent.max_code_matches = ev_agent.max_code_matches + extra_query_boost
        return ev_agent.collect(
            owner=owner,
            repo=repo,
            branch=branch,
            org=org,
            alert_kind=alert_kind,
            alert=alert,
            signature=sig,
        )

    evidence = _collect_evidence()
    hunter_cache = agent_cfg.setdefault("_org_hunter_cache", {})
    hunter_key = f"{org}:{owner}/{repo}"
    if isinstance(hunter_cache, dict) and hunter_key in hunter_cache:
        hunter = hunter_cache[hunter_key]
    else:
        hunter = OrgHunterAgent(client, config).discover(owner=owner, repo=repo, org=org)
        if isinstance(hunter_cache, dict):
            hunter_cache[hunter_key] = hunter

    skill_hits = KnowledgeManager.from_config(config).query_skills(
        " ".join(
            [
                alert_kind,
                sig.package,
                sig.ecosystem,
                sig.cve_id,
                sig.trigger_summary,
                " ".join(sig.vulnerable_apis),
                " ".join(m.path for m in evidence.matches[:10]),
            ],
        ),
    )
    skills_context = format_skill_hits(skill_hits)

    repo_full = f"{owner}/{repo}"
    global_memory = (
        GlobalMemory(repo_root, history_rel, store=memory_store)
        if repo_root is not None and history_rel
        else None
    )
    snap = (
        global_memory.query(package=sig.package, cve_id=sig.cve_id, current_repo=repo_full)
        if global_memory is not None
        else None
    )
    global_memory_summary = format_global_memory(snap) if snap is not None else ""

    truth_table = build_truth_table(
        profile=evidence.profile,
        matrix=evidence.matrix,
        extras=evidence.extras,
        sig=sig,
        hunter=hunter,
        config=config,
    )
    truth_table_summary = format_truth_table(truth_table)
    hunter_summary = format_org_hunter_findings(hunter)

    verdict = final_verdict(
        config,
        alert_kind=alert_kind,
        sig=sig,
        profile=evidence.profile,
        matches=evidence.matches,
        blame=evidence.blame,
        org_repos=evidence.org_repos,
        matrix=evidence.matrix,
        extras=evidence.extras,
        previous_run_hint=previous_run_hint,
        skills_context=skills_context,
        human_feedback_context=human_feedback_context,
        truth_table=truth_table,
        truth_table_summary=truth_table_summary,
        org_hunter_summary=hunter_summary,
        global_memory_summary=global_memory_summary,
    )

    if verdict.deterministic_short_circuit:
        verdict.tier = truth_table.tier
        verdict.tier_reason = truth_table.tier_reason
        verdict.truth_table_summary = truth_table_summary
        verdict.org_hunter_summary = hunter_summary
        verdict.global_memory_summary = global_memory_summary
        verdict.jira_comment = humanize(strip_internal_metadata(verdict.jira_comment), max_chars=280)
        return verdict

    payload = _final_user_payload(
        alert_kind,
        sig,
        evidence.profile,
        evidence.matches,
        evidence.blame,
        evidence.org_repos,
        evidence.matrix,
        evidence.extras,
        previous_run_hint=previous_run_hint,
        skills_context=skills_context,
        human_feedback_context=human_feedback_context,
        truth_table_summary=truth_table_summary,
        org_hunter_summary=hunter_summary,
        global_memory_summary=global_memory_summary,
    )

    prosecutor = ProsecutorAgent(config)
    prosecutor_report = prosecutor.review(
        verdict=verdict,
        truth_table=truth_table,
        evidence_payload=payload,
    )
    verdict.prosecutor_uphold = prosecutor_report.uphold
    verdict.prosecutor_attack_holes = prosecutor_report.attack_holes

    if (
        not prosecutor_report.uphold
        and prosecutor_report.alternate_decision
        and prosecutor_report.alternate_decision in {"false_positive", "reproducible", "needs_review"}
    ):
        # Adversarial override: rebuild the verdict using the prosecutor's
        # alternate decision but still in the certified syllogism format.
        decision = prosecutor_report.alternate_decision
        routing = "false_positive" if decision == "false_positive" else (
            "in_progress" if decision == "reproducible" else "leave_open"
        )
        major, minor, human_conclusion, ev_for, ev_against, exploitation = _make_force_verdict_judgment(
            sig=sig,
            profile=evidence.profile,
            matches=evidence.matches,
            blame=evidence.blame,
            extras=evidence.extras,
            matrix=evidence.matrix,
            decision=decision,
            force_reason=(
                prosecutor_report.alternate_conclusion
                or "adversarial peer review override"
            ),
        )
        human_body = _render_agentic_human_comment(
            routing=routing,
            sig=sig,
            human_conclusion=human_conclusion,
            matches=evidence.matches,
            truth_table=truth_table,
            extras=evidence.extras,
        )
        verdict.routing = routing
        verdict.impact = f"prosecutor_override_{decision}"
        verdict.reproducible = (decision == "reproducible")
        verdict.confidence = "high" if decision != "needs_review" else "low"
        verdict.major_premise = major
        verdict.minor_premise = minor
        verdict.evidence_for = ev_for
        verdict.evidence_against = ev_against + verdict.prosecutor_attack_holes
        verdict.exploitation_path = exploitation
        verdict.jira_comment = human_body

    if (
        deep_dive_enabled
        and prosecutor_report.should_recompute_evidence
        and verdict.deep_dive_count < deep_dive_max
    ):
        # Recursive deep dive: ask the EvidenceAgent for more queries and
        # re-judge with the same truth table + hunter findings.
        verdict.deep_dive_count += 1
        evidence = _collect_evidence(extra_query_boost=4)
        truth_table = build_truth_table(
            profile=evidence.profile,
            matrix=evidence.matrix,
            extras=evidence.extras,
            sig=sig,
            hunter=hunter,
            config=config,
        )
        truth_table_summary = format_truth_table(truth_table)
        verdict = final_verdict(
            config,
            alert_kind=alert_kind,
            sig=sig,
            profile=evidence.profile,
            matches=evidence.matches,
            blame=evidence.blame,
            org_repos=evidence.org_repos,
            matrix=evidence.matrix,
            extras=evidence.extras,
            previous_run_hint=previous_run_hint,
            skills_context=skills_context,
            human_feedback_context=human_feedback_context,
            truth_table=truth_table,
            truth_table_summary=truth_table_summary,
            org_hunter_summary=hunter_summary,
            global_memory_summary=global_memory_summary,
        )
        verdict.deep_dive_count = 1

    # Silent critic: never mutates the Jira comment. Only changes routing if
    # the critic finds an unrecoverable issue and recursive deep dive did not
    # already resolve it.
    critic = CriticAgent(config)
    trust_cfg = agent_cfg.get("production_trust", {}) if isinstance(agent_cfg.get("production_trust", {}), dict) else {}
    min_confidence = int(trust_cfg.get("min_confidence_for_action", truth_table.confidence_floor_post))
    critic_decision = critic.review(
        verdict=verdict,
        evidence_payload=payload,
        min_confidence=min_confidence,
    )
    if (
        not critic_decision.approve
        and critic_decision.downgrade_to == "needs_review"
        and verdict.deep_dive_count >= deep_dive_max
        and not truth_table.force_verdict
    ):
        verdict.routing = "leave_open"
        verdict.impact = "critic_downgrade"
        verdict.confidence = "low"
        verdict.reproducible = False
        verdict.priority = "P3"
        verdict.evidence_against.append(critic_decision.reason or "critic downgrade")
        # Rebuild the Jira comment so the conclusion line reflects the new
        # routing without leaking critic notes or scores.
        verdict.jira_comment = build_human_comment(
            routing="leave_open",
            human_conclusion=(
                "Automated peer review found unsupported claims in the generated verdict. "
                "Please review the dependency path manually before closing or upgrading this ticket."
            ),
        ).body

    verdict.tier = truth_table.tier
    verdict.tier_reason = truth_table.tier_reason
    verdict.truth_table_summary = truth_table_summary
    verdict.org_hunter_summary = hunter_summary
    verdict.global_memory_summary = global_memory_summary
    verdict.jira_comment = humanize(strip_internal_metadata(verdict.jira_comment), max_chars=280)
    return verdict
