"""One-line Jira comments for GHAS triage."""

from __future__ import annotations

import re

_BANNED_PATTERNS = (
    re.compile(r"<!--\s*ghas-triage-agent[^>]*-->", re.IGNORECASE),
    re.compile(r"\b(deterministic search|non-test(?:\s+\w+){0,3}|repository tier|negative proof|matrix|confidence)\b", re.IGNORECASE),
    re.compile(r"\([^)]*(?:private|actively maintained|last commit)[^)]*\)", re.IGNORECASE),
    re.compile(r"^\s*(Conclusion|Evidence|Impact|Repository tier|Negative proofs)\s*:\s*", re.IGNORECASE),
    re.compile(r"\bin the repository data provided\b", re.IGNORECASE),
)


def humanize(text: str, max_chars: int = 280) -> str:
    body = (text or "").replace("\n", " ").strip()
    for pat in _BANNED_PATTERNS:
        body = pat.sub("", body)
    body = re.sub(r"\s+", " ", body).strip(" -—:;")
    if len(body) <= max_chars:
        return body
    cut = body[: max(0, max_chars - 1)].rsplit(" ", 1)[0].strip()
    return (cut or body[: max_chars - 1]).rstrip(".,;") + "…"


def _pkg(package: str) -> str:
    return package or "the dependency"


def render_fixed_comment(package: str = "") -> str:
    return humanize(f"GitHub already marks {_pkg(package)} as fixed, so I’m closing this Jira ticket.")


def render_withdrawn_comment(package: str = "") -> str:
    return humanize(f"GitHub has withdrawn the advisory for {_pkg(package)}, so I’m closing this Jira ticket.")


def render_missing_alert_comment(repo: str = "") -> str:
    target = f" for {repo}" if repo else ""
    return humanize(f"The GitHub Dependabot alert{target} is no longer present, so I’m closing this Jira ticket as stale or withdrawn.")


def render_false_positive_comment(package: str, repo: str, reason: str = "", path_or_signal: str = "") -> str:
    where = f" in `{path_or_signal}`" if path_or_signal else ""
    why = reason or f"{_pkg(package)} is not reached by the vulnerable path"
    if re.search(r"\b(safe to close|false positive|not reachable|no reachable usage)\b", why, re.IGNORECASE):
        return humanize(f"{why}{where}")
    return humanize(f"{why}{where}, so this looks safe to close as a repo-specific false positive.")


def render_action_needed_comment(package: str, fixed_version: str = "", path: str = "", hosted_hint: str = "") -> str:
    version = f" to {fixed_version}" if fixed_version else ""
    where = f" via `{path}`" if path else ""
    host = f" ({hosted_hint})" if hosted_hint and hosted_hint != "unknown" else ""
    return humanize(f"Upgrade {_pkg(package)}{version}{where}{host}; the affected path is reachable here and should be retested after the dependency update.")


def render_needs_review_comment(package: str, exact_gap: str) -> str:
    gap = exact_gap or "the advisory does not name a specific reachable path"
    gap = re.sub(r"\bthe alert is not supported by\b", "GitHub did not show", gap, flags=re.IGNORECASE)
    gap = re.sub(r"\bIf a source call[^.]*\.", "", gap, flags=re.IGNORECASE)
    prefix = _pkg(package)
    if prefix == "the dependency" and "Cargo.lock" in gap:
        return humanize("Cargo.lock is the only signal found, so check the source path once before changing this ticket.")
    return humanize(f"{prefix} needs a quick manual check because {gap}.")

