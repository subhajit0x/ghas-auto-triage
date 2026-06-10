"""External security knowledge worker.

The worker keeps a shallow local cache of curated public security repositories
and returns short, relevant Markdown/YAML snippets for the Final Judge.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SkillRepo:
    name: str
    url: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class SkillHit:
    source: str
    path: str
    score: int
    excerpt: str


DEFAULT_SKILL_REPOS: tuple[SkillRepo, ...] = (
    SkillRepo(
        name="github-securitylab",
        url="https://github.com/github/securitylab.git",
        paths=("CodeQL", "SecurityExploits", "docs", "research"),
    ),
    SkillRepo(
        name="semgrep-rules",
        url="https://github.com/semgrep/semgrep-rules.git",
        paths=("p/security", "p/false-positives", "generic", "javascript", "python"),
    ),
    SkillRepo(
        name="osv-scanner",
        url="https://github.com/google/osv-scanner.git",
        paths=("docs", "internal", "pkg"),
    ),
    SkillRepo(
        name="owasp-cheatsheets",
        url="https://github.com/OWASP/CheatSheetSeries.git",
        paths=("cheatsheets",),
    ),
    SkillRepo(
        name="anthropic-cybersecurity-skills",
        url="https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git",
        paths=(),
    ),
)


class KnowledgeManager:
    """Clone/update skill repos and query reference snippets.

    Network work is opt-in through config. If clone/update fails, query_skills
    returns an empty list rather than blocking Jira triage.
    """

    def __init__(
        self,
        *,
        cache_dir: Path,
        repos: Iterable[SkillRepo] = DEFAULT_SKILL_REPOS,
        enabled: bool = True,
        refresh: bool = False,
        max_files_per_repo: int = 400,
    ) -> None:
        self.cache_dir = cache_dir
        self.repos = tuple(repos)
        self.enabled = enabled
        self.refresh = refresh
        self.max_files_per_repo = max_files_per_repo

    @classmethod
    def from_config(cls, config: dict) -> "KnowledgeManager":
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        skills_cfg = agent_cfg.get("skills_library", {})
        if not isinstance(skills_cfg, dict):
            skills_cfg = {}
        cache_dir = Path(
            os.environ.get(
                "GHAS_LLM_SKILLS_CACHE",
                str(skills_cfg.get("cache_dir", ".cache/skills")),
            ),
        )
        return cls(
            cache_dir=cache_dir,
            enabled=bool(skills_cfg.get("enabled", False)),
            refresh=bool(skills_cfg.get("refresh", False)),
            max_files_per_repo=int(skills_cfg.get("max_files_per_repo", 400)),
        )

    def ensure_repos(self) -> None:
        if not self.enabled:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        for repo in self.repos:
            target = self.cache_dir / repo.name
            try:
                if target.exists():
                    if self.refresh:
                        subprocess.run(
                            ["git", "-C", str(target), "pull", "--ff-only"],
                            check=False,
                            timeout=90,
                            capture_output=True,
                            text=True,
                        )
                    continue
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo.url, str(target)],
                    check=False,
                    timeout=180,
                    capture_output=True,
                    text=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                log.warning("skill repo %s unavailable: %s", repo.name, exc)

    def query_skills(
        self,
        context: str,
        *,
        max_hits: int = 6,
        max_excerpt_chars: int = 900,
    ) -> list[SkillHit]:
        if not self.enabled:
            return []
        self.ensure_repos()
        terms = _query_terms(context)
        if not terms:
            return []

        hits: list[SkillHit] = []
        for repo in self.repos:
            root = self.cache_dir / repo.name
            if not root.exists():
                continue
            for path in _candidate_files(root, repo.paths, self.max_files_per_repo):
                text = _read_text(path)
                if not text:
                    continue
                score = _score(text, terms)
                if score <= 0:
                    continue
                hits.append(
                    SkillHit(
                        source=repo.name,
                        path=str(path.relative_to(root)),
                        score=score,
                        excerpt=_excerpt(text, terms, max_excerpt_chars),
                    ),
                )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:max_hits]


def format_skill_hits(hits: list[SkillHit]) -> str:
    if not hits:
        return "External Skills: (no matching external skill snippets found)"
    blocks = ["External Skills:"]
    for hit in hits:
        blocks.append(
            f"- {hit.source}/{hit.path} (score={hit.score})\n"
            f"  {hit.excerpt.replace(chr(10), chr(10) + '  ')}",
        )
    return "\n".join(blocks)


def _candidate_files(root: Path, subpaths: tuple[str, ...], limit: int) -> list[Path]:
    starts = [root / p for p in subpaths] if subpaths else [root]
    out: list[Path] = []
    for start in starts:
        if not start.exists():
            continue
        for path in start.rglob("*"):
            if len(out) >= limit:
                return out
            if path.suffix.lower() not in {".md", ".markdown", ".yaml", ".yml"}:
                continue
            if any(part.startswith(".") and part != "." for part in path.parts):
                continue
            out.append(path)
    return out


def _query_terms(context: str) -> list[str]:
    raw = set(re.findall(r"[A-Za-z0-9_.:/-]{3,}", context.lower()))
    stop = {
        "github",
        "security",
        "dependabot",
        "code-scanning",
        "secret-scanning",
        "unknown",
        "package",
        "version",
    }
    return sorted(t for t in raw if t not in stop)[:40]


def _score(text: str, terms: list[str]) -> int:
    low = text.lower()
    score = 0
    for term in terms:
        if term in low:
            score += 1
    return score


def _excerpt(text: str, terms: list[str], max_chars: int) -> str:
    low = text.lower()
    first = min((low.find(t) for t in terms if t in low), default=0)
    start = max(0, first - 250)
    return " ".join(text[start:start + max_chars].split())


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:200_000]
    except OSError:
        return ""

