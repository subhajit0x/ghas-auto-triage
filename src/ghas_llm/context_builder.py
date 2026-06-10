"""Load repository file context for LLM (bounded size, read-only)."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


def _read_lines(path: Path, start: int | None, end: int | None, pad: int = 5) -> str:
    if not path.is_file():
        return f"(file not found: {path})"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"(read error: {path}: {e})"
    lines = text.splitlines()
    if start is None or end is None:
        chunk = lines[:300]
        return "\n".join(f"{i+1:5}|{line}" for i, line in enumerate(chunk))
    a = max(0, start - pad - 1)
    b = min(len(lines), end + pad)
    out = []
    for i in range(a, b):
        out.append(f"{i+1:5}|{lines[i]}")
    return "\n".join(out)


def clone_repo_readonly(owner: str, repo: str, target_dir: Path, branch: str = "") -> bool:
    """Shallow-clone a repo using SSH (ORG_SSH_KEY) or HTTPS (GITHUB_TOKEN). Read-only."""
    ssh_key = os.environ.get("ORG_SSH_KEY_PATH") or ""
    token = os.environ.get("GITHUB_TOKEN", "")
    prefer_ssh = os.environ.get("GHAS_LLM_PREFER_SSH_CLONE", "").strip().lower() in ("1", "true", "yes")

    if prefer_ssh and (not ssh_key or not Path(ssh_key).is_file()):
        log.warning("GHAS_LLM_PREFER_SSH_CLONE set but ORG_SSH_KEY_PATH missing or invalid")
        return False

    if ssh_key and Path(ssh_key).is_file():
        url = f"git@github.com:{owner}/{repo}.git"
        env = {**os.environ, "GIT_SSH_COMMAND": f"ssh -i {ssh_key} -o StrictHostKeyChecking=no"}
    elif token:
        url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
        env = dict(os.environ)
    else:
        return False

    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, str(target_dir)]

    try:
        subprocess.run(cmd, env=env, capture_output=True, timeout=120, check=True)
        ref = branch or "default"
        log.info("cloned %s/%s (ref=%s)", owner, repo, ref)
        return True
    except subprocess.CalledProcessError as exc:
        log.warning("clone %s/%s failed (exit %s): %s", owner, repo, exc.returncode,
                     (exc.stderr or b"").decode(errors="replace")[:500])
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.warning("clone %s/%s error: %s", owner, repo, exc)
        return False


def dependabot_usage_hints(repo_root: Path, alert: dict, max_chars: int = 3500) -> str:
    """Search cloned tree for import/require references to the dependency (bounded)."""
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    eco = str(pkg.get("ecosystem", "")).lower()
    name = str(pkg.get("name", "")).strip()
    if not name or not repo_root.is_dir():
        return ""

    needles: list[str] = []
    if eco == "pip":
        mod = name.lower().replace("-", "_")
        needles.extend([f"import {mod}", f"from {mod}", f"import {name}", f"from {name}"])
        if "pillow" in name.lower():
            needles.extend(["import PIL", "from PIL", "Pillow"])
    elif eco in ("npm", "yarn", "pnpm"):
        needles.extend([f'"{name}"', f"'{name}'", f'require("{name}")', f"require('{name}')", f"from '{name}'"])
    else:
        needles.append(name)

    lines_out: list[str] = []
    seen_files: set[str] = set()
    exts = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".gradle", ".xml"}
    try:
        for path in sorted(repo_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if len(seen_files) >= 80:
                break
            try:
                rel = path.relative_to(repo_root.resolve())
            except ValueError:
                continue
            rel_s = str(rel).replace("\\", "/")
            if any(x in rel_s for x in ("/.git/", "/node_modules/", "/venv/", "/.venv/", "/dist/", "/build/")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lower = text.lower()
            hit = False
            for n in needles:
                if n.lower() in lower:
                    hit = True
                    break
            if not hit:
                continue
            seen_files.add(rel_s)
            snippet = "\n".join(text.splitlines()[:120])
            lines_out.append(f"--- {rel_s} (match) ---\n{snippet[:2000]}")
            if sum(len(x) for x in lines_out) >= max_chars:
                break
    except OSError:
        return ""

    if not lines_out:
        return f"(No obvious source matches for package {name!r} in a quick scan; manifest-only or transitive.)"
    out = "\n\n".join(lines_out)
    if len(out) > max_chars:
        return out[: max_chars - 80] + "\n... [usage hints truncated]\n"
    return out


def build_context(
    repo_root: Path,
    *,
    paths: list[str],
    locations: list[tuple[str | None, int | None, int | None]],
    max_chars: int,
    clone_owner: str = "",
    clone_repo: str = "",
    clone_branch: str = "",
    dependabot_alert: dict | None = None,
) -> tuple[str, str | None]:
    """Concatenate unique file snippets until max_chars. Optionally clones via ORG_SSH_KEY.

    Returns (context_text, clone_error) where clone_error is set if clone was required but failed.
    """
    cloned_tmp: tempfile.TemporaryDirectory | None = None
    clone_error: str | None = None
    did_clone = False
    all_files = list(paths) + [r for r, _, _ in locations if r]
    has_local = any((repo_root / f.lstrip("/")).is_file() for f in all_files if f)

    if not has_local and clone_owner and clone_repo:
        log.info("no local files for %s/%s, attempting clone", clone_owner, clone_repo)
        cloned_tmp = tempfile.TemporaryDirectory(prefix="ghas_llm_clone_")
        clone_path = Path(cloned_tmp.name) / clone_repo
        branch = (clone_branch or "").strip()
        if clone_repo_readonly(clone_owner, clone_repo, clone_path, branch=branch):
            repo_root = clone_path
            did_clone = True
        else:
            clone_error = f"git clone failed for {clone_owner}/{clone_repo}" + (f" (branch {branch})" if branch else "")
            log.warning("clone failed for %s/%s, context will be empty", clone_owner, clone_repo)

    parts: list[str] = []
    seen_locs: set[str] = set()
    seen_paths: set[str] = set()
    for rel, start, end in locations:
        if not rel:
            continue
        rel = rel.replace("\\", "/").lstrip("/")
        key = f"{rel}:{start}:{end}"
        if key in seen_locs:
            continue
        seen_locs.add(key)
        full = (repo_root / rel).resolve()
        try:
            full.relative_to(repo_root.resolve())
        except ValueError:
            parts.append(f"### Skipped path outside repo: {rel}\n")
            continue
        block = f"### File: {rel}\n```\n{_read_lines(full, start, end)}\n```\n"
        parts.append(block)
        if sum(len(p) for p in parts) >= max_chars:
            break
    for rel in paths:
        rel = rel.replace("\\", "/").lstrip("/")
        if not rel or rel in seen_paths:
            continue
        seen_paths.add(rel)
        full = (repo_root / rel).resolve()
        try:
            full.relative_to(repo_root.resolve())
        except ValueError:
            continue
        block = f"### Manifest / lockfile: {rel}\n```\n{_read_lines(full, None, None)}\n```\n"
        parts.append(block)
        if sum(len(p) for p in parts) >= max_chars:
            break
    out = "\n".join(parts)

    if dependabot_alert and paths and (did_clone or has_local) and clone_error is None:
        hint_budget = min(4000, max(500, max_chars // 2))
        hints = dependabot_usage_hints(repo_root, dependabot_alert, max_chars=hint_budget)
        if hints:
            extra = "\n\n=== Usage search (package references) ===\n" + hints
            out = out + extra

    if cloned_tmp:
        cloned_tmp.cleanup()
    if len(out) > max_chars:
        out = out[: max_chars - 80] + "\n\n... [truncated to max_context_chars]\n"
    return out, clone_error


def locations_from_code_scanning(alert: dict) -> list[tuple[str | None, int | None, int | None]]:
    locs: list[tuple[str | None, int | None, int | None]] = []
    inst = alert.get("most_recent_instance") or {}
    loc = inst.get("location") or {}
    path = loc.get("path")
    sl = loc.get("start_line")
    el = loc.get("end_line")
    try:
        sli = int(sl) if sl is not None else None
    except (TypeError, ValueError):
        sli = None
    try:
        eli = int(el) if el is not None else None
    except (TypeError, ValueError):
        eli = None
    if path:
        locs.append((str(path), sli, eli))
    return locs


def paths_from_dependabot(alert: dict) -> list[str]:
    mp = alert.get("manifest_path")
    if isinstance(mp, str) and mp:
        return [mp]
    dep = alert.get("dependency") or {}
    if isinstance(dep, dict):
        mp = dep.get("manifest_path")
        if isinstance(mp, str) and mp:
            return [mp]
    return []


def _one_location(loc: dict) -> tuple[str | None, int | None, int | None] | None:
    path = loc.get("path")
    if not path:
        return None
    sl = loc.get("start_line")
    el = loc.get("end_line")
    try:
        sli = int(sl) if sl is not None else None
    except (TypeError, ValueError):
        sli = None
    try:
        eli = int(el) if el is not None else None
    except (TypeError, ValueError):
        eli = None
    return (str(path), sli, eli)


def locations_from_secret_scanning(alert: dict) -> list[tuple[str | None, int | None, int | None]]:
    locs: list[tuple[str | None, int | None, int | None]] = []
    raw = alert.get("locations")
    if isinstance(raw, list):
        for loc in raw:
            if isinstance(loc, dict):
                o = _one_location(loc)
                if o:
                    locs.append(o)
    loc = alert.get("location") or {}
    if isinstance(loc, dict):
        o = _one_location(loc)
        if o and o not in locs:
            locs.append(o)
    return locs
