from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")

from ghas_llm.agent import run_triage_cycle
from ghas_llm.config import default_config_path, load_config
from ghas_llm.github_api import GitHubClient
from ghas_llm.llm_triage import summarize_alert_for_llm, triage_with_openai, verify_llm_connectivity


def _detect_repo() -> str:
    r = os.environ.get("GITHUB_REPOSITORY")
    if r:
        return r
    try:
        out = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    if "github.com" in out:
        part = out.split("github.com", 1)[-1].strip("/").removesuffix(".git")
        return part.replace(":", "/")
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="GHAS-LLM: triage GHAS alerts, comment on Jira (read-only GitHub access).",
    )
    parser.add_argument("--config", type=Path, default=None,
                        help=f"Path to ghas_llm.yaml (default: {default_config_path()})")
    parser.add_argument("--repo", default=None,
                        help="Repository owner/name (default: GITHUB_REPOSITORY or git remote)")
    parser.add_argument("--repo-root", type=Path, default=None,
                        help="Root of checked-out repository")
    parser.add_argument("--max-alerts", type=int, default=None, metavar="N",
                        help="Override global.max_alerts_per_kind for this run")
    parser.add_argument("--llm-smoke", action="store_true",
                        help="Verify OPENAI_API_KEY with one tiny completion (no GitHub).")
    parser.add_argument("--fixture", type=Path, default=None, metavar="PATH",
                        help="Run LLM triage on a JSON file (mock alert, no GitHub APIs).")
    parser.add_argument("--kind",
                        choices=("dependabot", "code_scanning", "secret_scanning"),
                        default="dependabot",
                        help="Alert kind for --fixture (default: dependabot)")
    parser.add_argument("--fixture-context", default="",
                        help="Optional repo context text for --fixture")
    parser.add_argument("--scan-exposure", default=None, metavar="ORG",
                        help="Scan an org for public repos and exposed secrets.")
    parser.add_argument("--scan-org", default=None, metavar="ORG",
                        help="Triage GHAS alerts across all repos in an org (reads alerts only; respects dry_run).")
    parser.add_argument("--triage-jira", action="store_true",
                        help="Legacy: triage open Jira issues from text only (see jira.triage_existing_issues).")
    parser.add_argument("--jira-first", action="store_true",
                        help="Jira-first GHAS: poll Jira for GHAS tool issues, fetch alert from GitHub (read-only), triage, comment on Jira.")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.max_alerts is not None and args.max_alerts > 0:
        config["_max_alerts_override"] = args.max_alerts

    if args.llm_smoke:
        try:
            out = verify_llm_connectivity(config)
        except Exception as e:  # noqa: BLE001
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(out, indent=2, default=str))
        return 0

    if args.scan_exposure:
        from ghas_llm.exposure_scanner import scan_org_exposure
        token_env = config.get("global", {}).get("github", {}).get("token_env", "GITHUB_TOKEN")
        token = os.environ.get(token_env, "")
        if not token:
            print(f"error: set {token_env} for exposure scan", file=sys.stderr)
            return 2
        client = GitHubClient(token)
        result = scan_org_exposure(client, args.scan_exposure)
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.jira_first:
        from ghas_llm.jira_ghas_cycle import run_jira_first_ghas_cycle
        if args.repo_root is not None:
            repo_root = args.repo_root.resolve()
        elif os.environ.get("GITHUB_WORKSPACE"):
            repo_root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
        else:
            repo_root = Path.cwd().resolve()
        try:
            result = run_jira_first_ghas_cycle(config, repo_root)
        except (RuntimeError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.triage_jira:
        from ghas_llm.jira_triage import triage_jira_issues
        result = triage_jira_issues(config)
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.scan_org:
        token_env = config.get("global", {}).get("github", {}).get("token_env", "GITHUB_TOKEN")
        token = os.environ.get(token_env, "")
        if not token:
            print(f"error: set {token_env}", file=sys.stderr)
            return 2
        client = GitHubClient(token)
        repos = client.list_org_repos_with_security(args.scan_org)
        all_results: list[dict[str, Any]] = []
        for repo_info in repos:
            full = repo_info.get("full_name", "")
            if not full:
                continue
            print(f"--- Triaging {full} ---", file=sys.stderr)
            repo_root = Path.cwd().resolve()
            try:
                result = run_triage_cycle(config, full, repo_root)
                all_results.append({"repo": full, **result})
            except Exception as e:  # noqa: BLE001
                all_results.append({"repo": full, "error": str(e)})
        print(json.dumps(all_results, indent=2, default=str))
        return 0

    if args.fixture is not None:
        if not args.fixture.is_file():
            print(f"error: fixture not found: {args.fixture}", file=sys.stderr)
            return 2
        try:
            raw = json.loads(args.fixture.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: invalid fixture JSON: {e}", file=sys.stderr)
            return 2
        alert = raw if isinstance(raw, dict) else {"value": raw}
        summary = summarize_alert_for_llm(args.kind, alert)
        ctx = args.fixture_context or "(fixture mode: no repository files loaded)"
        try:
            tv = triage_with_openai(
                config,
                alert_kind=args.kind,
                alert_summary=summary,
                file_context=ctx,
            )
        except Exception as e:  # noqa: BLE001
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(asdict(tv), indent=2, default=str))
        return 0

    repo = args.repo or _detect_repo()
    if not repo:
        print("error: could not determine repository; set --repo or GITHUB_REPOSITORY", file=sys.stderr)
        return 2

    if args.repo_root is not None:
        repo_root = args.repo_root.resolve()
    elif os.environ.get("GITHUB_WORKSPACE"):
        repo_root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    else:
        repo_root = Path.cwd().resolve()

    try:
        result = run_triage_cycle(config, repo, repo_root)
    except (RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
