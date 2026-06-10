from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ghas_llm.context_builder import (
    build_context,
    locations_from_code_scanning,
    locations_from_secret_scanning,
    paths_from_dependabot,
)
from ghas_llm.dedup import key_for, load_processed, save_processed
from ghas_llm.github_api import GitHubAPIError, GitHubClient
from ghas_llm.auto_resolve import auto_resolve_alert, should_auto_resolve
from ghas_llm.integrations.github_alert_comments import post_triage_comment_on_github_alert
from ghas_llm.integrations.slack_notify import maybe_notify_slack
from ghas_llm.integrations.status_updates import apply_jira_updates
from ghas_llm.llm_triage import summarize_alert_for_llm, triage_with_openai
from ghas_llm.models import AlertResult


def _get_github_token(config: dict[str, Any]) -> str:
    env_name = config.get("global", {}).get("github", {}).get("token_env", "GITHUB_TOKEN")
    token = os.environ.get(env_name, "")
    if not token:
        raise RuntimeError(f"Missing GitHub token in environment: {env_name}")
    return token


def _mapping_path(config: dict[str, Any]) -> Path | None:
    integ = config.get("integrations") or {}
    jira = integ.get("jira") or {}
    raw = jira.get("mapping_file")
    if not raw:
        return None
    p = Path(str(raw))
    if not p.is_absolute():
        root = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
        p = Path(root) / p
    return p.resolve()


def _dedup_path(config: dict[str, Any]) -> Path | None:
    d = config.get("dedup") or {}
    if not d.get("enabled"):
        return None
    raw = d.get("state_file", ".processed_alerts.json")
    p = Path(str(raw))
    if not p.is_absolute():
        root = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
        p = Path(root) / p
    return p.resolve()


def run_triage_cycle(
    config: dict[str, Any],
    repo: str,
    repo_root: Path,
) -> dict[str, Any]:
    owner, _, name = repo.partition("/")
    if not owner or not name:
        raise ValueError(f"Invalid repository: {repo!r} (expected owner/name)")

    dry = bool(config.get("global", {}).get("dry_run", True))
    max_n = int(config.get("global", {}).get("max_alerts_per_kind", 25))
    if isinstance(config.get("_max_alerts_override"), int) and config["_max_alerts_override"] > 0:
        max_n = int(config["_max_alerts_override"])
    api_ver = str(config.get("global", {}).get("github", {}).get("api_version", "2022-11-28"))

    agent_cfg = config.get("agent", {})
    min_conf = str(
        agent_cfg.get("min_confidence_for_status_change")
        or agent_cfg.get("min_confidence_for_dismiss", "high")
    )
    require_ctx = bool(agent_cfg.get("require_code_validation", True))
    max_ctx = int(agent_cfg.get("max_context_chars", 24000))
    auto_resolve_cfg = agent_cfg

    alerts_cfg = config.get("alerts", {})
    kinds: dict[str, bool] = {
        "dependabot": bool(alerts_cfg.get("dependabot", True)),
        "code_scanning": bool(alerts_cfg.get("code_scanning", True)),
        "secret_scanning": bool(alerts_cfg.get("secret_scanning", True)),
    }

    integrations_cfg = config.get("integrations") or {}
    mapping_file = _mapping_path(config)

    dedup_cfg = config.get("dedup") or {}
    dedup_enabled = bool(dedup_cfg.get("enabled"))
    skip_if_processed = bool(dedup_cfg.get("skip_triage_if_processed"))
    dedup_file = _dedup_path(config)
    processed: set[str] = load_processed(dedup_file) if dedup_file and skip_if_processed else set()
    newly_processed: set[str] = set()

    token = _get_github_token(config)
    client = GitHubClient(token, api_version=api_ver)

    results: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "repository": repo,
        "dry_run": dry,
        "processed": 0,
        "skipped": 0,
        "errors": 0,
        "auto_resolved": 0,
    }

    def process_one(kind: str, num: int, alert: dict[str, Any], ctx_fn) -> None:
        k = key_for(kind, num)
        if dedup_file and skip_if_processed and k in processed:
            results.append(
                asdict(
                    AlertResult(
                        kind,  # type: ignore[arg-type]
                        num,
                        True,
                        "dedup: skip_triage_if_processed",
                        None,
                        dry,
                    )
                )
            )
            summary["skipped"] += 1
            return

        try:
            ctx = ctx_fn()
            if require_ctx and not (ctx or "").strip():
                ctx = "(minimal context)"

            summary_json = summarize_alert_for_llm(kind, alert)
            tv = triage_with_openai(
                config,
                alert_kind=kind,
                alert_summary=summary_json,
                file_context=ctx,
            )

            gh_cfg = integrations_cfg.get("github") or {}
            marker = str(gh_cfg.get("comment_marker", "<!-- ghas-llm -->"))
            post_gh = bool(gh_cfg.get("post_triage_comments", True))

            gh_actions: dict[str, Any] = {}
            if post_gh:
                gh_actions = post_triage_comment_on_github_alert(
                    client,
                    owner,
                    name,
                    kind,
                    num,
                    tv,
                    marker=marker,
                    dry_run=dry,
                )

            resolve_actions: dict[str, Any] = {}
            if should_auto_resolve(tv, auto_resolve_cfg):
                resolve_actions = auto_resolve_alert(
                    client, owner, name, kind, num, tv, dry_run=dry,
                )
                if resolve_actions.get("auto_resolve") in ("dismissed", "resolved"):
                    summary["auto_resolved"] += 1

            status_actions = apply_jira_updates(
                config=config,
                integrations_cfg=integrations_cfg,
                dry_run=dry,
                owner=owner,
                repo_name=name,
                kind=kind,
                number=num,
                tv=tv,
                min_confidence=min_conf,
                mapping_path=mapping_file,
            )

            actions = {**gh_actions, **resolve_actions, **status_actions}

            results.append(
                asdict(AlertResult(kind, num, False, None, tv, dry, actions))  # type: ignore[arg-type]
            )
            summary["processed"] += 1
            newly_processed.add(k)
        except Exception as e:  # noqa: BLE001
            results.append(
                asdict(
                    AlertResult(
                        kind,  # type: ignore[arg-type]
                        num,
                        False,
                        None,
                        None,
                        dry,
                        error=str(e),
                    )
                )
            )
            summary["errors"] += 1

    def handle_dependabot() -> None:
        if not kinds["dependabot"]:
            return
        try:
            alerts = client.list_dependabot_alerts(owner, name)[:max_n]
        except GitHubAPIError as e:
            results.append({"kind": "dependabot", "error": str(e), "body": e.body[:500]})
            summary["errors"] += 1
            return
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            num = int(alert.get("number", 0))

            def ctx_fn(a=alert):
                paths = paths_from_dependabot(a)
                ctx, _err = build_context(repo_root, paths=paths, locations=[], max_chars=max_ctx)
                return ctx

            process_one("dependabot", num, alert, ctx_fn)

    def handle_code_scanning() -> None:
        if not kinds["code_scanning"]:
            return
        try:
            alerts = client.list_code_scanning_alerts(owner, name)[:max_n]
        except GitHubAPIError as e:
            results.append({"kind": "code_scanning", "error": str(e), "body": e.body[:500]})
            summary["errors"] += 1
            return
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            num = int(alert.get("number", 0))

            def ctx_fn(a=alert):
                locs = locations_from_code_scanning(a)
                ctx, _err = build_context(repo_root, paths=[], locations=locs, max_chars=max_ctx)
                return ctx

            process_one("code_scanning", num, alert, ctx_fn)

    def handle_secret_scanning() -> None:
        if not kinds["secret_scanning"]:
            return
        try:
            alerts = client.list_secret_scanning_alerts(owner, name)[:max_n]
        except GitHubAPIError as e:
            results.append({"kind": "secret_scanning", "error": str(e), "body": e.body[:500]})
            summary["errors"] += 1
            return
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            num = int(alert.get("number", 0))

            def ctx_fn(a=alert):
                locs = locations_from_secret_scanning(a)
                ctx, _err = build_context(repo_root, paths=[], locations=locs, max_chars=max_ctx)
                return ctx

            process_one("secret_scanning", num, alert, ctx_fn)

    handle_dependabot()
    handle_code_scanning()
    handle_secret_scanning()

    if dedup_enabled and dedup_file and newly_processed and not dry:
        all_keys = processed | newly_processed
        save_processed(dedup_file, all_keys)
        summary["dedup_saved"] = len(all_keys)

    slack_meta = maybe_notify_slack(
        integrations_cfg=integrations_cfg,
        repo=repo,
        summary=summary,
        results=results,
    )
    for k, v in slack_meta.items():
        if k.startswith("slack"):
            summary[k] = v

    return {"summary": summary, "results": results}
