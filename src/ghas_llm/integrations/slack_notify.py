from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def _resolve_webhook_url(slack_cfg: dict[str, Any]) -> str:
    use_test = bool(slack_cfg.get("use_test_channel")) or os.environ.get(
        "GHAS_LLM_SLACK_USE_TEST", ""
    ).strip() in ("1", "true", "yes")
    if use_test:
        env_name = str(slack_cfg.get("test_webhook_env", "SLACK_TEST_CHANNEL"))
    else:
        env_name = str(slack_cfg.get("webhook_env", "SLACK_CHANNEL"))
    return (os.environ.get(env_name) or "").strip()


def post_incoming_webhook(url: str, payload: dict[str, Any], timeout_s: float = 15.0) -> tuple[int, str]:
    if not url.startswith("http://") and not url.startswith("https://"):
        return 0, "invalid webhook URL (must start with http/https)"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read().decode("utf-8", errors="replace")[:500]
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return e.code, body
    except urllib.error.URLError as e:
        return 0, str(e.reason or e)


def _verdict_counts(results: list[dict[str, Any]]) -> tuple[int, int, int]:
    tp = fp = other = 0
    for r in results:
        if not isinstance(r, dict):
            continue
        if r.get("skipped") or r.get("error"):
            continue
        v = r.get("verdict")
        if not isinstance(v, dict):
            other += 1
            continue
        verdict = str(v.get("verdict", "")).lower()
        if verdict == "true_positive":
            tp += 1
        elif verdict == "false_positive":
            fp += 1
        else:
            other += 1
    return tp, fp, other


def _per_issue_lines(results: list[dict[str, Any]], max_lines: int = 40) -> list[str]:
    lines: list[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        jira_key = r.get("jira_key", "")
        kind = str(r.get("kind", ""))
        num = r.get("number", "")
        repo = r.get("repository", "")
        prefix = f"`{jira_key}`" if jira_key else f"`{kind} #{num}`"
        if repo:
            prefix += f" ({repo})"

        if r.get("skipped"):
            reason = r.get("skip_reason", "unknown")
            lines.append(f"  SKIP {prefix}: {reason}")
        elif r.get("error"):
            lines.append(f"  ERR  {prefix}: {r['error'][:200]}")
        else:
            v = r.get("verdict")
            if isinstance(v, dict):
                verdict = v.get("verdict", "?")
                conf = v.get("confidence", "?")
                sev = v.get("severity_assessment", "?")
                pri = v.get("priority", "?")
                lines.append(f"  {prefix}: {verdict} (conf={conf}, sev={sev}, pri={pri})")
            actions = r.get("actions") or {}
            if isinstance(actions, dict):
                jc = actions.get("jira_comment") or actions.get("jira_comment_error")
                if jc:
                    lines.append(f"    jira_comment: {jc}")

        if len(lines) >= max_lines:
            lines.append("  ... (truncated)")
            break
    return lines


def build_run_summary_message(
    *,
    repo: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
    run_url: str,
) -> str:
    dry = summary.get("dry_run", True)
    proc = int(summary.get("processed", 0) or 0)
    skip = int(summary.get("skipped", 0) or 0)
    err_n = int(summary.get("errors", 0) or 0)
    tp, fp, other = _verdict_counts(results)
    mode = summary.get("mode", "github_first")
    lines = [
        f"*GHAS-LLM* | `{repo}` | mode: {mode}",
        f"Processed: *{proc}* | Skipped: *{skip}* | Errors: *{err_n}*",
        f"Verdicts: TP={tp} FP={fp}" + (f" Other={other}" if other else ""),
    ]
    if dry:
        lines.insert(0, "[DRY RUN]")
    if run_url:
        lines.append(f"Run: {run_url}")

    detail = _per_issue_lines(results)
    if detail:
        lines.append("")
        lines.append("*Per-issue log:*")
        lines.extend(detail)

    if err_n > 0:
        err_details = [
            r.get("error", "") for r in results
            if isinstance(r, dict) and r.get("error")
        ]
        if err_details:
            lines.append("")
            lines.append("*Errors:*")
            for e in err_details[:10]:
                lines.append(f"  {str(e)[:300]}")

    return "\n".join(lines)


def maybe_notify_slack(
    *,
    integrations_cfg: dict[str, Any],
    repo: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    slack_cfg = integrations_cfg.get("slack") or {}
    out: dict[str, Any] = {"slack_notified": False}
    if os.environ.get("GHAS_LLM_SLACK_DISABLE", "").strip().lower() in ("1", "true", "yes"):
        out["slack_note"] = "skipped (GHAS_LLM_SLACK_DISABLE)"
        return out
    if not slack_cfg.get("enabled"):
        return out

    dry = bool(summary.get("dry_run", True))
    if dry and not bool(slack_cfg.get("notify_in_dry_run")):
        return out

    url = _resolve_webhook_url(slack_cfg)
    if not url.startswith("http"):
        out["slack_error"] = "missing or invalid webhook URL (SLACK_CHANNEL / SLACK_TEST_CHANNEL)"
        return out

    run_url = os.environ.get("GHAS_LLM_RUN_URL", "").strip()
    if not run_url:
        server = os.environ.get("GITHUB_SERVER_URL", "").strip().rstrip("/")
        ghr = os.environ.get("GITHUB_REPOSITORY", "").strip()
        rid = os.environ.get("GITHUB_RUN_ID", "").strip()
        if server and ghr and rid:
            run_url = f"{server}/{ghr}/actions/runs/{rid}"

    text = build_run_summary_message(repo=repo, summary=summary, results=results, run_url=run_url)

    code, body = post_incoming_webhook(url, {"text": text})
    if 200 <= code < 300:
        out["slack_notified"] = True
        out["slack_http_status"] = code
    else:
        out["slack_error"] = f"HTTP {code}: {body}"
    return out
