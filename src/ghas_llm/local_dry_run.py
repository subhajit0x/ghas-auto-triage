"""Run agentic triage locally against live Jira/GitHub data — never posts.

Two modes:

  # By Jira ticket key (pulls alert ref from the ticket):
  python -m ghas_llm.local_dry_run --issue SEC-6236

  # By repo + kind + alert number (skips Jira entirely):
  python -m ghas_llm.local_dry_run --repo example-org/analytics-mage-infra \
      --kind dependabot --number 91

  # Bulk: process N oldest open Jira tickets matching the JQL:
  python -m ghas_llm.local_dry_run --limit 5

Required env (or AWS SSO login):
  GHAS_TRIAGE_GITHUB_TOKEN / GHAS_LLM_GITHUB_TOKEN   GitHub PAT (org ghas-triage-github-token first)
  OPENAI_API_KEY          OpenAI key for gpt-5.4-mini
  AWS_PROFILE             (only needed when --issue/--limit; reads your-org/jira/ghas-triage)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ghas_llm.agentic_triage import agentic_triage
from ghas_llm.config import load_config
from ghas_llm.github_api import GitHubAPIError, GitHubClient
from ghas_llm.jira_ghas_cycle import (
    _field_value,
    _flatten_description,
    _parse_alert_number,
    _parse_asset,
    fetch_github_alert,
    search_jira_github_tool_issues,
    tool_string_to_kind,
)

log = logging.getLogger("ghas_llm.local_dry_run")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _resolve_github_token(config: dict[str, Any]) -> str:
    for env_name in (
        "GHAS_TRIAGE_GITHUB_TOKEN",
        "GHAS_LLM_GITHUB_TOKEN",
        "GH_TOKEN",
    ):
        v = os.environ.get(env_name, "").strip()
        if v:
            return v
    raise SystemExit(
        "Missing GitHub token. Export GHAS_TRIAGE_GITHUB_TOKEN (org PAT ghas-triage-github-token) or GHAS_LLM_GITHUB_TOKEN with a PAT that has "
        "read access to the example-org org (security-events:read, contents:read).",
    )


def _default_branch(client: GitHubClient, owner: str, repo: str) -> str:
    try:
        meta = client.get_repo(owner, repo)
        if isinstance(meta, dict):
            return str(meta.get("default_branch", "main") or "main")
    except GitHubAPIError:
        pass
    return "main"


def _fetch_jira_issue(jira_cfg: dict[str, Any], key: str) -> dict[str, Any]:
    import urllib.parse
    import urllib.request

    from ghas_llm.jira_triage import _get_jira_auth

    base, auth = _get_jira_auth(jira_cfg)
    url = f"{base}/rest/api/3/issue/{urllib.parse.quote(key)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": auth})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _alert_ref_from_issue(
    issue: dict[str, Any], jira_cfg: dict[str, Any],
) -> tuple[str, int, tuple[str, str]] | None:
    fields = issue.get("fields") or {}
    if not isinstance(fields, dict):
        return None
    tool_field = jira_cfg.get("tool_custom_field", "customfield_10206")
    asset_field = jira_cfg.get("asset_custom_field", "customfield_10204")
    id_field = (jira_cfg.get("github_alert_id_custom_field") or "").strip()
    prefix = str(jira_cfg.get("github_tool_prefix", ""))

    tool_s = _field_value(fields.get(tool_field))
    asset_s = _field_value(fields.get(asset_field))
    desc_plain = _flatten_description(fields.get("description"))

    kind = tool_string_to_kind(tool_s, prefix)
    parsed = _parse_asset(asset_s)
    alert_num = _parse_alert_number(fields, desc_plain, id_field)
    if not kind or not parsed or alert_num is None:
        return None
    return kind, alert_num, parsed


# --------------------------------------------------------------------------- #
# Pretty printer                                                              #
# --------------------------------------------------------------------------- #


def _print_verdict(label: str, verdict: Any) -> None:
    print(f"\n{'=' * 78}")
    print(f"{label}")
    print("=" * 78)
    p = verdict.profile
    s = verdict.signature
    m = verdict.matrix
    print(
        f"Repo:          {p.full_name}  visibility={p.visibility}  fork={p.is_fork}  "
        f"archived={p.archived}  internal={p.is_internal}",
    )
    print(f"Activity:      {p.activity_label}")
    print(
        f"Advisory:      {s.cve_id or '(no CVE)'}  severity={s.severity or '?'}  "
        f"{s.ecosystem}/{s.package}  fixed_in={s.fixed_version or '?'}",
    )
    print(f"Vulnerable APIs: {', '.join(s.vulnerable_apis) or '(none extracted)'}")
    print(
        f"Matrix:        reproducible={m.reproducible}  direct={m.direct_code_hits}  "
        f"test_only={m.test_only_hits}  manifest={m.package_in_manifest}  "
        f"confidence={m.confidence_label} ({m.confidence_score})  active={m.repo_active}",
    )
    if verdict.matches:
        print("Matches:")
        for cm in verdict.matches[:6]:
            print(f"  - {cm.path}")
    if verdict.blame:
        print("Blame (last commit):")
        for b in verdict.blame:
            print(
                f"  - {b.path}: {b.last_commit_sha} by @{b.last_author_login or '?'} "
                f"<{b.last_author_email or 'n/a'}> on {b.last_commit_date or '?'}",
            )
    if verdict.org_repos_affected:
        print(f"Org-wide repos with this package: {verdict.org_repos_affected}")
    print(
        f"Routing:       {verdict.routing}    Impact: {verdict.impact}    "
        f"Risk: {verdict.risk_score}/10    Priority: {verdict.priority}    "
        f"Blast: {verdict.blast_radius}",
    )
    if verdict.exploitation_path:
        print(f"Exploitation:  {verdict.exploitation_path}")
    if verdict.evidence_for:
        print("Evidence for:")
        for e in verdict.evidence_for:
            print(f"  + {e}")
    if verdict.evidence_against:
        print("Evidence against:")
        for e in verdict.evidence_against:
            print(f"  - {e}")
    print(f"\n--- Jira comment that WOULD be posted ---\n{verdict.jira_comment}")


# --------------------------------------------------------------------------- #
# Modes                                                                       #
# --------------------------------------------------------------------------- #


def _run_one(
    config: dict[str, Any],
    client: GitHubClient,
    *,
    owner: str,
    repo: str,
    kind: str,
    number: int,
    org: str,
) -> dict[str, Any]:
    branch = _default_branch(client, owner, repo)
    try:
        alert = fetch_github_alert(client, owner, repo, kind, number)
    except GitHubAPIError as e:
        return {"error": f"fetch_alert: {e}", "owner": owner, "repo": repo, "kind": kind, "number": number}
    if not alert:
        return {"error": "empty_alert", "owner": owner, "repo": repo, "kind": kind, "number": number}

    verdict = agentic_triage(
        config=config,
        client=client,
        owner=owner,
        repo=repo,
        branch=branch,
        org=org,
        alert_kind=kind,
        alert=alert,
    )
    _print_verdict(f"{owner}/{repo} {kind} #{number}", verdict)
    return {
        "owner": owner, "repo": repo, "kind": kind, "number": number,
        "routing": verdict.routing, "impact": verdict.impact,
        "confidence": verdict.confidence, "reproducible": verdict.reproducible,
        "risk_score": verdict.risk_score, "priority": verdict.priority,
        "blast_radius": verdict.blast_radius,
        "exploitation_path": verdict.exploitation_path,
        "evidence_for": verdict.evidence_for,
        "evidence_against": verdict.evidence_against,
        "jira_comment": verdict.jira_comment,
        "matches": [m.path for m in verdict.matches[:8]],
        "matrix": asdict(verdict.matrix) if verdict.matrix else None,
    }


def _baseline_key(row: dict[str, Any]) -> str:
    if row.get("jira_key"):
        return str(row["jira_key"])
    return f"{row.get('owner')}/{row.get('repo')}:{row.get('kind')}:{row.get('number')}"


def _load_baseline(path: str) -> dict[str, str]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"Baseline file not found: {path}")
    raw = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            if not isinstance(item, dict):
                continue
            verdict = item.get("human_verdict") or item.get("verdict") or item.get("routing")
            if verdict:
                out[_baseline_key(item)] = str(verdict)
        return out
    return {}


def _attach_baseline(results: list[dict[str, Any]], baseline: dict[str, str]) -> dict[str, Any]:
    if not baseline:
        return {"baseline_total": 0, "baseline_matched": 0, "accuracy": None}
    matched = 0
    compared = 0
    for row in results:
        key = _baseline_key(row)
        expected = baseline.get(key)
        if not expected:
            continue
        compared += 1
        row["human_baseline"] = expected
        row["matches_human_baseline"] = str(row.get("routing", "")).lower() == expected.lower()
        if row["matches_human_baseline"]:
            matched += 1
    accuracy = round(matched / compared, 3) if compared else None
    return {"baseline_total": compared, "baseline_matched": matched, "accuracy": accuracy}


def _run_by_issue(
    config: dict[str, Any], client: GitHubClient, key: str, org: str,
) -> dict[str, Any]:
    jira_cfg = (config.get("integrations") or {}).get("jira") or {}
    issue = _fetch_jira_issue(jira_cfg, key)
    ref = _alert_ref_from_issue(issue, jira_cfg)
    if not ref:
        return {"jira_key": key, "error": "could not resolve alert ref from Jira issue"}
    kind, number, (owner, repo) = ref
    out = _run_one(config, client, owner=owner, repo=repo, kind=kind, number=number, org=org)
    out["jira_key"] = key
    return out


def _run_bulk(
    config: dict[str, Any], client: GitHubClient, limit: int, org: str,
) -> list[dict[str, Any]]:
    jira_cfg = (config.get("integrations") or {}).get("jira") or {}
    issues = search_jira_github_tool_issues(jira_cfg)[:limit]
    results: list[dict[str, Any]] = []
    for issue in issues:
        key = str(issue.get("key", ""))
        ref = _alert_ref_from_issue(issue, jira_cfg)
        if not ref:
            print(f"\n[skip] {key}: could not resolve alert ref")
            results.append({"jira_key": key, "skipped": "no_alert_ref"})
            continue
        kind, number, (owner, repo) = ref
        out = _run_one(config, client, owner=owner, repo=repo, kind=kind, number=number, org=org)
        out["jira_key"] = key
        results.append(out)
    return results


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ghas_llm.local_dry_run", description=__doc__)
    ap.add_argument("--config", default="ghas_llm.yaml")
    ap.add_argument("--issue", help="Jira issue key, e.g. SEC-6236")
    ap.add_argument("--repo", help="owner/name (skips Jira)")
    ap.add_argument("--kind", choices=["dependabot", "code_scanning", "secret_scanning"])
    ap.add_argument("--number", type=int)
    ap.add_argument("--limit", type=int, default=0,
                    help="Bulk: process N oldest open Jira tickets")
    ap.add_argument("--out", default=".local_dry_run.json")
    ap.add_argument("--baseline", help="JSON human baseline for bot-vs-human comparison")
    ap.add_argument("--aws-profile", help="Sets AWS_PROFILE for AWS Secrets Manager")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.aws_profile:
        os.environ["AWS_PROFILE"] = args.aws_profile

    config = load_config(Path(args.config))
    org = str(config.get("global", {}).get("github", {}).get("org", "example-org"))
    token = _resolve_github_token(config)
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        raise SystemExit("Missing OPENAI_API_KEY in environment.")

    api_ver = config.get("global", {}).get("github", {}).get("api_version", "2022-11-28")
    client = GitHubClient(token, api_version=api_ver)

    if args.repo and args.kind and args.number:
        owner, _, repo = args.repo.partition("/")
        if not owner or not repo:
            raise SystemExit("--repo must be owner/name")
        result = _run_one(config, client, owner=owner, repo=repo, kind=args.kind, number=args.number, org=org)
        results = [result]
    elif args.issue:
        result = _run_by_issue(config, client, args.issue, org)
        results = [result]
    elif args.limit:
        results = _run_bulk(config, client, args.limit, org)
    else:
        ap.error("provide either --issue KEY, --repo+--kind+--number, or --limit N")
        return 2

    baseline_summary = _attach_baseline(results, _load_baseline(args.baseline or ""))
    output: Any = (
        {"summary": baseline_summary, "results": results}
        if args.baseline
        else results
    )
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(output, indent=2, default=str))
    print(f"\nWrote {len(results)} result(s) to {args.out}")
    if baseline_summary["baseline_total"]:
        print(
            "Baseline comparison: "
            f"{baseline_summary['baseline_matched']}/{baseline_summary['baseline_total']} "
            f"matched (accuracy={baseline_summary['accuracy']})",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
