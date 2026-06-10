from __future__ import annotations

import json

from ghas_llm.logic.global_memory import GlobalMemory, format_global_memory


def _write_history(tmp_path, rows: list[dict]) -> str:
    rel = "history.jsonl"
    path = tmp_path / rel
    path.write_text("\n".join(json.dumps(r) for r in rows))
    return rel


def test_global_memory_consensus_false_positive(tmp_path) -> None:
    rel = _write_history(
        tmp_path,
        [
            {"jira_key": "SEC-1", "repository": "example-org/a", "package": "rustls-webpki", "cve_id": "CVE-1", "routing": "false_positive", "tier": "tier_3_internal"},
            {"jira_key": "SEC-2", "repository": "example-org/b", "package": "rustls-webpki", "cve_id": "CVE-1", "routing": "false_positive", "tier": "tier_2_supporting"},
            {"jira_key": "SEC-3", "repository": "example-org/c", "package": "rustls-webpki", "cve_id": "CVE-1", "routing": "false_positive", "tier": "tier_3_internal"},
            {"jira_key": "SEC-4", "repository": "example-org/d", "package": "rustls-webpki", "cve_id": "CVE-1", "routing": "leave_open", "tier": "tier_3_internal"},
        ],
    )
    snap = GlobalMemory(tmp_path, rel).query(
        package="rustls-webpki",
        cve_id="CVE-1",
        current_repo="example-org/e",
    )
    assert snap.consensus_routing == "false_positive"
    assert snap.consensus_strength == 4
    assert "example-org/a" in snap.repos_seen


def test_global_memory_no_consensus_with_split_decisions(tmp_path) -> None:
    rel = _write_history(
        tmp_path,
        [
            {"jira_key": "SEC-1", "repository": "example-org/a", "package": "lodash", "cve_id": "CVE-2", "routing": "false_positive"},
            {"jira_key": "SEC-2", "repository": "example-org/b", "package": "lodash", "cve_id": "CVE-2", "routing": "in_progress"},
            {"jira_key": "SEC-3", "repository": "example-org/c", "package": "lodash", "cve_id": "CVE-2", "routing": "leave_open"},
        ],
    )
    snap = GlobalMemory(tmp_path, rel).query(package="lodash", cve_id="CVE-2")
    assert snap.consensus_routing == ""
    assert snap.consensus_strength == 3


def test_format_global_memory_empty_path() -> None:
    snap = GlobalMemory(None, "").query(package="x", cve_id="CVE-X")  # type: ignore[arg-type]
    text = format_global_memory(snap)
    assert "no prior org-wide history" in text
