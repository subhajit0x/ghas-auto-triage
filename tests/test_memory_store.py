from __future__ import annotations

import json
from pathlib import Path

from ghas_llm.integrations.memory_store import TriageMemoryStore


def test_jsonl_append_and_load(tmp_path: Path) -> None:
    store = TriageMemoryStore(
        repo_root=tmp_path,
        history_rel=".triage_history.jsonl",
        feedback_rel=".human_feedback.jsonl",
    )
    row = {"ts": 1.0, "jira_key": "SEC-1", "routing": "leave_open", "package": "lodash"}
    store.append_history(row)
    loaded = store.load_history_rows(10)
    assert len(loaded) == 1
    assert loaded[0]["jira_key"] == "SEC-1"


def test_global_memory_reads_from_store(tmp_path: Path) -> None:
    store = TriageMemoryStore(
        repo_root=tmp_path,
        history_rel=".triage_history.jsonl",
        feedback_rel=".human_feedback.jsonl",
    )
    for row in [
        {"jira_key": "SEC-1", "repository": "example-org/a", "package": "lodash", "cve_id": "CVE-2", "routing": "false_positive"},
        {"jira_key": "SEC-2", "repository": "example-org/b", "package": "lodash", "cve_id": "CVE-2", "routing": "false_positive"},
        {"jira_key": "SEC-3", "repository": "example-org/c", "package": "lodash", "cve_id": "CVE-2", "routing": "false_positive"},
    ]:
        store.append_history(row)

    from ghas_llm.logic.global_memory import GlobalMemory

    snap = GlobalMemory(tmp_path, ".triage_history.jsonl", store=store).query(
        package="lodash",
        cve_id="CVE-2",
        current_repo="example-org/d",
    )
    assert snap.consensus_routing == "false_positive"


def test_trim_keeps_newest_lines(tmp_path: Path) -> None:
    store = TriageMemoryStore(
        repo_root=tmp_path,
        history_rel=".triage_history.jsonl",
        feedback_rel=".human_feedback.jsonl",
        max_history_lines=3,
        max_feedback_lines=3,
    )
    for i in range(5):
        store.append_history({"ts": float(i), "jira_key": f"SEC-{i}", "routing": "leave_open"})
    counts = store.trim_to_limits()
    assert counts["history_lines"] == 3
    rows = store.load_history_rows(10)
    assert [r["jira_key"] for r in rows] == ["SEC-2", "SEC-3", "SEC-4"]


def test_from_config_uses_yaml_limits(tmp_path: Path) -> None:
    cfg = {
        "agent": {},
        "memory_store": {"max_history_lines": 100, "max_feedback_lines": 50},
    }
    store = TriageMemoryStore.from_config(cfg, tmp_path)
    assert store.max_history_lines == 100
    assert store.max_feedback_lines == 50


def test_feedback_roundtrip(tmp_path: Path) -> None:
    store = TriageMemoryStore(
        repo_root=tmp_path,
        history_rel="h.jsonl",
        feedback_rel="f.jsonl",
    )
    store.append_feedback(
        {"ts": 2.0, "jira_key": "SEC-9", "human_verdict_guess": "false_positive", "human_text": "noise"},
    )
    rows = store.load_feedback_rows(5)
    assert len(rows) == 1
    assert rows[0]["human_verdict_guess"] == "false_positive"
