from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "persist_memory_git.sh"


def _init_git_repo(tmp_path: Path, branch: str) -> None:
    init = subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, text=True)
    if init.returncode != 0:
        pytest.skip(f"git init unavailable: {init.stderr.strip()}")
    checkout = subprocess.run(
        ["git", "checkout", "-b", branch],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    if checkout.returncode != 0:
        pytest.skip(f"git checkout unavailable: {checkout.stderr.strip()}")


def _run_script(cwd: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env or {})
    merged["GHAS_LLM_MEMORY_GIT_DRY_RUN"] = "true"
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=cwd,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


def test_persist_script_commits_memory_files(tmp_path: Path) -> None:
    _init_git_repo(tmp_path, "main")
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    history = tmp_path / ".triage_history.jsonl"
    feedback = tmp_path / ".human_feedback.jsonl"
    history.write_text(json.dumps({"jira_key": "SEC-1", "routing": "leave_open"}) + "\n")
    feedback.write_text("")

    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True, capture_output=True)

    history.write_text(
        history.read_text()
        + json.dumps({"jira_key": "SEC-2", "routing": "false_positive"}) + "\n",
    )

    proc = _run_script(
        tmp_path,
        ".triage_history.jsonl",
        ".human_feedback.jsonl",
        "test-run",
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout

    log = subprocess.run(
        ["git", "log", "-1", "--pretty=%s"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "update triage memory (run test-run)" in log.stdout


def test_persist_script_noop_when_unchanged(tmp_path: Path) -> None:
    _init_git_repo(tmp_path, "main")
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)

    history = tmp_path / ".triage_history.jsonl"
    feedback = tmp_path / ".human_feedback.jsonl"
    history.write_text("")
    feedback.write_text("")

    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)

    proc = _run_script(
        tmp_path,
        ".triage_history.jsonl",
        ".human_feedback.jsonl",
        "local",
    )
    assert proc.returncode == 0
    assert "No memory file changes" in proc.stdout
