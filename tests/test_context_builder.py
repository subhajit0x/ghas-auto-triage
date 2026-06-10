from __future__ import annotations

import tempfile
from pathlib import Path

from ghas_llm.context_builder import (
    build_context,
    dependabot_usage_hints,
    locations_from_code_scanning,
    locations_from_secret_scanning,
    paths_from_dependabot,
)


def test_build_context_reads_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "requirements.txt").write_text("flask==2.0\nurllib3==1.26.5\n")
        ctx, _err = build_context(root, paths=["requirements.txt"], locations=[], max_chars=5000)
    assert "flask" in ctx
    assert "urllib3" in ctx


def test_build_context_truncates() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "big.txt").write_text("x\n" * 10000)
        ctx, _err = build_context(root, paths=["big.txt"], locations=[], max_chars=200)
    assert len(ctx) <= 300


def test_build_context_blocks_path_traversal() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        ctx, _err = build_context(root, paths=[], locations=[("../../etc/passwd", 1, 5)], max_chars=5000)
    assert "Skipped" in ctx or ctx.strip() == ""


def test_locations_from_code_scanning() -> None:
    alert = {
        "most_recent_instance": {
            "location": {"path": "src/app.py", "start_line": 10, "end_line": 15}
        }
    }
    locs = locations_from_code_scanning(alert)
    assert len(locs) == 1
    assert locs[0] == ("src/app.py", 10, 15)


def test_locations_from_code_scanning_empty() -> None:
    assert locations_from_code_scanning({}) == []


def test_dependabot_usage_hints_finds_import(tmp_path: Path) -> None:
    root = tmp_path
    (root / "app.py").write_text("import requests\n", encoding="utf-8")
    alert = {"dependency": {"package": {"name": "requests", "ecosystem": "pip"}}}
    text = dependabot_usage_hints(root, alert, max_chars=2000)
    assert "app.py" in text
    assert "import requests" in text


def test_paths_from_dependabot() -> None:
    assert paths_from_dependabot({"manifest_path": "package.json"}) == ["package.json"]
    assert paths_from_dependabot({"dependency": {"manifest_path": "sub/requirements.txt"}}) == [
        "sub/requirements.txt",
    ]
    assert paths_from_dependabot({}) == []


def test_locations_from_secret_scanning() -> None:
    alert = {
        "locations": [
            {"path": ".env", "start_line": 3, "end_line": 3},
            {"path": "config.yaml", "start_line": 1, "end_line": 1},
        ]
    }
    locs = locations_from_secret_scanning(alert)
    assert len(locs) == 2
