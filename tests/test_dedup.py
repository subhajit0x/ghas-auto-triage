from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ghas_llm.dedup import key_for, load_processed, save_processed


def test_key_for() -> None:
    assert key_for("dependabot", 42) == "dependabot:42"
    assert key_for("code_scanning", 1) == "code_scanning:1"


def test_save_and_load_processed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "state.json"
        keys = {"dependabot:1", "code_scanning:5"}
        save_processed(p, keys)
        assert p.is_file()
        loaded = load_processed(p)
        assert loaded == keys


def test_load_processed_missing_file() -> None:
    p = Path("/tmp/nonexistent_dedup_test.json")
    if p.exists():
        p.unlink()
    assert load_processed(p) == set()


def test_load_processed_dict_format() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "state.json"
        p.write_text(json.dumps({"keys": ["a:1", "b:2"]}))
        loaded = load_processed(p)
        assert loaded == {"a:1", "b:2"}
