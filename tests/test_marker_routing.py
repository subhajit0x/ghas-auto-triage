from __future__ import annotations

from ghas_llm.agents.comment_scanner_agent import build_bot_marker, routing_from_marker
from ghas_llm.logic.consistency_gate import routing_from_comment


def test_v4_marker_carries_routing() -> None:
    marker = build_bot_marker("dependabot", 287, "in_progress")
    assert "v=4" in marker
    assert "routing=in_progress" in marker
    assert routing_from_marker(marker) == "in_progress"
    assert routing_from_comment(marker + "\nUpgrade the package.") == "in_progress"


def test_v3_marker_still_falls_back_to_text() -> None:
    body = "<!-- ghas-triage-agent v=3 kind=dependabot number=287 -->\nFalse positive for this repo."
    assert routing_from_marker(body) == ""
    assert routing_from_comment(body) == "false_positive"

