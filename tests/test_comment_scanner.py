from __future__ import annotations

from ghas_llm.agents.comment_scanner_agent import (
    CommentScannerAgent,
    build_bot_marker,
    is_bot_comment,
    strip_bot_marker,
)


def test_build_and_strip_bot_marker() -> None:
    body = f"{build_bot_marker('dependabot', 42)}\ndependabot #42 — org/repo\n\nConclusion: Needs human review."
    assert is_bot_comment(body, kind="dependabot", number=42)
    assert not is_bot_comment(body, kind="code_scanning", number=42)
    assert "ghas-triage-agent" not in strip_bot_marker(body)


def test_comment_scanner_no_bot_comment() -> None:
    state = CommentScannerAgent().classify(
        [{"body": "human note", "author": {"displayName": "Alice"}}],
        kind="dependabot",
        number=1,
    )
    assert state.state == "no_bot_comment"


def test_comment_scanner_bot_only() -> None:
    body = f"{build_bot_marker('dependabot', 1)}\ndependabot #1 — o/r\n\nConclusion: False positive for this repo — no usage."
    state = CommentScannerAgent().classify(
        [{"body": body, "author": {"displayName": "Bot"}}],
        kind="dependabot",
        number=1,
    )
    assert state.state == "bot_only"
    assert state.prior_bot_routing == "false_positive"


def test_comment_scanner_uses_stored_issue_property_without_marker() -> None:
    body = "GitHub already marks lodash as fixed, so I’m closing this Jira ticket."
    state = CommentScannerAgent().classify(
        [{"body": body, "author": {"displayName": "Bot"}, "created": "then"}],
        kind="dependabot",
        number=1,
        stored_state={
            "kind": "dependabot",
            "number": 1,
            "routing": "fixed",
            "comment_body": body,
            "comment_created": "then",
        },
    )
    assert state.state == "bot_only"
    assert state.prior_bot_routing == "fixed"
    assert state.prior_bot_comment == body


def test_comment_scanner_human_after_bot() -> None:
    bot = f"{build_bot_marker('dependabot', 1)}\ndependabot #1 — o/r\n\nConclusion: False positive for this repo — no usage."
    state = CommentScannerAgent().classify(
        [
            {"body": "Actually this is used in prod, please fix.", "author": {"displayName": "Alice"}, "created": "now"},
            {"body": bot, "author": {"displayName": "Bot"}, "created": "then"},
        ],
        kind="dependabot",
        number=1,
    )
    assert state.state == "human_after_bot"
    assert state.latest_human_author == "Alice"
    assert "used in prod" in state.latest_human_comment

