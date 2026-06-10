from __future__ import annotations

import os
from unittest.mock import patch

from ghas_llm.integrations.slack_notify import (
    build_run_summary_message,
    maybe_notify_slack,
    post_incoming_webhook,
)


def test_build_run_summary_message() -> None:
    text = build_run_summary_message(
        repo="acme/app",
        summary={"dry_run": False, "processed": 2, "skipped": 0, "errors": 0},
        results=[
            {
                "kind": "dependabot",
                "number": 1,
                "jira_key": "SEC-10",
                "repository": "acme/app",
                "verdict": {"verdict": "true_positive", "confidence": "high",
                            "severity_assessment": "high", "priority": "immediate"},
                "actions": {"jira_comment": "posted"},
            },
            {
                "kind": "code_scanning",
                "number": 3,
                "jira_key": "SEC-11",
                "repository": "acme/app",
                "verdict": {"verdict": "false_positive", "confidence": "high",
                            "severity_assessment": "low", "priority": "no_action"},
                "actions": {"jira_comment": "posted"},
            },
        ],
        run_url="https://github.com/acme/app/actions/runs/99",
    )
    assert "acme/app" in text
    assert "TP=1" in text
    assert "FP=1" in text
    assert "SEC-10" in text
    assert "SEC-11" in text
    assert "true_positive" in text
    assert "false_positive" in text


def test_build_run_summary_message_with_errors() -> None:
    text = build_run_summary_message(
        repo="org/repo",
        summary={"dry_run": True, "processed": 0, "skipped": 1, "errors": 1},
        results=[
            {"jira_key": "SEC-1", "skipped": True, "skip_reason": "tool_not_ghas", "tool": "terraform"},
            {"jira_key": "SEC-2", "kind": "dependabot", "number": 5, "error": "GitHub API 404: not found"},
        ],
        run_url="",
    )
    assert "DRY RUN" in text
    assert "SKIP" in text
    assert "tool_not_ghas" in text
    assert "ERR" in text
    assert "404" in text


def test_build_run_summary_message_per_issue_log() -> None:
    text = build_run_summary_message(
        repo="jira:VM",
        summary={"dry_run": False, "processed": 1, "skipped": 0, "errors": 0, "mode": "jira_first"},
        results=[
            {
                "kind": "dependabot",
                "number": 99,
                "jira_key": "SEC-55",
                "repository": "acme/app",
                "verdict": {"verdict": "true_positive", "confidence": "high",
                            "severity_assessment": "high", "priority": "immediate"},
                "actions": {"jira_comment": "posted"},
            },
        ],
        run_url="",
    )
    assert "jira_first" in text
    assert "Per-issue log" in text
    assert "SEC-55" in text
    assert "jira_comment: posted" in text


def test_maybe_notify_slack_skips_when_env_disable() -> None:
    os.environ["GHAS_LLM_SLACK_DISABLE"] = "true"
    try:
        out = maybe_notify_slack(
            integrations_cfg={"slack": {"enabled": True, "webhook_env": "SLACK_CHANNEL"}},
            repo="o/r",
            summary={"dry_run": False, "processed": 0, "skipped": 0, "errors": 0},
            results=[],
        )
    finally:
        del os.environ["GHAS_LLM_SLACK_DISABLE"]
    assert out.get("slack_note") == "skipped (GHAS_LLM_SLACK_DISABLE)"
    assert out.get("slack_notified") is False


@patch("ghas_llm.integrations.slack_notify.post_incoming_webhook")
def test_maybe_notify_slack_posts_when_enabled(mock_post: object) -> None:
    mock_post.return_value = (200, "ok")
    import os

    os.environ["SLACK_CHANNEL"] = "https://hooks.slack.com/services/fake"
    try:
        out = maybe_notify_slack(
            integrations_cfg={
                "slack": {
                    "enabled": True,
                    "webhook_env": "SLACK_CHANNEL",
                }
            },
            repo="o/r",
            summary={"dry_run": False, "processed": 0, "skipped": 0, "errors": 0},
            results=[],
        )
    finally:
        del os.environ["SLACK_CHANNEL"]
    assert out.get("slack_notified") is True


def test_post_incoming_webhook_invalid_url() -> None:
    code, body = post_incoming_webhook("not-a-url", {"text": "x"})
    assert code == 0
    assert "invalid" in body.lower()
