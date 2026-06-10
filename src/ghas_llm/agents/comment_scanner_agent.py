"""Jira comment-state worker for production triage routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ghas_llm.logic.consistency_gate import extract_conclusion, routing_from_comment

BOT_MARKER_PREFIX = "<!-- ghas-triage-agent"
BOT_MARKER_RE = re.compile(
    r"<!--\s*ghas-triage-agent\s+v=(?P<version>\d+)\s+kind=(?P<kind>[a-z_]+)\s+number=(?P<number>\d+)(?:\s+routing=(?P<routing>[a-z_]+))?\s*-->",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CommentState:
    state: str
    prior_bot_comment: str = ""
    prior_bot_routing: str = ""
    latest_human_comment: str = ""
    latest_human_author: str = ""
    latest_human_ts: str = ""
    human_comments_after_bot: list[dict[str, str]] | None = None


def build_bot_marker(kind: str, number: int, routing: str = "") -> str:
    route = f" routing={routing}" if routing else ""
    return f"<!-- ghas-triage-agent v=4 kind={kind} number={number}{route} -->"


def routing_from_marker(body: str) -> str:
    marker = BOT_MARKER_RE.search(body or "")
    if not marker:
        return ""
    return (marker.group("routing") or "").strip().lower()


def is_bot_comment(body: str, *, kind: str = "", number: int | None = None) -> bool:
    text = body or ""
    marker = BOT_MARKER_RE.search(text)
    if marker:
        if kind and marker.group("kind").lower() != kind.lower():
            return False
        if number is not None and int(marker.group("number")) != int(number):
            return False
        return True
    legacy_needle = f"{kind} #{number}" if kind and number is not None else ""
    return bool(legacy_needle and legacy_needle in text and "Conclusion:" in text)


def strip_bot_marker(body: str) -> str:
    return BOT_MARKER_RE.sub("", body or "").strip()


class CommentScannerAgent:
    name = "comment_scanner_agent"

    def classify(
        self,
        comments: list[dict[str, Any]],
        *,
        kind: str,
        number: int,
        stored_state: dict[str, Any] | None = None,
    ) -> CommentState:
        """Classify current Jira comment state.

        Jira integration requests newest-first comments. If an older Jira API
        response returns ascending order, this still works because we compare
        relative positions around the latest bot marker.
        """
        latest_bot_idx: int | None = None
        latest_bot_body = str((stored_state or {}).get("comment_body") or "")
        stored_routing = str((stored_state or {}).get("routing") or "")
        stored_created = str((stored_state or {}).get("comment_created") or "")
        latest_human_after_bot: dict[str, Any] | None = None

        for idx, comment in enumerate(comments):
            body = str(comment.get("body") or "")
            if is_bot_comment(body, kind=kind, number=number):
                latest_bot_idx = idx
                latest_bot_body = body
                break

        if latest_bot_idx is None:
            for idx, comment in enumerate(comments):
                body = str(comment.get("body") or "")
                if latest_bot_body and body.strip() == latest_bot_body.strip():
                    latest_bot_idx = idx
                    break
            if latest_bot_idx is None and stored_created:
                for idx, comment in enumerate(comments):
                    if str(comment.get("created") or "") == stored_created:
                        latest_bot_idx = idx
                        break
            if latest_bot_idx is None and stored_state:
                return CommentState(
                    state="bot_only",
                    prior_bot_comment=latest_bot_body,
                    prior_bot_routing=stored_routing,
                    human_comments_after_bot=[],
                )
            if latest_bot_idx is None:
                return CommentState(state="no_bot_comment", human_comments_after_bot=[])

        newer_comments = comments[:latest_bot_idx]
        human_comments: list[dict[str, str]] = []
        for comment in newer_comments:
            body = str(comment.get("body") or "")
            if not is_bot_comment(body, kind=kind, number=number) and body.strip():
                author = comment.get("author") or {}
                human_comments.append(
                    {
                        "body": body,
                        "author": str(author.get("displayName") or author.get("name") or ""),
                        "created": str(comment.get("created") or ""),
                    },
                )
                latest_human_after_bot = comment

        if latest_human_after_bot:
            author = latest_human_after_bot.get("author") or {}
            return CommentState(
                state="human_after_bot",
                prior_bot_comment=strip_bot_marker(latest_bot_body),
                prior_bot_routing=stored_routing or routing_from_comment(latest_bot_body),
                latest_human_comment=str(latest_human_after_bot.get("body") or ""),
                latest_human_author=str(author.get("displayName") or author.get("name") or ""),
                latest_human_ts=str(latest_human_after_bot.get("created") or ""),
                human_comments_after_bot=human_comments,
            )

        return CommentState(
            state="bot_only",
            prior_bot_comment=strip_bot_marker(latest_bot_body),
            prior_bot_routing=stored_routing or routing_from_comment(latest_bot_body),
            human_comments_after_bot=[],
        )


def comment_conclusion(body: str) -> str:
    return extract_conclusion(strip_bot_marker(body))

