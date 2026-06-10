from __future__ import annotations

from ghas_llm.logic.syllogism import build_human_comment, strip_internal_metadata
from ghas_llm.logic.human_comment import (
    humanize,
    render_action_needed_comment,
    render_false_positive_comment,
    render_needs_review_comment,
)


def test_build_human_comment_strips_internal_labels() -> None:
    comment = build_human_comment(
        routing="in_progress",
        human_conclusion=(
            "Repository tier: tier_2_supporting\n"
            "Negative proofs: no negative proof recorded.\n"
            "Evidence (Major Premise): package is present.\n"
            "Impact (Minor Premise): reachable path exists.\n"
            "Conclusion: Upgrade GitPython to 3.1.47 in mage-ai."
        ),
    )
    assert comment.routing == "in_progress"
    assert "Repository tier" not in comment.body
    assert "Negative proofs" not in comment.body
    assert "Evidence" not in comment.body
    assert "Impact" not in comment.body
    assert "Conclusion:" not in comment.body
    assert "Upgrade GitPython" in comment.body


def test_strip_internal_metadata_removes_confidence_and_critic() -> None:
    text = "Critic note: no\nConfidence score: 25\nConclusion: False positive for this repo."
    assert strip_internal_metadata(text) == "False positive for this repo."


def test_one_line_human_comment_bans_internal_jargon() -> None:
    out = humanize("Repository tier: tier_2\nConfidence: high\nUpgrade lodash in app.ts", max_chars=120)
    assert "\n" not in out
    assert "Repository tier" not in out
    assert "Confidence" not in out


def test_action_needed_comment_is_specific() -> None:
    out = render_action_needed_comment("lodash", "4.17.21", "src/app.ts", "serverless")
    assert "lodash" in out
    assert "4.17.21" in out
    assert "src/app.ts" in out


def test_renderer_avoids_repetitive_safe_to_close() -> None:
    out = render_false_positive_comment(
        "lodash",
        "acme/app",
        reason="No reachable usage of the vulnerable surface was found in acme/app. This alert is safe to close as noise for this repo.",
    )
    assert out.count("safe to close") == 1
    assert "so this looks safe" not in out


def test_needs_review_comment_avoids_internal_source_jargon() -> None:
    out = render_needs_review_comment(
        "",
        "The alert is not supported by a reachable application path in the repository data provided. The only matched location is Cargo.lock, and no non-test source usage was identified.",
    )
    assert "non-test" not in out
    assert "repository data provided" not in out
    assert "Cargo.lock" in out

