from __future__ import annotations

from ghas_llm.agentic_triage import VulnSignature
from ghas_llm.agents.human_feedback_agent import (
    HumanFeedbackAgent,
    extract_reason,
    guess_human_verdict,
)


def test_guess_human_verdict() -> None:
    assert guess_human_verdict("safe to close as false positive") == "false_positive"
    assert guess_human_verdict("please upgrade and fix this") == "in_progress"
    assert guess_human_verdict("unclear, needs review") == "leave_open"
    assert guess_human_verdict("thanks") == "unknown"


def test_record_and_retrieve_relevant_examples(tmp_path) -> None:
    cfg = {"agent": {"human_feedback_file": "feedback.jsonl"}}
    sig = VulnSignature(package="lodash", ecosystem="npm", cve_id="CVE-1")
    agent = HumanFeedbackAgent(tmp_path, cfg)

    feedback = agent.record(
        jira_key="SEC-1",
        repository="example-org/app",
        kind="dependabot",
        number=7,
        signature=sig,
        human_text="This is a true positive, lodash template is used in prod.",
        human_author="Alice",
    )

    assert feedback.human_verdict_guess == "in_progress"
    examples = agent.relevant_examples(signature=sig, repository="example-org/app")
    assert "SEC-1" in examples
    assert "lodash" in examples


def test_extract_reason_from_human_feedback() -> None:
    reason = extract_reason("False positive because lodash template is not reachable from the API.")
    assert "not reachable" in reason

