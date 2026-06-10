from ghas_llm.models import TriageVerdict


def test_triage_verdict_from_llm_json_defaults() -> None:
    tv = TriageVerdict.from_llm_json({
        "verdict": "false_positive",
        "confidence": "medium",
        "reasoning": "r",
        "code_usage": "u",
        "exploitability": "e",
        "suggested_action": "a",
        "severity_assessment": "low",
        "priority": "backlog",
    })
    assert tv.verdict == "false_positive"
    assert tv.confidence == "medium"
    assert tv.severity_assessment == "low"
    assert tv.priority == "backlog"


def test_triage_verdict_invalid_enums() -> None:
    tv = TriageVerdict.from_llm_json({"verdict": "maybe", "confidence": "unknown"})
    assert tv.verdict == "true_positive"
    assert tv.confidence == "low"
    assert tv.severity_assessment == "unknown"
    assert tv.priority == "next_sprint"


def test_triage_verdict_needs_review() -> None:
    tv = TriageVerdict.from_llm_json({
        "verdict": "needs_review",
        "confidence": "low",
        "reasoning": "not enough context",
        "severity_assessment": "unknown",
        "priority": "immediate",
    })
    assert tv.verdict == "needs_review"
    assert tv.priority == "immediate"


def test_triage_verdict_severity_levels() -> None:
    for sev in ("critical", "high", "medium", "low", "info"):
        tv = TriageVerdict.from_llm_json({"severity_assessment": sev})
        assert tv.severity_assessment == sev


def test_triage_verdict_priority_levels() -> None:
    for pr in ("immediate", "next_sprint", "backlog", "no_action"):
        tv = TriageVerdict.from_llm_json({"priority": pr})
        assert tv.priority == pr
