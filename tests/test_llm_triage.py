from __future__ import annotations

from unittest.mock import MagicMock, patch

from ghas_llm.llm_triage import (
    _normalize_brief_comment,
    _parse_json_object,
    brief_conclusion_with_openai,
    summarize_alert_for_llm,
    triage_with_openai,
    _enrich_dependabot_summary,
    _enrich_code_scanning_summary,
    _enrich_secret_scanning_summary,
)


def test_normalize_brief_comment_adds_conclusion() -> None:
    out = _normalize_brief_comment("Short note only.")
    assert "conclusion:" in out.lower()


def test_normalize_brief_comment_strips_fences() -> None:
    out = _normalize_brief_comment("```json\nHello.\nConclusion: Done.\n```")
    assert "```" not in out
    assert "Conclusion:" in out


@patch("ghas_llm.llm_triage.build_openai_client")
def test_brief_conclusion_with_openai(mock_build: MagicMock) -> None:
    mock_client = MagicMock()
    mock_build.return_value = mock_client
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="Alert affects lodash.\nConclusion: Upgrade lodash."))]
    )
    cfg = {
        "global": {"llm": {"model": "gpt-5.4-mini", "api_key_env": "OPENAI_API_KEY", "max_retries": 1}},
        "agent": {"review_passes": 2},
    }
    import os

    os.environ["OPENAI_API_KEY"] = "sk-test"
    try:
        text = brief_conclusion_with_openai(cfg, alert_kind="dependabot", alert_summary="{}", file_context="ctx")
    finally:
        del os.environ["OPENAI_API_KEY"]
    assert "Conclusion:" in text
    assert mock_client.chat.completions.create.call_count == 2


def test_parse_json_plain() -> None:
    d = _parse_json_object(
        '{"verdict":"false_positive","confidence":"high","reasoning":"r",'
        '"code_usage":"u","exploitability":"e","suggested_action":"s"}'
    )
    assert d["verdict"] == "false_positive"


def test_parse_json_embedded() -> None:
    d = _parse_json_object(
        'Analysis:\n{"verdict":"true_positive","confidence":"low","reasoning":"r",'
        '"code_usage":"u","exploitability":"e","suggested_action":"s"}\n'
    )
    assert d["verdict"] == "true_positive"


def test_parse_json_nested_braces_in_string() -> None:
    text = '{"verdict":"true_positive","confidence":"high","reasoning":"use {curl}","code_usage":"u","exploitability":"e","suggested_action":"s"}'
    d = _parse_json_object(text)
    assert "curl" in d["reasoning"]


@patch("ghas_llm.llm_triage.build_openai_client")
def test_triage_with_openai_success(mock_build: MagicMock) -> None:
    mock_client = MagicMock()
    mock_build.return_value = mock_client
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(
                    content=(
                        '{"verdict":"false_positive","confidence":"high","reasoning":"test",'
                        '"code_usage":"none","exploitability":"low","suggested_action":"none",'
                        '"severity_assessment":"low","priority":"no_action"}'
                    )
                )
            )
        ]
    )
    cfg = {"global": {"llm": {"model": "gpt-5.4-mini", "api_key_env": "OPENAI_API_KEY"}}}
    import os
    os.environ["OPENAI_API_KEY"] = "sk-test"
    try:
        tv = triage_with_openai(cfg, alert_kind="dependabot", alert_summary="{}", file_context="ctx")
    finally:
        del os.environ["OPENAI_API_KEY"]
    assert tv.verdict == "false_positive"
    assert tv.confidence == "high"
    assert tv.severity_assessment == "low"
    assert tv.priority == "no_action"


@patch("ghas_llm.llm_triage.build_openai_client")
def test_triage_returns_needs_review_on_failure(mock_build: MagicMock) -> None:
    mock_build.side_effect = RuntimeError("network down")
    cfg = {"global": {"llm": {"api_key_env": "OPENAI_API_KEY", "max_retries": 1}}}
    import os
    os.environ["OPENAI_API_KEY"] = "sk-test"
    try:
        tv = triage_with_openai(cfg, alert_kind="dependabot", alert_summary="{}", file_context="")
    finally:
        del os.environ["OPENAI_API_KEY"]
    assert tv.verdict == "needs_review"
    assert tv.confidence == "low"
    assert "network" in tv.reasoning


@patch("ghas_llm.llm_triage.build_openai_client")
def test_triage_needs_review_verdict(mock_build: MagicMock) -> None:
    mock_client = MagicMock()
    mock_build.return_value = mock_client
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(
                    content='{"verdict":"needs_review","confidence":"low","reasoning":"insufficient context",'
                            '"code_usage":"not found","exploitability":"unknown","suggested_action":"review manually",'
                            '"severity_assessment":"unknown","priority":"next_sprint"}'
                )
            )
        ]
    )
    cfg = {"global": {"llm": {"api_key_env": "OPENAI_API_KEY"}}}
    import os
    os.environ["OPENAI_API_KEY"] = "sk-test"
    try:
        tv = triage_with_openai(cfg, alert_kind="code_scanning", alert_summary="{}", file_context="")
    finally:
        del os.environ["OPENAI_API_KEY"]
    assert tv.verdict == "needs_review"


def test_enrich_dependabot_summary() -> None:
    alert = {
        "dependency": {"package": {"ecosystem": "pip", "name": "urllib3"}, "scope": "runtime"},
        "security_vulnerability": {"severity": "high", "vulnerable_version_range": "< 2.0.0",
                                   "first_patched_version": {"identifier": "2.0.0"}},
        "security_advisory": {"summary": "SSRF in urllib3", "cve_id": "CVE-2023-1234",
                              "cwes": [{"cwe_id": "CWE-918"}], "description": "SSRF vuln"},
        "manifest_path": "requirements.txt",
    }
    text = _enrich_dependabot_summary(alert)
    assert "pip/urllib3" in text
    assert "CVE-2023-1234" in text
    assert "CWE-918" in text
    assert "2.0.0" in text
    assert "runtime" not in text or "Scope" in text


def test_enrich_code_scanning_summary() -> None:
    alert = {
        "rule": {"id": "py/sql-injection", "description": "SQL injection", "severity": "error",
                 "security_severity_level": "critical", "tags": ["security", "injection"]},
        "tool": {"name": "CodeQL", "version": "2.15.0"},
        "most_recent_instance": {"location": {"path": "app.py", "start_line": 42, "end_line": 45},
                                 "message": {"text": "Untrusted data in query"}},
    }
    text = _enrich_code_scanning_summary(alert)
    assert "py/sql-injection" in text
    assert "critical" in text
    assert "app.py" in text
    assert "CodeQL" in text


def test_enrich_secret_scanning_summary() -> None:
    alert = {
        "secret_type_display_name": "AWS Access Key",
        "secret_type": "aws_access_key_id",
        "push_protection_bypassed": True,
        "validity": "active",
        "state": "open",
        "locations": [{"type": "commit", "details": {"path": ".env", "start_line": 3}}],
    }
    text = _enrich_secret_scanning_summary(alert)
    assert "AWS Access Key" in text
    assert "BYPASSED" in text
    assert ".env" in text


def test_summarize_dependabot_includes_enrichment() -> None:
    alert = {
        "dependency": {"package": {"ecosystem": "npm", "name": "lodash"}},
        "security_vulnerability": {"severity": "high"},
        "security_advisory": {"summary": "Prototype pollution"},
    }
    text = summarize_alert_for_llm("dependabot", alert)
    assert "npm/lodash" in text
    assert "Prototype pollution" in text
    assert "Raw alert JSON" in text


def test_summarize_secret_scanning_redacts() -> None:
    alert = {"secret": "AKIA1234567890", "secret_type": "aws_access_key_id"}
    text = summarize_alert_for_llm("secret_scanning", alert)
    assert "AKIA1234567890" not in text
    assert "REDACTED" in text
