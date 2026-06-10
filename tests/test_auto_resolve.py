from __future__ import annotations

from unittest.mock import MagicMock

from ghas_llm.auto_resolve import auto_resolve_alert, should_auto_resolve
from ghas_llm.models import TriageVerdict


def _make_verdict(verdict: str = "false_positive", confidence: str = "high") -> TriageVerdict:
    return TriageVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning="test",
        code_usage="test",
        exploitability="test",
        suggested_action="test",
        severity_assessment="medium",
        priority="backlog",
    )


def test_should_auto_resolve_enabled_fp_high():
    cfg = {"auto_resolve_enabled": True, "auto_resolve_min_confidence": "high"}
    tv = _make_verdict("false_positive", "high")
    assert should_auto_resolve(tv, cfg) is True


def test_should_auto_resolve_disabled():
    cfg = {"auto_resolve_enabled": False, "auto_resolve_min_confidence": "high"}
    tv = _make_verdict("false_positive", "high")
    assert should_auto_resolve(tv, cfg) is False


def test_should_auto_resolve_not_fp():
    cfg = {"auto_resolve_enabled": True, "auto_resolve_min_confidence": "high"}
    tv = _make_verdict("true_positive", "high")
    assert should_auto_resolve(tv, cfg) is False


def test_should_auto_resolve_low_confidence():
    cfg = {"auto_resolve_enabled": True, "auto_resolve_min_confidence": "high"}
    tv = _make_verdict("false_positive", "medium")
    assert should_auto_resolve(tv, cfg) is False


def test_should_auto_resolve_medium_gate():
    cfg = {"auto_resolve_enabled": True, "auto_resolve_min_confidence": "medium"}
    tv = _make_verdict("false_positive", "medium")
    assert should_auto_resolve(tv, cfg) is True


def test_auto_resolve_dependabot_dry_run():
    client = MagicMock()
    tv = _make_verdict()
    result = auto_resolve_alert(client, "o", "r", "dependabot", 1, tv, dry_run=True)
    assert result["auto_resolve"] == "skipped_dry_run"
    assert result["would_dismiss"] is True
    client.dismiss_dependabot_alert.assert_not_called()


def test_auto_resolve_dependabot_live():
    client = MagicMock()
    client.dismiss_dependabot_alert.return_value = {}
    tv = _make_verdict()
    result = auto_resolve_alert(client, "o", "r", "dependabot", 1, tv, dry_run=False)
    assert result["auto_resolve"] == "dismissed"
    client.dismiss_dependabot_alert.assert_called_once()
    args = client.dismiss_dependabot_alert.call_args
    assert args[0][0] == "o"
    assert args[0][1] == "r"
    assert args[0][2] == 1


def test_auto_resolve_code_scanning_live():
    client = MagicMock()
    client.dismiss_code_scanning_alert.return_value = {}
    tv = _make_verdict()
    result = auto_resolve_alert(client, "o", "r", "code_scanning", 5, tv, dry_run=False)
    assert result["auto_resolve"] == "dismissed"
    client.dismiss_code_scanning_alert.assert_called_once()


def test_auto_resolve_secret_scanning_live():
    client = MagicMock()
    client.resolve_secret_scanning_alert.return_value = {}
    tv = _make_verdict()
    result = auto_resolve_alert(client, "o", "r", "secret_scanning", 7, tv, dry_run=False)
    assert result["auto_resolve"] == "resolved"
    assert result["resolution"] == "false_positive"
    client.resolve_secret_scanning_alert.assert_called_once()


def test_auto_resolve_api_error():
    from ghas_llm.github_api import GitHubAPIError
    client = MagicMock()
    client.dismiss_dependabot_alert.side_effect = GitHubAPIError(403, "forbidden", "no access")
    tv = _make_verdict()
    result = auto_resolve_alert(client, "o", "r", "dependabot", 1, tv, dry_run=False)
    assert result["auto_resolve"] == "error"
    assert result["status"] == 403


def test_auto_resolve_unknown_kind():
    client = MagicMock()
    tv = _make_verdict()
    result = auto_resolve_alert(client, "o", "r", "unknown_kind", 1, tv, dry_run=False)
    assert result["auto_resolve"] == "unknown_kind"
