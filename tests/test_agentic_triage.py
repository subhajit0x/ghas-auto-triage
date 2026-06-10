from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from ghas_llm.agentic_triage import (
    AgenticVerdict,
    BlameInfo,
    CodeMatch,
    EvidenceMatrix,
    ExtraContext,
    RepoProfile,
    VulnSignature,
    _decision_to_routing,
    agentic_triage,
    compute_evidence_matrix,
    extract_vuln_signature,
    final_verdict,
    gather_extra_context,
    gather_repo_profile,
    is_test_path,
    load_previous_run_hint,
    sanitize_stakeholder_comment,
)


# --------------------------------------------------------------------------- #
# is_test_path                                                                #
# --------------------------------------------------------------------------- #


def test_is_test_path_recognises_common_locations() -> None:
    assert is_test_path("src/foo/__tests__/bar.py")
    assert is_test_path("tests/test_x.py")
    assert is_test_path("examples/usage.py")
    assert is_test_path("spec/widget_spec.rb")
    assert not is_test_path("src/handlers/payments.py")
    assert not is_test_path("internal/server/main.go")


# --------------------------------------------------------------------------- #
# RepoProfile activity & matrix activity treatment                            #
# --------------------------------------------------------------------------- #


def test_repo_profile_activity_known_recent() -> None:
    p = RepoProfile(
        full_name="example-org/x",
        days_since_last_push=12,
        push_date_known=True,
    )
    assert "actively maintained" in p.activity_label
    assert "12" in p.activity_label


def test_repo_profile_activity_unknown_does_not_say_999() -> None:
    p = RepoProfile(full_name="example-org/x")
    label = p.activity_label
    assert "unknown" in label
    assert "999" not in label


def test_repo_profile_activity_archived_label() -> None:
    p = RepoProfile(
        full_name="example-org/x",
        archived=True,
        push_date_known=True,
        days_since_last_push=10,
    )
    assert p.activity_label == "archived"


def test_matrix_unknown_push_date_treated_as_active() -> None:
    profile = RepoProfile(full_name="example-org/x", is_internal=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    m = compute_evidence_matrix(profile, [CodeMatch(path="src/x.py")], [], 0, sig)
    assert m.repo_active, "unknown activity must not be penalised as inactive"


def test_matrix_recent_push_active() -> None:
    profile = RepoProfile(
        full_name="example-org/x",
        is_internal=True,
        push_date_known=True,
        days_since_last_push=14,
    )
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    m = compute_evidence_matrix(profile, [CodeMatch(path="src/x.py")], [], 0, sig)
    assert m.repo_active


def test_matrix_old_push_not_active() -> None:
    profile = RepoProfile(
        full_name="example-org/x",
        is_internal=True,
        push_date_known=True,
        days_since_last_push=400,
    )
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    m = compute_evidence_matrix(profile, [CodeMatch(path="src/x.py")], [], 0, sig)
    assert not m.repo_active


# --------------------------------------------------------------------------- #
# Matrix scoring                                                              #
# --------------------------------------------------------------------------- #


def test_sanitize_stakeholder_comment_strips_internal_jargon() -> None:
    raw = "Do this now P0 risk 7/10 customer_facing blast radius high\nConclusion: ok."
    out = sanitize_stakeholder_comment(raw)
    assert "P0" not in out
    assert "7/10" not in out
    assert "customer_facing" not in out.lower()
    assert "Conclusion:" in out


def test_load_previous_run_hint_reads_last_key_match(tmp_path) -> None:
    hist = tmp_path / "h.jsonl"
    hist.write_text(
        '{"jira_key": "SEC-1", "routing": "leave_open", "jira_comment_status": "posted", "ts": 1}\n'
        '{"jira_key": "SEC-2", "routing": "in_progress", "jira_comment_status": "posted", "ts": 2}\n'
        '{"jira_key": "SEC-1", "routing": "false_positive", "jira_comment_status": "posted", "ts": 3}\n',
        encoding="utf-8",
    )
    h = load_previous_run_hint(tmp_path, "h.jsonl", "SEC-1")
    assert "false_positive" in h
    assert "SEC-1" not in h or "routing" in h


def test_matrix_cross_validated_when_manifest_and_hits() -> None:
    profile = RepoProfile(
        full_name="example-org/x", is_internal=True, push_date_known=True, days_since_last_push=1,
    )
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matches = [CodeMatch(path="src/x.py")]
    extras = ExtraContext(
        manifest_path="requirements.txt", package_pinned_in_manifest=True, manifest_excerpt="x==1",
    )
    m = compute_evidence_matrix(profile, matches, [], 0, sig, extras)
    assert m.cross_validated
    assert m.lockfile_pinned is False


def test_matrix_reproducible_high_confidence() -> None:
    profile = RepoProfile(
        full_name="example-org/payments",
        visibility="private",
        is_internal=True,
        push_date_known=True,
        days_since_last_push=3,
    )
    sig = VulnSignature(
        package="lodash", ecosystem="npm",
        vulnerable_apis=["template"], severity="high",
    )
    matches = [
        CodeMatch(path="src/handlers/order.ts"),
        CodeMatch(path="src/handlers/billing.ts"),
        CodeMatch(path="src/utils/templater.ts"),
    ]
    blame = [BlameInfo(path="src/handlers/order.ts", last_author_login="alice")]
    extras = ExtraContext(manifest_path="package.json", package_pinned_in_manifest=True)
    m = compute_evidence_matrix(profile, matches, blame, org_repos=4, sig=sig, extras=extras)
    assert m.reproducible
    assert m.direct_code_hits == 3
    assert m.confidence_label in ("high", "medium")
    assert m.org_wide_hit_repos == 4
    assert m.package_in_manifest


def test_matrix_no_apis_extracted_low() -> None:
    profile = RepoProfile(
        full_name="example-org/foo", visibility="private",
        is_internal=True, push_date_known=True, days_since_last_push=10,
    )
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=[])
    m = compute_evidence_matrix(profile, [], [], 0, sig)
    assert not m.reproducible
    assert m.confidence_label == "low"


def test_matrix_archived_penalised() -> None:
    profile = RepoProfile(
        full_name="example-org/legacy", visibility="private",
        is_internal=True, archived=True,
        push_date_known=True, days_since_last_push=900,
    )
    sig = VulnSignature(
        package="x", ecosystem="pip", vulnerable_apis=["foo"], severity="high",
    )
    matches = [CodeMatch(path="legacy/foo.py")]
    m = compute_evidence_matrix(profile, matches, [], 0, sig)
    assert m.repo_archived
    assert not m.repo_active
    assert m.confidence_label == "low"


def test_matrix_test_only_hits_does_not_make_reproducible() -> None:
    profile = RepoProfile(
        full_name="example-org/foo", visibility="private",
        is_internal=True, push_date_known=True, days_since_last_push=2,
    )
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matches = [CodeMatch(path="tests/test_foo.py"), CodeMatch(path="examples/sample.py")]
    m = compute_evidence_matrix(profile, matches, [], 0, sig)
    assert m.test_only_hits == 2
    assert m.direct_code_hits == 0
    assert not m.reproducible


# --------------------------------------------------------------------------- #
# gather_repo_profile: known vs unknown push date                             #
# --------------------------------------------------------------------------- #


def test_gather_repo_profile_known_push_date() -> None:
    from datetime import datetime, timedelta, timezone

    recent_push = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT12:00:00Z")
    client = MagicMock()
    client.get_repo.return_value = {
        "full_name": "example-org/app",
        "private": True,
        "fork": False,
        "archived": False,
        "default_branch": "main",
        "language": "Python",
        "stargazers_count": 0,
        "topics": [],
        "pushed_at": recent_push,
    }
    client.get.return_value = [{"login": "a"}, {"login": "b"}]
    p = gather_repo_profile(client, "example-org", "app", "example-org")
    assert p.push_date_known
    assert p.days_since_last_push <= 20
    assert "999" not in p.activity_label
    assert p.is_internal


def test_gather_repo_profile_missing_push_date_does_not_default_to_999() -> None:
    client = MagicMock()
    client.get_repo.return_value = {
        "full_name": "example-org/app",
        "private": True,
        "fork": False,
        "archived": False,
    }
    client.get.return_value = []
    p = gather_repo_profile(client, "example-org", "app", "example-org")
    assert not p.push_date_known
    assert p.days_since_last_push == 0
    assert "unknown" in p.activity_label
    assert "999" not in p.activity_label


def test_gather_repo_profile_falls_back_to_updated_at() -> None:
    client = MagicMock()
    client.get_repo.return_value = {
        "full_name": "example-org/app",
        "private": True,
        "updated_at": "2026-04-20T12:00:00Z",
    }
    client.get.return_value = []
    p = gather_repo_profile(client, "example-org", "app", "example-org")
    assert p.push_date_known


def test_gather_repo_profile_handles_failed_fetch() -> None:
    from ghas_llm.github_api import GitHubAPIError
    client = MagicMock()
    client.get_repo.side_effect = GitHubAPIError(404, "not found", "")
    p = gather_repo_profile(client, "external", "thing", "example-org")
    assert p.profile_fetch_failed
    assert not p.is_internal
    assert "unknown" in p.activity_label


# --------------------------------------------------------------------------- #
# extract_vuln_signature                                                      #
# --------------------------------------------------------------------------- #


def test_extract_vuln_signature_parses_json() -> None:
    config = {"global": {"llm": {"extract_model": "gpt-5.4-mini"}}}
    fake_resp = MagicMock()
    fake_resp.choices = [MagicMock()]
    fake_resp.choices[0].message.content = json.dumps({
        "vulnerable_apis": ["TemplateEngine.render", "evaluate"],
        "trigger_summary": "Prototype pollution via user-controlled template",
        "non_default_required": False,
    })
    fake_oai = MagicMock()
    fake_oai.chat.completions.create.return_value = fake_resp
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        sig = extract_vuln_signature(
            config,
            {
                "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
                "security_vulnerability": {
                    "severity": "high",
                    "vulnerable_version_range": "<4.17.21",
                    "first_patched_version": {"identifier": "4.17.21"},
                },
                "security_advisory": {
                    "cve_id": "CVE-2020-8203",
                    "summary": "Prototype pollution",
                    "description": "x" * 200,
                },
            },
        )
    assert sig.package == "lodash"
    assert sig.ecosystem == "npm"
    assert sig.severity == "high"
    assert sig.fixed_version == "4.17.21"
    assert "TemplateEngine.render" in sig.vulnerable_apis


def test_extract_vuln_signature_recovers_when_response_format_unsupported() -> None:
    config = {"global": {"llm": {"extract_model": "gpt-5.4-mini"}}}
    fake_resp = MagicMock()
    fake_resp.choices = [MagicMock()]
    fake_resp.choices[0].message.content = json.dumps({
        "vulnerable_apis": [], "trigger_summary": "", "non_default_required": False,
    })
    fake_oai = MagicMock()
    fake_oai.chat.completions.create.side_effect = [
        TypeError("response_format unsupported"), fake_resp,
    ]
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        sig = extract_vuln_signature(
            config,
            {"dependency": {"package": {"name": "x", "ecosystem": "pip"}}},
        )
    assert fake_oai.chat.completions.create.call_count == 2
    assert sig.vulnerable_apis == []


# --------------------------------------------------------------------------- #
# gather_extra_context                                                        #
# --------------------------------------------------------------------------- #


def test_gather_extra_context_fetches_readme_and_manifest() -> None:
    sig = VulnSignature(package="lodash", ecosystem="npm")
    side_effect = {
        ("README.md",): "# My App\n\nDoes a thing.",
        ("package.json",): '{"dependencies": {"lodash": "4.17.20"}}',
    }

    def _fake_get(client, owner, repo, path, ref):
        return side_effect.get((path,), "")

    client = MagicMock()
    with patch("ghas_llm.agentic_triage.get_file_via_api", side_effect=_fake_get):
        ctx = gather_extra_context(client, "example-org", "app", "main", sig)
    assert "My App" in ctx.readme_excerpt
    assert ctx.manifest_path == "package.json"
    assert ctx.package_pinned_in_manifest
    assert "lodash" in ctx.manifest_excerpt.lower()


def test_gather_extra_context_no_manifest_for_unknown_ecosystem() -> None:
    sig = VulnSignature(package="x", ecosystem="weird")
    client = MagicMock()
    with patch("ghas_llm.agentic_triage.get_file_via_api", return_value=""):
        ctx = gather_extra_context(client, "example-org", "app", "main", sig)
    assert ctx.manifest_path == ""
    assert not ctx.package_pinned_in_manifest


def test_gather_extra_context_fetches_dockerfile_and_ci() -> None:
    sig = VulnSignature(package="pillow", ecosystem="pip")
    files = {
        "README.md": "An image-resizing service",
        "requirements.txt": "Pillow==9.0.0\nrequests==2.28.0",
        "Dockerfile": "FROM python:3.10\nRUN pip install Pillow==9.0.0",
        ".github/workflows/ci.yml": "name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: pip install pillow",
    }

    def _fake(client, owner, repo, path, ref):
        return files.get(path, "")

    client = MagicMock()
    with patch("ghas_llm.agentic_triage.get_file_via_api", side_effect=_fake):
        ctx = gather_extra_context(client, "example-org", "app", "main", sig)
    assert ctx.package_pinned_in_manifest
    assert ctx.package_in_dockerfile
    assert "pillow" in ctx.dockerfile_excerpt.lower()
    assert ctx.ci_workflow_path == ".github/workflows/ci.yml"
    assert ctx.package_in_ci


# --------------------------------------------------------------------------- #
# Routing safety overrides                                                    #
# --------------------------------------------------------------------------- #


def test_routing_no_apis_means_leave_open() -> None:
    profile = RepoProfile(full_name="example-org/x", is_internal=True, push_date_known=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=[])
    matrix = EvidenceMatrix(reproducible=False)
    routing, impact = _decision_to_routing("false_positive", matrix, sig, profile)
    assert routing == "leave_open"
    assert impact == "insufficient_advisory_signal"


def test_routing_no_direct_usage_with_apis_is_false_positive() -> None:
    profile = RepoProfile(full_name="example-org/x", is_internal=True, push_date_known=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matrix = EvidenceMatrix(reproducible=False)
    routing, _ = _decision_to_routing("needs_review", matrix, sig, profile)
    assert routing == "false_positive"


def test_routing_high_confidence_reproducible_in_progress() -> None:
    profile = RepoProfile(full_name="example-org/x", is_internal=True, push_date_known=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matrix = EvidenceMatrix(reproducible=True, confidence_label="high", direct_code_hits=2)
    routing, impact = _decision_to_routing("reproducible", matrix, sig, profile)
    assert routing == "in_progress"
    assert impact == "direct_vulnerable_usage"


def test_routing_high_confidence_but_model_disagrees_leaves_open() -> None:
    profile = RepoProfile(full_name="example-org/x", is_internal=True, push_date_known=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matrix = EvidenceMatrix(reproducible=True, confidence_label="high", direct_code_hits=2)
    routing, _ = _decision_to_routing("false_positive", matrix, sig, profile)
    assert routing == "leave_open"


# --------------------------------------------------------------------------- #
# final_verdict — JSON output, hedge demotion                                 #
# --------------------------------------------------------------------------- #


def _final_resp(payload: dict) -> MagicMock:
    fake_resp = MagicMock()
    fake_resp.choices = [MagicMock()]
    fake_resp.choices[0].message.content = json.dumps(payload)
    return fake_resp


def test_final_verdict_uses_json_output_and_routes_correctly() -> None:
    config = {"global": {"llm": {"model": "gpt-5.4-mini"}}}
    profile = RepoProfile(
        full_name="example-org/app", visibility="private", is_internal=True,
        push_date_known=True, days_since_last_push=2,
    )
    sig = VulnSignature(
        package="lodash", ecosystem="npm", severity="high",
        vulnerable_apis=["template"], fixed_version="4.17.21",
    )
    matches = [CodeMatch(path="src/render.ts")]
    matrix = EvidenceMatrix(
        reproducible=True, confidence_label="high",
        direct_code_hits=1, repo_active=True,
    )
    extras = ExtraContext(readme_excerpt="App that renders templates")

    fake_oai = MagicMock()
    fake_oai.chat.completions.create.return_value = _final_resp({
        "evidence_for": ["template() called in src/render.ts"],
        "evidence_against": ["search may have missed an alias"],
        "falsifying_check": "Run a wider grep — done, no other paths.",
        "exploitation_path": "Untrusted user input -> render.ts:42 -> lodash.template -> RCE",
        "blast_radius": "customer_facing",
        "confidence_score": 90,
        "priority": "P1",
        "decision": "reproducible",
        "major_premise": "CVE-X affects lodash via the template path with high severity.",
        "minor_premise": "example-org/app uses lodash.template in src/render.ts (active repo).",
        "conclusion_summary": "Upgrade lodash to 4.17.21 in src/render.ts.",
    })
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        verdict = final_verdict(
            config, alert_kind="dependabot", sig=sig, profile=profile,
            matches=matches, blame=[], org_repos=0, matrix=matrix, extras=extras,
        )
    assert verdict.routing == "in_progress"
    assert verdict.impact == "direct_vulnerable_usage"
    assert "src/render.ts" in verdict.jira_comment or "render.ts" in verdict.minor_premise
    assert "Conclusion:" not in verdict.jira_comment
    assert verdict.evidence_for and verdict.evidence_against
    assert verdict.exploitation_path.startswith("Untrusted")
    assert verdict.blast_radius == "customer_facing"
    assert verdict.priority == "P1"
    assert "P1" not in verdict.jira_comment
    assert "Critic note" not in verdict.jira_comment
    assert "Confidence" not in verdict.jira_comment


def test_final_verdict_clamps_risk_for_false_positive() -> None:
    """False-positive verdicts default to low risk and a no-reachable-path note."""
    config = {"global": {"llm": {"model": "gpt-5.4-mini"}}}
    profile = RepoProfile(full_name="example-org/x", is_internal=True, push_date_known=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matrix = EvidenceMatrix(reproducible=False, confidence_label="low")
    extras = ExtraContext()

    fake_oai = MagicMock()
    fake_oai.chat.completions.create.return_value = _final_resp({
        "evidence_for": [], "evidence_against": [], "falsifying_check": "",
        "exploitation_path": "",
        "blast_radius": "internal_only",
        "decision": "false_positive",
        "major_premise": "Advisory affects foo() in package x.",
        "minor_premise": "example-org/x has zero non-test matches for foo().",
        "conclusion_summary": "No reachable usage of foo() in this repo.",
    })
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        verdict = final_verdict(
            config, alert_kind="dependabot", sig=sig, profile=profile,
            matches=[], blame=[], org_repos=0, matrix=matrix, extras=extras,
        )
    assert verdict.routing == "false_positive"
    assert verdict.risk_score <= 3
    assert verdict.exploitation_path == "no reachable path found"


def test_final_verdict_default_priority_when_missing() -> None:
    config = {"global": {"llm": {"model": "gpt-5.4-mini"}}}
    profile = RepoProfile(full_name="example-org/x", is_internal=True, push_date_known=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=[])
    matrix = EvidenceMatrix(reproducible=False, confidence_label="low")
    extras = ExtraContext()

    fake_oai = MagicMock()
    fake_oai.chat.completions.create.return_value = _final_resp({
        "evidence_for": [], "evidence_against": [], "falsifying_check": "",
        "decision": "needs_review",
        "major_premise": "Advisory does not name a specific API.",
        "minor_premise": "example-org/x has no reachability data without an API symbol.",
        "conclusion_summary": "Advisory does not name a surface.",
    })
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        verdict = final_verdict(
            config, alert_kind="dependabot", sig=sig, profile=profile,
            matches=[], blame=[], org_repos=0, matrix=matrix, extras=extras,
        )
    assert verdict.priority == "P3"
    assert verdict.blast_radius == "unknown"


def test_final_verdict_no_meta_talk_in_jira_comment() -> None:
    """The new judge contract must never produce critic notes, P-numbers,
    or confidence-score language inside the Jira comment.
    """
    config = {"global": {"llm": {"model": "gpt-5.4-mini"}}}
    profile = RepoProfile(
        full_name="example-org/app", visibility="private", is_internal=True,
        push_date_known=True, days_since_last_push=2,
    )
    sig = VulnSignature(
        package="x", ecosystem="pip", severity="high", vulnerable_apis=["foo"],
    )
    matrix = EvidenceMatrix(reproducible=True, confidence_label="high", direct_code_hits=1)
    extras = ExtraContext()

    fake_oai = MagicMock()
    fake_oai.chat.completions.create.return_value = _final_resp({
        "evidence_for": [], "evidence_against": [], "falsifying_check": "",
        "decision": "reproducible",
        "major_premise": "Advisory describes RCE in foo() of package x.",
        "minor_premise": "example-org/app has 1 non-test match for foo() in x.py.",
        "conclusion_summary": "Upgrade x to the fixed version.",
    })
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        verdict = final_verdict(
            config, alert_kind="dependabot", sig=sig, profile=profile,
            matches=[CodeMatch(path="x.py")], blame=[], org_repos=0,
            matrix=matrix, extras=extras,
        )
    body = verdict.jira_comment
    assert "Critic note" not in body
    assert "Confidence" not in body
    assert "hedging" not in body.lower()
    assert "P0" not in body and "P1" not in body and "P2" not in body and "P3" not in body
    assert verdict.routing == "in_progress"


def test_final_verdict_handles_llm_failure_gracefully() -> None:
    config = {"global": {"llm": {"model": "gpt-5.4-mini"}}}
    profile = RepoProfile(full_name="example-org/x", is_internal=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=[])
    matrix = EvidenceMatrix(reproducible=False, confidence_label="low")
    extras = ExtraContext()

    fake_oai = MagicMock()
    fake_oai.chat.completions.create.side_effect = RuntimeError("upstream timeout")
    with patch("ghas_llm.agentic_triage.build_openai_client", return_value=fake_oai):
        verdict = final_verdict(
            config, alert_kind="dependabot", sig=sig, profile=profile,
            matches=[], blame=[], org_repos=0, matrix=matrix, extras=extras,
        )
    assert "Conclusion:" not in verdict.jira_comment
    assert verdict.routing == "leave_open"


# --------------------------------------------------------------------------- #
# Final-payload sanity: never includes 999 days                               #
# --------------------------------------------------------------------------- #


def test_final_user_payload_does_not_contain_999_for_unknown_push() -> None:
    from ghas_llm.agentic_triage import _final_user_payload
    profile = RepoProfile(full_name="example-org/app", visibility="private", is_internal=True)
    sig = VulnSignature(package="x", ecosystem="pip", vulnerable_apis=["foo"])
    matrix = EvidenceMatrix(reproducible=False)
    extras = ExtraContext()
    payload = _final_user_payload(
        "dependabot", sig, profile, [], [], 0, matrix, extras,
    )
    assert "999" not in payload
    assert "unknown" in payload.lower()


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #


@patch("ghas_llm.agentic_triage.final_verdict")
@patch("ghas_llm.agentic_triage.gather_extra_context")
@patch("ghas_llm.agentic_triage.org_wide_impact", return_value=2)
@patch("ghas_llm.agentic_triage.gather_blame", return_value=[])
@patch("ghas_llm.agentic_triage.find_code_reachability")
@patch("ghas_llm.agentic_triage.extract_vuln_signature")
@patch("ghas_llm.agentic_triage.gather_repo_profile")
def test_agentic_triage_dependabot_orchestration(
    mock_profile: MagicMock,
    mock_extract: MagicMock,
    mock_search: MagicMock,
    _mock_blame: MagicMock,
    _mock_org: MagicMock,
    mock_extras: MagicMock,
    mock_final: MagicMock,
) -> None:
    mock_profile.return_value = RepoProfile(
        full_name="example-org/app", visibility="private",
        is_internal=True, push_date_known=True, days_since_last_push=1,
    )
    mock_extract.return_value = VulnSignature(
        package="lodash", ecosystem="npm", vulnerable_apis=["template"],
        severity="high", trigger_summary="prototype pollution via template",
    )
    mock_search.return_value = [CodeMatch(path="src/x.ts")]
    mock_extras.return_value = ExtraContext(readme_excerpt="x", manifest_path="package.json")

    mock_final.return_value = AgenticVerdict(
        routing="in_progress",
        impact="direct_vulnerable_usage",
        confidence="high",
        reproducible=True,
        confidence_score=80,
        jira_comment="Found template usage in src/x.ts.\n\nConclusion: Reproducible — upgrade lodash to 4.17.21.",
        profile=mock_profile.return_value,
        signature=mock_extract.return_value,
        matches=[CodeMatch(path="src/x.ts")],
        blame=[],
        org_repos_affected=2,
    )
    client = MagicMock()
    out = agentic_triage(
        config={"global": {"github": {"org": "example-org"}, "llm": {}}},
        client=client,
        owner="example-org",
        repo="app",
        branch="main",
        org="example-org",
        alert_kind="dependabot",
        alert={
            "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
            "security_vulnerability": {"severity": "high"},
            "security_advisory": {"summary": "Prototype pollution"},
        },
    )
    assert out.routing == "in_progress"
    assert out.reproducible
    mock_search.assert_called_once()
    mock_extras.assert_called_once()
    mock_final.assert_called_once()


# --------------------------------------------------------------------------- #
# JQL: scope is open + in progress                                            #
# --------------------------------------------------------------------------- #


def test_jql_uses_status_categories_in_default_yaml() -> None:
    import os
    import yaml
    from ghas_llm.jira_ghas_cycle import build_jira_github_jql

    cfg_path = os.path.join(
        os.path.dirname(__file__), "..", "ghas_llm.yaml",
    )
    with open(cfg_path) as fh:
        cfg = yaml.safe_load(fh)
    jira_cfg = cfg["integrations"]["jira"]
    jql = build_jira_github_jql(jira_cfg)
    assert "statusCategory" in jql
    assert "To Do" in jql
    assert "In Progress" in jql
    assert "False Positive" not in jql
