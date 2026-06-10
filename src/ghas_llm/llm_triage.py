from __future__ import annotations

import json
import os
import re
import time
from typing import Any, NamedTuple

from openai import OpenAI

from ghas_llm.models import TriageVerdict


class BriefStructuredResult(NamedTuple):
    jira_comment: str
    routing: str
    impact_classification: str
    confidence: str


SYSTEM_PROMPT = """You are an application-security engineer triaging GHAS alerts for the example-org organization.

For each alert (Dependabot, CodeQL, or secret scanning), determine whether it impacts our repositories by checking alert metadata and the source code / dependency files provided.

Decision order:
1. Reachability - Is the vulnerable function actually called in our code? If no evidence, say so.
2. Exploitability - Are there mitigations (input validation, WAF, auth gates, network isolation)?
3. Environment - Dev-only / test-only / build-time dependency that never runs in production?
4. Version match - Does the installed version fall in the advisory's affected range?
5. Secret scanning - Judge from type, file path, and age. Never see the actual secret value.

Output: one JSON object, no markdown fences.
Keys:
  verdict: "true_positive", "false_positive", or "needs_review"
  confidence: "high", "medium", or "low"
  severity_assessment: "critical", "high", "medium", "low", or "info" (based on exploitability in our repo, not raw advisory score)
  reasoning: 2-4 sentences with specific filenames, line numbers, function names from context
  code_usage: what the vulnerable code does in our codebase, or "not found in context"
  exploitability: who can trigger it, preconditions, existing mitigations
  suggested_action: concrete next step (e.g. "upgrade lodash to >=4.17.21 in package.json")
  priority: "immediate", "next_sprint", "backlog", or "no_action"

Rules:
- If insufficient context to confirm reachability, set verdict to "needs_review" and confidence to "low". Never fabricate paths or function names.
- Do not mark true_positive just because a package appears in a lockfile - need evidence of vulnerable usage.
- Do not mark false_positive just because a file is in a test directory - tests importing production code prove reachability.
- When Jira context is provided, use it to enrich analysis but base the verdict on GitHub alert data and code context.
"""

SYSTEM_PROMPT_BRIEF = """You are a senior application-security engineer on the example-org infosec team. You are writing a Jira comment for your teammates after reviewing a GitHub Advanced Security alert.

Rules:
- Write exactly as a human security engineer would: plain English, direct, no fluff.
- Do NOT start with "We have received..." or "A GitHub Advanced Security alert...". Jump straight into the finding.
- 3 to 6 sentences. Be concise but precise.
- Reference specific files, line numbers, function names, or paths when the context provides them. If the codebase was scanned and the vulnerable function is not called, say that clearly.
- Do NOT output JSON, markdown fences, bullet lists, labels like VERDICT/PRIORITY, or any structured format.
- The LAST line must be exactly: Conclusion: <one actionable sentence — what to do, or what was confirmed safe>
- Never invent file paths, function names, or line numbers that are not in the provided context.
- If the dependency appears only in a lockfile or manifest with no evidence of the vulnerable function being called, be honest: say the usage was not found in the scanned code.

You will be called multiple times for the same alert. Each call is a fresh review pass — bring your best judgment each time. Your final output replaces any prior draft.
"""

SYSTEM_PROMPT_STRUCT = """You are a senior application-security engineer triaging GitHub Advanced Security alerts for example-org.

You must compare the advisory to the repository evidence provided (file snippets, usage search, fork info, commit authors). Be precise: do not claim direct usage unless the context shows imports, calls, or the vulnerable code path.

Output exactly one JSON object (no markdown fences). Keys:
  "impact_classification": one of:
    "direct_vulnerable_usage" — application code uses the vulnerable dependency API or the flagged code path is reachable in prod
    "transitive_or_manifest_only" — package appears in lockfile/manifest but scanned code shows no direct import/use of the vulnerable surface (treat as not directly impacted)
    "code_scanning_location" — for code_scanning alerts: finding references a real code location
    "secret_exposure" — for secret_scanning alerts
    "insufficient_evidence" — cannot determine reachability from the evidence
  "confidence": "high" | "medium" | "low"
  "recommended_status": one of:
    "false_positive" — not exploitable here: no direct usage, transitive-only, or advisory does not apply to how we use the component
    "in_progress" — only if impact is direct_vulnerable_usage or (code_scanning_location with high/medium confidence) or secret_exposure needing remediation
    "leave_open" — uncertain; needs human review; do not imply team must upgrade "if maybe used"
  "jira_comment": plain English, 3-6 sentences, no JSON inside. Last line MUST be: Conclusion: <single sentence>

Hard rules:
- If the evidence says there are no direct references/calls to the package or vulnerable API in application code, set impact_classification to transitive_or_manifest_only and recommended_status to false_positive.
- Never set recommended_status to in_progress for transitive_or_manifest_only or insufficient_evidence unless confidence is high and you cite specific lines/paths proving direct use.
- If you would write "upgrade if used" or "if it is being used", use recommended_status leave_open and say so in the Conclusion.
- Low confidence must not produce in_progress.
"""


_HEDGE_IN_CONCLUSION = re.compile(
    r"if\s+(it\s+)?(is\s+)?being\s+used|if\s+used|if\s+the\s+package|may\s+need\s+to\s+upgrade|otherwise,\s*no\s+action",
    re.I,
)


def _enforce_structured_routing(
    data: dict[str, Any],
    *,
    alert_kind: str,
) -> tuple[str, str]:
    """Return (routing, impact) with safety overrides."""
    impact = str(data.get("impact_classification", "insufficient_evidence")).strip().lower()
    conf = str(data.get("confidence", "low")).strip().lower()
    if conf not in ("high", "medium", "low"):
        conf = "low"
    rec = str(data.get("recommended_status", "leave_open")).strip().lower().replace(" ", "_")
    if rec not in ("false_positive", "in_progress", "leave_open"):
        rec = "leave_open"

    transitive = "transitive" in impact or "manifest" in impact
    if transitive:
        rec = "false_positive"
    if impact == "insufficient_evidence":
        if rec == "in_progress":
            rec = "leave_open"
    if conf == "low" and rec == "in_progress":
        rec = "leave_open"
    if impact == "direct_vulnerable_usage" and conf == "low":
        rec = "leave_open"
    if alert_kind == "dependabot" and transitive:
        rec = "false_positive"

    return rec, impact


def brief_structured_review_with_openai(
    config: dict[str, Any],
    *,
    alert_kind: str,
    alert_summary: str,
    file_context: str,
    extra_context: str = "",
) -> BriefStructuredResult:
    """JSON structured verdict + comment; strict routing for Jira transitions."""
    g = config.get("global", {}).get("llm", {})
    model = str(g.get("model", "gpt-5.4-mini"))
    temperature = float(g.get("temperature", 0))
    review_passes = int(config.get("agent", {}).get("review_passes", 2))
    review_passes = max(1, min(review_passes, 4))

    user = (
        f"Alert kind: {alert_kind}\n\n"
        f"=== Extra ===\n{extra_context or '(none)'}\n\n"
        f"=== Alert data ===\n{alert_summary}\n\n"
        f"=== Repository context ===\n{file_context or '(no context)'}\n"
    )

    def _call_structured() -> dict[str, Any]:
        client = build_openai_client(config)
        resp = client.chat.completions.create(
            model=model,
            temperature=temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_STRUCT},
                {"role": "user", "content": user},
            ],
        )
        raw = (resp.choices[0].message.content or "").strip()
        return _parse_json_object(raw)

    try:
        data = _call_structured()
    except Exception as exc:  # noqa: BLE001
        return BriefStructuredResult(
            jira_comment=_normalize_brief_comment(
                f"Structured triage failed ({exc}).\n\nConclusion: Review manually.",
            ),
            routing="leave_open",
            impact_classification="insufficient_evidence",
            confidence="low",
        )

    comment = str(data.get("jira_comment", "")).strip()
    routing, impact = _enforce_structured_routing(data, alert_kind=alert_kind)
    comment = _normalize_brief_comment(comment)
    if _HEDGE_IN_CONCLUSION.search(comment):
        routing = "leave_open"
    conf = str(data.get("confidence", "low")).strip().lower()

    if review_passes > 1:
        try:
            client = build_openai_client(config)
            refine_in = (
                f"=== Alert + context ===\n{user}\n\n"
                f"=== Draft comment ===\n{comment}\n\n"
                f"Routing locked: {routing}. Rewrite comment only; keep same meaning; end with Conclusion:."
            )
            resp = client.chat.completions.create(
                model=model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": REFINE_PROMPT},
                    {"role": "user", "content": refine_in},
                ],
            )
            comment = _normalize_brief_comment((resp.choices[0].message.content or "").strip())
            if _HEDGE_IN_CONCLUSION.search(comment):
                routing = "leave_open"
        except Exception:  # noqa: BLE001
            pass

    return BriefStructuredResult(
        jira_comment=comment,
        routing=routing,
        impact_classification=impact,
        confidence=conf if conf in ("high", "medium", "low") else "low",
    )


def _parse_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if not text:
        raise ValueError("Empty model output")

    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    dec = json.JSONDecoder()
    start = text.find("{")
    if start < 0:
        raise ValueError("No JSON object in model output")
    try:
        obj, _ = dec.raw_decode(text, start)
    except json.JSONDecodeError as e:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            raise ValueError("No JSON object in model output") from e
        return json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("Root JSON must be an object")
    return obj


def build_openai_client(config: dict[str, Any]) -> OpenAI:
    g = config.get("global", {}).get("llm", {})
    api_key = get_openai_key(config)
    kwargs: dict[str, Any] = {"api_key": api_key}

    base_url = (g.get("base_url") or "").strip()
    if not base_url:
        base_url = os.environ.get(str(g.get("base_url_env", "OPENAI_BASE_URL")), "").strip()
    if base_url:
        kwargs["base_url"] = base_url

    org = (g.get("organization") or "").strip()
    if not org:
        org = os.environ.get(str(g.get("organization_env", "OPENAI_ORG_ID")), "").strip()
    if org:
        kwargs["organization"] = org

    timeout = g.get("timeout_seconds")
    if timeout is not None:
        kwargs["timeout"] = float(timeout)

    return OpenAI(**kwargs)


def get_openai_key(config: dict[str, Any]) -> str:
    env_name = (
        config.get("global", {})
        .get("llm", {})
        .get("api_key_env", "OPENAI_API_KEY")
    )
    key = os.environ.get(str(env_name), "")
    if not key:
        raise RuntimeError(f"Missing API key in environment: {env_name}")
    return key


def _enrich_dependabot_summary(alert: dict) -> str:
    parts: list[str] = []
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    parts.append(f"Package: {pkg.get('ecosystem', '?')}/{pkg.get('name', '?')}")
    if dep.get("manifest_path"):
        parts.append(f"Manifest: {dep['manifest_path']}")
    scope = dep.get("scope")
    if scope:
        parts.append(f"Scope: {scope}")
    sv = alert.get("security_vulnerability") or {}
    if sv.get("severity"):
        parts.append(f"Severity: {sv['severity']}")
    if sv.get("vulnerable_version_range"):
        parts.append(f"Affected versions: {sv['vulnerable_version_range']}")
    fv = sv.get("first_patched_version") or {}
    if isinstance(fv, dict) and fv.get("identifier"):
        parts.append(f"Fix available: {fv['identifier']}")
    elif isinstance(fv, str):
        parts.append(f"Fix available: {fv}")
    adv = alert.get("security_advisory") or {}
    if adv.get("summary"):
        parts.append(f"Advisory: {adv['summary']}")
    if adv.get("cve_id"):
        parts.append(f"CVE: {adv['cve_id']}")
    cwes = adv.get("cwes") or []
    if isinstance(cwes, list) and cwes:
        cwe_ids = [str(c.get("cwe_id", c) if isinstance(c, dict) else c) for c in cwes[:5]]
        parts.append(f"CWEs: {', '.join(cwe_ids)}")
    if adv.get("description"):
        parts.append(f"Description: {str(adv['description'])[:2000]}")
    refs = adv.get("references") or []
    if isinstance(refs, list):
        urls = [str(r.get("url", r) if isinstance(r, dict) else r) for r in refs[:5]]
        if urls:
            parts.append(f"References: {', '.join(urls)}")
    return "\n".join(parts)


def _enrich_code_scanning_summary(alert: dict) -> str:
    parts: list[str] = []
    rule = alert.get("rule") or {}
    parts.append(f"Rule: {rule.get('id', '?')} — {rule.get('description', '?')}")
    if rule.get("severity"):
        parts.append(f"Severity: {rule['severity']}")
    sec_sev = rule.get("security_severity_level")
    if sec_sev:
        parts.append(f"Security severity: {sec_sev}")
    if rule.get("full_description"):
        parts.append(f"Full description: {str(rule['full_description'])[:2000]}")
    if rule.get("help"):
        parts.append(f"Help: {str(rule['help'])[:1500]}")
    tags = rule.get("tags") or []
    if tags:
        parts.append(f"Tags: {', '.join(str(t) for t in tags[:10])}")
    tool_obj = alert.get("tool") or {}
    parts.append(f"Tool: {tool_obj.get('name', '?')} {tool_obj.get('version', '')}")
    inst = alert.get("most_recent_instance") or {}
    loc = inst.get("location") or {}
    if loc.get("path"):
        parts.append(f"Location: {loc['path']}:{loc.get('start_line', '?')}-{loc.get('end_line', '?')}")
    if inst.get("message", {}).get("text"):
        parts.append(f"Message: {inst['message']['text'][:1000]}")
    return "\n".join(parts)


def _enrich_secret_scanning_summary(alert: dict) -> str:
    parts: list[str] = []
    parts.append(f"Secret type: {alert.get('secret_type_display_name') or alert.get('secret_type', '?')}")
    if alert.get("push_protection_bypassed"):
        parts.append("Push protection: BYPASSED")
    if alert.get("validity"):
        parts.append(f"Validity: {alert['validity']}")
    if alert.get("state"):
        parts.append(f"State: {alert['state']}")
    locs = alert.get("locations") or []
    if isinstance(locs, list):
        for i, loc in enumerate(locs[:5]):
            if isinstance(loc, dict):
                lt = loc.get("type", "")
                details = loc.get("details") or {}
                if isinstance(details, dict):
                    parts.append(f"Location[{i}]: type={lt} path={details.get('path', '?')} "
                                 f"line={details.get('start_line', '?')}")
    return "\n".join(parts)


def summarize_alert_for_llm(kind: str, alert: dict) -> str:
    if kind == "secret_scanning":
        redacted = dict(alert)
        for k in ("secret",):
            if k in redacted:
                redacted[k] = "[REDACTED]"
        nested = redacted.get("secret_scanning")
        if isinstance(nested, dict):
            ns = dict(nested)
            if "secret" in ns:
                ns["secret"] = "[REDACTED]"
            redacted["secret_scanning"] = ns
        enriched = _enrich_secret_scanning_summary(redacted)
        raw = json.dumps(redacted, indent=2, default=str)[:6000]
        return f"{enriched}\n\n--- Raw alert JSON (truncated) ---\n{raw}"
    if kind == "dependabot":
        enriched = _enrich_dependabot_summary(alert)
        raw = json.dumps(alert, indent=2, default=str)[:8000]
        return f"{enriched}\n\n--- Raw alert JSON (truncated) ---\n{raw}"
    if kind == "code_scanning":
        enriched = _enrich_code_scanning_summary(alert)
        raw = json.dumps(alert, indent=2, default=str)[:8000]
        return f"{enriched}\n\n--- Raw alert JSON (truncated) ---\n{raw}"
    return json.dumps(alert, indent=2, default=str)[:12000]


def _normalize_brief_comment(text: str) -> str:
    """Strip accidental JSON / fences; ensure a Conclusion: line exists."""
    t = (text or "").strip()
    if not t:
        return "Conclusion: Automated review produced no text; please review the alert manually."
    if t.startswith("{") and '"verdict"' in t:
        try:
            data = _parse_json_object(t)
            parts = [str(data.get("reasoning", "")), str(data.get("suggested_action", ""))]
            t = " ".join(p for p in parts if p).strip() or t
        except (ValueError, KeyError):
            pass
    t = re.sub(r"^\s*```[a-zA-Z0-9]*\s*", "", t)
    t = re.sub(r"\s*```\s*$", "", t)
    t = t.strip()
    if "conclusion:" not in t.lower():
        t = f"{t}\n\nConclusion: Needs manual review — model did not provide a conclusion line."
    return t[:8000]


REFINE_PROMPT = """You are a senior security engineer doing a second review of a draft Jira comment written by a colleague. The draft may be too verbose, miss important details, or draw the wrong conclusion.

Rules:
- Rewrite the comment in 3-6 sentences max. Be direct.
- If the draft says "no usage found" but the context shows actual imports or function calls, correct that.
- If the draft is vague, make it specific (cite files, versions, CVEs).
- Keep the LAST line as: Conclusion: <one actionable sentence>
- Do NOT add headers, labels, JSON, or markdown fences.
- Output only the final rewritten comment, nothing else.
"""


def brief_conclusion_with_openai(
    config: dict[str, Any],
    *,
    alert_kind: str,
    alert_summary: str,
    file_context: str,
) -> str:
    """Multi-pass review: draft then refine, returning a short human Jira comment."""
    g = config.get("global", {}).get("llm", {})
    model = str(g.get("model", "gpt-5.4-mini"))
    temperature = float(g.get("temperature", 0))
    review_passes = int(config.get("agent", {}).get("review_passes", 2))
    review_passes = max(1, min(review_passes, 4))

    user_msg = (
        f"Alert kind: {alert_kind}\n\n"
        f"=== Alert data ===\n{alert_summary}\n\n"
        f"=== Repository context (file snippets and usage hints) ===\n"
        f"{file_context or '(no file context — state that the codebase could not be accessed)'}\n"
    )

    def _call(system: str, user: str) -> str:
        client = build_openai_client(config)
        resp = client.chat.completions.create(
            model=model,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return (resp.choices[0].message.content or "").strip()

    try:
        draft = _call(SYSTEM_PROMPT_BRIEF, user_msg)
        draft = _normalize_brief_comment(draft)

        for _ in range(review_passes - 1):
            refine_input = (
                f"=== Original alert + context ===\n{user_msg}\n\n"
                f"=== Draft comment to review ===\n{draft}"
            )
            draft = _call(REFINE_PROMPT, refine_input)
            draft = _normalize_brief_comment(draft)

        return draft
    except Exception as exc:  # noqa: BLE001
        return _normalize_brief_comment(
            f"Review failed ({exc}). "
            f"Conclusion: Review this alert and repository manually."
        )


def triage_with_openai(
    config: dict[str, Any],
    *,
    alert_kind: str,
    alert_summary: str,
    file_context: str,
) -> TriageVerdict:
    g = config.get("global", {}).get("llm", {})
    model = str(g.get("model", "gpt-5.4-mini"))
    temperature = float(g.get("temperature", 0))

    user = (
        f"Alert kind: {alert_kind}\n\n"
        f"=== Alert data ===\n{alert_summary}\n\n"
        f"=== Repository context (file snippets) ===\n{file_context or '(no file context available — set verdict to needs_review)'}\n"
    )
    max_attempts = int(g.get("max_retries", 3) or 3)
    if max_attempts < 1:
        max_attempts = 1
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            client = build_openai_client(config)
            resp = client.chat.completions.create(
                model=model,
                temperature=temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
            )
            content = (resp.choices[0].message.content or "").strip()
            data = _parse_json_object(content)
            return TriageVerdict.from_llm_json(data)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt + 1 < max_attempts:
                time.sleep(1.0 * (attempt + 1))
                continue
            break
    exc = last_exc or RuntimeError("unknown LLM failure")
    return TriageVerdict(
        verdict="needs_review",
        confidence="low",
        severity_assessment="unknown",
        reasoning=f"LLM triage failed; treat as needs manual review. ({exc})",
        code_usage="(unavailable)",
        exploitability="(unavailable)",
        suggested_action="Re-run triage or review alert manually.",
        priority="immediate",
        raw_response={"error": str(exc)},
    )


def verify_llm_connectivity(config: dict[str, Any]) -> dict[str, Any]:
    g = config.get("global", {}).get("llm", {})
    model = str(g.get("model", "gpt-5.4-mini"))
    client = build_openai_client(config)
    resp = client.chat.completions.create(
        model=model,
        temperature=0,
        max_tokens=64,
        messages=[{"role": "user", "content": 'Reply with only JSON: {"ok": true, "service": "openai"}'}],
        response_format={"type": "json_object"},
    )
    content = (resp.choices[0].message.content or "").strip()
    parsed = _parse_json_object(content)
    return {"ok": bool(parsed.get("ok")), "model": model, "sample": parsed}
