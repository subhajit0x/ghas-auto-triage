"""Prosecutor: adversarial peer review of the Final Judge."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ghas_llm.agentic_triage import AgenticVerdict
from ghas_llm.core.preflight import TruthTable
from ghas_llm.llm_triage import _parse_json_object, build_openai_client
from ghas_llm.logic.judge_prompt import PROSECUTOR_SYSTEM_PROMPT

log = logging.getLogger(__name__)


@dataclass
class ProsecutorReport:
    uphold: bool = True
    attack_holes: list[str] = field(default_factory=list)
    should_recompute_evidence: bool = False
    missing_evidence: list[str] = field(default_factory=list)
    alternate_decision: str | None = None
    alternate_conclusion: str = ""
    error: str = ""


class ProsecutorAgent:
    name = "prosecutor_agent"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        agent_cfg = config.get("agent", {}) if isinstance(config.get("agent", {}), dict) else {}
        prosecutor_cfg = (
            agent_cfg.get("prosecutor", {})
            if isinstance(agent_cfg.get("prosecutor", {}), dict)
            else {}
        )
        self.enabled = bool(prosecutor_cfg.get("enabled", True))
        self.recompute_on_disagreement = bool(
            prosecutor_cfg.get("recompute_on_disagreement", True),
        )

    def review(
        self,
        *,
        verdict: AgenticVerdict,
        truth_table: TruthTable,
        evidence_payload: str,
    ) -> ProsecutorReport:
        if not self.enabled:
            return ProsecutorReport(uphold=True)

        deterministic = self._deterministic_check(verdict, truth_table)
        if deterministic is not None:
            return deterministic

        g = self.config.get("global", {}).get("llm", {})
        model = str(g.get("prosecutor_model", g.get("judge_model", g.get("model", "gpt-5.4-mini"))))
        user = (
            f"Judge decision: {verdict.routing}\n"
            f"Judge confidence: {verdict.confidence} ({verdict.confidence_score})\n"
            f"Judge reproducible: {verdict.reproducible}\n"
            f"Judge stakeholder draft (for review only):\n{verdict.jira_comment}\n\n"
            f"Truth Table:\n  tier={truth_table.tier} reason={truth_table.tier_reason}\n"
            f"  force_verdict={truth_table.force_verdict or 'none'} ({truth_table.force_reason or 'n/a'})\n"
            f"  negative_proof_complete={truth_table.negative_proof_complete}\n"
            f"  direct_hits={truth_table.direct_code_hits} test_only={truth_table.test_only_hits}\n"
            f"  org_external_deploy={truth_table.org_external_deploy_evidence} kinds={truth_table.org_external_deploy_kinds}\n\n"
            f"Evidence payload (the Judge saw the same):\n{evidence_payload[:14000]}"
        )
        try:
            client = build_openai_client(self.config)
            try:
                resp = client.chat.completions.create(
                    model=model,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": PROSECUTOR_SYSTEM_PROMPT},
                        {"role": "user", "content": user},
                    ],
                )
            except Exception:  # noqa: BLE001
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": PROSECUTOR_SYSTEM_PROMPT},
                        {"role": "user", "content": user},
                    ],
                )
            data = _parse_json_object((resp.choices[0].message.content or "").strip())
            attack_holes = [str(x)[:280] for x in (data.get("attack_holes") or []) if x][:5]
            missing_evidence = [str(x)[:280] for x in (data.get("missing_evidence") or []) if x][:5]
            alt = data.get("alternate_decision")
            if isinstance(alt, str) and alt.lower() in {"false_positive", "reproducible", "needs_review"}:
                alternate_decision = alt.lower()
            else:
                alternate_decision = None
            return ProsecutorReport(
                uphold=bool(data.get("uphold", True)),
                attack_holes=attack_holes,
                should_recompute_evidence=bool(
                    data.get("should_recompute_evidence", False),
                ),
                missing_evidence=missing_evidence,
                alternate_decision=alternate_decision,
                alternate_conclusion=str(data.get("alternate_conclusion", "") or "")[:400],
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("prosecutor failed: %s", exc)
            return ProsecutorReport(
                uphold=True,
                error=f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _deterministic_check(
        verdict: AgenticVerdict,
        table: TruthTable,
    ) -> ProsecutorReport | None:
        if table.force_verdict and verdict.routing != _routing_for(table.force_verdict):
            target = _routing_for(table.force_verdict)
            return ProsecutorReport(
                uphold=False,
                attack_holes=[
                    f"Pre-Flight Truth Table forces {target} ({table.force_reason}) "
                    f"but the Judge produced {verdict.routing}.",
                ],
                alternate_decision=table.force_verdict,
                should_recompute_evidence=False,
            )
        if (
            verdict.routing == "false_positive"
            and verdict.reproducible
            and table.direct_code_hits > 0
        ):
            return ProsecutorReport(
                uphold=False,
                attack_holes=[
                    f"Direct reachability is {table.direct_code_hits} hits; "
                    "false_positive contradicts the reachability evidence.",
                ],
                alternate_decision="reproducible",
                should_recompute_evidence=False,
            )
        if (
            verdict.routing == "in_progress"
            and not verdict.reproducible
            and table.direct_code_hits == 0
        ):
            return ProsecutorReport(
                uphold=False,
                attack_holes=[
                    "Action-needed verdict with zero direct hits and no reachability proof.",
                ],
                alternate_decision="false_positive",
                should_recompute_evidence=False,
            )
        return None


def _routing_for(decision: str) -> str:
    if decision == "false_positive":
        return "false_positive"
    if decision == "reproducible":
        return "in_progress"
    return "leave_open"
