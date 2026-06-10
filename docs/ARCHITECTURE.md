# Architecture — Z1 → Z4 (Jira edition)

Same zone model as [appsec-triage](https://github.com/safernandez666/appsec-triage#architecture--the-llm-never-acts-alone), adapted for **Jira-first** output.

```
Z1 routing  →  Z2 investigation  →  Z3 judgment  →  Z4 output (Jira)
```

## Zone 1 — Routing (`jira_ghas_cycle.py`)

- Poll Jira for GHAS tool tickets (To Do / In Progress)
- Parse tool, `owner/repo`, alert number from custom fields + description
- Fast-path: alert `fixed` / `withdrawn` / `404` → short comment, optional close
- Fetch failure → error note on Jira, no Z2/Z3

## Zone 2 — Investigation (`agentic_triage.py`, agents)

| Component | Module | Role |
|-----------|--------|------|
| Advisory Agent | `agents/advisory_agent.py` | LLM extracts vulnerable API symbols from advisory |
| Evidence Agent | `agents/evidence_agent.py` | Code search, manifests, lockfiles, blame |
| Org Hunter | `agents/org_hunter_agent.py` | Org-wide deploy/infra discovery |
| Truth Table | `core/preflight.py` | Tier + forced verdict before judge |
| Global Memory | `logic/global_memory.py` | Cross-repo CVE consensus from history JSONL |

## Zone 3 — Judgment

| Component | Module | Role |
|-----------|--------|------|
| Final Judge | `agentic_triage.final_verdict` | LLM verdict + human conclusion |
| Prosecutor | `agents/prosecutor_agent.py` | Adversarial review; can downgrade only |
| Critic | `agents/critic_agent.py` | Confidence vs tier floor |
| Consistency Gate | `logic/consistency_gate.py` | SKIP / POST / GUARD vs prior runs |
| Human Feedback | `agents/human_feedback_agent.py` | Learn from human Jira replies |

## Zone 4 — Output (Jira)

- Comment on ticket (`brief_conclusion` or structured style)
- Issue property `ghas-triage.agent.state` for bot state
- HTML marker `<!-- ghas-triage-agent ... -->` for comment scanner
- Optional Jira transition when `auto_transition` + confidence ≥ tier floor
- **Never** auto-dismiss GitHub alerts by default (`post_triage_comments: false`)

## Guardrails (non-negotiable)

- Tier-1 repos: highest transition floors in `ghas_llm.yaml` → `production_trust.tier_floors`
- `human_after_bot`: skip re-comment when human replied after bot (learn only)
- `dry_run`: no Jira writes
- Temperature 0 on LLM calls (configurable via YAML)
