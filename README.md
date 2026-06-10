# GHAS Auto-Triage

**Multi-agent GHAS triage for Jira — fewer LLM calls, fewer false positives, less alert fatigue.**

[![Tests](https://img.shields.io/badge/tests-191%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Open-source defensive triage for **Dependabot**, **CodeQL**, and **secret scanning**. Reads your Jira security queue, gathers **deterministic** evidence from GitHub (read-only), runs a **multi-agent** LLM pipeline, and posts **one-line human** comments with optional status transitions.

> The **LLM never acts alone.** Truth table, prosecutor, and critic wrap every verdict. Most alerts never reach the judge.

Sibling: [appsec-triage](https://github.com/safernandez666/appsec-triage) (GitHub Issues edition, `httpx`-only). This repo is the **Jira / enterprise** edition — [docs/RELATIONSHIP.md](docs/RELATIONSHIP.md).

---

## Why teams use it

| USP | What you get |
|-----|----------------|
| **9 specialized agents** | Advisory, Evidence, Org Hunter, Judge, Prosecutor, Critic, Comment Scanner, Human Feedback, Global Memory — each with a narrow job |
| **Token-efficient by design** | Truth table **forces** verdicts without LLM; org memory **skips** judge when ≥3 repos agree; fast-path closes fixed/missing alerts with **zero** LLM; dedup skips redundant comments |
| **Jira-native** | Poll VM/security queue → comment → transition when confidence + tier floors pass |
| **Human-in-the-loop** | Learns from analyst replies; never talks over a human (`human_after_bot`) |
| **Cross-run memory** | `.triage_history.jsonl` + `.human_feedback.jsonl`, git-persisted between runs |
| **Production guardrails** | Tier-1 highest floors; `dry_run`; prosecutor only **downgrades**; temperature 0 |
| **Self-hosted** | GitHub Actions + YAML config — no SaaS lock-in |

---

## Multi-agent pipeline (Z1 → Z4)

```
Z1 Routing        →  skip / fast-path (no LLM)
Z2 Investigation  →  Advisory + Evidence + Truth Table (LLM extract only)
Z3 Judgment       →  Judge → Prosecutor → Critic → Consistency
Z4 Output         →  Jira comment + optional transition
```

| Agent | LLM? | Saves tokens by… |
|-------|------|------------------|
| **Truth table** | No | Force FP/TP before any judge call |
| **Global memory** | No | Reuse org CVE consensus — skip judge |
| **Advisory** | Extract only | Pull API names; never decides verdict |
| **Evidence** | No | Code search, manifests, blame — facts only |
| **Org hunter** | Optional | Infra/deploy context without re-prompting judge |
| **Final judge** | Yes | One structured JSON verdict per alert |
| **Prosecutor** | Optional | Deterministic checks first; LLM only if needed |
| **Critic** | No | Floor check — degrade low confidence |
| **Comment scanner** | No | Skip re-triage when human already replied |

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Quick start

```bash
git clone https://github.com/subhajit0x/ghas-auto-triage.git && cd ghas-auto-triage
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp ghas_llm.yaml.example ghas_llm.yaml
cp .env.example .env
```

**Configure** `ghas_llm.yaml`: GitHub org, Jira URL, project key, tool/asset custom field IDs.

**Env vars:** `OPENAI_API_KEY`, `GHAS_TRIAGE_GITHUB_TOKEN`, `JIRA_EMAIL`, `JIRA_API_TOKEN`

```bash
python -m ghas_llm --llm-smoke                    # 1-token LLM ping
python -m ghas_llm --jira-first --repo-root .  # full Jira queue
python -m ghas_llm.local_dry_run --issue SEC-123
```

---

## GitHub Actions (daily triage)

Secrets: `OPENAI_API_KEY`, `GHAS_TRIAGE_GITHUB_TOKEN`, `JIRA_EMAIL`, `JIRA_API_TOKEN`

Run workflow with `dry_run=false`, `triage_limit=0`, `auto_transition=true`.

Memory files auto-commit via `persist-memory` job (SSH or `GITHUB_TOKEN`). Disable: `GHAS_LLM_MEMORY_GIT_PUSH=false`.

---

## Jira ticket format

1. **Tool** — `dependabot` \| `code-scanning` \| `secret-scanning`
2. **Asset** — `owner/repo`
3. **Alert #** — in description or parsed from GitHub URL

State: Jira property `ghas-triage.agent.state` · Marker: `<!-- ghas-triage-agent ... -->`

---

## vs [appsec-triage](https://github.com/safernandez666/appsec-triage)

| | appsec-triage | **ghas-auto-triage** |
|---|---------------|----------------------|
| Output | GitHub Issues | **Jira** |
| Deps | `httpx` | `openai` + `yaml` |
| Human feedback | — | **Yes** |
| Org hunter | — | **Yes** |
| Git memory | artifact | **commit on branch** |

---

## Tests & license

```bash
pytest tests/ -q   # 191 tests
```

Apache 2.0 · [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md)

**Author:** [Subhajit Saha](https://github.com/subhajit0x)
