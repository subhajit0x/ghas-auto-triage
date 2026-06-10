# Relationship to AppSec Triage

This repository and [appsec-triage](https://github.com/safernandez666/appsec-triage) are **sibling projects** from the same multi-agent defensive triage design:

| | [appsec-triage](https://github.com/safernandez666/appsec-triage) | **ghas-auto-triage** (this repo) |
|---|------|------|
| **Output** | GitHub Issues + alert dismiss | **Jira** comments + status transitions |
| **Entry** | `appsec-triage --repo org/svc` | `python -m ghas_llm --jira-first` |
| **Config** | `.env` + optional TOML | `ghas_llm.yaml` |
| **Deps** | `httpx` only | `openai`, `pyyaml`, `boto3` (optional AWS Jira secrets) |
| **Scope** | GitHub-native PoC, batch `--repos` | Enterprise Jira queue, org-wide memory, human feedback |
| **Memory** | `.triage_history.jsonl` | Same + `.human_feedback.jsonl` + git persist |

## Same ideas (shared DNA)

Both implement **“the LLM never acts alone”**:

1. **Routing / fast-path** — fixed, dismissed, missing alerts skip full LLM
2. **Investigation** — Advisory (extract APIs) + Evidence (code search, repo profile)
3. **Truth table** — deterministic tier + forced verdicts before the judge
4. **Judgment** — Final judge LLM + Prosecutor + Critic
5. **Consistency** — anti flip-flop via `.triage_history.jsonl`
6. **Org memory** — cross-repo CVE/package consensus

## When to use which

- **appsec-triage** — teams without Jira; want Issues on the repo; minimal deps; `--offline` demo; `--repos` batch
- **ghas-auto-triage** — teams with a **Jira VM/security queue**; need ticket comments, transitions, and human-in-the-loop learning

You can run both: appsec-triage on repos without Jira tickets; ghas-auto-triage on the central security board.
