# Changelog

## 0.1.0 — 2026-06-08

Initial public release on [subhajit0x/ghas-auto-triage](https://github.com/subhajit0x/ghas-auto-triage).

- Multi-agent Jira-first GHAS triage (Dependabot, CodeQL, secret scanning)
- Same defensive pipeline family as [appsec-triage](https://github.com/safernandez666/appsec-triage): truth table, prosecutor, critic, consistency, org memory
- Git-persisted `.triage_history.jsonl` and `.human_feedback.jsonl`
- GitHub Actions workflow with optional SSH memory push
- 191 tests
