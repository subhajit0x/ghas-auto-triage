# Contributing

Thanks for your interest in GHAS Auto-Triage.

## Development setup

```bash
git clone https://github.com/subhajit0x/ghas-auto-triage.git
cd ghas-auto-triage
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp ghas_llm.yaml.example ghas_llm.yaml
pytest tests/ -q
```

## Pull requests

- Keep changes focused; match existing style.
- Add or update tests for behavior changes.
- Do not commit secrets, real Jira keys, or org-specific config.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
