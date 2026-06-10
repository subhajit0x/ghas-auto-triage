"""Main autonomous Jira-first orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ghas_llm.jira_ghas_cycle import run_jira_first_ghas_cycle


class GHASOrchestrator:
    """Owns the Jira lifecycle and delegates evidence work to agents.

    The current production entry point is still run_jira_first_ghas_cycle; this
    class gives the multi-agent system a stable home without duplicating Jira or
    AWS Secrets Manager code.
    """

    name = "orchestrator"

    def __init__(self, config: dict[str, Any], repo_root: Path) -> None:
        self.config = config
        self.repo_root = repo_root

    def run(self) -> dict[str, Any]:
        return run_jira_first_ghas_cycle(self.config, self.repo_root)

