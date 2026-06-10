"""LLM advisory worker.

Extracts the small signature the rest of the pipeline needs: affected package,
fixed version, vulnerable APIs/sinks, and special preconditions.
"""

from __future__ import annotations

from ghas_llm.agentic_triage import VulnSignature, extract_vuln_signature


class AdvisoryAgent:
    name = "advisory_agent"

    def __init__(self, config: dict) -> None:
        self.config = config

    def extract(self, alert: dict) -> VulnSignature:
        return extract_vuln_signature(self.config, alert)

