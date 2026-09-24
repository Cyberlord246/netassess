"""Orchestration layer — deterministic by default, AI-assisted optionally.

The orchestrator decides *what to do next* given the current asset graph. It
NEVER executes network actions itself and NEVER bypasses the Scope/Policy
engines: it only emits Task objects that the engine runs through the scheduler,
each of which is scope-checked again at execution time.

MODE deterministic:
    A fixed, well-understood decision tree drives the pipeline. No LLM needed;
    the full baseline assessment always completes.

MODE ai / auto:
    An LLM (if a provider/key is configured) is asked to rank/curate the next
    tasks the deterministic planner proposes. The LLM may only *choose among*
    or *deprioritise* already-scope-valid candidate tasks — it cannot invent a
    target, widen scope, or select a forbidden port. If no provider is
    available, it transparently falls back to deterministic planning.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..config import Config
from ..models import Host
from ..state import AssetGraph


class TaskType(str, Enum):
    DISCOVERY = "discovery"
    REVERSE_DNS = "reverse_dns"
    PORT_SCAN = "port_scan"
    SERVICE_ID = "service_id"
    PROBE = "probe"
    VULN = "vuln"
    DONE = "done"


@dataclass
class Task:
    type: TaskType
    target: Optional[str] = None
    port: Optional[int] = None
    reason: str = ""
    meta: dict = field(default_factory=dict)


class LLMClient:
    """Thin, optional LLM wrapper. Returns None when unavailable."""

    def __init__(self, config: Config):
        self.config = config
        self.enabled = config.ai_provider not in ("none", "", None)
        self._client = None
        if self.enabled and config.ai_provider == "anthropic":
            self._client = self._try_anthropic()
            self.enabled = self._client is not None

    def _try_anthropic(self):
        import os
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return None
        try:
            import anthropic  # type: ignore
            return anthropic.Anthropic()
        except Exception:
            return None

    def rank_tasks(self, candidates: list[Task], graph_summary: dict
                   ) -> Optional[list[int]]:
        """Ask the LLM to return a permutation of candidate indices.

        Returns None on any failure so the caller keeps deterministic order.
        Crucially, the LLM only reorders/drops from a pre-validated candidate
        list — it cannot add new targets or ports.
        """
        if not self.enabled or not self._client:
            return None
        prompt = self._build_prompt(candidates, graph_summary)
        try:
            msg = self._client.messages.create(
                model=self.config.ai_model,
                max_tokens=512,
                system=("You are a network-assessment planner. You may only "
                        "reorder or drop the provided candidate tasks by index. "
                        "Never invent targets or ports. Reply with a JSON array "
                        "of integer indices, most important first."),
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(getattr(b, "text", "") for b in msg.content)
            order = json.loads(text[text.find("["): text.rfind("]") + 1])
            valid = [i for i in order if isinstance(i, int) and 0 <= i < len(candidates)]
            return valid or None
        except Exception:
            return None

    def _build_prompt(self, candidates: list[Task], summary: dict) -> str:
        lines = ["Current assessment state:", json.dumps(summary, indent=2),
                 "", "Candidate next tasks (index: description):"]
        for i, t in enumerate(candidates):
            lines.append(f"{i}: {t.type.value} target={t.target} port={t.port} "
                         f"reason={t.reason}")
        lines.append("\nReturn a JSON array of indices, most valuable first. "
                     "Drop redundant tasks by omitting their index.")
        return "\n".join(lines)


class Orchestrator:
    def __init__(self, config: Config):
        self.config = config
        self.mode = config.mode
        self.llm = LLMClient(config) if config.mode in ("ai", "auto") else None

    def plan_probes(self, graph: AssetGraph, probes) -> list[Task]:
        """Given open ports, propose PROBE tasks (deterministic candidate set)."""
        candidates: list[Task] = []
        for host, port in graph.iter_open_ports():
            matched = [p.name for p in probes if p.matches(port)]
            if not matched:
                continue
            candidates.append(Task(
                type=TaskType.PROBE, target=host.ip, port=port.number,
                reason=f"service={port.service.name} probes={matched}",
                meta={"probes": matched},
            ))
        # AI reordering (optional, safe — only reorders validated candidates)
        if self.llm and self.llm.enabled and candidates:
            summary = self._summarize(graph)
            order = self.llm.rank_tasks(candidates, summary)
            if order:
                reordered = [candidates[i] for i in order]
                # keep any dropped tasks at the end (we never silently skip a
                # baseline probe — AI can only *reprioritise*, not remove work)
                seen = set(order)
                reordered += [candidates[i] for i in range(len(candidates))
                              if i not in seen]
                return reordered
        return candidates

    def next_after_probe(self, host: Host, port_num: int) -> list[Task]:
        """Decide follow-ups after probing a port (e.g. queue vuln check)."""
        return [Task(type=TaskType.VULN, target=host.ip, port=port_num,
                     reason="post-probe evidence available")]

    def _summarize(self, graph: AssetGraph) -> dict:
        return {
            "hosts": len(graph.hosts),
            "live": len(graph.live_hosts()),
            "open_ports": sum(len(h.open_ports()) for h in graph.hosts.values()),
            "http_services": len(graph.all_http_services()),
            "findings": len(graph.all_findings()),
        }
