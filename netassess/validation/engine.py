"""Validation engine — runs applicable validators over every finding.

For each finding it gathers the results of all applicable validators, keeps the
strongest (by state rank, then method authority), and applies it back to the
finding: updating the validation state, recording *how* it was validated, and
enriching evidence / reasoning / recommended next step. Purely orchestration —
the actual checks live in the validators.
"""
from __future__ import annotations

from typing import Optional

from ..models import Finding, Host, Port, ValidationState
from .base import ValidationResult, Validator
from .validators import (
    ApplicabilityValidator, CredentialedValidator, NonDestructiveValidator,
)


class ValidationEngine:
    def __init__(self, validators: Optional[list[Validator]] = None):
        self.validators = validators if validators is not None else []

    @classmethod
    def from_config(cls, config) -> "ValidationEngine":
        """Assemble the default validator chain, honouring opt-in config flags."""
        validators: list[Validator] = [
            ApplicabilityValidator(),
            NonDestructiveValidator(),
        ]
        cred = CredentialedValidator.from_config(config)
        if cred is not None:
            validators.append(cred)
        return cls(validators)

    # -- per-finding ------------------------------------------------------ #
    def _port_for(self, host: Host, finding: Finding) -> Optional[Port]:
        _, _, port_s = finding.asset.partition(":")
        try:
            return host.ports.get(int(port_s))
        except (ValueError, TypeError):
            return None

    def validate_finding(self, finding: Finding, host: Host) -> bool:
        port = self._port_for(host, finding)
        best: Optional[ValidationResult] = None
        for v in self.validators:
            try:
                if not v.applies(finding, host, port):
                    continue
                result = v.validate(finding, host, port)
            except Exception:            # a validator bug must not kill the run
                continue
            if result is None:
                continue
            if best is None or result.rank() > best.rank():
                best = result
        if best is None:
            return False
        self._apply(finding, best)
        return True

    def _apply(self, finding: Finding, r: ValidationResult) -> None:
        finding.validation = r.state
        finding.validation_method = r.method
        if r.confidence is not None:
            finding.confidence = r.confidence
        if r.evidence:
            finding.evidence = (f"{finding.evidence} | {r.evidence}"
                                if finding.evidence else r.evidence)
        if r.reasoning:
            # keep detection rationale, append the validation rationale
            finding.why_it_matters = (f"{finding.why_it_matters} "
                                      f"[validation] {r.reasoning}").strip()
        if r.next_step:
            finding.remediation = (f"{r.next_step} {finding.remediation}".strip()
                                   if finding.remediation else r.next_step)

    # -- whole graph ------------------------------------------------------ #
    def validate_graph(self, graph) -> dict:
        counts = {"validated": 0, "credentialed": 0, "downgraded": 0, "touched": 0}
        for host in graph.hosts.values():
            for f in host.findings:
                before_state = f.validation
                if not self.validate_finding(f, host):
                    continue
                counts["touched"] += 1
                if f.validation == ValidationState.CONFIRMED:
                    counts["validated"] += 1
                    if f.validation_method == "credentialed":
                        counts["credentialed"] += 1
                elif (before_state == ValidationState.NEEDS_VALIDATION
                      and f.validation == ValidationState.POTENTIAL):
                    counts["downgraded"] += 1
        return counts
