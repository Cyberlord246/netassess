"""Validator plugin interface and shared value types.

A ``Validator`` inspects one finding (with its host/port context) and, if it can
say something stronger about it, returns a ``ValidationResult``. Validators must
be non-destructive: read-only checks over data already collected, or safe live
probes. The engine picks the strongest result across all applicable validators.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import Confidence, Finding, Host, Port, ValidationState

# how strong a state is, used by the engine to pick the best result and by
# reports to order findings. Mirrors findings_view.VALIDATION_RANK.
STATE_RANK = {
    ValidationState.CONFIRMED: 4,
    ValidationState.NEEDS_VALIDATION: 3,
    ValidationState.POTENTIAL: 2,
    ValidationState.OBSERVED: 1,
    ValidationState.INFO: 1,
    ValidationState.FALSE_POSITIVE: 0,
}

# tie-breaker when two validators land on the same state: more authoritative
# methods win. "poc"/"credentialed" outrank a paper applicability check.
METHOD_RANK = {
    "credentialed": 4,
    "poc": 3,
    "non-destructive": 2,
    "config": 2,
    "applicability": 1,
    "": 0,
}


@dataclass
class ValidationResult:
    """The outcome of running one validator against one finding."""
    state: ValidationState
    method: str                       # applicability | non-destructive | config | credentialed | poc
    evidence: str = ""                # appended to the finding's evidence
    reasoning: str = ""               # why we reached this conclusion (validation rationale)
    next_step: str = ""               # recommended next action to raise assurance
    confidence: Optional[Confidence] = None   # optional confidence adjustment

    def rank(self) -> tuple[int, int]:
        return (STATE_RANK.get(self.state, 0), METHOD_RANK.get(self.method, 0))


class Validator:
    """Base class for validators. Subclasses override ``applies`` + ``validate``."""
    name = "validator"

    def applies(self, finding: Finding, host: Host, port: Optional[Port]) -> bool:
        return False

    def validate(self, finding: Finding, host: Host,
                 port: Optional[Port]) -> Optional[ValidationResult]:
        return None


# --------------------------------------------------------------------------- #
# Report-facing label: map (state, method) -> the vocabulary the operator wants
# --------------------------------------------------------------------------- #
def display_state(validation: ValidationState, method: str = "",
                  category: str = "") -> str:
    """Human label for a finding's assurance level.

    Maps the internal ``ValidationState`` (+ how it was validated) onto the
    operator-facing vocabulary: Detected / Candidate / Validated / Credentialed /
    PoC Validated / Unconfirmed.
    """
    if validation == ValidationState.CONFIRMED:
        if method == "credentialed":
            return "Credentialed"
        if method == "poc":
            return "PoC Validated"
        return "Validated"
    if validation == ValidationState.NEEDS_VALIDATION:
        return "Candidate" if category == "known-vulnerability" else "Needs validation"
    if validation == ValidationState.POTENTIAL:
        return "Unconfirmed"
    if validation == ValidationState.OBSERVED:
        return "Detected"
    if validation == ValidationState.FALSE_POSITIVE:
        return "False positive"
    return "Info"
