"""Tests for the Validation & Assessment layer.

Covers: applicability grading (strong candidate kept, weak candidate demoted),
non-destructive annotation of already-confirmed findings, the engine's whole-graph
pass, the credentialed validator's opt-in gating, and the display-label mapping.

Run: python -m netassess.tests.test_validation
"""
from __future__ import annotations

from ..config import Config
from ..models import (
    Confidence, Finding, Host, Port, PortState, Service, Severity, ValidationState,
)
from ..validation import ValidationEngine, display_state
from ..validation.validators import (
    ApplicabilityValidator, CredentialedValidator, NonDestructiveValidator,
)


def _host_with_port(number=443, conf=Confidence.HIGH, name="nginx", version="1.18.0"):
    host = Host(ip="192.0.2.10")
    svc = Service(name=name, product=name, version=version, confidence=conf)
    host.ports[number] = Port(number=number, state=PortState.OPEN, service=svc)
    return host


def _cve_finding(asset="192.0.2.10:443", evidence="service detection: nginx 1.18.0; "
                 "matched version 1.18.0"):
    return Finding(
        title="CVE-2021-23017: nginx", asset=asset, evidence=evidence,
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        validation=ValidationState.NEEDS_VALIDATION,
        source="cve-kb", category="known-vulnerability",
    )


def test_applicability_keeps_well_evidenced_candidate():
    host = _host_with_port(conf=Confidence.HIGH)
    f = _cve_finding()
    v = ApplicabilityValidator()
    assert v.applies(f, host, host.ports[443])
    r = v.validate(f, host, host.ports[443])
    assert r.state == ValidationState.NEEDS_VALIDATION      # still a Candidate
    assert r.method == "applicability"
    assert "affected-range applies" in r.reasoning


def test_applicability_demotes_weak_candidate():
    host = _host_with_port(conf=Confidence.LOW)
    # inferred version, no authoritative banner phrase
    f = _cve_finding(evidence="technology: nginx/1.18.0; matched version 1.18.0")
    r = ApplicabilityValidator().validate(f, host, host.ports[443])
    assert r.state == ValidationState.POTENTIAL            # Unconfirmed
    assert r.confidence == Confidence.LOW


def test_nondestructive_tags_confirmed_prober_finding():
    host = Host(ip="192.0.2.20")
    f = Finding(title="SMTP open relay", asset="192.0.2.20:25",
                validation=ValidationState.CONFIRMED, source="smtp-probe",
                category="misconfiguration")
    v = NonDestructiveValidator()
    assert v.applies(f, host, None)
    r = v.validate(f, host, None)
    assert r.state == ValidationState.CONFIRMED and r.method == "non-destructive"


def test_nondestructive_ignores_non_active_sources():
    host = Host(ip="192.0.2.20")
    f = Finding(title="X", asset="192.0.2.20:80",
                validation=ValidationState.CONFIRMED, source="cve-kb")
    assert not NonDestructiveValidator().applies(f, host, None)


def test_engine_applies_strongest_and_updates_finding():
    host = _host_with_port(conf=Confidence.LOW)
    f = _cve_finding(evidence="technology: nginx/1.18.0; matched version 1.18.0")
    host.findings.append(f)

    class _Graph:
        hosts = {"192.0.2.10": host}
    engine = ValidationEngine([ApplicabilityValidator(), NonDestructiveValidator()])
    counts = engine.validate_graph(_Graph())
    assert counts["touched"] == 1 and counts["downgraded"] == 1
    assert f.validation == ValidationState.POTENTIAL
    assert f.validation_method == "applicability"
    assert "[validation]" in f.why_it_matters       # rationale appended
    assert f.remediation                            # next step populated


def test_engine_picks_higher_rank_result():
    # two validators applicable; the stronger state (CONFIRMED) must win
    host = Host(ip="192.0.2.30")
    port = host.ports.setdefault(443, Port(number=443))
    f = Finding(title="T", asset="192.0.2.30:443",
                validation=ValidationState.NEEDS_VALIDATION,
                category="known-vulnerability", source="cve-kb")

    from ..validation.base import ValidationResult, Validator

    class _Weak(Validator):
        name = "applicability"
        def applies(self, *a): return True
        def validate(self, *a):
            return ValidationResult(ValidationState.POTENTIAL, "applicability")

    class _Strong(Validator):
        name = "credentialed"
        def applies(self, *a): return True
        def validate(self, *a):
            return ValidationResult(ValidationState.CONFIRMED, "credentialed")

    ValidationEngine([_Weak(), _Strong()]).validate_finding(f, host)
    assert f.validation == ValidationState.CONFIRMED
    assert f.validation_method == "credentialed"


def test_credentialed_is_opt_in_off_by_default():
    cfg = Config(targets=["192.0.2.10/32"])
    assert cfg.validation_credentialed is False
    assert CredentialedValidator.from_config(cfg) is None


def test_credentialed_needs_existing_auth_file():
    cfg = Config(targets=["192.0.2.10/32"])
    cfg.validation_credentialed = True
    cfg.auth_config = "/nonexistent/auth.json"
    assert CredentialedValidator.from_config(cfg) is None


def test_engine_from_config_default_chain():
    cfg = Config(targets=["192.0.2.10/32"])
    engine = ValidationEngine.from_config(cfg)
    names = {v.name for v in engine.validators}
    assert names == {"applicability", "non-destructive"}   # credentialed off


def test_display_state_labels():
    assert display_state(ValidationState.CONFIRMED, "credentialed") == "Credentialed"
    assert display_state(ValidationState.CONFIRMED, "poc") == "PoC Validated"
    assert display_state(ValidationState.CONFIRMED, "non-destructive") == "Validated"
    assert display_state(ValidationState.NEEDS_VALIDATION, "",
                         "known-vulnerability") == "Candidate"
    assert display_state(ValidationState.POTENTIAL) == "Unconfirmed"
    assert display_state(ValidationState.OBSERVED) == "Detected"


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
