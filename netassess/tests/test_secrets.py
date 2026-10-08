"""Tests for secret detection in JS/served content.

Run: python -m netassess.tests.test_secrets
"""
from __future__ import annotations

from ..models import Confidence, Severity
from ..secrets import scan_text, findings_for


def _types(hits):
    return {h["type"] for h in hits}


def test_detects_high_precision_secrets():
    google = "AIza" + "a" * 35                 # AIza + exactly 35 chars
    github = "ghp_" + "a" * 36                  # ghp_ + exactly 36 chars
    text = f"""
        var awsKey = "AKIAIOSFODNN7EXAMPLE";
        const g = "{google}";
        token = '{github}';
        const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456";
    """
    hits = scan_text(text, "http://h/app.js")
    t = _types(hits)
    assert "AWS access key id" in t
    assert "Google API key" in t
    assert "GitHub token" in t
    assert "JWT" in t
    # the redacted snippet must not contain the full secret
    assert all("AKIAIOSFODNN7EXAMPLE" != h["snippet"] for h in hits)


def test_private_key_is_critical():
    hits = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIabc", "http://h/leak.js")
    assert hits and hits[0]["type"] == "Private key"
    assert hits[0]["severity"] == Severity.CRITICAL


def test_generic_placeholder_suppressed():
    # placeholder-looking values must not fire the generic rule
    text = 'api_key = "YOUR_API_KEY_HERE_xxxx"; password = "changeme123456789"'
    hits = [h for h in scan_text(text, "http://h/x.js")
            if h["type"] == "Hardcoded secret assignment"]
    assert hits == []


def test_generic_real_assignment_detected_as_lead():
    text = 'const apiKey = "a1b2c3d4e5f6g7h8i9j0k1l2"'
    hits = [h for h in scan_text(text, "http://h/x.js")
            if h["type"] == "Hardcoded secret assignment"]
    assert hits and hits[0]["confidence"] == Confidence.MEDIUM


def test_findings_grouped_by_type():
    hits = (scan_text('k="AKIAIOSFODNN7EXAMPLE"', "a.js")
            + scan_text('k2="AKIA1234567890ABCDEF"', "b.js"))
    fs = findings_for("10.0.0.5:443", hits)
    aws = [f for f in fs if "AWS" in f.title]
    assert len(aws) == 1 and "2 match" in aws[0].evidence
    assert aws[0].category == "secret-exposure"


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
