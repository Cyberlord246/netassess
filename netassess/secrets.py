"""Secret detection in fetched text (JavaScript bundles, inline script, config).

High-precision patterns for credentials and tokens that regularly leak in
client-side JS. Each pattern has a confidence: HIGH patterns are structurally
unambiguous (AWS key id, Google API key, private-key header, JWT, provider
tokens); the single generic ``key = "…"`` pattern is MEDIUM and FP-prone, so it
is reported as a lead, not a confirmation.

Non-destructive: this only *reads* already-discovered, in-scope content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import (
    Confidence, Finding, SEVERITY_ORDER, Severity, ValidationState,
)


@dataclass(frozen=True)
class _Pat:
    name: str
    regex: "re.Pattern"
    severity: Severity
    confidence: Confidence


# High-precision, well-known credential shapes. Ordered most→least specific.
_PATTERNS: list[_Pat] = [
    _Pat("Private key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL, Confidence.HIGH),
    _Pat("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
         Severity.HIGH, Confidence.HIGH),
    _Pat("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
         Severity.HIGH, Confidence.HIGH),
    _Pat("GitHub token", re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{40,}\b"),
        Severity.HIGH, Confidence.HIGH),
    _Pat("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
         Severity.HIGH, Confidence.HIGH),
    _Pat("Slack webhook", re.compile(
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}"),
        Severity.MEDIUM, Confidence.HIGH),
    _Pat("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
         Severity.CRITICAL, Confidence.HIGH),
    _Pat("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
         Severity.HIGH, Confidence.MEDIUM),
    _Pat("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b"),
         Severity.HIGH, Confidence.HIGH),
    _Pat("JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.MEDIUM, Confidence.HIGH),
    _Pat("Firebase/GCM server key", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
         Severity.HIGH, Confidence.HIGH),
    # generic, FP-prone -> MEDIUM severity + MEDIUM confidence (a lead)
    _Pat("Hardcoded secret assignment", re.compile(
        r"""(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)"""
        r"""["'\s]{0,4}[:=]["'\s]{0,4}["']([A-Za-z0-9\-_/+=.]{16,64})["']"""),
        Severity.MEDIUM, Confidence.MEDIUM),
]

# Values that look like secrets but are placeholders — suppress these.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{6,}|0{6,}|1{6,}|your[_-]?|example|changeme|placeholder|dummy|test|"
    r"<[^>]+>|\$\{|%[0-9a-f]{2}|sample|redacted|xxxx)")


def _redact(s: str) -> str:
    """Show enough to recognise the hit without printing the full secret."""
    s = s.strip()
    if len(s) <= 10:
        return s[:3] + "…"
    return f"{s[:6]}…{s[-4:]} (len {len(s)})"


def scan_text(text: str, source: str) -> list[dict]:
    """Return raw secret hits: {type, snippet, severity, confidence, source}."""
    if not text:
        return []
    hits: list[dict] = []
    seen: set[tuple] = set()
    for pat in _PATTERNS:
        for m in pat.regex.finditer(text):
            raw = m.group(1) if (pat.regex.groups and m.lastindex) else m.group(0)
            if pat.name == "Hardcoded secret assignment" and _PLACEHOLDER.match(raw):
                continue
            key = (pat.name, raw)
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "type": pat.name, "snippet": _redact(raw),
                "severity": pat.severity, "confidence": pat.confidence,
                "source": source,
            })
    return hits


def findings_for(asset: str, hits: list[dict]) -> list[Finding]:
    """Group raw hits (possibly across several JS files) into findings per type."""
    by_type: dict[str, list[dict]] = {}
    for h in hits:
        by_type.setdefault(h["type"], []).append(h)
    out: list[Finding] = []
    for typ, group in by_type.items():
        sev = max((g["severity"] for g in group), key=lambda s: SEVERITY_ORDER[s])
        conf = group[0]["confidence"]
        srcs = sorted({g["source"] for g in group})
        samples = "; ".join(f"{g['snippet']} in {g['source']}" for g in group[:5])
        out.append(Finding(
            title=f"Possible secret in client-side content: {typ}",
            asset=asset,
            evidence=f"{len(group)} match(es). Examples: {samples}"[:1800],
            description=f"A value matching the '{typ}' pattern was found in "
                        f"JavaScript/served content from {', '.join(srcs[:3])}. "
                        "Secrets embedded in client-side code are retrievable by "
                        "anyone who loads the page.",
            why_it_matters="Leaked keys/tokens can grant direct access to the "
                           "associated service or data.",
            severity=sev, confidence=conf,
            impact="Credential exposure; possible account/service compromise.",
            remediation="Remove the secret from client-side code, rotate it, and "
                        "move it server-side; restrict scope/permissions.",
            validation=ValidationState.NEEDS_VALIDATION,
            source="secrets-scan", category="secret-exposure",
        ))
    return out
