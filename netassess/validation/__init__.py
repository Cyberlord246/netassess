"""Validation & Assessment layer.

Sits between CVE/KEV-EPSS enrichment and role/anomaly analysis. Its job is to
move findings along the lifecycle from *detected* / *candidate* toward
*validated* — using only safe, non-destructive evidence — so the report can
distinguish "the version looks affected" from "we confirmed it."

Design principles:
  * Reuse the existing ``ValidationState`` lifecycle; do not invent a parallel one.
  * Every validator is a small, self-contained plugin (see ``base.Validator``),
    so new checks (config validation, credentialed, safe PoC) drop in without
    touching the engine.
  * Nothing here is destructive. Active checks are read-only; anything more
    intrusive than that is opt-in and gated behind explicit config flags.
"""
from __future__ import annotations

from .base import Validator, ValidationResult, display_state
from .engine import ValidationEngine

__all__ = ["Validator", "ValidationResult", "ValidationEngine", "display_state"]
