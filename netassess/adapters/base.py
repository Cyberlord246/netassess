"""Adapter interface.

Every external-tool integration implements this interface and returns
*structured* data (normalised into the platform's models), never raw terminal
output. Each adapter also reports availability so the engine can pick a
pure-Python fallback when a tool is missing.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class ToolAdapter(ABC):
    name: str = "adapter"

    @abstractmethod
    def available(self) -> bool:
        """True if the underlying tool is installed and usable."""

    def describe(self) -> dict:
        return {"name": self.name, "available": self.available()}
