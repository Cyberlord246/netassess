"""Live assessment progress reporting.

Prints an up-front plan of the stages that will run, then frames each stage with
a RUNNING/DONE marker and an ``[k/N]`` position, and shows a live
"tested X/Y — Z remaining" counter for the stages that iterate over hosts or
services. Output is ASCII-only so it renders on legacy Windows consoles (cp1252)
as well as Linux/macOS terminals.
"""
from __future__ import annotations

import sys
import threading


class Progress:
    def __init__(self, out=None, enabled: bool = True):
        self.out = out if out is not None else sys.stdout
        self.enabled = enabled
        self.labels: list[str] = []
        self.total = 0
        self._done_count = 0
        self._lock = threading.Lock()
        self._line_open = False        # a \r counter line is currently on screen

    # -- plan ------------------------------------------------------------- #
    def set_plan(self, labels: list[str]) -> None:
        self.labels = list(labels)
        self.total = len(self.labels)
        if not self.enabled:
            return
        self._w("\n" + "=" * 60 + "\n")
        self._w(f" Assessment plan - {self.total} stage(s)\n")
        self._w("=" * 60 + "\n")
        for i, label in enumerate(self.labels, 1):
            self._w(f"   [ ] {i:>2}/{self.total}  {label}\n")
        self._w("-" * 60 + "\n")

    # -- per-stage -------------------------------------------------------- #
    def stage_start(self, index: int, label: str) -> None:
        if not self.enabled:
            return
        self._w(f"\n[{index}/{self.total}] {label} ... RUNNING\n")

    def stage_done(self, index: int, label: str, summary: str = "") -> None:
        if not self.enabled:
            return
        self._close_line()
        extra = f" ({summary})" if summary else ""
        self._w(f"[{index}/{self.total}] {label} ... DONE{extra}\n")

    def stage_skipped(self, index: int, label: str, why: str = "") -> None:
        if not self.enabled:
            return
        extra = f" ({why})" if why else ""
        self._w(f"[{index}/{self.total}] {label} ... SKIPPED{extra}\n")

    def stage_failed(self, index: int, label: str, error: str = "") -> None:
        """Mark a stage FAILED so a crash is reported, never silently swallowed."""
        if not self.enabled:
            return
        self._close_line()
        extra = f": {error}" if error else ""
        self._w(f"[{index}/{self.total}] {label} ... FAILED{extra}\n")

    # -- per-item counter (thread-safe) ----------------------------------- #
    def items(self, done: int, total: int, unit: str = "items") -> None:
        """Render an in-place 'done/total - remaining' counter for one stage."""
        if not self.enabled or total <= 0:
            return
        remaining = max(0, total - done)
        pct = int(done * 100 / total) if total else 100
        with self._lock:
            self._w(f"\r    {unit}: {done}/{total} ({pct}%) - "
                    f"{remaining} remaining      ")
            self._line_open = True
            if done >= total:
                self._w("\n")
                self._line_open = False

    def bump(self, total: int, unit: str = "items") -> None:
        """Increment the shared done-counter by one and render. Use inside a
        concurrent stage where each worker reports one completed unit."""
        with self._lock:
            self._done_count += 1
            done = self._done_count
        self.items(done, total, unit)

    def reset_counter(self) -> None:
        with self._lock:
            self._done_count = 0

    # -- internals -------------------------------------------------------- #
    def _close_line(self) -> None:
        if self._line_open:
            self._w("\n")
            self._line_open = False

    def _w(self, s: str) -> None:
        try:
            self.out.write(s)
            self.out.flush()
        except Exception:
            pass
