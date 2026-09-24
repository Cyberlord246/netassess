"""Safe external-process runner.

External tools (nmap, etc.) are invoked only through this helper, which:
  * never uses shell=True (argument lists only, no shell injection surface),
  * enforces a hard timeout,
  * returns structured results instead of raising on non-zero exit,
  * reports "not found" cleanly so adapters can degrade gracefully.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProcResult:
    ok: bool
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    not_found: bool = False
    error: str = ""


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def run(argv: list[str], timeout: float = 120.0,
        input_text: Optional[str] = None) -> ProcResult:
    if not argv:
        return ProcResult(False, None, "", "", error="empty argv")
    if which(argv[0]) is None:
        return ProcResult(False, None, "", "", not_found=True,
                          error=f"{argv[0]} not found on PATH")
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        return ProcResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except subprocess.TimeoutExpired as exc:
        return ProcResult(False, None, exc.stdout or "", exc.stderr or "",
                          timed_out=True, error="timeout")
    except OSError as exc:
        return ProcResult(False, None, "", "", error=str(exc))
