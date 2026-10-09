"""External technology-fingerprinting adapters: WhatWeb and Wappalyzer.

These have far larger, better-maintained fingerprint databases than the built-in
signatures, so when one is installed we use it and merge its results into each
service's technology list. The built-in signatures remain the pure-Python
fallback, so there is no hard dependency.

Parsers are unit-testable without the binaries.
"""
from __future__ import annotations

import json

from ..models import Confidence, Technology
from .base import ToolAdapter
from .process import ProcResult, run, which

# WhatWeb "plugins" that aren't technologies — don't turn these into findings.
_WHATWEB_SKIP = {
    "Country", "IP", "Title", "Email", "Script", "HTML5", "UncommonHeaders",
    "Cookies", "HttpOnly", "Strict-Transport-Security", "X-Frame-Options",
    "X-XSS-Protection", "PasswordField", "Meta-Author", "Via-Proxy",
    "Content-Security-Policy", "Allow", "Frame", "RedirectLocation",
    "Access-Control-Allow-Methods", "X-Powered-By", "HTTPServer", "Object",
    "MetaGenerator", "Comments", "X-UA-Compatible", "probably",
}


class WhatWebAdapter(ToolAdapter):
    name = "whatweb"

    def available(self) -> bool:
        return which("whatweb") is not None

    def build_argv(self, targets_file: str, *, threads: int = 20) -> list[str]:
        return ["whatweb", "--quiet", "--no-errors", "--log-json=-",
                "-a", "3", "--max-threads", str(max(1, threads)),
                f"--input-file={targets_file}"]

    def parse_json(self, stdout: str) -> dict[str, list[Technology]]:
        """WhatWeb --log-json emits a JSON array (or NDJSON). Return
        {target_url: [Technology]}."""
        out: dict[str, list[Technology]] = {}
        objs = self._load(stdout)
        for obj in objs:
            target = obj.get("target") or ""
            plugins = obj.get("plugins") or {}
            techs: list[Technology] = []
            for name, info in plugins.items():
                if name in _WHATWEB_SKIP:
                    continue
                ver = ""
                if isinstance(info, dict):
                    vs = info.get("version") or []
                    if isinstance(vs, list) and vs:
                        ver = str(vs[0])
                    elif isinstance(vs, str):
                        ver = vs
                techs.append(Technology(
                    name=name, category="", version=ver,
                    evidence="whatweb", confidence=Confidence.HIGH))
            if target and techs:
                out[target] = techs
        return out

    @staticmethod
    def _load(stdout: str) -> list[dict]:
        stdout = (stdout or "").strip()
        if not stdout:
            return []
        try:
            data = json.loads(stdout)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
        objs = []
        for line in stdout.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    objs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return objs

    def scan(self, targets_file: str, *, threads: int = 20,
             run_timeout: float = 300.0
             ) -> tuple[dict[str, list[Technology]], ProcResult]:
        res = run(self.build_argv(targets_file, threads=threads), timeout=run_timeout)
        if res.not_found:
            return {}, res
        return self.parse_json(res.stdout), res


class WappalyzerAdapter(ToolAdapter):
    name = "wappalyzer"

    def available(self) -> bool:
        return which("wappalyzer") is not None

    def parse_json(self, stdout: str, url: str = "") -> dict[str, list[Technology]]:
        """Parse the wappalyzer CLI's {technologies:[{name,version,categories}]}."""
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            return {}
        techs = []
        for t in data.get("technologies", []) or []:
            cats = t.get("categories") or []
            cat = (cats[0].get("name") if cats and isinstance(cats[0], dict) else "")
            techs.append(Technology(
                name=t.get("name", ""), category=cat or "",
                version=t.get("version") or "", evidence="wappalyzer",
                confidence=Confidence.HIGH))
        techs = [t for t in techs if t.name]
        return {url or data.get("urls", {}) and next(iter(data["urls"]), url) or url:
                techs} if techs else {}

    def scan(self, url: str, *, run_timeout: float = 120.0
             ) -> tuple[dict[str, list[Technology]], ProcResult]:
        res = run(["wappalyzer", url], timeout=run_timeout)
        if res.not_found:
            return {}, res
        return self.parse_json(res.stdout, url), res


def choose(tech_tool: str):
    """Return (adapter, name) for the configured tech tool, or (None, '')."""
    tech_tool = (tech_tool or "auto").lower()
    ww, wap = WhatWebAdapter(), WappalyzerAdapter()
    if tech_tool == "whatweb":
        return ww, "whatweb"
    if tech_tool == "wappalyzer":
        return wap, "wappalyzer"
    if tech_tool == "builtin":
        return None, ""
    # auto: prefer whatweb, then wappalyzer
    if ww.available():
        return ww, "whatweb"
    if wap.available():
        return wap, "wappalyzer"
    return None, ""
