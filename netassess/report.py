"""Report generator.

Produces a comprehensive Markdown report (and a machine-readable JSON export)
covering every section required by the assessment brief. Findings are grouped by
validation state so confirmed issues are never conflated with unvalidated hints.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

from .correlation import CorrelationEngine
from .findings_view import build_view
from .models import (
    Finding, HostStatus, SEVERITY_ORDER, Severity, ValidationState,
)
from .prioritize import PriorityEngine
from .scope import ScopeEngine
from .state import AssetGraph

# Media/static extensions excluded from the human report (images, css, fonts,
# audio/video). JS/map are also treated as assets for discovered-paths, but kept
# for endpoint/JS references (the JS refs are the point of that stage).
_MEDIA_EXT = {
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico", "cur", "css",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "m4v", "m4a", "mp3", "wav",
    "ogg", "webm", "avi", "mov", "flv", "mpg", "mpeg", "swf",
}


def _ext_of(s: str) -> str:
    last = (s or "").split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def _visible_paths(svc) -> list[dict]:
    """Discovered content-discovery paths minus media/static assets (incl. js/css)."""
    from .content_discovery import _is_static
    return [p for p in (svc.discovered_paths or []) if not _is_static(p)]


def _visible_endpoints(svc) -> list[str]:
    """Endpoint/JS references minus pure media (images/css/fonts/av); keep .js."""
    return [e for e in (getattr(svc, "endpoints", None) or [])
            if _ext_of(e) not in _MEDIA_EXT]


class ReportGenerator:
    def __init__(self, graph: AssetGraph, scope: ScopeEngine, config):
        self.graph = graph
        self.scope = scope
        self.config = config

    # -- public ----------------------------------------------------------- #
    def write(self, out_dir: str) -> dict:
        os.makedirs(out_dir, exist_ok=True)
        md = self.render_markdown()
        md_path = os.path.join(out_dir, "report.md")
        json_path = os.path.join(out_dir, "report.json")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(self._json_export(), fh, indent=2)
        paths = {"markdown": md_path, "json": json_path}
        if getattr(self.config, "html_report", True):
            from .report_html import HTMLReport
            paths["html"] = HTMLReport(self.graph, self.scope, self.config).write(out_dir)
        if getattr(self.config, "csv_report", False):
            from .exporters import to_csv
            p = os.path.join(out_dir, "report.csv")
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(to_csv(self.graph))
            paths["csv"] = p
        if getattr(self.config, "sarif_report", False):
            from .exporters import to_sarif
            p = os.path.join(out_dir, "report.sarif")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(to_sarif(self.graph))
            paths["sarif"] = p
        return paths

    # -- rendering -------------------------------------------------------- #
    def render_markdown(self) -> str:
        g = self.graph
        s: list[str] = []
        w = s.append

        view = build_view(
            g,
            min_severity=getattr(self.config, "report_min_severity", "info"),
            aggregate=getattr(self.config, "report_aggregate", True),
            suppress_titles=getattr(self.config, "report_suppress_titles", None),
        )
        by_val = view.by_validation

        w("# Network Attack-Surface Assessment Report\n")
        w(self._executive_summary(view))

        # scope note
        w("\n## Scope & Authorization\n")
        summ = self.scope.summary()
        w(f"- **Authorized networks:** {', '.join(summ['included_networks']) or '(none)'}")
        w(f"- **Excluded networks:** {', '.join(summ['excluded_networks']) or '(none)'}")
        w(f"- **Forbidden ports:** {summ['forbidden_ports'] or '(none)'}")
        w(f"- **Authorized operations executed:** {summ['authorized_ops']}")
        w(f"- **Operations denied by scope engine:** {summ['denied_ops']}")
        w("- Only explicitly authorized targets were assessed. Hosts observed "
          "in redirects or DNS were **not** auto-added to scope.\n")

        w(self._attack_surface_summary())
        w(self._live_hosts())
        w(self._reverse_dns())
        w(self._domains_section())
        w(self._ports_and_services())
        w(self._service_versions())
        w(self._http_section())
        w(self._content_section())
        w(self._tls_section())
        w(self._technologies())
        w(self._correlation())
        w(self._prioritization())

        w(self._risk_ranking(view))

        # findings by validation state (severity-filtered + aggregated)
        note = (f"\n_{view.suppressed} low-signal finding(s) hidden from this report "
                f"(suppressed titles, or below severity **{view.threshold.value}**). "
                "Full detail is in report.json._\n"
                if view.suppressed else "")

        w("\n## Confirmed Findings\n" + note)
        w(self._render_findings(by_val.get(ValidationState.CONFIRMED, [])))

        w("\n## Potential Security Issues\n")
        pot = by_val.get(ValidationState.POTENTIAL, []) + \
            by_val.get(ValidationState.OBSERVED, [])
        pot.sort(key=lambda a: SEVERITY_ORDER[a.severity], reverse=True)
        w(self._render_findings(pot))

        w("\n## Unvalidated Findings\n")
        w(self._render_findings(by_val.get(ValidationState.NEEDS_VALIDATION, [])))

        w("\n## False Positives\n")
        fp = by_val.get(ValidationState.FALSE_POSITIVE, [])
        w(self._render_findings(fp) if fp else "_None recorded._\n")

        w(self._assessment_gaps())
        w(self._next_steps())
        return "\n".join(s) + "\n"

    # -- sections --------------------------------------------------------- #
    def _executive_summary(self, view) -> str:
        g = self.graph
        sc = view.severity_counts
        live = len(g.live_hosts())
        open_ports = sum(len(h.open_ports()) for h in g.hosts.values())
        http = len(g.all_http_services())
        lines = [
            "\n## Executive Summary\n",
            f"- **Hosts assessed:** {len(g.hosts)}  "
            f"(**live:** {live})",
            f"- **Open ports discovered:** {open_ports}",
            f"- **HTTP/HTTPS services:** {http}",
            f"- **Reported findings:** {view.kept} "
            f"(severity ≥ {view.threshold.value}; {view.suppressed} lower "
            f"suppressed)",
            f"  - Critical: {sc.get('critical',0)} · "
            f"High: {sc.get('high',0)} · "
            f"Medium: {sc.get('medium',0)} · "
            f"Low: {sc.get('low',0)} · "
            f"Info: {sc.get('info',0)}",
            self._kev_summary_line(view),
            "\nThis report inventories the externally reachable attack surface of "
            "the authorized targets and highlights safe, non-destructively "
            "detected security issues. Version-derived issues are marked for "
            "validation and should be confirmed before remediation prioritisation.",
        ]
        return "\n".join(lines)

    def _kev_summary_line(self, view) -> str:
        kev = sum(1 for aggs in view.by_validation.values()
                  for a in aggs if a.kev)
        if kev:
            return (f"- **(!) Actively exploited (CISA KEV): {kev}** - prioritise "
                    "these first")
        return "- Actively exploited (CISA KEV): 0"

    def _attack_surface_summary(self) -> str:
        g = self.graph
        svc_counter = Counter()
        for _h, p in g.iter_open_ports():
            svc_counter[p.service.name] += 1
        lines = ["\n## Attack Surface Summary\n",
                 "| Service | Instances |", "|---|---|"]
        for name, n in svc_counter.most_common():
            lines.append(f"| {name} | {n} |")
        if len(lines) == 3:
            lines.append("| _(none)_ | 0 |")
        return "\n".join(lines)

    def _live_hosts(self) -> str:
        lines = ["\n## Live Hosts\n", "| IP | Status | Method | Latency (ms) |",
                 "|---|---|---|---|"]
        for ip in sorted(self.graph.hosts):
            h = self.graph.hosts[ip]
            lines.append(f"| {h.ip} | {h.status.value} | {h.discovery_method} | "
                         f"{h.latency_ms if h.latency_ms is not None else '-'} |")
        return "\n".join(lines)

    def _reverse_dns(self) -> str:
        lines = ["\n## Reverse DNS\n", "| IP | Hostnames |", "|---|---|"]
        any_row = False
        for ip in sorted(self.graph.hosts):
            h = self.graph.hosts[ip]
            if h.hostnames:
                any_row = True
                lines.append(f"| {h.ip} | {', '.join(h.hostnames)} |")
        if not any_row:
            lines.append("| _(no PTR records resolved)_ | - |")
        lines.append("\n_Hostnames are evidence only and do not prove ownership._")
        return "\n".join(lines)

    def _domains_section(self) -> str:
        from .domains import all_domains
        rows = all_domains(self.graph)
        lines = ["\n## Discovered Domains\n",
                 "All hostnames observed across every source (reverse DNS, TLS "
                 "certificate SAN/CN, HTTP redirects, virtual hosts).\n",
                 "| Domain | Seen on | Source(s) |", "|---|---|---|"]
        for name, sources, ips in rows:
            lines.append(f"| `{name}` | {', '.join(ips)} | {', '.join(sources)} |")
        if not rows:
            lines.append("| _(no hostnames discovered)_ | - | - |")
        return "\n".join(lines)

    def _ports_and_services(self) -> str:
        lines = ["\n## Open Ports & Services\n"]
        for ip in sorted(self.graph.hosts):
            h = self.graph.hosts[ip]
            ports = h.open_ports()
            if not ports:
                continue
            from .risk import host_risk
            role = f" — _role: {h.primary_role}_" if h.primary_role and h.primary_role != "unknown" else ""
            hr, hband = host_risk(h)
            risk_str = f" — _risk: {hr}/100 ({hband})_" if hr else ""
            lines.append(f"\n### {h.ip}"
                         + (f" ({h.hostnames[0]})" if h.hostnames else "")
                         + role + risk_str)
            for p in ports:
                svc = p.service
                extra = f" — {svc.product} {svc.version}".rstrip() if svc.product else ""
                lines.append(f"- `{p.number}/{p.protocol}` → **{svc.name}**"
                             f"{extra}  _(confidence: {svc.confidence.value})_")
            for p in sorted(h.udp_ports.values(), key=lambda x: x.number):
                if p.state.value not in ("open", "open|filtered"):
                    continue
                svc = p.service
                extra = f" — {svc.product}" if svc.product else ""
                lines.append(f"- `{p.number}/udp` → **{svc.name}**{extra}  "
                             f"_({p.state.value})_")
        if len(lines) == 1:
            lines.append("_No open ports discovered._")
        return "\n".join(lines)

    def _service_versions(self) -> str:
        lines = ["\n## Service Versions\n",
                 "| Asset | Service | Product | Version | Confidence | Evidence |",
                 "|---|---|---|---|---|---|"]
        rows = 0
        for h, p in self.graph.iter_open_ports():
            svc = p.service
            if svc.product or svc.version:
                rows += 1
                lines.append(f"| {h.ip}:{p.number} | {svc.name} | {svc.product} | "
                             f"{svc.version} | {svc.confidence.value} | {svc.evidence or svc.banner[:40]} |")
        if not rows:
            lines.append("| _(no version data collected)_ | | | | | |")
        return "\n".join(lines)

    def _http_section(self) -> str:
        lines = ["\n## HTTP / HTTPS Services\n"]
        services = self.graph.all_http_services()
        if not services:
            lines.append("_No HTTP/HTTPS services identified._")
            return "\n".join(lines)
        for h, svc in services:
            lines.append(f"\n### {svc.url}")
            lines.append(f"- **IP/Port:** {svc.ip}:{svc.port} ({svc.scheme})")
            lines.append(f"- **Status:** {svc.status}")
            lines.append(f"- **Title:** {svc.title or '-'}")
            lines.append(f"- **Server:** {svc.server or '-'}")
            lines.append(f"- **Content-Type:** {svc.content_type or '-'}")
            lines.append(f"- **Content-Length:** {svc.content_length}")
            if svc.redirect_chain:
                lines.append(f"- **Redirects:** {' | '.join(svc.redirect_chain)}")
            missing = [k for k, v in svc.security_headers.items() if not v]
            lines.append(f"- **Missing security headers:** "
                         f"{', '.join(missing) if missing else 'none'}")
            if svc.technologies:
                techs = ", ".join(
                    f"{t.name}{('/' + t.version) if t.version else ''} "
                    f"({t.confidence.value})" for t in svc.technologies)
                lines.append(f"- **Technologies:** {techs}")
            lines.append(f"- **Response time:** {svc.response_ms} ms")
        return "\n".join(lines)

    def _content_section(self) -> str:
        # Media/static assets (images, css, fonts, audio/video, js) are excluded
        # from the human report — they're noise. Raw data stays in report.json.
        content_svcs = [(h, s, p) for h, s in self.graph.all_http_services()
                        if (p := _visible_paths(s))]
        endpoint_svcs = [(h, s, e) for h, s in self.graph.all_http_services()
                         if (e := _visible_endpoints(s))]
        if not content_svcs and not endpoint_svcs:
            return ""

        _CAP = 300          # max URLs listed per service (rest noted + in JSON)
        lines = ["\n## Discovered Web Content\n",
                 "_Media/static assets (images, css, fonts, audio/video) are "
                 "excluded; full raw list is in `report.json`._\n"]

        if content_svcs:
            lines += ["| Service | Total | 200 | 3xx | 401/403 | Other |",
                      "|---|---|---|---|---|---|"]
            for _h, s, paths in content_svcs:
                n = len(paths)
                c200 = sum(1 for p in paths if p["status"] == 200)
                c3xx = sum(1 for p in paths if 300 <= p["status"] < 400)
                cauth = sum(1 for p in paths if p["status"] in (401, 403))
                lines.append(f"| {s.url} | {n} | {c200} | {c3xx} | {cauth} "
                             f"| {n - c200 - c3xx - cauth} |")

            for _h, s, paths in content_svcs:
                lines.append(f"\n### {s.url}")
                paths = sorted(paths,
                               key=lambda p: (p.get("status", 0), p.get("path", "")))
                for p in paths[:_CAP]:
                    url = p.get("url") or f"{s.url.rstrip('/')}/{p.get('path','').lstrip('/')}"
                    st = p.get("status", "?")
                    loc = p.get("location")
                    extra = f" → {loc}" if (loc and 300 <= int(st or 0) < 400) else ""
                    title = p.get("title")
                    tnote = f"  _{title}_" if title else ""
                    lines.append(f"- `{st}` {url}{extra}{tnote}")
                if len(paths) > _CAP:
                    lines.append(f"- _… +{len(paths) - _CAP} more "
                                 "(full list in `report.json`)_")

        if endpoint_svcs:
            lines.append("\n### Endpoints / JS references (from page analysis)")
            for _h, s, eps in endpoint_svcs:
                base = s.url.rstrip("/")
                lines.append(f"\n**{s.url}** — {len(eps)} reference(s):")
                for ep in eps[:_CAP]:
                    absu = ep if "://" in ep else f"{base}/{ep.lstrip('/')}"
                    lines.append(f"- {absu}")
                if len(eps) > _CAP:
                    lines.append(f"- _… +{len(eps) - _CAP} more "
                                 "(full list in `report.json`)_")
        return "\n".join(lines)

    def _tls_section(self) -> str:
        lines = ["\n## TLS Information\n"]
        any_tls = False
        for ip in sorted(self.graph.hosts):
            h = self.graph.hosts[ip]
            for port, tls in sorted(h.tls.items()):
                any_tls = True
                lines.append(f"\n### {h.ip}:{port}")
                lines.append(f"- **Subject:** {tls.subject or '-'}")
                lines.append(f"- **Issuer:** {tls.issuer or '-'}")
                lines.append(f"- **SANs:** {', '.join(tls.sans) or '-'}")
                lines.append(f"- **Valid until:** {tls.not_after or '-'}"
                             + (f" ({tls.days_to_expiry} days)"
                                if tls.days_to_expiry is not None else ""))
                lines.append(f"- **Negotiated:** {tls.negotiated_protocol} "
                             f"{tls.negotiated_cipher}")
                if tls.protocols_offered:
                    lines.append(f"- **Protocols offered:** {', '.join(tls.protocols_offered)}")
                if tls.problems:
                    lines.append(f"- **Problems:** {'; '.join(tls.problems)}")
        if not any_tls:
            lines.append("_No TLS endpoints analysed._")
        return "\n".join(lines)

    def _technologies(self) -> str:
        counter = Counter()
        for _h, svc in self.graph.all_http_services():
            for t in svc.technologies:
                label = f"{t.name}{('/' + t.version) if t.version else ''}"
                counter[label] += 1
        lines = ["\n## Technologies\n", "| Technology | Instances |", "|---|---|"]
        for name, n in counter.most_common():
            lines.append(f"| {name} | {n} |")
        if len(lines) == 3:
            lines.append("| _(none identified)_ | 0 |")
        return "\n".join(lines)

    def _correlation(self) -> str:
        lines = ["\n## Correlation (IP → Service → Version → Tech → Findings)\n"]
        chains = CorrelationEngine().correlate(self.graph)
        if not chains:
            lines.append("_Nothing to correlate._")
            return "\n".join(lines)
        for c in chains:
            lines.append(f"- `{c.chain()}`"
                         + (f"  → findings: {', '.join(c.findings)}"
                            if c.findings else ""))
        return "\n".join(lines)

    def _prioritization(self) -> str:
        lines = ["\n## Prioritized Attack Surfaces\n",
                 "Ranked by evidence-weighted score. Presence alone is never "
                 "rated critical.\n",
                 "| Rank | Asset | Score | Top severity | Why |",
                 "|---|---|---|---|---|"]
        items = PriorityEngine().prioritize(self.graph)
        for i, item in enumerate(items[:25], 1):
            lines.append(f"| {i} | {item.asset} | {item.score} | "
                         f"{item.top_severity} | {'; '.join(item.reasons)} |")
        if not items:
            lines.append("| - | _(none)_ | - | - | - |")
        return "\n".join(lines)

    def _risk_ranking(self, view) -> str:
        from .risk import band
        allf = [a for bucket in view.by_validation.values() for a in bucket]
        allf.sort(key=lambda a: a.risk, reverse=True)
        top = [a for a in allf if a.risk > 0][:15]
        lines = ["\n## Risk Ranking\n",
                 "Findings ranked by environmental risk score (severity fused with "
                 "exploitation reality — CISA KEV / EPSS — and evidence strength).\n",
                 "| Risk | Band | Finding | Hosts |", "|---|---|---|---|"]
        for a in top:
            lines.append(f"| **{a.risk}**/100 | {band(a.risk)} | {a.title} | "
                         f"{a.count} |")
        if not top:
            lines.append("| - | - | _(no scored findings)_ | - |")
        return "\n".join(lines)

    def _render_findings(self, aggs) -> str:
        if not aggs:
            return "_None._\n"
        aggs = sorted(aggs, key=lambda a: (SEVERITY_ORDER[a.severity], a.count),
                      reverse=True)
        out = []
        for a in aggs:
            suffix = f" (×{a.count} hosts)" if a.count > 1 else ""
            flag = " [ACTIVELY EXPLOITED - CISA KEV]" if a.kev else ""
            out.append(f"\n### {a.title}{suffix}{flag}")
            epss_str = f"  |  **EPSS:** {a.epss:.0%}" if a.epss is not None else ""
            from .validation import display_state
            label = display_state(a.validation, a.validation_method, a.category)
            out.append(f"- **Risk:** {a.risk}/100  |  "
                       f"**Severity:** {a.severity.value}  |  "
                       f"**Confidence:** {a.confidence.value}  |  "
                       f"**Assurance:** {label} ({a.validation.value}){epss_str}")
            method = (f"  |  **Validation method:** {a.validation_method}"
                      if a.validation_method else "")
            out.append(f"- **Category:** {a.category}  |  "
                       f"**Detection source:** {a.source}{method}")
            out.append(f"- **Affected assets ({a.count}):** "
                       + ", ".join(f"`{x}`" for x in a.assets))
            # show a couple of representative evidence samples
            samples = [f"{asset}: {ev}" for asset, ev in
                       list(a.evidence_by_asset.items())[:3] if ev]
            if samples:
                out.append(f"- **Evidence:** " + " | ".join(samples)
                           + (" …" if a.count > 3 else ""))
            out.append(f"- **Description:** {a.description or '-'}")
            out.append(f"- **Why it matters:** {a.why_it_matters or '-'}")
            out.append(f"- **Potential impact:** {a.impact or '-'}")
            out.append(f"- **Recommended remediation:** {a.remediation or '-'}")
        return "\n".join(out) + "\n"

    def _assessment_gaps(self) -> str:
        gaps = []
        # A failed stage is a real gap: its checks did not run. Surface it loudly
        # rather than letting the report imply full coverage.
        stage_errors = (self.graph.meta or {}).get("stage_errors") or {}
        for label, err in stage_errors.items():
            gaps.append(f"- **Stage failed — did not complete:** {label} ({err}). "
                        "Findings from this stage are missing; re-run or "
                        "investigate.")
        unresp = [h.ip for h in self.graph.hosts.values()
                  if h.status in (HostStatus.UNRESPONSIVE, HostStatus.FILTERED)]
        if unresp:
            gaps.append(f"- {len(unresp)} host(s) unresponsive/filtered — may be "
                        "firewalled rather than offline: "
                        f"{', '.join(unresp[:10])}"
                        + (" …" if len(unresp) > 10 else ""))
        if not self.config.full_port_scan:
            gaps.append("- Only a curated port set was scanned; services on other "
                        "ports were not assessed (use `--full-port-scan` to widen).")
        if self.config.service_detection == "off":
            gaps.append("- Service/version detection was disabled.")
        gaps.append("- Deep credentialed checks, exploitation, and destructive "
                    "tests were intentionally NOT performed (safe assessment).")
        denied = self.scope.denied_decisions()
        if denied:
            gaps.append(f"- {len(denied)} operation(s) were blocked by the scope "
                        "engine and therefore not assessed.")
        return "\n## Assessment Gaps\n\n" + "\n".join(gaps)

    def _next_steps(self) -> str:
        items = PriorityEngine().prioritize(self.graph)
        lines = ["\n## Recommended Next Testing Areas\n"]
        top = items[:8]
        if not top:
            lines.append("_No reachable services to recommend follow-up on._")
            return "\n".join(lines)
        for item in top:
            lines.append(f"- **{item.asset}** — {'; '.join(item.reasons)}. "
                         "Validate findings, then perform authorized, targeted "
                         "testing appropriate to the service.")
        lines.append("\n> All follow-up testing must remain within the authorized "
                     "scope and follow the rules of engagement.")
        return "\n".join(lines)

    # -- json ------------------------------------------------------------- #
    def _json_export(self) -> dict:
        return {
            "scope": self.scope.summary(),
            "config": self.config.to_dict(),
            "graph": self.graph.to_dict(),
            "prioritization": [
                {"asset": i.asset, "score": i.score,
                 "top_severity": i.top_severity, "reasons": i.reasons}
                for i in PriorityEngine().prioritize(self.graph)
            ],
        }
