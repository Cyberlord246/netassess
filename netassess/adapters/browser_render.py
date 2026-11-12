"""Headless-browser rendering of dynamic (JS/SPA) web roots via Playwright.

OPTIONAL and auto-detected. When Playwright and a Chromium build are installed
and ``--render`` is set, each in-scope web root is loaded in a real headless
browser so single-page apps (React/Vue/Angular, Next.js, …) — which ship an
almost-empty HTML body and build everything in JavaScript — are observed *after*
the scripts run. For each root we collect:

  * the rendered DOM (post-hydration HTML), so body-based tech fingerprinting and
    the secret scanner see content the static GET never does;
  * every network URL the page requested — the runtime API/XHR/fetch endpoints
    that a static parser cannot know about;
  * the response bodies of same-host script / JSON / text responses, fed into the
    existing secrets scanner (many SPAs leak keys in a runtime-loaded config.json
    or a lazily-fetched JS chunk).

Strictly READ-ONLY / non-destructive: we navigate (GET), wait for the network to
settle, read the DOM, and passively observe responses. No clicks, no form input,
no downloads (``accept_downloads=False``), no script injection beyond reading
``page.content()``. Heavy, irrelevant resources (images/media/fonts) are aborted
to keep rendering fast. Scope is enforced by the caller — only in-scope roots are
passed in — and we only retain response bodies served by the target host.

If Playwright or the browser binary is missing, ``open()`` returns an explanatory
string and the caller logs it and skips rendering; the rest of the assessment is
unaffected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class RenderResult:
    url: str
    dom: str = ""
    endpoints: list[str] = field(default_factory=list)   # same-host path(+query)
    bodies: list[tuple[str, str]] = field(default_factory=list)  # (url, text)
    requests: list[str] = field(default_factory=list)    # all request URLs
    error: str = ""


# content types whose bodies are worth scanning for secrets / endpoints
_SCANNABLE = ("javascript", "json", "html", "text/plain", "text/css")
# resource types we abort (not needed to find secrets/endpoints; speeds rendering)
_SKIP_RESOURCES = {"image", "media", "font"}


class BrowserRenderAdapter:
    """Owns a single headless browser for the whole render phase.

    Lifecycle: ``open()`` once (launches Chromium), ``render(...)`` per web root,
    ``close()`` at the end. ``open()`` returns ``None`` on success or an error
    string the caller should surface and then proceed without rendering.
    """

    def __init__(self, *, nav_timeout: float = 15.0, max_bodies: int = 30,
                 max_body_bytes: int = 1_000_000, max_urls: int = 400):
        self.nav_timeout = float(nav_timeout)
        self.max_bodies = int(max_bodies)
        self.max_body_bytes = int(max_body_bytes)
        self.max_urls = int(max_urls)
        self._pw = None
        self._browser = None
        self._context = None

    @staticmethod
    def available() -> bool:
        """True if the Playwright Python package is importable. This does not
        guarantee the Chromium binary is installed — that is confirmed at
        ``open()`` and reported there."""
        try:
            import playwright  # noqa: F401
        except Exception:
            return False
        return True

    def open(self) -> str | None:
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            return (f"Playwright not installed ({exc}). Install with: "
                    "pip install playwright && playwright install chromium")
        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            self._context = self._browser.new_context(
                ignore_https_errors=True, accept_downloads=False,
                user_agent="netassess")
            self._context.set_default_navigation_timeout(
                int(self.nav_timeout * 1000))
            self._context.route("**/*", self._route)
            return None
        except Exception as exc:
            self.close()
            return (f"could not launch headless Chromium ({exc}). "
                    "Run: playwright install chromium")

    def _route(self, route) -> None:
        try:
            if route.request.resource_type in _SKIP_RESOURCES:
                route.abort()
            else:
                route.continue_()
        except Exception:
            try:
                route.continue_()
            except Exception:
                pass

    def _in_scope(self, host: str | None, hosts: set[str]) -> bool:
        return bool(host) and host in hosts

    def render(self, url: str, svc_ip: str, port: int,
               *, host_header: str | None = None) -> RenderResult:
        """Render one web root. Never raises — failures are captured in
        ``RenderResult.error`` and whatever was collected is still returned."""
        res = RenderResult(url=url)
        if self._context is None:
            res.error = "browser not open"
            return res

        hosts: set[str] = {svc_ip}
        if host_header:
            hosts.add(host_header)
        pu = urlparse(url)
        if pu.hostname:
            hosts.add(pu.hostname)

        seen_ep: set[str] = set()
        captured = {"n": 0}

        def on_response(resp):
            try:
                ru = resp.url
                res.requests.append(ru)
                rp = urlparse(ru)
                if not self._in_scope(rp.hostname, hosts):
                    return
                key = rp.path + (("?" + rp.query) if rp.query else "")
                if key and key not in seen_ep and len(seen_ep) < self.max_urls:
                    seen_ep.add(key)
                    res.endpoints.append(key)
                if captured["n"] >= self.max_bodies:
                    return
                ct = ""
                try:
                    ct = (resp.headers or {}).get("content-type", "").lower()
                except Exception:
                    ct = ""
                if not any(t in ct for t in _SCANNABLE):
                    return
                try:
                    body = resp.text()
                except Exception:
                    body = ""
                if body:
                    captured["n"] += 1
                    res.bodies.append((ru, body[: self.max_body_bytes]))
            except Exception:
                pass

        page = None
        try:
            page = self._context.new_page()
            page.on("response", on_response)
            try:
                # wait for the network to settle so lazily-loaded chunks/XHR fire
                page.goto(url, wait_until="networkidle",
                          timeout=int(self.nav_timeout * 1000))
            except Exception as exc:
                # long-poll / websocket pages never go idle: note it, read anyway
                res.error = f"navigation did not fully settle: {str(exc)[:160]}"
            try:
                res.dom = page.content() or ""
            except Exception as exc:
                if not res.error:
                    res.error = f"could not read DOM: {str(exc)[:160]}"
        except Exception as exc:
            res.error = f"render failed: {str(exc)[:160]}"
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass
        return res

    def close(self) -> None:
        for obj, meth in ((self._context, "close"), (self._browser, "close"),
                          (self._pw, "stop")):
            try:
                if obj is not None:
                    getattr(obj, meth)()
            except Exception:
                pass
        self._context = self._browser = self._pw = None
