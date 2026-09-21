"""
The audit runner: drive visits at the target and record what the defenses did.

Design notes that matter for correctness:

* One browser is reused across visitors; each visitor gets a fresh **context**.
  A browser launch costs seconds and a process, a context costs ~100ms, and both
  carry an independent fingerprint -- so reuse is what makes hundreds of visitors
  affordable. This relies on Camoufox's per-context fingerprint injection.

* Every navigation is routed through the scope gate and the safety ceilings.
  There is no code path that fetches a URL without both checks, because a single
  unguarded navigation is enough to send traffic somewhere unauthorized.

* One browser serves a whole rung by default (`reuse_browser`), and each visitor
  gets a fresh context. A browser launch costs seconds and a process; a context
  costs ~100ms, and both carry an independent fingerprint -- so reuse is what makes
  hundreds of visitors affordable. It is also the cheaper *signature*: 100 visitors
  that each spawn a Firefox process is a shape no human population produces.

* The runner is honest about what it did not do: a level that hits a ceiling is
  marked `aborted` with a reason, and a rung whose named signal could not be
  exercised says so, rather than being reported as a clean result.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .behavior import BehaviorModel, Cursor, campaign_dwell, spend_dwell
from .config import AuditConfig, AuditReport, CampaignEvent, LevelResult, VisitResult
from .detection import VENDOR_SIGNATURES, Verdict, classify_response
from .evasion import EvasionLevel
from .journey import (
    ArrivalSource,
    build_arrival_referer,
    discover_banner_candidates,
    plan_outbound_visit,
    plan_visit,
)
from .schedule import build_schedule
from .scope import ScopeViolation, TargetScope

__all__ = ["AuditRunner", "SafetyStop"]


class SafetyStop(RuntimeError):
    """A safety ceiling was reached; the audit stopped deliberately."""


#: Headers the rung intends to send on its own navigation.
#:
#: Named here so the scope guard's stamping step knows which header name carries
#: the arrival referer, and which header names Camoufox already sets -- re-applying
#: those would be the inconsistency the nav/context split exists to avoid.
_REFERER_HEADER = "Referer"


class _OpenResult:
    """
    The outcome of trying to follow a promotional banner.

    A small carrier rather than a tuple so the failure modes stay distinguishable:
    `loaded` is False when nothing was reached, `status` is None when the
    destination loaded but its response was not observed (a click that landed in a
    tab whose first response the listener missed), and `page` is the page that
    needs closing.
    """

    __slots__ = ("page", "status", "headers", "body", "loaded")

    def __init__(self) -> None:
        self.page: Optional[Any] = None
        self.status: Optional[int] = None
        self.headers: Dict[str, str] = {}
        self.body: str = ""
        self.loaded: bool = False


#: Status codes that mean "go here instead", not "here is the page".
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    A urllib redirect handler that will not follow a redirect out of scope.

    The browser rungs are contained by the route guard; the HTTP rung is not a
    browser and has no routes, so it needs its own gate. urllib's default opener
    follows a `Location:` to any host it names, which is the same leak the browser
    path had: the target gets to choose what this tool talks to. This handler is
    installed on the opener and refuses the redirect *before* the next request is
    issued, so the out-of-scope host is never contacted.
    """

    def __init__(self, permit, blocked: Optional[List[str]] = None) -> None:
        super().__init__()
        self._permit = permit
        self._blocked = blocked

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urljoin(req.full_url, newurl)
        if not self._permit(target):
            if self._blocked is not None:
                host = (urlparse(target).hostname or "").lower()
                if host and host not in self._blocked:
                    self._blocked.append(host)
            raise ScopeViolation(f"redirect to {target!r} left the declared scope")
        return super().redirect_request(req, fp, code, msg, headers, target)


class _ScopeGuard:
    """
    The single place a browser request is permitted to leave.

    Why this exists
    ---------------
    The scope gate used to be consulted once, for the URL the runner had chosen,
    and then the browser was left to route itself. That is not the same thing as
    an enforced scope: the page under audit decides what its own subresources
    point at, and the target decides where a response redirects. Both were
    followed unexamined, so a page could pull assets from -- or redirect a visit
    to -- a host the operator never named. An audit tool whose authorization
    boundary can be widened by the thing being audited is not contained.

    How it closes both holes
    ------------------------
    One context-level route handler sees every request. A request to an undeclared
    host is aborted with no traffic sent -- the request never reaches a socket, so
    the gate is preventive, not merely observational.

    Redirects need different handling, because a redirect hop is *not* re-routed:
    measured on the Playwright the audit drives, a route handler sees only the
    first request of a chain (a redirect's second request never comes back through
    it). So the handler resolves a navigation's chain itself, one hop at a time,
    judging each destination against the scope before asking for it. The browser
    is then served the final in-scope response and never speaks to the
    out-of-scope host at all. The alternative -- letting the browser follow the
    302 and aborting the request it makes -- is too late: the request has already
    left, which is the thing the gate exists to prevent.

    Subresources take the cheap path (`continue_()`), so the browser's own request
    goes out untouched and the audit still measures the real client. Navigations
    are resolved through `fetch()`, which costs some fidelity in Chromium -- it
    drops `Sec-Fetch-*` -- but not in Firefox, which is the engine Camoufox
    drives; verified against a real server, the headers the target sees are
    identical. Fidelity is the product here, so it is checked rather than assumed.

    Everything is counted: the guard tallies subresources so the request ceiling
    accounts for the traffic that actually leaves, rather than only the
    navigations the runner drives by hand.
    """

    def __init__(
        self,
        scope: TargetScope,
        *,
        limiter: "_Limiter",
        on_block=None,
        on_sent=None,
        stamp=None,
        max_hops: int = 10,
    ) -> None:
        self._scope = scope
        self._limiter = limiter
        self._on_block = on_block
        self._on_sent = on_sent
        self._stamp = stamp
        self._max_hops = max_hops
        #: Distinct refused hosts, in first-seen order, for the report.
        self.blocked_hosts: List[str] = []
        self._blocked_seen: set = set()
        self._stamped = False

    # -- decisions ---------------------------------------------------------

    def _block(self, url: str, resource_type: str) -> None:
        host = _normalize_scope_host(url)
        if host and host not in self._blocked_seen:
            self._blocked_seen.add(host)
            self.blocked_hosts.append(host)
        if self._on_block is not None:
            try:
                self._on_block(host, url, resource_type)
            except Exception:
                pass

    def _sent(self, count: int = 1) -> None:
        """Report requests that left, for the visit's traffic census."""
        if self._on_sent is not None:
            try:
                self._on_sent(count)
            except Exception:
                pass

    async def handle(self, route, request) -> None:
        """
        Judge one request.

        A navigation is resolved hop by hop so a redirect cannot smuggle the
        request past the gate; anything else is decided from its URL alone.
        """
        url = request.url
        is_navigation = bool(request.is_navigation_request())
        resource_type = getattr(request, "resource_type", "") or ""

        if is_navigation:
            await self._handle_navigation(route, request, url)
            return

        if not _is_web_url(url):
            # A non-http(s) request (`about:blank`, `data:`, a `blob:`) is not
            # traffic to a third party and is not the audit's to police.
            await self._safe_continue(route)
            return

        if not self._permits(url):
            self._block(url, resource_type)
            await self._safe_abort(route)
            return

        # A subresource costs the target a request too, and it is exactly the
        # traffic the ceiling was blind to. Charge the limiter here so the ceiling
        # bounds what actually leaves; a ceiling reached mid-page then stops the
        # page's remaining assets rather than only its navigations.
        try:
            await self._limiter.acquire()
        except SafetyStop:
            self._block(url, resource_type)
            await self._safe_abort(route)
            return
        self._sent()
        await self._safe_continue(route)

    async def _handle_navigation(self, route, request, url: str) -> None:
        if not _is_web_url(url):
            await self._safe_continue(route)
            return

        if not self._permits(url):
            self._block(url, resource_type="document")
            await self._safe_abort(route)
            return

        headers = dict(request.headers or {})
        if not self._stamped and self._stamp is not None:
            extra = None
            try:
                extra = self._stamp(request)
            except Exception:
                extra = None
            if extra:
                headers.update(extra)
                self._stamped = True

        hop = url
        first = True
        try:
            for _ in range(self._max_hops):
                if not self._permits(hop):
                    # The chain tried to leave the authorized scope. Nothing has
                    # been sent to this host, and nothing will be.
                    self._block(hop, resource_type="redirect")
                    await self._safe_abort(route)
                    return
                # The runner acquires the limiter for the navigation it is about to
                # make and counts it as a request itself; charging or counting
                # this hop again would do both twice. Each later hop is a request
                # the runner did not know about, so it is charged and counted here.
                if first:
                    first = False
                else:
                    try:
                        await self._limiter.acquire()
                    except SafetyStop:
                        self._block(hop, resource_type="redirect")
                        await self._safe_abort(route)
                        return
                    self._sent()
                response = await route.fetch(
                    url=hop, max_redirects=0, headers=headers
                )
                if response.status in _REDIRECT_STATUSES:
                    location = response.headers.get("location")
                    if not location:
                        await route.fulfill(response=response)
                        return
                    hop = urljoin(str(response.url), location)
                    continue
                await route.fulfill(response=response)
                return
            # A chain longer than the cap is not something to follow blindly.
            self._block(url, resource_type="redirect")
            await self._safe_abort(route)
        except SafetyStop:
            await self._safe_abort(route)
        except Exception:
            # A request that cannot be resolved is a failure of this one
            # navigation, not a reason to hang it: fail the request so the visit
            # records an error rather than stalling the run.
            await self._safe_abort(route)

    def _permits(self, url: str) -> bool:
        """
        Whether this URL may be requested.

        Two ways in, and both are operator-declared: the URL is inside the
        authorized scope (which is what the target itself is), or its host is one
        the funnel already reached and recorded. Nothing discovered at visit time
        can widen this -- the funnel admits a banner through `authorize_outbound`,
        and only then does the guard let its landing page load.

        Note that `authorize_outbound` refuses IP-literal hosts outright (the
        cloud metadata endpoint is a literal), so an IP-literal target is admitted
        by the scope check, not by the outbound one. Using the outbound check alone
        would refuse a legitimate IP-addressed target.
        """
        return _scope_permits(self._scope, url)

    # -- route primitives --------------------------------------------------

    @staticmethod
    async def _safe_abort(route) -> None:
        try:
            await route.abort()
        except Exception:
            pass

    @staticmethod
    async def _safe_continue(route) -> None:
        try:
            await route.continue_()
        except Exception:
            pass


def _normalize_scope_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_web_url(url: str) -> bool:
    """Whether a URL names a network destination the scope gate should judge."""
    return (urlparse(url).scheme or "").lower() in ("http", "https")


def _scope_permits(scope: TargetScope, url: str) -> bool:
    """
    The scope gate in one place, so every path asks the same question.

    In scope (the target), or a host the funnel already admitted this session.
    Kept as a function rather than a method because both the browser guard and the
    plain-HTTP redirect handler need it, and a second copy is how the two would
    drift.

    Note this is the *navigation* question, not the funnel question. It deliberately
    does not call `authorize_outbound`: doing so would make every URL permitted,
    because the funnel's default is now to follow what the page serves. The funnel
    asks `authorize_outbound` itself, at the moment it decides to click.
    """
    return scope.permits_navigation(url)


async def _capture_response(
    handler: "_OpenResult", page: Any, response: Any
) -> None:
    """Fill `handler` from a landing page and, when available, its response."""
    handler.page = page
    handler.loaded = True
    if response is None:
        return
    handler.status = getattr(response, "status", None)
    try:
        handler.headers = dict(response.headers or {})
    except Exception:
        handler.headers = {}
    try:
        handler.body = (await response.text())[:200_000]
    except Exception:
        handler.body = ""


class _Limiter:
    """
    A rolling-window rate limiter, plus an absolute request counter.

    A token bucket would allow a burst; a rolling window does not, and a burst is
    exactly what a defense (or an upstream) is least tolerant of. For an audit
    whose whole point is to be tolerated, the stricter shape is the right one.
    """

    def __init__(self, max_rps: float, max_requests: int) -> None:
        self.max_rps = max_rps
        self.max_requests = max_requests
        self.count = 0
        self._recent: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            if self.max_requests and self.count >= self.max_requests:
                raise SafetyStop(
                    f"Request ceiling reached ({self.max_requests}). The audit "
                    f"stopped rather than continue."
                )
            now = time.monotonic()
            self._recent = [t for t in self._recent if now - t < 1.0]
            if self.max_rps > 0 and len(self._recent) >= self.max_rps:
                wait = 1.0 - (now - self._recent[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = time.monotonic()
                    self._recent = [t for t in self._recent if now - t < 1.0]
            self._recent.append(time.monotonic())
            self.count += 1

    @property
    def remaining(self) -> Optional[int]:
        if not self.max_requests:
            return None
        return max(0, self.max_requests - self.count)


class AuditRunner:
    """Run an audit, level by level."""

    def __init__(
        self,
        config: AuditConfig,
        *,
        on_progress=None,
        cancel_event: Optional[Any] = None,
    ) -> None:
        self.config = config
        self._on_progress = on_progress
        self._cancel = cancel_event
        self._rng = random.Random(config.seed)
        # The resolved ceilings, not the raw ones: with `auto_scale_ceiling` on the
        # global request budget is derived from the traffic plan (see
        # `AuditConfig.resolved_limits`). Resolved once, here, so every enforcement
        # point reads the same number.
        self._limits = config.resolved_limits()
        self._limiter = _Limiter(self._limits.max_rps, self._limits.max_requests)
        self._proxy_counts: Dict[str, int] = {}
        self._consecutive_errors = 0
        self._virtual_display_used = False
        self._geoip_missing_noted = False
        self._no_proxy_noted = False
        self._headless_override_noted = False
        self._persistence_noted = False
        self._single_level_noted = False
        self._browser_reuse_noted = False
        self._funnel_gate_noted = False
        self._funnel_scope_noted = False
        self._rotator = None
        self._behavior = BehaviorModel()
        #: The level-scoped browser when `reuse_browser` is on, or None when each
        #: visit launches (and closes) its own.
        self._level_browser: Optional[Any] = None
        self._level_browser_handle: Optional[Tuple[Any, Any]] = None
        #: One artifact per level, not per visitor: 100 visitors of the same
        #: fingerprint would write 100 near-identical screenshots, and the first
        #: is the one that shows what the rung encountered.
        self._artifacts_written: set = set()
        self._artifacts_by_level: Dict[int, List[str]] = {}
        if config.proxy:
            from ..proxy import build_rotator

            self._rotator = build_rotator(config.proxy)

    # -- cancellation / progress ------------------------------------------

    def _cancelled(self) -> bool:
        return bool(self._cancel is not None and self._cancel.is_set())

    @staticmethod
    def _has_display() -> bool:
        """True when this host already has a usable X server."""
        if sys.platform.startswith("win") or sys.platform == "darwin":
            return True
        display = os.environ.get("DISPLAY", "")
        if not display:
            return False
        # "localhost:0" and similar still need the socket to exist.
        if display.startswith(":"):
            number = display[1:].split(".")[0]
            return os.path.exists(f"/tmp/.X11-unix/X{number}")
        return True

    def _note_virtual_display(self) -> None:
        if self._virtual_display_used:
            return
        self._virtual_display_used = True
        self._progress(
            event="notice",
            message=(
                "No X server detected; headed levels will use Camoufox's virtual "
                "display. Results are valid, but a real desktop may still differ."
            ),
        )

    @staticmethod
    def _has_geoip() -> bool:
        """True when the optional geoip extra is installed."""
        import importlib.util

        return importlib.util.find_spec("geoip2") is not None

    def _launch_needs_own_proxy(self, level: EvasionLevel) -> bool:
        """
        True when a rung's browser launch depends on the visitor's own exit IP.

        A rung with `geoip` and IP rotation resolves its geography at launch, so
        two visitors on different proxies need two launches. Sharing one would
        give every visitor the first visitor's timezone and locale -- a
        *more* inconsistent fingerprint than not spoofing at all, because the
        browser would then claim a geography its exit IP contradicts.
        """
        return bool(level.camoufox_options.get("geoip")) and level.requires_rotation

    def _note_geoip_missing(self) -> None:
        if self._geoip_missing_noted:
            return
        self._geoip_missing_noted = True
        self._progress(
            event="notice",
            message=(
                "The geoip extra is not installed, so fingerprint spoofing runs "
                "without IP-based geolocation and timezone alignment. Install it "
                "with 'pip install camoufox[geoip]' for a stronger mask."
            ),
        )

    def _note_no_proxy(self, level: EvasionLevel) -> None:
        if self._no_proxy_noted:
            return
        self._no_proxy_noted = True
        self._progress(
            event="notice",
            message=(
                f"{level.name} ran without a proxy, so it measured the fingerprint "
                "and header posture on this host's own exit IP -- not IP rotation. "
                "Configure a proxy pool to make the IP-rotation result mean what the "
                "rung says it means."
            ),
        )

    def _note_headless_override(self, level: EvasionLevel, forced: bool) -> None:
        declared = bool((level.camoufox_options or {}).get("headless"))
        if declared == forced:
            # The override agrees with this rung's own posture, so nothing was
            # actually overridden and there is nothing to announce. Checking
            # before the once-only flag matters: the first rung that agrees must
            # not consume the notice owed to a later rung that does not.
            return
        if self._headless_override_noted:
            return
        self._headless_override_noted = True
        forced_word = "headless" if forced else "headful"
        self._progress(
            event="notice",
            message=(
                f"The configured headless setting forced every rung {forced_word}, "
                f"overriding the posture {level.name} is defined by. The run is "
                "still valid, but this rung now measures a "
                f"{forced_word} stock browser rather than its declared mode."
            ),
        )

    def _note_browser_reuse(self, level: EvasionLevel) -> None:
        """Warn when per-visit launches are in use, since that is the costly path."""
        if self._browser_reuse_noted:
            return
        self._browser_reuse_noted = True
        if self._launch_needs_own_proxy(level):
            # Reuse is on; this rung is the exception, and saying "off" here would
            # send someone to a setting that is already what they want.
            reason = (
                f"{level.name} rotates IPs and aligns its geography at launch, so "
                f"each visitor needs its own browser rather than a shared one"
            )
        else:
            reason = f"reuse_browser is off, so every visit at {level.name} launches its own browser"
        self._progress(
            event="notice",
            message=(
                f"{reason}. That is correct for measuring a cold-start client, "
                f"but it costs a process per visitor and is itself a resource shape "
                f"a human population does not produce."
            ),
        )

    def _note_persistence_unavailable(self, level: EvasionLevel) -> None:
        if self._persistence_noted:
            return
        self._persistence_noted = True
        self._progress(
            event="notice",
            message=(
                f"{level.name} is defined by a durable profile and cookie jar, but "
                "the audit reuses one browser across visitors and gives each a fresh "
                "context, so no profile persists. The rung ran, but the "
                "returning-visitor signal it names was not exercised."
            ),
        )

    def _note_single_level(self, level: EvasionLevel) -> None:
        if self._single_level_noted:
            return
        self._single_level_noted = True
        self._progress(
            event="notice",
            message=(
                f"Single-rung mode: only {level.name} will run, with the visitor "
                f"count pinned to {self.config.visitor_count} so repeat runs are "
                "comparable. No cheaper rung is included, so the report measures "
                "this one posture rather than attributing the defense to a control."
            ),
        )

    def _launch_options(
        self,
        level: EvasionLevel,
        proxy_session: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """The Camoufox launch options for one rung, with fallbacks applied.

        Split out from the visit path so it can be asserted on without starting a
        browser: what a rung launches *with* is the contract, and it is the part
        that silently regresses on a host that lacks a display or an optional
        extra.

        `proxy_session` is the visitor's own proxy, when there is one, and it is
        what keeps a geoip rung honest. `geoip=True` is resolved at *launch* time,
        but the proxy reaches the browser at *context* time (Playwright scopes
        `proxy` to the context). Launching with the flag and no session therefore
        resolves the host's own public IP and bakes the host's timezone, locale and
        WebRTC address into the fingerprint while the traffic exits from the pool --
        the exact geo/exit mismatch this rung exists to rule out. With the session
        passed, the library resolves the exit through the proxy itself; a verified
        `exit_ip` short-circuits that second lookup so the launch cannot land on a
        different exit than the context will use.
        """
        options = dict(level.camoufox_options or {})
        if options.get("geoip") and proxy_session is not None:
            # `geoip=True` resolves at launch, and with the session in hand the
            # library asks the *proxy* what IP the world sees (see
            # `launch_options`, which calls `public_ip` on the session's proxy).
            # Leaving it as `True` therefore does the right thing -- but an
            # already-verified exit is preferred, because a second lookup can race
            # the gateway into a different exit than the context will actually use.
            exit_ip = getattr(proxy_session, "exit_ip", None)
            if exit_ip:
                options["geoip"] = exit_ip
        # A rung declares its own headed/headless posture (L1 exists precisely
        # because it is headless), so the config value is an *override* for hosts
        # that cannot honour the posture -- it is applied on top, and announced
        # when it contradicts the rung.
        override = self.config.headless
        if override is not None:
            options["headless"] = bool(override)
            self._note_headless_override(level, bool(override))
        options.setdefault("headless", False)
        if not options["headless"]:
            # A headed rung needs an X server. On a headless host (a CI runner, a
            # VPS) the launch would fail outright with "no DISPLAY environment
            # variable specified", which measures nothing and reports an error
            # where the operator expects a verdict. 'virtual' tells Camoufox to
            # start its own Xvfb, so the rung still exercises a real headed
            # browser. An explicit DISPLAY is left alone.
            if not self._has_display():
                options["headless"] = "virtual"
                self._note_virtual_display()
        if options.get("geoip") and not self._has_geoip():
            # geoip2 is an optional extra; leaving the flag set would make every
            # rung that uses it fail to launch, measuring nothing at all.
            options["geoip"] = False
            self._note_geoip_missing()
        return options

    def _progress(self, **payload) -> None:
        if self._on_progress:
            try:
                self._on_progress(payload)
            except Exception:
                pass

    # -- scope -------------------------------------------------------------

    def _check_url(self, url: str) -> str:
        return self.config.scope.check(url)

    def _candidate_paths(self) -> List[str]:
        base = self.config.target_url
        paths = [""] + list(self.config.paths)
        return [urljoin(base, p) for p in paths]

    # -- proxy -------------------------------------------------------------

    def _acquire_proxy(self) -> Tuple[Optional[Any], Optional[str]]:
        """
        Get a proxy session, respecting the per-proxy concurrency ceiling.

        Returns (session, skip_reason). A session of None with a reason means
        this visitor should be skipped rather than run without a proxy.
        """
        if self._rotator is None:
            return None, None
        cap = self._limits.max_per_proxy
        for _ in range(8):
            session = self._rotator.acquire_session()
            if session is None:
                # allow_direct_fallback was set on the pool.
                return None, None
            label = session.endpoint.redacted()
            used = self._proxy_counts.get(label, 0)
            if cap and used >= cap:
                continue
            self._proxy_counts[label] = used + 1
            return session, None
        return None, (
            f"every proxy in the pool has reached the per-proxy ceiling "
            f"({cap}); skipping this visitor rather than overloading one exit"
        )

    def _release_proxy(self, session: Optional[Any]) -> None:
        if session is None:
            return
        label = session.endpoint.redacted()
        if label in self._proxy_counts:
            self._proxy_counts[label] = max(0, self._proxy_counts[label] - 1)

    # -- one visit ---------------------------------------------------------

    async def _visit_http(
        self, level: EvasionLevel, plan, url: str, headers: Dict[str, str]
    ) -> VisitResult:
        """Level 0: a plain HTTP request with no browser at all."""
        result = VisitResult(
            visitor_index=-1,
            level_id=level.id,
            started_at=time.time(),
            source=plan.source,
            referer=plan.referer,
        )
        await self._limiter.acquire()
        send_headers = dict(headers)
        if plan.referer:
            send_headers["Referer"] = plan.referer

        started = time.monotonic()
        blocked_hosts: List[str] = []
        status, resp_headers, body, error = await asyncio.to_thread(
            self._http_fetch, url, send_headers, blocked_hosts
        )
        result.latencies.append(time.monotonic() - started)
        result.requests_made = 1
        result.finished_at = time.time()
        result.http_status = status
        if blocked_hosts:
            result.blocked_hosts = list(blocked_hosts)
            for host in blocked_hosts:
                result.evidence.append(
                    f"scope gate refused a redirect to {host!r}; no request was sent"
                )

        if error:
            result.launcher_error = error
            result.reason = error
            # A request the scope gate refused is not a transport failure. It is a
            # finding about the target's links, so it gets its own verdict rather
            # than being reported as "the audit could not reach the site".
            if result.blocked_hosts:
                result.verdict = Verdict.OUT_OF_SCOPE
                result.reason = (
                    "the scope gate refused a redirect to "
                    + ", ".join(repr(h) for h in result.blocked_hosts)
                )
            else:
                result.verdict = Verdict.ERROR
            return result

        verdict = classify_response(status, resp_headers, body)
        result.verdict = verdict.verdict
        result.vendors = verdict.vendors
        result.reason = verdict.reason
        result.evidence = verdict.evidence
        self._capture_http_artifact(level, result, body)
        return result

    def _capture_http_artifact(
        self, level: EvasionLevel, result: VisitResult, body: str
    ) -> None:
        """
        Write the served HTML for a non-browser rung.

        The browser rungs capture through a page handle; this rung has only the
        response body, so it writes that. Without this, `artifact_dir` silently
        produced nothing for a run made entirely of HTTP rungs -- and L0 is the
        rung most likely to be blocked, which is the page worth keeping.
        """
        if not self.config.artifact_dir or level.id in self._artifacts_written:
            return
        self._artifacts_written.add(level.id)
        directory = Path(self.config.artifact_dir)
        try:
            directory.mkdir(parents=True, exist_ok=True)
            html = directory / f"{level.id:02d}-{level.key}.html"
            html.write_text(body, encoding="utf-8")
        except OSError as exc:
            result.evidence.append(f"artifact capture failed: {type(exc).__name__}: {exc}")
            return
        result.evidence.append(f"html: {html}")
        self._artifacts_by_level.setdefault(level.id, []).append(str(html))

    def _http_fetch(
        self,
        url: str,
        headers: Dict[str, str],
        blocked_out: Optional[List[str]] = None,
    ) -> Tuple[Optional[int], Dict[str, str], str, Optional[str]]:
        """Synchronous fetch, run in a thread so the event loop stays responsive."""
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, headers=headers, method="GET")
        opener = urllib.request.build_opener(
            _ScopedRedirectHandler(
                lambda target: _scope_permits(self.config.scope, target),
                blocked_out,
            )
        )
        try:
            with opener.open(request, timeout=20) as response:
                return (
                    response.status,
                    dict(response.headers.items()),
                    response.read(400_000).decode("utf-8", errors="replace"),
                    None,
                )
        except urllib.error.HTTPError as exc:
            # An HTTPError is a real response (403, 429, ...) and is exactly the
            # finding we want, so it is a result, not a failure.
            try:
                body = exc.read(400_000).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return (
                exc.code,
                dict(exc.headers.items()) if exc.headers else {},
                body,
                None,
            )
        except ScopeViolation as exc:
            # The redirect gate refused a hop. urllib wraps handler exceptions in
            # a generic URLError, so the refusal is reported through its own type
            # rather than as a transport failure.
            return None, {}, "", f"ScopeViolation: {exc}"
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ScopeViolation):
                return None, {}, "", f"ScopeViolation: {reason}"
            return None, {}, "", f"{type(exc).__name__}: {exc}"
        except Exception as exc:
            return None, {}, "", f"{type(exc).__name__}: {exc}"

    async def _visit_browser(
        self,
        browser,
        level: EvasionLevel,
        plan,
        url: str,
        index: int,
        proxy_session,
    ) -> VisitResult:
        """Levels 1+: a real Camoufox context, driven through a human-ish journey."""
        result = VisitResult(
            visitor_index=index,
            level_id=level.id,
            started_at=time.time(),
            source=plan.source,
            referer=plan.referer,
            proxy_label=proxy_session.endpoint.redacted() if proxy_session else None,
            exit_ip=getattr(proxy_session, "exit_ip", None),
        )

        # Split the rung's headers by where a browser would really send them. The
        # rung's set is stamped on the top-level navigation via a route; the
        # context-wide set is genuinely repeated on subresources and can go
        # context-wide (it is empty for every shipped rung). Applying a navigation
        # header context-wide was itself an inconsistency: a stylesheet requested
        # with `Accept: text/html` is a synthetic-client tell.
        context_headers = {**level.context_headers, **self.config.extra_headers}
        nav_headers = dict(level.navigation_headers)

        context_kwargs: Dict[str, Any] = {}
        if context_headers:
            context_kwargs["extra_http_headers"] = context_headers
        if proxy_session is not None:
            context_kwargs["proxy"] = proxy_session.playwright

        from ..async_api import AsyncNewContext

        try:
            context = await AsyncNewContext(browser, **context_kwargs)
        except Exception as exc:
            result.launcher_error = f"{type(exc).__name__}: {exc}"
            result.reason = "could not open a browser context"
            result.verdict = Verdict.ERROR
            result.finished_at = time.time()
            return result

        try:
            await self._install_scope_guard(context, level, url, nav_headers, plan, result)
            await self._drive_journey(context, level, plan, url, result)
        finally:
            try:
                await context.close()
            except Exception:
                pass

        result.finished_at = time.time()
        return result

    async def _capture_artifact(self, page, level: EvasionLevel, result: VisitResult) -> None:
        """
        Write the evidence for one rung: a screenshot and the served HTML.

        `AuditConfig.artifact_dir` was declared and documented but read nowhere,
        so setting it silently did nothing. It is captured here because a finding
        an operator cannot inspect is one they have to take on trust -- "blocked,
        Cloudflare, 403" is far more actionable with the page that said it.

        One artifact per rung, not per visitor: the visitors of a rung share a
        fingerprint and a posture, so the second screenshot is near-identical and
        only costs disk. The *first* visit is the informative one, because it is
        what the rung encountered before any challenge state accumulated.

        Best-effort by design. A screenshot failing (offscreen platform, a page
        already gone) must not turn a completed audit into a failed one, so a
        capture error is recorded as evidence rather than raised.
        """
        if not self.config.artifact_dir or level.id in self._artifacts_written:
            return
        # Mark first: a capture that fails must not be retried 99 more times.
        self._artifacts_written.add(level.id)

        directory = Path(self.config.artifact_dir)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            result.evidence.append(f"could not create artifact directory {directory}: {exc}")
            return

        stem = f"{level.id:02d}-{level.key}"
        try:
            shot = directory / f"{stem}.png"
            await page.screenshot(path=str(shot), full_page=False)
            result.evidence.append(f"screenshot: {shot}")
            self._artifacts_by_level.setdefault(level.id, []).append(str(shot))
        except Exception as exc:  # noqa: BLE001 - evidence is best-effort
            result.evidence.append(f"screenshot failed: {type(exc).__name__}: {exc}")
        try:
            html = directory / f"{stem}.html"
            html.write_text(await page.content(), encoding="utf-8")
            result.evidence.append(f"html: {html}")
            self._artifacts_by_level.setdefault(level.id, []).append(str(html))
        except Exception as exc:  # noqa: BLE001 - evidence is best-effort
            result.evidence.append(f"html capture failed: {type(exc).__name__}: {exc}")

    async def _install_scope_guard(
        self,
        context,
        level: EvasionLevel,
        url: str,
        headers: Dict[str, str],
        plan,
        result: VisitResult,
    ) -> None:
        """
        Put the scope gate on the wire, once, for the whole context.

        A single context-level route replaces the per-page header route, because
        the two cannot coexist: measured on this Playwright, a page-level route
        takes precedence and a context-level one never runs, so a header route on
        the page would silently disable the scope guard underneath it. One handler
        then has to do both jobs -- stamp the arrival's navigation-only headers
        *and* judge every request -- which is why `_ScopeGuard` takes the stamping
        callback rather than the runner installing a second route.

        The stamp applies to the first navigation only, for the reason it always
        did: a browser derives the Referer for later hops from the page it is
        leaving, and a rung's `Accept`/`Sec-Fetch-*` belong on the document, not on
        every stylesheet.

        The blocked-host recorder is per-visit: the guard reports each refusal
        here, and the first refusal of each host lands on the visit as a finding.
        """
        wanted = dict(headers or {})
        if plan.referer:
            wanted[_REFERER_HEADER] = plan.referer

        target_host = urlparse(url).netloc

        def stamp(request) -> Optional[Dict[str, str]]:
            if not wanted:
                return None
            if not request.is_navigation_request():
                return None
            if urlparse(request.url).netloc != target_host:
                return None
            return dict(wanted)

        def on_block(host: str, blocked_url: str, resource_type: str) -> None:
            if host and host not in result.blocked_hosts:
                result.blocked_hosts.append(host)
                label = "redirect to" if resource_type == "redirect" else "subresource from"
                result.evidence.append(
                    f"scope gate refused a {label} {host!r}; no request was sent"
                )

        def on_sent(count: int) -> None:
            # The guard sees every request the browser makes, which is the only
            # place the subresource side of the census can be counted. The
            # navigations the runner drives are counted separately (one per
            # `goto`/`page.goto`), so those are not attributed here twice.
            if count > 0:
                result.subrequests_made += count

        guard = _ScopeGuard(
            self.config.scope,
            limiter=self._limiter,
            on_block=on_block,
            on_sent=on_sent,
            stamp=stamp,
        )
        try:
            await context.route("**/*", guard.handle)
        except Exception as exc:
            # Without the guard there is no enforced scope, and running anyway
            # would be exactly the uncontained behavior the gate exists to stop.
            raise ScopeViolation(
                f"could not install the scope gate on the browser context "
                f"({type(exc).__name__}: {exc}); refusing to run uncontained"
            )

    async def _drive_journey(
        self,
        context,
        level: EvasionLevel,
        plan,
        url: str,
        result: VisitResult,
    ) -> None:
        """
        Walk one visitor through their planned session, honoring the plan.

        The scope gate is already installed on the context by `_visit_browser`;
        nothing here needs to route requests itself.
        """
        page = await context.new_page()
        try:
            await self._limiter.acquire()
            started = time.monotonic()
            status = None
            body = ""
            resp_headers: Dict[str, str] = {}
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                if response is not None:
                    status = response.status
                    resp_headers = dict(response.headers or {})
                    try:
                        body = (await response.text())[:400_000]
                    except Exception:
                        body = ""
            except Exception as exc:
                result.launcher_error = f"{type(exc).__name__}: {exc}"
            result.latencies.append(time.monotonic() - started)
            result.requests_made += 1

            verdict = classify_response(status, resp_headers, body)
            result.http_status = status
            result.verdict = verdict.verdict
            result.vendors = verdict.vendors
            result.reason = verdict.reason
            result.evidence = list(verdict.evidence)
            result.pages_loaded = 1

            # Capture the arrival page -- including when it was a block or a
            # challenge, which is exactly the page an operator most wants to see.
            await self._capture_artifact(page, level, result)

            # A challenge or block ends the visit: there is nothing beyond it to
            # measure, and pushing on would be probing a closed door.
            if verdict.detected or verdict.verdict == Verdict.ERROR:
                return

            cursor = Cursor(page, self._rng, self._behavior)
            dwell_spent = 0.0
            budget = max(0.1, float(self.config.journey.interaction_budget_s))
            stage_deadline = time.monotonic() + budget
            planned_scrolls = max(1, plan.scroll_steps)

            for page_index in range(max(1, plan.page_count)):
                if self._cancelled():
                    return

                # Interaction first: a reader moves the pointer and scrolls while
                # reading, not before. Bounded by the visit's interaction budget so
                # a long session is reading time rather than a burst of synthetic
                # activity -- a 45s visit must not be 45s of scrolling.
                stage_deadline = time.monotonic() + budget
                if page_index == 0:
                    await cursor.glance()
                dispatched = await cursor.scroll(
                    planned_scrolls // max(1, plan.page_count) + 1,
                    deadline=stage_deadline,
                )
                if dispatched:
                    result.evidence.append(f"scrolled {dispatched} bursts")

                if plan.will_type and page_index == 0:
                    await self._maybe_type(page, cursor, result, stage_deadline)

                # Outbound funnel: after the visitor has read the arrival page,
                # which is when a person notices a promotional banner. Runs only
                # on a behavioral rung (see `_funnel_applies`), and only on the
                # first page. A click-through is a *departure*: the visitor left
                # the page under audit for the campaign destination, so the
                # journey ends here rather than picking its next hop from links
                # the destination happens to have.
                if page_index == 0 and self._funnel_applies(level):
                    self._note_funnel_scope()
                    if await self._walk_outbound_funnel(
                        context, page, cursor, level, plan, url, result
                    ):
                        return

                # Then the rest of the page's reading time, which is where the
                # dwell actually lands.
                remaining = self._page_dwell(plan, page_index)
                dwell_spent += await spend_dwell(
                    max(0.0, remaining),
                    slice_s=self._behavior.sleep_slice_s,
                    cancelled=self._cancelled,
                )

                if page_index >= plan.page_count - 1:
                    break

                # Per-visitor request ceiling. The plan's page count was the only
                # bound before, so this documented setting did nothing -- a safety
                # control that silently no-ops is worse than none, because it is
                # relied on.
                cap = int(self.config.journey.max_requests_per_visitor)
                if cap > 0 and result.requests_made >= cap:
                    result.evidence.append(
                        f"stopped at the per-visitor request ceiling ({cap})"
                    )
                    break

                next_url = await self._pick_next_url(page, plan)
                if next_url is None:
                    break
                if not self.config.scope.permits_url(next_url):
                    # Following an out-of-scope link would take the audit off
                    # target; stop rather than wander onto a third party.
                    result.evidence.append(f"skipped out-of-scope link {next_url!r}")
                    break

                if self._cancelled():
                    return

                await self._limiter.acquire()
                started = time.monotonic()
                response = None
                if level.is_behavioral and plan.follow_links:
                    # Drive the hop the way a reader would, by clicking the link;
                    # fall through to a direct navigation only if that fails.
                    response = await self._follow_link(page, cursor, next_url)
                try:
                    if response is None:
                        response = await page.goto(
                            next_url, wait_until="domcontentloaded", timeout=30_000
                        )
                    if response is not None:
                        status = response.status
                        resp_headers = dict(response.headers or {})
                        try:
                            body = (await response.text())[:200_000]
                        except Exception:
                            body = ""
                    else:
                        status, resp_headers, body = None, {}, ""
                except Exception as exc:
                    result.launcher_error = f"{type(exc).__name__}: {exc}"
                    status, resp_headers, body = None, {}, ""
                result.latencies.append(time.monotonic() - started)
                result.requests_made += 1
                result.pages_loaded += 1
                hop_verdict = classify_response(status, resp_headers, body)
                if hop_verdict.detected:
                    # Later hops can trip a defense the first page did not.
                    result.verdict = hop_verdict.verdict
                    result.vendors = sorted(set(result.vendors) | set(hop_verdict.vendors))
                    result.reason = f"on page {page_index + 2}: {hop_verdict.reason}"
                    result.evidence = list(hop_verdict.evidence)
                    result.http_status = status
                    break

            if dwell_spent > 0:
                result.evidence.append(f"spent {dwell_spent:.1f}s on the page")
        finally:
            try:
                await page.close()
            except Exception:
                pass

    #: Finds the anchor whose *resolved* href equals the URL we chose.
    #:
    #: Link selection reads `e.href`, which the DOM resolves to an absolute URL,
    #: but the attribute on the element is usually relative (`/about`). Matching
    #: `a[href="<absolute>"]` therefore finds nothing and the hop silently
    #: degrades to a typed-URL navigation. Resolving both sides is what makes the
    #: click actually happen.
    _FIND_ANCHOR_JS = """url => {
        const anchors = Array.from(document.querySelectorAll('a[href]'));
        return anchors.findIndex(a => a.href === url);
    }"""

    #: Scrolls a promotional banner into view and reports the ones present.
    #:
    #: Reads the DOM because the point of the funnel audit is to discover the
    #: campaign destinations dynamically -- no hand-maintained domain list. The
    #: selector set is deliberately narrow: a banner is a promotional anchor, and
    #: the whole page's nav/footer links are not campaign destinations. `href` is
    #: the *resolved* property (`a.href`), not the attribute, so a relative link
    #: becomes the absolute URL the audit would actually contact.
    #:
    #: Visibility is checked so a hidden tracking pixel wrapped in an anchor does
    #: not count as a banner a person could click.
    _DISCOVER_BANNERS_JS = """() => {
        const selectors = ['a.promo-banner', 'div.hero-promo a',
                           'a[data-campaign]', 'a[data-banner]',
                           'a[class*="promo" i]', 'a[class*="banner" i]'];
        const seen = new Set();
        const out = [];
        for (const sel of selectors) {
            for (const el of document.querySelectorAll(sel)) {
                const href = el.href;
                if (!href || seen.has(href)) continue;
                const rect = el.getBoundingClientRect();
                const style = window.getComputedStyle(el);
                if (rect.width < 1 || rect.height < 1) continue;
                if (style.visibility === 'hidden' || style.display === 'none') continue;
                seen.add(href);
                const label = (el.getAttribute('data-campaign') ||
                               el.textContent || '').trim().slice(0, 120);
                out.push({href: href, selector: sel, text: label});
                if (out.length >= 60) return out;
            }
        }
        return out;
    }"""

    async def _follow_link(self, page, cursor: Cursor, next_url: str):
        """
        Navigate by clicking the link a reader would click.

        A human does not type a URL to move between pages; they aim at the anchor
        and press it. Driving every hop with `goto` makes each navigation a
        typed-URL navigation -- a different and rarer behavior -- and it arrives
        with no Referer, which is a stronger bot signal than the one it avoids.

        Returns the landing response, or None when the link cannot be clicked, so
        the caller can fall back to a direct navigation rather than lose the hop.
        """
        try:
            index = await page.evaluate(self._FIND_ANCHOR_JS, next_url)
            if index is None or index < 0:
                return None
            locator = page.locator("a[href]").nth(index)
            await locator.scroll_into_view_if_needed(timeout=3000)
            box = await locator.bounding_box()
            if not box:
                return None
            await cursor.move_to(
                box["x"] + box["width"] * self._rng.uniform(0.25, 0.75),
                box["y"] + box["height"] * self._rng.uniform(0.35, 0.65),
                min_distance=6.0,
            )
            async with page.expect_navigation(
                wait_until="domcontentloaded", timeout=15_000
            ) as nav:
                if not await cursor.click():
                    return None
            return await nav.value
        except Exception:
            return None

    def _page_dwell(self, plan, page_index: int) -> float:
        """
        How long to read the page at `page_index`, within the visit's budget.

        The plan's slices sum to the drawn dwell; the budget clips that total, so a
        900s outlier becomes a bounded visit rather than a 15-minute slot hold,
        while short visits are still spent in full.
        """
        slices = plan.page_dwell_s or []
        if not slices:
            return 0.0
        total = plan.dwell_s or 0.0
        budget = max(0.0, self.config.journey.dwell_budget_s)
        scale = 1.0 if total <= 0 or total <= budget else budget / total
        index = min(page_index, len(slices) - 1)
        return max(0.0, slices[index] * scale)

    # -- outbound funnel ---------------------------------------------------

    def _funnel_applies(self, level: EvasionLevel) -> bool:
        """
        Whether this rung may click a promotional banner.

        Gated on the two conditions the feature is defined by: the operator turned
        it on, and the rung is behavioral. A click-through is human behavior, and
        a rung that does not claim behavior must not silently exhibit it --
        otherwise L2's verdict would be the product of an interaction L2 never
        claimed, which is exactly the unattributable-verdict failure the ladder is
        built to prevent.
        """
        return bool(self.config.enable_outbound_funnel) and level.is_behavioral

    def _note_funnel_skipped(self, level: EvasionLevel) -> None:
        if self._funnel_gate_noted:
            return
        self._funnel_gate_noted = True
        self._progress(
            event="notice",
            message=(
                f"Outbound funnel auditing is on, but {level.name} does not claim "
                f"behavior, so no banner is clicked at this rung. The funnel runs on "
                f"the behavioral rungs (L5/L6); add a behavioral rung to measure it."
            ),
        )

    def _note_funnel_scope(self) -> None:
        if self._funnel_scope_noted:
            return
        self._funnel_scope_noted = True
        scope = self.config.scope
        if scope.excluded_outbound_hosts:
            self._progress(
                event="notice",
                message=(
                    "Outbound funnel auditing is on. Every banner the page serves is "
                    "followed except those on the excluded campaign hosts: "
                    + ", ".join(sorted(scope.excluded_outbound_hosts))
                    + ". Remove a host from the exclusion list to follow it again."
                ),
            )

    async def _discover_banners(self, page, page_url: str) -> List[Any]:
        """
        Read the page's promotional banners and keep the ones we may follow.

        Discovery is dynamic -- the DOM decides which destinations exist, so there
        is no hand-maintained campaign list to drift. The gate is what trims them:
        a banner the page serves is followed by default, and one on a host the
        operator excluded is dropped here, with the refusal recorded by the caller
        so a skipped campaign link shows up in the report rather than being
        silently invisible.

        With `include_iframes` on, every child frame is read as well. A campaign is
        routinely served from an ad iframe, so a main-frame-only scan reports "no
        promotional banner found" on a page that is visibly showing one -- a false
        negative about the site's funnel, which is the thing being measured. Frames
        are read through their own `evaluate`, and each anchor carries the *frame
        ordinal* so the click can be aimed back at the frame it was seen in.

        A frame is untrusted content, so nothing here is more trusted for coming
        out of one: the anchors go through the same gate as the main document's.
        """
        anchors = await self._collect_banner_anchors(page)
        return discover_banner_candidates(
            anchors,
            page_url=page_url,
            scope=self.config.scope,
            include_iframes=self.config.include_iframes,
        )

    async def _collect_banner_anchors(self, page) -> List[Any]:
        """
        Read promotional anchors from the main document and, when enabled, frames.

        Returns the raw anchor mappings with a `frame_index` stamped on each, so a
        downstream refusal can be attributed to the frame it came from. Main-frame
        anchors are index 0; child frames follow `page.frames` order.

        A frame that cannot be read (cross-origin teardown, a detached frame, a
        navigation in flight) is skipped rather than failing the scan: one
        unreadable frame must not hide the banners in the others.
        """
        out: List[Any] = []
        try:
            raw = await page.evaluate(self._DISCOVER_BANNERS_JS)
        except Exception:
            raw = []
        for anchor in raw if isinstance(raw, list) else []:
            if isinstance(anchor, dict):
                entry = dict(anchor)
                entry.setdefault("frame_index", 0)
                out.append(entry)

        if not self.config.include_iframes:
            return out

        # `page.frames` includes the main frame first, so index 0 is the document
        # already read above. Child ordinals therefore start at 1 -- numbering them
        # from 0 would collide with the main document and make `_frame_for` resolve
        # an iframe banner back to the top-level page.
        for index, frame in enumerate(self._child_frames(page), start=1):
            try:
                raw = await frame.evaluate(self._DISCOVER_BANNERS_JS)
            except Exception:
                continue
            for anchor in raw if isinstance(raw, list) else []:
                if isinstance(anchor, dict):
                    entry = dict(anchor)
                    entry["frame_index"] = index
                    out.append(entry)
        return out

    @staticmethod
    def _child_frames(page) -> List[Any]:
        """
        The page's child frames, in the order a candidate's ordinal counts them.

        `page.frames` is documented to hold the main frame first, but that ordering
        is an implementation contract the click depends on, so it is checked here
        rather than assumed: if the main frame is ever not first, the ordinals would
        silently point every iframe candidate at the wrong frame. A page whose main
        frame cannot be identified in the list contributes no child frames -- the
        scan loses frames it cannot number correctly, which is visible in the
        report's scan-scope line, rather than mis-numbering them.
        """
        frames = list(getattr(page, "frames", []) or [])
        if not frames:
            return []
        main = getattr(page, "main_frame", None)
        if main is None:
            # No way to tell which frame is the document; number none of them.
            return []
        if frames[0] is main:
            return frames[1:]
        return [f for f in frames if f is not main]

    def _frame_for(self, page, frame_index: int) -> Any:
        """
        Resolve a candidate's frame ordinal back to the live frame.

        Returns the page itself for index 0 (so callers can use one code path) and
        None when the ordinal no longer resolves -- a frame can be removed between
        discovery and the click, and aiming at a stale frame would mis-target the
        cursor.
        """
        if frame_index <= 0:
            return page
        frames = self._child_frames(page)
        if 0 < frame_index <= len(frames):
            return frames[frame_index - 1]
        return None

    async def _walk_outbound_funnel(
        self,
        context,
        page,
        cursor: Cursor,
        level: EvasionLevel,
        plan,
        url: str,
        result: VisitResult,
    ) -> bool:
        """
        Maybe click a promotional banner and engage with where it lands.

        Runs after the visitor has read the arrival page, because that is when a
        person notices a banner. Nothing here can leave the authorized scope: the
        destination was admitted by `_discover_banners` through the outbound gate,
        and it is re-checked immediately before the navigation so the check that
        authorized it and the request that uses it cannot drift apart.

        Returns True when the visitor actually departed for the destination, so
        the caller can end the journey there. A refused or unreachable banner is
        recorded on the visit and returns False -- the funnel is an observation
        layered on the posture, not a reason to fail a rung.
        """
        candidates = await self._discover_banners(page, url)
        if not candidates:
            result.evidence.append("no promotional banner found on the page")
            return False

        usable = [c for c in candidates if c.authorized]
        refused = [c for c in candidates if not c.authorized]
        if refused:
            # A banner that exists but was refused is a finding in its own right:
            # the page points somewhere the operator excluded. Recorded so it is
            # visible, never followed.
            result.evidence.append(
                f"{len(refused)} banner(s) refused by the campaign gate, "
                f"e.g. {refused[0].url!r}"
            )
        if not usable:
            result.evidence.append(
                "every promotional banner on this page was on an excluded "
                "campaign host; nothing was followed"
            )
            return False

        outbound = plan_outbound_visit(
            self.config.outbound_campaign_rate_pct, usable, self._rng
        )
        if not outbound.triggered or not outbound.campaign_url:
            result.evidence.append(
                f"saw {len(usable)} followable banner(s); CTR roll did not trigger"
            )
            return False

        destination = outbound.campaign_url
        event = CampaignEvent(
            campaign_url=destination,
            first_party=outbound.first_party,
            selector_hint=outbound.selector_hint,
            frame_index=outbound.frame_index,
        )
        result.campaign = event

        # Re-check right before the navigation. The gate is the only thing between
        # this and an unauthorized request, and re-reading it here means a banner
        # whose href changed between discovery and click cannot be followed.
        #
        # This is the funnel's own decision, so it asks the funnel question
        # (`authorize_outbound`), not the navigation one: a destination outside the
        # target is followed by default now, unless the operator excluded it.
        if not self.config.scope.authorize_outbound(destination):
            event.skipped_reason = "outbound destination was refused by the campaign gate"
            event.refused_by_scope = True
            result.evidence.append(f"refused excluded campaign link {destination!r}")
            return False

        return await self._visit_campaign_destination(
            context, page, cursor, level, destination, event, result
        )

    async def _visit_campaign_destination(
        self,
        context,
        page,
        cursor: Cursor,
        level: EvasionLevel,
        destination: str,
        event: CampaignEvent,
        result: VisitResult,
    ) -> bool:
        """
        Click the banner, then behave like a reader on the landing page.

        Driven as a click wherever the anchor can be found and pressed -- a typed
        URL is a different, rarer behavior and arrives with no Referer, which is
        the stronger tell. The direct navigation is the fallback, and the event
        records which one happened so the report does not overstate the fidelity.

        Returns True when the visitor reached the destination, so the caller stops
        the journey there.
        """
        opened = None
        try:
            # Aim at the frame the banner was discovered in. A heading-less click
            # would press the top-level document's anchor of the same href -- or
            # none at all -- when the real banner lives in an iframe.
            target_frame = self._frame_for(page, event.frame_index)
            if target_frame is None:
                event.skipped_reason = "the banner's frame was gone before the click"
                return False
            opened = await self._click_or_open_banner(
                page, cursor, destination, event, target_frame
            )
            if opened is None or not opened.loaded:
                event.skipped_reason = event.skipped_reason or "banner could not be opened"
                return False

            event.landed = True
            status, headers, body = opened.status, opened.headers, opened.body

            landing = classify_response(status, headers, body)
            event.landing_status = status
            event.landing_verdict = landing.verdict
            result.pages_loaded += 1
            # A destination that was challenged or blocked is still a funnel
            # finding -- the campaign link resolved, but the landing did not serve
            # the offer. Recorded on the event rather than folded into the visit's
            # verdict, which belongs to the rung's own posture.
            if landing.detected:
                event.skipped_reason = f"landing page was {landing.verdict}"
                result.evidence.append(
                    f"campaign landing {destination!r} was {landing.verdict}"
                )
                # The visitor did depart -- the destination answered, it just
                # refused to serve the offer -- so the journey still ends here.
                return True

            # Spend a plausible amount of attention on the offer, with the pointer
            # and scroll moving the way they would on any page.
            target_dwell = campaign_dwell(self._rng, self._behavior)
            deadline = time.monotonic() + target_dwell
            event.glances = 0
            event.scroll_bursts = 0
            try:
                await cursor.glance()
                event.glances += 1
                bursts = self._rng.randint(
                    self._behavior.campaign_scroll_bursts_min,
                    self._behavior.campaign_scroll_bursts_max,
                )
                event.scroll_bursts = await cursor.scroll(bursts, deadline=deadline)
            except Exception:
                pass
            remaining = max(0.0, deadline - time.monotonic())
            event.dwell_s = await spend_dwell(
                remaining,
                slice_s=self._behavior.sleep_slice_s,
                cancelled=self._cancelled,
            )
            result.evidence.append(
                f"campaign click-through to {destination!r} "
                f"({event.dwell_s:.1f}s, {event.scroll_bursts} scroll bursts)"
            )
            return True
        except Exception as exc:
            event.skipped_reason = f"{type(exc).__name__}: {exc}"
            return False
        finally:
            # Close the landing tab, not the page under audit. A destination that
            # opened in a new tab must not be left open, or a long run accumulates
            # tabs; an in-place navigation leaves `page` as the destination, and
            # the caller ends the visit there anyway.
            landing_page = getattr(opened, "page", None)
            if (
                opened is not None
                and landing_page is not None
                and landing_page is not page
            ):
                try:
                    await landing_page.close()
                except Exception:
                    pass

    async def _click_or_open_banner(
        self, page, cursor: Cursor, destination: str, event: CampaignEvent, frame=None
    ) -> Optional["_OpenResult"]:
        """
        Press the banner's anchor, or navigate to it if it cannot be pressed.

        A promotion usually opens in a new tab (`target="_blank"`), but it may also
        navigate in place, so both shapes are handled: a response listener is
        attached to the whole context *before* the click, and afterwards the result
        is read from whichever page actually loaded the destination. Attaching the
        listener first is what makes the in-place case observable at all -- a
        `page.goto` afterwards would issue a second, synthetic request and measure
        that instead of the click.

        `frame` is where the anchor lives: the page itself for a main-document
        banner, or a child frame for one served from an iframe. The anchor lookup
        and the locator both run against that frame, and the pointer is moved using
        the coordinates Playwright reports -- for a frame element those are already
        translated into the top-level viewport, so the same cursor motion works in
        both cases and the mouse stays a page-level input.

        The result records whether a real press happened, because a typed-URL hop
        is not the same evidence as a click.
        """
        if frame is None:
            frame = page
        handler = _OpenResult()

        captured: Dict[str, Any] = {}

        def _on_response(response) -> None:
            if captured.get("response") is not None:
                return
            try:
                if response.url.split("#", 1)[0].rstrip("/") == destination.rstrip("/"):
                    captured["response"] = response
            except Exception:
                pass

        context = page.context
        context.on("response", _on_response)

        index = -1
        try:
            index = await frame.evaluate(self._FIND_ANCHOR_JS, destination)
        except Exception:
            index = -1

        try:
            if index is not None and index >= 0:
                locator = frame.locator("a[href]").nth(index)
                before = len(context.pages)
                if await cursor.click_locator(locator):
                    event.interaction = "clicked"
                    # Give the click time to open a tab or navigate in place, and
                    # for the response listener to see the destination land.
                    deadline = time.monotonic() + 6.0
                    while time.monotonic() < deadline:
                        if captured.get("response") is not None:
                            break
                        await asyncio.sleep(0.1)

                    pages = context.pages
                    # Prefer the page that actually holds the destination; a popup
                    # is the usual shape, but an in-place navigation leaves `page`
                    # as the one that navigated.
                    landing_page = page
                    if len(pages) > before and pages[-1] is not page:
                        landing_page = pages[-1]
                        try:
                            await landing_page.wait_for_load_state(
                                "domcontentloaded", timeout=15_000
                            )
                        except Exception:
                            pass

                    response = captured.get("response")
                    if response is None:
                        # The click landed but the response was not observed; the
                        # page still holds the destination, so its content is the
                        # evidence rather than a second request.
                        try:
                            await landing_page.wait_for_load_state(
                                "domcontentloaded", timeout=15_000
                            )
                        except Exception:
                            pass
                    await _capture_response(handler, landing_page, response)
                    return handler
        except Exception:
            # Any failure to click falls through to the direct navigation, which
            # is recorded as such rather than as a click.
            handler = _OpenResult()
        finally:
            try:
                context.remove_listener("response", _on_response)
            except Exception:
                pass

        # Fallback: request the destination directly. Recorded as such, because a
        # typed-URL hop is not the same evidence as a click.
        try:
            response = await page.goto(
                destination, wait_until="domcontentloaded", timeout=30_000
            )
            event.interaction = "navigated"
            await _capture_response(handler, page, response)
            return handler
        except Exception as exc:
            event.skipped_reason = f"navigation failed: {type(exc).__name__}: {exc}"
            return None

    async def _maybe_type(
        self, page, cursor: Cursor, result: VisitResult, deadline: Optional[float] = None
    ) -> None:
        """
        Find a field, hover it, and type with a human cadence.

        The cursor moves to the field before the click so the pointer has a
        trajectory into the control, rather than appearing on it.
        """
        try:
            locator = page.locator("input[type=search], input[type=text], textarea").first
            if await locator.count() == 0:
                return
            box = await locator.bounding_box()
            if box:
                await cursor.move_to(
                    box["x"] + box["width"] / 2,
                    box["y"] + box["height"] / 2,
                    min_distance=8.0,
                )
            text = self._rng.choice(["pricing", "how to", "features", "support", "docs"])
            if await cursor.type_into(locator, text, deadline=deadline):
                result.evidence.append(f"typed {text!r} into a form field")
        except Exception:
            return

    async def _pick_next_url(self, page, plan) -> Optional[str]:
        """Choose the next in-site link, or a configured path."""
        if plan.follow_links:
            try:
                hrefs = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
            except Exception:
                hrefs = []
            parsed_target = urlparse(self.config.target_url)
            same_site = [
                h
                for h in hrefs
                if h
                and urlparse(h).netloc == parsed_target.netloc
                and urlparse(h).scheme in ("http", "https")
            ]
            if same_site:
                return self._rng.choice(same_site)
        paths = list(self.config.paths)
        if paths:
            return urljoin(self.config.target_url, self._rng.choice(paths))
        return None

    # -- level orchestration ----------------------------------------------

    async def _run_level(self, level: EvasionLevel, schedule) -> LevelResult:
        lr = LevelResult(level=level, scheduled=schedule.count, started_at=time.time())
        self._progress(
            event="level_start",
            level_id=level.id,
            level_name=level.name,
            scheduled=schedule.count,
        )

        started_at = time.time()
        semaphore = asyncio.Semaphore(max(1, self._limits.max_concurrency))

        # One browser for the whole rung, when reuse is on. Opened before any
        # visitor is scheduled so the launch cost is paid once, and released after
        # the last one, so visitors share it without racing its lifetime.
        #
        # A geoip rung that rotates IPs cannot share: its timezone and locale are
        # baked in at launch from the visitor's own exit IP, so one shared browser
        # would paint every visitor with the first visitor's geography. Those
        # rungs launch per visit instead (the proxy itself is per-context, so IP
        # rotation is unaffected either way).
        can_share = self.config.reuse_browser and not self._launch_needs_own_proxy(level)
        if level.client == "browser" and can_share:
            try:
                browser, manager = await self._open_browser(level)
                self._level_browser = browser
                self._level_browser_handle = (browser, manager)
            except Exception as exc:
                # Every visit would fail the same way; leave the per-visit path to
                # record the error so the rung's failures stay visible.
                self._level_browser = None
                self._level_browser_handle = None
                self._progress(
                    event="notice",
                    message=(
                        f"{level.name} could not launch a shared browser "
                        f"({type(exc).__name__}: {exc}); each visit will try to "
                        f"launch its own."
                    ),
                )

        async def run_one(index: int, arrival) -> None:
            if self._cancelled():
                return
            while True:
                delay = arrival.at.timestamp() - time.time()
                if delay <= 0:
                    break
                # Sleep in slices so cancellation is responsive on a 24h schedule,
                # and re-read the clock each pass so a paused run catches up.
                await asyncio.sleep(min(delay, 5.0))
                if self._cancelled():
                    return
            if self._cancelled():
                return

            async with semaphore:
                if self._cancelled():
                    return
                visit = await self._run_one_visit(level, index)
                if visit is not None:
                    lr.visits.append(visit)
                    self._progress(event="visit", level_id=level.id, visit=visit.to_dict())
                    if visit.verdict == Verdict.ERROR and visit.launcher_error:
                        self._consecutive_errors += 1
                    else:
                        self._consecutive_errors = 0
                    if (
                        self._limits.abort_after_consecutive_errors
                        and self._consecutive_errors
                        >= self._limits.abort_after_consecutive_errors
                    ):
                        lr.aborted = True
                        lr.abort_reason = (
                            f"aborted after {self._consecutive_errors} consecutive "
                            f"transport errors"
                        )
                        raise SafetyStop(lr.abort_reason)

        tasks = []
        try:
            for index, arrival in enumerate(schedule.arrivals):
                tasks.append(asyncio.create_task(run_one(index, arrival)))
            if tasks:
                await asyncio.gather(*tasks)
        except SafetyStop as exc:
            lr.aborted = True
            lr.abort_reason = str(exc)
        except asyncio.CancelledError:
            lr.aborted = True
            lr.abort_reason = "cancelled"
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await self._close_browser(getattr(self, "_level_browser_handle", None))
            self._level_browser = None
            self._level_browser_handle = None

        lr.finished_at = time.time()
        lr.artifacts = list(self._artifacts_by_level.get(level.id, []))
        self._progress(event="level_end", level_id=level.id, level=lr.to_dict())
        return lr

    async def _run_one_visit(self, level: EvasionLevel, index: int) -> Optional[VisitResult]:
        # The journey is only planned at full fidelity on a rung that claims
        # behavior. A rung below it sends a single direct request, so the arrival
        # source, referer, dwell, scroll and typing it "has" cannot confound the
        # axis that rung is actually testing.
        plan = plan_visit(self.config.journey, self._rng, behavior=level.is_behavioral)
        url = self._rng.choice(self._candidate_paths())
        if plan.source != ArrivalSource.DIRECT:
            plan.referer = build_arrival_referer(plan.source, self.config.target_url, self._rng)

        # A proxy is acquired only for a rung that is *defined* by rotating the
        # exit IP. Earlier rungs must go out on this host's own address, otherwise
        # L3's verdict would be the product of an IP the rung never claimed to use.
        proxy_session, skip_reason = (None, None)
        if level.requires_rotation:
            proxy_session, skip_reason = self._acquire_proxy()
        if skip_reason:
            visit = VisitResult(
                visitor_index=index,
                level_id=level.id,
                started_at=time.time(),
                finished_at=time.time(),
                verdict=Verdict.ERROR,
                reason=skip_reason,
            )
            return visit

        try:
            if level.client == "http":
                headers = {"User-Agent": "python-urllib/3"}
                headers.update(self.config.extra_headers)
                visit = await self._visit_http(level, plan, url, headers)
                visit.visitor_index = index
                return visit
            return await self._run_browser_visit(level, plan, url, proxy_session, index)
        except ScopeViolation as exc:
            # A ScopeViolation no longer means "this one URL was out of scope" --
            # the guard handles that per-request, by aborting it. It now means the
            # scope gate could not be enforced at all, which is a condition under
            # which *no* visit is trustworthy. Fail the run closed rather than
            # collect verdicts from traffic that was never contained.
            raise SafetyStop(f"scope gate unavailable: {exc}") from exc
        finally:
            self._release_proxy(proxy_session)

    async def _open_browser(
        self,
        level: EvasionLevel,
        proxy_session: Optional[Any] = None,
    ) -> Any:
        """
        Launch the level's browser.

        Resolved inside the guard: the import is lazy, and a host without camoufox
        installed should record an error for this rung rather than let an
        ImportError escape and kill the whole audit.

        `proxy_session` is passed through so a geoip rung derives its timezone and
        locale from the proxy's verified exit rather than from this host -- see
        `_launch_options`.
        """
        from ..async_api import AsyncCamoufox

        options = self._launch_options(level, proxy_session)
        launch_kwargs = {k: v for k, v in options.items() if k != "persistent_context"}
        # The audit gives each visitor a fresh context, so no rung can carry a
        # profile directory: not the persistent rung (which is named for it) and
        # not the ones below (which must stay throwaway identities). Drop it, and
        # say so for the rung whose name promises it.
        launch_kwargs.pop("user_data_dir", None)
        if level.is_persistent:
            self._note_persistence_unavailable(level)

        # The proxy also reaches the *launch* for a geoip rung. Launching with
        # `geoip=<exit_ip>` needs no proxy to resolve it, but passing the session
        # lets Camoufox use the already-verified exit instead of re-deriving it,
        # which could race the gateway into a different exit than the context will
        # use. The context still carries its own proxy for the traffic itself.
        if proxy_session is not None:
            launch_kwargs["proxy_session"] = proxy_session

        manager = AsyncCamoufox(**launch_kwargs)
        return await manager.__aenter__(), manager

    async def _close_browser(self, handle: Optional[Tuple[Any, Any]]) -> None:
        if handle is None:
            return
        _, manager = handle
        try:
            await manager.__aexit__(None, None, None)
        except Exception:
            pass

    async def _run_browser_visit(self, level, plan, url, proxy_session, index) -> VisitResult:
        if level.requires_rotation and proxy_session is None:
            # This rung's whole claim is "a fresh exit IP per visitor". With no
            # pool there is nothing to rotate, so say so rather than let a
            # direct-IP result be read as an IP-rotation verdict.
            self._note_no_proxy(level)

        # One browser per rung by default. Launching per visit would mean 100
        # Firefox processes for 100 visitors, which is both the dominant cost of a
        # run and a resource shape no human population produces.
        if self._level_browser is not None:
            browser = self._level_browser
            try:
                return await self._visit_browser(
                    browser, level, plan, url, index, proxy_session
                )
            except ScopeViolation:
                raise
            except Exception as exc:
                return self._launcher_failure(level, index, exc)

        if level.client == "browser":
            self._note_browser_reuse(level)
        try:
            browser, manager = await self._open_browser(level, proxy_session)
        except ScopeViolation:
            raise
        except Exception as exc:
            return self._launcher_failure(level, index, exc)

        try:
            return await self._visit_browser(
                browser, level, plan, url, index, proxy_session
            )
        except ScopeViolation:
            raise
        except Exception as exc:
            return self._launcher_failure(level, index, exc)
        finally:
            await self._close_browser((browser, manager))

    @staticmethod
    def _launcher_failure(level: EvasionLevel, index: int, exc: BaseException) -> VisitResult:
        return VisitResult(
            visitor_index=index,
            level_id=level.id,
            started_at=time.time(),
            finished_at=time.time(),
            verdict=Verdict.ERROR,
            reason=f"browser launch failed: {type(exc).__name__}: {exc}",
            launcher_error=f"{type(exc).__name__}: {exc}",
        )

    # -- top level ---------------------------------------------------------

    async def run(self) -> AuditReport:
        report = AuditReport(config=self.config)
        problems = self.config.validate()
        if problems:
            report.aborted = True
            report.abort_reason = "invalid configuration: " + "; ".join(problems)
            report.finished_at = time.time()
            return report

        if self.config.single_level_mode:
            self._note_single_level(self.config.selected_levels()[0])

        if self.config.enable_outbound_funnel:
            # Say up front when the funnel cannot run, rather than let an operator
            # read an empty funnel as "no banner worked". A rake of only
            # non-behavioral rungs cannot exercise the click-through at all.
            if not any(level.is_behavioral for level in self.config.selected_levels()):
                self._note_funnel_skipped(self.config.selected_levels()[-1])

        selected = self.config.selected_levels()
        for position, level in enumerate(selected):
            if self._cancelled():
                report.aborted = True
                report.abort_reason = "cancelled"
                break
            # Every rung gets its own window, built here so it is anchored to the
            # moment that rung starts rather than to the run's start.
            #
            # Reusing one schedule across the ladder was a design error with two
            # effects, both severe. The rungs run in sequence, so by the time the
            # second rung began, most of the shared window was already in the past
            # and its visitors fired immediately -- every rung above L0 arrived as
            # a burst, the opposite of human. And the first rung's arrival times
            # were reused verbatim, so a log that correlated by timestamp would see
            # a python-urllib client and a masked browser hitting the same pages in
            # the same seconds, which is the ladder's own signature.
            #
            # Re-anchoring fixes both: each rung spreads its own visitors across
            # its own window, so no arrival time is shared between postures.
            schedule = build_schedule(self.config.schedule_config(), self._rng)
            if position == 0:
                report.schedule_warnings = list(schedule.warnings)
            level_result = await self._run_level(level, schedule)
            report.levels.append(level_result)
            if level_result.aborted:
                report.aborted = True
                report.abort_reason = level_result.abort_reason
                break
            if position < len(selected) - 1 and self.config.cooldown_between_levels_s:
                # Breathing room between rungs: an audit that hammers straight
                # through confuses its own rate-limit findings.
                cooldown = self.config.cooldown_between_levels_s
                while cooldown > 0 and not self._cancelled():
                    slice_s = min(cooldown, 2.0)
                    await asyncio.sleep(slice_s)
                    cooldown -= slice_s

        report.finished_at = time.time()
        return report


def run_audit(config: AuditConfig, **kwargs) -> AuditReport:
    """Synchronous entry point, for the CLI."""
    return asyncio.run(AuditRunner(config, **kwargs).run())
