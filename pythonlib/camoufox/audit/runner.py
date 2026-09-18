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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .behavior import BehaviorModel, Cursor, spend_dwell
from .config import AuditConfig, AuditReport, LevelResult, VisitResult
from .detection import VENDOR_SIGNATURES, Verdict, classify_response
from .evasion import EvasionLevel
from .journey import ArrivalSource, build_arrival_referer, plan_visit
from .schedule import build_schedule
from .scope import ScopeViolation

__all__ = ["AuditRunner", "SafetyStop"]


class SafetyStop(RuntimeError):
    """A safety ceiling was reached; the audit stopped deliberately."""


#: Headers the rung intends to send on its own navigation.
#:
#: Named here so the referer route knows which header names it may override and
#: which user agents Camoufox already sets -- re-applying those would be the
#: inconsistency the nav/context split exists to avoid.
_REFERER_HEADER = "Referer"


def _merge_navigation_headers(
    existing: Optional[Dict[str, str]],
    wanted: Dict[str, str],
) -> Dict[str, str]:
    """
    Overlay the rung's navigation headers onto a request's own headers.

    Preserves the browser's header order for everything it already sent (only the
    names that are being overridden are replaced in place; new names are appended),
    because a reordered navigation header set is itself a fingerprint.
    """
    merged: Dict[str, str] = dict(existing or {})
    lowered = {k.lower(): k for k in merged}
    for name, value in wanted.items():
        key = lowered.get(name.lower())
        if key is not None:
            merged[key] = value
        else:
            merged[name] = value
            lowered[name.lower()] = name
    return merged


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
        self._limiter = _Limiter(config.limits.max_rps, config.limits.max_requests)
        self._proxy_counts: Dict[str, int] = {}
        self._consecutive_errors = 0
        self._virtual_display_used = False
        self._geoip_missing_noted = False
        self._no_proxy_noted = False
        self._headless_override_noted = False
        self._persistence_noted = False
        self._single_level_noted = False
        self._browser_reuse_noted = False
        self._rotator = None
        self._behavior = BehaviorModel()
        #: The level-scoped browser when `reuse_browser` is on, or None when each
        #: visit launches (and closes) its own.
        self._level_browser: Optional[Any] = None
        self._level_browser_handle: Optional[Tuple[Any, Any]] = None
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
        cap = self.config.limits.max_per_proxy
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
        status, resp_headers, body, error = await asyncio.to_thread(
            self._http_fetch, url, send_headers
        )
        result.latencies.append(time.monotonic() - started)
        result.requests_made = 1
        result.finished_at = time.time()
        result.http_status = status

        if error:
            result.launcher_error = error
            result.reason = error
            result.verdict = Verdict.ERROR
            return result

        verdict = classify_response(status, resp_headers, body)
        result.verdict = verdict.verdict
        result.vendors = verdict.vendors
        result.reason = verdict.reason
        result.evidence = verdict.evidence
        return result

    def _http_fetch(
        self, url: str, headers: Dict[str, str]
    ) -> Tuple[Optional[int], Dict[str, str], str, Optional[str]]:
        """Synchronous fetch, run in a thread so the event loop stays responsive."""
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
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
            await self._drive_journey(context, level, plan, url, nav_headers, result)
        finally:
            try:
                await context.close()
            except Exception:
                pass

        result.finished_at = time.time()
        return result

    async def _install_navigation_headers(self, page, url: str, headers, referer) -> None:
        """
        Apply the rung's navigation headers to the first navigation only.

        Two constraints shape this. The navigation-only headers (Sec-Fetch-*,
        Accept, Cache-Control) must reach the document request without being
        stamped on every subresource, which rules out context-level
        `extra_http_headers`. And the Referer must be set for the *arrival* and
        then left alone: a browser derives the referer for every later navigation
        from the page it is leaving, and overriding the header set wholesale would
        throw that away -- turning a natural link-follow into a bare request.

        So the route intercepts exactly one request (the first navigation) and then
        removes itself. Everything after that is the browser's own header set,
        untouched.
        """
        wanted = dict(headers or {})
        if referer:
            wanted[_REFERER_HEADER] = referer
        if not wanted:
            return

        target_host = urlparse(url).netloc
        done = False

        async def handler(route, request) -> None:
            nonlocal done
            consumed = False
            try:
                if (
                    not done
                    and request.is_navigation_request()
                    and urlparse(request.url).netloc == target_host
                ):
                    consumed = True
                    await route.continue_(
                        headers=_merge_navigation_headers(request.headers, wanted)
                    )
                    return
                await route.continue_()
            except Exception:
                # A route that raises would leave the request hanging; let it
                # through unmodified rather than stall the visit.
                try:
                    await route.continue_()
                except Exception:
                    pass
            finally:
                if consumed:
                    done = True
                    # Only the first navigation is ours; later ones need the
                    # browser's own Referer, which this route would clobber.
                    try:
                        await page.unroute("**/*", handler)
                    except Exception:
                        pass

        try:
            await page.route("**/*", handler)
        except Exception:
            pass

    async def _drive_journey(
        self,
        context,
        level: EvasionLevel,
        plan,
        url: str,
        nav_headers: Dict[str, str],
        result: VisitResult,
    ) -> None:
        """Walk one visitor through their planned session, honoring the plan."""
        page = await context.new_page()
        try:
            await self._install_navigation_headers(page, url, nav_headers, plan.referer)

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
        semaphore = asyncio.Semaphore(max(1, self.config.limits.max_concurrency))

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
                        self.config.limits.abort_after_consecutive_errors
                        and self._consecutive_errors
                        >= self.config.limits.abort_after_consecutive_errors
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
            visit = VisitResult(
                visitor_index=index,
                level_id=level.id,
                started_at=time.time(),
                finished_at=time.time(),
                verdict=Verdict.ERROR,
                reason=str(exc),
                launcher_error="ScopeViolation",
            )
            return visit
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