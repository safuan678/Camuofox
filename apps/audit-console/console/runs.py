"""
Running audits for the console: one session per request, streamed as it happens.

An audit is slow by design -- arrivals are spread over a window rather than fired at
once -- so the console cannot answer with a single blocking response. Each session
owns a thread running its own event loop, appends progress events as the runner
emits them, and keeps the finished report for export.

The scope gate is the important part. This console can be hosted, and a hosted
console that will audit any URL it is handed is an open request forwarder: anyone
could point it at a third party and use it to send traffic from our address. So the
session is constructed with an explicit allow-list of hosts, and any target not in
it is refused before a single request leaves. The hosted build passes only its own
demo WAF; a local operator can pass their own hosts deliberately.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ._engine import (
    AuditConfig,
    AuditRunner,
    SafetyLimits,
    ScopeViolation,
    TargetScope,
    levels_up_to,
)
from ._engine.report import build_findings, render_text, write_report
from .proxies import ROTATION_LEVEL_IDS, ProxyPoolStore

#: Ceilings the console applies regardless of what the request asks for. The
#: console is shared, so the brake cannot be something the caller sets.
CONSOLE_LIMITS = SafetyLimits(
    max_requests=500,
    max_concurrency=6,
    max_rps=25.0,
    max_arrivals_per_minute=120,
    abort_after_consecutive_errors=15,
)

#: How many audits may run at the same time. `CONSOLE_LIMITS.max_concurrency`
#: bounds the visitors *within* one audit; without a bound *across* audits, N
#: concurrent requests each get their own thread and their own six visitors, so
#: the console's real concurrency -- and its outbound request rate -- is Nx6
#: rather than 6. A shared ceiling is the difference between a bounded service
#: and a request amplifier, so it is enforced here, not per session.
CONSOLE_MAX_RUNNING_AUDITS = 3

#: How long a request waits for an admission slot before being refused. Bounded
#: rather than infinite so a saturated console answers a caller instead of
#: parking an HTTP worker thread until something else finishes.
CONSOLE_ADMISSION_TIMEOUT_S = 30.0

#: Per-IP request budgets for the routes that cost something, over
#: `RATE_LIMIT_WINDOW_S`. Read-only polls are absent on purpose and unlimited.
#: This is a flood brake, not the admission control -- that is the semaphore,
#: which is exact about concurrency. Deliberately loose: a legitimate operator
#: restarting a few audits must never trip it.
RATE_LIMIT_PER_ROUTE = {"/api/audits": 30, "/api/proxy": 30}
RATE_LIMIT_WINDOW_S = 60.0
#: Cap on the number of (ip, route) buckets kept, so a caller cycling source
#: addresses cannot grow the table without bound.
RATE_TABLE_MAX = 4096


class TooManyAudits(RuntimeError):
    """The console is already running as many audits as it allows at once."""


MAX_VISITORS = 400
#: L6 is the end of the engine's ladder; nothing above it exists to climb.
MAX_LEVELS = 6


def browser_available() -> bool:
    """
    Whether an installed camoufox can drive the browser rungs.

    Levels 1 and up launch a real Camoufox; L0 does not. The console is built to
    run on a bare Python, so "no browser here" is a normal state, not an error --
    it caps the ladder at L0 and says so, rather than accepting a max_level and
    then reporting a launch failure for every rung.
    """
    try:
        import camoufox.async_api  # noqa: F401
    except Exception:
        return False
    return True


class TargetNotAllowed(RuntimeError):
    """The requested target is not on this console's allow-list."""


@dataclass
class AuditSession:
    """One console-initiated audit, its progress log, and its result."""

    id: str
    target_url: str
    visitor_count: int
    duration_hours: float
    max_level: int
    seed: Optional[int]
    #: The rungs actually run, after a missing browser or pool pruned some.
    levels: List[int] = field(default_factory=list)
    #: True when the request asked for one rung rather than the ladder.
    single_level_mode: bool = False
    #: Redacted description of the pool, or None. Never carries a password.
    proxy_summary: Optional[Dict[str, Any]] = None
    status: str = "running"  # running | done | failed | cancelled
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    events: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[Any] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cancel: Optional[threading.Event] = field(default=None, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)
    #: Called exactly once when this session stops running, whatever the outcome.
    #: The service uses it to give back the admission slot it took to start this
    #: audit; a crash must not leak that slot, or the console wedges shut.
    on_finish: Optional[Callable[[], None]] = field(default=None, repr=False)
    _finished: bool = field(default=False, repr=False)

    # -- progress ----------------------------------------------------------

    def _append(self, event: Dict[str, Any]) -> None:
        with self._lock:
            event = {"seq": len(self.events), **event}
            self.events.append(event)

    def events_since(self, seq: int) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["seq"] >= seq]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "target_url": self.target_url,
                "status": self.status,
                "error": self.error,
                "visitor_count": self.visitor_count,
                "duration_hours": self.duration_hours,
                "max_level": self.max_level,
                "levels": self.levels,
                "single_level_mode": self.single_level_mode,
                "proxy": self.proxy_summary,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "event_count": len(self.events),
                "summary": self._summary(),
            }

    def _summary(self) -> Optional[Dict[str, Any]]:
        if self.report is None:
            return None
        report = self.report
        levels = []
        for lr in report.levels:
            entry = lr.to_dict()
            # The result carries what happened; the rung definition carries what
            # it *means*. The report needs both to be readable.
            entry["description"] = lr.level.description
            entry["isolates"] = lr.level.isolates
            levels.append(entry)
        return {
            "total_requests": report.total_requests,
            "navigations": report.navigations,
            "subrequests": report.subrequests,
            "blocked_hosts": report.blocked_hosts,
            "total_visits": report.total_visits,
            "findings": build_findings(report),
            "first_effective_level": (
                report.first_effective_level().level.name
                if report.first_effective_level()
                else None
            ),
            "aborted": report.aborted,
            "abort_reason": report.abort_reason,
            "levels": levels,
        }

    # -- execution ---------------------------------------------------------

    def start(self, config: AuditConfig) -> None:
        self._cancel = threading.Event()
        self._thread = threading.Thread(
            target=self._run, args=(config, self._cancel), daemon=True
        )
        self._thread.start()

    def cancel(self) -> bool:
        if self._cancel is not None and self.status == "running":
            self._cancel.set()
            return True
        return False

    def _run(self, config: AuditConfig, cancel: threading.Event) -> None:
        # A fresh loop in this thread: the session must not borrow the HTTP
        # server's loop, and asyncio.run cannot be called from a running one.
        try:
            asyncio.run(self._run_async(config, cancel))
        except Exception as exc:  # a crash must be visible, not a stuck session
            self.error = f"{type(exc).__name__}: {exc}"
            self._append({"event": "error", "message": self.error})
            self.status = "failed"
        finally:
            self.finished_at = time.time()
            if self.status == "running":
                self.status = "done"
            self._append({"event": "end", "status": self.status})
            self._release_slot()

    def _release_slot(self) -> None:
        """
        Hand the admission slot back, exactly once.

        Guarded by `_finished` because both the normal completion path and an
        explicit cancellation can reach here; releasing a `BoundedSemaphore`
        twice would let one audit's completion admit two more.
        """
        with self._lock:
            if self._finished:
                return
            self._finished = True
            callback = self.on_finish
        if callback is not None:
            callback()

    async def _run_async(self, config: AuditConfig, cancel: threading.Event) -> None:
        runner = AuditRunner(
            config,
            on_progress=self._append,
            cancel_event=cancel,
        )
        report = await runner.run()
        self.report = report
        if report.aborted:
            self.status = "failed"
            self.error = report.abort_reason

    # -- export ------------------------------------------------------------

    def export(self, fmt: str) -> Optional[str]:
        if self.report is None:
            return None
        if fmt == "json":
            import json

            payload = self.report.to_dict()
            payload["findings"] = build_findings(self.report)
            return json.dumps(payload, indent=2, default=str)
        if fmt == "text":
            return render_text(self.report)
        return None

    def export_html(self) -> Optional[str]:
        if self.report is None:
            return None
        from ._engine.report import render_html

        return render_html(self.report)


class AuditService:
    """Holds the sessions and the allow-list that scopes them."""

    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        demo_target: str = "",
    ) -> None:
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or [])]
        self.demo_target = demo_target
        self.proxies = ProxyPoolStore()
        self._sessions: Dict[str, AuditSession] = {}
        self._lock = threading.Lock()
        self._cap = 20
        # Blocks when `CONSOLE_MAX_RUNNING_AUDITS` audits are already in flight,
        # released by whichever session finishes first. Sized once here rather
        # than per session, because the thing being bounded is the service.
        self._admission = threading.BoundedSemaphore(CONSOLE_MAX_RUNNING_AUDITS)
        self._rate: Dict[Any, List[float]] = {}
        self._rate_lock = threading.Lock()

    def running_audits(self) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.status == "running")

    def _evict_locked(self) -> None:
        """
        Trim finished sessions to `_cap`, never a running one. Caller holds `_lock`.

        Evicting purely by age discarded a session that was still running -- so a
        21st audit would delete the in-flight results of the 1st, and the caller
        polling for them got a 404 for an audit that was still going. Running
        sessions are therefore exempt from eviction; if they alone exceed the cap
        the cap is simply breached, which is bounded anyway by
        `CONSOLE_MAX_RUNNING_AUDITS` and is the correct trade against losing live
        results.
        """
        if len(self._sessions) <= self._cap:
            return
        finished = sorted(
            (s for s in self._sessions.values() if s.status != "running"),
            key=lambda s: s.started_at,
        )
        for stale in finished[: len(self._sessions) - self._cap]:
            self._sessions.pop(stale.id, None)

    def readiness(self) -> Dict[str, Any]:
        """
        Whether this console can accept an audit right now, and if not, why.

        Distinct from liveness on purpose. The process being up says nothing about
        whether it can serve: with every admission slot held, or with no demo
        target, it is live but not ready, and a load balancer routing to it
        produces 503s that read like a bug. Each blocker is named so a caller is
        told what to wait for rather than just "not ready".
        """
        blockers: List[str] = []
        if not self.demo_target and not self.allowed_hosts:
            blockers.append("no demo target and no allow-list: nothing may be audited")
        # Non-blocking probe: if the slot cannot be taken now, the service is full.
        if not self._admission.acquire(blocking=False):
            blockers.append(
                f"all {CONSOLE_MAX_RUNNING_AUDITS} audit slots are in use"
            )
        else:
            self._admission.release()
        return {"ready": not blockers, "blockers": blockers}

    def note_request(self, client_ip: str, route: str) -> bool:
        """
        Record one request against a per-IP window. False means "refuse".

        A crude flood brake in front of the exact admission control. It exists
        because the semaphore bounds *concurrent* audits, not how fast a caller
        can ask for them: an unauthenticated caller can otherwise retry in a tight
        loop and keep all the slots churning. Only the routes that cost something
        are limited, so polling a running audit is never penalised.
        """
        limit = RATE_LIMIT_PER_ROUTE.get(route)
        if limit is None:
            return True
        now = time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW_S
        with self._rate_lock:
            recent = [t for t in self._rate.get((client_ip, route), []) if t > cutoff]
            if len(recent) >= limit:
                self._rate[(client_ip, route)] = recent
                return False
            recent.append(now)
            self._rate[(client_ip, route)] = recent
            # Bound the table itself: a caller looping over new keys must not be
            # able to grow it without limit.
            if len(self._rate) > RATE_TABLE_MAX:
                for key in [k for k, v in self._rate.items() if not any(t > cutoff for t in v)]:
                    self._rate.pop(key, None)
        return True

    # -- scope -------------------------------------------------------------

    def authorize(self, target_url: str) -> str:
        """
        Return the host if this console may audit it, else raise.

        This is the console's own gate, in front of the engine's. The engine
        refuses anything outside its scope; this decides what scope the console is
        willing to *declare* in the first place, which is what keeps a hosted
        instance from being pointed at a third party.
        """
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise TargetNotAllowed("target must be an http(s) URL")
        host = (parsed.hostname or "").lower()
        if not host:
            raise TargetNotAllowed("target URL has no host")
        if self.allowed_hosts and host not in self.allowed_hosts:
            raise TargetNotAllowed(
                f"host {host!r} is not on this console's allow-list "
                f"({', '.join(self.allowed_hosts)}). A hosted console only audits "
                f"its own demo target."
            )
        return host

    # -- sessions ----------------------------------------------------------

    def start_audit(
        self,
        *,
        target_url: str,
        visitor_count: int,
        duration_hours: float,
        max_level: int,
        seed: Optional[int],
        extra_headers: Optional[Dict[str, str]] = None,
        single_level: Optional[int] = None,
    ) -> AuditSession:
        # Wait for a slot rather than refuse: the caller asked for an audit and
        # will get one, just not simultaneously with an unbounded number of
        # others. A long timeout turns "the console is saturated" into a 503
        # instead of a request that blocks a worker thread indefinitely.
        if not self._admission.acquire(timeout=CONSOLE_ADMISSION_TIMEOUT_S):
            raise TooManyAudits(
                f"{CONSOLE_MAX_RUNNING_AUDITS} audits are already running; try "
                f"again when one finishes."
            )
        try:
            session = self._prepare_audit(
                target_url=target_url,
                visitor_count=visitor_count,
                duration_hours=duration_hours,
                max_level=max_level,
                seed=seed,
                extra_headers=extra_headers,
                single_level=single_level,
            )
        except BaseException:
            self._admission.release()
            raise
        return session

    def _prepare_audit(
        self,
        *,
        target_url: str,
        visitor_count: int,
        duration_hours: float,
        max_level: int,
        seed: Optional[int],
        extra_headers: Optional[Dict[str, str]] = None,
        single_level: Optional[int] = None,
    ) -> AuditSession:
        host = self.authorize(target_url)

        visitor_count = max(1, min(int(visitor_count), MAX_VISITORS))
        max_level = max(0, min(int(max_level), MAX_LEVELS))
        duration_hours = max(0.001, float(duration_hours))
        single_level_mode = single_level is not None

        notices: List[str] = []

        available = browser_available()
        if not available and max_level > 0:
            max_level = 0
            notices.append(
                "No installed camoufox to drive the browser rungs, so the ladder is "
                "capped at L0 (naive HTTP). Levels 1+ need the browser; see pythonlib/."
            )

        pool = self.proxies.get()
        if single_level_mode:
            requested_levels = [max(0, min(int(single_level), MAX_LEVELS))]
        else:
            requested_levels = list(range(0, max_level + 1))
        selected = [i for i in requested_levels if pool is not None or i not in ROTATION_LEVEL_IDS]
        dropped = [i for i in requested_levels if i not in selected]
        if single_level_mode and not selected:
            # The one rung that was asked for is exactly the one that cannot run
            # here. Silently returning a session with no levels would look like a
            # clean result; refuse instead, and name the rung as clamped, since
            # that is what will appear in the report.
            raise TargetNotAllowed(
                f"L{requested_levels[0]} is defined by a rotating exit IP and no proxy "
                f"pool is configured, so this console cannot run it. Add a pool, or "
                f"pick another rung."
            )
        if single_level_mode and not available and requested_levels[0] > 0:
            raise TargetNotAllowed(
                f"L{requested_levels[0]} needs the browser, which is not installed on "
                f"this host. Only L0 can run here."
            )
        if dropped:
            # L4+ are defined by a rotating exit IP. Running them with no pool
            # would measure this host's own IP while the report still said
            # "proxy rotation", which points the operator at the wrong control.
            # Prune and say so, the same way a missing browser prunes L1+.
            notices.append(
                "Rungs "
                + ", ".join(f"L{i}" for i in dropped)
                + " are defined by a rotating exit IP, and no proxy pool is "
                "configured, so they were left out rather than run directly and "
                "reported as IP rotation. Add a pool to climb them."
            )

        scope = TargetScope.from_urls(
            [target_url],
            acknowledged=True,
            acknowledgment_note="hosted demo console; operator acknowledged at launch",
        )
        config = AuditConfig(
            target_url=target_url,
            scope=scope,
            # In single-rung mode the engine derives the rung from `single_level`;
            # passing `levels` too would be two sources for the same decision, and
            # validate() rejects that rather than pick one silently.
            levels=None if single_level_mode else selected,
            single_level_mode=single_level_mode,
            single_level=requested_levels[0],
            visitor_count=visitor_count,
            duration_hours=duration_hours,
            cooldown_between_levels_s=0.0,
            seed=seed,
            limits=CONSOLE_LIMITS,
            extra_headers=dict(extra_headers or {}),
            # Each rung runs the posture it defines; on this host the headed rungs
            # fall back to Camoufox's virtual display, which is a real headed
            # browser rather than a headless one. Forcing headless here would
            # collapse L1 into the rungs above it and quietly change what L2+
            # measures.
            headless=None,
            proxy=pool.spec if pool is not None else None,
        )
        problems = config.validate()
        if problems:
            raise TargetNotAllowed("; ".join(problems))

        session = AuditSession(
            id=uuid.uuid4().hex[:12],
            target_url=target_url,
            visitor_count=config.visitor_count,
            duration_hours=duration_hours,
            max_level=max(requested_levels, default=0),
            levels=selected,
            single_level_mode=single_level_mode,
            proxy_summary=pool.summary() if pool is not None else None,
            seed=seed,
            # Bound *before* the thread starts, so a fast finish cannot find the
            # slot unwired. The slot is held until this session reaches a
            # terminal state, which `_release_slot` signals.
            on_finish=self._admission.release,
        )
        with self._lock:
            self._sessions[session.id] = session
            self._evict_locked()
        session.start(config)
        for message in notices:
            session._append({"event": "notice", "message": message})
        return session

    def get(self, session_id: str) -> Optional[AuditSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def levels(self) -> List[Dict[str, Any]]:
        """
        Every rung, annotated with whether this console can currently climb it.

        The UI needs to distinguish "reachable now" from "needs a proxy pool", and
        it must not be the UI's job to know which rungs are defined by the exit IP.
        """
        pool = self.proxies.get()
        has_browser = browser_available()
        out: List[Dict[str, Any]] = []
        for level in levels_up_to(MAX_LEVELS):
            entry = level.to_dict()
            needs_pool = level.id in ROTATION_LEVEL_IDS
            needs_browser = level.client == "browser"
            runnable = (not needs_browser or has_browser) and (
                not needs_pool or pool is not None
            )
            entry["reachable"] = runnable
            entry["requires_pool"] = needs_pool
            if needs_pool and pool is None:
                entry["unreachable_reason"] = (
                    "needs a proxy pool: this rung is defined by a rotating exit IP"
                )
            elif needs_browser and not has_browser:
                entry["unreachable_reason"] = (
                    "needs the browser: camoufox is not installed on this host"
                )
            out.append(entry)
        return out

    def proxy_state(self) -> Dict[str, Any]:
        """The pool as the API may report it: never a password."""
        pool = self.proxies.get()
        if pool is None:
            return {"configured": False, "mode": None, "count": 0, "labels": [], "gateway": ""}
        return pool.summary()

    def configure_proxy(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set or clear the rotation pool.

        Two accepted shapes, matching the engine's own: `entries` (a list of proxy
        strings) or `gateway` (one rotating endpoint). Anything else is refused
        rather than guessed at.
        """
        if body.get("clear"):
            self.proxies.clear()
            return self.proxy_state()
        gateway = str(body.get("gateway") or "").strip()
        entries = body.get("entries")
        if gateway and entries:
            raise ValueError("pass either 'gateway' or 'entries', not both")
        if gateway:
            pool = self.proxies.set_gateway(gateway)
        elif entries:
            if isinstance(entries, str):
                entries = entries.splitlines()
            if not isinstance(entries, list):
                raise ValueError("'entries' must be a list of proxy strings")
            pool = self.proxies.set_list([str(e) for e in entries])
        else:
            raise ValueError("provide 'entries' (a list of proxies) or 'gateway'")
        return pool.summary()
