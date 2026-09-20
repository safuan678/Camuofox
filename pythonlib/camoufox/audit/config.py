"""
Audit configuration and result containers.

A single object describing what to test, plus the records produced by running it.
Keeping these declarative (and serializable) is what lets the same audit be
launched from the CLI, from the GUI, or from a saved profile.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .detection import Verdict
from .evasion import EvasionLevel, level_by_id, levels_up_to
from .journey import JourneyConfig, parse_rate_pct
from .schedule import ArrivalPattern, ScheduleConfig
from .scope import TargetScope

__all__ = [
    "SafetyLimits",
    "AuditConfig",
    "VisitResult",
    "CampaignEvent",
    "LevelResult",
    "AuditReport",
    "SINGLE_LEVEL_VISITORS",
]

#: The visitor count a single-rung run always uses.
#:
#: Single-level mode is a repeat-run preset: the operator already knows which
#: rung they are watching, so the run is pinned to one posture at a fixed sample
#: size instead of inheriting a ladder's per-rung count. Fixing it here rather
#: than defaulting it means two single-rung runs are directly comparable, which is
#: the only reason to run one.
SINGLE_LEVEL_VISITORS = 100


@dataclass
class SafetyLimits:
    """
    Hard ceilings the runner enforces regardless of what the schedule asks for.

    A schedule is a plan; these are the brakes. They exist because the most
    common way an authorized audit causes real damage is a misconfigured count
    or pattern, not malice -- and once the traffic is leaving, a wrong request
    cannot be un-sent.
    """

    #: Absolute ceiling on requests, across the whole audit. 0 = unlimited.
    max_requests: int = 20000
    #: Ceiling on concurrent visitor sessions / browser contexts.
    max_concurrency: int = 8
    #: Ceiling on requests per second, computed from a rolling window.
    max_rps: float = 10.0
    #: Ceiling on arrivals per minute. 0 = no ceiling.
    max_arrivals_per_minute: int = 60
    #: Ceiling on visitors in any single proxy's rotation slot. 0 = unlimited.
    max_per_proxy: int = 0
    #: Abort the whole audit after this many consecutive transport errors.
    abort_after_consecutive_errors: int = 15

    def to_dict(self) -> dict:
        return {
            "max_requests": self.max_requests,
            "max_concurrency": self.max_concurrency,
            "max_rps": self.max_rps,
            "max_arrivals_per_minute": self.max_arrivals_per_minute,
            "max_per_proxy": self.max_per_proxy,
            "abort_after_consecutive_errors": self.abort_after_consecutive_errors,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SafetyLimits":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})


@dataclass
class AuditConfig:
    """Everything needed to run an audit."""

    target_url: str
    scope: TargetScope = field(default_factory=TargetScope)
    #: Highest rung of the ladder to climb. Use max_evasion_level for a full audit.
    max_evasion_level: int = 3
    #: Alternative to max_evasion_level: run exactly these levels.
    levels: Optional[List[int]] = None
    visitor_count: int = 100
    duration_hours: float = 1.0
    pattern: str = ArrivalPattern.HUMAN_DIURNAL
    journey: JourneyConfig = field(default_factory=JourneyConfig)
    limits: SafetyLimits = field(default_factory=SafetyLimits)
    #: Proxy rotation config (mapping) or a rotator; used from L4 up.
    proxy: Optional[Any] = None
    #: Seed for reproducibility. None means random.
    seed: Optional[int] = None
    #: Extra in-scope paths to sample, e.g. ["/pricing", "/docs"].
    paths: List[str] = field(default_factory=list)

    #: Headers every request carries. Use this to supply a session cookie or an
    #: authorization token when auditing a page behind a login, so the audit can
    #: reach the protected surface instead of measuring the login redirect.
    extra_headers: Dict[str, str] = field(default_factory=dict)
    #: Seconds to wait between completing one level and starting the next.
    cooldown_between_levels_s: float = 30.0
    #: Where per-level artifacts (screenshots, HTML) are written. None = none.
    artifact_dir: Optional[str] = None
    #: Keep the browser open between visitors (much cheaper) or relaunch per visit.
    #:
    #: Reuse is the default and it is what the design relies on: one browser serves
    #: a whole rung, and each visitor opens its own context (which carries its own
    #: fingerprint). A browser launch costs seconds and a process, so per-visit
    #: launches turn 100 visitors into 100 Firefox processes -- the dominant cost
    #: of a run, and a resource shape no human population produces.
    reuse_browser: bool = True
    #: Force the headed/headless posture for every browser rung.
    #:
    #: None (the default) honours each rung's own posture, which is what makes the
    #: ladder mean anything -- L1 is defined by being headless and L2 by being
    #: headful. True/False overrides the posture for a host that cannot provide a
    #: display (or an operator who wants every rung run the same way); the runner
    #: announces the override when it contradicts a rung, so a verdict is never
    #: silently credited to a posture that was not actually used.
    headless: Optional[bool] = None

    #: Run one rung on its own instead of climbing the ladder from L0.
    #:
    #: The ladder exists for attribution: every rung runs so the first one that
    #: holds names the control doing the work. That is the right shape for a first
    #: look and the wrong one for a repeat run, where the operator already knows
    #: which rung they care about and does not want to spend traffic on the rungs
    #: below it. With this True, `single_level` picks the rung and nothing else
    #: runs -- 100 visitors at L5 means 100 visitors at L5, not 100 at each of
    #: L0..L5.
    #:
    #: A single-rung run cannot attribute anything: with nothing below it to
    #: compare against, its report describes one posture rather than naming the
    #: defense that holds. The report says so rather than letting the absence of a
    #: ladder be read as a finding about one.
    single_level_mode: bool = False
    #: The rung to run when single_level_mode is True. Ignored otherwise.
    single_level: int = 0

    #: Follow promotional banners to their destination and record the funnel.
    #:
    #: Runs on top of the ladder rather than as a rung of its own: a click-through
    #: is only meaningful on a posture that already claims behavior, so it is
    #: exercised on the behavioral rungs (L5/L6) and skipped on the rest, which
    #: keeps a lower rung's verdict about the control it isolates.
    #:
    #: Destinations are discovered from the page, but only *followed* when the
    #: operator authorized them -- first-party links (already in scope) or a host
    #: declared in `scope.outbound_hosts`. See `TargetScope.authorize_outbound`.
    enable_outbound_funnel: bool = False
    #: Fraction of sessions that click a promotional banner, as a percentage.
    #:
    #: Stored as a percentage (2.5 means 2.5%) because that is what the operator
    #: types; the CTR roll compares it against `uniform(0, 100)`. Bounded to
    #: [0, 30] by `__post_init__`.
    outbound_campaign_rate_pct: float = 2.5
    #: Whether banner discovery may look inside child frames.
    #:
    #: Many real campaigns are served from an ad iframe, so a main-frame-only
    #: scan reports "no promotional banner found" on a page that is showing one.
    #: Defaults to True because that is the shape the tool is meant to measure.
    #:
    #: This widens *discovery*, never authorization: a destination found inside a
    #: frame is still admitted only by `TargetScope`, exactly like one found in the
    #: main document. A frame is untrusted content by definition, so treating
    #: frame-extracted URLs as somehow more trusted would be the opposite of safe.
    include_iframes: bool = True

    def __post_init__(self) -> None:
        if self.single_level_mode:
            # Pinned rather than defaulted: a single-rung run exists to be
            # repeated and compared, and a caller-supplied count (or a ladder's
            # per-rung count) would make two such runs incomparable.
            self.visitor_count = SINGLE_LEVEL_VISITORS
        # Normalize through the same parser the GUI uses, so a value that reached
        # the engine by a route other than the GUI (a saved profile, a script) is
        # bounded identically rather than silently widening the run.
        #
        # Only enforced when the funnel is on. With it off the rate decides no
        # traffic, and refusing to build a config over an unused field would block
        # runs that are perfectly well-defined -- so an off funnel keeps the raw
        # value and lets `validate` stay silent about it.
        try:
            self.outbound_campaign_rate_pct = parse_rate_pct(
                self.outbound_campaign_rate_pct
            )
        except ValueError:
            if self.enable_outbound_funnel:
                raise

    def selected_levels(self) -> List[EvasionLevel]:
        if self.single_level_mode:
            return [level_by_id(self.single_level)]
        if self.levels:
            return [level_by_id(i) for i in self.levels]
        return levels_up_to(self.max_evasion_level)

    def schedule_config(self, start_at: Optional[Any] = None) -> ScheduleConfig:
        """
        The arrival plan for one window.

        `start_at` lets the runner anchor each rung's window to the moment that
        rung starts. Omitting it means "now", which the schedule then uses both as
        the window's origin and as the hour the diurnal curve is aligned to -- so a
        run begun in the afternoon is busy in the afternoon.
        """
        return ScheduleConfig(
            visitor_count=self.visitor_count,
            duration_hours=self.duration_hours,
            pattern=self.pattern,
            start_at=start_at,
            max_arrivals_per_minute=self.limits.max_arrivals_per_minute,
        )

    def validate(self) -> List[str]:
        """Return a list of problems; empty means the config is runnable."""
        problems: List[str] = []
        if not self.target_url:
            problems.append("target_url is required")
        if not self.scope.hosts:
            problems.append("scope must name at least one host")
        elif not self.scope.acknowledged:
            problems.append(
                "scope is not acknowledged -- confirm you are authorized to test it"
            )
        if self.target_url and self.scope.hosts:
            from urllib.parse import urlparse

            host = (urlparse(self.target_url).hostname or "").lower()
            if host and not self.scope.permits(host):
                problems.append(
                    f"target_url host {host!r} is not inside the declared scope "
                    f"({self.scope.describe()})"
                )
        if self.visitor_count < 0:
            problems.append("visitor_count cannot be negative")
        if self.duration_hours <= 0:
            problems.append("duration_hours must be positive")
        if self.max_evasion_level < 0 or self.max_evasion_level > 6:
            problems.append("max_evasion_level must be between 0 and 6")
        if self.single_level < 0 or self.single_level > 6:
            problems.append("single_level must be between 0 and 6")
        if self.single_level_mode and self.levels:
            # Both name the rungs to run, so accepting both would mean silently
            # dropping one. Refuse instead: an operator who passed both meant one
            # of them, and only they know which.
            problems.append(
                f"single_level_mode is on, so levels={list(self.levels)} cannot also "
                f"be given; pass one or the other. Remove levels to run only "
                f"L{self.single_level}."
            )
        if self.visitor_count > self.limits.max_requests > 0:
            problems.append(
                f"visitor_count ({self.visitor_count}) exceeds max_requests "
                f"({self.limits.max_requests}); the audit would be cut off partway"
            )
        if self.enable_outbound_funnel:
            try:
                rate = parse_rate_pct(self.outbound_campaign_rate_pct)
            except ValueError:
                problems.append(
                    f"outbound_campaign_rate_pct ({self.outbound_campaign_rate_pct!r}) "
                    f"is not a percentage; give a number like 2.5 for 2.5%"
                )
            else:
                if rate <= 0:
                    # Not an error, but a run that clicks nothing measures no
                    # funnel, and the operator asked for one. Say so rather than
                    # let a zero rate be read as "no banner worked".
                    problems.append(
                        "enable_outbound_funnel is on but outbound_campaign_rate_pct "
                        "is 0, so no visitor will click a banner; set a rate above 0 "
                        "or turn the funnel off"
                    )
        return problems

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "scope": self.scope.to_dict(),
            "max_evasion_level": self.max_evasion_level,
            "levels": self.levels,
            "single_level_mode": self.single_level_mode,
            "single_level": self.single_level,
            "enable_outbound_funnel": self.enable_outbound_funnel,
            "outbound_campaign_rate_pct": self.outbound_campaign_rate_pct,
            "include_iframes": self.include_iframes,
            "visitor_count": self.visitor_count,
            "duration_hours": self.duration_hours,
            "pattern": self.pattern,
            "limits": self.limits.to_dict(),
            "seed": self.seed,
            "paths": list(self.paths),
            "cooldown_between_levels_s": self.cooldown_between_levels_s,
            "reuse_browser": self.reuse_browser,
            "headless": self.headless,
        }


@dataclass
class CampaignEvent:
    """
    One visitor's promotional-banner click-through, and what followed it.

    Rides on the `VisitResult` it happened during rather than being a record of
    its own, because a click-through is only interpretable against the posture
    that produced it: the same banner can land on a rung that reached the site
    and a rung that was challenged, and only the pairing says which.
    """

    #: The destination the banner pointed at.
    campaign_url: str
    #: True when the destination was inside the audited site.
    first_party: bool = True
    #: The banner's anchor selector, for an operator who wants to find it again.
    selector_hint: str = ""
    #: The frame the banner was found in (0 = the main document).
    #:
    #: Recorded because "the offer was in an iframe" is a real finding about how
    #: the site serves its campaign -- and the reason a main-frame-only scan can
    #: report no banner at all.
    frame_index: int = 0
    #: How the click resolved: "clicked" (a real anchor press) or "navigated"
    #: (the anchor could not be pressed and the URL was requested directly).
    #:
    #: The distinction matters -- a typed-URL hop is a different, rarer behavior
    #: than a click, and reporting one as the other overstates the fidelity.
    interaction: str = "clicked"
    #: Whether the destination loaded, and what it answered with.
    landed: bool = False
    landing_status: Optional[int] = None
    landing_verdict: Optional[str] = None
    #: Seconds actually spent on the destination.
    dwell_s: float = 0.0
    glances: int = 0
    scroll_bursts: int = 0
    #: Set when the gate refused the destination; the visit is still recorded.
    skipped_reason: str = ""
    #: The gate refused this destination because the operator never declared it.
    #:
    #: Carried as a flag rather than inferred from `skipped_reason`, because that
    #: field is prose and counting it by substring would let a landing message
    #: that merely mentions "scope" be tallied as a refusal.
    refused_by_scope: bool = False

    @property
    def engaged(self) -> bool:
        """
        True when the visitor actually got to spend time on the offer.

        Distinct from `landed`: a destination that answered 403 landed but served
        nothing, so counting its zero-second visit as engagement would drag the
        dwell statistics down and misreport how long visitors read the offer.
        """
        return self.landed and not self.skipped_reason

    def to_dict(self) -> dict:
        return {
            "campaign_url": self.campaign_url,
            "first_party": self.first_party,
            "selector_hint": self.selector_hint,
            "frame_index": self.frame_index,
            "interaction": self.interaction,
            "landed": self.landed,
            "engaged": self.engaged,
            "landing_status": self.landing_status,
            "landing_verdict": self.landing_verdict,
            "dwell_s": round(self.dwell_s, 3),
            "glances": self.glances,
            "scroll_bursts": self.scroll_bursts,
            "skipped_reason": self.skipped_reason,
            "refused_by_scope": self.refused_by_scope,
        }


@dataclass
class VisitResult:
    """What happened to one visitor."""

    visitor_index: int
    level_id: int
    started_at: float
    finished_at: float = 0.0
    verdict: str = Verdict.ERROR
    vendors: List[str] = field(default_factory=list)
    reason: str = ""
    http_status: Optional[int] = None
    requests_made: int = 0
    #: Requests the browser issued that `requests_made` does not count.
    #:
    #: A page load is not one request: the document pulls a favicon, stylesheets,
    #: scripts and images, all of which reach the target and all of which the
    #: defenses see. Counting only the navigations the runner drives understates
    #: the traffic the audit actually sent -- and, worse, makes the request ceiling
    #: advisory, because a browser rung sent 2x the number the report admits.
    #: Held separately so the attributable figure (one per visit) stays readable
    #: next to the true one.
    subrequests_made: int = 0
    pages_loaded: int = 0
    source: str = ""
    referer: Optional[str] = None
    proxy_label: Optional[str] = None
    exit_ip: Optional[str] = None
    launcher_error: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    #: Per-request latencies in seconds.
    latencies: List[float] = field(default_factory=list)
    #: The funnel click-through that happened during this visit, if any.
    campaign: Optional[CampaignEvent] = None
    #: Distinct hosts the scope gate refused during this visit, in first-seen order.
    #:
    #: The page under audit deciding to reference a host the operator never named
    #: is a finding about the site, so it is recorded on the visit rather than only
    #: logged. Distinct by host so a page pulling 50 assets from one undeclared CDN
    #: reads as one destination, not fifty.
    blocked_hosts: List[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    @property
    def total_requests(self) -> int:
        """Every request this visit caused, navigations plus subresources."""
        return self.requests_made + self.subrequests_made

    @property
    def detected(self) -> bool:
        return self.verdict in Verdict.DETECTED

    @property
    def p50_latency(self) -> Optional[float]:
        return _percentile(self.latencies, 50)

    @property
    def p95_latency(self) -> Optional[float]:
        return _percentile(self.latencies, 95)

    def to_dict(self) -> dict:
        return {
            "visitor_index": self.visitor_index,
            "level_id": self.level_id,
            "verdict": self.verdict,
            "detected": self.detected,
            "vendors": list(self.vendors),
            "reason": self.reason,
            "http_status": self.http_status,
            "requests_made": self.requests_made,
            "subrequests_made": self.subrequests_made,
            "total_requests": self.total_requests,
            "pages_loaded": self.pages_loaded,
            "duration_s": round(self.duration_s, 3),
            "source": self.source,
            "referer": self.referer,
            "proxy_label": self.proxy_label,
            "exit_ip": self.exit_ip,
            "launcher_error": self.launcher_error,
            "evidence": list(self.evidence),
            "latencies": [round(x, 4) for x in self.latencies],
            "p50_latency": self.p50_latency,
            "p95_latency": self.p95_latency,
            "campaign": self.campaign.to_dict() if self.campaign else None,
            "blocked_hosts": list(self.blocked_hosts),
        }


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 4)
    rank = (pct / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return round(ordered[low] + frac * (ordered[high] - ordered[low]), 4)


@dataclass
class LevelResult:
    """Aggregate outcome for one rung of the ladder."""

    level: EvasionLevel
    visits: List[VisitResult] = field(default_factory=list)
    scheduled: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    aborted: bool = False
    abort_reason: str = ""
    #: Paths of the screenshots and HTML captured for this rung, when
    #: `AuditConfig.artifact_dir` is set. Empty when capture is off.
    artifacts: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {v: 0 for v in Verdict.ALL}
        for visit in self.visits:
            out[visit.verdict] = out.get(visit.verdict, 0) + 1
        return out

    @property
    def completed(self) -> int:
        return len(self.visits)

    @property
    def allowed(self) -> int:
        return sum(1 for v in self.visits if v.verdict == Verdict.ALLOWED)

    @property
    def detected(self) -> int:
        return sum(1 for v in self.visits if v.detected)

    @property
    def detection_rate(self) -> float:
        return 0.0 if not self.visits else self.detected / len(self.visits)

    @property
    def bypass_rate(self) -> float:
        return 0.0 if not self.visits else self.allowed / len(self.visits)

    def vendors_seen(self) -> List[str]:
        seen: Dict[str, int] = {}
        for visit in self.visits:
            for vendor in visit.vendors:
                seen[vendor] = seen.get(vendor, 0) + 1
        return sorted(seen, key=lambda v: (-seen[v], v))

    def p95_latency(self) -> Optional[float]:
        all_latencies = [x for v in self.visits for x in v.latencies]
        return _percentile(all_latencies, 95)

    # -- outbound funnel ---------------------------------------------------

    @property
    def campaign_clicks(self) -> int:
        """Visitors at this rung who clicked a promotional banner."""
        return sum(1 for v in self.visits if v.campaign is not None)

    @property
    def campaign_landings(self) -> int:
        """Click-throughs whose destination actually loaded."""
        return sum(1 for v in self.visits if v.campaign and v.campaign.landed)

    @property
    def campaign_engagements(self) -> int:
        """Click-throughs that reached a destination and were actually served it."""
        return sum(1 for v in self.visits if v.campaign and v.campaign.engaged)

    @property
    def campaign_dwell_s(self) -> List[float]:
        return [v.campaign.dwell_s for v in self.visits if v.campaign and v.campaign.engaged]

    def campaign_dwell_p50(self) -> Optional[float]:
        return _percentile(self.campaign_dwell_s, 50)

    def to_dict(self) -> dict:
        return {
            "level_id": self.level.id,
            "level_key": self.level.key,
            "level_name": self.level.name,
            "scheduled": self.scheduled,
            "completed": self.completed,
            "allowed": self.allowed,
            "detected": self.detected,
            "detection_rate": round(self.detection_rate, 4),
            "bypass_rate": round(self.bypass_rate, 4),
            "counts": self.counts(),
            "vendors": self.vendors_seen(),
            "p95_latency": self.p95_latency(),
            "campaign_clicks": self.campaign_clicks,
            "campaign_landings": self.campaign_landings,
            "campaign_dwell_p50": self.campaign_dwell_p50(),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "artifacts": list(self.artifacts),
            "duration_s": round(max(0.0, self.finished_at - self.started_at), 2),
            "visits": [v.to_dict() for v in self.visits],
        }


@dataclass
class AuditReport:
    """The full audit: every rung, plus the conclusion."""

    config: AuditConfig
    levels: List[LevelResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    aborted: bool = False
    abort_reason: str = ""
    schedule_warnings: List[str] = field(default_factory=list)

    @property
    def total_visits(self) -> int:
        return sum(lr.completed for lr in self.levels)

    @property
    def total_requests(self) -> int:
        """Every request the audit caused, navigations plus subresources."""
        return sum(v.total_requests for lr in self.levels for v in lr.visits)

    @property
    def navigations(self) -> int:
        """Document requests only -- the visits and hops the runner drove."""
        return sum(v.requests_made for lr in self.levels for v in lr.visits)

    @property
    def subrequests(self) -> int:
        """Requests the browser issued on its own: favicon, CSS, scripts, images."""
        return sum(v.subrequests_made for lr in self.levels for v in lr.visits)

    @property
    def blocked_hosts(self) -> List[str]:
        """Distinct hosts the scope gate refused, across the whole run."""
        seen: List[str] = []
        for lr in self.levels:
            for visit in lr.visits:
                for host in visit.blocked_hosts:
                    if host not in seen:
                        seen.append(host)
        return seen

    def first_effective_level(self) -> Optional[LevelResult]:
        """
        The lowest rung the defenses actually stopped.

        This is the headline finding: it is the defense that is doing the work.
        Below it, controls are already defeated; a defense that never holds is
        not a defense.
        """
        for lr in self.levels:
            if lr.visits and lr.detection_rate >= 0.5:
                return lr
        return None

    def highest_bypassing_level(self) -> Optional[LevelResult]:
        """The most advanced posture that still got through cleanly."""
        bypassing = [lr for lr in self.levels if lr.visits and lr.bypass_rate >= 0.5]
        return bypassing[-1] if bypassing else None

    # -- outbound funnel ---------------------------------------------------

    @property
    def funnel_enabled(self) -> bool:
        return bool(self.config.enable_outbound_funnel)

    def campaign_events(self) -> List[CampaignEvent]:
        """Every click-through across the run, in visit order."""
        return [
            v.campaign
            for lr in self.levels
            for v in lr.visits
            if v.campaign is not None
        ]

    def funnel_summary(self) -> Dict[str, Any]:
        """
        The campaign aggregate, kept separate from the evasion attribution.

        A click-through rate and the rung that held are answers to different
        questions, and mixing them into one number is how a report starts
        implying that a banner's CTR is a defense result. This is the whole
        funnel in one dict, and the report prints it under its own heading.
        """
        events = self.campaign_events()
        clicks = len(events)
        landed = [e for e in events if e.landed]
        engaged = [e for e in events if e.engaged]
        dwell = sorted(e.dwell_s for e in engaged)
        destinations: Dict[str, int] = {}
        for event in events:
            destinations[event.campaign_url] = destinations.get(event.campaign_url, 0) + 1
        first_party = sum(1 for e in events if e.first_party)
        iframe_clicks = sum(1 for e in events if e.frame_index > 0)
        return {
            "enabled": self.funnel_enabled,
            "rate_pct": self.config.outbound_campaign_rate_pct,
            "clicks": clicks,
            "landed": len(landed),
            "engaged": len(engaged),
            "refused": len(landed) - len(engaged),
            "unreachable": sum(
                1
                for e in events
                if e.skipped_reason and not e.landed and not e.refused_by_scope
            ),
            "skipped_by_scope": sum(1 for e in events if e.refused_by_scope),
            "first_party_clicks": first_party,
            "partner_clicks": clicks - first_party,
            "iframe_clicks": iframe_clicks,
            "landing_rate": round(len(landed) / clicks, 4) if clicks else 0.0,
            "dwell_p50_s": _percentile(dwell, 50),
            "dwell_min_s": round(dwell[0], 3) if dwell else None,
            "dwell_max_s": round(dwell[-1], 3) if dwell else None,
            "destinations": sorted(
                ({"url": url, "clicks": count} for url, count in destinations.items()),
                key=lambda d: (-d["clicks"], d["url"]),
            ),
        }

    def to_dict(self) -> dict:
        return {
            "target_url": self.config.target_url,
            "scope": self.config.scope.describe(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(max(0.0, self.finished_at - self.started_at), 2),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "schedule_warnings": list(self.schedule_warnings),
            "config": self.config.to_dict(),
            "totals": {
                "visits": self.total_visits,
                "requests": self.total_requests,
                "navigations": self.navigations,
                "subrequests": self.subrequests,
                "blocked_hosts": self.blocked_hosts,
            },
            "funnel": self.funnel_summary(),
            "levels": [lr.to_dict() for lr in self.levels],
        }