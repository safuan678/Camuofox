"""
Human-like visitor journeys.

A visitor is not a single request. It is an arrival, a period of attention, some
interaction, and a departure. Behavioral defenses score exactly that shape: a
client that requests one page and vanishes is not behaving like a reader, and a
client that requests every page in a fixed order and fixed interval is behaving
like a crawler.

Everything here is randomized on purpose, and drawn from distributions that
resemble real attention rather than a uniform range. Uniform dwell time is the
tell: real reading time is right-skewed, with most visits short and a long tail.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

__all__ = [
    "ArrivalSource",
    "JourneyConfig",
    "VisitPlan",
    "BannerCandidate",
    "OutboundPlan",
    "plan_visit",
    "plan_outbound_visit",
    "build_arrival_referer",
    "discover_banner_candidates",
    "is_ad_syndication_url",
    "parse_rate_pct",
    "roll_outbound_trigger",
    "select_campaign",
]

#: Real search engines and a couple of common referral hosts. A visitor that
#: claims a search-engine referer on every visit is itself a pattern, so the
#: mix matters as much as the individual values.
SEARCH_ENGINES = {
    "google": "https://www.google.com/",
    "bing": "https://www.bing.com/",
    "duckduckgo": "https://duckduckgo.com/",
    "yahoo": "https://search.yahoo.com/",
    "ecosia": "https://www.ecosia.org/",
}

SOCIAL_REFERRERS = [
    "https://www.facebook.com/",
    "https://t.co/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://www.instagram.com/",
]


class ArrivalSource:
    """How a visitor found the site."""

    DIRECT = "direct"
    SEARCH = "search"
    REFERRAL = "referral"
    INTERNAL = "internal"

    ALL = (DIRECT, SEARCH, REFERRAL, INTERNAL)


def build_arrival_referer(source: str, target_url: str, rng: random.Random) -> Optional[str]:
    """
    A plausible Referer for an arrival, or None for a direct visit.

    Direct traffic sends no Referer at all. An audit that always sends one is
    trivially separable from real traffic, which is mostly direct.
    """
    if source == ArrivalSource.DIRECT or source == ArrivalSource.INTERNAL:
        return None
    if source == ArrivalSource.SEARCH:
        engine = rng.choice(list(SEARCH_ENGINES.values()))
        query = rng.choice(
            ["", "?q=" + rng.choice(["site", "login", "pricing", "docs", "contact", "reviews"]),
             "?q=" + urlparse(target_url).netloc]
        )
        return engine + query
    if source == ArrivalSource.REFERRAL:
        return rng.choice(SOCIAL_REFERRERS)
    return None


@dataclass
class JourneyConfig:
    """Tunables for one visitor's behavior, all randomized within these bounds."""

    #: Fraction of visitors arriving by each channel. Direct-heavy by default,
    #: because that is the common shape of real traffic.
    source_weights: dict = field(
        default_factory=lambda: {
            ArrivalSource.DIRECT: 0.45,
            ArrivalSource.SEARCH: 0.35,
            ArrivalSource.REFERRAL: 0.20,
        }
    )
    #: How long the visitor stays, in seconds. Log-normal mimics real attention:
    #: mostly short visits with a long tail, unlike a uniform draw.
    dwell_median_s: float = 75.0
    dwell_sigma: float = 0.9
    dwell_min_s: float = 8.0
    dwell_max_s: float = 900.0
    #: Ceiling on the dwell the runner actually spends per visit, in seconds.
    #:
    #: The draw above is the *shape*; this is the budget. A visitor planned at 900s
    #: is not worth 15 minutes of a concurrency slot, and 1000 such visitors would
    #: run for days -- but spending none of it was the original bug, because a
    #: session that finishes in a few hundred milliseconds is trivially separable
    #: from a reader. Visits below the budget are spent in full, so short and long
    #: visits stay distinguishable; only the tail is clipped.
    dwell_budget_s: float = 45.0
    #: Pages viewed in one session.
    pages_min: int = 1
    pages_max: int = 6
    #: When set, draw the page count uniformly from 1..this value instead of from
    #: `pages_min`..`pages_max`.
    #:
    #: This is the GUI's "Max requests / visitor": the operator names a ceiling N
    #: and each visitor lands somewhere in 1..N, so a run of 1000 visitors at N=5
    #: produces a mix of 1-, 2-, 3-, 4- and 5-page sessions rather than the same
    #: fixed journey repeated -- a population of identical session lengths is its
    #: own signature. Distinct from `pages_max`, which is the top of the
    #: human-journey range; this is the operator's stated ceiling, and the two
    #: mean different things when a saved profile sets only one of them.
    #:
    #: Each draw is bounded by `max_requests_per_visitor`, so the ceiling the
    #: operator set is also the largest journey that can be planned.
    uniform_pages_max: Optional[int] = None
    #: Whether to scroll, and roughly how far down the page.
    scroll_probability: float = 0.85
    scroll_steps_min: int = 2
    scroll_steps_max: int = 10
    #: Whether to type into a form/search box when one is available.
    type_probability: float = 0.15
    #: Probability the visitor leaves immediately (bounce).
    bounce_probability: float = 0.35
    #: Follow in-site links found on a page vs. request known paths directly.
    follow_links_probability: float = 0.6
    #: Ceiling on pages requested from any single path, to avoid hammering one URL.
    max_requests_per_visitor: int = 12
    #: Per-visit interaction budget, in seconds. Bounds what one visitor can spend
    #: in mouse movement, scrolling and typing, so a long dwell is reading time
    #: rather than a burst of synthetic interaction.
    interaction_budget_s: float = 20.0


@dataclass
class VisitPlan:
    """One visitor's scripted session, decided up front."""

    source: str
    referer: Optional[str]
    dwell_s: float
    page_count: int
    scroll_steps: int
    will_type: bool
    is_bounce: bool
    follow_links: bool
    inter_page_delay_s: List[float] = field(default_factory=list)
    #: One entry per *request* (the first page plus each subsequent hop): how long
    #: to spend on that page before acting. Sums to the planned dwell, so the
    #: reader's time is spread across the session instead of piled on the last
    #: page.
    page_dwell_s: List[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "referer": self.referer,
            "dwell_s": round(self.dwell_s, 2),
            "page_count": self.page_count,
            "scroll_steps": self.scroll_steps,
            "will_type": self.will_type,
            "is_bounce": self.is_bounce,
            "follow_links": self.follow_links,
            "inter_page_delay_s": [round(d, 2) for d in self.inter_page_delay_s],
            "page_dwell_s": [round(d, 2) for d in self.page_dwell_s],
        }


def _lognormal(median: float, sigma: float, low: float, high: float, rng: random.Random) -> float:
    """Sample a right-skewed dwell time, clamped to a sane range."""
    import math

    value = rng.lognormvariate(math.log(max(median, 1e-6)), sigma)
    return float(min(max(value, low), high))


def _split_dwell(dwell_s: float, pages: int, rng: random.Random) -> List[float]:
    """
    Split a session's dwell into one slice per request.

    Weighted by a random draw rather than divided evenly: an even split would give
    every page the same reading time, which is the same regularity tell as uniform
    arrival spacing. The first page gets a floor, because a visitor reads the
    landing page before clicking anything.
    """
    pages = max(1, int(pages))
    if pages == 1:
        return [max(0.0, dwell_s)]

    weights = [0.5 + rng.random()] + [rng.random() for _ in range(pages - 1)]
    total = sum(weights) or 1.0
    return [dwell_s * (weight / total) for weight in weights]


def plan_visit(
    config: JourneyConfig,
    rng: random.Random,
    *,
    behavior: bool = True,
) -> VisitPlan:
    """
    Decide what one visitor does, before touching the network.

    Planning first keeps the behavior coherent: the referer, the page count and
    the cadence are chosen together rather than drifting independently, which is
    what makes a session look scripted.

    `behavior` gates the *human cadence* axes -- dwell, goto-scrolling, typing,
    multi-page journeys and the arrival source. When False the visit is a single
    direct request, which is what the rungs below the behavioral one have to send
    to stay honest: a rung whose job is to test header consistency cannot also be
    silently humanized, or its verdict would credit the wrong control. Camoufox's
    own cursor humanization is a separate axis, enabled by the rung's launch
    options.
    """
    if not behavior:
        # A single, direct, immediate request: no referer, no scroll, no typing,
        # no follow-up pages. The shape is what distinguishes this from the
        # behavioral rungs, not the dwell value.
        return VisitPlan(
            source=ArrivalSource.DIRECT,
            referer=None,
            dwell_s=0.0,
            page_count=1,
            scroll_steps=0,
            will_type=False,
            is_bounce=True,
            follow_links=False,
            inter_page_delay_s=[],
            page_dwell_s=[0.0],
        )

    sources = list(config.source_weights.keys())
    weights = list(config.source_weights.values())
    source = rng.choices(sources, weights=weights, k=1)[0]

    # The operator's stated ceiling, when one was given. Every visitor draws its
    # own session length uniformly from 1..N, so the population is a mix rather
    # than one repeated journey. Bounded by the per-visitor request ceiling so the
    # two cannot disagree: the plan must not promise more pages than the runner
    # will let it make.
    ceiling = int(config.uniform_pages_max or 0)
    if ceiling > 0:
        cap = int(config.max_requests_per_visitor)
        ceiling = min(ceiling, cap) if cap > 0 else ceiling
        pages = rng.randint(1, max(1, ceiling))
        # A one-page draw *is* a bounce -- the visitor arrived, read, and left.
        # Treated as one so the dwell shape stays right rather than reading a
        # deliberate single-page session as an abandoned multi-page one.
        is_bounce = pages <= 1
        dwell = _lognormal(
            config.dwell_median_s * (0.25 if is_bounce else 1.0),
            config.dwell_sigma * (0.7 if is_bounce else 1.0),
            config.dwell_min_s,
            min(config.dwell_max_s, 60.0) if is_bounce else config.dwell_max_s,
            rng,
        )
        scroll_steps = (
            rng.randint(config.scroll_steps_min, config.scroll_steps_max)
            if rng.random() < config.scroll_probability
            else 0
        )
        page_dwell = _split_dwell(dwell, pages, rng)
        return VisitPlan(
            source=source,
            referer=None,
            dwell_s=dwell,
            page_count=pages,
            scroll_steps=scroll_steps,
            will_type=rng.random() < config.type_probability,
            is_bounce=is_bounce,
            follow_links=rng.random() < config.follow_links_probability,
            inter_page_delay_s=page_dwell[1:],
            page_dwell_s=page_dwell,
        )

    is_bounce = rng.random() < config.bounce_probability
    if is_bounce:
        # A bounce is a short visit that requests one page and leaves.
        dwell = _lognormal(
            med := config.dwell_median_s * 0.25,
            config.dwell_sigma * 0.7,
            config.dwell_min_s,
            min(config.dwell_max_s, 60.0),
            rng,
        )
        return VisitPlan(
            source=source,
            referer=None,
            dwell_s=dwell,
            page_count=1,
            scroll_steps=0 if rng.random() < 0.7 else rng.randint(1, 3),
            will_type=False,
            is_bounce=True,
            follow_links=False,
            inter_page_delay_s=[],
            page_dwell_s=[dwell],
        )

    pages = rng.randint(config.pages_min, config.pages_max)
    dwell = _lognormal(
        config.dwell_median_s, config.dwell_sigma, config.dwell_min_s, config.dwell_max_s, rng
    )

    scroll_steps = (
        rng.randint(config.scroll_steps_min, config.scroll_steps_max)
        if rng.random() < config.scroll_probability
        else 0
    )

    # Split the dwell across the session as reading pauses, rather than sleeping
    # the whole time on the last page. The runner spends these slices, so this is
    # the table that decides how long the visit actually lasts.
    page_dwell = _split_dwell(dwell, pages, rng)
    delays = page_dwell[1:]

    return VisitPlan(
        source=source,
        referer=None,  # filled in by the caller, which knows the target URL
        dwell_s=dwell,
        page_count=pages,
        scroll_steps=scroll_steps,
        will_type=rng.random() < config.type_probability,
        is_bounce=False,
        follow_links=rng.random() < config.follow_links_probability,
        inter_page_delay_s=delays,
        page_dwell_s=page_dwell,
    )


# ---------------------------------------------------------------------------
# Outbound funnel: promotional banners and the campaign click-through
# ---------------------------------------------------------------------------
#
# The funnel audit asks a different question from the evasion ladder: not "does
# the defense hold", but "does the campaign banner reach its destination, and
# does a visitor who clicks it get tracked through". It runs *on top of* a rung
# rather than as a rung of its own, because a click-through is a property of a
# human-shaped posture -- it is only meaningful on a rung that already claims
# behavior. Everything in this section is therefore pure: it decides, from what
# the page shows, what a visitor would plausibly click.

#: Result of `parse_rate_pct`: the operator's "2.5" means 2.5 percent.
PCT_MIN = 0.0
PCT_MAX = 30.0

#: The shape of a percentage the GUI and CLI accept. Deliberately strict: a rate
#: is a quantity that decides how much traffic leaves, so "2.5%" is read as 2.5
#: and a malformed value is refused rather than guessed at.
_PCT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*%?\s*$")


def parse_rate_pct(value: Any) -> float:
    """
    Parse an operator-entered campaign rate into a percentage float.

    Accepts what a spinbox or a text field realistically produces: `2.5`, `2.5%`,
    ` 2.5 %`, `"2.5"`, `"0.1"`. Rejects anything else with `ValueError` rather
    than coercing it, because a silently misread rate is traffic the operator did
    not authorize. Clamps to the ladder's supported range so a value out of range
    cannot widen the run beyond what the UI offers.
    """
    if isinstance(value, bool):
        raise ValueError(f"Not a campaign rate: {value!r}")
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        match = _PCT_RE.match(str(value or ""))
        if not match:
            raise ValueError(f"Not a campaign rate: {value!r}")
        number = float(match.group(1))
    if number != number:  # NaN
        raise ValueError(f"Not a campaign rate: {value!r}")
    return min(max(number, PCT_MIN), PCT_MAX)


#: Ad-syndication and programmatic-exchange hosts.
#:
#: The funnel is about *first-party and direct partner* campaigns. A banner that
#: points into a real-time bidding exchange or an ad network is not a campaign
#: link -- clicking it measures the exchange's redirect chain, not the site's
#: funnel -- and it would drag the audit onto hosts nobody authorized. These are
#: filtered before a destination is ever considered.
_AD_SYNDICATION_MARKERS: Tuple[str, ...] = (
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com/ads",
    "adservice.google.",
    "amazon-adsystem.com",
    "taboola.com",
    "outbrain.com",
    "criteo.",
    "pubmatic.com",
    "rubiconproject.com",
    "openx.net",
    "adnxs.com",
    "casalemedia.com",
    "smartadserver.com",
    "sharethrough.com",
    "teads.tv",
    "mgid.com",
    "revcontent.com",
    "zergnet.com",
    "yieldmo.com",
    "sitescout.com",
    "bidswitch.net",
    "360yield.com",
    "improvedigital.com",
    "adform.net",
    "adsrvr.org",
    "1rx.io",
)

#: Query parameters that mark a URL as a click-wrapper/redirector rather than a
#: destination. A direct campaign link has a real path; an exchange hands over
#: its own endpoint with the destination buried in a parameter.
_REDIRECT_PARAM_MARKERS: Tuple[str, ...] = (
    "adurl",
    "adurl=",
    "gclid",
    "gbraid",
    "wbraid",
    "gad_source",
    "fbclid",
    "msclkid",
    "dclid",
    "twclid",
    "ttclid",
    "yclid",
    "utm_source=adwords",
)


def is_ad_syndication_url(url: str) -> bool:
    """
    True when a URL points at an ad exchange, syndication network or wrapper.

    Filtering happens on the *host and query*, not on the anchor's class, because
    a class name is a claim the page makes about itself while the destination is
    what the audit would actually contact. A link that redirects through an
    exchange is refused for the same reason a link to one is.
    """
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if not host:
        return True
    for marker in _AD_SYNDICATION_MARKERS:
        # A trailing dot marks a prefix family (`criteo.` matches criteo.com and
        # criteo.net, and `adservice.google.` its subdomains). It must sit on a
        # label boundary, so `notcriteo.com` does not match.
        if marker.endswith("."):
            if host.startswith(marker) or ("." + marker) in host:
                return True
        elif host == marker or host.endswith("." + marker):
            return True
    blob = (parsed.query or "").lower() + " " + (parsed.netloc or "").lower()
    for marker in _REDIRECT_PARAM_MARKERS:
        if marker in blob:
            return True
    return False


@dataclass
class BannerCandidate:
    """One promotional banner the page offered, and what it points at."""

    url: str
    selector_hint: str = ""
    text: str = ""
    #: True when the destination is inside the audited site rather than a partner.
    first_party: bool = False
    #: True when the outbound gate admitted the destination for this session.
    authorized: bool = False
    #: Why the gate refused it, when it did. Kept so the report can name the
    #: refused destination instead of silently dropping it.
    refusal: str = ""
    #: Which frame the banner was found in: 0 is the main document, and positive
    #: values are the child frames in `page.frames` order.
    #:
    #: An ordinal rather than the frame's URL, because a frame's URL can be empty
    #: (`about:blank`, `srcdoc`) or shared by two frames, and the click has to
    #: resolve back to *the* frame the banner was seen in. Pairing the candidate
    #: with the wrong frame would aim the cursor at another frame's geometry.
    frame_index: int = 0

    @property
    def from_iframe(self) -> bool:
        """True when this banner was found in a child frame, not the main document."""
        return self.frame_index > 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "selector_hint": self.selector_hint,
            "text": self.text,
            "first_party": self.first_party,
            "authorized": self.authorized,
            "refusal": self.refusal,
            "frame_index": self.frame_index,
            "from_iframe": self.from_iframe,
        }


def discover_banner_candidates(
    anchors: Sequence[Any],
    *,
    page_url: str,
    scope: Any = None,
    limit: int = 60,
    include_iframes: bool = True,
) -> List[BannerCandidate]:
    """
    Turn the page's anchors into the promotional candidates worth considering.

    `anchors` is what the page reported -- a list of mappings with `href`, and
    optionally `text`, `selector` and `frame_index`, produced by the discovery
    script in the runner. Keeping this a pure function of that data is what makes
    the filtering testable without a browser.

    Filtering, in order: a resolvable http(s) destination; not an ad-exchange
    wrapper; and a deduplication pass. When a `scope` is given, a destination the
    outbound gate refuses is *kept* with `authorized=False` and a `refusal`
    reason rather than dropped, so the audit can report that a third-party or
    undeclared banner existed and was deliberately not followed. Only authorized
    candidates are ever eligible for selection (`select_campaign` filters on
    `authorized`), so keeping the refused ones cannot cause traffic.

    `include_iframes=False` drops every anchor reported from a child frame, which
    is how an operator restricts discovery to the main document. The policy lives
    here rather than only in the runner so it is a pure, testable decision -- and
    so there is one place that decides it, not one per call site.
    """
    seen = set()
    candidates: List[BannerCandidate] = []
    base = urlparse(page_url)

    for anchor in anchors or []:
        href = ""
        frame_index = 0
        if isinstance(anchor, dict):
            href = str(anchor.get("href") or "").strip()
            try:
                frame_index = max(0, int(anchor.get("frame_index") or 0))
            except (TypeError, ValueError):
                frame_index = 0
        elif isinstance(anchor, str):
            href = anchor.strip()
        if not href:
            continue
        # An iframe banner the operator asked not to inspect is dropped before the
        # gate, so excluding frames cannot leave the frame's destination counted
        # in the refused-banner evidence either.
        if frame_index > 0 and not include_iframes:
            continue

        parsed = urlparse(href)
        if (parsed.scheme or "").lower() not in ("http", "https"):
            continue
        if not parsed.hostname:
            continue
        # A same-document fragment is not a destination.
        if _same_document(parsed, base):
            continue
        key = href.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)

        if is_ad_syndication_url(href):
            continue

        candidate = BannerCandidate(
            url=href,
            selector_hint=str(anchor.get("selector") or "") if isinstance(anchor, dict) else "",
            text=str(anchor.get("text") or "")[:120] if isinstance(anchor, dict) else "",
            frame_index=frame_index,
        )
        if scope is not None:
            candidate.first_party = scope.permits_url(href)
            candidate.authorized = scope.check_unattended(href)
            if not candidate.authorized:
                candidate.refusal = (
                    "the destination host is a partner host that was not declared "
                    "in the outbound scope"
                )
        else:
            candidate.authorized = True
        candidates.append(candidate)
        if len(candidates) >= max(1, int(limit)):
            break
    return candidates


def _same_document(parsed, base) -> bool:
    return bool(
        parsed.hostname == base.hostname
        and (parsed.path or "/") == (base.path or "/")
        and parsed.query == base.query
    )


@dataclass
class OutboundPlan:
    """What one visitor does about the funnel: whether, and to which banner."""

    triggered: bool
    campaign_url: Optional[str] = None
    selector_hint: str = ""
    first_party: bool = True
    #: The frame the chosen banner was found in (0 = the main document). Carried
    #: through the plan because the click has to resolve back to that frame: the
    #: same href can exist in two frames, and pressing the wrong one would move
    #: the cursor to another frame's geometry.
    frame_index: int = 0

    def to_dict(self) -> dict:
        return {
            "triggered": self.triggered,
            "campaign_url": self.campaign_url,
            "selector_hint": self.selector_hint,
            "first_party": self.first_party,
            "frame_index": self.frame_index,
        }


def roll_outbound_trigger(
    rate_pct: float, rng: random.Random, *, uniform: Optional[float] = None
) -> bool:
    """
    The per-session CTR roll: `uniform(0, 100) < rate_pct`.

    `uniform` lets a caller supply the draw, which makes the roll deterministic in
    tests without reaching into the RNG's state.
    """
    draw = rng.uniform(0.0, 100.0) if uniform is None else float(uniform)
    return draw < float(rate_pct)


def select_campaign(
    candidates: Sequence[BannerCandidate], rng: random.Random
) -> Optional[BannerCandidate]:
    """
    Choose one banner uniformly from the candidates.

    `random.choice()` over the whole set, not weighted by position or size: a
    visitor picks what catches their eye, and a distribution that favours the
    first banner is the pattern a funnel audit exists to *find*, not to emit.
    """
    usable = [c for c in candidates if c.authorized]
    if not usable:
        return None
    return rng.choice(usable)


def plan_outbound_visit(
    rate_pct: float,
    candidates: Sequence[BannerCandidate],
    rng: random.Random,
) -> OutboundPlan:
    """
    Decide whether this visitor clicks a banner, and which one.

    Planning before touching the network keeps the roll and the choice together:
    a visitor who did not trigger should not later discover a banner, and one who
    did should not have the destination chosen by whatever the page happens to
    render first.
    """
    if not roll_outbound_trigger(rate_pct, rng):
        return OutboundPlan(triggered=False)
    chosen = select_campaign(candidates, rng)
    if chosen is None:
        return OutboundPlan(triggered=False)
    return OutboundPlan(
        triggered=True,
        campaign_url=chosen.url,
        selector_hint=chosen.selector_hint,
        first_party=chosen.first_party,
        frame_index=chosen.frame_index,
    )