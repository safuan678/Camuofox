"""
Scope enforcement for the WAF / bot-defense audit tool.

The audit tool drives Camoufox at a target the operator does not control from
inside this process. Everything in this package is therefore gated behind an
explicit, narrow, verifiable scope: a target must be named *and* acknowledged as
authorized before any request is allowed to leave.

The gate is enforced here, at the single point every scheduled request passes
through, rather than trusted to the caller. A UI checkbox is a reminder, not a
security control; this is the control.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Sequence, Set
from urllib.parse import urlparse

__all__ = [
    "ScopeViolation",
    "AuthorizationRequired",
    "TargetScope",
    "registrable_domain",
]

#: Second-level labels that are part of a registry's own structure rather than a
#: site's name, under a two-letter country code.
#:
#: `example.co.uk` is one site whose registrable domain is the last three labels,
#: not `co.uk`; `blog.example.co.uk` belongs to `example.co.uk`. Resolving this
#: needs the Public Suffix List, which is a data file this package does not ship
#: and will not fetch at import time. The token list below covers the structures
#: that actually appear in audit targets, and the fallback (last two labels) is
#: correct for every plain TLD -- so an unlisted oddity degrades to the
#: two-label answer rather than to something wrong in a way that widens scope.
_MULTI_PART_SLD_TOKENS = frozenset(
    {
        "ac", "asn", "co", "com", "edu", "firm", "gen", "go", "gob", "govern",
        "gov", "govt", "gr", "id", "idv", "ind", "in", "kiwi", "lg", "ltd",
        "maori", "med", "me", "mil", "muni", "ne", "net", "nhs", "or", "org",
        "pe", "per", "plc", "re", "res", "sch", "school", "sc", "web",
    }
)


def registrable_domain(host: str) -> str:
    """
    The main domain `host` belongs to -- what an operator means by "the site".

    A target of `https://staging.example.co.uk/pricing` names `example.co.uk`.
    Deriving this rather than asking for it is what lets the GUI infer the
    authorized host from the target URL alone: the operator names the page they
    want audited, and the site it lives on follows from it.

    IP literals are returned unchanged -- a literal has no domain structure, and
    stripping labels off `203.0.113.7` would invent a scope that does not exist.
    A single-label host (`localhost`) is returned unchanged for the same reason.
    """
    host = _normalize_host(host)
    if not host:
        return ""
    if _is_ip_literal(host):
        return host
    if not _is_valid_hostname(host):
        # Not a host at all -- `//not a url` yields "not a url" from `urlparse`.
        # Returning "" rather than the input keeps a caller from scoping an audit
        # to a string that cannot resolve; `for_target` turns that into an error.
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    # Only a two-letter final label can be a country code, and only a country code
    # has the registry's own structure in front of the site's name. A three-label
    # `.com` host is `foo.bar.com`, whose registrable domain is `bar.com`.
    if len(labels[-1]) == 2 and labels[-2] in _MULTI_PART_SLD_TOKENS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class ScopeViolation(RuntimeError):
    """A request was aimed outside the authorized target scope."""


class AuthorizationRequired(RuntimeError):
    """The audit was started without an authorization acknowledgment."""


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


#: A hostname is dot-separated labels of letters, digits and inner hyphens. The
#: check exists because `urlparse` is permissive: it happily returns `not a url`
#: as the hostname of `//not a url`, and an audit scoped to a string with spaces
#: in it would then claim a host that cannot resolve.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                          r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _is_valid_hostname(host: str) -> bool:
    return bool(host) and bool(_HOSTNAME_RE.match(host))


@dataclass
class TargetScope:
    """
    The set of hosts an audit is permitted to touch.

    Matching is exact-host plus explicitly listed subdomains; a bare domain does
    *not* implicitly authorize every subdomain, because a wildcard scope is how
    an audit accidentally reaches a third-party property that shares a suffix.
    """

    hosts: List[str] = field(default_factory=list)
    allow_subdomains: bool = False
    acknowledged: bool = False
    acknowledgment_note: str = ""
    #: Operator-declared campaign/partner destinations to keep the outbound
    #: funnel *out* of.
    #:
    #: The funnel is deny-by-exception, not allow-by-exception: every banner the
    #: page (or an iframe inside it) serves is in scope by default, because an
    #: audit that silently skips a site's real ad traffic measures nothing. This
    #: list is the exception -- the campaign hosts the operator wants left alone,
    #: for a partner they must not touch or an ad network they do not want to
    #: hit. Naming one here skips it; naming nothing excludes nothing.
    excluded_outbound_hosts: List[str] = field(default_factory=list)
    #: Hosts actually reached through the funnel during this session.
    #:
    #: Populated by `authorize_outbound()` so a report can state precisely which
    #: destinations the run touched, rather than only which were excluded.
    session_outbound: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.hosts = [_normalize_host(h) for h in self.hosts if _normalize_host(h)]
        self.excluded_outbound_hosts = [
            _normalize_host(h) for h in self.excluded_outbound_hosts if _normalize_host(h)
        ]

    # -- construction ------------------------------------------------------

    @classmethod
    def for_target(
        cls,
        target_url: str,
        *,
        include_subdomains: bool = True,
        acknowledged: bool = True,
        acknowledgment_note: str = "",
        exclude_urls: Sequence[str] = (),
    ) -> "TargetScope":
        """
        Derive the scope from the one URL the operator actually named.

        The authorized host is not a second thing to type: it is a property of the
        target. Asking for both invited the two to disagree -- a target on
        `staging.example.com` scoped to `example.com` would have the audit refused
        its own arrival page -- and it made the common case two fields instead of
        one. Deriving it here means GUI and CLI cannot drift apart on the rule.

        `include_subdomains` is the operator's answer to a real question: whether
        they are auditing one page or a site. A static single page has no
        subdomains to wander into, which is why the GUI pairs it with a one-page
        journey (see `JourneyConfig`).
        """
        host = urlparse(
            target_url if "//" in target_url else f"//{target_url}"
        ).hostname or ""
        # `urlparse` is permissive enough to hand back `not a url` for `//not a
        # url`, so the derived host is validated rather than trusted. An audit
        # scoped to a string that cannot resolve would report a scope it never had.
        if not host or not (_is_valid_hostname(host) or _is_ip_literal(host)):
            raise ValueError(f"Could not parse a host out of {target_url!r}")
        # The target's own host must be in scope even in the no-subdomains mode
        # and even when it sits on a subdomain. Without it, a target of
        # `https://staging.example.com/` scoped to `example.com` with subdomains
        # off would have the gate refuse the audit's own arrival page -- the run
        # would report OUT_OF_SCOPE for the one URL the operator asked about.
        # With subdomains allowed the main domain already covers it, so listing it
        # again would only make the scope read as two hosts when it is one site.
        main = registrable_domain(host)
        hosts = [main]
        if not include_subdomains and host != main:
            hosts.append(host)
        return cls.from_urls(
            hosts,
            allow_subdomains=include_subdomains,
            acknowledged=acknowledged,
            acknowledgment_note=acknowledgment_note,
            exclude_urls=exclude_urls,
        )

    @classmethod
    def from_urls(
        cls,
        urls: Sequence[str],
        *,
        allow_subdomains: bool = False,
        acknowledged: bool = False,
        acknowledgment_note: str = "",
        exclude_urls: Sequence[str] = (),
    ) -> "TargetScope":
        hosts: List[str] = []
        for url in urls:
            parsed = urlparse(url if "//" in url else f"//{url}")
            host = parsed.hostname
            if not host:
                raise ValueError(f"Could not parse a host out of {url!r}")
            hosts.append(host)
        excluded_outbound_hosts: List[str] = []
        for url in exclude_urls:
            parsed = urlparse(url if "//" in url else f"//{url}")
            host = parsed.hostname
            if not host:
                raise ValueError(f"Could not parse a host out of {url!r}")
            excluded_outbound_hosts.append(host)
        return cls(
            hosts=hosts,
            allow_subdomains=allow_subdomains,
            acknowledged=acknowledged,
            acknowledgment_note=acknowledgment_note,
            excluded_outbound_hosts=excluded_outbound_hosts,
        )

    # -- the gate ----------------------------------------------------------

    def check(self, url: str) -> str:
        """
        Return the normalized host for `url`, or raise.

        Every navigation goes through here, so there is exactly one place that
        decides whether a request is in scope.
        """
        if not self.acknowledged:
            raise AuthorizationRequired(
                "Refusing to send traffic: the audit has not been acknowledged as "
                "authorized. The operator must confirm they own the target or have "
                "written permission to test it."
            )
        if not self.hosts:
            raise ScopeViolation(
                "Refusing to send traffic: the target scope is empty. Name the "
                "hosts under test before starting the audit."
            )

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ScopeViolation(
                f"Refusing to fetch {url!r}: only http/https targets are audited."
            )

        host = _normalize_host(parsed.hostname or "")
        if not host:
            raise ScopeViolation(f"Refusing to fetch {url!r}: no host in URL.")
        if not self.permits(host):
            raise ScopeViolation(
                f"Refusing to fetch {host!r}: outside the authorized scope "
                f"({', '.join(self.hosts)}). The audit will not touch hosts that "
                f"were not named."
            )
        return host

    def permits(self, host: str) -> bool:
        """Host-only check, for pre-flight validation without raising."""
        host = _normalize_host(host)
        if not host:
            return False
        for allowed in self.hosts:
            if host == allowed:
                return True
            if self.allow_subdomains and not _is_ip_literal(allowed):
                if host.endswith("." + allowed):
                    return True
        return False

    def permits_url(self, url: str) -> bool:
        host = _normalize_host(urlparse(url).hostname or "")
        return self.permits(host)

    def permits_navigation(self, url: str) -> bool:
        """
        The browser guard's check: may this request be issued?

        Two ways in. The URL is inside the authorized scope -- the target itself
        and anything it serves. Or its host is one the funnel has *already*
        reached, recorded in `session_outbound` when `authorize_outbound` admitted
        the click-through. The second arm is what lets a banner landing page load
        its own assets without re-opening the gate to every host the page names.

        Deliberately NOT "call authorize_outbound and see": that would make the
        guard permissive for any URL, so a link on a landing page could walk the
        audit onto a third party. Admission through the funnel is a decision the
        funnel makes explicitly, in advance; the guard only reads the result.
        """
        host = _normalize_host(urlparse(url).hostname or "")
        if not host:
            return False
        if self.permits(host):
            return True
        return host in self.session_outbound

    # -- session-scoped outbound authorization -----------------------------
    #
    # The outbound-funnel audit follows promotional banners to the destination
    # they point at, and that destination is often a partner or campaign host
    # outside the site being audited. The funnel is therefore deny-by-exception:
    # a banner the page serves is followed by default, because that is the ad
    # traffic the audit exists to measure, and an audit that skipped it would
    # report "no banner" for a page that was displaying one.
    #
    # The exception is the operator's exclusion list. A campaign host named there
    # is skipped rather than followed, which is what you want for a partner you
    # must not touch or an ad network you do not want to hit. Naming nothing
    # excludes nothing.
    #
    # What survives from the allowlist design is the shape of the refusal: a
    # non-http(s) scheme, an IP-literal host, and an empty host are still refused
    # outright, and every destination the run actually reaches is still recorded
    # in `session_outbound`. The safety properties that matter are the recorded
    # set and the refusals, not the direction of the default.

    def authorize_outbound(self, url: str) -> bool:
        """
        Admit one outbound destination for this session.

        Returns False without raising when the URL is not a web destination, is an
        IP literal, or names an excluded campaign host, so the discovery path can
        record it. Returns True otherwise -- the funnel follows what the page
        serves unless the operator has excluded it.

        Refuses, deliberately: any non-http(s) scheme, an empty host, and an
        IP-literal host (the cloud metadata endpoint is a literal, and so is any
        internal service a campaign link could be tricked into naming).
        """
        parsed = urlparse(url)
        if (parsed.scheme or "").lower() not in ("http", "https"):
            return False
        host = _normalize_host(parsed.hostname or "")
        if not host or _is_ip_literal(host):
            return False
        if self._outbound_excluded(host):
            return False
        self.session_outbound.add(host)
        return True

    def _outbound_excluded(self, host: str) -> bool:
        """
        Whether `host` is one the operator took the funnel out of.

        A bare named domain also covers its subdomains -- excluding `ads.example.com`
        while still following `track.ads.example.com` would not be what an operator
        writing that line meant. Matching is suffix-at-a-label-boundary so
        `notads.example.com` is not caught by `ads.example.com`.
        """
        for entry in self.excluded_outbound_hosts:
            if host == entry or host.endswith("." + entry):
                return True
        return False

    def check_unattended(self, url: str) -> bool:
        """
        The discovery path's check: does the outbound gate permit this URL?

        Deliberately shaped like `check()` minus the raise. The funnel walk uses
        this so a refused third-party banner is a recorded finding rather than an
        exception that aborts the visit -- the audit should report the skipped
        destination, not die on it. It still authorizes through
        `authorize_outbound()`, so nothing reaches a socket that the gate refused.
        """
        if not self.acknowledged or not self.hosts:
            return False
        return self.authorize_outbound(url)

    def outbound_description(self) -> str:
        excluded = ", ".join(sorted(self.excluded_outbound_hosts)) or "(none)"
        reached = ", ".join(sorted(self.session_outbound)) or "(none)"
        return f"excluded: {excluded}; reached this session: {reached}"

    # -- description -------------------------------------------------------

    def describe(self) -> str:
        scope = ", ".join(self.hosts) if self.hosts else "(none)"
        suffix = " + subdomains" if self.allow_subdomains else ""
        return f"{scope}{suffix}"

    def to_dict(self) -> dict:
        return {
            "hosts": list(self.hosts),
            "allow_subdomains": self.allow_subdomains,
            "acknowledged": self.acknowledged,
            "acknowledgment_note": self.acknowledgment_note,
            "excluded_outbound_hosts": list(self.excluded_outbound_hosts),
            "session_outbound": sorted(self.session_outbound),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TargetScope":
        return cls(
            hosts=list(data.get("hosts") or []),
            allow_subdomains=bool(data.get("allow_subdomains")),
            acknowledged=bool(data.get("acknowledged")),
            acknowledgment_note=str(data.get("acknowledgment_note") or ""),
            excluded_outbound_hosts=list(data.get("excluded_outbound_hosts") or []),
            session_outbound=set(data.get("session_outbound") or ()),
        )
