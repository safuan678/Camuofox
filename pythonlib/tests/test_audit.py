"""
Tests for camoufox.audit - the WAF / bot-defense audit engine.

These run against a real HTTP server on localhost that behaves like a small WAF,
rather than against mocks, so the whole path (scheduling, HTTP, classification,
attribution, reporting) is exercised end to end.

Run with:
    cd pythonlib && python -m pytest tests/test_audit.py -v
"""

import asyncio
import os
import random
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dataclasses import replace  # noqa: E402

from camoufox.audit import (  # noqa: E402
    SINGLE_LEVEL_VISITORS,
    AuditConfig,
    AuditReport,
    AuditRunner,
    AuthorizationRequired,
    CAPABILITIES,
    EVASION_LEVELS,
    JourneyConfig,
    LevelResult,
    SafetyLimits,
    ScopeViolation,
    TargetScope,
    Verdict,
    VisitResult,
    build_schedule,
    classify_response,
    ladder_problems,
    level_by_id,
)
from camoufox.audit.report import build_findings, render_html, render_text  # noqa: E402
from camoufox.audit.schedule import ArrivalPattern, ScheduleConfig  # noqa: E402
from camoufox.proxy import ProxyRotator  # noqa: E402


# --------------------------------------------------------------------------
# A small WAF to audit: blocks library user agents, challenges Chrome-like ones
# on the first hit and allows them once a cookie is presented.
# --------------------------------------------------------------------------


class _WafHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits = 0
    #: Every request's headers, so a test can assert what actually reached the
    #: target rather than what the config merely accepted.
    seen_headers = []

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        type(self).hits += 1
        type(self).seen_headers.append(dict(self.headers.items()))
        ua = self.headers.get("User-Agent", "")
        cookie = self.headers.get("Cookie", "")

        if "python" in ua.lower() or "urllib" in ua.lower() or not ua:
            self._send(
                403,
                b"<html>Attention Required! | Cloudflare</html>",
                {"Server": "cloudflare"},
            )
            return

        if "Chrome" in ua and "cf_clearance" not in cookie:
            self._send(
                200,
                b"<html>Just a moment...</html>",
                {"cf-mitigated": "challenge"},
            )
            return

        self._send(200, b"<html>welcome</html>")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def waf_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WafHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}/"
    server.shutdown()
    server.server_close()


def _scope(url, **kwargs):
    return TargetScope.from_urls([url], acknowledged=True, **kwargs)


def _config(url, **overrides):
    params = dict(
        target_url=url,
        scope=_scope(url),
        levels=[0],
        visitor_count=6,
        # Small window keeps the suite fast: arrivals are still spread out and
        # jittered, which is all these tests need. The scheduling semantics
        # themselves are covered by the schedule tests above.
        duration_hours=0.002,
        cooldown_between_levels_s=0,
        limits=SafetyLimits(max_requests=200, max_rps=50, max_concurrency=4),
        seed=1,
    )
    params.update(overrides)
    # The two ways of naming rungs are mutually exclusive, and `levels=[0]` is
    # only here to keep an ordinary ladder test cheap. A single-rung config must
    # not inherit it, or every such test would fail validation instead of testing
    # what it meant to.
    if params.get("single_level_mode") and "levels" not in overrides:
        params["levels"] = None
    return AuditConfig(**params)


# --------------------------------------------------------------------------
# Classification: the distinction the whole report rests on
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,headers,body,expected",
    [
        # A 403 block page is a refusal, not an invitation to solve a challenge.
        (403, {"server": "cloudflare"}, "<html>Attention Required! | Cloudflare</html>", Verdict.BLOCKED),
        (403, {}, "<html>Access Denied</html>", Verdict.BLOCKED),
        # The same marker with a 200 is a challenge interstitial.
        (200, {}, "<html>Just a moment...</html>", Verdict.CHALLENGED),
        (200, {"cf-mitigated": "challenge"}, "", Verdict.CHALLENGED),
        (200, {}, "<html>Checking your browser before accessing</html>", Verdict.CHALLENGED),
        # Rate limiting is distinct from blocking: it has a retry horizon.
        (429, {}, "", Verdict.RATE_LIMITED),
        (429, {"retry-after": "30"}, "", Verdict.RATE_LIMITED),
        (503, {}, "", Verdict.RATE_LIMITED),
        # A normal page.
        (200, {}, "<html>hello</html>", Verdict.ALLOWED),
        (200, {"server": "nginx"}, "<html>ok</html>", Verdict.ALLOWED),
        # Server errors are errors, not verdicts about the client.
        (500, {}, "", Verdict.ERROR),
    ],
)
def test_classify_response(status, headers, body, expected):
    assert classify_response(status, headers, body).verdict == expected


def test_classification_keeps_evidence():
    """Every verdict should carry the signal that produced it."""
    result = classify_response(
        403, {"server": "cloudflare"}, "<html>Attention Required! | Cloudflare</html>"
    )
    assert result.vendors, "expected a product attribution"
    assert result.evidence, "expected the matched signal to be recorded"
    assert result.reason


def test_block_and_challenge_are_not_conflated():
    """The regression this suite exists for: a hard block scored as a challenge."""
    block = classify_response(403, {}, "<html>Attention Required!</html>")
    challenge = classify_response(200, {}, "<html>Attention Required!</html>")
    assert block.verdict == Verdict.BLOCKED
    assert challenge.verdict == Verdict.CHALLENGED


# --------------------------------------------------------------------------
# Scope / authorization gate
# --------------------------------------------------------------------------


def test_scope_requires_acknowledgment():
    """The gate must refuse at check time, not merely warn."""
    scope = TargetScope.from_urls(["https://example.com"], acknowledged=False)
    with pytest.raises(AuthorizationRequired):
        scope.check("https://example.com/")


def test_scope_blocks_off_scope_target():
    scope = TargetScope.from_urls(["https://example.com"], acknowledged=True)
    assert scope.permits("example.com")
    assert not scope.permits("other.example.net")
    with pytest.raises(ScopeViolation):
        scope.check("https://other.example.net/")


def test_scope_subdomains_opt_in():
    strict = TargetScope.from_urls(["https://example.com"], acknowledged=True)
    assert not strict.permits("api.example.com")

    loose = TargetScope.from_urls(
        ["https://example.com"], acknowledged=True, allow_subdomains=True
    )
    assert loose.permits("api.example.com")


def test_scope_rejects_lookalike_host():
    """A suffix check would let evil-example.com through; the boundary must be exact."""
    scope = TargetScope.from_urls(
        ["https://example.com"], acknowledged=True, allow_subdomains=True
    )
    assert not scope.permits("evil-example.com")
    assert not scope.permits("notexample.com")


def test_config_validate_rejects_out_of_scope_target():
    config = _config("http://127.0.0.1:9/", scope=_scope("https://example.com"))
    assert any("scope" in p.lower() for p in config.validate())


# --------------------------------------------------------------------------
# Scheduling: the property that makes traffic look human
# --------------------------------------------------------------------------


def test_schedule_is_not_uniform():
    """Arrivals must not be evenly spaced; that is the whole point."""
    schedule = build_schedule(
        ScheduleConfig(
            visitor_count=500, duration_hours=24.0, pattern=ArrivalPattern.HUMAN_DIURNAL
        ),
        rng=random.Random(3),
    )
    gaps = schedule.inter_arrival_seconds()
    assert len(gaps) == 499
    assert len(set(round(g, 3) for g in gaps)) > 100, "gaps look quantised, not random"
    assert max(gaps) > min(gaps) * 10, "arrivals are too evenly spread"


def test_schedule_is_not_simultaneous():
    schedule = build_schedule(
        ScheduleConfig(visitor_count=200, duration_hours=1.0),
        rng=random.Random(4),
    )
    offsets = sorted(a.offset_s for a in schedule.arrivals)
    assert offsets[0] < offsets[-1]
    assert all(b - a >= 0 for a, b in zip(offsets, offsets[1:]))


def test_schedule_is_reproducible_with_a_seed():
    def run():
        return [
            a.offset_s
            for a in build_schedule(
                ScheduleConfig(visitor_count=50, duration_hours=1.0),
                rng=random.Random(99),
            ).arrivals
        ]

    assert run() == run()


def test_schedule_respects_arrivals_per_minute_cap():
    """The cap is a safety control, so it must actually bound the burst rate."""
    schedule = build_schedule(
        ScheduleConfig(
            visitor_count=300, duration_hours=1.0, pattern=ArrivalPattern.CONSTANT,
            max_arrivals_per_minute=10,
        ),
        rng=random.Random(5),
    )
    minute_buckets = {}
    for arrival in schedule.arrivals:
        minute_buckets.setdefault(int(arrival.offset_s // 60), 0)
        minute_buckets[int(arrival.offset_s // 60)] += 1
    assert max(minute_buckets.values()) <= 10


def test_schedule_warns_when_window_cannot_fit_visitors():
    """A minimum gap can silently push arrivals past the window; that must surface."""
    schedule = build_schedule(
        ScheduleConfig(visitor_count=100, duration_hours=0.01, min_gap_s=30.0),
        rng=random.Random(6),
    )
    assert schedule.warnings


def test_patterns_produce_different_shapes():
    """
    Constant spreads arrivals evenly; diurnal clusters them by time of day.

    Comparing halves does not separate the two -- the diurnal curve is roughly
    symmetric about noon -- so compare how uneven the hourly buckets are.
    """
    def hourly_spread(pattern):
        schedule = build_schedule(
            ScheduleConfig(visitor_count=400, duration_hours=24.0, pattern=pattern),
            rng=random.Random(7),
        )
        buckets = [0] * 24
        for arrival in schedule.arrivals:
            buckets[min(23, int(arrival.offset_s // 3600))] += 1
        mean = sum(buckets) / len(buckets)
        variance = sum((b - mean) ** 2 for b in buckets) / len(buckets)
        return variance / (mean ** 2) if mean else 0.0  # squared coefficient of variation

    constant = hourly_spread(ArrivalPattern.CONSTANT)
    diurnal = hourly_spread(ArrivalPattern.HUMAN_DIURNAL)

    # Even a perfectly uniform rate shows sampling noise of roughly 1/mean per
    # bucket (~0.06 at 400 visitors over 24 buckets), so the uniform bound has
    # to sit above that; the diurnal curve then has to clear it by a wide margin.
    assert constant < 0.15, f"constant pattern should be near-uniform, got {constant}"
    assert diurnal > constant * 2.5, (
        f"diurnal pattern should cluster far more than constant "
        f"(diurnal={diurnal}, constant={constant})"
    )


# --------------------------------------------------------------------------
# Evasion ladder
# --------------------------------------------------------------------------


def test_ladder_is_ordered_and_each_rung_isolates_one_vector():
    ids = [level.id for level in EVASION_LEVELS]
    assert ids == sorted(ids), "ladder must be ordered by increasing capability"
    for level in EVASION_LEVELS:
        assert level.isolates, f"{level.name} does not say what it isolates"
        assert level.description


def test_evasion_level_lookup():
    assert level_by_id(0).id == 0
    assert level_by_id(len(EVASION_LEVELS) - 1).id == len(EVASION_LEVELS) - 1


# --------------------------------------------------------------------------
# Runner end to end against the local WAF
# --------------------------------------------------------------------------


def test_runner_attributes_block_to_the_naive_rung(waf_server):
    """L0 should be refused, and the refusal attributed to the WAF."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())

    assert report.levels, "expected at least one level result"
    level = report.levels[0]
    assert level.completed == 6
    assert level.detected == 6
    assert level.bypass_rate == 0.0
    assert "Cloudflare" in level.vendors_seen()

    effective = report.first_effective_level()
    assert effective is not None and effective.level.id == 0


def test_runner_reports_clean_traffic_as_allowed(waf_server):
    """A browser-like client with clearance must not be flagged."""
    report = asyncio.run(
        AuditRunner(_config(waf_server, extra_headers={"User-Agent": "Mozilla/5.0 Chrome/131", "Cookie": "cf_clearance=1"})).run()
    )
    level = report.levels[0]
    assert level.allowed == 6
    assert level.bypass_rate == 1.0
    assert report.first_effective_level() is None


def test_runner_records_exit_ip_and_proxy_label(waf_server):
    """Per-visit attribution must survive into the report."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    assert report.levels[0].visits
    for visit in report.levels[0].visits:
        assert visit.visitor_index >= 0
        assert visit.reason, "every visit needs a stated reason"


def test_runner_stops_at_request_ceiling(waf_server):
    """The ceiling must abort the run rather than being advisory."""
    config = _config(
        waf_server,
        visitor_count=50,
        limits=SafetyLimits(max_requests=5, max_rps=50, max_concurrency=4),
    )
    report = asyncio.run(AuditRunner(config).run())
    assert report.total_requests <= 5
    assert report.aborted


def test_runner_respects_cancellation(waf_server):
    cancel = threading.Event()
    cancel.set()
    report = asyncio.run(
        AuditRunner(_config(waf_server, visitor_count=40), cancel_event=cancel).run()
    )
    assert report.aborted
    assert report.total_requests < 40


def test_runner_emits_progress_events(waf_server):
    events = []
    asyncio.run(
        AuditRunner(_config(waf_server), on_progress=events.append).run()
    )
    kinds = {e.get("event") for e in events}
    assert "level_start" in kinds
    assert "visit" in kinds
    assert "level_end" in kinds


def test_runner_refuses_out_of_scope_target(waf_server):
    """An out-of-scope target must not receive traffic; the run fails closed."""
    config = _config(waf_server, scope=_scope("https://example.com"))
    report = asyncio.run(AuditRunner(config).run())
    assert report.aborted
    assert "scope" in report.abort_reason.lower()
    assert report.total_requests == 0


def test_display_detection_matches_the_environment(monkeypatch):
    """
    A headed rung needs an X server; detecting one must not be optimistic.

    Reporting a display that is not there sends a headed launch straight into
    "no DISPLAY environment variable specified" and turns a verdict into an error.
    """
    monkeypatch.delenv("DISPLAY", raising=False)
    assert AuditRunner._has_display() is False

    monkeypatch.setenv("DISPLAY", ":98765")
    assert AuditRunner._has_display() is False, "a socket that does not exist is not a display"


def test_headed_level_falls_back_to_virtual_display(waf_server, monkeypatch):
    """
    On a host with no X server, a headed rung must use Camoufox's virtual display
    rather than failing to launch, and must say so in a progress notice.

    Asserted on the assembled launch options, not on a live visit: the pythonlib
    tier is browser-free by design (CI does not fetch a browser for it), so a
    test that needs a real launch would report CamoufoxNotInstalled as an audit
    error -- a false failure of the tier's own contract.
    """
    monkeypatch.delenv("DISPLAY", raising=False)
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[2], visitor_count=2),
        on_progress=events.append,
    )

    options = runner._launch_options(level_by_id(2))

    assert options["headless"] == "virtual", (
        "a headed rung with no display must fall back to the virtual display"
    )
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("virtual display" in n.get("message", "") for n in notices), (
        "the fallback must be announced, not silent"
    )


def test_an_explicit_display_is_left_alone(waf_server, monkeypatch):
    """A host that has an X server must launch headed, not virtual."""
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[2], visitor_count=1))

    assert runner._launch_options(level_by_id(2))["headless"] is False


def test_geoip_absent_falls_back_instead_of_failing_to_launch(waf_server, monkeypatch):
    """
    Rungs that ask for geoip must still run when the optional extra is missing.

    geoip2 is an optional dependency, so on a plain install every rung from L3 up
    would fail to launch, and the audit would report errors for levels it never
    actually exercised. The masking is weaker without geolocation, but a rung that
    runs and is measured beats one that errors out.

    As above, this asserts the launch contract rather than a live visit, so it
    holds on the browser-free tier.
    """
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: False))
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[3], visitor_count=1),
        on_progress=events.append,
    )

    options = runner._launch_options(level_by_id(3))

    assert options["geoip"] is False, (
        "the geoip flag must be cleared when the extra is missing, or the rung "
        "fails to launch instead of being measured"
    )
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("geoip" in n.get("message", "").lower() for n in notices), (
        "a weaker mask must be announced, not silent"
    )


def test_geoip_is_kept_when_the_extra_is_installed(waf_server, monkeypatch):
    """The flag survives when geoip2 is importable: the fallback is conditional."""
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[3], visitor_count=1))

    assert runner._launch_options(level_by_id(3))["geoip"] is True


def test_rotation_rung_without_a_pool_says_so(waf_server):
    """
    A proxy rung with no pool must not report itself as IP rotation.

    L4 and up are defined by "a fresh exit IP per visitor". With no rotator the
    visit goes out on this host's own address, so a report that still called the
    rung "Proxy rotation" would point the operator at a control that was never
    exercised. The run proceeds (some masking still happens) but announces the
    gap.
    """
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[4], visitor_count=1),
        on_progress=events.append,
    )
    report = asyncio.run(runner.run())

    assert report.levels[0].level.id == 4
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("without a proxy" in n.get("message", "") for n in notices), notices


def test_no_missing_proxy_notice_when_a_pool_is_configured(waf_server, tmp_path):
    """The notice is conditional, so a configured pool must not trigger it."""
    pool = tmp_path / "proxies.txt"
    pool.write_text("http://127.0.0.1:1\n", encoding="utf-8")
    events = []
    config = _config(
        waf_server,
        levels=[4],
        visitor_count=1,
        proxy={"mode": "file", "file": str(pool)},
    )
    runner = AuditRunner(config, on_progress=events.append)

    assert runner._rotator is not None
    notices = [e for e in events if e.get("event") == "notice"]
    assert not any("without a proxy" in n.get("message", "") for n in notices), notices


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def test_findings_name_the_holding_rung(waf_server):
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    findings = " ".join(build_findings(report))
    assert "L0" in findings
    assert "Cloudflare" in findings


def test_text_report_is_self_describing(waf_server):
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    text = render_text(report)
    assert report.config.target_url in text
    assert "FINDINGS" in text
    assert "EVASION LADDER" in text


def test_html_report_is_self_contained(waf_server):
    """No external assets: the report must open from disk with no network."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    html = render_html(report)
    assert html.lstrip().startswith("<!doctype html")
    for marker in ("http://cdn", "https://cdn", "<script"):
        assert marker not in html


def test_report_exports_all_formats(waf_server, tmp_path):
    from camoufox.audit.report import write_report

    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    written = write_report(report, str(tmp_path))
    assert set(written) == {"json", "csv", "html", "text"}
    for path in written.values():
        assert os.path.getsize(path) > 0

    import json

    payload = json.loads(open(written["json"]).read())
    assert payload["target_url"] == report.config.target_url
    assert payload["findings"]


def test_html_escapes_target_url(waf_server, tmp_path):
    """A target containing markup must not break out of the report."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    report.config.target_url = "https://example.com/<script>alert(1)</script>"
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------------------------
# The ladder must isolate exactly one capability per rung
# --------------------------------------------------------------------------


def test_ladder_adds_exactly_one_capability_per_rung():
    """Each rung's whole claim is that it differs from the one below by one axis.

    A rung that repeats the rung below it (L3/L4/L5 used to be byte-identical,
    with no launch-option difference at all) or that turns on two axes at once
    makes a verdict unattributable, which is the one thing the ladder exists to
    prevent.
    """
    assert ladder_problems() == []


def test_each_capability_is_introduced_exactly_once():
    seen = [level.adds for level in EVASION_LEVELS if level.adds is not None]
    assert len(seen) == len(set(seen)), f"a capability is introduced twice: {seen}"
    assert set(seen) <= set(CAPABILITIES)


def test_rungs_that_claim_behavior_are_the_only_ones_flagged():
    behavioral = [level.id for level in EVASION_LEVELS if level.is_behavioral]
    assert behavioral == [5, 6], (
        "only L5 and up may act like a human; lower rungs that scroll, type or "
        "carry a referer would credit behavior for a static-signal verdict"
    )


def test_rotation_is_claimed_only_by_the_rungs_that_rotate():
    rotating = [level.id for level in EVASION_LEVELS if level.requires_rotation]
    assert rotating == [4, 5, 6]


def test_the_rungs_below_behavior_do_not_carry_humanize():
    """humanize is Camoufox's cursor humanization: a behavioral capability."""
    for level in EVASION_LEVELS:
        if not level.is_behavioral:
            assert not (level.camoufox_options or {}).get("humanize"), (
                f"{level.name} enables humanize but does not claim behavior"
            )


def test_plan_visit_without_behavior_is_a_single_direct_request():
    """A non-behavioral rung must send one direct request, nothing more."""
    from camoufox.audit.journey import ArrivalSource, JourneyConfig, plan_visit

    plan = plan_visit(JourneyConfig(), random.Random(7), behavior=False)
    assert plan.source == ArrivalSource.DIRECT
    assert plan.referer is None
    assert plan.page_count == 1
    assert plan.scroll_steps == 0
    assert plan.will_type is False
    assert plan.follow_links is False


def test_plan_visit_with_behavior_still_produces_varied_journeys():
    """The gate must not flatten the behavioral rung's own session shape."""
    from camoufox.audit.journey import JourneyConfig, plan_visit

    rng = random.Random(3)
    plans = [plan_visit(JourneyConfig(), rng, behavior=True) for _ in range(40)]
    assert any(p.page_count > 1 for p in plans)
    assert any(p.will_type for p in plans)


# --------------------------------------------------------------------------
# Proxy acquisition is gated on the rung that is defined by rotation
# --------------------------------------------------------------------------


def _pool_file(tmp_path):
    pool = tmp_path / "proxies.txt"
    pool.write_text("http://127.0.0.1:1\n", encoding="utf-8")
    return pool


def test_a_rung_below_rotation_never_acquires_a_proxy(waf_server, tmp_path):
    """L3 is not defined by the exit IP, so it must go out on this host's address.

    Acquiring a session for it would make L3's verdict a product of an IP the rung
    never claimed to use, and would spend pool capacity before L4 ever runs.
    """
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[3],
            visitor_count=2,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )

    def refuse():
        raise AssertionError("L3 must not acquire a proxy")

    runner._acquire_proxy = refuse
    report = asyncio.run(runner.run())
    assert report.levels[0].level.id == 3


def test_a_geoip_rung_resolves_geography_from_the_proxy_not_the_host(monkeypatch):
    """
    The fingerprint's timezone and locale must describe the exit IP, not this host.

    `geoip=True` is resolved at *launch* time by Camoufox, but Playwright scopes
    `proxy` to the *context* -- so launching with the flag and no session baked the
    host's own IP, timezone and locale into every visitor while the traffic exited
    from a proxy pool. On the wire that is a browser whose WebRTC address and
    locale belong to a continent its exit IP is nowhere near, which is the
    geo/exit mismatch the rung exists to rule out.

    `_has_geoip` is stubbed because geoip2 is an optional extra that CI's
    browser-free tier does not install; the launch contract is what is under test,
    not whether this host happens to have the extra.
    """
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: True))
    from camoufox.audit.evasion import EVASION_LEVELS
    from camoufox.proxy import ProxySession, parse_proxy_string

    level = next(lv for lv in EVASION_LEVELS if lv.id == 4)
    runner = AuditRunner(_config("http://127.0.0.1:1/", levels=[4], visitor_count=1))
    verified = ProxySession(
        endpoint=parse_proxy_string("http://127.0.0.1:1"),
        session_id="s",
        strategy="file/round_robin",
        exit_ip="8.8.8.8",
        verified=True,
    )
    # A verified exit is passed straight through, so the launch cannot re-resolve
    # to a different exit than the context will use.
    assert runner._launch_options(level, verified)["geoip"] == "8.8.8.8"


def test_an_unverified_geoip_rung_still_resolves_through_the_proxy(monkeypatch):
    """
    An unverified exit is not a reason to drop geo spoofing -- the proxy answers.

    The fix is the *session*, not the exit IP: with the session in hand,
    `launch_options` asks the proxy what IP the world sees. Leaving `geoip=True`
    and letting it resolve through the proxy is correct, and it also spoofs WebRTC
    and timezone. Disabling geoip here would drop alignment *and* leave WebRTC
    pointing at this host, which is strictly worse than the bug being fixed.
    """
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: True))
    from camoufox.audit.evasion import EVASION_LEVELS
    from camoufox.proxy import ProxySession, parse_proxy_string

    level = next(lv for lv in EVASION_LEVELS if lv.id == 4)
    runner = AuditRunner(_config("http://127.0.0.1:1/", levels=[4], visitor_count=1))
    unverified = ProxySession(
        endpoint=parse_proxy_string("http://127.0.0.1:1"),
        session_id="s",
        strategy="file/round_robin",
        exit_ip=None,
    )
    options = runner._launch_options(level, unverified)
    assert options["geoip"] is True, (
        "an unverified exit must still resolve through the proxy, not fall back "
        "to the host and not be switched off"
    )


def test_a_non_rotating_geoip_rung_needs_no_session(monkeypatch):
    """L3 has no pool; this host's IP is genuinely the answer there."""
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: True))
    from camoufox.audit.evasion import EVASION_LEVELS

    level = next(lv for lv in EVASION_LEVELS if lv.id == 3)
    runner = AuditRunner(_config("http://127.0.0.1:1/", levels=[3], visitor_count=1))
    assert runner._launch_options(level, None)["geoip"] is True


def test_a_proxied_geoip_rung_passes_its_session_to_the_launch():
    """
    Without the session the flag resolves this host; the session is the whole fix.

    This asserts the wiring rather than the resolution: `_open_browser` must hand
    the visitor's session to `AsyncCamoufox`, and `launch_options` must receive it,
    or the geoip logic above never runs against the right proxy.
    """
    import inspect

    from camoufox.audit import runner as runner_mod

    source = inspect.getsource(runner_mod.AuditRunner._open_browser)
    assert "proxy_session" in source
    assert 'launch_kwargs["proxy_session"] = proxy_session' in source


def test_a_rotating_geoip_rung_never_shares_one_browser():
    """
    One shared launch would give every visitor the first visitor's geography.

    The timezone and locale are baked in when the browser starts, so a shared
    browser cannot serve visitors on different exit IPs -- it would make the
    fingerprint *more* inconsistent, not less. L4 stays per-visit; L3 (no
    rotation) may still share.
    """
    from camoufox.audit.evasion import EVASION_LEVELS

    runner = AuditRunner(_config("http://127.0.0.1:1/", levels=[4], visitor_count=1))
    l4 = next(lv for lv in EVASION_LEVELS if lv.id == 4)
    l3 = next(lv for lv in EVASION_LEVELS if lv.id == 3)
    assert runner._launch_needs_own_proxy(l4) is True
    assert l4.requires_rotation and l4.camoufox_options.get("geoip")
    assert runner._launch_needs_own_proxy(l3) is False


def test_rotation_rung_still_acquires_a_proxy(waf_server, tmp_path):
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[4],
            visitor_count=1,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )
    acquired = []
    original = runner._acquire_proxy

    def spy():
        acquired.append(True)
        return original()

    runner._acquire_proxy = spy
    asyncio.run(runner.run())
    assert acquired, "a rotation rung must acquire a proxy session"


def test_proxy_accounting_is_untouched_on_rungs_that_use_no_proxy(waf_server, tmp_path):
    """The per-proxy counter must stay empty for rungs that never take a proxy."""
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[0],
            visitor_count=3,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )
    asyncio.run(runner.run())
    assert runner._proxy_counts == {}


def test_each_visitor_gets_its_own_proxy_session(waf_server, tmp_path):
    """The product claim is "a fresh exit IP per visitor", so pin it per visit.

    The rotator's own tests cover that `acquire_session()` advances; what they
    cannot see is whether the *runner* asks it once per visitor or reuses one
    session across a whole rung. A reused session would make L4's verdict the
    product of a single exit, which is the one thing the rung claims not to do.
    """
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[4],
            visitor_count=3,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )
    seen = []
    original = runner._acquire_proxy

    def spy():
        session, reason = original()
        if session is not None:
            seen.append(session.session_id)
        return session, reason

    runner._acquire_proxy = spy
    asyncio.run(runner.run())

    assert len(seen) >= 2, f"a rotation rung must take a session per visitor: {seen}"
    assert len(seen) == len(set(seen)), f"a session was reused across visitors: {seen}"


def test_a_gateway_session_token_is_substituted_per_visitor(
    waf_server, tmp_path, monkeypatch
):
    """A gateway expresses stickiness through `{session}`, so each visit gets its own.

    Without the substitution every visitor would share one token and therefore
    one exit IP -- a rotation feature that silently rotates nothing.
    """
    # The gateway host is not real, so stub the reachability probe rather than
    # let a DNS failure be read as "the token was not substituted".
    monkeypatch.setattr(ProxyRotator, "_endpoint_reachable", lambda self, endpoint: True)
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[4],
            visitor_count=3,
            proxy={
                "mode": "gateway",
                "gateway": "http://user-session-{session}:pw@gw.invalid:8000",
                "verify_ip": False,
            },
        )
    )
    tokens = []
    original = runner._acquire_proxy

    def spy():
        session, reason = original()
        if session is not None:
            tokens.append(session.endpoint.username)
        return session, reason

    runner._acquire_proxy = spy
    asyncio.run(runner.run())

    assert len(tokens) >= 2, f"expected a token per visitor, got {tokens}"
    assert all("{session}" not in (t or "") for t in tokens), tokens
    assert len(tokens) == len(set(tokens)), f"two visitors shared a gateway token: {tokens}"


# --------------------------------------------------------------------------
# The headless setting is an override, not a silent flattening of the ladder
# --------------------------------------------------------------------------


def test_default_config_leaves_each_rung_its_own_posture(waf_server, monkeypatch):
    """With no override, L1 launches headless and L2 launches headed.

    On a host with a real display the headed rung is `False`; with none it is
    `'virtual'`, Camoufox's own Xvfb. Either way it is *not* headless, which is
    the distinction the ladder depends on.
    """
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[1, 2], visitor_count=1))
    assert runner._launch_options(level_by_id(1))["headless"] is True
    assert runner._launch_options(level_by_id(2))["headless"] is False


def test_headless_rung_falls_back_to_virtual_on_a_displayless_host(waf_server, monkeypatch):
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: False))
    runner = AuditRunner(_config(waf_server, levels=[2], visitor_count=1))
    assert runner._launch_options(level_by_id(2))["headless"] == "virtual"


def test_headless_override_forces_every_rung_and_announces_it(waf_server, monkeypatch):
    """Ticking the box must actually force headless, and say that it overrode L2."""
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[1, 2], visitor_count=1, headless=True),
        on_progress=events.append,
    )
    assert runner._launch_options(level_by_id(1))["headless"] is True
    assert runner._launch_options(level_by_id(2))["headless"] is True
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("forced every rung headless" in n.get("message", "") for n in notices), notices


def test_headful_override_is_honoured_too(waf_server, monkeypatch):
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[1], visitor_count=1, headless=False))
    assert runner._launch_options(level_by_id(1))["headless"] is False


def test_no_override_notice_when_the_rung_agrees_with_the_setting(waf_server, monkeypatch):
    """Forcing headless for L1 agrees with L1, so there is nothing to announce."""
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[1], visitor_count=1, headless=True),
        on_progress=events.append,
    )
    runner._launch_options(level_by_id(1))
    notices = [e for e in events if e.get("event") == "notice"]
    assert not any("forced every rung" in n.get("message", "") for n in notices), notices


# --------------------------------------------------------------------------
# Single-level mode: one rung, a pinned count, and no false attribution
# --------------------------------------------------------------------------


def test_single_level_mode_runs_only_the_selected_rung(waf_server, monkeypatch):
    """L0 alone, with no L0..L4 preamble: one rung means one rung."""
    seen = []

    async def capture(self, level, schedule):
        seen.append(level.id)
        return LevelResult(level=level)

    monkeypatch.setattr(AuditRunner, "_run_level", capture)
    asyncio.run(
        AuditRunner(_config(waf_server, single_level_mode=True, single_level=0)).run()
    )
    assert seen == [0]


def test_single_level_mode_selects_a_browser_rung_without_a_preamble(waf_server):
    """
    A deeper rung is selected directly, with no cheaper rung planned.

    Asserted on the selection rather than by running it: CI never fetches a
    browser, so driving L5 would report a launch failure for the rung instead of
    proving which rungs were chosen.
    """
    config = _config(waf_server, single_level_mode=True, single_level=5)
    assert [level.id for level in config.selected_levels()] == [5]


def test_single_level_mode_pins_the_visitor_count(waf_server):
    """The count is 100 regardless of what the caller passed, so runs compare."""
    config = _config(waf_server, single_level_mode=True, single_level=0, visitor_count=7)
    assert config.visitor_count == SINGLE_LEVEL_VISITORS == 100
    # Asserted on the schedule the run would use: driving 100 visitors takes 100s
    # on the min-gap floor, and the count is decided before any traffic moves.
    assert build_schedule(config.schedule_config()).count == 100


def test_single_level_mode_needs_no_level_list(waf_server):
    """The rung comes from `single_level`, and `levels` is not consulted."""
    config = _config(waf_server, single_level_mode=True, single_level=2, levels=None)
    assert [level.id for level in config.selected_levels()] == [2]


def test_single_level_mode_rejects_a_competing_level_list(waf_server):
    """Two sources for the same decision is a config error, not a silent pick."""
    problems = _config(
        waf_server, single_level_mode=True, single_level=2, levels=[0, 1]
    ).validate()
    assert any("cannot also" in p for p in problems), problems


def test_single_level_mode_rejects_an_out_of_range_rung(waf_server):
    problems = _config(waf_server, single_level_mode=True, single_level=7).validate()
    assert any("single_level must be between 0 and 6" in p for p in problems), problems


def _visit(level_id, verdict, index):
    return VisitResult(
        visitor_index=index, level_id=level_id, started_at=0.0, verdict=verdict
    )


def _report(url, levels, single_level_mode=False, single_level=0, holds_at=None):
    """
    A report with a chosen shape, built without running any traffic.

    Pins the wording tests to the shape of the ladder and the verdicts rather
    than the clock: a real run costs one second per visitor on the min-gap floor,
    and these tests are about the sentence. `holds_at` picks the rung the defenses
    stop, so the attribution branch has something to attribute.
    """
    config = _config(
        url,
        single_level_mode=single_level_mode,
        single_level=single_level,
        # single_level_mode and levels are mutually exclusive by design, so a
        # single-rung config must not also carry a level list.
        levels=None if single_level_mode else levels,
    )
    results = []
    for level_id in levels:
        rung = level_by_id(level_id)
        verdict = (
            Verdict.BLOCKED if holds_at is not None and level_id >= holds_at else Verdict.ALLOWED
        )
        visits = [_visit(level_id, verdict, i) for i in range(4)]
        results.append(LevelResult(level=rung, visits=visits, scheduled=len(visits)))
    return AuditReport(config=config, levels=results)


def test_single_level_run_says_it_cannot_attribute(waf_server):
    """
    A ladder of one cannot name the control doing the work.

    The report's usual headline is "the defenses first hold at Lx", which is a
    claim about a rung *relative to the ones below it*. With none below it, the
    same sentence would be read as an attribution it cannot support.
    """
    report = _report(waf_server, [0], single_level_mode=True, single_level=0)
    findings = " ".join(build_findings(report))
    assert "Single-rung run" in findings
    assert "cannot attribute" in findings
    assert "first hold at" not in findings


def test_single_level_run_announces_the_mode(waf_server, monkeypatch):
    """
    The mode notice is emitted by a real run, without driving a real rung.

    `_run_level` is stubbed because a 100-visitor rung costs 100s on the min-gap
    floor; the notice is emitted before any traffic and is what this asserts.
    """
    events = []

    async def no_traffic(self, level, schedule):
        return LevelResult(level=level)

    monkeypatch.setattr(AuditRunner, "_run_level", no_traffic)
    runner = AuditRunner(
        _config(waf_server, single_level_mode=True, single_level=2),
        on_progress=events.append,
    )
    asyncio.run(runner.run())
    notices = [e.get("message", "") for e in events if e.get("event") == "notice"]
    assert any("Single-rung mode" in n and "L2" in n for n in notices), notices
    assert any(str(SINGLE_LEVEL_VISITORS) in n for n in notices), notices


def test_full_ladder_report_still_attributes(waf_server):
    """The single-rung wording must not leak into an ordinary ladder run."""
    findings = " ".join(build_findings(_report(waf_server, [0, 1, 2], holds_at=2)))
    assert "Single-rung run" not in findings
    assert "first hold at" in findings


def test_single_level_mode_is_serialized(waf_server):
    """A saved profile has to carry the mode, or reloading silently changes it."""
    data = _config(waf_server, single_level_mode=True, single_level=4).to_dict()
    assert data["single_level_mode"] is True
    assert data["single_level"] == 4
    assert data["visitor_count"] == SINGLE_LEVEL_VISITORS


def test_single_level_text_report_names_the_mode(waf_server):
    text = render_text(_report(waf_server, [0], single_level_mode=True, single_level=0))
    assert "SINGLE RUNG" in text
    assert "EVASION LADDER" not in text


def test_single_level_html_report_names_the_rung_it_ran(waf_server):
    """
    The summary row must show the rung that ran, not "none held".

    A rung that got through has no holding rung, so reusing that field would
    print "none held" under a "Rung tested" heading and hide the only result the
    run produced.
    """
    allowed = render_html(_report(waf_server, [0], single_level_mode=True, single_level=0))
    assert "<dt>Outcome</dt><dd>allowed</dd>" in allowed
    assert "none held" not in allowed

    stopped = render_html(
        _report(waf_server, [0], single_level_mode=True, single_level=0, holds_at=0)
    )
    assert "<dt>Outcome</dt><dd>stopped</dd>" in stopped


# --------------------------------------------------------------------------
# Honesty about the rungs whose named signal cannot be exercised
# --------------------------------------------------------------------------


def test_persistent_rung_says_the_profile_was_not_exercised(waf_server):
    """L6 is named for a durable profile the reused-browser design cannot give it."""
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[6], visitor_count=1),
        on_progress=events.append,
    )
    asyncio.run(runner.run())
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("durable profile" in n.get("message", "") for n in notices), notices


# --------------------------------------------------------------------------
# Realistic human traffic: the fixes that make a run look like visitors
#
# These assert the properties the audit claims, at the level where they are
# decided. Most run without a browser (CI's pythonlib tier never fetches one), so
# they assert on the plan, the assembled options and the request the runner
# builds -- the parts that silently regress.
# --------------------------------------------------------------------------


def test_dwell_is_split_across_the_visit_and_sums_to_the_plan():
    """
    The dwell must be spent, and spent across the session.

    The original bug was that `plan.dwell_s` was drawn and then never used, so a
    six-page visit that claimed a minute of attention finished in a few hundred
    milliseconds. The split has to sum to the draw or the visit is not the length
    the plan says it is.
    """
    from camoufox.audit.journey import JourneyConfig, plan_visit

    rng = random.Random(11)
    plans = [plan_visit(JourneyConfig(), rng, behavior=True) for _ in range(30)]
    multi = [p for p in plans if p.page_count > 1]
    assert multi, "expected some multi-page visits"
    for plan in multi:
        assert len(plan.page_dwell_s) == plan.page_count
        assert abs(sum(plan.page_dwell_s) - plan.dwell_s) < 1e-6
        # Not an even split: equal reading time per page is its own tell.
        assert len(set(round(d, 4) for d in plan.page_dwell_s)) > 1


def test_non_behavioral_rungs_plan_no_dwell():
    """A rung below behavior must not claim reading time it does not spend."""
    from camoufox.audit.journey import JourneyConfig, plan_visit

    plan = plan_visit(JourneyConfig(), random.Random(5), behavior=False)
    assert plan.dwell_s == 0.0
    assert plan.page_dwell_s == [0.0]


def test_the_dwell_budget_clips_the_tail_without_flattening_short_visits(waf_server):
    """
    A 900s outlier becomes a bounded visit; a 20s visit is spent in full.

    The budget exists because the log-normal draw has a long tail: spending it
    whole would hold a concurrency slot for minutes. Clipping the *total* while
    keeping short visits intact is what preserves the shape of real attention.
    """
    from camoufox.audit.journey import JourneyConfig, plan_visit

    config = _config(waf_server, levels=[5], visitor_count=1)
    runner = AuditRunner(config)
    journey = config.journey
    assert journey.dwell_budget_s > 0

    long_plan = plan_visit(
        JourneyConfig(dwell_median_s=600.0), random.Random(2), behavior=True
    )
    spent_long = sum(
        runner._page_dwell(long_plan, i) for i in range(long_plan.page_count)
    )
    assert spent_long <= journey.dwell_budget_s + 1e-6
    assert spent_long > 0

    short_plan = plan_visit(
        JourneyConfig(dwell_median_s=6.0, dwell_min_s=1.0, dwell_max_s=8.0),
        random.Random(2),
        behavior=True,
    )
    spent_short = sum(
        runner._page_dwell(short_plan, i) for i in range(short_plan.page_count)
    )
    assert abs(spent_short - short_plan.dwell_s) < 1e-6


def test_referer_is_sent_on_the_first_navigation_not_context_wide():
    """
    The arrival Referer must reach the navigation, and only the navigation.

    Two bugs in one: the referer was never sent at all in a browser rung (the
    code path was a bare `pass`), and the obvious fix -- putting it in the
    context's extra headers -- would stamp it on every CSS and image request,
    which is a synthetic tell rather than a human signal.

    The stamping now lives in the scope guard (one route has to do both jobs), so
    the check follows it there: the guard's stamp callback must key off
    `is_navigation_request`, and the context-wide headers must stay referer-free.
    """
    import inspect

    from camoufox.audit import runner as runner_module

    source = inspect.getsource(runner_module.AuditRunner._install_scope_guard)
    assert "is_navigation_request" in source, (
        "the arrival-header stamp must be limited to navigations"
    )
    assert "referer" in source.lower()

    # And the context-wide headers must not carry a referer.
    assert "referer" not in {h.lower() for h in level_by_id(5).context_headers}


def test_the_uncontrollable_header_set_is_the_measured_one():
    """
    This set is a measurement, so a change to it is a change to a claim.

    Each member was asked for through `route.continue_(headers=...)` on a real
    navigation and arrived unchanged; each excluded name arrived changed. Widening
    the set would silently excuse a rung from a control it does have; narrowing it
    would demand a control the engine will not give. Both are wrong in ways that
    only show up as an unattributable verdict, so the membership is pinned here.
    """
    from camoufox.audit.evasion import UNCONTROLLABLE_HEADERS

    assert UNCONTROLLABLE_HEADERS == frozenset(
        {
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "upgrade-insecure-requests",
            "accept-encoding",
            "connection",
            "host",
            "referer",
        }
    )
    # These four *are* settable, and must stay out of the set so a rung that pins
    # a wrong one is judged by its coherence rather than excused as impossible.
    for settable in ("user-agent", "accept", "accept-language", "cache-control"):
        assert settable not in UNCONTROLLABLE_HEADERS


def test_no_rung_declares_a_header_the_client_cannot_change():
    """
    A header Firefox generates itself is not a control, it is a no-op.

    Measured against the wire, Firefox emits Sec-Fetch-Dest/Mode/Site/User and
    Upgrade-Insecure-Requests itself and will not let them be overridden or
    removed -- neither a route that deletes them nor
    `dom.security.secFetch.enabled=false` changes the bytes. A rung that declares
    one therefore changes nothing while its `adds` claim reads as though it did,
    which is exactly the unattributable-verdict failure the ladder exists to
    prevent. This is the check that would have caught it.
    """
    from camoufox.audit.evasion import UNCONTROLLABLE_HEADERS

    for level in EVASION_LEVELS:
        bogus = sorted(
            name for name in level.headers if name.lower() in UNCONTROLLABLE_HEADERS
        )
        assert not bogus, f"{level.name} declares uncontrollable header(s) {bogus}"


def test_the_ladder_reports_no_problems():
    """The ladder's own consistency check must pass on the shipped rungs."""
    assert ladder_problems() == []


def test_a_rung_never_stamps_its_headers_on_every_request():
    """
    A navigation header on a subresource is a synthetic tell.

    `Accept: text/html` on a stylesheet is something no browser produces. The rung
    headers are applied to the arrival navigation and nowhere else, so the
    context-wide set is empty -- and any future rung that reintroduces a
    context-wide header has to fail this first.
    """
    for level in EVASION_LEVELS:
        assert level.context_headers == {}, f"{level.name} sets context-wide headers"
        # The header set is preserved, just scoped to the arrival navigation.
        assert set(level.navigation_headers) == set(level.headers)


def test_the_arrival_route_does_not_outlive_the_first_navigation():
    """
    The header stamp must apply to the arrival and nothing after it.

    The Referer is set for the arrival and then left alone: a browser derives the
    referer of every later navigation from the page it is leaving. A route that
    kept replacing the header set wholesale turned a natural link-follow into a
    bare request -- measured on the wire, every in-site hop arrived with
    `Referer: none`, which is a stronger bot signal than the one the route was
    installed to avoid.

    The old design un-routed itself; the new one keeps one context-wide route and
    makes the stamp single-shot instead, because un-routing it would take the
    scope gate down with it. The invariant is the same either way: the stamping
    callback fires once.
    """
    source = (Path(__file__).resolve().parents[1] / "camoufox/audit/runner.py").read_text()
    guard = source[source.index("class _ScopeGuard") : source.index("def _normalize_scope_host")]
    assert "if not self._stamped and self._stamp is not None:" in guard, (
        "the stamp latch is never consulted; the stamp would fire on every navigation"
    )
    # The latch must be *set*, not only read, or every navigation is stamped.
    assert "self._stamped = True" in guard, (
        "the arrival-header stamp is checked but never latched"
    )
    # The stamp lives in the one context-wide route; installing a separate page
    # route for it would take precedence and disable the scope guard underneath.
    install = source[source.index("async def _install_scope_guard") : source.index("async def _drive_journey")]
    assert "context.route" in install, "the guard is not installed on the context"
    assert "page.route" not in install, (
        "a page-level route takes precedence over the context guard and disables it"
    )


def test_the_hops_a_journey_makes_are_clicks_not_typed_urls():
    """
    A reader follows links; they do not retype the address bar mid-session.

    Driving every hop with `goto` makes each navigation a typed-URL navigation --
    a different and rarer behavior, and one that arrives with no Referer. The
    journey clicks the anchor instead, falling back to `goto` only when the link
    is not clickable, so the visit is not lost.
    """
    source = (Path(__file__).resolve().parents[1] / "camoufox/audit/runner.py").read_text()
    assert "async def _follow_link" in source
    drive = source[source.index("async def _drive_journey") :]
    assert "_follow_link" in drive, "the journey never follows a link by clicking"
    # The fallback must still exist, or an unclickable link loses the hop.
    assert "page.goto(" in drive, "no fallback navigation when a link cannot be clicked"


def test_a_visit_touches_the_page_without_touching_a_control():
    """
    A visit that only scrolls still has a pointer.

    A page whose sole pointer activity is a wheel is a page no mouse ever visited.
    The journey emits one pointer move per page (`glance`) so pointer entropy is
    non-zero even when the visit never reaches a form field.
    """
    from camoufox.audit.behavior import Cursor

    assert hasattr(Cursor, "glance")
    source = (Path(__file__).resolve().parents[1] / "camoufox/audit/runner.py").read_text()
    drive = source[source.index("async def _drive_journey") :]
    assert "glance" in drive, "a visit with no form field never moves the pointer"


def test_interaction_is_bounded_by_a_budget_not_by_the_whole_dwell():
    """
    A long visit is reading time, not a long burst of synthetic activity.

    Interaction is capped by `interaction_budget_s` so that a 45s dwell is not 45s
    of scrolling -- a rate no human produces and a trivially separable one. The
    budget is passed down as a monotonic deadline so both scrolling and typing
    stop at it.
    """
    from camoufox.audit.config import JourneyConfig

    budget = JourneyConfig().interaction_budget_s
    assert 0 < budget <= 20, f"interaction budget {budget}s is not a plausible cap"

    source = (Path(__file__).resolve().parents[1] / "camoufox/audit/runner.py").read_text()
    drive = source[source.index("async def _drive_journey") :]
    assert "deadline=stage_deadline" in drive, "the scroll stage ignores the budget"
    assert "_maybe_type(page, cursor, result, stage_deadline)" in drive, (
        "the typing stage ignores the budget"
    )


def test_no_rung_pins_an_accept_belonging_to_a_different_engine():
    """
    The rung must not send Chromium's Accept from a Firefox UA.

    Camoufox is a Firefox engine and sends a Firefox UA. Chromium's Accept is
    `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,
    image/apng,*/*;q=0.8`; Firefox's is the same but ends
    `...,*/*;q=0.8` with no per-format image list. Pinning Chromium's value on
    this engine manufactures exactly the cross-engine inconsistency the audit
    claims to detect -- an Accept that belongs to a browser the UA denies being.
    `Cache-Control: max-age=0` is Chromium's reload header and Firefox sends
    none, so it is disallowed for the same reason.
    """
    for level in EVASION_LEVELS:
        accept = level.headers.get("Accept", "")
        assert "image/avif" not in accept and "image/webp" not in accept, (
            f"{level.name} pins a Chromium Accept on a Firefox engine"
        )
        assert "cache-control" not in {k.lower() for k in level.headers}, (
            f"{level.name} pins Chromium's reload header on a Firefox engine"
        )


def test_no_rung_hardcodes_accept_language_against_the_spoofed_locale():
    """
    The rung must not pin a language the fingerprint may contradict.

    Camoufox derives Accept-Language from the spoofed locale
    (`locale:all` -> `intl.accept_languages`), so a rung that hardcodes `en-US`
    produces `navigator.language = de-DE` alongside `Accept-Language: en-US` on
    any non-en-US fingerprint -- a one-line inconsistency, and one the audit was
    manufacturing rather than measuring.
    """
    for level in EVASION_LEVELS:
        for name, value in level.headers.items():
            if name.lower() == "accept-language":
                raise AssertionError(
                    f"{level.name} pins Accept-Language={value!r}; let the engine "
                    f"derive it from the spoofed locale"
                )


def test_diurnal_curve_is_aligned_to_the_local_start_hour():
    """
    A run started in the afternoon must be busy in the afternoon.

    With `start_hour` left at 0.0 the curve was anchored to midnight regardless of
    the clock, so a 14:00 start peaked at 24:00 and idled at 10:00 -- the daily
    pattern inverted, which is a specific wrong signature rather than merely a
    missing one.
    """
    from datetime import datetime, timedelta, timezone

    from camoufox.audit.schedule import ScheduleConfig, build_schedule

    tz = timezone(timedelta(hours=6))
    start = datetime(2026, 6, 1, 14, 0, tzinfo=tz)
    schedule = build_schedule(
        ScheduleConfig(
            visitor_count=3000,
            duration_hours=24.0,
            pattern=ArrivalPattern.HUMAN_DIURNAL,
            start_at=start,
        ),
        rng=random.Random(2),
    )
    buckets = [0] * 24
    for arrival in schedule.arrivals:
        buckets[arrival.at.hour % 24] += 1

    # 14:00 is inside the busy plateau; 04:00 is the trough.
    busy = buckets[14] + buckets[15] + buckets[16]
    quiet = buckets[3] + buckets[4] + buckets[5]
    assert busy > quiet, f"afternoon should be busier than the small hours: {buckets}"


def test_an_explicit_start_hour_still_wins():
    """Deriving the hour must not remove the ability to pin one."""
    from camoufox.audit.schedule import ScheduleConfig

    assert ScheduleConfig(start_hour=9.0).resolved_start_hour() == 9.0


def test_each_rung_gets_its_own_schedule_window(waf_server, monkeypatch):
    """
    Rungs must not share arrival times, and must not fire as a burst.

    Reusing one schedule across the ladder had two effects. The rungs run in
    sequence, so from the second rung on the shared window was already in the past
    and every visitor fired at once -- the opposite of a spread-out arrival
    pattern. And the timestamps themselves were shared, so a log correlating by
    time would see a python-urllib client and a masked browser on the same pages in
    the same seconds: the ladder's own signature.
    """
    seen = []

    async def capture(self, level, schedule):
        seen.append((level.id, [a.offset_s for a in schedule.arrivals]))
        return LevelResult(level=level)

    monkeypatch.setattr(AuditRunner, "_run_level", capture)
    asyncio.run(
        AuditRunner(_config(waf_server, levels=[0, 1, 2], visitor_count=5)).run()
    )
    assert [level_id for level_id, _ in seen] == [0, 1, 2]
    offsets = [tuple(o) for _, o in seen]
    assert len(set(offsets)) == len(offsets), (
        "two rungs share an identical arrival pattern; the schedules were reused"
    )


def test_browser_reuse_is_the_default_and_launches_once_per_rung(waf_server, monkeypatch):
    """
    One browser per rung, not one per visit.

    The module claimed reuse while `_run_browser_visit` launched a browser per
    visit, so 100 visitors meant 100 Firefox processes -- the dominant cost of a
    run, and a resource shape a human population does not produce.
    """
    assert AuditConfig(target_url=waf_server).reuse_browser is True

    launches = []

    class FakeManager:
        def __init__(self, **kwargs):
            launches.append(kwargs)

        async def __aenter__(self):
            return object()

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(
        "camoufox.async_api.AsyncCamoufox", lambda **kwargs: FakeManager(**kwargs)
    )

    async def fake_visit(self, browser, level, plan, url, index, proxy_session):
        return VisitResult(
            visitor_index=index,
            level_id=level.id,
            started_at=0.0,
            verdict=Verdict.ALLOWED,
        )

    monkeypatch.setattr(AuditRunner, "_visit_browser", fake_visit)
    report = asyncio.run(
        AuditRunner(_config(waf_server, levels=[2], visitor_count=4)).run()
    )
    assert len(launches) == 1, f"expected one launch for the rung, got {len(launches)}"
    assert report.levels[0].completed == 4


def test_per_visit_launch_is_still_available_and_announced(waf_server, monkeypatch):
    """Turning reuse off must work, and must say what it costs."""
    launches = []

    class FakeManager:
        def __init__(self, **kwargs):
            launches.append(kwargs)

        async def __aenter__(self):
            return object()

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(
        "camoufox.async_api.AsyncCamoufox", lambda **kwargs: FakeManager(**kwargs)
    )

    async def fake_visit(self, browser, level, plan, url, index, proxy_session):
        return VisitResult(
            visitor_index=index,
            level_id=level.id,
            started_at=0.0,
            verdict=Verdict.ALLOWED,
        )

    monkeypatch.setattr(AuditRunner, "_visit_browser", fake_visit)
    events = []
    asyncio.run(
        AuditRunner(
            _config(waf_server, levels=[2], visitor_count=3, reuse_browser=False),
            on_progress=events.append,
        ).run()
    )
    assert len(launches) == 3, "per-visit mode must launch per visit"
    notices = [e.get("message", "") for e in events if e.get("event") == "notice"]
    assert any("reuse_browser is off" in n for n in notices), notices


# --------------------------------------------------------------------------
# Human interaction primitives
# --------------------------------------------------------------------------


def test_cursor_path_is_not_a_straight_line():
    """A straight interpolation is the most obvious trajectory tell."""
    from camoufox.audit.behavior import BehaviorModel, cursor_path

    model = BehaviorModel()
    paths = [
        cursor_path((0.0, 0.0), (600.0, 400.0), random.Random(seed), model)
        for seed in range(20)
    ]
    assert any(len(p) > 2 for p in paths), "some moves must have intermediate legs"
    # A leg off the straight line proves the scatter is applied.
    off_line = False
    for path in paths:
        for x, y in path[:-1]:
            if abs(y - x * (400.0 / 600.0)) > 0.5:
                off_line = True
    assert off_line, "no path deviated from the straight line"


def test_cursor_path_is_reproducible_from_a_seed():
    from camoufox.audit.behavior import BehaviorModel, cursor_path

    model = BehaviorModel()
    first = cursor_path((0.0, 0.0), (300.0, 200.0), random.Random(4), model)
    second = cursor_path((0.0, 0.0), (300.0, 200.0), random.Random(4), model)
    assert first == second


def test_wheel_deltas_decay_instead_of_repeating():
    """
    A momentum burst, not N identical deltas.

    Constant deltas per event are a synthetic-device signature, and they carry no
    velocity information at all.
    """
    from camoufox.audit.behavior import BehaviorModel, wheel_profile

    deltas = wheel_profile(6, random.Random(3), BehaviorModel())
    assert len(deltas) == 6
    assert len(set(round(d, 4) for d in deltas)) > 1, "deltas look constant"
    assert deltas[0] > deltas[-1], "the burst should decay"


def test_keystroke_delays_are_right_skewed_and_pause_at_boundaries():
    """
    Uniform inter-key delay is a keystroke-dynamics give-away.

    Real cadence has a mode, a tail, and a longer pause at every word boundary.
    """
    from camoufox.audit.behavior import BehaviorModel, keystroke_delays

    model = BehaviorModel()
    text = "hello world again"
    delays = keystroke_delays(text, random.Random(6), model)
    assert len(delays) == len(text)
    assert len(set(round(d, 4) for d in delays)) > 5, "delays look quantised"

    at_spaces = [d for c, d in zip(text, delays) if c == " "]
    others = [d for c, d in zip(text, delays) if c != " "]
    assert min(at_spaces) > min(others), "a word boundary should cost extra time"


def test_click_has_a_real_hold_duration():
    """
    A zero-length press is a machine tell, and click forensics measure it.

    `page.click()` issues down and up with no gap; the cursor primitive must
    separate them by a drawn duration.
    """
    import math

    from camoufox.audit.behavior import BehaviorModel, Cursor

    model = BehaviorModel()
    holds = []
    for seed in range(25):
        rng = random.Random(seed)
        value = rng.lognormvariate(math.log(model.hold_median_s), model.hold_sigma)
        holds.append(min(max(value, model.hold_min_s), model.hold_max_s))
    assert min(holds) > 0.0
    assert max(holds) <= model.hold_max_s
    assert model.hold_min_s >= 0.02, "a press shorter than ~20ms is not a human click"
    assert hasattr(Cursor, "click")


def test_cursor_move_tracks_its_position_and_clicks_with_down_up():
    """The pointer must have a history, and a click must be a held press."""
    from camoufox.audit.behavior import BehaviorModel, Cursor

    calls = []

    class FakeMouse:
        async def move(self, x, y):
            calls.append(("move", x, y))

        async def down(self):
            calls.append(("down",))

        async def up(self):
            calls.append(("up",))

        async def wheel(self, dx, dy):
            calls.append(("wheel", dx, dy))

    class FakePage:
        mouse = FakeMouse()

        async def evaluate(self, _script):
            return {"w": 1280, "h": 720}

    async def exercise():
        cursor = Cursor(FakePage(), random.Random(1), BehaviorModel())
        await cursor.move_to(500.0, 300.0)
        assert cursor.x == 500.0 and cursor.y == 300.0
        assert sum(1 for c in calls if c[0] == "move") > 1, "a move must emit a trajectory"

        calls.clear()
        assert await cursor.click() is True
        kinds = [c[0] for c in calls]
        assert "down" in kinds and "up" in kinds
        assert kinds.index("down") < kinds.index("up"), "down must precede up"

    asyncio.run(exercise())


def test_a_rung_below_behavior_still_gets_no_interaction():
    """
    The gate must hold: only L5+ may move a pointer, scroll or type.

    A lower rung that behaved like a human would credit behavior for a verdict
    that is about static signals.
    """
    behavioral = [level.id for level in EVASION_LEVELS if level.is_behavioral]
    assert behavioral == [5, 6]
    for level in EVASION_LEVELS:
        if not level.is_behavioral:
            assert not (level.camoufox_options or {}).get("humanize")
# --------------------------------------------------------------------------
# Outbound funnel: promotional-banner discovery, CTR simulation and telemetry.
#
# The spec item asked for dynamic scope management driven by DOM-extracted URLs.
# The engine reconciles that with its core invariant -- out-of-scope hosts are
# refused unless the operator declared them -- so discovery is dynamic but
# authorization stays operator-declared. These tests pin both halves.
# --------------------------------------------------------------------------

from urllib.parse import urlparse  # noqa: E402

from camoufox.audit import (  # noqa: E402
    BannerCandidate,
    CampaignEvent,
    discover_banner_candidates,
    is_ad_syndication_url,
    parse_rate_pct,
    plan_outbound_visit,
)
from camoufox.audit.behavior import BehaviorModel as _BM, campaign_dwell  # noqa: E402
from camoufox.audit.report import write_csv  # noqa: E402


def test_parse_rate_pct_accepts_the_shapes_an_operator_writes():
    assert parse_rate_pct("2.5") == pytest.approx(2.5)
    assert parse_rate_pct("2.5%") == pytest.approx(2.5)
    assert parse_rate_pct("0.05") == pytest.approx(0.05)
    assert parse_rate_pct(3) == pytest.approx(3.0)


@pytest.mark.parametrize("bad", ["", "   ", "two percent", "abc%", None, "1,5"])
def test_parse_rate_pct_rejects_junk(bad):
    with pytest.raises(ValueError):
        parse_rate_pct(bad)


def test_discovery_follows_a_third_party_banner_by_default():
    """
    The funnel is deny-by-exception: a discovered host is followable unless excluded.

    This is the deliberate policy change from the allowlist design. A page's real
    ad traffic is the thing being measured, so skipping it by default would report
    "no banner" on a page that was showing one. The escape hatch is the exclusion
    list, exercised in the next test.
    """
    scope = TargetScope.from_urls(["https://shop.example.com/"], acknowledged=True)
    candidates = discover_banner_candidates(
        [
            {"href": "https://shop.example.com/spring-sale", "selector": "a.promo-banner"},
            {"href": "https://untrusted.example.net/offer", "selector": "a[data-campaign]"},
        ],
        page_url="https://shop.example.com/",
        scope=scope,
    )
    by_host = {urlparse(c.url).hostname: c for c in candidates}
    first_party = by_host["shop.example.com"]
    third_party = by_host["untrusted.example.net"]

    assert first_party.first_party is True
    assert first_party.authorized is True
    assert third_party.first_party is False
    assert third_party.authorized is True
    assert not third_party.refusal


def test_an_excluded_third_party_banner_is_seen_reported_and_not_followed():
    """
    The exclusion is the one thing that keeps a banner from being followed.

    A refused banner is still discovered and retains a reason, so the report can
    say which destination was skipped and why rather than silently dropping it.
    """
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=["https://untrusted.example.net/"],
    )
    candidates = discover_banner_candidates(
        [
            {"href": "https://shop.example.com/spring-sale", "selector": "a.promo-banner"},
            {"href": "https://untrusted.example.net/offer", "selector": "a[data-campaign]"},
        ],
        page_url="https://shop.example.com/",
        scope=scope,
    )
    by_host = {urlparse(c.url).hostname: c for c in candidates}
    third_party = by_host["untrusted.example.net"]

    assert third_party.authorized is False
    assert third_party.refusal, "a refusal must carry a reason to report"

    # The selection step only ever considers authorized candidates, so with the
    # third-party banner excluded the first-party one is what gets picked.
    picked = plan_outbound_visit("100", candidates, random.Random(0))
    assert picked.campaign_url is not None
    assert urlparse(picked.campaign_url).hostname == "shop.example.com"


def test_a_partner_banner_is_followable_without_widening_the_scope():
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
    )
    candidates = discover_banner_candidates(
        [{"href": "https://partner.example.net/landing"}],
        page_url="https://shop.example.com/",
        scope=scope,
    )
    assert len(candidates) == 1
    assert candidates[0].authorized is True
    assert candidates[0].first_party is False
    # Following a partner must not make the *target* scope broader: the banner
    # was admitted for this funnel hop, not added to the authorized hosts.
    assert scope.permits_url("https://partner.example.net/landing") is False
    assert scope.permits_url("https://shop.example.com/") is True


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://shop.example.com/offer", False),
        ("https://criteo.com/click?x=1", True),
        ("https://criteo.net/x", True),
        ("https://adservice.google.com/pagead/aclk", True),
        ("https://partner.example.net/landing", False),
        ("https://notcriteo.example.com/x", False),
        ("https://mycriteo.com.example.net/x", False),
    ],
)
def test_ad_syndication_wrappers_are_filtered_and_lookalikes_are_not(url, expected):
    assert is_ad_syndication_url(url) is expected


def test_outbound_scope_round_trips_and_remembers_what_was_reached():
    original = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=["https://blocked.example.net/"],
    )
    assert original.check_unattended("https://partner.example.net/landing") is True

    restored = TargetScope.from_dict(original.to_dict())
    assert restored.excluded_outbound_hosts == original.excluded_outbound_hosts
    assert restored.session_outbound == original.session_outbound
    assert restored.check_unattended("https://partner.example.net/x") is True
    # The exclusion survives the round trip, so the blocked host stays blocked.
    assert restored.check_unattended("https://blocked.example.net/x") is False


def test_outbound_gate_refuses_ip_literals_and_excluded_hosts():
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=["https://partner.example.net/"],
    )
    # The metadata endpoint is a literal and is never followed.
    assert scope.check_unattended("http://169.254.169.254/latest/meta-data") is False
    # The named host is excluded, and so are its subdomains.
    assert scope.check_unattended("https://partner.example.net/x") is False
    assert scope.check_unattended("https://track.partner.example.net/x") is False
    # A lookalike must not be caught by the exclusion.
    assert scope.check_unattended("https://evil-partner.example.net/x") is True
    assert scope.check_unattended("javascript:alert(1)") is False


def test_an_unacknowledged_scope_permits_no_outbound_destination():
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=False,
    )
    assert scope.check_unattended("https://partner.example.net/x") is False


def test_discovery_drops_non_http_and_same_document_fragments():
    candidates = discover_banner_candidates(
        [
            {"href": "javascript:alert(1)"},
            {"href": "mailto:hi@example.com"},
            {"href": "https://shop.example.com/#section"},
            {"href": "https://shop.example.com/real"},
        ],
        page_url="https://shop.example.com/",
    )
    assert [c.url for c in candidates] == ["https://shop.example.com/real"]


def test_discovery_deduplicates_by_url():
    candidates = discover_banner_candidates(
        [
            {"href": "https://shop.example.com/offer"},
            {"href": "https://shop.example.com/offer"},
            {"href": "https://shop.example.com/offer#a"},
        ],
        page_url="https://shop.example.com/",
    )
    assert len(candidates) == 1


# --------------------------------------------------------------------------
# Iframe banner discovery
# --------------------------------------------------------------------------


def test_include_iframes_discovers_banners_inside_a_child_frame():
    """
    An ad iframe's banner is a candidate when frames are inspected.

    A campaign served from an iframe is the common case, so a main-frame-only
    scan reports "no banner" on a page that is visibly showing one. The frame
    ordinal is carried on the candidate so the click can be aimed back at it.
    """
    anchors = [
        {"href": "https://shop.example.com/main-offer", "frame_index": 0},
        {"href": "https://partner.example.net/framed", "frame_index": 1},
    ]
    candidates = discover_banner_candidates(
        anchors, page_url="https://shop.example.com/", include_iframes=True
    )
    urls = {c.url for c in candidates}
    assert "https://shop.example.com/main-offer" in urls
    assert "https://partner.example.net/framed" in urls

    framed = next(c for c in candidates if c.url.endswith("/framed"))
    assert framed.frame_index == 1
    assert framed.from_iframe is True
    main = next(c for c in candidates if c.url.endswith("/main-offer"))
    assert main.frame_index == 0
    assert main.from_iframe is False


def test_include_iframes_false_excludes_child_frame_banners():
    """
    Turning the option off restricts discovery to the main document.

    The framed anchor must vanish entirely -- not merely be refused -- so that
    excluding frames cannot leave the frame's destination counted anywhere in the
    report.
    """
    anchors = [
        {"href": "https://shop.example.com/main-offer", "frame_index": 0},
        {"href": "https://partner.example.net/framed", "frame_index": 1},
    ]
    candidates = discover_banner_candidates(
        anchors, page_url="https://shop.example.com/", include_iframes=False
    )
    assert [c.url for c in candidates] == ["https://shop.example.com/main-offer"]


def test_iframe_banners_pass_the_gate_unless_their_host_is_excluded():
    """
    A frame-derived destination is treated exactly like a main-document one.

    A frame is untrusted content, so coming out of an iframe must not elevate a
    destination -- but it must not lower it either. An iframe banner is followable
    by default, and is left unauthorized only when its host is excluded.
    """
    scope = TargetScope.from_urls(["https://shop.example.com/"], acknowledged=True)
    candidates = discover_banner_candidates(
        [{"href": "https://partner.example.net/framed", "frame_index": 1}],
        page_url="https://shop.example.com/",
        scope=scope,
        include_iframes=True,
    )
    assert len(candidates) == 1
    assert candidates[0].from_iframe is True
    assert candidates[0].authorized is True
    assert not candidates[0].refusal

    # And the roll can produce a destination from the iframe banner.
    assert plan_outbound_visit("100", candidates, random.Random(0)).triggered is True


def test_an_excluded_partner_inside_a_frame_is_refused():
    """The exclusion, not the frame, is what refuses an iframe destination."""
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=["https://partner.example.net/"],
    )
    candidates = discover_banner_candidates(
        [{"href": "https://partner.example.net/framed", "frame_index": 2}],
        page_url="https://shop.example.com/",
        scope=scope,
        include_iframes=True,
    )
    assert candidates[0].authorized is False
    assert candidates[0].refusal
    # The frame ordinal is still carried, so a refusal can be reported with the
    # frame it came from.
    assert candidates[0].frame_index == 2


def test_the_selected_plan_carries_the_frame_of_the_chosen_banner():
    """
    The frame ordinal survives selection.

    The click resolves the frame from the plan, so if selection dropped the
    ordinal an iframe banner would be pressed in the main document -- or not at
    all. Pinned here because the loss would be silent.
    """
    candidates = [
        BannerCandidate(url="https://shop.example.com/a", authorized=True, frame_index=0),
        BannerCandidate(url="https://shop.example.com/b", authorized=True, frame_index=3),
    ]
    plans = [plan_outbound_visit("100", candidates, random.Random(s)) for s in range(40)]
    assert all(p.triggered for p in plans)
    for plan in plans:
        chosen = next(c for c in candidates if c.url == plan.campaign_url)
        assert plan.frame_index == chosen.frame_index


def test_resolving_a_frame_ordinal_maps_to_the_right_child_frame():
    """
    Ordinal 0 is the page; ordinal N is the Nth child frame.

    `page.frames` holds the main frame first, so a naive enumerate-from-zero would
    make child frame 1 alias the main document and mis-aim the cursor. The
    ordinals are asserted against a stand-in page here rather than trusted.
    """
    url = "http://127.0.0.1:1/"
    runner = AuditRunner(_config(url))

    class _StubFrame:
        def __init__(self, name):
            self.name = name

    main = _StubFrame("main")
    child_a = _StubFrame("a")
    child_b = _StubFrame("b")

    class _StubPage:
        frames = [main, child_a, child_b]
        main_frame = main

    page = _StubPage()
    assert runner._frame_for(page, 0) is page
    assert runner._frame_for(page, 1) is child_a
    assert runner._frame_for(page, 2) is child_b
    # An ordinal past the end must not silently fall back to the main document.
    assert runner._frame_for(page, 9) is None


def test_child_frames_follow_the_list_order_even_if_the_main_frame_is_not_first():
    """
    The main frame is excluded by identity, not by trusting position zero.

    `page.frames` ordering is an implementation contract, so the guard matters:
    if the main frame were ever listed later, counting from zero would have made
    child frame 1 alias the document and aimed the cursor at the wrong geometry.
    """
    url = "http://127.0.0.1:1/"
    runner = AuditRunner(_config(url))

    class _StubFrame:
        def __init__(self, name):
            self.name = name

    main = _StubFrame("main")
    child_a = _StubFrame("a")

    class _StubPage:
        frames = [child_a, main]
        main_frame = main

    assert runner._child_frames(_StubPage()) == [child_a]
    assert runner._frame_for(_StubPage(), 1) is child_a


def test_a_page_with_no_identifiable_main_frame_yields_no_child_frames():
    """
    Without a main_frame to exclude, no frame is numbered.

    The alternative -- numbering every listed frame -- could point ordinal 1 at
    the document itself and press the wrong element. Losing frames is recoverable
    and visible; mis-numbering them is neither.
    """
    url = "http://127.0.0.1:1/"
    runner = AuditRunner(_config(url))

    class _StubPage:
        frames = [object(), object()]
        main_frame = None

    assert runner._child_frames(_StubPage()) == []
    assert runner._frame_for(_StubPage(), 1) is None


def test_include_iframes_defaults_to_true():
    """Frames are inspected by default; the opt-out is explicit."""
    cfg = AuditConfig(target_url="https://shop.example.com/", scope=TargetScope.from_urls(
        ["https://shop.example.com/"], acknowledged=True
    ))
    assert cfg.include_iframes is True
    assert cfg.to_dict()["include_iframes"] is True


def test_the_runner_reads_child_frames_only_when_enabled():
    """
    The runner reads frames through their own `evaluate`, gated on the flag.

    `page.locator()` is `mainFrame().locator()` in Playwright, so a child frame's
    anchors are invisible to any main-frame query -- the runner has to ask each
    frame directly. The stand-in below records which frames were read, which is
    the behaviour the flag controls.
    """
    url = "http://127.0.0.1:1/"
    main_anchors = [{"href": "https://shop.example.com/main-offer"}]
    frame_anchors = [{"href": "https://shop.example.com/framed"}]

    class _StubFrame:
        def __init__(self, anchors, name):
            self._anchors = anchors
            self.name = name
            self.reads = 0

        async def evaluate(self, _script, *args):
            self.reads += 1
            return self._anchors

    child = _StubFrame(frame_anchors, "child")

    class _StubPage:
        def __init__(self):
            self.main_frame = _StubFrame(main_anchors, "main")
            self.frames = [self.main_frame, child]

        async def evaluate(self, _script, *args):
            return self.main_frame._anchors

    async def collect(include_iframes):
        runner = AuditRunner(_config(url, include_iframes=include_iframes))
        page = _StubPage()
        return await runner._collect_banner_anchors(page), page

    anchors_on, _ = asyncio.run(collect(True))
    urls = {a["href"] for a in anchors_on}
    assert urls == {"https://shop.example.com/main-offer", "https://shop.example.com/framed"}
    framed = next(a for a in anchors_on if a["href"].endswith("/framed"))
    assert framed["frame_index"] == 1, "a child frame is ordinal 1, never 0"
    main = next(a for a in anchors_on if a["href"].endswith("/main-offer"))
    assert main["frame_index"] == 0

    anchors_off, _ = asyncio.run(collect(False))
    assert {a["href"] for a in anchors_off} == {"https://shop.example.com/main-offer"}


def test_an_unreadable_frame_does_not_hide_the_others():
    """
    One frame that throws must not fail the whole scan.

    Frames detach, navigate mid-read, and tear down at cross-origin boundaries.
    Losing a readable frame's banners because a sibling raised would turn a
    routine race into a false "no banner found".
    """
    url = "http://127.0.0.1:1/"

    class _BadFrame:
        name = "bad"

        async def evaluate(self, _script, *args):
            raise RuntimeError("frame detached")

    class _GoodFrame:
        name = "good"

        async def evaluate(self, _script, *args):
            return [{"href": "https://shop.example.com/good"}]

    class _StubPage:
        def __init__(self):
            self.main_frame = _BadFrame()
            self.frames = [self.main_frame, _BadFrame(), _GoodFrame()]

        async def evaluate(self, _script, *args):
            return []

    runner = AuditRunner(_config(url))

    async def collect():
        return await runner._collect_banner_anchors(_StubPage())

    anchors = asyncio.run(collect())
    assert [a["href"] for a in anchors] == ["https://shop.example.com/good"]
    assert anchors[0]["frame_index"] == 2


def test_observed_ctr_tracks_the_configured_rate():
    """
    The simulated CTR must be a random draw at roughly the set rate, not a
    fixed count and not a per-visitor deterministic pattern.
    """
    candidates = [
        BannerCandidate(url="https://shop.example.com/offer", first_party=True, authorized=True)
    ]
    rate = 2.5
    n = 6000
    rng = random.Random(1234)
    clicks = sum(1 for _ in range(n) if plan_outbound_visit(rate, candidates, rng).triggered)
    observed = 100.0 * clicks / n
    assert 2.0 < observed < 3.0, f"observed {observed:.2f}% for a {rate}% rate"


def test_a_zero_rate_never_clicks():
    candidates = [BannerCandidate(url="https://x.example.com/o", authorized=True)]
    for rate in ("0", "0.0"):
        for seed in range(30):
            assert plan_outbound_visit(rate, candidates, random.Random(seed)).triggered is False


def test_no_candidates_never_clicks():
    plan = plan_outbound_visit("100", [], random.Random(0))
    assert plan.triggered is False


def test_campaign_dwell_is_right_skewed_within_bounds():
    model = _BM()
    rng = random.Random(7)
    draws = [campaign_dwell(rng, model) for _ in range(2000)]
    assert all(model.campaign_min_s <= d <= model.campaign_max_s for d in draws)
    assert min(draws) < model.campaign_median_s < max(draws)
    # Log-normal: the mean sits above the median.
    assert sum(draws) / len(draws) > model.campaign_median_s


def test_engaged_excludes_a_landing_that_refused_to_serve():
    blocked = CampaignEvent(
        campaign_url="https://partner.example.net/x",
        landed=True,
        landing_status=403,
        landing_verdict="blocked",
        skipped_reason="landing page was blocked",
    )
    served = CampaignEvent(
        campaign_url="https://shop.example.com/offer",
        landed=True,
        landing_status=200,
        landing_verdict="allowed",
        dwell_s=25.0,
    )
    assert blocked.engaged is False
    assert served.engaged is True


def test_campaign_event_round_trips_through_to_dict():
    event = CampaignEvent(
        campaign_url="https://shop.example.com/offer",
        first_party=True,
        selector_hint="a.promo-banner",
        landed=True,
        landing_status=200,
        landing_verdict="allowed",
        dwell_s=21.33333,
        glances=1,
        scroll_bursts=3,
    )
    payload = event.to_dict()
    assert payload["campaign_url"] == "https://shop.example.com/offer"
    assert payload["dwell_s"] == pytest.approx(21.333)
    assert payload["engaged"] is True
    assert payload["scroll_bursts"] == 3


def test_funnel_config_validates_a_bad_rate():
    scope = TargetScope.from_urls(["https://shop.example.com/"], acknowledged=True)

    # With the funnel on, a rate that cannot be read is refused at construction
    # rather than silently coerced -- an unreadable rate would decide real
    # traffic, so failing fast is the safe default.
    with pytest.raises(ValueError):
        AuditConfig(
            target_url="https://shop.example.com/",
            scope=scope,
            enable_outbound_funnel=True,
            outbound_campaign_rate_pct="lots",
        )

    # `validate` still catches a rate that was set after construction, with a
    # message an operator can act on.
    mutated = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        enable_outbound_funnel=True,
        outbound_campaign_rate_pct="2.5",
    )
    mutated.outbound_campaign_rate_pct = "lots"
    assert any("outbound_campaign_rate_pct" in p for p in mutated.validate())

    zero = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        enable_outbound_funnel=True,
        outbound_campaign_rate_pct="0",
    )
    assert any("no visitor will click" in p for p in zero.validate())

    # With the funnel off the rate decides no traffic, so an unreadable value is
    # tolerated and not reported -- the run is still well-defined.
    off = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        enable_outbound_funnel=False,
        outbound_campaign_rate_pct="lots",
    )
    assert off.validate() == []


def test_funnel_config_round_trips_through_to_dict():
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=["https://partner.example.net/"],
    )
    cfg = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        enable_outbound_funnel=True,
        outbound_campaign_rate_pct="4.5",
    )
    payload = cfg.to_dict()
    assert payload["enable_outbound_funnel"] is True
    # Normalized to a float by construction, so the serialized form is canonical.
    assert payload["outbound_campaign_rate_pct"] == pytest.approx(4.5)
    assert payload["scope"]["excluded_outbound_hosts"] == ["partner.example.net"]


def _funnel_report(events, *, exclude_hosts=()):
    """Assemble an AuditReport carrying the given campaign events."""
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=list(exclude_hosts),
    )
    cfg = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        enable_outbound_funnel=True,
        outbound_campaign_rate_pct="2.5",
        levels=[5],
        visitor_count=len(events),
    )
    report = AuditReport(config=cfg)
    lr = LevelResult(level=level_by_id(5))
    for index, event in enumerate(events):
        lr.visits.append(
            VisitResult(
                visitor_index=index,
                level_id=5,
                started_at=0.0,
                finished_at=1.0,
                verdict=Verdict.ALLOWED,
                campaign=event,
            )
        )
    lr.finished_at = 1.0
    report.levels.append(lr)
    report.finished_at = 1.0
    return report


def test_funnel_summary_counts_clicks_landings_and_engagement():
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/offer",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=30.0,
            ),
            CampaignEvent(
                campaign_url="https://partner.example.net/x",
                first_party=False,
                landed=True,
                landing_status=403,
                landing_verdict="blocked",
                skipped_reason="landing page was blocked",
            ),
            CampaignEvent(
                campaign_url="https://partner.example.net/y",
                first_party=False,
                skipped_reason="outbound destination was not authorized by scope",
                refused_by_scope=True,
            ),
        ],
        exclude_hosts=["partner.example.net"],
    )
    funnel = report.funnel_summary()
    assert funnel["clicks"] == 3
    assert funnel["landed"] == 2
    assert funnel["engaged"] == 1
    assert funnel["refused"] == 1
    assert funnel["skipped_by_scope"] == 1
    assert funnel["first_party_clicks"] == 1
    assert funnel["partner_clicks"] == 2
    # Dwell only reflects the destination that actually served the offer.
    assert funnel["dwell_p50_s"] == pytest.approx(30.0)
    assert funnel["dwell_min_s"] == pytest.approx(30.0)


def test_a_landing_reason_mentioning_scope_is_not_tallied_as_a_refusal():
    """
    The refusal category is a flag, not a substring of the reason text.

    `skipped_reason` is prose meant for an operator. Classifying by searching it
    for "scope" would mis-file an ordinary unreachable landing whose message
    happens to use the word -- the kind of bug that stays invisible until a
    wording change silently moves a number in the report.
    """
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://partner.example.net/x",
                first_party=False,
                skipped_reason="navigation failed: the landing was outside its scope",
            )
        ],
        exclude_hosts=["partner.example.net"],
    )
    funnel = report.funnel_summary()
    assert funnel["skipped_by_scope"] == 0
    assert funnel["unreachable"] == 1


def test_funnel_findings_name_the_rate_and_the_engagement():
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/offer",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=42.0,
            )
        ]
    )
    joined = "\n".join(build_findings(report))
    assert "2.5%" in joined
    assert "42" in joined


def test_funnel_findings_name_the_excluded_hosts():
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/offer",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=20.0,
            )
        ],
        exclude_hosts=["partner.example.net"],
    )
    joined = "\n".join(build_findings(report))
    assert "excluded" in joined.lower()
    assert "partner.example.net" in joined


def test_funnel_findings_say_so_when_nothing_clicked():
    # A visit that completed but produced no click-through: the funnel ran and
    # found nothing, which is a conclusion rather than an empty report.
    report = _funnel_report([None])
    joined = "\n".join(build_findings(report))
    assert "no visitor clicked a promotional banner" in joined


def test_report_renders_the_funnel_section_in_text_and_html():
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/offer",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=33.0,
                scroll_bursts=4,
            )
        ]
    )
    text = render_text(report)
    assert "OUTBOUND FUNNEL" in text
    assert "https://shop.example.com/offer" in text

    html = render_html(report)
    assert "Outbound funnel" in html
    assert "https://shop.example.com/offer" in html


def test_csv_exports_campaign_columns(tmp_path):
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/offer",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=19.5,
            )
        ]
    )
    out = tmp_path / "audit.csv"
    write_csv(report, str(out))
    body = out.read_text(encoding="utf-8")
    assert "campaign_url" in body.splitlines()[0]
    assert "campaign_dwell_s" in body.splitlines()[0]
    assert "https://shop.example.com/offer" in body


def test_the_report_marks_a_banner_that_was_served_from_an_iframe(tmp_path):
    """
    A frame-served campaign is visible in the aggregate and the CSV.

    "The offer was in an iframe" is a finding about how the site serves its
    campaign, and the explanation for a main-frame-only scan reporting no banner.
    It is carried through the funnel summary and the machine-readable export.
    """
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/framed",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=11.0,
                frame_index=2,
            )
        ]
    )
    funnel = report.funnel_summary()
    assert funnel["iframe_clicks"] == 1
    assert "from iframes" in render_text(report)

    out = tmp_path / "audit.csv"
    write_csv(report, str(out))
    body = out.read_text(encoding="utf-8")
    assert "campaign_frame_index" in body.splitlines()[0]


def test_a_main_document_click_is_not_counted_as_an_iframe_click():
    report = _funnel_report(
        [
            CampaignEvent(
                campaign_url="https://shop.example.com/offer",
                first_party=True,
                landed=True,
                landing_status=200,
                landing_verdict="allowed",
                dwell_s=10.0,
                frame_index=0,
            )
        ]
    )
    assert report.funnel_summary()["iframe_clicks"] == 0
    assert "from iframes" not in render_text(report)


def test_the_funnel_section_states_the_scan_scope():
    """
    The report says whether frames were inspected.

    "No promotional banner found" means something different when frames were
    skipped, and the operator should not have to remember a config flag to read
    the finding.
    """
    framed = _funnel_report([None])
    assert "main document + iframes" in render_text(framed)

    scope = TargetScope.from_urls(["https://shop.example.com/"], acknowledged=True)
    cfg = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        enable_outbound_funnel=True,
        include_iframes=False,
    )
    report = AuditReport(config=cfg)
    text = render_text(report)
    assert "main document only" in text
    assert "main document + iframes" not in text


def test_a_funnel_off_report_omits_the_section():
    scope = TargetScope.from_urls(["https://shop.example.com/"], acknowledged=True)
    cfg = AuditConfig(target_url="https://shop.example.com/", scope=scope)
    report = AuditReport(config=cfg)
    assert report.funnel_summary()["enabled"] is False
    assert "OUTBOUND FUNNEL" not in render_text(report)
    assert all("funnel" not in f.lower() for f in build_findings(report))


def test_the_funnel_gate_holds_on_non_behavioral_rungs():
    """
    Only a rung that claims behavior may click a banner.

    A click-through is an interaction. On a rung that does not claim behavior,
    emitting one would make that rung's verdict the product of an interaction it
    never claimed -- the unattributable-verdict failure the ladder is built to
    prevent.
    """
    url = "http://127.0.0.1:1/"
    config = _config(url, enable_outbound_funnel=True, levels=[0, 2])
    runner = AuditRunner(config)
    assert runner._funnel_applies(level_by_id(0)) is False
    assert runner._funnel_applies(level_by_id(2)) is False
    assert runner._funnel_applies(level_by_id(5)) is True


def test_the_funnel_is_off_by_default_so_no_rung_clicks():
    url = "http://127.0.0.1:1/"
    config = _config(url, levels=[5])
    runner = AuditRunner(config)
    assert config.enable_outbound_funnel is False
    assert runner._funnel_applies(level_by_id(5)) is False


def test_the_walk_reports_an_excluded_banner_and_never_selects_it():
    """
    The runner reports an excluded banner and never selects it.

    A stub page reports one followable first-party banner and one banner on an
    excluded campaign host, with the interaction rate pinned at 100% so the roll
    always fires. The walk is asserted to have chosen the first-party
    destination, and to have recorded the refused one -- and because the stub
    page cannot be clicked, the walk ends without a landing, which is the honest
    outcome rather than a claimed click-through.
    """
    scope = TargetScope.from_urls(
        ["https://shop.example.com/"],
        acknowledged=True,
        exclude_urls=["https://undeclared.example.net/"],
    )
    config = AuditConfig(
        target_url="https://shop.example.com/",
        scope=scope,
        levels=[5],
        visitor_count=1,
        enable_outbound_funnel=True,
        outbound_campaign_rate_pct="100",
        seed=1,
    )
    runner = AuditRunner(config)

    class StubPage:
        """A page that reports banners; it cannot be clicked or navigated."""

        async def evaluate(self, _script, *args):
            return [
                {"href": "https://shop.example.com/offer", "selector": "a.promo-banner"},
                {"href": "https://undeclared.example.net/x", "selector": "a[data-campaign]"},
            ]

    async def walk():
        result = VisitResult(visitor_index=0, level_id=5, started_at=0.0)
        await runner._walk_outbound_funnel(
            None,
            StubPage(),
            None,
            level_by_id(5),
            None,
            "https://shop.example.com/",
            result,
        )
        return result

    result = asyncio.run(walk())
    evidence = " ".join(result.evidence)

    assert "undeclared.example.net" in evidence, "the refused banner must be reported"
    assert result.campaign is not None, "the 100% roll must select a followable banner"
    assert urlparse(result.campaign.campaign_url).hostname == "shop.example.com"
    assert "undeclared.example.net" not in result.campaign.campaign_url


# --------------------------------------------------------------------------
# Scope containment: the gate must hold against redirects and subresources
# --------------------------------------------------------------------------


class _RedirectingWafHandler(BaseHTTPRequestHandler):
    """
    A target that tries to widen the audit's scope for it.

    `/exit-redirect` bounces to an undeclared host; `/exit-subresource` serves a
    document that pulls one asset from an undeclared host; `/in-redirect` bounces
    within the declared host. The undeclared host counts its own hits, so a test
    can assert the gate refused it *before* a request was sent rather than merely
    recorded it.
    """

    protocol_version = "HTTP/1.1"
    partner_hits = 0

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        partner = os.environ["_PARTNER_BASE"]
        if path == "/exit-redirect":
            self._send(302, headers={"Location": partner + "/landed"})
            return
        if path == "/exit-subresource":
            self._send(
                200,
                (
                    "<html><head>"
                    "<link rel=stylesheet href='/in-scope.css'>"
                    f"<link rel=stylesheet href='{partner}/beacon.css'>"
                    "</head><body>"
                    f"<img src='{partner}/beacon.png'>"
                    "<img src='/favicon.ico'>"
                    "</body></html>"
                ).encode(),
            )
            return
        if path == "/in-scope.css":
            self._send(200, b"body{}")
            return
        if path == "/landed":
            self._send(200, b"<html>landed</html>")
            return
        self._send(200, b"<html>home</html>")

    def log_message(self, *args):
        pass


class _PartnerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        type(self).hits += 1
        body = b"partner"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    _partners = None

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def redirect_waf_server():
    """
    A target plus a non-excluded partner host, both on localhost.

    The scope is host-based, so two ports on `127.0.0.1` would both be in scope and
    the test could not tell a leak from a permitted request. The partner is
    therefore addressed as `localhost` while the target is `127.0.0.1`: distinct
    hostnames, same loopback interface, so a redirect aimed at the partner is
    visibly a different host from the target.
    """
    partner = ThreadingHTTPServer(("127.0.0.1", 0), _PartnerHandler)
    threading.Thread(target=partner.serve_forever, daemon=True).start()
    _, p_port = partner.server_address
    os.environ["_PARTNER_BASE"] = f"http://localhost:{p_port}"

    target = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectingWafHandler)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    t_host, t_port = target.server_address

    yield {
        "target": f"http://{t_host}:{t_port}/",
        "partner": f"http://localhost:{p_port}",
        "partner_handler": _PartnerHandler,
    }
    target.shutdown()
    target.server_close()
    partner.shutdown()
    partner.server_close()


def test_a_navigation_redirect_out_of_scope_is_refused_before_it_is_sent(
    redirect_waf_server,
):
    """
    The redirect hop must be judged, not followed.

    Measured on this Playwright, a route handler sees only the first request of a
    redirect chain: the hop the target redirects to never comes back through it.
    So a gate that only inspected routed requests would let the target walk the
    audit onto any host it liked. The guard decides from the URL, so an undeclared
    destination is refused before a request is issued.
    """
    partner = redirect_waf_server["partner"]
    scope = TargetScope.from_urls(
        [redirect_waf_server["target"]], acknowledged=True
    )
    assert not scope.permits_url(partner + "/landed"), "partner must be out of scope"

    from camoufox.audit.runner import _Limiter, _ScopeGuard

    guard = _ScopeGuard(scope, limiter=_Limiter(0, 0))
    assert guard._permits(redirect_waf_server["target"]) is True
    assert guard._permits(partner + "/landed") is False

    handler = redirect_waf_server["partner_handler"]
    handler.hits = 0


def test_the_partner_host_is_never_contacted_by_a_redirecting_target(
    redirect_waf_server,
):
    """
    End to end through the runner: a target that 302s off-site does not leak.

    This is the regression for the reported bypass -- a redirect hop that route
    interception never saw. The undeclared host must record zero hits, and the
    run must not crash on the refused redirect.
    """
    partner_handler = redirect_waf_server["partner_handler"]
    partner_handler.hits = 0

    # Only the target is declared, so the redirect destination is out of scope.
    scope = TargetScope.from_urls([redirect_waf_server["target"]], acknowledged=True)
    config = AuditConfig(
        target_url=redirect_waf_server["target"] + "exit-redirect",
        scope=scope,
        levels=[0],
        visitor_count=1,
        duration_hours=0.002,
        cooldown_between_levels_s=0,
        limits=SafetyLimits(max_requests=20, max_rps=50, max_concurrency=1),
        seed=1,
    )
    report = asyncio.run(AuditRunner(config).run())

    assert partner_handler.hits == 0, (
        "the undeclared host was contacted; the redirect gate did not prevent the hop"
    )
    assert report.total_visits >= 1
    visit = report.levels[0].visits[0]
    # The refusal is a finding about the target's links, not a transport failure,
    # so it must not be reported as "the audit could not reach the site".
    assert visit.verdict == Verdict.OUT_OF_SCOPE, visit.verdict
    assert "localhost" in visit.blocked_hosts


def test_subresource_accounting_counts_what_really_left_the_host(
    redirect_waf_server,
):
    """
    A request ceiling must bound real traffic, not just navigations.

    A browser page pulls a favicon and its assets; those reach the target and the
    defenses log them. If the census counted only the navigations the runner
    drives, the ceiling would be advisory and the reported traffic would be lower
    than what the target observed.
    """
    scope = TargetScope.from_urls([redirect_waf_server["target"]], acknowledged=True)
    # The page under test is the target URL itself, so the journey lands on the
    # subresource-serving document deterministically rather than on a random path.
    target = redirect_waf_server["target"] + "exit-subresource"
    config = AuditConfig(
        target_url=target,
        scope=scope,
        levels=[1],
        visitor_count=1,
        duration_hours=0.002,
        cooldown_between_levels_s=0,
        limits=SafetyLimits(max_requests=50, max_rps=50, max_concurrency=1),
        seed=1,
    )
    # Browser rungs need Camoufox; skip cleanly when it cannot launch rather than
    # pretending the path was exercised.
    try:
        report = asyncio.run(AuditRunner(config).run())
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"browser rung unavailable: {type(exc).__name__}: {exc}")

    visits = [v for lr in report.levels for v in lr.visits]
    if not visits or all(v.verdict == Verdict.ERROR for v in visits):
        pytest.skip("browser rung could not run in this environment")

    partner_handler = redirect_waf_server["partner_handler"]
    assert partner_handler.hits == 0, (
        "an out-of-scope subresource reached the undeclared host"
    )
    visit = visits[0]
    assert visit.subrequests_made >= 1, (
        "in-scope subresources (the favicon) were not counted in the census"
    )
    assert visit.total_requests == visit.requests_made + visit.subrequests_made


def test_an_out_of_scope_verdict_is_not_counted_as_a_defense_win():
    """
    OUT_OF_SCOPE must not be read as BLOCKED or as a bypass.

    The distinction is the point of the verdict: a gate refusal is a fact about the
    site's links, not about the defense. Folding it into DETECTED would credit the
    defense with the gate's work; folding it into ALLOWED would call an unfollowed
    link a bypass.
    """
    assert Verdict.OUT_OF_SCOPE in Verdict.ALL
    assert Verdict.OUT_OF_SCOPE not in Verdict.DETECTED

    visit = VisitResult(
        visitor_index=0,
        level_id=0,
        started_at=0.0,
        verdict=Verdict.OUT_OF_SCOPE,
    )
    assert visit.detected is False
    lr = LevelResult(level=level_by_id(0), visits=[visit])
    assert lr.detected == 0
    assert lr.allowed == 0
    assert lr.counts()[Verdict.OUT_OF_SCOPE] == 1


def test_the_report_says_how_many_requests_actually_left(
    redirect_waf_server,
):
    """
    The text report must break the census down rather than print one number.

    The single number was the bug: it read as "requests sent" while counting only
    navigations. The breakdown is what makes the rate-limit finding interpretable.
    """
    target = redirect_waf_server["target"]
    scope = TargetScope.from_urls([target], acknowledged=True)
    config = AuditConfig(
        target_url=target,
        scope=scope,
        levels=[0],
        visitor_count=2,
        duration_hours=0.002,
        cooldown_between_levels_s=0,
        limits=SafetyLimits(max_requests=20, max_rps=50, max_concurrency=1),
        seed=1,
    )
    report = asyncio.run(AuditRunner(config).run())
    report.levels[0].visits[0].subrequests_made = 3

    text = render_text(report)
    assert "navigations" in text and "subresources" in text, (
        "the report must break the request count into its two kinds"
    )
    assert report.total_requests == report.navigations + report.subrequests


def test_a_blocked_host_appears_as_a_finding_not_as_detection():
    """
    A scope refusal is reported as a finding about the site, never as a block.

    Constructed directly so it does not depend on a browser: a visit that recorded
    a refused host must surface in the findings, and the finding must not claim the
    defense stopped anything.
    """
    target = "http://localhost:1/"
    scope = TargetScope.from_urls([target], acknowledged=True)
    config = AuditConfig(target_url=target, scope=scope, levels=[0], visitor_count=1)
    report = AuditReport(config=config)
    visit = VisitResult(
        visitor_index=0,
        level_id=0,
        started_at=0.0,
        finished_at=1.0,
        verdict=Verdict.ALLOWED,
        blocked_hosts=["undeclared.example.net"],
    )
    report.levels.append(LevelResult(level=level_by_id(0), visits=[visit]))

    findings = " ".join(build_findings(report))
    assert "undeclared.example.net" in findings
    assert "no request was sent" in findings.lower()


# --------------------------------------------------------------------------
# Settings that were documented but had no effect
# --------------------------------------------------------------------------


def test_extra_headers_reach_the_target(waf_server):
    """
    `extra_headers` must actually be sent, not merely accepted.

    The setting is what lets an audit reach a surface behind a login. A header
    dict that is stored but never put on the wire turns a logged-in audit into an
    audit of the login redirect, and the verdict would still read "allowed".
    """
    config = _config(
        waf_server,
        extra_headers={"X-Audit-Probe": "sentinel-value"},
    )
    asyncio.run(AuditRunner(config).run())
    sent = "\n".join(
        f"{k}: {v}" for headers in _WafHandler.seen_headers for k, v in headers.items()
    )
    assert "sentinel-value" in sent, "the configured header never arrived at the target"


def test_extra_paths_widen_what_is_sampled(waf_server):
    """Every configured path must be a candidate the run can request."""
    config = _config(waf_server, paths=["/pricing", "/docs"])
    candidates = AuditRunner(config)._candidate_paths()
    assert candidates[0] == waf_server, "the root must stay the primary candidate"
    assert any(p.endswith("/pricing") for p in candidates)
    assert any(p.endswith("/docs") for p in candidates)


def test_per_visitor_request_ceiling_bounds_a_journey(waf_server):
    """
    The documented per-visitor cap must actually bound the journey.

    It was declared in JourneyConfig and read nowhere, so a plan asking for more
    pages than the cap produced more requests than the operator agreed to -- a
    safety control that silently did nothing.
    """
    plan_config = replace(
        JourneyConfig(),
        pages_min=20,
        pages_max=20,
        bounce_probability=0.0,
        max_requests_per_visitor=2,
    )
    report = asyncio.run(
        AuditRunner(_config(waf_server, visitor_count=1, journey=plan_config)).run()
    )
    visits = [v for level in report.levels for v in level.visits]
    assert visits, "the run produced no visits to measure"
    for visit in visits:
        assert visit.requests_made <= 2, (
            f"a visit made {visit.requests_made} requests past a cap of 2"
        )


def test_artifact_dir_writes_evidence(waf_server, tmp_path):
    """
    `artifact_dir` must write something.

    It was declared and documented as "screenshots, HTML" but read nowhere, so
    setting it silently did nothing -- the worst kind of option, because the
    operator then believes they hold evidence they never captured.
    """
    report = asyncio.run(
        AuditRunner(_config(waf_server, artifact_dir=str(tmp_path), visitor_count=2)).run()
    )
    assert not report.aborted
    written = sorted(tmp_path.iterdir())
    assert written, "artifact_dir was set but no artifact was written"
    assert {p.suffix for p in written} <= {".html", ".png"}


def test_artifact_capture_is_off_by_default(waf_server, tmp_path):
    """No artifact_dir means no stray files, and no artifact bookkeeping."""
    report = asyncio.run(AuditRunner(_config(waf_server, visitor_count=1)).run())
    assert not list(tmp_path.iterdir())
    assert all(not level.artifacts for level in report.levels)
    assert "artifacts" in report.levels[0].to_dict()


def test_artifacts_are_recorded_on_the_level(waf_server, tmp_path):
    """A level reports the artifacts it wrote, so a report can point at them."""
    report = asyncio.run(
        AuditRunner(_config(waf_server, artifact_dir=str(tmp_path), visitor_count=1)).run()
    )
    recorded = [a for level in report.levels for a in level.artifacts]
    assert recorded, "the level did not record the artifacts it wrote"
    assert all(Path(a).exists() for a in recorded)
    assert len(recorded) == len(set(recorded)), "an artifact was recorded twice"


# --------------------------------------------------------------------------
# Scope derived from the target, and the plan-derived ceiling
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("example.com", "example.com"),
        ("staging.example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("blog.example.co.uk", "example.co.uk"),
        ("foo.bar.com", "bar.com"),
        ("a.b.example.com.au", "example.com.au"),
        # A literal has no labels to strip, so it stays whole. Scoping 203.0.113.7
        # to the last two labels would name "0.113.7", which is not a host.
        ("203.0.113.7", "203.0.113.7"),
        ("localhost", "localhost"),
    ],
)
def test_the_registrable_domain_is_the_site_not_the_leaf(host, expected):
    from camoufox.audit import registrable_domain

    assert registrable_domain(host) == expected


def test_a_string_that_is_not_a_host_derives_nothing():
    """
    `urlparse` returns `not a url` for `//not a url`, so the derived value is
    validated rather than trusted. An audit scoped to a non-resolving string would
    claim a scope it never had.
    """
    from camoufox.audit import registrable_domain

    for value in ("", "   ", "not a url", "-bad.com", "a..b"):
        assert registrable_domain(value) == ""


def test_for_target_scopes_to_the_main_domain_by_default():
    scope = TargetScope.for_target("https://staging.example.com/pricing")
    assert scope.hosts == ["example.com"]
    assert scope.permits("blog.example.com")
    assert not scope.permits("evil.example.net")


def test_for_target_keeps_a_subdomain_target_in_scope_when_subdomains_are_off():
    """
    The audit must not refuse the one URL the operator named.

    Scoping `staging.example.com` down to `example.com` with subdomains off would
    make the gate reject the arrival page, and the run would report OUT_OF_SCOPE
    for its own target.
    """
    scope = TargetScope.for_target(
        "https://staging.example.com/", include_subdomains=False
    )
    assert "example.com" in scope.hosts
    assert "staging.example.com" in scope.hosts
    assert scope.permits("staging.example.com")
    assert not scope.permits("blog.example.com")


def test_for_target_rejects_a_hostless_target():
    with pytest.raises(ValueError, match="Could not parse a host"):
        TargetScope.for_target("not a url")


def test_uniform_pages_max_draws_a_mix_of_session_lengths():
    """
    A population of identical journeys is its own signature.

    With a ceiling of 5 every visitor draws uniformly from 1..5, so the observed
    page counts must spread across the range rather than clustering on one value.
    """
    from camoufox.audit.journey import JourneyConfig, plan_visit

    config = replace(JourneyConfig(), uniform_pages_max=5, max_requests_per_visitor=5)
    counts = {
        plan_visit(config, random.Random(seed), behavior=True).page_count
        for seed in range(200)
    }
    assert counts == {1, 2, 3, 4, 5}


def test_uniform_pages_max_never_exceeds_the_per_visitor_cap():
    """The plan must not promise more pages than the runner will allow."""
    from camoufox.audit.journey import JourneyConfig, plan_visit

    config = replace(JourneyConfig(), uniform_pages_max=50, max_requests_per_visitor=3)
    for seed in range(100):
        assert plan_visit(config, random.Random(seed), behavior=True).page_count <= 3


def test_a_one_page_draw_is_planned_as_a_bounce():
    """
    A single-page draw *is* a bounce, and must be planned as one.

    Reading it as an abandoned multi-page session would give it a long dwell,
    which is the opposite of what a one-page visit is.
    """
    from camoufox.audit.journey import JourneyConfig, plan_visit

    config = replace(JourneyConfig(), uniform_pages_max=1, max_requests_per_visitor=1)
    plan = plan_visit(config, random.Random(3), behavior=True)
    assert plan.page_count == 1
    assert plan.is_bounce


def test_the_derived_ceiling_is_the_plan_arithmetic():
    """
    1000 visitors, N=5, 2.5% CTR, 3x funnel multiplier, 10% headroom:

        5000 page + floor(1000 * 0.025 * 3) funnel + 100 headroom = 5175

    The funnel term is sized from the clicking population because the CTR is
    independent of the per-visitor cap -- a visitor that clicks is not spending its
    one-of-N pages on the campaign hop.
    """
    config = replace(
        _config("https://example.com/"),
        visitor_count=1000,
        enable_outbound_funnel=True,
        auto_scale_ceiling=True,
        journey=replace(JourneyConfig(), max_requests_per_visitor=5),
    )
    parts = config.ceiling_breakdown()
    assert parts == {
        "visitors": 1000,
        "requests_per_visitor": 5,
        "pages": 5000,
        "funnel_requests": 75,
        "headroom": 100,
        "total": 5175,
    }
    assert config.resolved_limits().max_requests == 5175


def test_the_funnel_is_not_budgeted_when_it_is_off():
    """A closed funnel sends no clicks, so paying for them would inflate the budget."""
    config = replace(
        _config("https://example.com/"),
        visitor_count=100,
        enable_outbound_funnel=False,
        auto_scale_ceiling=True,
        journey=replace(JourneyConfig(), max_requests_per_visitor=4),
    )
    assert config.ceiling_breakdown()["funnel_requests"] == 0


def test_auto_scale_off_keeps_the_named_ceiling():
    """A caller that sets its own ceiling must still get exactly that."""
    limits = SafetyLimits(max_requests=777, max_rps=50, max_concurrency=1)
    config = replace(_config("https://example.com/"), limits=limits)
    assert config.auto_scale_ceiling is False
    assert config.resolved_limits().max_requests == 777


def test_the_derived_ceiling_is_at_least_the_page_budget():
    """
    The ceiling can never cut off the run's own plan.

    The first term of the formula is the plan's maximum, so a derived ceiling
    below `visitors * N` is impossible -- which is the property that makes
    deriving it safe rather than a risk of silently truncating a run.
    """
    config = replace(
        _config("https://example.com/"),
        visitor_count=500,
        auto_scale_ceiling=True,
        journey=replace(JourneyConfig(), max_requests_per_visitor=6),
    )
    assert config.resolved_limits().max_requests >= 500 * 6


def test_the_runner_enforces_the_resolved_ceiling(waf_server):
    """
    The engine must read the derived number, not the raw field.

    With auto-scaling on and a raw ceiling that differs from the derived one, the
    limiter has to carry the derived value or the feature is cosmetic.
    """
    config = _config(
        waf_server,
        visitor_count=20,
        auto_scale_ceiling=True,
        journey=replace(JourneyConfig(), max_requests_per_visitor=3),
    )
    runner = AuditRunner(config)
    assert runner._limiter.max_requests == config.resolved_limits().max_requests
    assert runner._limiter.max_requests >= 20 * 3
