"""
The GUI bridge's handling of the settings that reach the engine.

These run offscreen: `AuditBackend` is a plain QObject bridge, so it needs a Qt
application object but never a window or a display. Every case here is a
*rejection* path -- the run stops before a worker is spawned -- so the suite stays
offline and does not depend on the engine having a live target.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# CI's pythonlib tier installs no Qt, so this module cannot even be imported
# there. Skipping keeps that tier reporting what it actually verified instead of
# failing collection on a dependency it was never given. These cases do run in
# any environment that has PySide6 -- `pythonlib/tests` with the `gui` extra.
pytest.importorskip("PySide6")

from camoufox.gui import audit_backend as ab  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtGui import QGuiApplication

    app = QGuiApplication.instance() or QGuiApplication([])
    yield app
    del app


@pytest.fixture
def backend(qapp):
    """A fresh bridge per test.

    Module scope would let one test's malformed header leak into the next, which
    is exactly the kind of order dependence that hides a real failure.
    """
    instance = ab.AuditBackend()
    yield instance
    del instance


# -- header / path parsing --------------------------------------------------


def test_header_lines_parse_into_a_mapping():
    parsed = ab._parse_header_lines("Authorization: Bearer abc\nCookie: s=1")
    assert parsed == {"Authorization": "Bearer abc", "Cookie": "s=1"}


def test_blank_and_comment_lines_are_ignored():
    parsed = ab._parse_header_lines("\n# a note\nX-A: 1\n   \n")
    assert parsed == {"X-A": "1"}


def test_a_colon_inside_a_value_is_kept():
    """`Cookie: a=b; c=d` must not be truncated at the second colon."""
    assert ab._parse_header_lines("Cookie: a=b; expires=Thu")["Cookie"] == (
        "a=b; expires=Thu"
    )


def test_a_malformed_header_is_rejected_not_dropped():
    """
    Dropping a malformed line would silently un-authenticate the audit.

    The run would then measure the login page and still report a verdict, which
    is a wrong answer presented as a finding. Raising is the only safe response.
    """
    with pytest.raises(ValueError, match="line 1"):
        ab._parse_header_lines("not a header")


def test_an_invalid_header_name_is_rejected():
    with pytest.raises(ValueError, match="invalid name"):
        ab._parse_header_lines("Bad Name: x")


def test_the_offending_line_number_is_reported():
    with pytest.raises(ValueError, match="line 2"):
        ab._parse_header_lines("Good: 1\nbad")


def test_paths_are_normalised_with_a_leading_slash():
    assert ab._parse_path_lines("pricing\n/docs\n\n# c") == ["/pricing", "/docs"]


# -- the run is stopped before it starts -----------------------------------


def _armed(backend):
    """A backend pointed at a target whose scope derives cleanly.

    The scope is no longer typed -- it comes from the target -- so arming the
    backend is just naming the target and a visitor count.
    """
    backend.setAcknowledged(True)
    backend.setTarget("https://example.com/")
    backend.setVisitors(6)
    return backend


def test_a_malformed_header_stops_the_run_with_a_reason(backend):
    _armed(backend)
    backend.setExtraHeaders("this is not a header")
    backend.start()
    assert "Custom headers" in backend.error
    assert not backend.running


def test_an_out_of_scope_extra_path_is_rejected(backend):
    """Paths are appended to the target, so a full URL there is a mistake."""
    _armed(backend)
    backend.setExtraPaths("https://elsewhere.example.net/x")
    backend.start()
    assert "must be a path on the target" in backend.error
    assert not backend.running


def test_an_unusable_artifact_directory_stops_the_run(backend, tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    _armed(backend)
    backend.setArtifactDir(str(blocker / "child"))
    backend.start()
    assert "Artifact directory unusable" in backend.error
    assert not backend.running


def test_the_new_settings_have_working_setters(backend, tmp_path):
    """Each exposed setting must round-trip, or the QML binds to a dead field."""
    backend.setAbortAfterErrors(7)
    backend.setCooldownSeconds(2.5)
    backend.setExtraPaths("/a")
    backend.setExtraHeaders("X-A: 1")
    backend.setReuseBrowser(False)
    backend.setArtifactDir(str(tmp_path))
    backend.setMaxRequestsPerVisitor(4)

    assert backend.abortAfterErrors == 7
    assert backend.cooldownSeconds == 2.5
    assert backend.extraPaths == "/a"
    assert backend.extraHeaders == "X-A: 1"
    assert backend.reuseBrowser is False
    assert backend.artifactDir == str(tmp_path)
    assert backend.maxRequestsPerVisitor == 4


def test_setters_clamp_out_of_range_values(backend):
    """A negative ceiling must not reach the engine as a negative."""
    backend.setAbortAfterErrors(-5)
    assert backend.abortAfterErrors == 0
    backend.setCooldownSeconds(-1.0)
    assert backend.cooldownSeconds == 0.0
    backend.setMaxRequestsPerVisitor(0)
    assert backend.maxRequestsPerVisitor == 1

# -- rolling log buffer -----------------------------------------------------
#
# The buffer is what keeps a long audit from growing the log window without
# bound, so both ceilings are exercised directly rather than through a run.

def _messages(buffer):
    """The buffered lines with the display timestamp stripped off each one."""
    return [line.split("] ", 1)[1] for line in buffer.lines()]


def test_log_buffer_evicts_oldest_lines_past_the_count_ceiling():
    buffer = ab.RollingLogBuffer(max_lines=5, window_s=10_000)
    for index in range(12):
        buffer.append(f"line {index}", now=100.0 + index * 0.001)

    assert len(buffer) == 5
    # The newest survive; the oldest are the ones dropped.
    assert _messages(buffer) == [f"line {i}" for i in range(7, 12)]


def test_log_buffer_evicts_lines_past_the_age_window():
    buffer = ab.RollingLogBuffer(max_lines=1000, window_s=60.0)
    for index in range(10):
        buffer.append(f"old {index}", now=1000.0 + index)

    # A long silence, then one new line: everything older than the window goes.
    buffer.append("fresh", now=1100.0)

    assert len(buffer) == 1
    assert _messages(buffer) == ["fresh"]


def test_log_buffer_keeps_a_line_at_exactly_the_window_edge():
    """The window drops "older than", so an entry at the cutoff is retained."""
    buffer = ab.RollingLogBuffer(max_lines=1000, window_s=60.0)
    buffer.append("edge", now=1000.0)
    buffer.append("now", now=1060.0)

    assert _messages(buffer) == ["edge", "now"]


def test_log_buffer_whichever_ceiling_comes_first_wins():
    """A burst within the window still stops at the line cap."""
    buffer = ab.RollingLogBuffer(max_lines=3, window_s=10_000.0)
    for index in range(50):
        buffer.append(f"burst {index}", now=500.0 + index * 0.01)

    assert len(buffer) == 3
    assert _messages(buffer) == ["burst 47", "burst 48", "burst 49"]


def test_log_buffer_lines_limit_returns_only_the_newest():
    buffer = ab.RollingLogBuffer(max_lines=100, window_s=10_000)
    for index in range(20):
        buffer.append(f"l{index}", now=200.0 + index * 0.01)

    tail = buffer.lines(limit=3)
    assert len(tail) == 3
    assert [line.split("] ", 1)[1] for line in tail] == ["l17", "l18", "l19"]
    # A limit wider than the buffer is not an error, and neither is clearing.
    assert len(buffer.lines(limit=999)) == 20
    buffer.clear()
    assert len(buffer) == 0 and buffer.lines() == []


def test_backend_log_property_is_bounded_even_after_many_lines(backend):
    """
    The bridge's own buffer must stay bounded, not just the standalone class.

    A run emits far more lines than the window will ever show, so the ceiling
    has to be enforced at the point lines are appended -- if it only trimmed on
    read, the full history would still be held for the life of the run.
    """
    for index in range(ab._LOG_MAX_LINES + 250):
        backend._append_log(f"line {index}")

    assert len(backend._log) == ab._LOG_MAX_LINES
    shown = backend.log
    assert len(shown) == 300
    assert shown[-1].endswith(f"line {ab._LOG_MAX_LINES + 249}")

    backend.clearLog()
    assert backend.log == []


# -- the scope is derived from the target, not typed -------------------------


def test_the_authorized_host_is_derived_from_the_target(backend):
    """
    A page URL names the site; the site is the scope.

    The old two-field form let the two disagree -- a target on a subdomain scoped
    to the apex would have the audit refuse its own arrival page. Deriving removes
    the possibility rather than documenting it.
    """
    backend.setTarget("https://staging.example.com/pricing")
    assert backend.derivedHost == "example.com"
    assert "example.com" in backend.scopeDescription


def test_a_multi_label_country_code_keeps_its_registry_label(backend):
    """`blog.example.co.uk` is one site, not two labels of `co.uk`."""
    backend.setTarget("https://blog.example.co.uk/post")
    assert backend.derivedHost == "example.co.uk"


def test_an_ip_literal_derives_itself(backend):
    """
    A literal has no domain structure, so stripping labels would invent a scope.

    `203.0.113.7` must stay whole; treating it as a three-label host would scope
    the audit to `0.113.7`, which is not a host at all.
    """
    backend.setTarget("http://203.0.113.7:8080/app")
    assert backend.derivedHost == "203.0.113.7"


def test_an_empty_or_hostless_target_derives_nothing(backend):
    for value in ("", "   ", "not a url"):
        backend.setTarget(value)
        assert backend.derivedHost == ""
        assert not backend.canRun


def test_subdomains_are_in_scope_by_default(backend):
    backend.setTarget("https://example.com/")
    assert backend.includeSubdomains is True
    assert backend.subdomainsExcluded is False
    assert "subdomain" in backend.scopeDescription


def test_excluding_subdomains_is_the_inverse_toggle(backend):
    """The two radio options are one setting, so each must move the other."""
    backend.setSubdomainsExcluded(True)
    assert backend.includeSubdomains is False
    backend.setIncludeSubdomains(True)
    assert backend.subdomainsExcluded is False


def test_excluding_subdomains_pins_the_journey_to_one_page(backend):
    """
    "No subdomains" means "this is one static page", so N must collapse to 1.

    Leaving N at 12 would promise twelve-page journeys that the scope can only
    partly serve: the visitor would exhaust in-scope links and the run would spend
    its budget finding nothing. The backend clamps it, not just the disabled QML
    field, because a binding is not an enforcement.
    """
    backend.setMaxRequestsPerVisitor(9)
    assert backend.maxRequestsPerVisitor == 9
    backend.setIncludeSubdomains(False)
    assert backend.maxRequestsPerVisitor == 1
    assert backend.maxRequestsPerVisitorLocked is True
    # A later write must not reopen it while the mode is on.
    backend.setMaxRequestsPerVisitor(7)
    assert backend.maxRequestsPerVisitor == 1


def test_the_static_page_hint_names_the_pin(backend):
    backend.setIncludeSubdomains(False)
    assert "1" in backend.maxRequestsPerVisitorHint
    backend.setIncludeSubdomains(True)
    assert "1-" in backend.maxRequestsPerVisitorHint


# -- authorization is implicit, the control is not --------------------------


def test_the_backend_starts_authorized(backend):
    """
    No checkbox means the state must be true from construction.

    The engine's gate still reads `scope.acknowledged`; what changed is that the
    GUI supplies it, so a run cannot reach the gate unauthorized.
    """
    assert backend.acknowledged is True
    assert backend.acknowledgmentNote == ab.AUTO_ACKNOWLEDGMENT_NOTE


def test_the_built_config_carries_the_auto_acknowledgment(backend):
    """The note has to survive into the engine's config, not just the property."""
    _armed(backend)
    config = backend._build_config()
    assert config.scope.acknowledged is True
    assert config.scope.acknowledgment_note == ab.AUTO_ACKNOWLEDGMENT_NOTE


# -- the global ceiling is derived from the plan -----------------------------


def test_the_ceiling_is_derived_from_the_traffic_plan(backend):
    """
    The ceiling must be the plan's own arithmetic, not a second guess.

    With 1000 visitors, N=5, a 2.5% CTR and 10% headroom the derived budget is
    5000 page + 75 funnel + 100 headroom = 5175. The funnel term is sized from the
    clicking population because the CTR is independent of the per-visitor cap: a
    visitor that clicks is not spending its one-of-N pages on the campaign hop.
    """
    _armed(backend)
    backend.setVisitors(1000)
    backend.setMaxRequestsPerVisitor(5)
    parts = backend.safetyCeiling
    assert parts["pages"] == 5000
    assert parts["headroom"] == 100
    assert parts["total"] == (
        parts["pages"] + parts["funnel_requests"] + parts["headroom"]
    )
    assert "5000" in backend.safetyCeilingSummary


def test_the_ceiling_grows_with_the_visitor_count(backend):
    _armed(backend)
    backend.setMaxRequestsPerVisitor(4)
    backend.setVisitors(100)
    small = backend.safetyCeiling["total"]
    backend.setVisitors(400)
    assert backend.safetyCeiling["total"] > small


def test_the_ceiling_is_empty_without_a_derivable_target(backend):
    """A half-filled form shows nothing rather than a misleading zero."""
    backend.setTarget("")
    assert backend.safetyCeiling == {}
    assert backend.safetyCeilingSummary == ""


def test_the_built_config_derives_its_ceiling(backend):
    _armed(backend)
    backend.setVisitors(1000)
    backend.setMaxRequestsPerVisitor(5)
    config = backend._build_config()
    assert config.auto_scale_ceiling is True
    assert config.resolved_limits().max_requests == config.ceiling_breakdown()["total"]


def test_a_preview_does_not_create_directories(backend, tmp_path):
    """
    A property read must not touch the filesystem.

    `safetyCeiling` is bound to the form, so it re-reads on keystrokes; creating
    the artifact directory there would litter the disk as the operator types.
    """
    _armed(backend)
    target = tmp_path / "not-yet"
    backend.setArtifactDir(str(target))
    backend._build_config_for_preview()
    assert not target.exists()
    backend._build_config()
    assert target.exists()
