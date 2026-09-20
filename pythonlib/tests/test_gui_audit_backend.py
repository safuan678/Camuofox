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
    """An acknowledged backend pointed at a target that parses cleanly."""
    backend.setAcknowledged(True)
    backend.setTarget("https://example.com/")
    backend.setScopeHosts("example.com")
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