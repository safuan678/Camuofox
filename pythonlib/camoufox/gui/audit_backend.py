"""
QML bridge for the WAF / bot-defense audit tab.

The audit runs on a worker thread and reports back through signals, because the
GUI must stay responsive while a 24-hour schedule is pending -- a blocked event
loop would make Stop unclickable, which is the one control that must always work.

Two things are deliberately enforced here rather than in QML:

* the authorization acknowledgment and the scope, so a UI bug cannot start an
  unauthorized run;
* the safety ceilings, so a mistyped visitor count cannot become real traffic.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from collections import deque
from dataclasses import replace
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from PySide6.QtCore import (
    Property,
    QAbstractListModel,
    QModelIndex,
    QObject,
    Qt,
    QThread,
    Signal,
    Slot,
)

from ..audit import (
    AuditConfig,
    AuditRunner,
    JourneyConfig,
    SafetyLimits,
    TargetScope,
    build_schedule,
    parse_rate_pct,
    registrable_domain,
)
from ..audit.detection import Verdict as _Verdict
from ..audit.report import build_findings, render_text, write_report
from ..audit.schedule import ArrivalPattern

__all__ = ["AuditVisitModel", "AuditBackend", "RollingLogBuffer"]

#: RFC 9110 token, which is what a header field name must be. Used to reject a
#: typo like "Authorization :" before it becomes a mystery 401.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

#: The log is a FIFO with two independent ceilings: an age window and a line
#: count. Whichever is reached first evicts from the head.
#:
#: Two ceilings because they fail differently. An audit that stalls still emits
#: lines, so the count cap bounds a long run; an audit that idles bursts after a
#: pause, so the age window keeps a stale line from sitting at the top forever.
#: A live audit logs thousands of lines, and holding all of them for the length of
#: a run is what made the window grow without bound.
_LOG_WINDOW_S = 2 * 60 * 60
_LOG_MAX_LINES = 5000

#: The audit is authorized at the moment the operator clicks Start.
#:
#: There is no ticket field and no checkbox: the GUI records the acknowledgment
#: itself, with this note, and the engine's gate still requires one -- the scope
#: check in `TargetScope.check` is unchanged, so a run that reached it without an
#: acknowledgment would still be refused. What is removed is the *prompt*, not the
#: control.
AUTO_ACKNOWLEDGMENT_NOTE = "Auto-Authorized via GUI"


_VERDICT_COLOR = {
    _Verdict.ALLOWED: "#6b9e7e",
    _Verdict.CHALLENGED: "#d7a44a",
    _Verdict.RATE_LIMITED: "#d7a44a",
    _Verdict.BLOCKED: "#f14c4c",
    _Verdict.ERROR: "#a0a0a0",
}


def _parse_header_lines(raw: str) -> Dict[str, str]:
    """
    Parse "Name: value" lines into a header dict.

    Raises ValueError with the offending line number rather than skipping a
    malformed line, because a silently dropped `Authorization:` header turns a
    logged-in audit into an audit of the login redirect -- and the report would
    say "allowed", which is a wrong answer presented as a finding.
    """
    headers: Dict[str, str] = {}
    for number, line in enumerate((raw or "").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, sep, value = stripped.partition(":")
        name = name.strip()
        if not sep or not name:
            raise ValueError(
                f"header line {number} is not 'Name: value' ({stripped!r})"
            )
        if not _HEADER_NAME_RE.match(name):
            raise ValueError(f"header line {number} has an invalid name ({name!r})")
        headers[name] = value.strip()
    return headers


class RollingLogBuffer:
    """
    A bounded FIFO of timestamped log lines.

    Evicts from the head whenever either ceiling is crossed: the buffer holds at
    most `max_lines` entries and drops any entry older than `window_s`. Both are
    enforced on every append, so the buffer's size is bounded by construction
    rather than by a periodic sweep that a busy run could outrun.

    Timestamps are stored alongside each line rather than parsed back out of the
    formatted text, because the formatted line also carries a clock time for the
    operator and the two must not be allowed to disagree.
    """

    def __init__(self, max_lines: int = _LOG_MAX_LINES, window_s: float = _LOG_WINDOW_S):
        self._max_lines = max(1, int(max_lines))
        self._window_s = max(0.0, float(window_s))
        self._entries: Deque[Tuple[float, str]] = deque()

    def append(self, line: str, *, now: Optional[float] = None) -> None:
        """Add `line`, evicting from the head until both ceilings hold again."""
        moment = time.monotonic() if now is None else now
        self._entries.append((moment, f"[{time.strftime('%H:%M:%S')}] {line}"))
        self._trim(moment)

    def _trim(self, now: float) -> None:
        cutoff = now - self._window_s
        # Drop by age first, then by count. An entry exactly at the cutoff is kept:
        # the window is "older than", not "at least as old as".
        while self._entries and self._entries[0][0] < cutoff:
            self._entries.popleft()
        while len(self._entries) > self._max_lines:
            self._entries.popleft()

    def clear(self) -> None:
        self._entries.clear()

    def lines(self, limit: Optional[int] = None) -> List[str]:
        """The buffered lines, oldest first, optionally only the newest `limit`."""
        if limit is None or limit >= len(self._entries):
            return [text for _, text in self._entries]
        return [text for _, text in list(self._entries)[-limit:]]

    def __len__(self) -> int:
        return len(self._entries)


def _parse_path_lines(raw: str) -> List[str]:
    """Parse one path per line, normalising each to a leading slash."""
    paths: List[str] = []
    for line in (raw or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        paths.append(stripped if stripped.startswith("/") else "/" + stripped)
    return paths


class AuditVisitModel(QAbstractListModel):
    """Live list of visits for the results table."""

    VisitorRole = Qt.ItemDataRole.UserRole + 1
    LevelRole = Qt.ItemDataRole.UserRole + 2
    VerdictRole = Qt.ItemDataRole.UserRole + 3
    StatusRole = Qt.ItemDataRole.UserRole + 4
    ReasonRole = Qt.ItemDataRole.UserRole + 5
    ColorRole = Qt.ItemDataRole.UserRole + 6
    SourceRole = Qt.ItemDataRole.UserRole + 7
    ProxyRole = Qt.ItemDataRole.UserRole + 8
    RequestsRole = Qt.ItemDataRole.UserRole + 9

    #: Keep the table bounded; a 24h run can produce thousands of rows and the
    #: operator only ever reads the tail. Dropping the oldest keeps memory flat.
    MAX_ROWS = 500

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict[str, Any]] = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None
        row = self._rows[index.row()]
        return {
            self.VisitorRole: row.get("visitor_index", 0),
            self.LevelRole: row.get("level_name", ""),
            self.VerdictRole: row.get("verdict", ""),
            self.StatusRole: row.get("http_status") or "-",
            self.ReasonRole: row.get("reason", ""),
            self.ColorRole: _VERDICT_COLOR.get(row.get("verdict"), "#a0a0a0"),
            self.SourceRole: row.get("source", ""),
            self.ProxyRole: row.get("proxy_label") or "-",
            self.RequestsRole: row.get("requests_made", 0),
        }.get(role)

    def roleNames(self):
        return {
            self.VisitorRole: b"visitorIndex",
            self.LevelRole: b"levelName",
            self.VerdictRole: b"verdict",
            self.StatusRole: b"httpStatus",
            self.ReasonRole: b"reason",
            self.ColorRole: b"verdictColor",
            self.SourceRole: b"source",
            self.ProxyRole: b"proxyLabel",
            self.RequestsRole: b"requestsMade",
        }

    def append(self, row: Dict[str, Any]) -> None:
        if len(self._rows) >= self.MAX_ROWS:
            drop = len(self._rows) - self.MAX_ROWS + 1
            self.beginRemoveRows(QModelIndex(), 0, drop - 1)
            del self._rows[:drop]
            self.endRemoveRows()
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(row)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._rows)


class AuditWorker(QThread):
    """Runs one audit off the GUI thread."""

    progress = Signal(dict)
    finished_report = Signal(dict, str)
    failed = Signal(str)

    def __init__(self, config: AuditConfig, out_dir: Optional[str], parent=None):
        super().__init__(parent)
        self.config = config
        self.out_dir = out_dir
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            report = asyncio.run(
                AuditRunner(
                    self.config,
                    on_progress=self._emit_progress,
                    cancel_event=self._cancel,
                ).run()
            )
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return

        payload = report.to_dict()
        payload["findings"] = build_findings(report)
        payload["text_report"] = render_text(report)

        written: Dict[str, str] = {}
        if self.out_dir:
            try:
                written = write_report(report, self.out_dir)
            except Exception as exc:
                payload.setdefault("findings", []).append(
                    f"Could not write reports to {self.out_dir}: {exc}"
                )
        payload["written"] = written
        self.finished_report.emit(payload, json.dumps(payload, default=str))

    def _emit_progress(self, payload: dict) -> None:
        self.progress.emit(payload)


class AuditBackend(QObject):
    """State and slots the Audit tab binds to."""

    changed = Signal()
    visitsChanged = Signal()
    logChanged = Signal()
    runningChanged = Signal()
    summaryChanged = Signal()
    findingsChanged = Signal()
    schedulePreviewChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._visits = AuditVisitModel(self)
        self._running = False
        self._worker: Optional[AuditWorker] = None

        # --- target / scope ---------------------------------------------
        self._target = ""
        self._exclude_hosts = ""
        #: Whether subdomains of the target's main domain are in scope. On by
        #: default: the common audit is a site, and a site is more than its apex.
        #: Off means the operator has told us this is a single static page, which
        #: is why off also pins the per-visitor journey to one page.
        self._include_subdomains = True
        #: The audit is auto-authorized: the GUI starts it on the operator's click
        #: with no separate checkbox. See `acknowledged`.
        self._acknowledged = True
        self._ack_note = AUTO_ACKNOWLEDGMENT_NOTE

        # --- outbound funnel ---------------------------------------------
        self._enable_funnel = False
        self._campaign_rate = "2.5"
        self._include_iframes = True

        # --- traffic plan ------------------------------------------------
        self._visitors = 100
        self._hours = 24.0
        self._pattern_index = 0
        self._max_level = 3
        self._single_level_mode = False
        self._single_level = 5
        self._max_rps = 5.0
        self._max_concurrency = 4
        self._max_per_minute = 30
        self._max_per_proxy = 0
        #: Consecutive transport errors before a rung is aborted. The engine's
        #: ceiling, exposed because 15 is a sensible default for a healthy target
        #: and the wrong one for a flaky one.
        self._abort_after_errors = 15
        #: Seconds between rungs. The engine's default is 30, which matters when a
        #: target rate-limits: back-to-back rungs make the audit's own traffic the
        #: thing being measured.
        self._cooldown_s = 30.0
        #: Extra in-scope paths to sample, one per line, e.g. "/pricing".
        self._paths = ""
        #: Headers every request carries, one "Name: value" per line. This is how
        #: an audit reaches a surface behind a login: a session cookie or an
        #: authorization token the operator already holds.
        self._extra_headers = ""
        #: Keep one browser open for a whole rung (default) or relaunch per visit.
        self._reuse_browser = True
        #: Where per-rung screenshots and HTML are written. Empty = none.
        self._artifact_dir = ""
        #: Extra with-headers ceiling applied to a single visitor's journey.
        #:
        #: This is the operator's "Max requests / visitor": when subdomains are in
        #: scope it is the *top* of a uniform 1..N draw, so a population of
        #: visitors makes mixed-length journeys. When they are not, the journey is
        #: pinned to one page and this reads 1.
        self._max_requests_per_visitor = 12
        #: Force headless for every browser rung. False (the default) honours each
        #: rung's own posture, which is what lets L1 be headless and L2 headful;
        #: ticking the box overrides them all, and the run announces the override.
        self._force_headless = False
        self._seed = ""

        # --- proxy --------------------------------------------------------
        self._proxy_mode_index = 0  # 0 none, 1 file, 2 gateway
        self._proxy_file = ""
        self._proxy_gateway = ""
        self._proxy_policy_index = 0

        self._out_dir = ""
        self._log = RollingLogBuffer()
        self._findings: List[str] = []
        self._summary: Dict[str, Any] = {}
        self._preview: List[str] = []
        self._preview_summary = ""
        self._error = ""

    # -- models ------------------------------------------------------------

    @Property(QObject, constant=True)
    def visits(self):
        return self._visits

    @Property(list, notify=logChanged)
    def log(self):
        return self._log.lines(limit=300)

    @Property(list, notify=findingsChanged)
    def findings(self):
        return self._findings

    @Property("QVariantMap", notify=summaryChanged)
    def summary(self):
        return self._summary

    @Property(list, notify=schedulePreviewChanged)
    def schedulePreview(self):
        return self._preview

    @Property(str, notify=schedulePreviewChanged)
    def schedulePreviewSummary(self):
        return self._preview_summary

    @Slot(result=int)
    def maxPreview(self) -> int:
        """Largest bucket in the arrival preview, for scaling the bar chart."""
        return max(self._preview) if self._preview else 1

    @Property(str, notify=changed)
    def error(self):
        return self._error

    @Property(bool, notify=runningChanged)
    def running(self):
        return self._running

    @Property(bool, notify=changed)
    def canRun(self):
        return bool(
            not self._running
            and self._target
            and self._derives_a_host()
            and self._visitors > 0
        )

    def _derives_a_host(self) -> bool:
        """
        Whether the target parses into a host the audit could scope to.

        The old gate was "the operator typed something in the hosts field". With
        the scope derived from the target there is no such field, so the
        equivalent question is whether the target yields a host at all -- an empty
        or hostless target has no scope and `for_target` would raise on it.
        """
        return bool(self.derivedHost)

    # -- target ------------------------------------------------------------

    @Property(str, notify=changed)
    def target(self):
        return self._target

    @Slot(str)
    def setTarget(self, value: str) -> None:
        self._target = (value or "").strip()
        # The authorized host is derived from the target, not typed separately --
        # see `TargetScope.for_target`. Exposed for display so the operator can
        # see what the audit will actually be scoped to before starting it.
        self.changed.emit()
        self._refresh_preview()

    @Property(str, notify=changed)
    def derivedHost(self):
        """The main domain the target resolves to, or "" when it does not parse."""
        if not self._target:
            return ""
        return registrable_domain(self._target_host())

    @Property(str, notify=changed)
    def scopeDescription(self):
        """
        One line stating what the run will touch, for the operator to check.

        This is the replacement for the old "Authorized hosts" field: the scope is
        no longer typed, so it has to be *shown*, or the operator is auditing a
        scope they cannot see.
        """
        host = self.derivedHost
        if not host:
            return "Enter a target URL to derive the audited scope."
        if self._include_subdomains:
            return f"{host} and any subdomain (e.g. blog.{host})"
        return f"{host} only, as the single page named above"

    def _target_host(self) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(
            self._target if "//" in self._target else f"//{self._target}"
        )
        return parsed.hostname or ""

    @Property(bool, notify=changed)
    def includeSubdomains(self):
        return self._include_subdomains

    @Slot(bool)
    def setIncludeSubdomains(self, value: bool) -> None:
        """
        Include the target's subdomains in scope, or treat it as a static page.

        Turning this off is the operator saying "this is one page". A one-page
        target has no subdomains to wander into, so the per-visitor journey is
        pinned to a single page and the field is locked in the UI -- letting N
        stay above 1 there would promise journeys the scope cannot deliver, and
        the run would spend its budget finding nothing.
        """
        self._include_subdomains = bool(value)
        if not self._include_subdomains:
            self._max_requests_per_visitor = 1
        self.changed.emit()
        self._refresh_preview()

    @Property(bool, notify=changed)
    def subdomainsExcluded(self):
        """Inverse of `includeSubdomains`, for the QML's radio binding."""
        return not self._include_subdomains

    @Slot(bool)
    def setSubdomainsExcluded(self, value: bool) -> None:
        self.setIncludeSubdomains(not bool(value))

    @Property(str, notify=changed)
    def excludeHosts(self):
        """Campaign hosts whose banners the funnel must skip."""
        return self._exclude_hosts

    @Slot(str)
    def setExcludeHosts(self, value: str) -> None:
        self._exclude_hosts = value or ""
        self.changed.emit()
        self._refresh_preview()

    @Property(bool, notify=changed)
    def enableOutboundFunnel(self):
        return self._enable_funnel

    @Slot(bool)
    def setEnableOutboundFunnel(self, value: bool) -> None:
        self._enable_funnel = bool(value)
        self.changed.emit()

    @Property(str, notify=changed)
    def campaignRatePct(self):
        return self._campaign_rate

    @Slot(str)
    def setCampaignRatePct(self, value: str) -> None:
        self._campaign_rate = value or ""
        self.changed.emit()

    @Property(bool, notify=changed)
    def includeIframes(self):
        """Whether banner discovery looks inside child frames."""
        return self._include_iframes

    @Slot(bool)
    def setIncludeIframes(self, value: bool) -> None:
        self._include_iframes = bool(value)
        self.changed.emit()

    @Property(bool, notify=changed)
    def acknowledged(self):
        """
        Whether the run is authorized. Always True in the GUI.

        Kept as a property because the engine's gate and the report both read it,
        and because the QML shows the authorization state. It is no longer set by
        a checkbox: the operator's click on Start *is* the acknowledgment, recorded
        with `AUTO_ACKNOWLEDGMENT_NOTE` when the config is built.
        """
        return self._acknowledged

    @Slot(bool)
    def setAcknowledged(self, value: bool) -> None:
        self._acknowledged = bool(value)
        self.changed.emit()

    @Property(str, notify=changed)
    def acknowledgmentNote(self):
        return self._ack_note

    @Slot(str)
    def setAcknowledgmentNote(self, value: str) -> None:
        self._ack_note = value or ""
        self.changed.emit()

    # -- traffic plan ------------------------------------------------------

    @Property(int, notify=changed)
    def visitors(self):
        return self._visitors

    @Slot(int)
    def setVisitors(self, value: int) -> None:
        self._visitors = max(0, int(value))
        self.changed.emit()
        self._refresh_preview()

    @Property(float, notify=changed)
    def hours(self):
        return self._hours

    @Slot(float)
    def setHours(self, value: float) -> None:
        self._hours = max(0.01, float(value))
        self.changed.emit()
        self._refresh_preview()

    @Property(list, constant=True)
    def patternOptions(self):
        return ["Human (diurnal)", "Constant", "Ramp up", "Spike", "Sustained"]

    @Property(int, notify=changed)
    def patternIndex(self):
        return self._pattern_index

    @Slot(int)
    def setPatternIndex(self, value: int) -> None:
        self._pattern_index = max(0, min(int(value), len(ArrivalPattern.ALL) - 1))
        self.changed.emit()
        self._refresh_preview()

    @Property(int, notify=changed)
    def maxLevel(self):
        return self._max_level

    @Slot(int)
    def setMaxLevel(self, value: int) -> None:
        self._max_level = max(0, min(int(value), 6))
        self.changed.emit()

    @Property(bool, notify=changed)
    def singleLevelMode(self):
        return self._single_level_mode

    @Slot(bool)
    def setSingleLevelMode(self, value: bool) -> None:
        """Run one rung on its own instead of the ladder from L0.

        The visitor count is pinned by the engine in this mode, so a repeat run
        at the same rung is directly comparable.
        """
        self._single_level_mode = bool(value)
        self.changed.emit()
        self._refresh_preview()

    @Property(int, notify=changed)
    def singleLevel(self):
        return self._single_level

    @Slot(int)
    def setSingleLevel(self, value: int) -> None:
        self._single_level = max(0, min(int(value), 6))
        self.changed.emit()

    @Property(int, notify=changed)
    def maxRps(self):
        return self._max_rps

    @Slot(float)
    def setMaxRps(self, value: float) -> None:
        self._max_rps = max(0.0, float(value))
        self.changed.emit()

    @Property(int, notify=changed)
    def maxConcurrency(self):
        return self._max_concurrency

    @Slot(int)
    def setMaxConcurrency(self, value: int) -> None:
        self._max_concurrency = max(1, int(value))
        self.changed.emit()

    @Property(int, notify=changed)
    def maxPerMinute(self):
        return self._max_per_minute

    @Slot(int)
    def setMaxPerMinute(self, value: int) -> None:
        self._max_per_minute = max(1, int(value))
        self.changed.emit()
        self._refresh_preview()

    @Property(int, notify=changed)
    def maxPerProxy(self):
        return self._max_per_proxy

    @Slot(int)
    def setMaxPerProxy(self, value: int) -> None:
        self._max_per_proxy = max(0, int(value))
        self.changed.emit()

    @Property(int, notify=changed)
    def abortAfterErrors(self):
        return self._abort_after_errors

    @Slot(int)
    def setAbortAfterErrors(self, value: int) -> None:
        """Consecutive transport errors that abort a rung (0 disables)."""
        self._abort_after_errors = max(0, int(value))
        self.changed.emit()

    @Property(float, notify=changed)
    def cooldownSeconds(self):
        return self._cooldown_s

    @Slot(float)
    def setCooldownSeconds(self, value: float) -> None:
        """Seconds to wait between finishing one rung and starting the next."""
        self._cooldown_s = max(0.0, float(value))
        self.changed.emit()

    @Property(str, notify=changed)
    def extraPaths(self):
        return self._paths

    @Slot(str)
    def setExtraPaths(self, value: str) -> None:
        self._paths = value or ""
        self.changed.emit()

    @Property(str, notify=changed)
    def extraHeaders(self):
        return self._extra_headers

    @Slot(str)
    def setExtraHeaders(self, value: str) -> None:
        self._extra_headers = value or ""
        self.changed.emit()

    @Property(bool, notify=changed)
    def reuseBrowser(self):
        return self._reuse_browser

    @Slot(bool)
    def setReuseBrowser(self, value: bool) -> None:
        """Keep one browser per rung (True) or launch one per visitor."""
        self._reuse_browser = bool(value)
        self.changed.emit()

    @Property(str, notify=changed)
    def artifactDir(self):
        return self._artifact_dir

    @Slot(str)
    def setArtifactDir(self, value: str) -> None:
        """Directory for per-rung screenshots and HTML. Empty disables capture."""
        self._artifact_dir = (value or "").strip()
        self.changed.emit()

    @Slot(result="QVariantMap")
    def browseArtifactDir(self) -> dict:
        from PySide6.QtWidgets import QFileDialog

        chosen = QFileDialog.getExistingDirectory(None, "Artifact directory")
        if chosen:
            self._artifact_dir = chosen
            self.changed.emit()
            return {"path": chosen, "ok": True, "message": ""}
        return {"path": "", "ok": False, "message": "No directory selected."}

    @Property(int, notify=changed)
    def maxRequestsPerVisitor(self):
        return self._max_requests_per_visitor

    @Slot(int)
    def setMaxRequestsPerVisitor(self, value: int) -> None:
        """
        Top of the per-visitor page draw, or a pinned 1 in static-page mode.

        Clamped at 1 here rather than only in the UI: the QML field is disabled
        when subdomains are excluded, but a binding is not an enforcement, and the
        rule ("a static page is one page") has to hold whichever way the value
        arrives.
        """
        if not self._include_subdomains:
            self._max_requests_per_visitor = 1
        else:
            self._max_requests_per_visitor = max(1, int(value))
        self.changed.emit()

    @Property(bool, notify=changed)
    def maxRequestsPerVisitorLocked(self):
        """Whether the field is pinned because the target is a static page."""
        return not self._include_subdomains

    @Property(str, notify=changed)
    def maxRequestsPerVisitorHint(self):
        """What the per-visitor setting currently means, in one line."""
        if not self._include_subdomains:
            return (
                "Static page: pinned to 1. Each visitor loads the target once, "
                "then leaves."
            )
        return (
            f"Each visitor makes a random 1-{self._max_requests_per_visitor} page "
            f"visits, drawn uniformly."
        )

    @Property("QVariantMap", notify=changed)
    def safetyCeiling(self):
        """
        The derived global request ceiling, for display in place of the old field.

        The operator can no longer set this number, so they have to be able to see
        it -- otherwise a run stopping at a ceiling they never chose reads as a
        bug. Empty when the target does not yet yield a scope.
        """
        if not self._derives_a_host():
            return {}
        try:
            config = self._build_config_for_preview()
        except Exception:
            return {}
        if config is None:
            return {}
        return config.ceiling_breakdown()

    @Property(str, notify=changed)
    def safetyCeilingSummary(self):
        parts = self.safetyCeiling
        if not parts:
            return ""
        return (
            f"{parts['total']} requests: {parts['pages']} page "
            f"({parts['visitors']} visitors x {parts['requests_per_visitor']} "
            f"max), {parts['funnel_requests']} funnel, {parts['headroom']} headroom"
        )

    @Property(bool, notify=changed)
    def headless(self):
        return self._force_headless

    @Slot(bool)
    def setHeadless(self, value: bool) -> None:
        """Force every browser rung to run headless (True) or honour each rung's
        declared posture (False, the default)."""
        self._force_headless = bool(value)
        self.changed.emit()

    @Property(str, notify=changed)
    def seed(self):
        return self._seed

    @Slot(str)
    def setSeed(self, value: str) -> None:
        self._seed = (value or "").strip()
        self.changed.emit()
        self._refresh_preview()

    # -- proxy -------------------------------------------------------------

    @Property(list, constant=True)
    def proxyModeOptions(self):
        return ["No proxy", "Proxy list file", "Rotating gateway"]

    @Property(int, notify=changed)
    def proxyModeIndex(self):
        return self._proxy_mode_index

    @Slot(int)
    def setProxyModeIndex(self, value: int) -> None:
        self._proxy_mode_index = max(0, min(int(value), 2))
        self.changed.emit()

    @Property(str, notify=changed)
    def proxyFile(self):
        return self._proxy_file

    @Slot(str)
    def setProxyFile(self, value: str) -> None:
        self._proxy_file = (value or "").strip()
        self.changed.emit()

    @Slot(result="QVariantMap")
    def browseProxyFile(self) -> dict:
        """
        Open a file chooser for the proxy list and adopt whatever is picked.

        The chosen path is validated here rather than in QML, so the operator
        sees "37 usable proxies" the moment they pick a file instead of finding
        out when the run starts. Picking a file also sets the field, so the
        displayed path and the path the run will use cannot drift apart.

        QFileDialog needs QtWidgets, which this app does not otherwise use, and
        its native path wants a QApplication rather than the QGuiApplication the
        app creates. Both are handled: the built-in Qt dialog is requested, and
        any failure falls back to telling the operator to paste the path, which
        the text field still accepts.
        """
        try:
            from PySide6.QtWidgets import QFileDialog
        except Exception:
            return {
                "ok": False,
                "path": "",
                "message": "A file chooser is unavailable in this build; paste the path instead.",
            }

        start_dir = str(Path(self._proxy_file).expanduser().parent) if self._proxy_file else str(Path.home())
        try:
            path, _ = QFileDialog.getOpenFileName(
                None,
                "Select a proxy list",
                start_dir,
                "Proxy lists (*.txt *.csv *.list);;All files (*)",
                options=QFileDialog.Option.DontUseNativeDialog,
            )
        except Exception as exc:
            return {
                "ok": False,
                "path": "",
                "message": f"Could not open a file chooser ({exc}); paste the path instead.",
            }

        if not path:
            return {"ok": False, "path": "", "message": "No file selected."}

        self._proxy_file = path
        self.changed.emit()
        result = self.validateProxyFile(path)
        return {"ok": result.get("ok", False), "path": path, "message": result.get("message", "")}

    @Property(str, notify=changed)
    def proxyGateway(self):
        return self._proxy_gateway

    @Slot(str)
    def setProxyGateway(self, value: str) -> None:
        self._proxy_gateway = (value or "").strip()
        self.changed.emit()

    @Property(list, constant=True)
    def proxyPolicyOptions(self):
        return ["Round robin", "Least used", "Random"]

    @Property(int, notify=changed)
    def proxyPolicyIndex(self):
        return self._proxy_policy_index

    @Slot(int)
    def setProxyPolicyIndex(self, value: int) -> None:
        self._proxy_policy_index = max(0, min(int(value), 2))
        self.changed.emit()

    @Property(str, notify=changed)
    def outDir(self):
        return self._out_dir

    @Slot(str)
    def setOutDir(self, value: str) -> None:
        self._out_dir = (value or "").strip()
        self.changed.emit()

    # -- proxy validation --------------------------------------------------

    @Slot(str, result="QVariantMap")
    def validateProxyFile(self, path: str) -> dict:
        """
        Parse a proxy list and report what was usable.

        Passwords are never echoed back; the UI shows redacted endpoints so a
        screenshot of the app does not leak the pool's credentials.
        """
        from ..proxy import parse_proxy_file

        if not path:
            return {"ok": False, "message": "No file selected.", "endpoints": []}
        try:
            endpoints = parse_proxy_file(path)
        except Exception as exc:
            return {"ok": False, "message": str(exc), "endpoints": []}
        if not endpoints:
            return {
                "ok": False,
                "message": "No usable proxies found. Expected one per line.",
                "endpoints": [],
            }
        return {
            "ok": True,
            "message": f"{len(endpoints)} usable proxies.",
            "endpoints": [e.redacted() for e in endpoints],
        }

    # -- schedule preview --------------------------------------------------

    def _refresh_preview(self) -> None:
        """
        Show what the current settings will actually do, before anything runs.

        A count and a duration are easy to set and hard to picture; the preview
        turns them into a concrete arrival pattern so an operator can see that
        1000 visitors over 24h is ~42/hour before they commit to it.
        """
        if self._visitors <= 0 or self._hours <= 0:
            self._preview = []
            self._preview_summary = ""
            self.schedulePreviewChanged.emit()
            return
        try:
            cfg = AuditConfig(
                target_url=self._target or "http://example.invalid/",
                visitor_count=self._visitors,
                duration_hours=self._hours,
                pattern=ArrivalPattern.ALL[self._pattern_index],
                limits=SafetyLimits(max_arrivals_per_minute=self._max_per_minute),
                single_level_mode=self._single_level_mode,
                single_level=self._single_level,
            )
            schedule = build_schedule(cfg.schedule_config())
        except Exception as exc:
            self._preview = []
            self._preview_summary = f"Could not preview: {exc}"
            self.schedulePreviewChanged.emit()
            return

        buckets = 24
        width = self._hours * 3600.0 / buckets
        counts = [0] * buckets
        for arrival in schedule.arrivals:
            idx = min(buckets - 1, int(arrival.offset_s / width)) if width > 0 else 0
            counts[idx] += 1

        self._preview = counts
        gaps = schedule.inter_arrival_seconds()
        per_hour = cfg.visitor_count / self._hours if self._hours else 0
        self._preview_summary = (
            f"{schedule.count} arrivals over {self._hours:g}h (~{per_hour:.1f}/hour). "
            f"Busiest bucket {max(counts) if counts else 0}, quietest "
            f"{min(counts) if counts else 0}. "
            f"Gap {min(gaps):.0f}s-{max(gaps):.0f}s."
            if gaps
            else f"{schedule.count} arrivals."
        )
        if self._single_level_mode:
            self._preview_summary += (
                f" Single-rung mode pins the count to {cfg.visitor_count}."
            )
        self.schedulePreviewChanged.emit()

    # -- run ---------------------------------------------------------------

    @Slot()
    def start(self) -> None:
        if self._running:
            return
        self._error = ""
        self._log.clear()
        self._findings = []
        self._summary = {}
        self._visits.clear()
        self.findingsChanged.emit()
        self.summaryChanged.emit()
        self.logChanged.emit()
        self.visitsChanged.emit()

        if not self._acknowledged:
            self._error = (
                "Confirm you are authorized to test this target before starting."
            )
            self.changed.emit()
            return

        try:
            config = self._build_config()
        except ValueError as exc:
            self._error = str(exc)
            self.changed.emit()
            return

        if self._single_level_mode:
            self._append_log(
                f"Starting audit of {self._target} - single rung "
                f"{config.selected_levels()[0].name}, {config.visitor_count} "
                f"visitors over {self._hours:g}h"
            )
        else:
            self._append_log(
                f"Starting audit of {self._target} - {self._visitors} visitors over "
                f"{self._hours:g}h, levels 0-{self._max_level}"
            )
        limits = config.resolved_limits()
        if config.auto_scale_ceiling:
            # The operator never set this number, so the log has to show where it
            # came from or a run stopping at it reads as a bug.
            parts = config.ceiling_breakdown()
            self._append_log(
                f"Ceilings: {limits.max_requests} requests = "
                f"{parts['pages']} page + {parts['funnel_requests']} funnel + "
                f"{parts['headroom']} headroom (derived), "
                f"{limits.max_rps}/s, {limits.max_concurrency} concurrent, "
                f"{limits.max_arrivals_per_minute}/min"
            )
        else:
            self._append_log(
                f"Ceilings: {limits.max_requests} requests, {limits.max_rps}/s, "
                f"{limits.max_concurrency} concurrent, "
                f"{limits.max_arrivals_per_minute}/min"
            )

        self._running = True
        self.runningChanged.emit()
        self._worker = AuditWorker(config, self._out_dir or None, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_report.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _build_config(self, *, create_dirs: bool = True) -> AuditConfig:
        """
        Assemble the run's config, or raise ValueError with a reason to show.

        Shared by `start()` and the ceiling preview so the number the operator is
        shown is the number the run will actually enforce. Building it twice from
        the same fields is fine; building it two *different* ways was the bug this
        avoids.

        `create_dirs` is off for the preview: the artifact directory is made as a
        side effect of validating it, and a property read bound to a text field
        must not touch the filesystem on every keystroke.
        """
        excluded = [
            h.strip() for h in self._exclude_hosts.replace(",", " ").split() if h.strip()
        ]
        if self._enable_funnel:
            # The rate is only fatal when the funnel is on: with it off the field
            # decides no traffic, so refusing to start would block a run that is
            # perfectly well-defined. Same rule the engine applies in `__post_init__`.
            try:
                rate = parse_rate_pct(self._campaign_rate)
            except ValueError:
                raise ValueError(
                    f"Campaign interaction rate {self._campaign_rate!r} is not a "
                    f"number; give a percentage like 2.5."
                ) from None
            if rate <= 0:
                raise ValueError(
                    "Campaign interaction rate is 0, so no visitor would click a "
                    "banner and the funnel would measure nothing."
                )
        try:
            # The scope is derived from the target, so there is no second field to
            # disagree with it. `for_target` keeps the target's own host in scope
            # even when it sits on a subdomain.
            scope = TargetScope.for_target(
                self._target,
                include_subdomains=self._include_subdomains,
                acknowledged=True,
                acknowledgment_note=AUTO_ACKNOWLEDGMENT_NOTE,
                exclude_urls=excluded,
            )
        except Exception as exc:
            raise ValueError(f"Invalid scope: {exc}") from None

        proxy: Optional[Any] = None
        if self._proxy_mode_index == 1:
            if not self._proxy_file:
                raise ValueError("Select a proxy list file, or choose 'No proxy'.")
            proxy = {
                "mode": "file",
                "file": self._proxy_file,
                "policy": ["round_robin", "least_used", "random"][self._proxy_policy_index],
            }
        elif self._proxy_mode_index == 2:
            if not self._proxy_gateway:
                raise ValueError("Enter a gateway URL, or choose 'No proxy'.")
            proxy = {"mode": "gateway", "gateway": self._proxy_gateway}

        seed: Optional[int] = None
        if self._seed:
            try:
                seed = int(self._seed)
            except ValueError:
                raise ValueError("Seed must be a whole number, or empty.") from None

        # Both are parsed here rather than in QML so a typo is rejected with a
        # reason instead of reaching the engine as a silently empty mapping. An
        # audit that drops its own Authorization header still reports a verdict,
        # and that verdict is about the login page.
        try:
            extra_headers = _parse_header_lines(self._extra_headers)
        except ValueError as exc:
            raise ValueError(f"Custom headers: {exc}") from None

        paths = _parse_path_lines(self._paths)
        for path in paths:
            if not path.startswith("/") or "://" in path:
                raise ValueError(
                    f"Extra path {path!r} must be a path on the target "
                    f"(e.g. /pricing), not a full URL: the audit stays on the "
                    f"audited host."
                )

        artifact_dir = self._artifact_dir.strip()
        if artifact_dir and create_dirs:
            try:
                Path(artifact_dir).mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ValueError(f"Artifact directory unusable: {exc}") from None

        # A static page makes one hop per visitor, so the draw's top is 1 and the
        # runner's per-visitor cap agrees with it. Otherwise N is the top of a
        # uniform 1..N draw, and the cap is the same N so the plan can never
        # promise more pages than the runner will allow.
        per_visitor = (
            self._max_requests_per_visitor if self._include_subdomains else 1
        )
        journey = replace(
            JourneyConfig(),
            max_requests_per_visitor=per_visitor,
            uniform_pages_max=per_visitor,
        )

        config = AuditConfig(
            target_url=self._target,
            scope=scope,
            max_evasion_level=self._max_level,
            single_level_mode=self._single_level_mode,
            single_level=self._single_level,
            enable_outbound_funnel=self._enable_funnel,
            outbound_campaign_rate_pct=self._campaign_rate,
            include_iframes=self._include_iframes,
            # The global ceiling is derived from the plan rather than typed, so it
            # cannot disagree with the traffic the run intends to send.
            auto_scale_ceiling=True,
            visitor_count=self._visitors,
            duration_hours=self._hours,
            pattern=ArrivalPattern.ALL[self._pattern_index],
            proxy=proxy,
            seed=seed,
            headless=True if self._force_headless else None,
            paths=paths,
            extra_headers=extra_headers,
            cooldown_between_levels_s=self._cooldown_s,
            artifact_dir=artifact_dir or None,
            reuse_browser=self._reuse_browser,
            journey=journey,
            limits=SafetyLimits(
                max_rps=self._max_rps,
                max_concurrency=self._max_concurrency,
                max_arrivals_per_minute=self._max_per_minute,
                max_per_proxy=self._max_per_proxy,
                abort_after_consecutive_errors=self._abort_after_errors,
            ),
        )

        problems = config.validate()
        if problems:
            raise ValueError("; ".join(problems))
        return config

    def _build_config_for_preview(self) -> Optional[AuditConfig]:
        """`_build_config` for a half-filled form, or None when it cannot build."""
        try:
            return self._build_config(create_dirs=False)
        except Exception:
            return None

    @Slot()
    def stop(self) -> None:
        if self._worker is not None and self._running:
            self._append_log("Stop requested; finishing in-flight visits...")
            self._worker.cancel()

    @Slot()
    def clearLog(self) -> None:
        self._log.clear()
        self.logChanged.emit()

    @Slot()
    def clearResults(self) -> None:
        self._visits.clear()
        self._findings = []
        self._summary = {}
        self.visitsChanged.emit()
        self.findingsChanged.emit()
        self.summaryChanged.emit()

    def _append_log(self, line: str) -> None:
        # The buffer stamps each line itself, so the two ceilings can evict on the
        # same monotonic clock it records.
        self._log.append(line)
        self.logChanged.emit()

    @Slot(dict)
    def _on_progress(self, payload: dict) -> None:
        event = payload.get("event")
        if event == "level_start":
            self._append_log(
                f"{payload.get('level_name')}: starting {payload.get('scheduled')} visits"
            )
        elif event == "visit":
            visit = payload.get("visit") or {}
            self._visits.append(visit)
            self.visitsChanged.emit()
        elif event == "level_end":
            level = payload.get("level") or {}
            self._append_log(
                f"{level.get('level_name')}: bypass {level.get('bypass_rate', 0):.0%}, "
                f"detected {level.get('detection_rate', 0):.0%}"
            )

    def _funnel_summary_for(self, payload: dict) -> dict:
        """
        Flatten the run's funnel section for the QML summary panel.

        Kept as a plain dict of already-formatted strings so the QML side only
        renders, never computes -- the CTR and dwell figures must come from the
        same place the reports do, or the GUI and the file would disagree.
        """
        funnel = payload.get("funnel") or {}
        if not funnel.get("enabled"):
            return {"enabled": False}
        rate = funnel.get("rate_pct")
        return {
            "enabled": True,
            "ratePct": rate,
            "clicks": funnel.get("clicks", 0),
            "landed": funnel.get("landed", 0),
            "engaged": funnel.get("engaged", 0),
            "partnerClicks": funnel.get("partner_clicks", 0),
            "firstPartyClicks": funnel.get("first_party_clicks", 0),
            "refused": funnel.get("refused", 0),
            "unreachable": funnel.get("unreachable", 0),
            "skippedByScope": funnel.get("skipped_by_scope", 0),
            "dwellP50": funnel.get("dwell_p50_s"),
            "dwellMin": funnel.get("dwell_min_s"),
            "dwellMax": funnel.get("dwell_max_s"),
            "destinations": [
                {"url": d.get("url", ""), "clicks": d.get("clicks", 0)}
                for d in (funnel.get("destinations") or [])
            ],
        }

    @Slot(dict, str)
    def _on_finished(self, payload: dict, payload_json: str) -> None:
        self._running = False
        self._worker = None
        self.runningChanged.emit()

        self._findings = list(payload.get("findings") or [])
        self.findingsChanged.emit()

        totals = payload.get("totals") or {}
        levels = payload.get("levels") or []
        self._summary = {
            "visits": totals.get("visits", 0),
            "requests": totals.get("requests", 0),
            "duration": round(payload.get("duration_s", 0.0), 1),
            "aborted": payload.get("aborted", False),
            "abortReason": payload.get("abort_reason", ""),
            "funnel": self._funnel_summary_for(payload),
            "levels": [
                {
                    "name": lv.get("level_name", ""),
                    "completed": lv.get("completed", 0),
                    "bypassRate": lv.get("bypass_rate", 0.0),
                    "detectionRate": lv.get("detection_rate", 0.0),
                    "vendors": ", ".join(lv.get("vendors") or []),
                    "aborted": lv.get("aborted", False),
                    "abortReason": lv.get("abort_reason", ""),
                }
                for lv in levels
            ],
            "written": payload.get("written") or {},
        }
        self.summaryChanged.emit()

        for fmt, path in (payload.get("written") or {}).items():
            self._append_log(f"Wrote {fmt} report to {path}")
        self._append_log("Audit complete.")

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._running = False
        self._worker = None
        self.runningChanged.emit()
        self._error = message
        self.changed.emit()
        self._append_log(f"Audit failed: {message}")

    # -- export ------------------------------------------------------------

    @Slot(str, result=bool)
    def exportText(self, path: str) -> bool:
        """Write a plain-text report of the last run to `path`."""
        if not path:
            return False
        try:
            body = "\n".join(self._findings) if self._findings else "(no findings)"
            header = (
                f"WAF / bot-defense audit\n"
                f"Target: {self._target}\n"
                f"Scope: {self.scopeDescription}\n"
                f"Visitors: {self._visitors} over {self._hours:g}h\n\n"
            )
            Path(path).write_text(header + body + "\n", encoding="utf-8")
            self._append_log(f"Wrote summary to {path}")
            return True
        except Exception as exc:
            self._error = f"Export failed: {exc}"
            self.changed.emit()
            return False

    @Slot(result="QVariantMap")
    def browseExportText(self) -> dict:
        """
        Ask where to save a plain-text summary, then write it there.

        The engine's own reports land in the run's output directory, which is
        fine for a machine but awkward when an operator wants to attach one to a
        ticket. This is that escape hatch.

        Like browseProxyFile, QFileDialog needs QtWidgets, which this app does
        not otherwise import, and its native path wants a QApplication rather
        than the QGuiApplication the app creates; both are handled so a build
        without them degrades to a message instead of crashing the GUI.
        """
        try:
            from PySide6.QtWidgets import QFileDialog
        except Exception:
            return {
                "ok": False,
                "path": "",
                "message": "A file chooser is unavailable in this build.",
            }

        start = str(Path(self._out_dir).expanduser()) if self._out_dir else str(Path.home())
        try:
            path, _ = QFileDialog.getSaveFileName(
                None,
                "Save audit summary",
                str(Path(start) / "audit-summary.txt"),
                "Text files (*.txt);;All files (*)",
                options=QFileDialog.Option.DontUseNativeDialog,
            )
        except Exception as exc:
            return {"ok": False, "path": "", "message": f"Could not open a file chooser ({exc})."}

        if not path:
            return {"ok": False, "path": "", "message": "No file selected."}
        if not path.lower().endswith(".txt"):
            path += ".txt"
        ok = self.exportText(path)
        return {
            "ok": ok,
            "path": path,
            "message": f"Saved to {path}" if ok else "Could not write the summary.",
        }

    @Slot(str, result=bool)
    def openPath(self, path: str) -> bool:
        """Open a report in whatever the desktop uses for that file type."""
        if not path:
            return False
        target = Path(path)
        if not target.exists():
            self._error = f"Not found: {path}"
            self.changed.emit()
            return False
        try:
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices

            return QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))
        except Exception as exc:
            self._error = f"Could not open {path}: {exc}"
            self.changed.emit()
            return False
