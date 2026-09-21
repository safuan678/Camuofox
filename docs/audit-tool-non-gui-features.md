# WAF audit tool — non-GUI feature reference

Scope: everything the audit tool does that is not a Qt/QML surface. The GUI
(`pythonlib/camoufox/gui/`) is deliberately out of scope; this documents the
engine, the CLI, the hosted console, and the packaging/CI that carry them.

Two readings, one tool. The engine answers **"which control of mine is actually
holding?"** and the console answers the same question for a site owner who has
nothing installed. Both are *attribution* tools: they run an ordered ladder of
client postures and report which defense stopped which rung. Neither is a bypass
bot, and neither attempts a control the operator did not ask it to test.

---

## 1. The engine — `pythonlib/camoufox/audit/` (6,108 lines)

| Module | Lines | Role |
|---|---|---|
| `runner.py` | 2,039 | Async execution, ceilings, progress events, cancellation, the browser and HTTP rungs, banner discovery, cursor motion |
| `config.py` | 723 | `AuditConfig`, `SafetyLimits`, `VisitResult`, `LevelResult`, `AuditReport`, `CampaignEvent`, `BannerCandidate` |
| `journey.py` | 644 | `plan_visit()` — human-like navigation; `discover_banner_candidates()`, `plan_outbound_visit()` |
| `report.py` | 603 | Findings, text/HTML/JSON/CSV export |
| `behavior.py` | 496 | Humanized dwell, scroll, glance and campaign-landing distributions |
| `evasion.py` | 469 | `EVASION_LEVELS` — the ladder definition, each rung declaring cumulative `capabilities` and the one `adds` |
| `detection.py` | 399 | `classify_response()` → `Verdict`, with vendor attribution and evidence |
| `schedule.py` | 348 | `build_schedule()` — non-uniform, jittered arrivals across a window |
| `scope.py` | 268 | `TargetScope` — the authorization gate |
| `__init__.py` | 119 | Public surface |

### 1.1 Scope gate — the authorization boundary

`TargetScope` is the only thing that authorizes a request, and `check()` **raises**
rather than returning a flag. Because it raises, there is no code path that
reaches a socket without passing it — a truthy-return API would let a caller
forget the branch and still ship. Both the GUI and the CLI gate on it.

The outbound half is deny-by-exception, because the funnel measures the ad
traffic a page actually serves:

- Every banner a page (or an iframe inside it) serves is **in scope by default**.
  An audit that skipped a site's real campaign traffic would report "no banner"
  for a page that was displaying one, which measures nothing.
- The exception is the operator's exclusion list
  (`TargetScope.excluded_outbound_hosts`, `exclude_urls=` to `from_urls`, the
  "Exclude campaign hosts" GUI field). A host named there is skipped; naming
  nothing excludes nothing. A bare name also covers its subdomains, so excluding
  `ads.example.net` also skips `track.ads.example.net`.
- `authorize_outbound()` still rejects non-`http(s)` schemes, an empty host, and
  IP-literal hosts (the cloud metadata endpoint is a literal, and so is any
  internal service a campaign link could be tricked into naming).
- An excluded banner is **seen and reported as a refusal**, never followed.

The gate has two distinct questions, and keeping them separate is what makes the
above safe:

- `authorize_outbound()` is the *funnel* question, asked once when the walk
  decides to click a banner.
- `permits_navigation()` is the *navigation* question, asked by the browser guard
  and the redirect handler. It admits the target plus hosts the funnel already
  reached. It deliberately does **not** call `authorize_outbound` — doing so
  would permit every URL, because the funnel's default is now "follow".

The egress containment added in PR #9 extends this to every hop: the guard is
enforced on subresource requests and on redirects, not only on the top-level
navigation. `ScopeViolation` is distinguished from a transport `ERROR`, and
`Verdict.OUT_OF_SCOPE` ("refused by scope") reports it as its own outcome rather
than folding it into `BLOCKED` (which would credit the target's defense with work
the gate did) or `ALLOWED` (which would call an unfollowed link a bypass).

### 1.2 Vendor attribution

`classify_response()` attributes a response to a named WAF/anti-bot vendor from
three independent signal families — response headers, body markers, and cookies.
Vendors covered: **Cloudflare, Akamai, AWS WAF, Imperva, F5 BIG-IP ASM, Sucuri,
Fastly, DataDome, HUMAN/PerimeterX, Kasada, Vercel, Google reCAPTCHA**. Each
match carries the evidence that produced it, so a finding is auditable rather
than a score.

The verdicts are deliberately six, not two:

| Verdict | Meaning |
|---|---|
| `ALLOWED` | Served normally |
| `CHALLENGED` | A defense interstitial on a 2xx — the marker is there, the status is not a refusal |
| `RATE_LIMITED` | Throttled |
| `BLOCKED` | A refusal |
| `ERROR` | Transport failed; not a finding about the target |
| `OUT_OF_SCOPE` | The gate refused it; not a finding about the target |

`blocks` and `challenges` are kept separate because a Cloudflare "Attention
Required!" page is a *block* at 403 and a *challenge* at 200; conflating them
tells the operator to change the wrong control. The status code decides, and the
body only says a defense page was served. A refusal is never `ALLOWED` — a
defense marker on a 2xx is reported as challenged, because reporting it as
allowed would inflate the bypass rate.

### 1.3 The evasion ladder

Each rung is a client posture, and each declares exactly one capability over the
rung below it. Those declarations are **not labels** — the runner gates on them:
`requires_rotation` decides whether a proxy is acquired, `is_behavioral` decides
whether the journey runs at full fidelity, `is_persistent` decides whether the
profile notice fires.

| Rung | Posture | `adds` |
|---|---|---|
| L0 | Naive HTTP | — (baseline; dependency-free) |
| L1 | Headless browser | `browser` |
| L2 | Consistent headers | `headers` |
| L3 | Fingerprint masking | `fingerprint` |
| L4 | Proxy rotation | `ip_rotation` |
| L5 | Human behavior | `behavior` |
| L6 | Persistent identity | `persistence` |

`ladder_problems()` fails if a rung silently repeats the rung below it or turns
on two axes at once. This is a real regression guard: the original bug made
L3/L4/L5 byte-identical and gave every rung a referer and scroll behavior, so
every "finding" above L3 was unattributable.

Two further guards worth naming, because both encode a bug the tool exists to
detect:

- **A rung declares only headers the client can actually change.** Firefox
  generates `Sec-Fetch-*`, `Upgrade-Insecure-Requests`, `Accept-Encoding` and
  `Referer` itself; a rung declaring one is a no-op whose `adds` claim reads as a
  control it is not. They are listed in `UNCONTROLLABLE_HEADERS`.
- **A header pinned on a Firefox engine must be a Firefox value.** Camoufox sends
  a Firefox UA, so Chromium's `Accept` (with `image/avif,image/webp,image/apng`)
  or Chromium's `Cache-Control: max-age=0` is a cross-engine mismatch the audit
  would be *manufacturing* rather than measuring.

### 1.4 Scheduling and behavior

`build_schedule()` spreads arrivals non-uniformly across the window with jittered
inter-arrival times. That non-uniformity is the point and is protected by an
invariant: replacing it with a fixed interval would make the traffic itself the
signal.

`behavior.py` models dwell, scroll bursts and glances as distributions (e.g.
landing-page dwell log-normally between a floor and ceiling), and `journey.py`
plans referers (search engines, social, direct) and navigation so a visit has a
plausible arrival route. The report states the arrival route, which is what makes
a "blocked at L2" finding interpretable.

### 1.5 Ceilings

`SafetyLimits` covers `max_requests`, `max_rps`, `max_concurrency`,
`max_arrivals_per_minute`, `max_per_proxy`, and a consecutive-error rule.
Ceilings **abort the run and record why** rather than warning — a ceiling that
merely advises is not a ceiling.

### 1.6 Report surface

Findings, per-level tables, a funnel section, and export to **text, HTML, JSON and
CSV**. `audit report` re-renders a saved JSON report in another format, so an
exported run can be re-read without re-running it. Proxy passwords are redacted
and `extra_headers` is never echoed into the report.

### 1.7 The outbound funnel (promotional-banner click-through)

`enabled` by `AuditConfig.enable_outbound_funnel` (default **off**). Layered on a
behavioral rung, the runner:

1. reads the promotional banners the page actually served — `include_iframes`
   (default **on**) widens discovery to child frames, because campaigns are
   routinely served from an ad iframe and a main-frame-only scan reports "no
   banner found" on a page that is showing one;
2. rolls a per-visitor CTR (`outbound_campaign_rate_pct`, default 2.5, parsed
   once and clamped to `[0, 30]`);
3. follows the chosen banner only if it is authorized, and measures landing-page
   engagement.

It is **observation only** — it records what the audited site served and where it
pointed, and never drives a conversion.

Design points that are load-bearing:

- **The funnel only runs on a behavior rung** (L5+). A click-through is an
  interaction; emitting one on a rung that does not claim behavior would make that
  rung's verdict the product of an interaction it never claimed.
- **Iframe banners are read through the frame, not through the page.**
  Playwright's `page.locator()` is `mainFrame().locator()`, so a child frame's
  anchors are invisible to any page-level query. Widening frames must never widen
  authorization: the same `TargetScope` gate applies to a framed anchor.
- **A candidate's frame ordinal is 0 for the main document and counts child frames
  from 1.** The click resolves the ordinal back through `_frame_for()`, which
  asserts `page.frames[0]` is `main_frame` rather than assuming it; an
  enumerate-from-zero would aim the cursor at the wrong geometry. A frame removed
  between discovery and click aborts the hop with a recorded reason rather than
  falling back to the main document.
- **`engaged` excludes a landing that refused to serve.** A 403 landing is
  reachable but not engaged, so a blocked landing is not credited as a visit.
- **Ad-network and RTB hosts are filtered before a destination is considered**
  (`_AD_SYNDICATION_MARKERS` — DoubleClick, Taboola, Outbrain, Criteo,
  PubMatic, OpenX, adnxs, and ~20 more). Clicking an exchange measures the
  exchange's redirect chain, not the site's funnel, and would drag the audit onto
  hosts nobody authorized.

### 1.8 GeoIP and the exit IP

`geoip=True` is resolved at *launch*, but Playwright scopes `proxy` to the
*context*. Launching with the flag and no session therefore bakes this host's
timezone, locale and WebRTC address into a visitor whose traffic exits a pool.
The invariant is that geography must come from the **exit IP, never the host**: a
visitor's `proxy_session` is passed into the launch so `launch_options` resolves
the exit through the proxy, and a verified `exit_ip` is passed as `geoip` to skip
a second lookup. A rung that both rotates IPs and sets `geoip` cannot share one
browser — `_launch_needs_own_proxy()` forces a launch per visitor.

### 1.9 Platform fallbacks, declared rather than hidden

- **A headed rung must not fail for want of a display.** `_has_display()` decides;
  a host without an X server gets Camoufox's `headless="virtual"` mode with a
  notice. Plain `headless: True` would silently stop testing the headed posture,
  which is what L2 exists to measure.
- **A rung must not fail for want of an optional extra.** `geoip2` is optional, so
  `_has_geoip()` gates the `geoip` flag and clears it with a notice. Leaving the
  flag set makes every L3+ rung fail to launch on a plain install and report an
  error for a posture it never tested.
- **`AuditConfig.headless` is an override, not a default.** `None` means "run the
  posture each rung declares"; `True`/`False` forces every browser rung and the
  runner emits a notice when that contradicts a rung.

---

## 2. The CLI — `camoufox` (Click, `pythonlib/camoufox/__main__.py`)

Top-level commands: `fetch`, `set`, `sync`, `list`, `remove`, `test`, `server`,
`gui`, `version`, `active`, `path`, plus two groups.

### Audit group — `camoufox audit`

| Command | Purpose |
|---|---|
| `audit levels` | Print the ladder: each rung, what it isolates, what it adds |
| `audit run` | Run an audit and emit reports |
| `audit report` | Re-render a saved JSON report in another format |

`audit run` is the full surface: `--target`, repeatable `--authorized-host`,
`--allow-subdomains`, `--i-am-authorized` (**required**), `--visitors`, `--hours`,
arrival distribution, `--max-level`, repeatable `--level`, single-rung mode,
`--proxy-file` / `--proxy-gateway` / `--proxy-policy`, `--max-requests`,
`--max-rps`, `--max-concurrency`, `--max-per-minute`, `--max-per-proxy`,
headless/headful overrides, `--seed`, `--out`, `--quiet`.

Two properties worth calling out:

- **`--i-am-authorized` is required, not a flag you may pass.** Authorization is
  an explicit act.
- **`--seed` makes a run reproducible** for scheduling and behavior, so a
  surprising result can be re-run rather than argued about. Note it does *not*
  seed the target's own behavior — that is outside the tool's control.

### Proxy group — `camoufox proxy`

`check`, `status`, `reset`. Rotation has two deliberately different points: one
exit IP per **browser** (`Camoufox(proxy_rotator=...)`) and one per **context**
(`NewContext(proxy_rotator=...)`, the "new IP per visit" case). Modes are
`gateway` (one rotating endpoint, `{session}` substituted per session) and `file`
(a text list, one proxy per session). Nothing identifying is persisted beyond
`host:port` plus a short username hash — **passwords must never reach the state
file or the logs** — and there is no silent direct fallback: an unusable pool
raises rather than leaking the host IP under a foreign fingerprint.

### Python API (non-GUI entry points)

- `sync_api.py` — `Camoufox` context manager, `NewBrowser()`, `NewContext()`
- `async_api.py` — async equivalents
- `utils.py` — `launch_options()` (the option surface)
- `fingerprints.py` — `generate_context_fingerprint()` (BrowserForge + presets)
- `server.py` — `launch_server()`, a websocket Playwright server
- `pkgman.py` / `multiversion.py` — release discovery, install, channel pinning
- `geolocation.py`, `locales.py`, `proxy.py`, `addons.py`, `display.py`,
  `virtdisplay.py`

`pkgman.py`'s release resolution is worth one note: `repos.yml` lists this fork
**first** and upstream behind it, and that order is load-bearing — the patch
guards assert on behaviour that lives in `additions/juggler/`, which only reaches
a browser built from this tree. `list_available_versions()` treats "no version
**this platform can install**" as a reason to keep walking, so a 404, an empty
list, and a release built only for another platform are all "not an answer"
rather than "the answer is nothing" — otherwise the fallback behind the fork
would be unreachable.

---

## 3. The hosted console — `apps/audit-console/`

A separate, self-contained app that **does not import camoufox** — it vendors the
engine, so it cannot drift from the ladder it reports on. It answers the same
question for a site owner with nothing installed.

| Path | Role |
|---|---|
| `app.py` | Entry point; `--self-test` is what CI uses |
| `sync_engine.py` | Regenerates `console/_engine/` from `pythonlib/camoufox/audit/` |
| `build.py` | Builds the single-file `.pyz` |
| `console/server.py` | Stdlib `http.server`; explicit route table |
| `console/runs.py` | `AuditService` — allow-list gate, ceilings, run manager |
| `console/demo_waf.py` | The bundled Cloudflare-ish demo it audits by default |
| `console/proxies.py` | `ProxyPoolStore` — redacted pool state |
| `console/ui/` | The page and its script |

**It runs on a bare Python 3.10+ with nothing installed.** That is what makes it
hostable, and it is the property the single-file build is bought for: CI asserts
the `.pyz` carries no third-party packages. The routes are few enough that an
explicit table beats a framework's decorator registry.

### 3.1 Security posture

- **The allow-list is the only thing standing between this and an open request
  forwarder.** It is checked before any request leaves, and it *raises* rather
  than returning a flag, so there is no path to a socket that skips it. The demo
  is the default target; `--target` additionally needs `--i-am-authorized`.
  Crucially, **nothing adds a host** and the allow-list is not configurable at
  runtime — a runtime-configurable allow-list is the same as no allow-list.
- Request bodies capped at 64 KiB; visitor count and ladder depth capped
  regardless of what the request asks for; concurrency bounded.
- The upstream engine's ceilings are re-declared as `CONSOLE_LIMITS` and apply
  **regardless of the request**, because the console is shared.
- UI assets are read through `read_ui_asset()`, which accepts only a bare
  filename — that is what keeps traversal out in both the directory and the
  zipapp form.
- Responses carry `X-Content-Type-Options: nosniff` and `Referrer-Policy:
  no-referrer`.

### 3.2 Degrading honestly

**When no browser is installed the ladder caps at L0, with a notice.** This is the
*normal* state for the hosted build. Accepting a deeper `max_level` and then
reporting a launch failure for every rung would attribute a finding to a posture
that was never tested.

The same applies to proxy rungs: L4+ are defined by a rotating exit IP, so with no
pool they are **pruned with a notice** rather than run directly and reported as
"IP rotation". Asking for a single rung the host cannot reach is **refused**
rather than pruned to nothing, because a session with no levels would look like a
clean result.

### 3.3 Single-rung mode

Runs just the selected rung, with the visitor count pinned to 100, to repeat one
measurement and compare it over time. A single-rung run says in its own findings
that it **cannot attribute a defense** — attribution only exists relative to the
rungs below.

### 3.4 Cross-run concurrency (added in this change)

`CONSOLE_LIMITS.max_concurrency` bounds the visitors *within* one audit. Nothing
bounded the number of *audits* — each request got its own thread and its own six
visitors, so the console's real concurrency against the target was `N x 6`
rather than 6, and a shared console could be used as an unbounded request
amplifier. `AuditService` now holds one `BoundedSemaphore`
(`CONSOLE_MAX_RUNNING_AUDITS`, default 3) acquired in `start_audit` and released
by the session when it reaches a terminal state — including on a crash, or the
console would wedge shut. A request that finds no slot within
`CONSOLE_ADMISSION_TIMEOUT_S` gets a **503 with `Retry-After`**, distinct from the
403 that means "you may not audit this host": the request was fine, the service is
full, and retrying is the right answer.

---

## 4. Packaging and release machinery (non-GUI)

- **Desktop GUI packaging** (`pythonlib/packaging/`) — PyInstaller spec plus
  `_qt_trim.py`. The trim filters the finished TOC against a denylist, because
  `excludes` cannot remove a Qt library: PyInstaller's own `hook-PySide6.*`
  inserts libraries into the analysis TOC and the binary dependency walk pulls
  them back through `DT_NEEDED`. Measured on this fork: **907 MB → 517 MB
  (−43%)**, self-check identical.
- **The console artifact** — `build.py` produces one `.pyz` carrying console,
  engine and UI; CI builds it, asserts no third-party packages, and runs
  `--self-test` against it.
- **Release pipeline** — a `v<version>-<build>` tag drives `build.yml`; the
  workflow checks the tag, asset names, the presence of `lin.x86_64`, and that
  the release is visible **without a token** (a draft is invisible to the
  unauthenticated releases API the fetch path sometimes uses).

## 5. Test and CI surface

**813 tests** run without a browser: `pythonlib/tests`, `apps/audit-console/tests`,
`ci/tests`. The audit suite runs against a real `ThreadingHTTPServer` that behaves
like a small WAF — HTTP, classification, scheduling, ceilings and reporting are
all exercised for real, with **no mocks and no real internet**, because most of
the tests exist to prove a refusal happens *before* a request leaves and a mocked
transport would not prove that.

`ci/` is a tiered pipeline (static → unit → browser → smoke → full → gate) with a
single required check, `All tests passed`, so the required-check list does not
need editing every time a suite is added or resharded. Two design choices worth
knowing:

- **Anything that is not `success` fails the gate, including `skipped`.** A suite
  that did not run has not passed, and quietly skipping one is the cheapest route
  to a green tick. A required suite that produced no result file is a **failure**,
  never a skip.
- **The browser suites run isolated first**, then fall back to the main world only
  for what fails, counting every fallback. Running main-world-only made upstream
  tests pass while measuring a mode nobody ships.

---

## 6. Invariants worth not breaking

Collected, because each one encodes a bug that actually happened:

1. No traffic without an acknowledged scope. `TargetScope.check()` raises; do not
   add a path that skips it.
2. A URL found in the DOM is not an authorized host. Discovery is dynamic,
   authorization is not.
3. `blocks` and `challenges` are different findings. The status code decides.
4. A refusal is never `ALLOWED`.
5. Ceilings abort; they do not advise.
6. Scheduling stays non-uniform.
7. A headed rung must not fail for want of a display, and a rung must not fail
   for want of an optional extra.
8. A rung declares only headers the client can change, and only values its own
   engine would send.
9. Geography comes from the exit IP, never from the host.
10. Each rung adds exactly one capability, and the code gates on that declaration.
11. Secrets stay out of reports and logs.
12. The vendor engine is generated, never edited; CI fails on drift.
13. The console allow-list is not configurable at runtime.