# Production-readiness gap report

What stands between this fork and something you would put in front of paying
users or a hostile internet. Ordered by how much damage the gap can do, not by
how hard it is to close.

Method: full read of the engine, the CLI, the console, `ci/`, packaging, and the
GitHub-side configuration; the non-browser suites were run (809 passed, 4 failed
only for a missing `Xvfb` on this host). Every finding below was verified against
the named file, not inferred.

---

## Summary

| # | Finding | Severity | Effort |
|---|---|---|---|
| G1 | No release has ever been published; the fork's fetch path cannot install | **Blocker** | S |
| G2 | Console has no authentication, rate limit, or CSRF protection | **High** | M |
| G3 | `LICENSE` is MPL-2.0 but `pythonlib/pyproject.toml` declares MIT | **High** | S |
| G4 | No `SECURITY.md` and no private vulnerability-reporting route | **High** | S |
| G5 | Branch protection is documented but **not applied** | **High** | S |
| G6 | Console session store is in-process and unbounded in time | Medium | M |
| G7 | No dependency pinning or automated vulnerability scanning | Medium | S |
| G8 | No `CHANGELOG.md` across a rapidly moving fork | Medium | S |
| G9 | Unauthenticated `/api/health` is fine; the rest needs a readiness contract | Low | S |
| G10 | 4 tests require `Xvfb`, which CI installs but a dev box may not | Low | S |

---

## G1 — No release has ever been published (Blocker)

**Evidence.** `GET /repos/mostakimnasim3/camoufox/releases` returns an empty list.
`pythonlib/camoufox/repos.yml` lists `mostakimnasim3/camoufox` **first** for the
`Official` channel, ahead of `daijro/camoufox`. `pythonlib/camoufox/pkgman.py`
walks that list in order.

**Why it is a blocker, not a nit.** The fork's browser patches — the Juggler
input-dispatch and fingerprint work the patch guards assert on — only exist in a
browser built from this tree. The fork is first in `repos.yml` *precisely so*
that `camoufox fetch` installs that browser. With zero releases, the first entry
answers nothing and every fetch silently falls through to **upstream's** build.
The result is the exact inversion `ci/README.md` warns about: a fetch that
installs a browser which does not contain the changes under test, while every
guard reports against it looking healthy.

Upstream happens to be at the same generation (`v152.0.4-beta.30` vs this tree's
`beta.32`), so the failure is quiet today. The moment `upstream.sh` moves to a
new generation and a fork build is not published, the fetch path has nothing
correct to install at all.

**Close it.** Push a `v152.0.4-beta.32` tag and let `build.yml` publish. The
workflow already validates the tag shape, asset names, the presence of
`lin.x86_64`, and that the release is visible **without a token**. Add a
post-release smoke test that runs `camoufox fetch` against a clean install and
asserts the installed artifact came from the fork (an asset digest or a
build-stamp check), so a silent upstream fallback becomes a red build rather
than a note nobody reads.

---

## G2 — Console has no authentication, rate limiting, or CSRF protection (High)

**Evidence.** `apps/audit-console/console/server.py` binds `0.0.0.0` by default
(`app.py:49`) and its route table has no auth check on any handler. There is no
`Authorization` parsing, no `429`, and no `Origin`/`Referer` validation anywhere
in the file. Body size is capped (64 KiB) and the allow-list is enforced, but
neither is authentication.

**Why it matters.** The allow-list does real work — it stops the console being
pointed at a third party — but on a **public** deployment it does not stop:

- **Exhaustion.** `CONSOLE_MAX_RUNNING_AUDITS` (this change) bounds concurrency,
  which is the important half, but an unauthenticated caller can still hold all
  three slots continuously and deny the service to everyone else. The 503 is
  honest, but it is a denial of service, not a defense.
- **Stored-data exposure.** Every finished report is readable through
  `/api/audits/<id>` with no credential. If an operator runs a real audit of a
  staging host, the findings — and the target's identity — are readable by anyone
  who can guess or observe a 12-hex-character id.
- **CSRF.** With no `Origin` check, a page on any origin can POST
  `/api/audits` or `/api/proxy` from a visitor's browser. The scope gate limits
  what that achieves, but it is still an unauthorized state change.

**Close it.** For a hosted deployment: a shared token or basic auth in front of
everything except `/` and `/api/health`; a per-IP rate limit on `/api/audits`;
and an `Origin` allow-list on state-changing routes. For the single-file
"host on a laptop" story, keep it unauthenticated but **bind `127.0.0.1` by
default** and make `0.0.0.0` an explicit opt-in — a secure default is cheaper
than a documented caveat. The README currently frames exposure as "safe to
expose, but narrow"; the narrower reading is that it is safe to expose *to
people you would give a terminal to*.

---

## G3 — License mismatch: MPL-2.0 repo, MIT-declared package (High)

**Evidence.** `LICENSE` is "Mozilla Public License Version 2.0"; GitHub reports
`license: MPL-2.0`. `pythonlib/pyproject.toml` declares `license = "MIT"` and
`authors = ["daijro <daijro.dev@gmail.com>"]`, with `repository` and `homepage`
still pointing at `daijro/camoufox`.

**Why it matters.** A mismatch between the repository license and the advertised
package license is a distribution-rights ambiguity, and it is the kind that
surfaces at the worst possible moment — a company evaluating the package, a
package-index review, or a redistribution. Separately, the metadata still
attributes the package to upstream and advertises an upstream repository, so
the fork is invisible where it matters most: `pip show` and PyPI.

**Close it.** Decide the intent — the browser is MPL-2.0 and `pythonlib/` is a
wrapper, so MIT *may* be deliberate for the wrapper alone, but that must be
stated rather than accidental. Then correct `authors`, `repository`, and
`homepage` to name the fork, and add a per-directory license note so
`additions/` + `patches/` (MPL-2.0, with upstream source obligations) and
`pythonlib/` (whatever is chosen) are unambiguous. `AGENTS.md` already says
"keep the license header/source obligations intact when redistributing modified
files" — this is the same obligation, applied to metadata.

---

## G4 — No security policy or private reporting route (High)

**Evidence.** No `SECURITY.md`; no private vulnerability reporting configured.

**Why it matters.** This tool performs authorized security testing and handles
proxy credentials. Either property is enough to attract a report you would want
private; both together mean the default "open a public issue" is the wrong
channel. A report that arrives as a public issue is disclosed the moment it
lands, and deleting it afterward does not take that back. The `AGENTS.md`
invariant "secrets stay out of reports and logs" shows the codebase takes this
seriously — the repository-level process should match it.

**Close it.** Add `SECURITY.md` naming a private channel and a supported-version
policy, and enable GitHub private vulnerability reporting so the channel
actually exists. State explicitly which artifacts are in scope (the engine, the
console, the packaging) and which are not (`camoufox-<version>/`, generated).

---

## G5 — Branch protection is written down but not applied (High)

**Evidence.** `ci/branch-protection.json` defines the policy and `ci/README.md`
explains it well. `GET /repos/mostakimnasim3/camoufox/branches/main/protection`
returns **404 "Branch not protected"**. The repository is **public**.

**Why it matters.** `main` is currently writable without review or a passing
check. The single required check (`All tests passed`) is the mechanism that makes
the whole tiered pipeline meaningful — without it the pipeline is a report, not a
gate. The design is good; the intent simply has not been applied. On a public
repository, unprotected `main` also means a compromised token can rewrite the
tree and the release path.

**Close it.**

```bash
gh api -X PUT repos/mostakimnasim3/camoufox/branches/main/protection \
  --input ci/branch-protection.json
```

This needs admin on the repository. Note that `enforce_admins: false` is
deliberate and good (a solo maintainer must be able to merge when CI itself is
broken), and `strict: false` is likewise justified by the 70-minute cold build.
Verify the "All tests passed" context name matches the job that actually
reports — a required check naming a job that never runs blocks every merge, and
the failure mode looks like "CI is green but I cannot merge".

---

## G6 — Console session store is in-process and unbounded in time (Medium)

**Evidence.** `AuditService._sessions` is a plain `dict` guarded by a lock, capped
at 20 entries by `_cap`, evicting by `started_at`. It lives only in memory.

**Why it matters.** Three consequences, none fatal for a demo, all real for a
service:

- **Restart loses every report.** Upgrading or crashing the console discards
  finished audits that a user is still looking at.
- **Multi-worker deployments break.** Two workers behind a load balancer have
  disjoint session stores, so a poll for an id created on the other worker 404s.
  The README does not say the console is single-process; that constraint is
  implicit.
- **Eviction is by insertion order, not by need.** A 21st audit evicts the
  oldest session *even if it is still running*, so its results vanish mid-run.

**Close it.** Either state the single-process constraint in the README and refuse
to start under a multi-worker server, or move finished reports to a small on-disk
store (the export path already serialises them) and evict only terminal sessions.
The cheapest real fix is to exclude running sessions from eviction and document
the single-process requirement.

---

## G7 — No dependency pinning or vulnerability scanning (Medium)

**Evidence.** `pythonlib/pyproject.toml` pins only `browserforge = "^1.2.4"` and
`playwright = "<1.63"`; everything else is `"*"`. No `dependabot.yml`, no
`renovate.json`, no lockfile, no `pip-audit`/`safety` step in `ci/`.

**Why it matters.** `"*"` in a security tool means a transitive CVE can appear
in a production install without a commit. The `playwright` ceiling is
excellent — the comment explains that `camoufox.server` imports the private
`playwright._impl._driver` API — and it shows the maintainers already think this
way; the gap is that the same discipline is not applied to the rest, and that
nothing *detects* a bad version after the fact.

**Close it.** Add a `dependabot.yml` for the `poetry`, `github-actions`, and
`pip` ecosystems, and a scheduled `pip-audit` job that reports rather than blocks
(so a CVE in a transitive dependency does not freeze all development). The
`playwright` ceiling deserves a comment-adjacent test asserting the pin is still
below the version whose Juggler schema breaks — the comment already explains the
reason; a test would keep the reason true.

---

## G8 — No changelog (Medium)

**Evidence.** No `CHANGELOG.md`. The fork moves fast — GUI tab refactor, scope
containment, console work, proxy rotation — and the only history is commit
messages.

**Why it matters.** Two audiences are currently served badly: someone upgrading a
pinned install cannot see what changed or what broke, and a security reviewer
cannot tell whether a given fix is in the version they have. `ci/README.md` is
excellent on *why* each decision was made; that knowledge is stranded in a
developer document rather than surfaced where a user looks.

**Close it.** Adopt a `CHANGELOG.md` in Keep-a-Changelog form, and add a release
check to `build.yml` that the version in `pythonlib/camoufox/__version__.py` has
an entry. The `--check-fetched` machinery already proves the tag and the built
version agree; this closes the same loop for the human-readable half.

---

## G9 — No readiness/health contract (Low)

**Evidence.** `/api/health` exists and is unauthenticated. It reports liveness.

**Why it matters.** For a hosted deployment behind a load balancer or orchestrator,
liveness is not enough: a console with a full admission semaphore, a dead demo
WAF, or no browser installed is *live* but not *ready*, and routing traffic to it
produces 503s that look like a bug. The distinction between "the process is up"
and "the process can accept an audit" is exactly what a readiness probe reads.

**Close it.** Split the endpoint into `/api/health` (liveness, always 200) and
`/api/health/ready` (200 only when a slot is free, the demo target is reachable,
and the ladder's dependencies are as expected), and document which one a probe
should use. Keep both unauthenticated — they must be, for a probe to read them —
and keep them free of anything that identifies a target.

---

## G10 — Four tests depend on `Xvfb` (Low)

**Evidence.** `pythonlib/tests/test_virtdisplay.py` fails with
`CannotFindXvfb: Please install Xvfb to use headless mode.` on a host without it.
The other **809 non-browser tests pass**.

**Why it matters.** This is an environment gap, not a product bug — CI installs
`Xvfb`, so the pipeline is green. But a developer running `pytest pythonlib/tests`
on a clean machine gets four red tests and has to work out that they are
environmental. That is the same failure shape the audit engine goes out of its
way to avoid elsewhere (a rung must not fail for want of an optional extra) —
here the *test suite* does what the engine avoids.

**Close it.** Add a `pytest.mark.skipif(not which("Xvfb"), reason="Xvfb not installed")`
so the four skip with a reason on a machine that cannot run them, and keep CI
running them because it installs `Xvfb`. A skip that names a missing dependency
is information; a failure that looks like a product defect is noise.

---

## What is already production-grade

Worth stating, because it shapes where effort should go — the *engineering*
here is stronger than the *packaging*:

- **Ceilings abort rather than advise**, and they are enforced server-side in the
  console regardless of the request.
- **The scope gate raises rather than returning a flag**, at every hop including
  redirects and subresources (PR #9).
- **The vendor engine is generated and CI fails on drift**, so the console cannot
  report on a ladder it no longer matches.
- **The console's `.pyz` is asserted to carry no third-party packages** and is
  self-tested, which is what makes "runs on a bare Python" a fact rather than a
  hope.
- **Isolated-first testing with a counted fallback** measures the mode users
  actually run, rather than the mode that makes the suite pass.
- **813 browser-free tests** exercise HTTP, classification, scheduling, ceilings
  and reporting against a real server with no mocks — the refusal tests are only
  meaningful because of this.
- **`AGENTS.md` encodes the *reasons*** behind invariants, not just the
  invariants. That is the single biggest asset for safe future change.

The gaps above are mostly operational — release, license metadata, repository
governance, and the small amount of hostile-input hardening the console still
needs to face the open internet. None of them require reworking the engine.

---

## Suggested order

1. **G1** — publish a release; without it the fork's own fetch path does not
   install the fork's browser, and every other guarantee is downstream of that.
2. **G5, G4, G3** — three small administrative changes that close a governance
   hole, a disclosure hole, and a distribution-rights ambiguity.
3. **G2** — bind `127.0.0.1` by default, then add auth + rate limiting before any
   public deployment.
4. **G6, G7, G8, G9, G10** — the operational polish that turns a good demo into a
   dependable service.