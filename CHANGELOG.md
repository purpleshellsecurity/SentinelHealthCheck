# Changelog

All notable changes to this module. Format loosely follows Keep a Changelog.

## [0.3.0-beta] - 2026-07-29

First public beta. Feedback and bug reports welcome — please open an issue.

### Removed
- ROADMAP.md and REQUIREMENTS.md. Planned work now lives in issues; the README
  keeps the short version. References in CONTRIBUTING.md, the issue/PR
  templates, and the command help updated to match.

### Added
- Pipeline support: workspace objects bind by property name —
  `Get-AzOperationalInsightsWorkspace | Invoke-SentinelHealthCheck -SubscriptionId $sub`
  scans each piped workspace (`Name` aliases `WorkspaceName`). Fixes a latent
  bug where the defaulted report path leaked into later pipeline iterations,
  overwriting the first workspace's report.
- Gallery search metadata: `PSEdition_Core`/`Windows`/`Linux`/`MacOS` tags and
  a `ReleaseNotes` link to this changelog.
- Full per-table freshness inventory (`Table`, `LastSeenUtc`, `DaysSilent`,
  `WatchedByRules`) on HC-02's `Data` slot for `-PassThru` consumers. Only
  rule-watched tables are graded findings — a dead table nothing watches is
  not a detection blind spot — but the raw last-seen list is now kept.
- Community health files per GitHub's public-repo checklist: SECURITY.md
  (private vulnerability reporting, with the tool's actual attack surface
  spelled out), CONTRIBUTING.md (the non-negotiable rules: evidence discipline,
  tolerant matching, blindness-is-never-health, health-only scope),
  CODE_OF_CONDUCT.md, issue forms, a PR template, and Dependabot for Actions.

### Changed
- HC-03 split into its two questions. The findings table now ranks rules by
  **false-alarm rate** (minimum 5 classified closures, so the rate means
  something — previously a low-volume 100%-false-positive rule was invisible
  behind the top-20-by-volume cut); pure **volume** moved to the noisiest
  leaderboard, fed from the check's `Data.TopTalkers`. The score is now
  workspace-wide (false-alarm share of all classified closures + unclassified
  share of all closures) instead of top-20-based. Card and board now rank
  different things, so both can appear in the same report.
- Check summaries rewritten plain and concise — two short sentences each:
  what is wrong, what to do. Metaphors removed.
- The per-card "How this was measured" block and the leaderboard captions are
  removed from the HTML. Method notes (mechanics + sources) remain on every
  check's `-PassThru` envelope.
- Report layout: failing checks come directly after the KPI tiles, volume
  outliers below them; the Passing list renders as an aligned checklist; the
  title is now "Sentinel Workspace Health Report". Leaderboards grew to
  top-10; the noisiest board hides when every row is a single incident
  (ties rank nothing). HC-03 retitled "Alert noise and triage discipline"
  with a plain-language headline.
- HC-09 judges observability by **last-event age, not data existence**, and the
  finding table gains a "Last event" column ("4 min ago" / "3 days ago").
  `SentinelHealth` must be fresh within 24 hours — any enabled scheduled rule
  produces daily health events, so older data means monitoring stopped
  ("Stale", penalized like off). `SentinelAudit` keeps its event-driven
  unverified handling. Query auditing (`LAQueryLogs`) is demoted to
  informational — shown, never scored: its value is an IR audit trail, not
  detection health. HC-01's gate applies the same 24-hour freshness bar.
- HC-02's staleness threshold is **fixed at 24 hours** and the `-StaleDays`
  parameter is removed (it previously defaulted to 7 days). A rule-watched
  production telemetry table silent for more than a day is a gap, full stop —
  Azure's documented ingestion lag fits comfortably inside 24 hours. The
  threshold lives at the top of `Test-ShcDeadDataSources` if you disagree.
- README: the "Honest limitations" and "What SentinelHealthCheck cannot tell
  you" sections are removed. The per-check caveats remain where they bind to
  findings — each check's "How this was measured" note in the report.
- The bearer token now reaches `Invoke-RestMethod` as a SecureString via
  `-Authentication Bearer` — no plaintext copy of the credential is held in a
  variable (PS7-native; the old-Az.Accounts plaintext path converts immediately).
- Per-step progress lines ("Collecting…", "Running Test-…") moved from
  `Write-Host` to `Write-Verbose` so scripted callers can silence them; the
  banner, per-check summary, and report path remain interactive output.
- Report prose slimmed (merged from the report-polish branch): check summaries
  and method notes rewritten shorter, leaderboard captions tightened — same
  facts and citations. The per-card "How this was measured" block stays after
  architect review: collapsed by default, it is the report's provenance
  mechanism when a finding is challenged.

### Fixed
- One failing check no longer takes down the whole run: the catch fallback is
  now keyed by the check's real HC-## id (via a function→identity catalog), so
  the KPI/leaderboard lookups resolve instead of crashing under StrictMode.
  (Merged from the report-polish branch; regression test added.)
- HC-01 gates on the same 30-day health sub-window its query reads. Gating on
  the full scan window let "monitoring stopped mid-window" pass as a clean
  100 — old rows satisfied the gate while the sub-window query found nothing.
- `SentinelAudit` is event-driven, so an empty-in-window table is now reported
  as "No events in window" (unverified) with no score penalty — a workspace
  where nobody changed a rule all window is stable, not blind. Silence in
  `SentinelHealth` and `LAQueryLogs` is still penalized as off.
- `Get-ShcTableState` reads the API error body from `ErrorDetails` (PowerShell 7
  puts the SemanticError text there, not in `Exception.Message`), so a genuinely
  absent table now classifies as `missing` instead of failing the check.
- Table presence no longer counts as feature health. A `SentinelHealth` table
  that exists but recorded nothing in the scan window (monitoring enabled once,
  then stopped) previously passed the HC-01/HC-09 gates — HC-01 would then
  report a false clean from an empty table. A new `Get-ShcTableState`
  distinguishes missing / empty / present: HC-09 now reports "No recent data"
  and penalizes it like off; HC-01 excludes itself from the grade either way.
  Found on a real tenant before the first shakedown run.

## [0.2.0] - 2026-07-27

### Added
- Custom scan windows: `-StartDate`/`-EndDate` parameter set alongside
  `-LookbackDays` (which now tab-completes the 7/14/30/60/90 presets). All KQL
  moved from `ago()` to explicit window bounds; point-in-time checks (HC-01
  rule health, HC-02 table freshness) anchor to the window end, so historical
  ranges report what was broken then. Fixes the KPI tile hardcoding "(90d)"
  regardless of the actual lookback.
- Volume-outlier leaderboards in the report and `-PassThru` object: top-5 noisiest
  rules (most incidents, from HC-03) and top-5 quietest firing rules (fewest
  alerts in the lookback, from HC-04's fire counts).
- Check envelope gained an optional `Data` slot for check-specific extras.

### Changed
- Manifest hygiene: `ProjectUri`/`LicenseUri` now point at this public repo,
  `CompatiblePSEditions = Core`, `Az.Accounts` pinned to a minimum version, and
  the module version is single-sourced from the manifest.
- CI pins Pester to 5.x (unpinned minimum now resolves to Pester 6) and fails
  the lint step on warnings, not just errors.
- Check IDs standardized to the canonical HC-## series: HC-01 (was OH-01),
  HC-02 (was LS-04), HC-03 (was OH-04), HC-04 (was OH-03), HC-05 (was OH-02),
  HC-06 (was OH-06), HC-09 (was OH-00). HC-07/HC-08 are reserved for planned
  checks. Reports generated before this change carry the old IDs.

### Added
- CI: PSScriptAnalyzer lint + Pester tests on push/PR.
- Test coverage for every check's core logic, the grade/leaderboard assembly, and
  HTML encoding in the report renderer — including regression guards for the
  CamelCase table-match bug and HC-01's tolerant resource-type filter.

### Removed
- All cost-analysis surface. The `AnnualizedDollars` field is gone from the check
  envelope and cost-tool history is out of this changelog — cost analysis is a
  separate, private tool. This module is health-only, by design.

### Fixed
- Check scores were silently rounded to integers: `[Math]::Max(0, <double>)`
  resolves to the integer overload in PowerShell, truncating fractional scores
  (found by the new HC-03 test). All checks now use `Max(0.0, ...)`.
- Rule table-reference matching is constrained to actual billable tables, removing
  false positives from CamelCase column/function tokens.

## [0.1.0]

### Added
- `Invoke-SentinelHealthCheck`: read-only detection-health scanner for Microsoft
  Sentinel. Six checks (OH-01/02/03/04/06, LS-04), weighted A–F grade, self-contained
  HTML report. Maps to the detection assessment methodology's mechanical pass.
