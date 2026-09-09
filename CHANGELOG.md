# Changelog

All notable changes to this module. Format loosely follows Keep a Changelog.

## [Unreleased]

### Added
- **HC-08, health signal coverage and taxonomy.** HC-09 answers whether health
  monitoring is on; HC-01 grades analytics-rule failures. Neither answers the
  question underneath both: which of the four resource types Microsoft says report
  health are actually reporting it in this workspace, and what values do they use?
  A workspace can pass HC-09 while three of the four categories have never emitted
  an event, because the diagnostic setting only selected some log categories -
  failures there are invisible and no other check sees it. HC-08 enumerates every
  distinct (resource type, operation, status, reason) combination in SentinelHealth
  and SentinelAudit over the scan window, names the documented resource types that
  reported nothing, and marks any combination absent from Microsoft's published
  list. Deliberately ungraded (weight 0, null score): a census is an observation,
  not a judgement, and scoring it would penalise the same fact HC-09 already scores.
- **`Get-ShcHealthTaxonomy`, the documented value set in one place.** Checks that
  match on `SentinelResourceType` or `Status` each carried their own tolerant
  matcher (HC-01's `contains "rule"`), every one an independent guess at a value set
  written down nowhere. It is written down here now, from
  `health-table-reference` and `audit-table-reference`. Comparison via
  `Test-ShcDocumentedHealthValue` is case-insensitive, so the tenant casing variant
  HC-01 hit in July ("Analytics Rule" against the docs' "Analytics rule") is not
  reported as drift - only genuinely unlisted values are.

  What the taxonomy deliberately does not cover: `Reason` is typed as an enum whose
  "possible values depend on the resource type" and Microsoft never publishes the
  list, and `Description` is free text. Those two carry the actual failure cause, so
  the only way to learn their value set is to observe it. HC-08 puts its full census
  in the result's `.Data` (`HealthCensus`, `AuditCensus`, `ExtendedPropertyKeys`,
  `UndocumentedValues`, `MissingResourceTypes`) for `-PassThru` callers to aggregate
  across workspaces - which is how that catalogue gets built.

  The `ExtendedProperties` key census collapses to one representative record per
  (type, operation, status) with `arg_max` before expanding the JSON bag, so it
  costs roughly ten rows of `mv-expand` rather than the whole window; it reports the
  keys on the most recent record of each combination, not the union of every key
  ever seen. That query is also the one most likely to be rejected or throttled on a
  large estate, so it fails soft - losing the key census does not cost the caller the
  rest of the check.

## [0.4.0-beta] - 2026-08-24

### Fixed
- **Sovereign clouds now work.** The Log Analytics query host and token audience
  were hardcoded to `api.loganalytics.io`, so in Azure Government
  (`api.loganalytics.us`) and China (`api.loganalytics.azure.cn`) every KQL-backed
  check failed at the token request and degraded to "not measurable" - leaving the
  grade meaningless. Both are now resolved per cloud from the signed-in context via
  `Get-ShcLogAnalyticsEndpoint`, falling back to the commercial defaults when an
  older `Az.Accounts` leaves the environment properties blank. ARM calls needed no
  change: `Invoke-AzRestMethod -Path` already resolves against the context.
- **Timestamps are normalised to UTC.** `[datetime]'...Z'` yields `Kind=Local`, so
  any API value that arrived as a string (rather than being auto-converted by the
  JSON deserializer) was compared against the `Kind=Utc` window end with the host's
  offset baked in - under-reporting staleness east of UTC and over-reporting west,
  and rendering dates a day off. All API timestamps now pass through
  `ConvertTo-ShcUtc`, which honours the offset and is invariant to host time zone
  and culture. HC-02 also skips `Usage` rows with no parseable timestamp instead of
  inventing a staleness figure from a blank.
- **A rendering failure no longer discards a completed scan.** `New-ShcReport` was
  the one unguarded call in the orchestrator, so anything it threw cost the user the
  whole run - two ARM collections and every KQL query - after all the work was done.
  It is now wrapped, `-PassThru` still returns the result, and the console says the
  report was not written rather than naming a file that does not exist. (A companion
  StrictMode fix for the old PowerShell table renderer was dropped in the 0.3.1-beta
  merge: the dashboard redesign moved table building into the browser, so that code
  no longer exists.)
- **`-OutputPath` is validated before the scan, not after.** A missing directory
  surfaced only at the final `Set-Content`, throwing away two ARM collections and
  ~10 KQL queries. The path is now resolved and checked before the first ARM call.
  `New-ShcReport` also writes with `-LiteralPath` (`-Path` treats `[` and `]` as
  wildcards and fails on paths containing them), and the default path uses
  `$PWD.ProviderPath` so it stays correct when the caller is on a non-filesystem
  provider.

- **HC-02 missed the worst case it existed to catch.** Candidate tables came from
  the `Usage` table, which only lists tables that have ingested — so a table that
  has **never** ingested produced no `Usage` row and was never considered. Found on
  a live workspace: eight Kubernetes rules watching an empty `AKSAudit`, plus rules
  on `Event` and `NTANetAnalytics`, all graded healthy. Candidates now come from the
  workspace's full ARM table inventory (`Get-ShcWorkspaceTables`), and a referenced
  table absent from `Usage` is probed directly. Findings gained an `Issue` column
  distinguishing `Stale` from `No data` / `Table not found`. On the workspace that
  surfaced this, the check went from 2 affected rules (8.7%) to 12 (52.2%).
- **HC-02 no longer counts a table named only in a comment or string literal.**
  Matching ran against raw query text, so `// AzureActivity is not used here` made
  a rule "watch" AzureActivity. `Get-ShcQueryTables` strips comments and string
  literals before matching — this removed a real false positive on the live
  workspace while raising per-rule coverage from 13/23 to 23/23.
- **HC-04 had no blindness gate.** With an empty `SecurityAlert` it reported
  "N of N rules never fired" and scored 0/100 — the most alarming finding the tool
  produces, derived from a table with no data, unable to distinguish "no rule fired"
  from "alerts are not reaching the table". It now returns `unknown` and is excluded
  from the grade, matching HC-01/HC-02/HC-03. Same bug class as commit `885d61d`.

- **A non-Sentinel workspace produced a wall of escaped JSON.** Pointing the scan
  at a Log Analytics workspace that is not onboarded to Sentinel — the most likely
  first-run mistake — dumped a double-encoded ARM error body and a full subscription
  path. `Get-ShcArmErrorMessage` unwraps nested ARM errors, and the onboarding case
  now reports one readable line telling you what to do.
- **No retry on throttling or transient failures.** Any 429 or 5xx mid-paging killed
  the whole scan. ARM paging now retries `408/429/500/502/503/504` up to five times,
  honouring `Retry-After` when present (capped at 60s) and backing off exponentially
  otherwise; the query path uses PowerShell 7's `-MaximumRetryCount`/`-RetryIntervalSec`.
  This matters more since HC-02 began probing tables absent from `Usage`.
- **ARM paging had no cycle guard.** A `nextLink` pointing back at an already-read
  page would loop forever; repeated links now stop paging with a warning.
- **HC-02 asserted a diagnosis it had not earned.** The summary said "fix the feed"
  for every finding. A table that resolves but has never held a row looks identical
  whether the feed is broken or the rule is deployed to the wrong workspace — a real
  case found in testing, where eight rules watched an `AKSAudit` that lives in a
  different workspace entirely. The `No data` wording now names both possibilities.

### Added
- `TESTING.md`: local verification guide, including the time-zone matrix that CI
  (UTC-only) cannot cover.
- Regression tests for each fix above, plus `ConvertTo-ShcUtc`,
  `Get-ShcLogAnalyticsEndpoint`, `Get-ShcQueryTables`, `Get-ShcArmErrorMessage` and retry/backoff
  unit tests, plus source guards pinning the hostname fix and asserting every file
  parses (PSScriptAnalyzer reports nothing for a file with a syntax error, so the
  lint gate alone cannot catch one). Suite is 80
  tests, green in UTC, US Eastern/Pacific, Kolkata (UTC+5:30), Sydney and
  Kiritimati (UTC+14).
## [0.3.1-beta] - 2026-08-08

### Changed
- Redesigned the HTML report as an interactive dashboard: a radial score gauge
  with the grade at its center, a per-check score bar chart (worst-first; click a
  bar to jump to that check), a "never-fired rules by severity" donut, and live
  search plus column-sort on every findings table. Added a light/dark theme
  toggle, with both themes designed. The report is still a single,
  self-contained, offline file with no external dependencies.
- The renderer now embeds the scan result as an HTML-safe JSON island and builds
  the page client-side, replacing the server-side HTML-table building. Untrusted
  strings (rule names, incident titles) are unicode-escaped so nothing can break
  out of the data block, and every value is written to the DOM as text.

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
