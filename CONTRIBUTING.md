# Contributing

Issues and PRs welcome. This page is short because the bar is simple: keep the
tool honest, tested, and free of scope creep.

## Dev setup

PowerShell 7+, then:

```powershell
Install-Module PSScriptAnalyzer -MinimumVersion 1.22.0 -Scope CurrentUser
Install-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99 -Scope CurrentUser -SkipPublisherCheck

# Lint - must be completely clean (Warning counts as failure)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Tests - must all pass
Invoke-Pester -Path ./tests
```

CI runs both on every push and PR; a warning fails the build.

## Rules that are not style preferences

- **Evidence discipline.** A new check needs a source: a Microsoft doc or a
  named framework, cited in its `MethodNote` before it ships. No check claims
  "best practice" without one.
- **Tolerant matching on Sentinel strings.** Sentinel's enum-ish values vary
  across tables and tenants (`SentinelHealth` says "Analytics Rule";
  `SentinelAudit` says "Analytic Rule" — same tenant). Match with `contains`,
  never exact-match. There are tests that fail if you "clean this up."
- **Blindness is never health.** A missing or silent table must gate a check
  into "not measurable," never into a clean pass. Gate on data in the same
  window the check queries.
- **Health only.** No cost analysis, no dollar figures, no pricing logic. That
  lives in a separate private tool, permanently.
- **Bug fixes ship a regression test.** Every bug found so far has one; keep
  the streak.
- **Read-only, minimal footprint.** GETs and KQL queries only; `Az.Accounts`
  stays the only required module.

## Mechanics

- Layout: exported commands in `Public/`, helpers in `Private/` (one function
  per file, `Shc` prefix). Only `Invoke-SentinelHealthCheck` is exported.
- Add a line to `CHANGELOG.md` under `[Unreleased]`.
- PRs target `main`.
