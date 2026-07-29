## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1` is clean (warnings count as failures)
- [ ] `Invoke-Pester -Path ./tests` — all green
- [ ] Bug fix? A regression test is included
- [ ] New check? Source cited in its `MethodNote`
- [ ] No exact-matching on Sentinel enum-ish strings (they vary across tables and tenants)
- [ ] No cost/pricing logic (this module is health-only)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
