# Local testing

How to verify a change before opening a PR. CI runs the first two sections; the
rest exists because CI **cannot** catch some of what this tool gets wrong.

## Prerequisites

```powershell
Install-Module PSScriptAnalyzer -MinimumVersion 1.22.0 -Scope CurrentUser
Install-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99 -Scope CurrentUser -SkipPublisherCheck
```

PowerShell 7+. `Az.Accounts` is only needed for the live-tenant section — the
whole automated suite runs offline against stubs, with no tenant and no network.

## 1. The fast loop

```powershell
# Lint - must be completely clean. Warning counts as failure.
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Tests - all must pass.
Invoke-Pester -Path ./tests -Output Detailed
```

Expected: no analyzer output at all, and `Passed=59 Failed=0`.

If a test makes a real network call, something is wrong with its stubs — the
suite must never touch Azure. A stub only shadows a dot-sourced function when it
is declared **inside the `It` block itself**; defining it in a `BeforeAll` helper
or at `global:` scope does not work, because PowerShell resolves the call through
the caller's scope chain. Symptom: an unexpected `Invoke-AzRestMethod` error such
as `InvalidSubscriptionId`.

## 2. The time-zone matrix

**This is the one CI cannot do.** `ubuntu-latest` runs in UTC, so any bug that
only appears at a non-zero offset is invisible to the pipeline. A real example
from this branch: `[datetime]'2026-06-01T00:00:00Z'` yields `Kind=Local`, which
rendered as `2026-05-31` for every developer in the Americas while CI stayed
green.

```bash
for tz in UTC America/New_York America/Los_Angeles Australia/Sydney Asia/Kolkata Pacific/Kiritimati; do
  printf '%-24s ' "$tz"
  TZ=$tz pwsh -NoProfile -Command '
    Import-Module Pester -MinimumVersion 5.0.0
    $c = New-PesterConfiguration
    $c.Run.Path = "./tests"; $c.Run.PassThru = $true; $c.Output.Verbosity = "None"
    $r = Invoke-Pester -Configuration $c
    "Passed=$($r.PassedCount) Failed=$($r.FailedCount)"' | tail -1
done
```

Expected: identical counts on every row. Those six cover UTC, both US offsets, a
half-hour offset (Kolkata, UTC+5:30), and both extremes of the date line.

On Windows, substitute `Set-TimeZone` in an elevated session, or run the loop in
WSL.

Run this whenever a change touches a timestamp, a date format, or a staleness
comparison.

## 3. Verifying this branch's fixes

### 3.1 Sovereign-cloud endpoints

The query host and token audience must follow the signed-in cloud. Without a Gov
or China tenant you can still prove the resolution logic:

```powershell
Import-Module Az.Accounts
. ./Private/Invoke-ShcQuery.ps1
foreach ($name in 'AzureCloud','AzureUSGovernment','AzureChinaCloud') {
    $real = Get-AzEnvironment -Name $name
    function Get-AzContext { [CmdletBinding()] param() [pscustomobject]@{ Environment = $real } }
    $e = Get-ShcLogAnalyticsEndpoint
    '{0,-18} audience={1,-38} uri={2}' -f $name, $e.Resource, $e.BaseUri
}
```

Expected:

| Cloud | audience | query base |
|---|---|---|
| AzureCloud | `https://api.loganalytics.io` | `https://api.loganalytics.io/v1` |
| AzureUSGovernment | `https://api.loganalytics.us` | `https://api.loganalytics.us/v1` |
| AzureChinaCloud | `https://api.loganalytics.azure.cn` | `https://api.loganalytics.azure.cn/v1` |

Red flag: any `api.loganalytics.io` appearing for a sovereign cloud, or a literal
`loganalytics` host anywhere outside `Get-ShcLogAnalyticsEndpoint`:

```bash
grep -rn 'loganalytics' Private/ Public/ | grep -v 'Get-ShcLogAnalyticsEndpoint'
```

Only that function's own doc comment and its two fallback defaults should match.

### 3.2 UTC normalisation

```powershell
. ./Private/ConvertTo-ShcUtc.ps1
ConvertTo-ShcUtc '2026-06-01T00:00:00Z'        | ForEach-Object { $_.Kind; $_.ToString('o') }
ConvertTo-ShcUtc '2026-06-01T10:00:00+10:00'   | ForEach-Object { $_.ToString('o') }
ConvertTo-ShcUtc '2026-06-01T00:00:00'         | ForEach-Object { $_.ToString('o') }
```

Expected in **every** time zone: `Utc`, then `2026-06-01T00:00:00.0000000Z` for
all three. An offset-less value is *labelled* UTC, never shifted — ARM `*Utc`
properties and KQL datetime columns are UTC by contract.

Guard against regressions:

```bash
grep -rn '\[datetime\]' Private/ Public/ | grep -v ConvertTo-ShcUtc.ps1
```

The only hits should be the `[datetime]$StartDate` / `[datetime]$EndDate`
parameter declarations (user input, deliberately interpreted as local time and
documented as such) and `[datetime]$Context.WindowEnd` (already `Kind=Utc`). Any
new `[datetime]` cast applied to an API value is a bug.

### 3.3 Report rendering never discards a completed scan

Rendering happens *after* the whole scan, so a failure there must not cost the run:

```powershell
pwsh -NoProfile -Command '
  Import-Module ./SentinelHealthCheck.psd1 -Force
  # Force a render failure by pointing at a path that cannot be written
  $r = Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName "rg-sec" `
      -WorkspaceName "law-sentinel" -PassThru -WarningAction SilentlyContinue
  $r.Grade
'
```

Expected: a warning naming the failure, `Report: not written (see warning above).`
on the console, and `-PassThru` still returning the full result object. A run that
throws and returns nothing is the regression.

Note: the report is a client-side dashboard as of 0.3.1-beta. Findings are embedded
as a JSON island and rendered in the browser, so escaping lives in two places — the
`\u003c`/`\u003e`/`\u0026` replacement applied after `ConvertTo-Json` (which stops a
rule named `</script>` terminating the block) and the `esc()` helper on every
`innerHTML` path. Both are covered by the XSS test in the suite.

### 3.4 Output path is validated before the scan

```powershell
# Should fail immediately, before any Azure call
Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName 'rg-sec' `
    -WorkspaceName 'law-sentinel' -OutputPath ./nope/report.html
```

Expected: throws `Cannot write the report: directory '...' does not exist.`
within a second, with no "scanning..." banner and no rules fetched. If you see
the scan run first, the check moved back to the wrong place.

## 4. Live tenant smoke test

Everything the tool does is read-only: two ARM GETs and a handful of KQL queries.
It never writes to the workspace. Needs **Microsoft Sentinel Reader** and **Log
Analytics Reader**.

```powershell
Connect-AzAccount
Import-Module ./SentinelHealthCheck.psd1 -Force

$r = Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName 'rg-sec' `
    -WorkspaceName 'law-sentinel' -LookbackDays 14 -PassThru -Verbose
```

Check:

- All seven checks return, none with `Status = 'unknown'` reading
  `Check failed to run.` (that means a check threw — the message names it).
- `$r.Checks | Select-Object CheckId, Status, Score, Headline` reads sensibly
  against what you know about the workspace.
- Dates in the report are UTC. Cross-check one against the portal:
  `$r.Checks | Where-Object CheckId -eq 'HC-02' | ForEach-Object { $_.Findings }`.
- Open the HTML. Confirm the grade, the KPI tiles, and that rule names with
  `<`, `>` or `&` render as text rather than markup.

Then a historical window, which exercises the custom-range path and proves the
point-in-time checks are measured at the window end rather than "now":

```powershell
Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName 'rg-sec' `
    -WorkspaceName 'law-sentinel' -StartDate '2026-04-01' -EndDate '2026-06-30'
```

And the pipeline path, which regressed once before — each workspace must get its
**own** report file:

```powershell
Get-AzOperationalInsightsWorkspace -ResourceGroupName 'rg-sec' |
    Invoke-SentinelHealthCheck -SubscriptionId $sub
```

Generated reports are gitignored (`*.html`), but they contain real workspace and
rule names — treat them as client data and do not attach one to an issue.

## 5. Pre-PR checklist

- [ ] Analyzer clean at Warning+ (`section 1`)
- [ ] Full suite green (`section 1`)
- [ ] Time-zone matrix green, if anything touched time (`section 2`)
- [ ] Module imports and exports exactly one function:
      `Import-Module ./SentinelHealthCheck.psd1 -Force; Get-Command -Module SentinelHealthCheck`
- [ ] `Test-ModuleManifest ./SentinelHealthCheck.psd1` passes
- [ ] Every bug fix ships a regression test that fails without the fix
- [ ] Any new check cites a Microsoft doc or named framework in its `MethodNote`
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No new required module — `Az.Accounts` stays the only dependency
