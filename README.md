# SentinelHealthCheck

[![CI](https://github.com/purpleshellsecurity/SentinelHealthCheck/actions/workflows/ci.yml/badge.svg)](https://github.com/purpleshellsecurity/SentinelHealthCheck/actions/workflows/ci.yml)

> [!IMPORTANT]
> **Beta (0.3.0-beta).** This is a pre-release looking for testers. It is
> read-only and safe to run, but expect rough edges — if something breaks or a
> finding looks wrong, please [open an issue](https://github.com/purpleshellsecurity/SentinelHealthCheck/issues).

Free, read-only detection-health scanner for Microsoft Sentinel. One command,
in less than 5 minutes, one HTML report card that grades the health of your
Sentinel Workspace.

## What It Checks

| Check | Question it answers |
|-------|---------------------|
| **HC-09** Detection observability | Can the workspace even see its detections (health, audit, and query logging on)? Runs first |
| **HC-01** Rules in error state | Which rules are failing to run at all, and would you know? |
| **HC-02** Dead data sources | Which enabled rules watch tables that stopped ingesting: blind spots wearing green checkmarks? |
| **HC-03** Alert noise & triage discipline | Which rules have the worst false-alarm rates, and does every closed incident get classified? |
| **HC-04** Never-fired rules | Which enabled rules produced zero alerts in 90 days: tripwire or corpse? |
| **HC-05** Disabled inventory | How much claimed coverage is switched off? |
| **HC-06** Silent auto-close | Which automation rules close incidents before a human ever sees them? |

<br>

## What's in the Report

| Section | What it tells you |
|---------|-------------------|
| **A–F grade** | One weighted score for the whole detection estate |
| **KPI tiles** | Rule counts, never-fired, dead-data, erroring, auto-close at a glance |
| **Volume outliers** | Top-10 **noisiest** rules (most incidents, with FP rate) and top-10 **quietest** (fewest alerts, one dry spell from never-fired) |
| **Needs attention** | Each failing check with its findings table |
| **Passing / Not measured** | Collapsed, so the problems stay above the fold |

## Prerequisites

| Requirement | Details |
|-------------|---------|
| PowerShell 7 | `winget install --id Microsoft.PowerShell --source winget` |
| Az.Accounts module | `Install-Module Az.Accounts -Scope CurrentUser` |
| Workspace permissions | **Microsoft Sentinel Reader** + **Log Analytics Reader** |

## Quick Start

### 1. Clone and Import

```powershell
git clone https://github.com/purpleshellsecurity/SentinelHealthCheck.git
cd SentinelHealthCheck
Import-Module ./SentinelHealthCheck.psd1
```

### 2. Sign In and Scan

```powershell
Connect-AzAccount
Invoke-SentinelHealthCheck -SubscriptionId '<sub-id>' `
                           -ResourceGroupName '<rg>' `
                           -WorkspaceName '<workspace>'
```

### 3. Read Your Grade

The report lands next to you as `SentinelHealthCheck-<workspace>-<timestamp>.html`.
Open it, read your grade, screenshot it for your boss.

<br>

> [!NOTE]
> Read-only by design: ARM GETs and KQL queries only. Nothing is modified,
> nothing leaves your environment, and the report is a local file.

<br>

> [!TIP]
> Scanning more than one workspace? Pipe them in, one report each:
> ```powershell
> Get-AzOperationalInsightsWorkspace -ResourceGroupName '<rg>' | Invoke-SentinelHealthCheck -SubscriptionId '<sub-id>'
> ```

<br>

## Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-LookbackDays` | 90 | History window ending now. Presets tab-complete (7 / 14 / 30 / 60 / 90); any 7–365 accepted |
| `-StartDate` / `-EndDate` | (none) | Custom scan window instead of a lookback (max 365 days, `-EndDate` defaults to now). A date-only end means *through* that day |
| `-OutputPath` | `./SentinelHealthCheck-<ws>-<stamp>.html` | Report location |
| `-PassThru` | off | Return the full result object (every finding, uncapped) for automation |

<br>

> [!NOTE]
> With a custom range, point-in-time checks (rules in error, dead tables) are
> measured as of the window's end: the report shows what was broken *then*, not now.

<br>

## Contributing

Issues and PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev
setup and the rules that are not style preferences.

## License

This project is licensed under the [MIT License](LICENSE).

> ⚠️ **Disclaimer:** This tool is provided as-is. Run it only against
> workspaces you are authorized to assess.
