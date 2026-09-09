function Test-ShcErroringRules {
    <#
    .SYNOPSIS
        HC-01 (was OH-01) - Analytics rules whose most recent health status is not Success.
        Requires the SentinelHealth table (health diagnostics enabled on the workspace).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-01'
    $title   = 'Rules in error or failed state'
    $weight  = 20

    # Health state is "latest status per rule", so use a short sub-window ending at
    # the scan-window end - a historical range grades what was failing *then*.
    $healthLookback = [Math]::Min(30, $Context.LookbackDays)
    $healthStart = ([datetime]$Context.WindowEnd).AddDays(-$healthLookback).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $healthTimespan = "$healthStart/$($Context.KqlEnd)"

    # Gate on FRESH data in the SAME sub-window the query reads. Gating on the full
    # scan window lets "monitoring stopped mid-window" through, and week-old rows
    # inside the sub-window are the same blindness: any enabled scheduled rule
    # produces daily health events, so nothing in 24 hours means monitoring is off
    # or broken right now.
    $healthProbe = Get-ShcTableState -WorkspaceId $Context.WorkspaceId -TableName 'SentinelHealth' -Timespan $healthTimespan
    $windowEnd = [datetime]$Context.WindowEnd
    $healthFresh = $healthProbe.State -eq 'present' -and ($windowEnd - $healthProbe.LastSeenUtc).TotalHours -le 24
    if (-not $healthFresh) {
        $headline = if ($healthProbe.State -eq 'missing') {
            'Rule health monitoring is not enabled - rule failures are invisible.'
        } else {
            'SentinelHealth recorded nothing in the last 24 hours - rule failures are invisible right now.'
        }
        $summary = if ($healthProbe.State -eq 'missing') {
            'No SentinelHealth table, so nothing records when a rule fails to run. A rule can break ' +
            'and stay broken, silently. Turn on health monitoring: Sentinel > Settings > Health monitoring.'
        } else {
            'Any workspace with an enabled scheduled rule produces health events daily, so a silent ' +
            'SentinelHealth means monitoring is off or broken - check the workspace diagnostic ' +
            'settings (Sentinel > Settings > Health monitoring).'
        }
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'warning' `
            -Headline $headline -Summary $summary `
            -MethodNote "SentinelHealth state: $($healthProbe.State); freshness bar: 24 hours before the window end. Excluded from the grade."
    }

    # Select on the documented operation names rather than guessing at
    # SentinelResourceType. The old filter (contains "rule", !contains "automation")
    # hedged against a value set nobody had written down; Get-ShcHealthTaxonomy is
    # that value set now, taken from health-table-reference. Analytics rules emit
    # exactly these two operations, so the automation exclusion is implicit.
    #
    # Why an exact list is safe here when it was not before: a tenant emitting an
    # operation name outside the documented set used to produce a silent false
    # clean. HC-08 now censuses every operation the workspace actually reports and
    # flags anything unlisted, so that drift surfaces instead of hiding. Do not
    # narrow this further without keeping HC-08 in the run.
    #
    # in~ is case-insensitive, which covers the "Analytics Rule" casing variant
    # observed on a live tenant (2026-07-28). Names are module constants, not user
    # input, so simple quoting is sufficient.
    $analyticsOps = @((Get-ShcHealthTaxonomy).Health |
            Where-Object { $_.ResourceType -eq 'Analytics rule' } |
            ForEach-Object { $_.OperationName })
    $opList = ($analyticsOps | ForEach-Object { '"' + $_ + '"' }) -join ', '

    $query = @"
SentinelHealth
| where TimeGenerated between (datetime($healthStart) .. datetime($($Context.KqlEnd)))
| where OperationName in~ ($opList)
| summarize arg_max(TimeGenerated, Status, Description) by SentinelResourceName
| where Status !~ "Success"
| project RuleName = SentinelResourceName, LastStatus = Status, LastSeenUtc = TimeGenerated, Detail = Description
| order by RuleName asc
"@
    $failing = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $query -Timespan $healthTimespan |
            ForEach-Object {
                [pscustomobject]@{
                    RuleName    = $_.RuleName
                    LastStatus  = $_.LastStatus
                    LastSeenUtc = (ConvertTo-ShcUtc $_.LastSeenUtc).ToString('yyyy-MM-dd HH:mm')
                    Detail      = $_.Detail
                }
            })

    $enabledCount = [Math]::Max(1, $Context.EnabledRuleCount)
    $failPct = [Math]::Round(($failing.Count / $enabledCount) * 100, 1)
    $score = [Math]::Max(0.0, 100 - (5 * $failPct))

    $status = if ($failing.Count -eq 0) { 'good' }
    elseif ($failPct -lt 2)   { 'warning' }
    elseif ($failPct -lt 10)  { 'serious' }
    else                      { 'critical' }

    $headline = if ($failing.Count -eq 0) {
        'No analytics rules were in a failed state at the end of the scan window.'
    } else {
        "$($failing.Count) analytics rule(s) most recently ran with a non-success status ($failPct% of enabled rules)."
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These rules errored on their last run and are not detecting anything right now. Fix ' +
        'the cause in the Detail column, then confirm the next run succeeds.') `
        -Findings $failing -Columns @('RuleName', 'LastStatus', 'LastSeenUtc', 'Detail') `
        -MethodNote ("SentinelHealth, latest status per rule over $healthLookback days to the window end. " +
        "Rows are selected by the operation names Microsoft documents for analytics rules " +
        "($($analyticsOps -join ', ')), matched case-insensitively; HC-08 reports any operation " +
        "outside that set. Microsoft: monitor-analytics-rule-integrity, health-table-reference (HC-01).")
}
