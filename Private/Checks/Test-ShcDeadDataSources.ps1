function Test-ShcDeadDataSources {
    <#
    .SYNOPSIS
        HC-02 (was LS-04 / RQ-05) - Enabled rules whose queries reference tables that have stopped
        ingesting. A live rule watching dead data is a blind spot that looks covered.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-02'
    $title   = 'Enabled rules watching dead data sources'
    $weight  = 25
    # Deliberately fixed, not a parameter: a rule-watched production telemetry
    # table silent for more than a day is a gap, full stop. Azure's documented
    # ingestion lag fits comfortably inside 24 hours.
    $staleDays = 1

    $query = @"
Usage
| where TimeGenerated between (datetime($($Context.KqlStart)) .. datetime($($Context.KqlEnd)))
| summarize LastSeenUtc = max(TimeGenerated) by DataType
"@
    $usage = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $query -Timespan $Context.Timespan)

    if ($usage.Count -eq 0) {
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'unknown' `
            -Headline 'Could not read table ingestion history (Usage table returned no rows).' `
            -MethodNote 'This check is excluded from the grade.'
    }

    # Staleness is measured against the end of the scan window, so a historical
    # -StartDate/-EndDate range reports what was dead *then*, not what is dead now.
    $windowEnd = [datetime]$Context.WindowEnd
    $tableFreshness = @{}
    foreach ($row in $usage) {
        $tableFreshness[$row.DataType] = [datetime]$row.LastSeenUtc
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $affectedRules = [System.Collections.Generic.HashSet[string]]::new()
    $watchedTables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($rule in $Context.QueryRules) {
        $ruleQuery = $rule.properties.query
        if ([string]::IsNullOrWhiteSpace($ruleQuery)) { continue }

        foreach ($tableName in $tableFreshness.Keys) {
            if ($ruleQuery -notmatch "\b$([regex]::Escape($tableName))\b") { continue }
            $null = $watchedTables.Add($tableName)
            $lastSeen = $tableFreshness[$tableName]
            $daysSilent = [Math]::Floor(($windowEnd - $lastSeen).TotalDays)
            if ($daysSilent -lt $staleDays) { continue }

            $null = $affectedRules.Add($rule.name)
            $findings.Add([pscustomobject]@{
                    RuleName    = $rule.properties.displayName
                    Table       = $tableName
                    LastSeenUtc = $lastSeen.ToString('yyyy-MM-dd HH:mm')
                    DaysSilent  = $daysSilent
                })
        }
    }

    # Full per-table freshness inventory for -PassThru consumers (Data.TableFreshness).
    # Only rule-watched tables are graded findings - a dead table nothing watches is
    # not a detection blind spot - but the raw last-seen list is free to keep.
    $inventory = @($tableFreshness.Keys | ForEach-Object {
            [pscustomobject]@{
                Table          = $_
                LastSeenUtc    = $tableFreshness[$_].ToString('yyyy-MM-dd HH:mm')
                DaysSilent     = [Math]::Floor(($windowEnd - $tableFreshness[$_]).TotalDays)
                WatchedByRules = $watchedTables.Contains($_)
            }
        } | Sort-Object -Property DaysSilent -Descending)

    $sorted = @($findings | Sort-Object -Property DaysSilent -Descending)
    $enabledQueryRules = [Math]::Max(1, @($Context.QueryRules).Count)
    $affectedPct = [Math]::Round(($affectedRules.Count / $enabledQueryRules) * 100, 1)
    $score = [Math]::Max(0.0, 100 - (3 * $affectedPct))

    $status = if ($affectedRules.Count -eq 0) { 'good' }
    elseif ($affectedPct -lt 5)     { 'warning' }
    elseif ($affectedPct -lt 20)    { 'serious' }
    else                            { 'critical' }

    $headline = if ($affectedRules.Count -eq 0) {
        'Every table referenced by an enabled rule had fresh ingestion at the end of the scan window.'
    } else {
        "$($affectedRules.Count) enabled rule(s) ($affectedPct%) reference a table with no ingestion for 24+ hours."
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These rules run, but their data source stopped sending data, so they can never fire. ' +
        'Fix the feed, or retire the rule if the system is gone.') `
        -Findings $sorted -Columns @('RuleName', 'Table', 'LastSeenUtc', 'DaysSilent') `
        -Data @{ TableFreshness = $inventory } `
        -MethodNote ("Table names parsed from enabled Scheduled/NRT rule queries, matched to the workspace " +
        'Usage DataTypes (billable tables). Stale threshold: 24 hours, measured at the window end. ' +
        'Free tables and functions are not yet evaluated. Full per-table freshness rides -PassThru. ' +
        'Microsoft: monitor-data-connector-health (HC-02).')
}
