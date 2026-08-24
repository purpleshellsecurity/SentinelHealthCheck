function Test-ShcDeadDataSources {
    <#
    .SYNOPSIS
        HC-02 (was LS-04 / RQ-05) - Enabled rules whose queries reference tables with no
        current data. A live rule watching dead data is a blind spot that looks covered.

    .DESCRIPTION
        Two ways a rule's data source can be dead, and both count:

          Stale        - the table ingested once and stopped. Caught by comparing the
                         Usage table's last-seen against the window end.
          No data      - the table has never ingested in the window at all. These do
                         NOT appear in Usage, so an earlier version of this check
                         could not see them: eight rules watching an empty AKSAudit
                         table graded as healthy. Candidate tables now come from the
                         workspace's full ARM inventory, and anything referenced but
                         absent from Usage is probed directly.
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
        $lastSeenUtc = ConvertTo-ShcUtc $row.LastSeenUtc
        # A DataType with no parseable last-seen tells us nothing about freshness;
        # grading it would invent a staleness figure out of a blank.
        if ($null -eq $lastSeenUtc) { continue }
        $tableFreshness[$row.DataType] = $lastSeenUtc
    }

    if ($tableFreshness.Count -eq 0) {
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'unknown' `
            -Headline 'Could not read table ingestion history (no usable timestamps in the Usage table).' `
            -MethodNote 'This check is excluded from the grade.'
    }

    # Candidate universe: the workspace's real table inventory. Falls back to the
    # Usage keys when the inventory could not be read - degraded, but no worse
    # than the previous behaviour.
    $knownTables = @()
    if ($Context.ContainsKey('WorkspaceTables')) { $knownTables = @($Context.WorkspaceTables) }
    $inventoryAvailable = $knownTables.Count -gt 0
    if (-not $inventoryAvailable) { $knownTables = @($tableFreshness.Keys) }

    $findings = [System.Collections.Generic.List[object]]::new()
    $affectedRules = [System.Collections.Generic.HashSet[string]]::new()
    $watchedTables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # One probe per referenced-but-unbilled table, not one per rule that names it.
    $probeCache = @{}

    foreach ($rule in $Context.QueryRules) {
        $referenced = Get-ShcQueryTables -Query $rule.properties.query -KnownTables $knownTables
        foreach ($tableName in $referenced) {
            $null = $watchedTables.Add($tableName)

            if ($tableFreshness.ContainsKey($tableName)) {
                $lastSeen = $tableFreshness[$tableName]
                $daysSilent = [int][Math]::Floor(($windowEnd - $lastSeen).TotalDays)
                if ($daysSilent -lt $staleDays) { continue }
                $issue = 'Stale'
                $lastSeenText = $lastSeen.ToString('yyyy-MM-dd HH:mm')
            }
            else {
                # Not in Usage. Either it never ingested, or it is a non-billable
                # table Usage does not track - probe to tell those apart.
                if (-not $probeCache.ContainsKey($tableName)) {
                    try {
                        $probeCache[$tableName] = Get-ShcTableState -WorkspaceId $Context.WorkspaceId `
                            -TableName $tableName -Timespan $Context.Timespan
                    }
                    catch {
                        $probeCache[$tableName] = $null
                    }
                }
                $probe = $probeCache[$tableName]
                if ($null -eq $probe) { continue }

                if ($probe.State -eq 'present') {
                    $lastSeen = ConvertTo-ShcUtc $probe.LastSeenUtc
                    if ($null -eq $lastSeen) { continue }
                    $daysSilent = [int][Math]::Floor(($windowEnd - $lastSeen).TotalDays)
                    if ($daysSilent -lt $staleDays) { continue }
                    $issue = 'Stale'
                    $lastSeenText = $lastSeen.ToString('yyyy-MM-dd HH:mm')
                }
                else {
                    # 'empty' (table resolves, no rows) or 'missing' (no such table).
                    # Both mean the rule cannot fire on this source.
                    $issue = if ($probe.State -eq 'missing') { 'Table not found' } else { 'No data' }
                    $daysSilent = $Context.LookbackDays
                    $lastSeenText = 'never in window'
                }
            }

            $null = $affectedRules.Add($rule.name)
            $findings.Add([pscustomobject]@{
                    RuleName    = $rule.properties.displayName
                    Table       = $tableName
                    Issue       = $issue
                    LastSeenUtc = $lastSeenText
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
                DaysSilent     = [int][Math]::Floor(($windowEnd - $tableFreshness[$_]).TotalDays)
                WatchedByRules = $watchedTables.Contains($_)
            }
        } | Sort-Object -Property DaysSilent -Descending)

    $sorted = @($findings | Sort-Object -Property @{ Expression = 'DaysSilent'; Descending = $true }, @{ Expression = 'RuleName'; Descending = $false })
    $enabledQueryRules = [Math]::Max(1, @($Context.QueryRules).Count)
    $affectedPct = [Math]::Round(($affectedRules.Count / $enabledQueryRules) * 100, 1)
    $score = [Math]::Max(0.0, 100 - (3 * $affectedPct))

    $status = if ($affectedRules.Count -eq 0) { 'good' }
    elseif ($affectedPct -lt 5)     { 'warning' }
    elseif ($affectedPct -lt 20)    { 'serious' }
    else                            { 'critical' }

    $noDataCount = @($sorted | Where-Object { $_.Issue -ne 'Stale' }).Count
    $headline = if ($affectedRules.Count -eq 0) {
        'Every table referenced by an enabled rule had fresh ingestion at the end of the scan window.'
    } elseif ($noDataCount -gt 0) {
        "$($affectedRules.Count) enabled rule(s) ($affectedPct%) reference a table with no usable data - $noDataCount reference a table with no data at all."
    } else {
        "$($affectedRules.Count) enabled rule(s) ($affectedPct%) reference a table with no ingestion for 24+ hours."
    }

    $inventoryNote = if ($inventoryAvailable) {
        'Candidate tables come from the workspace ARM table inventory, so tables that have never ingested are still evaluated. '
    } else {
        'Table inventory unavailable, so only tables present in Usage were evaluated; never-ingested tables are not covered in this run. '
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These rules run, but their data source is stale or empty, so they can never fire. ' +
        'Fix the feed, or retire the rule if the system is gone.') `
        -Findings $sorted -Columns @('RuleName', 'Table', 'Issue', 'LastSeenUtc', 'DaysSilent') `
        -Data @{ TableFreshness = $inventory } `
        -MethodNote ($inventoryNote +
        'Table names are matched after stripping comments and string literals, so a table named only in a ' +
        'comment no longer counts as watched. Freshness comes from the Usage table (billable) or a direct ' +
        'probe when a referenced table has no Usage rows. Stale threshold: 24 hours, measured at the window ' +
        'end. Functions and saved searches are not resolved. Full per-table freshness rides -PassThru. ' +
        'Microsoft: monitor-data-connector-health (HC-02).')
}
