function Test-ShcObservability {
    <#
    .SYNOPSIS
        HC-09 (was OH-00) - Detection observability prerequisites. Before grading detections,
        establish whether the workspace can even SEE them: are Sentinel health monitoring,
        audit monitoring, and query auditing enabled? All three are off by default.

    .DESCRIPTION
        This is the precondition finding. When health monitoring is off, you cannot know
        whether your analytics rules are failing to run (HC-01), and several other checks
        degrade to "not measurable." Elevating it to its own top-level check means the
        report leads with "here's why you're blind" instead of scattering it across
        footnotes.

        Enablement is inferred from table presence (the reliable signal available
        read-only): the tables exist once the feature is on and data flows.
        - SentinelHealth  (free)     -> rule/connector/automation run health   [health-audit doc]
        - SentinelAudit   (billable) -> config-change / tamper trail            [health-audit doc]
        - LAQueryLogs     (billable) -> human query activity (cost attribution) [query-audit doc]
        Caveat: a just-enabled workspace has the table but sparse data; absence is a strong
        signal the feature is off (or the workspace is brand new).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )
    $checkId = 'HC-09'
    $title   = 'Detection observability enabled'
    $weight  = 15

    # Kind sets how silence is judged:
    #   continuous    - rule runs feed it constantly; any tenant with an enabled
    #                   scheduled rule produces events daily, so no data in the
    #                   last 24h means off or broken. Penalized.
    #   eventdriven   - only records when something happens (a rule change): an
    #                   empty window is "unverified", not "off". No penalty.
    #   informational - shown for awareness, never scored. Query auditing is an
    #                   IR audit trail (who searched your logs), not detection
    #                   health.
    $features = @(
        @{ Table = 'SentinelHealth'; Name = 'Health monitoring';  Penalty = 50; Kind = 'continuous'
            Impact = 'You cannot tell whether analytics rules are failing to run, or if a data source went silent.' }
        @{ Table = 'SentinelAudit';  Name = 'Audit monitoring';   Penalty = 25; Kind = 'eventdriven'
            Impact = 'No record of who enabled/disabled/edited a rule, or when - no tamper trail.' }
        @{ Table = 'LAQueryLogs';    Name = 'Query auditing';     Penalty = 0;  Kind = 'informational'
            Impact = 'No audit trail of who searches your logs (post-incident: was data enumerated?).' }
    )

    $windowEnd = [datetime]$Context.WindowEnd
    $findings = [System.Collections.Generic.List[object]]::new()
    $score = 100
    $healthOff = $false
    $offCount = 0
    $unverifiedCount = 0
    foreach ($f in $features) {
        $probe = Get-ShcTableState -WorkspaceId $Context.WorkspaceId -TableName $f.Table -Timespan $Context.Timespan

        $ageHours = if ($null -ne $probe.LastSeenUtc) { ($windowEnd - $probe.LastSeenUtc).TotalHours } else { $null }
        $lastEvent = if ($null -eq $ageHours) { '-' }
        elseif ($ageHours -lt 1) { "$([Math]::Max(0, [Math]::Round($ageHours * 60))) min ago" }
        elseif ($ageHours -lt 48) { "$([Math]::Round($ageHours, 1)) h ago" }
        else { "$([Math]::Floor($ageHours / 24)) days ago" }

        # A continuous feed must be fresh (<24h old at the window end) to count as
        # on - week-old rows mean monitoring stopped, and stopped is blind.
        $verdict = if ($probe.State -eq 'present') {
            if ($f.Kind -eq 'continuous' -and $ageHours -gt 24) { 'stale' } else { 'on' }
        }
        elseif ($probe.State -eq 'empty' -and $f.Kind -eq 'eventdriven') { 'unverified' }
        elseif ($probe.State -eq 'empty') { 'silent' }
        else { 'off' }

        if ($verdict -in @('stale', 'silent', 'off')) {
            $score -= $f.Penalty
            if ($f.Kind -ne 'informational') {
                $offCount++
                if ($f.Table -eq 'SentinelHealth') { $healthOff = $true }
            }
        }
        if ($verdict -eq 'unverified') { $unverifiedCount++ }

        $findings.Add([pscustomobject]@{
                Feature   = $f.Name
                Table     = $f.Table
                Enabled   = switch ($verdict) {
                    'on' { 'Yes' } 'stale' { 'Stale' } 'unverified' { 'No events in window' }
                    'silent' { 'No recent data' } default { 'No' }
                }
                LastEvent = $lastEvent
                Impact    = switch ($verdict) {
                    'on' { '' }
                    'stale' { "Data stopped $lastEvent - monitoring was on and is no longer producing. $($f.Impact)" }
                    'unverified' { 'Event-driven table with no events in the window - enablement cannot be confirmed from data. The next rule change verifies it.' }
                    'silent' { "Table exists but recorded nothing in the scan window - monitoring stopped, or was only just enabled. $($f.Impact)" }
                    default { $f.Impact }
                }
            })
    }
    $score = [Math]::Max(0.0, $score)

    $status = if ($offCount -eq 0) { 'good' }
    elseif ($healthOff)  { 'serious' }
    else                 { 'warning' }

    $headline = if ($offCount -eq 0 -and $unverifiedCount -eq 0) {
        'Health and audit monitoring are on.'
    } elseif ($offCount -eq 0) {
        "Health monitoring is on; $unverifiedCount feature(s) unverified - no events in the window to prove it."
    } else {
        "$offCount scored observability feature(s) off or stale" +
        $(if ($healthOff) { ' - including health monitoring, so rule failures are invisible.' } else { '.' })
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These logs track Sentinel''s own health. When they are off, rules break and data feeds ' +
        'die with no warning. Turn them on in Sentinel Settings; SentinelHealth is free.') `
        -Findings $findings -Columns @('Feature', 'Table', 'Enabled', 'LastEvent', 'Impact') `
        -MethodNote ('Judged by last-event age, not table existence (read-only). SentinelHealth must be fresh ' +
        'within 24 hours - any enabled scheduled rule produces daily health events, so older data means ' +
        'monitoring stopped. SentinelAudit is event-driven (quiet windows are unverified, not off). Query ' +
        'auditing is informational and never scored. Off by default per Microsoft docs (HC-09).')
}
