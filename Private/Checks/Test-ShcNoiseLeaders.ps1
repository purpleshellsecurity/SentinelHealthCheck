function Test-ShcNoiseLeaders {
    <#
    .SYNOPSIS
        HC-03 (was OH-04 / AR-04) - False-alarm rates and triage discipline. Score is
        workspace-wide: the false-alarm share of all classified closures plus the
        share of closures that got no classification. The findings table ranks rules
        by false-alarm rate (minimum 5 classified closures, so the rate means
        something); pure volume ranking lives in the Top talkers leaderboard, which
        this check supplies via Data.TopTalkers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-03'
    $title   = 'Alert noise and triage discipline'
    $weight  = 15
    # A false-alarm rate needs evidence: rules with fewer classified closures than
    # this are excluded from the ranked table (1-of-1 = 100% proves nothing).
    $minClassified = 5

    if (-not (Test-ShcTableExists -WorkspaceId $Context.WorkspaceId -TableName 'SecurityIncident')) {
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'unknown' `
            -Headline 'SecurityIncident table not available - triage outcomes cannot be measured.' `
            -MethodNote 'This check is excluded from the grade.'
    }

    $statsQuery = @"
SecurityIncident
| where CreatedTime between (datetime($($Context.KqlStart)) .. datetime($($Context.KqlEnd)))
| summarize arg_max(LastModifiedTime, Status, Classification, Title) by IncidentNumber
| where Status =~ "Closed"
| summarize Incidents = count(),
            TruePositive = countif(Classification =~ "TruePositive"),
            BenignPositive = countif(Classification =~ "BenignPositive"),
            FalsePositive = countif(Classification =~ "FalsePositive"),
            Unclassified = countif(isempty(Classification) or Classification =~ "Undetermined")
    by Title
"@
    $perRule = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $statsQuery -Timespan $Context.Timespan)

    $totalsQuery = @"
SecurityIncident
| where CreatedTime between (datetime($($Context.KqlStart)) .. datetime($($Context.KqlEnd)))
| summarize arg_max(LastModifiedTime, Status, Classification) by IncidentNumber
| where Status =~ "Closed"
| summarize Closed = count(),
            TruePositive = countif(Classification =~ "TruePositive"),
            BenignPositive = countif(Classification =~ "BenignPositive"),
            FalsePositive = countif(Classification =~ "FalsePositive"),
            Unclassified = countif(isempty(Classification) or Classification =~ "Undetermined")
"@
    $totals = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $totalsQuery -Timespan $Context.Timespan) |
        Select-Object -First 1

    if (-not $totals -or [long]$totals.Closed -eq 0) {
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'unknown' `
            -Headline "No closed incidents in $($Context.WindowLabel) - nothing to measure." `
            -MethodNote 'This check is excluded from the grade.'
    }

    $rows = foreach ($row in $perRule) {
        $classified = [long]$row.TruePositive + [long]$row.BenignPositive + [long]$row.FalsePositive
        $fpRate = if ($classified -gt 0) { [Math]::Round(([long]$row.FalsePositive / $classified) * 100, 0) } else { $null }
        [pscustomobject]@{
            RuleOrIncidentTitle = $row.Title
            Incidents           = [long]$row.Incidents
            TruePositive        = [long]$row.TruePositive
            BenignPositive      = [long]$row.BenignPositive
            FalsePositive       = [long]$row.FalsePositive
            Unclassified        = [long]$row.Unclassified
            FalsePositivePct    = if ($null -ne $fpRate) { "$fpRate%" } else { 'n/a' }
            ClassifiedCount     = $classified
            FpRateValue         = if ($null -ne $fpRate) { [double]$fpRate } else { -1.0 }
        }
    }

    # Findings: worst false-alarm rates first, floor applied. Top talkers (pure
    # volume) go to the leaderboard via Data - two lists, two different questions.
    $findings = @($rows | Where-Object { $_.ClassifiedCount -ge $minClassified } |
            Sort-Object -Property @{ Expression = { $_.FpRateValue }; Descending = $true },
            @{ Expression = { $_.Incidents }; Descending = $true } |
            Select-Object -First 20)
    $topTalkers = @($rows |
            Sort-Object -Property @{ Expression = { $_.Incidents }; Descending = $true } |
            Select-Object -First 10 RuleOrIncidentTitle, Incidents, FalsePositivePct)

    # Score is workspace-wide: every incident counts once, so the false-alarm share
    # is naturally weighted by volume - no top-N caveat needed.
    $classifiedTotal = [long]$totals.TruePositive + [long]$totals.BenignPositive + [long]$totals.FalsePositive
    $fpPct = if ($classifiedTotal -gt 0) { [Math]::Round(([long]$totals.FalsePositive / $classifiedTotal) * 100, 1) } else { 0 }
    $unclassifiedPct = [Math]::Round(([long]$totals.Unclassified / [long]$totals.Closed) * 100, 1)

    $score = [Math]::Max(0.0, 100 - (0.7 * $fpPct) - (0.3 * $unclassifiedPct))

    $status = if ($fpPct -lt 20 -and $unclassifiedPct -lt 20) { 'good' }
    elseif ($fpPct -lt 50 -and $unclassifiedPct -lt 50) { 'warning' }
    elseif ($fpPct -lt 80) { 'serious' }
    else { 'critical' }

    $headline = if ($fpPct -eq 0 -and $unclassifiedPct -eq 0) {
        'No false alarms, and every closed incident was classified.'
    } else {
        "$fpPct% of all classified closures were false alarms; $unclassifiedPct% of closures were never classified."
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ("Rules ranked by false-alarm rate (at least $minClassified classified closures each). " +
        'Tune the worst ones, and classify every incident on close.') `
        -Findings $findings `
        -Columns @('RuleOrIncidentTitle', 'Incidents', 'TruePositive', 'BenignPositive', 'FalsePositive', 'Unclassified', 'FalsePositivePct') `
        -Data @{ TopTalkers = $topTalkers } `
        -MethodNote ("Closed incidents in $($Context.WindowLabel), latest state per incident, grouped by " +
        'incident title (usually the rule). Score: false-alarm share of all classified closures (70%) plus ' +
        "unclassified share of all closures (30%). Table lists rules with at least $minClassified classified " +
        'closures, worst rate first. Microsoft: detection-tuning (HC-03); thresholds per SOC-CMM.')
}
