function Test-ShcNeverFiredRules {
    <#
    .SYNOPSIS
        HC-04 (was OH-03) - Enabled Scheduled/NRT rules that produced zero alerts in the lookback
        window. Each one is either a healthy low-frequency tripwire (fine, if it has
        ever been proven to fire) or a detection that silently can't fire.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-04'
    $title   = 'Enabled rules that never fired'
    $weight  = 15

    # Gate on data, not on the query returning nothing. An empty SecurityAlert
    # cannot distinguish "no rule fired" from "alerts are not reaching the table"
    # - and reporting 100% never-fired at 0/100 off an empty table is the most
    # alarming finding this tool produces. Blindness is never health.
    $alertProbe = Get-ShcTableState -WorkspaceId $Context.WorkspaceId -TableName 'SecurityAlert' -Timespan $Context.Timespan
    if ($alertProbe.State -ne 'present') {
        $headline = if ($alertProbe.State -eq 'missing') {
            'SecurityAlert table not available - rule firing cannot be measured.'
        } else {
            "SecurityAlert recorded no alerts of any kind in $($Context.WindowLabel) - rule firing cannot be measured."
        }
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'unknown' `
            -Headline $headline `
            -Summary ('With no alerts in the table there is no way to tell a rule that never fired from a ' +
            'workspace where alerts are not being written at all. Confirm alerts are reaching SecurityAlert, ' +
            'then re-run.') `
            -MethodNote "SecurityAlert state: $($alertProbe.State). Excluded from the grade."
    }

    $query = @"
SecurityAlert
| where TimeGenerated between (datetime($($Context.KqlStart)) .. datetime($($Context.KqlEnd)))
| where ProviderName in~ ("ASI Scheduled Alerts", "Azure Sentinel", "Microsoft Sentinel")
| summarize Fires = count() by AlertName
"@
    $alertCounts = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $query -Timespan $Context.Timespan)

    $firedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $alertCounts) { $null = $firedNames.Add([string]$row.AlertName) }

    $ruleByName = @{}
    foreach ($rule in $Context.QueryRules) { $ruleByName[[string]$rule.properties.displayName] = $rule }

    # The quietest firing rules - one dry spell away from never-fired, same
    # validation prompt. Surfaced by the orchestrator as a leaderboard.
    $lowVolume = @($alertCounts |
            Where-Object { $ruleByName.ContainsKey([string]$_.AlertName) } |
            Sort-Object { [long]$_.Fires }, { [string]$_.AlertName } |
            Select-Object -First 10 | ForEach-Object {
                $rule = $ruleByName[[string]$_.AlertName]
                [pscustomobject]@{
                    RuleName = $rule.properties.displayName
                    Alerts   = [long]$_.Fires
                    Severity = $rule.properties.severity
                    Kind     = $rule.kind
                }
            })

    $neverFired = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Context.QueryRules) {
        if ($firedNames.Contains([string]$rule.properties.displayName)) { continue }
        $lastModified = ''
        if ($rule.properties.PSObject.Properties['lastModifiedUtc'] -and $rule.properties.lastModifiedUtc) {
            $lastModified = (ConvertTo-ShcUtc $rule.properties.lastModifiedUtc).ToString('yyyy-MM-dd')
        }
        $neverFired.Add([pscustomobject]@{
                RuleName        = $rule.properties.displayName
                Severity        = $rule.properties.severity
                Kind            = $rule.kind
                LastModifiedUtc = $lastModified
            })
    }

    $sorted = @($neverFired | Sort-Object -Property @{Expression = {
                switch ("$($_.Severity)") {
                    'High' { 0 } 'Medium' { 1 } 'Low' { 2 } 'Informational' { 3 } default { 4 }
                }
            }}, RuleName)

    $enabledQueryRules = [Math]::Max(1, @($Context.QueryRules).Count)
    $neverFiredPct = [Math]::Round(($sorted.Count / $enabledQueryRules) * 100, 1)
    $score = [Math]::Max(0.0, 100 - (1.5 * $neverFiredPct))

    $status = if ($neverFiredPct -eq 0)   { 'good' }
    elseif ($neverFiredPct -lt 15) { 'warning' }
    elseif ($neverFiredPct -lt 40) { 'serious' }
    else                           { 'critical' }

    $headline = if ($sorted.Count -eq 0) {
        "Every enabled query rule produced at least one alert in $($Context.WindowLabel)."
    } else {
        "$($sorted.Count) of $enabledQueryRules enabled query rules ($neverFiredPct%) produced zero alerts in $($Context.WindowLabel)."
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These rules never fired in the window. Test each one to prove it still works; fix or ' +
        'retire the ones that cannot fire.') `
        -Findings $sorted -Columns @('RuleName', 'Severity', 'Kind', 'LastModifiedUtc') `
        -Data @{ LowVolume = $lowVolume } `
        -MethodNote ("Enabled Scheduled/NRT rules matched by display name against SecurityAlert in " +
        "$($Context.WindowLabel). Renamed rules can appear here wrongly, so verify first. " +
        "Detection-engineering practice, not a Microsoft mandate (HC-04).")
}
