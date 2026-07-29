function Test-ShcDisabledRules {
    <#
    .SYNOPSIS
        HC-05 (was OH-02) - The disabled-rule inventory. Disabled is a legitimate state only when
        it is a decision with a reason and a review date; usually it is where rules
        went during a noise storm and were forgotten.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-05'
    $title   = 'Disabled rule inventory'
    $weight  = 10

    $disabled = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Context.AllRules) {
        $props = $rule.properties
        if (-not $props.PSObject.Properties['enabled']) { continue }
        if ([bool]$props.enabled) { continue }

        $lastModified = ''
        if ($props.PSObject.Properties['lastModifiedUtc'] -and $props.lastModifiedUtc) {
            $lastModified = ([datetime]$props.lastModifiedUtc).ToString('yyyy-MM-dd')
        }
        $severity = if ($props.PSObject.Properties['severity']) { [string]$props.severity } else { '' }

        $disabled.Add([pscustomobject]@{
                RuleName        = $props.displayName
                Kind            = $rule.kind
                Severity        = $severity
                LastModifiedUtc = $lastModified
            })
    }

    $totalWithState = [Math]::Max(1, @($Context.AllRules | Where-Object { $_.properties.PSObject.Properties['enabled'] }).Count)
    $disabledPct = [Math]::Round(($disabled.Count / $totalWithState) * 100, 1)
    $score = [Math]::Max(0.0, 100 - (2 * $disabledPct))

    $status = if ($disabledPct -lt 5)   { 'good' }
    elseif ($disabledPct -lt 15) { 'warning' }
    elseif ($disabledPct -lt 30) { 'serious' }
    else                         { 'critical' }

    $headline = if ($disabled.Count -eq 0) {
        'No disabled analytics rules.'
    } else {
        "$($disabled.Count) of $totalWithState analytics rules ($disabledPct%) are disabled."
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These rules are switched off and provide no protection. Re-enable each one, or record ' +
        'why it is off and when that gets reviewed.') `
        -Findings @($disabled | Sort-Object -Property LastModifiedUtc -Descending) `
        -Columns @('RuleName', 'Kind', 'Severity', 'LastModifiedUtc') `
        -MethodNote 'All alert rules with enabled=false from the SecurityInsights API, all rule kinds.'
}
