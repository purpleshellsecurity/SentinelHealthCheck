function Test-ShcAutoClose {
    <#
    .SYNOPSIS
        HC-06 (was OH-06) - Automation rules that close incidents automatically. This is where
        detections die invisibly: the analytics rule looks enabled and healthy while
        an automation rule closes every incident it raises.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-06'
    $title   = 'Automation rules silently closing incidents'
    $weight  = 15

    $findings = [System.Collections.Generic.List[object]]::new()
    $broadCount = 0
    $scopedCount = 0

    foreach ($auto in $Context.AutomationRules) {
        $props = $auto.properties
        $closeActions = @($props.actions | Where-Object {
                $_.actionType -eq 'ModifyProperties' -and
                $_.actionConfiguration.PSObject.Properties['status'] -and
                $_.actionConfiguration.status -eq 'Closed'
            })
        if ($closeActions.Count -eq 0) { continue }

        $enabled = [bool]$props.triggeringLogic.isEnabled
        $conditions = @()
        if ($props.triggeringLogic.PSObject.Properties['conditions'] -and $props.triggeringLogic.conditions) {
            $conditions = @($props.triggeringLogic.conditions)
        }
        $ruleScoped = @($conditions | Where-Object {
                $_.PSObject.Properties['conditionProperties'] -and
                $_.conditionProperties.PSObject.Properties['propertyName'] -and
                $_.conditionProperties.propertyName -eq 'IncidentRelatedAnalyticRuleIds'
            }).Count -gt 0

        $scope = if ($ruleScoped) { 'Scoped to specific rules' }
        elseif ($conditions.Count -gt 0) { 'Conditional (not rule-scoped)' }
        else { 'ALL incidents' }

        if ($enabled) {
            if ($ruleScoped) { $scopedCount++ } else { $broadCount++ }
        }

        $classification = ''
        $config = $closeActions[0].actionConfiguration
        if ($config.PSObject.Properties['classification'] -and $config.classification) {
            $classification = [string]$config.classification
        }

        $findings.Add([pscustomobject]@{
                AutomationRule       = $props.displayName
                Enabled              = $enabled
                Scope                = $scope
                ConditionCount       = $conditions.Count
                ClosesAs             = $classification
                Order                = $props.order
            })
    }

    $score = [Math]::Max(0.0, 100 - (30 * $broadCount) - (10 * $scopedCount))

    $status = if ($findings.Count -eq 0) { 'good' }
    elseif ($broadCount -eq 0) { 'warning' }
    elseif ($broadCount -eq 1) { 'serious' }
    else                       { 'critical' }

    $headline = if ($findings.Count -eq 0) {
        'No automation rules auto-close incidents.'
    } else {
        "$($findings.Count) automation rule(s) auto-close incidents - $broadCount enabled with broad or unscoped triggers."
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $score -Status $status -Headline $headline `
        -Summary ('These automation rules close incidents before anyone looks at them. Review each one - ' +
        'especially any that applies to ALL incidents.') `
        -Findings @($findings | Sort-Object -Property @{Expression = { $_.Scope -eq 'ALL incidents' }; Descending = $true }, AutomationRule) `
        -Columns @('AutomationRule', 'Enabled', 'Scope', 'ConditionCount', 'ClosesAs', 'Order') `
        -MethodNote 'Automation rules with a ModifyProperties action setting incident status to Closed, from the SecurityInsights API.'
}
