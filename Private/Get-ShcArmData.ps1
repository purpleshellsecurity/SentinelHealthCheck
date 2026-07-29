function Get-ShcArmCollection {
    <#
    .SYNOPSIS
        GETs an ARM collection endpoint and follows nextLink paging. Read-only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    while ($next) {
        $response = Invoke-AzRestMethod -Path $next -Method GET -ErrorAction Stop
        if ($response.StatusCode -ge 400) {
            throw "ARM request failed ($($response.StatusCode)) for '$next': $($response.Content)"
        }
        $payload = $response.Content | ConvertFrom-Json
        if ($payload.PSObject.Properties['value']) {
            foreach ($item in $payload.value) { $results.Add($item) }
        }
        $next = $null
        if ($payload.PSObject.Properties['nextLink'] -and $payload.nextLink) {
            $next = ([uri]$payload.nextLink).PathAndQuery
        }
    }
    return $results
}

function Get-ShcWorkspace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
    '?api-version=2023-09-01'
    $response = Invoke-AzRestMethod -Path $path -Method GET -ErrorAction Stop
    if ($response.StatusCode -ge 400) {
        throw "Could not read workspace '$WorkspaceName' ($($response.StatusCode)): $($response.Content)"
    }
    return ($response.Content | ConvertFrom-Json)
}

function Get-ShcAlertRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
    '/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-11-01'
    return Get-ShcArmCollection -Path $path
}

function Get-ShcAutomationRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
    '/providers/Microsoft.SecurityInsights/automationRules?api-version=2023-11-01'
    return Get-ShcArmCollection -Path $path
}

function New-ShcCheckResult {
    <#
    .SYNOPSIS
        Standard result envelope every check returns; the grader and the report
        renderer consume only this shape.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][int]$Weight,
        [AllowNull()][nullable[double]]$Score,
        [Parameter(Mandatory)][ValidateSet('good', 'warning', 'serious', 'critical', 'unknown')][string]$Status,
        [Parameter(Mandatory)][string]$Headline,
        [string]$Summary = '',
        [object[]]$Findings = @(),
        [string[]]$Columns = @(),
        [string]$MethodNote = '',
        # Check-specific extras (not rendered as findings) - e.g. HC-04 stashes the
        # low-volume leaderboard here for the orchestrator to surface.
        [hashtable]$Data = @{}
    )
    [pscustomobject]@{
        CheckId    = $CheckId
        Title      = $Title
        Weight     = $Weight
        Score      = $Score
        Status     = $Status
        Headline   = $Headline
        Summary    = $Summary
        Findings   = $Findings
        Columns    = $Columns
        MethodNote = $MethodNote
        Data       = $Data
    }
}
