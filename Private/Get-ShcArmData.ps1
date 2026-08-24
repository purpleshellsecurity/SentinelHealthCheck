function Get-ShcArmErrorMessage {
    <#
    .SYNOPSIS
        Pulls the human-readable message out of an ARM error body.

    .DESCRIPTION
        ARM nests its errors, and SecurityInsights double-encodes them: the outer
        error.message is itself a JSON document containing the real message. Raw,
        a user pointing at the wrong workspace gets a wall of escaped JSON and a
        full subscription path. Unwrap until there is nothing left to unwrap.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Content
    )

    if ([string]::IsNullOrWhiteSpace($Content)) { return '' }
    $text = $Content
    for ($depth = 0; $depth -lt 5; $depth++) {
        $payload = $null
        try { $payload = $text | ConvertFrom-Json -ErrorAction Stop } catch { break }
        if ($null -eq $payload -or -not $payload.PSObject.Properties['error']) { break }
        if (-not $payload.error.PSObject.Properties['message']) { break }
        $text = [string]$payload.error.message
    }
    return $text.Trim()
}

function Get-ShcRetryDelaySeconds {
    <#
    .SYNOPSIS
        How long to wait before retrying a throttled or transiently failed ARM call.
        Honours Retry-After when the service sends it, otherwise backs off
        exponentially with a ceiling.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Response,
        [Parameter(Mandatory)][int]$Attempt
    )

    # Azure tells us how long to wait when it throttles; guessing is worse.
    if ($null -ne $Response -and $Response.PSObject.Properties['Headers'] -and $Response.Headers) {
        foreach ($header in $Response.Headers) {
            if ($header.Key -and $header.Key -ieq 'Retry-After') {
                $raw = @($header.Value) | Select-Object -First 1
                $seconds = 0
                if ([int]::TryParse([string]$raw, [ref]$seconds) -and $seconds -gt 0) {
                    return [Math]::Min($seconds, 60)
                }
            }
        }
    }
    return [int][Math]::Min([Math]::Pow(2, $Attempt), 30)
}

function Get-ShcArmCollection {
    <#
    .SYNOPSIS
        GETs an ARM collection endpoint and follows nextLink paging. Read-only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    # Transient statuses worth retrying. Everything else is a real answer.
    $retryable = @(408, 429, 500, 502, 503, 504)
    $maxAttempts = 5

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    # A malformed nextLink that points back at a page we have already read would
    # otherwise spin forever.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    while ($next) {
        if (-not $seen.Add($next)) {
            Write-Warning "ARM paging returned a repeated nextLink; stopping to avoid a loop."
            break
        }

        $attempt = 0
        while ($true) {
            $response = Invoke-AzRestMethod -Path $next -Method GET -ErrorAction Stop
            if ($response.StatusCode -notin $retryable -or $attempt -ge $maxAttempts) { break }
            $attempt++
            $delay = Get-ShcRetryDelaySeconds -Response $response -Attempt $attempt
            Write-Verbose "ARM returned $($response.StatusCode); retry $attempt of $maxAttempts in ${delay}s."
            Start-Sleep -Seconds $delay
        }

        if ($response.StatusCode -ge 400) {
            $detail = Get-ShcArmErrorMessage -Content $response.Content
            # Pointing at a Log Analytics workspace that is not Sentinel-enabled is
            # the most likely first-run mistake; it deserves one clear line, not an
            # ARM path and a wall of escaped JSON.
            if ($detail -match 'not onboarded to Microsoft Sentinel') {
                throw "$detail Point the scan at a Sentinel-enabled workspace, or onboard this one first."
            }
            throw "ARM request failed ($($response.StatusCode)): $detail"
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
        throw "Could not read workspace '$WorkspaceName' ($($response.StatusCode)): $(Get-ShcArmErrorMessage -Content $response.Content)"
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

function Get-ShcWorkspaceTables {
    <#
    .SYNOPSIS
        All table names in the workspace schema, from ARM. Read-only.

    .DESCRIPTION
        The full inventory, not just tables that have ingested. HC-02 needs this:
        deriving candidate tables from Usage means a table that has NEVER ingested
        is absent from the candidate list entirely, so rules pointed at it are
        invisible to the check meant to catch exactly that.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
    '/tables?api-version=2022-10-01'
    return @(Get-ShcArmCollection -Path $path | ForEach-Object { $_.name })
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
