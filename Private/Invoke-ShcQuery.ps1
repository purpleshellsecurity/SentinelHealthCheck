function Get-ShcLogAnalyticsEndpoint {
    <#
    .SYNOPSIS
        Resolves the Log Analytics query host and token audience for the cloud the
        caller is signed in to.

    .DESCRIPTION
        Sovereign clouds do not use api.loganalytics.io - Azure Government is
        api.loganalytics.us, China is api.loganalytics.azure.cn. Hardcoding the
        commercial host fails at the token request, so every KQL-backed check
        degrades to "not measurable" and the grade becomes meaningless. ARM calls
        need no equivalent fix: Invoke-AzRestMethod -Path already resolves against
        the context's ARM endpoint.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $context = Get-AzContext -ErrorAction Stop
    $resource = $null
    $baseUri = $null
    if ($context -and $context.Environment) {
        $azEnv = $context.Environment
        if ($azEnv.PSObject.Properties['AzureOperationalInsightsEndpointResourceId']) {
            $resource = $azEnv.AzureOperationalInsightsEndpointResourceId
        }
        if ($azEnv.PSObject.Properties['AzureOperationalInsightsEndpoint']) {
            $baseUri = $azEnv.AzureOperationalInsightsEndpoint
        }
    }

    # Older Az.Accounts builds can leave these blank. Falling back to the
    # commercial defaults keeps the common path working instead of failing the
    # whole scan over a missing environment property.
    if ([string]::IsNullOrWhiteSpace($resource)) { $resource = 'https://api.loganalytics.io' }
    if ([string]::IsNullOrWhiteSpace($baseUri)) { $baseUri = "$($resource.TrimEnd('/'))/v1" }

    [pscustomobject]@{
        Resource = $resource.TrimEnd('/')
        BaseUri  = $baseUri.TrimEnd('/')
    }
}

function Invoke-ShcQuery {
    <#
    .SYNOPSIS
        Runs a KQL query against a Log Analytics workspace via the query REST API.
        Returns rows of the primary table as objects. Read-only.

    .NOTES
        Deliberately raw REST rather than Az.OperationalInsights'
        Invoke-AzOperationalInsightsQuery: one endpoint does not justify a second
        required module - Az.Accounts stays the only dependency.

        Going raw means the SDK's conveniences become this module's job. What that
        buys and what it costs:
          - endpoint resolution -> Get-ShcLogAnalyticsEndpoint (per-cloud)
          - throttling / transient failures -> MaximumRetryCount + RetryIntervalSec
          - token shape across Az.Accounts versions -> the SecureString branch below
        Adding a call here means checking that list. The alternative,
        Az.OperationalInsights' Invoke-AzOperationalInsightsQuery, cannot express
        an absolute start/end interval - its -Timespan is a [timespan] duration -
        so it cannot serve -StartDate/-EndDate or HC-01's sub-window gate.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Back-compat shim only: Az.Accounts < 4.x hands us the token already in plaintext; converting it straight to SecureString is strictly safer than the plaintext Authorization header it replaces.')]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$Query,
        [int]$TimespanDays = 90,
        # Full ISO-8601 timespan ("P30D" or "<start>/<end>"); wins over TimespanDays.
        [string]$Timespan
    )

    $endpoint = Get-ShcLogAnalyticsEndpoint
    $token = Get-AzAccessToken -ResourceUrl $endpoint.Resource -ErrorAction Stop
    # Az.Accounts >= 4.x returns Token as SecureString; older versions return plain
    # text. Either way it reaches Invoke-RestMethod as SecureString - no plaintext
    # copy of the credential is held in a variable here.
    $secureToken = if ($token.Token -is [securestring]) {
        $token.Token
    } else {
        ConvertTo-SecureString -String $token.Token -AsPlainText -Force
    }

    $body = @{
        query    = $Query
        timespan = if ($Timespan) { $Timespan } else { "P$($TimespanDays)D" }
    } | ConvertTo-Json -Depth 4

    $params = @{
        Uri            = "$($endpoint.BaseUri)/workspaces/$WorkspaceId/query"
        Method         = 'Post'
        Authentication = 'Bearer'
        Token          = $secureToken
        ContentType    = 'application/json'
        Body           = $body
        ErrorAction    = 'Stop'
        # PowerShell 7 retries 429 and 5xx natively. The query API throttles per
        # workspace, and a scan issues ~10 queries plus one probe per referenced
        # table that Usage does not cover, so this is reachable on a large estate.
        MaximumRetryCount = 5
        RetryIntervalSec  = 5
    }
    $response = Invoke-RestMethod @params

    $table = $response.tables | Select-Object -First 1
    if (-not $table -or -not $table.rows) { return @() }

    $columnNames = @($table.columns | ForEach-Object { $_.name })
    foreach ($row in $table.rows) {
        $obj = [ordered]@{}
        for ($i = 0; $i -lt $columnNames.Count; $i++) {
            $obj[$columnNames[$i]] = $row[$i]
        }
        [pscustomobject]$obj
    }
}

function Get-ShcTableState {
    <#
    .SYNOPSIS
        Probes a table's state AND freshness in one query: returns an object with
        State ('present' = rows in the timespan, 'empty' = table resolves but no
        rows, 'missing' = table does not exist) and LastSeenUtc (the newest
        TimeGenerated found, $null unless present). A table's mere existence is
        NOT proof its feature is on - and neither is week-old data; callers judge
        the age against their own freshness bar.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$TableName,
        [string]$Timespan = 'P90D'
    )
    try {
        $rows = @(Invoke-ShcQuery -WorkspaceId $WorkspaceId -Query "$TableName | summarize LastSeen = max(TimeGenerated)" -Timespan $Timespan)
        $lastSeen = $null
        if ($rows.Count -gt 0 -and $rows[0].PSObject.Properties['LastSeen'] -and $rows[0].LastSeen) {
            $lastSeen = ConvertTo-ShcUtc $rows[0].LastSeen
        }
        [pscustomobject]@{
            State       = if ($null -ne $lastSeen) { 'present' } else { 'empty' }
            LastSeenUtc = $lastSeen
        }
    }
    catch {
        # On PowerShell 7, Invoke-RestMethod's Exception.Message is the generic
        # status line; the API's error body (where SemanticError lives) is in
        # ErrorDetails.Message. Check both.
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { '' }
        if ("$detail $($_.Exception.Message)" -match 'SemanticError|Failed to resolve table|BadArgumentError') {
            return [pscustomobject]@{ State = 'missing'; LastSeenUtc = $null }
        }
        throw
    }
}

function Test-ShcTableExists {
    <#
    .SYNOPSIS
        Returns $true when a table exists in the workspace schema (with or without
        data), $false when the query API rejects it as an unknown name. Use
        Get-ShcTableState when "exists but silent" must be treated as blind.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$TableName
    )
    (Get-ShcTableState -WorkspaceId $WorkspaceId -TableName $TableName -Timespan 'P1D').State -ne 'missing'
}
