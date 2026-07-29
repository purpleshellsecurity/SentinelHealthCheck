function Invoke-ShcQuery {
    <#
    .SYNOPSIS
        Runs a KQL query against a Log Analytics workspace via the query REST API.
        Returns rows of the primary table as objects. Read-only.

    .NOTES
        Deliberately raw REST rather than Az.OperationalInsights'
        Invoke-AzOperationalInsightsQuery: one endpoint does not justify a second
        required module - Az.Accounts stays the only dependency.
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

    $token = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -ErrorAction Stop
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
        Uri            = "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query"
        Method         = 'Post'
        Authentication = 'Bearer'
        Token          = $secureToken
        ContentType    = 'application/json'
        Body           = $body
        ErrorAction    = 'Stop'
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
            $lastSeen = ([datetime]$rows[0].LastSeen).ToUniversalTime()
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
