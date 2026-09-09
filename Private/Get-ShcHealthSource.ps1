function Get-ShcHealthTableRef {
    <#
    .SYNOPSIS
        Returns the query source to use for SentinelHealth or SentinelAudit: the
        pre-built function Microsoft recommends when the workspace resolves it,
        otherwise the raw table name.

    .DESCRIPTION
        The health/audit reference says, of these two tables:

          "For best results, build your queries on the pre-built functions on
           these tables, _SentinelHealth() and _SentinelAudit(), instead of
           querying the tables directly. These functions ensure the maintenance
           of your queries' backward compatibility in the event of changes being
           made to the schema of the tables themselves."

        Every check queried the tables directly. For a module whose whole value
        is surviving schema and tenant drift, taking Microsoft's own compatibility
        shim is close to free.

        It is a preference, not a requirement: a workspace that does not resolve
        the function still has the table, so the probe falls back rather than
        failing the check. The result is cached per workspace for the life of the
        session - the answer cannot change mid-scan, and a scan issues enough
        queries already.

        Enablement is still judged from the TABLE (Get-ShcTableState), not from
        this: the function is a view over the table, so it resolves in a workspace
        where monitoring was switched on and later produced nothing, and "the
        function exists" would be a weaker signal than "rows exist".

    .LINK
        https://learn.microsoft.com/en-us/azure/sentinel/health-audit
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][ValidateSet('SentinelHealth', 'SentinelAudit')][string]$TableName
    )

    if (-not $script:ShcHealthSourceCache) { $script:ShcHealthSourceCache = @{} }
    $key = "$WorkspaceId/$TableName"
    if ($script:ShcHealthSourceCache.ContainsKey($key)) { return $script:ShcHealthSourceCache[$key] }

    $fn = "_$TableName()"
    $source = $TableName
    try {
        # summarize rather than take: cheap, and it cannot be optimised into
        # never touching the function name we are trying to resolve.
        $null = Invoke-ShcQuery -WorkspaceId $WorkspaceId -Query "$fn | summarize Rows = count()" -Timespan 'P1D'
        $source = $fn
    }
    catch {
        # Same error shape Get-ShcTableState matches on: the query API reports an
        # unresolvable name as a semantic error, and its body is in ErrorDetails.
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { '' }
        if ("$detail $($_.Exception.Message)" -notmatch 'SemanticError|Failed to resolve|BadArgumentError') {
            # A throttle or a transport failure says nothing about the function.
            # Fall back for this call without caching the wrong answer.
            Write-Verbose "Could not resolve $fn ($($_.Exception.Message)); using $TableName for this call."
            return $TableName
        }
        Write-Verbose "$fn does not resolve in this workspace; using $TableName."
    }

    $script:ShcHealthSourceCache[$key] = $source
    $source
}
