function Test-ShcHealthCoverage {
    <#
    .SYNOPSIS
        HC-08 - Health signal coverage and taxonomy. Enumerates every distinct
        (resource type, operation, status, reason) combination the workspace has
        actually recorded in SentinelHealth and SentinelAudit, and names the
        documented signals that are missing. Ungraded.

    .DESCRIPTION
        HC-09 answers "is health monitoring on at all". HC-01 grades analytics-rule
        failures. Neither answers the question underneath both of them: WHICH of the
        four resource types Microsoft says report health are actually reporting it
        here, and what values do they use?

        That matters twice over.

        For the operator: Microsoft documents health signals for data connectors,
        analytics rules, automation rules and playbooks. A workspace can have health
        monitoring switched on (so HC-09 passes) while three of those four categories
        have never emitted a single event - because the diagnostic setting only
        selected some log categories. That is a blind spot no other check sees.

        For the module: Reason is typed as an enum whose "possible values depend on
        the resource type", and Microsoft never publishes the list. Description is
        free text. Those two fields carry the actual failure cause, and the only way
        to learn their value set is to observe it. Every check that matches on these
        strings today does so with a hand-tuned tolerant matcher (HC-01's
        `contains "rule"`), each an independent guess.

        So this check is deliberately ungraded (Weight 0, Score $null). A census is
        an observation, not a judgement, and scoring it would double-count HC-09.
        The census lands in .Data for -PassThru callers to aggregate across
        workspaces - which is how the undocumented Reason catalogue gets built.

    .NOTES
        Read-only. Three KQL queries, all summarised server-side. The
        ExtendedProperties key census uses arg_max to collapse to one representative
        record per (type, operation, status) BEFORE expanding the JSON bag, so it
        costs roughly ten rows of mv-expand rather than the whole window. The
        trade-off: it reports the keys present in the most recent record of each
        combination, not the union of every key ever seen.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context
    )

    $checkId = 'HC-08'
    $title   = 'Health signal coverage and taxonomy'
    # Weight 0 and a null score: informational by design. See .DESCRIPTION.
    $weight  = 0

    $taxonomy = Get-ShcHealthTaxonomy

    $healthProbe = Get-ShcTableState -WorkspaceId $Context.WorkspaceId -TableName 'SentinelHealth' -Timespan $Context.Timespan
    if ($healthProbe.State -ne 'present') {
        $headline = if ($healthProbe.State -eq 'missing') {
            'No SentinelHealth table - there is no health signal to enumerate.'
        } else {
            'SentinelHealth exists but recorded nothing in the scan window.'
        }
        return New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
            -Score $null -Status 'unknown' `
            -Headline $headline `
            -Summary ('This check inventories which Sentinel resource types are reporting health and what ' +
            'values they use. With no health data in the window there is nothing to inventory. HC-09 ' +
            'covers whether monitoring is enabled; fix that first.') `
            -MethodNote "SentinelHealth state: $($healthProbe.State). Ungraded (HC-08)."
    }

    $window = "datetime($($Context.KqlStart)) .. datetime($($Context.KqlEnd))"

    # column_ifexists keeps the census working on a tenant whose schema is missing an
    # optional column - a hard reference would fail the whole query with a
    # SemanticError and lose the columns that DO exist.
    $healthQuery = @"
SentinelHealth
| where TimeGenerated between ($window)
| summarize Events = count(), FirstSeenUtc = min(TimeGenerated), LastSeenUtc = max(TimeGenerated)
    by ResourceType = tostring(column_ifexists("SentinelResourceType", "")),
       ResourceKind = tostring(column_ifexists("SentinelResourceKind", "")),
       Operation    = tostring(OperationName),
       Status       = tostring(Status),
       Reason       = tostring(column_ifexists("Reason", ""))
| order by ResourceType asc, Operation asc, Status asc, Events desc
"@

    $rows = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $healthQuery -Timespan $Context.Timespan)

    $findings = [System.Collections.Generic.List[object]]::new()
    $drift = [System.Collections.Generic.List[object]]::new()
    $seenTypes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($row in $rows) {
        $resourceType = $row.ResourceType
        $operation    = $row.Operation
        $status       = $row.Status
        $reason       = $row.Reason
        $events       = $row.Events
        $lastSeen     = ConvertTo-ShcUtc $row.LastSeenUtc

        if ($resourceType) { $null = $seenTypes.Add($resourceType) }

        $documented = Test-ShcDocumentedHealthValue -Table 'Health' -OperationName $operation -Status $status
        if (-not $documented) {
            $drift.Add([pscustomobject]@{
                    Table = 'SentinelHealth'; ResourceType = $resourceType
                    Operation = $operation; Status = $status; Reason = $reason; Events = $events
                })
        }

        $findings.Add([pscustomobject]@{
                Table        = 'SentinelHealth'
                ResourceType = $resourceType
                Operation    = $operation
                Status       = $status
                Reason       = if ($reason) { $reason } else { '-' }
                Events       = $events
                LastSeen     = if ($lastSeen) { $lastSeen.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { '-' }
                Documented   = if ($documented) { 'Yes' } else { 'Not in Microsoft docs' }
            })
    }

    # SentinelAudit is event-driven and billable, so an empty one is normal rather
    # than broken - enumerate it when it has data and stay quiet when it does not.
    $auditRows = @()
    $auditProbe = Get-ShcTableState -WorkspaceId $Context.WorkspaceId -TableName 'SentinelAudit' -Timespan $Context.Timespan
    if ($auditProbe.State -eq 'present') {
        $auditQuery = @"
SentinelAudit
| where TimeGenerated between ($window)
| summarize Events = count(), FirstSeenUtc = min(TimeGenerated), LastSeenUtc = max(TimeGenerated)
    by ResourceType = tostring(column_ifexists("SentinelResourceType", "")),
       ResourceKind = tostring(column_ifexists("SentinelResourceKind", "")),
       Operation    = tostring(OperationName),
       Status       = tostring(Status)
| order by Operation asc, Status asc, Events desc
"@
        $auditRows = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $auditQuery -Timespan $Context.Timespan)

        foreach ($row in $auditRows) {
            $operation = $row.Operation
            $status    = $row.Status
            $lastSeen  = ConvertTo-ShcUtc $row.LastSeenUtc
            $documented = Test-ShcDocumentedHealthValue -Table 'Audit' -OperationName $operation -Status $status
            if (-not $documented) {
                $drift.Add([pscustomobject]@{
                        Table = 'SentinelAudit'; ResourceType = $row.ResourceType
                        Operation = $operation; Status = $status; Reason = ''
                        Events = $row.Events
                    })
            }
            $findings.Add([pscustomobject]@{
                    Table        = 'SentinelAudit'
                    ResourceType = $row.ResourceType
                    Operation    = $operation
                    Status       = $status
                    Reason       = '-'
                    Events       = $row.Events
                    LastSeen     = if ($lastSeen) { $lastSeen.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { '-' }
                    Documented   = if ($documented) { 'Yes' } else { 'Not in Microsoft docs' }
                })
        }
    }

    # The JSON bag's keys vary by operation AND status per the reference doc, so
    # collapse by all three before expanding. See .NOTES for the cost trade-off.
    $bagRows = @()
    try {
        $bagQuery = @"
SentinelHealth
| where TimeGenerated between ($window)
| where isnotempty(ExtendedProperties)
| summarize arg_max(TimeGenerated, ExtendedProperties)
    by ResourceType = tostring(column_ifexists("SentinelResourceType", "")),
       Operation    = tostring(OperationName),
       Status       = tostring(Status)
| mv-expand Key = bag_keys(ExtendedProperties) to typeof(string)
| project ResourceType, Operation, Status, Key
| order by ResourceType asc, Operation asc, Key asc
"@
        $bagRows = @(Invoke-ShcQuery -WorkspaceId $Context.WorkspaceId -Query $bagQuery -Timespan $Context.Timespan)
    }
    catch {
        # A census is a nice-to-have; losing it must not cost the caller the rest of
        # the check, which is the part the report renders.
        Write-Verbose "ExtendedProperties key census failed: $($_.Exception.Message)"
    }

    $missingTypes = @($taxonomy.HealthResourceTypes | Where-Object { -not $seenTypes.Contains($_) })

    $headline = if ($missingTypes.Count -eq 0) {
        "All $($taxonomy.HealthResourceTypes.Count) documented resource types are reporting health."
    } else {
        "$($missingTypes.Count) of $($taxonomy.HealthResourceTypes.Count) documented resource types have reported no health events: $($missingTypes -join ', ')."
    }
    if ($drift.Count -gt 0) {
        $headline += " $($drift.Count) value combination(s) are not in Microsoft's published list."
    }

    # Built as a statement rather than inline: the census is the part callers
    # aggregate across workspaces, and it reads better named than buried in a
    # backtick continuation.
    $data = @{
        HealthCensus         = $rows
        AuditCensus          = $auditRows
        ExtendedPropertyKeys = $bagRows
        UndocumentedValues   = @($drift)
        MissingResourceTypes = $missingTypes
    }

    New-ShcCheckResult -CheckId $checkId -Title $title -Weight $weight `
        -Score $null -Status 'good' `
        -Headline $headline `
        -Summary ('An inventory of the health signals this workspace actually produces. Microsoft documents ' +
        'health events for data connectors, analytics rules, automation rules and playbooks; a category ' +
        'reporting nothing usually means its log category was never selected in the diagnostic setting, ' +
        'so failures there are invisible. Informational - this check never affects the grade.') `
        -Findings $findings -Columns @('Table', 'ResourceType', 'Operation', 'Status', 'Reason', 'Events', 'LastSeen', 'Documented') `
        -MethodNote ('Distinct value census over the scan window. Resource-type coverage is compared against ' +
        'the values documented in health-table-reference and audit-table-reference; comparison is ' +
        'case-insensitive, so tenant casing variants are not reported as drift. Reason and Description ' +
        'have no published value set - that is what the census is for. Ungraded (HC-08).') `
        -Data $data
}
