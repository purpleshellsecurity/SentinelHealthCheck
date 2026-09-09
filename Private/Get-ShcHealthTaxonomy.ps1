function Get-ShcHealthTaxonomy {
    <#
    .SYNOPSIS
        The value set Microsoft documents for the SentinelHealth and SentinelAudit
        tables: resource types, operation names, and the statuses each operation can
        report. Single source of truth for anything that matches on those strings.

    .DESCRIPTION
        Checks that filter on SentinelResourceType or Status currently hardcode their
        own tolerant matchers (see HC-01's `contains "rule"`). That works, but every
        such matcher is an independent guess about a value set nobody has written
        down in one place. This is that place.

        Two things it is NOT:

        - Not exhaustive for Reason or Description. Microsoft types Reason as an enum
          whose "possible values depend on the resource type" and then never lists
          them; Description is free text. Those are the fields that actually explain
          a failure, and there is no published catalogue for either. HC-08 exists to
          build one empirically.

        - Not an exact-match contract. The docs render Analytics rule in sentence
          case; a live tenant emitted "Analytics Rule" (HC-01, 2026-07-28). Compare
          case-insensitively and expect drift - reporting the drift is the point.

        Sources (both verified 2026-09-09):
          learn.microsoft.com/en-us/azure/sentinel/health-table-reference
          learn.microsoft.com/en-us/azure/sentinel/audit-table-reference
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # One row per documented (resource type, operation) pair with the statuses that
    # operation can report. Statuses are per-operation, not global: only automation
    # rules report 'Partial success', and only the connector failure summary reports
    # 'Informational'.
    $health = @(
        [pscustomobject]@{ ResourceType = 'Data connector'; OperationName = 'Data fetch status change';  Statuses = @('Success', 'Failure') }
        [pscustomobject]@{ ResourceType = 'Data connector'; OperationName = 'Data fetch failure summary'; Statuses = @('Informational') }
        [pscustomobject]@{ ResourceType = 'Automation rule'; OperationName = 'Automation rule run';       Statuses = @('Success', 'Partial success', 'Failure') }
        [pscustomobject]@{ ResourceType = 'Playbook';        OperationName = 'Playbook was triggered';    Statuses = @('Success', 'Failure') }
        [pscustomobject]@{ ResourceType = 'Analytics rule';  OperationName = 'Scheduled analytics rule run'; Statuses = @('Success', 'Failure') }
        [pscustomobject]@{ ResourceType = 'Analytics rule';  OperationName = 'NRT analytics rule run';    Statuses = @('Success', 'Failure') }
    )

    # SentinelAudit has covered only analytics rules since it shipped; the reference
    # page still says "other types may be added later" and is dated January 2023.
    $audit = @(
        [pscustomobject]@{ ResourceType = 'Analytics rule'; OperationName = 'Microsoft.SecurityInsights/alertRules/Write';  Statuses = @('Success', 'Failure') }
        [pscustomobject]@{ ResourceType = 'Analytics rule'; OperationName = 'Microsoft.SecurityInsights/alertRules/Delete'; Statuses = @('Success', 'Failure') }
    )

    [pscustomobject]@{
        Health              = $health
        Audit               = $audit
        HealthResourceTypes = @($health.ResourceType | Sort-Object -Unique)
        HealthOperations    = @($health.OperationName | Sort-Object -Unique)
        HealthStatuses      = @($health.Statuses | ForEach-Object { $_ } | Sort-Object -Unique)
        AuditOperations     = @($audit.OperationName | Sort-Object -Unique)
        AuditStatuses       = @($audit.Statuses | ForEach-Object { $_ } | Sort-Object -Unique)
    }
}

function Test-ShcDocumentedHealthValue {
    <#
    .SYNOPSIS
        Returns $true when an observed (OperationName, Status) pair matches something
        Microsoft documents for the given table. Comparison is case-insensitive and
        whitespace-trimmed, so tenant casing variants are NOT reported as drift -
        only genuinely unlisted values are.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][ValidateSet('Health', 'Audit')][string]$Table,
        [AllowNull()][AllowEmptyString()][string]$OperationName,
        [AllowNull()][AllowEmptyString()][string]$Status
    )

    $rows = (Get-ShcHealthTaxonomy).$Table
    $op = "$OperationName".Trim()
    $st = "$Status".Trim()

    foreach ($row in $rows) {
        if ($row.OperationName.Trim() -ine $op) { continue }
        # A known operation reporting an unknown status is still drift worth seeing,
        # so both halves have to match for the pair to count as documented.
        foreach ($known in $row.Statuses) {
            if ($known.Trim() -ieq $st) { return $true }
        }
    }
    return $false
}
