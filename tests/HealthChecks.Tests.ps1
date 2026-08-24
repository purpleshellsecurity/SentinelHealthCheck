#Requires -Module @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Tests for the detection-health checks. Shadows the Azure-dependent functions with
# stubs so the check logic can be exercised without a tenant.

BeforeAll {
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    $script:ShcVersion = '0.0.0-test'
    Get-ChildItem "$moduleRoot/Private" -Filter '*.ps1' -Recurse | ForEach-Object { . $_.FullName }
    Get-ChildItem "$moduleRoot/Public"  -Filter '*.ps1'           | ForEach-Object { . $_.FullName }

    # Shared stub builders. Rules mimic the ARM alert-rule shape the checks read;
    # contexts carry the same window fields the orchestrator provides.
    function script:NewStubRule {
        param($Name, $Severity = 'Medium', $Query = '')
        [pscustomobject]@{ name = $Name; kind = 'Scheduled'; properties = [pscustomobject]@{
                displayName = $Name; severity = $Severity; enabled = $true; query = $Query } }
    }
    function script:NewTableState {
        param($State, $LastSeenUtc = $null)
        [pscustomobject]@{ State = $State; LastSeenUtc = $LastSeenUtc }
    }
    function script:NewStubContext {
        param($QueryRules = @(), $AllRules = @(), $AutomationRules = @(), $EnabledRuleCount = 0)
        $w = Get-ShcTimeWindow -LookbackDays 90
        @{
            WorkspaceId = 'x'; LookbackDays = $w.Days
            WindowEnd = $w.EndUtc; WindowLabel = $w.Label
            KqlStart = $w.KqlStart; KqlEnd = $w.KqlEnd; Timespan = $w.Timespan; IsCustomRange = $false
            AllRules = $AllRules; QueryRules = $QueryRules
            EnabledRuleCount = $EnabledRuleCount; AutomationRules = $AutomationRules
        }
    }
}

Describe 'New-ShcCheckResult envelope' {
    It 'produces the fields the grader and renderer consume' {
        $r = New-ShcCheckResult -CheckId 'X-01' -Title 't' -Weight 10 -Score 50 `
            -Status 'warning' -Headline 'h'
        $r.CheckId | Should -Be 'X-01'
        $r.Weight | Should -Be 10
        $r.Score | Should -Be 50
        $r.Status | Should -Be 'warning'
    }
    It 'rejects an out-of-range status' {
        { New-ShcCheckResult -CheckId 'X' -Title 't' -Weight 1 -Score 1 `
                -Status 'bananas' -Headline 'h' } | Should -Throw
    }
    It 'defaults Data to an empty hashtable' {
        $r = New-ShcCheckResult -CheckId 'X-03' -Title 't' -Weight 10 -Score 90 `
            -Status 'good' -Headline 'h'
        $r.Data.Count | Should -Be 0
    }
}

Describe 'Get-ShcTimeWindow' {
    It 'builds a lookback window with a period timespan' {
        $w = Get-ShcTimeWindow -LookbackDays 30
        $w.Days | Should -Be 30
        $w.Timespan | Should -Be 'P30D'
        $w.IsCustomRange | Should -BeFalse
        [Math]::Round(($w.EndUtc - $w.StartUtc).TotalDays) | Should -Be 30
        $w.ShortLabel | Should -Be '30-day lookback'
    }
    It 'builds a custom range with an ISO interval timespan' {
        $today = (Get-Date).Date
        $w = Get-ShcTimeWindow -StartDate $today.AddDays(-30) -EndDate $today.AddDays(-2)
        $w.IsCustomRange | Should -BeTrue
        $w.Timespan | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        $w.EndUtc | Should -BeGreaterThan $w.StartUtc
    }
    It 'treats a date-only EndDate as through-that-day' {
        $today = (Get-Date).Date
        $dateOnly = Get-ShcTimeWindow -StartDate $today.AddDays(-30) -EndDate $today.AddDays(-2)
        $withTime = Get-ShcTimeWindow -StartDate $today.AddDays(-30) -EndDate $today.AddDays(-2).AddHours(12)
        ($dateOnly.EndUtc - $withTime.EndUtc).TotalSeconds | Should -Be 43199  # 23:59:59 vs 12:00:00
    }
    It 'defaults EndDate to now' {
        $w = Get-ShcTimeWindow -StartDate (Get-Date).Date.AddDays(-7)
        ((Get-Date).ToUniversalTime() - $w.EndUtc).TotalMinutes | Should -BeLessThan 5
    }
    It 'rejects a future EndDate, an inverted range, and a span over 365 days' {
        $today = (Get-Date).Date
        { Get-ShcTimeWindow -StartDate $today.AddDays(-7) -EndDate $today.AddDays(2) } | Should -Throw '*future*'
        { Get-ShcTimeWindow -StartDate $today.AddDays(-1) -EndDate $today.AddDays(-7) } | Should -Throw '*earlier*'
        { Get-ShcTimeWindow -StartDate $today.AddDays(-400) -EndDate $today.AddDays(-1) } | Should -Throw '*365*'
    }
}

Describe 'Test-ShcNeverFiredRules (HC-04)' {
    It 'separates never-fired rules from low-volume firing rules' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, $TimespanDays)
            $null = $WorkspaceId, $Query, $TimespanDays
            @(
                [pscustomobject]@{ AlertName = 'Busy'; Fires = 500 }
                [pscustomobject]@{ AlertName = 'Quiet'; Fires = 2 }
            )
        }
        $ctx = NewStubContext -QueryRules @((NewStubRule 'Busy' 'High'), (NewStubRule 'Quiet' 'Low'), (NewStubRule 'Silent' 'Medium'))
        $r = Test-ShcNeverFiredRules -Context $ctx
        @($r.Findings).RuleName | Should -Be @('Silent')
        @($r.Data['LowVolume']).RuleName | Should -Not -Contain 'Silent'
    }
    It 'ranks the low-volume leaderboard by ascending fire count, capped at ten' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, $TimespanDays)
            $null = $WorkspaceId, $Query, $TimespanDays
            1..12 | ForEach-Object { [pscustomobject]@{ AlertName = "R$_"; Fires = $_ * 10 } }
        }
        $ctx = NewStubContext -QueryRules @(1..12 | ForEach-Object { NewStubRule "R$_" 'Low' })
        $r = Test-ShcNeverFiredRules -Context $ctx
        $low = @($r.Data['LowVolume'])
        $low.Count | Should -Be 10
        $low[0].RuleName | Should -Be 'R1'
        $low[0].Alerts | Should -Be 10
        $low[-1].RuleName | Should -Be 'R10'
    }
}

Describe 'Test-ShcAutoClose (HC-06)' {
    It 'flags a broad, enabled auto-close automation rule as at least serious' {
        $ctx = @{
            AutomationRules = @(
                [pscustomobject]@{ name='a1'; properties=[pscustomobject]@{
                        displayName='Close all'; order=1
                        actions=@([pscustomobject]@{ actionType='ModifyProperties'
                                actionConfiguration=[pscustomobject]@{ status='Closed'; classification='BenignPositive' } })
                        triggeringLogic=[pscustomobject]@{ isEnabled=$true; conditions=@() }
                    }}
            )
        }
        $r = Test-ShcAutoClose -Context $ctx
        $r.Findings.Count | Should -Be 1
        $r.Status | Should -BeIn @('serious', 'critical')
    }
    It 'is healthy when no automation closes incidents' {
        $r = Test-ShcAutoClose -Context @{ AutomationRules = @() }
        $r.Status | Should -Be 'good'
    }
}

Describe 'Test-ShcObservability (HC-09)' {
    It 'flags health monitoring off as serious and blind to rule failures' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'missing' }  # all off
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'serious'
        $r.Headline | Should -Match 'health monitoring'
        (@($r.Findings | Where-Object Enabled -eq 'No')).Count | Should -Be 3
    }
    It 'is healthy when all observability features have fresh data' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'good'
        $r.Score  | Should -Be 100
        ($r.Findings | Where-Object Table -eq 'SentinelHealth').LastEvent | Should -Match 'min ago'
    }
    It 'is a warning (not serious) when only audit is off but health is on' {
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $Timespan
            if ($TableName -eq 'SentinelHealth') { NewTableState 'present' ((Get-Date).ToUniversalTime()) } else { NewTableState 'missing' }
        }
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'warning'
    }
    It 'treats a table with no recent data as blind, not enabled (regression)' {
        # A SentinelHealth table that exists but recorded nothing (monitoring
        # enabled once, then stopped) must never count as "on".
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $Timespan
            if ($TableName -eq 'SentinelHealth') { NewTableState 'empty' } else { NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        }
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'serious'
        ($r.Findings | Where-Object Table -eq 'SentinelHealth').Enabled | Should -Be 'No recent data'
    }
    It 'treats health data older than 24 hours as stale and blind (regression)' {
        # A continuous feed whose newest event is days old means monitoring
        # stopped - present-but-stale must never count as on.
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $Timespan
            if ($TableName -eq 'SentinelHealth') { NewTableState 'present' ((Get-Date).ToUniversalTime().AddDays(-3)) }
            else { NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        }
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'serious'
        $health = $r.Findings | Where-Object Table -eq 'SentinelHealth'
        $health.Enabled | Should -Be 'Stale'
        $health.LastEvent | Should -Match 'days ago'
    }
    It 'reports an event-driven table with no events as unverified, without a penalty' {
        # SentinelAudit only records rule changes. A stable workspace where nobody
        # touched a rule in the window is not blind - do not dock 25 points for it.
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $Timespan
            if ($TableName -eq 'SentinelAudit') { NewTableState 'empty' } else { NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        }
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'good'
        $r.Score | Should -Be 100
        ($r.Findings | Where-Object Table -eq 'SentinelAudit').Enabled | Should -Be 'No events in window'
        $r.Headline | Should -Match 'unverified'
    }
    It 'shows query auditing state without ever scoring it (informational)' {
        # Query auditing is an IR audit trail, not detection health - visible in
        # the table, never a penalty.
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $Timespan
            if ($TableName -eq 'LAQueryLogs') { NewTableState 'missing' } else { NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        }
        $r = Test-ShcObservability -Context (NewStubContext)
        $r.Status | Should -Be 'good'
        $r.Score | Should -Be 100
        ($r.Findings | Where-Object Table -eq 'LAQueryLogs').Enabled | Should -Be 'No'
    }
}

Describe 'Get-ShcTableState' {
    It 'returns present with a last-seen timestamp when data exists, empty when none does' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ LastSeen = '2026-07-28T12:00:00Z' })
        }
        $s = Get-ShcTableState -WorkspaceId 'w' -TableName 'T'
        $s.State | Should -Be 'present'
        $s.LastSeenUtc | Should -Not -BeNullOrEmpty
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ LastSeen = $null })   # summarize max() over no rows
        }
        (Get-ShcTableState -WorkspaceId 'w' -TableName 'T').State | Should -Be 'empty'
    }
    It 'classifies a missing table from the PS7-shaped error, where the API body is in ErrorDetails (regression)' {
        # PowerShell 7's Invoke-RestMethod puts "SemanticError" in ErrorDetails.Message;
        # Exception.Message is only the generic status line.
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            $ex = [System.Exception]::new('Response status code does not indicate success: 400 (Bad Request).')
            $record = [System.Management.Automation.ErrorRecord]::new($ex, 'HttpResponseException', 'InvalidOperation', $null)
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                '{"error":{"code":"BadArgumentError","innererror":{"code":"SemanticError","message":"Failed to resolve table or column expression named ''SentinelHealth''"}}}')
            throw $record
        }
        (Get-ShcTableState -WorkspaceId 'w' -TableName 'SentinelHealth').State | Should -Be 'missing'
    }
    It 'rethrows errors that are not table-resolution failures' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan; throw 'throttled: too many requests'
        }
        { Get-ShcTableState -WorkspaceId 'w' -TableName 'T' } | Should -Throw '*throttled*'
    }
}

Describe 'Test-ShcErroringRules (HC-01)' {
    It 'is a warning excluded from the grade when SentinelHealth is absent' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'missing' }
        $r = Test-ShcErroringRules -Context (NewStubContext -EnabledRuleCount 10)
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'warning'
        $r.Headline | Should -Match 'not enabled'
    }
    It 'is a warning, not a clean pass, when SentinelHealth exists but is silent (regression)' {
        # Gate on data, not table presence: an empty health table previously let
        # this check report zero failing rules - a false clean.
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'empty' }
        $r = Test-ShcErroringRules -Context (NewStubContext -EnabledRuleCount 10)
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'warning'
        $r.Headline | Should -Match 'recorded nothing'
    }
    It 'is a warning when the last health event is older than 24 hours (regression)' {
        # Present-but-stale is the same blindness: any enabled scheduled rule
        # produces daily health events, so day-old silence means monitoring stopped.
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $TableName, $Timespan
            NewTableState 'present' ((Get-Date).ToUniversalTime().AddDays(-3))
        }
        $r = Test-ShcErroringRules -Context (NewStubContext -EnabledRuleCount 10)
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'warning'
        $r.Headline | Should -Match 'recorded nothing'
    }
    It 'gates on the same sub-window its query reads, not the full scan window (regression)' {
        # Monitoring disabled 40 days ago: old rows satisfy a full-window gate while
        # the 30-day query finds nothing - a false clean. The gate must use the
        # query''s own sub-window timespan.
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $TableName; $script:hc01GateTimespan = $Timespan; NewTableState 'missing'
        }
        $null = Test-ShcErroringRules -Context (NewStubContext -EnabledRuleCount 10)
        $script:hc01GateTimespan | Should -Not -Be 'P90D'
        $script:hc01GateTimespan | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
    }
    It 'flags rules whose latest health status is not success' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ RuleName = 'R1'; LastStatus = 'Failed'; LastSeenUtc = '2026-07-01T00:00:00Z'; Detail = 'boom' })
        }
        $r = Test-ShcErroringRules -Context (NewStubContext -EnabledRuleCount 100)
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].LastStatus | Should -Be 'Failed'
        $r.Status | Should -Be 'warning'   # 1% of enabled rules
        $r.Score | Should -Be 95
    }
    It 'keeps the tolerant resource-type filter - do not simplify to an exact match' {
        # Deliberate: SentinelResourceType value variants differ across tenants; an
        # exact "Analytics Rule" match gives a false clean. This test fails if
        # someone "cleans up" the filter.
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $TimespanDays, $Timespan
            $script:hc01Query = $Query; @()
        }
        $null = Test-ShcErroringRules -Context (NewStubContext -EnabledRuleCount 10)
        $script:hc01Query | Should -Match 'SentinelResourceType contains "rule"'
        $script:hc01Query | Should -Match '!contains "automation"'
    }
}

Describe 'Test-ShcDeadDataSources (HC-02)' {
    It 'flags an enabled rule watching a table that went silent, measured at the window end' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ DataType = 'SecurityEvent'; LastSeenUtc = (Get-Date).ToUniversalTime().AddDays(-20) })
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'R1' -Query 'SecurityEvent | where EventID == 4625')
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Table | Should -Be 'SecurityEvent'
        $r.Findings[0].DaysSilent | Should -BeIn @(19, 20)
        $r.Status | Should -Be 'critical'   # 100% of enabled query rules affected
    }
    It 'does not match table names inside longer CamelCase tokens (regression)' {
        # Regression guard: an earlier bug matched 'SecurityEvent' inside tokens
        # like 'MySecurityEventTable', producing false dead-source findings.
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ DataType = 'SecurityEvent'; LastSeenUtc = (Get-Date).ToUniversalTime().AddDays(-20) })
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'R1' -Query 'MySecurityEventTable | count')
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 0
        $r.Status | Should -Be 'good'
    }
    It 'passes when referenced tables are fresh (within 24 hours)' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ DataType = 'SecurityEvent'; LastSeenUtc = (Get-Date).ToUniversalTime().AddHours(-12) })
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'R1' -Query 'SecurityEvent | take 1')
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 0
        $r.Status | Should -Be 'good'
    }
    It 'is unknown and ungraded when Usage returns nothing' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan; @()
        }
        $r = Test-ShcDeadDataSources -Context (NewStubContext)
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'unknown'
    }
    It 'keeps a full freshness inventory on Data without grading unwatched tables' {
        # A dead table nothing watches is not a detection blind spot - it never
        # becomes a finding - but the raw last-seen list rides -PassThru.
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @(
                [pscustomobject]@{ DataType = 'SecurityEvent'; LastSeenUtc = (Get-Date).ToUniversalTime().AddDays(-20) }
                [pscustomobject]@{ DataType = 'OrphanTable'; LastSeenUtc = (Get-Date).ToUniversalTime().AddDays(-40) }
            )
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'R1' -Query 'SecurityEvent | take 1')
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Table | Should -Not -Contain 'OrphanTable'
        $inventory = @($r.Data['TableFreshness'])
        $inventory.Count | Should -Be 2
        ($inventory | Where-Object Table -eq 'SecurityEvent').WatchedByRules | Should -BeTrue
        ($inventory | Where-Object Table -eq 'OrphanTable').WatchedByRules | Should -BeFalse
        $inventory[0].Table | Should -Be 'OrphanTable'   # sorted by DaysSilent descending
    }
}

Describe 'Test-ShcNoiseLeaders (HC-03)' {
    It 'scores the workspace-wide false-alarm rate and unclassified share' {
        function Test-ShcTableExists { param($WorkspaceId, $TableName) $null = $WorkspaceId, $TableName; $true }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $TimespanDays, $Timespan
            if ($Query -match 'by Title') {
                @([pscustomobject]@{ Title = 'Noisy'; Incidents = 100; TruePositive = 30; BenignPositive = 30; FalsePositive = 40; Unclassified = 0 })
            } else {
                @([pscustomobject]@{ Closed = 200; TruePositive = 30; BenignPositive = 30; FalsePositive = 40; Unclassified = 50 })
            }
        }
        $r = Test-ShcNoiseLeaders -Context (NewStubContext)
        $r.Findings[0].FalsePositivePct | Should -Be '40%'
        [Math]::Round($r.Score, 1) | Should -Be 64.5   # 100 - 0.7*40 (FP share of classified) - 0.3*25 (unclassified share)
        $r.Status | Should -Be 'warning'
    }
    It 'ranks findings by false-alarm rate with a classified-closure floor, keeps top talkers on Data' {
        function Test-ShcTableExists { param($WorkspaceId, $TableName) $null = $WorkspaceId, $TableName; $true }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $TimespanDays, $Timespan
            if ($Query -match 'by Title') {
                @(
                    # High volume, low FP rate - top talker, but not the worst finding.
                    [pscustomobject]@{ Title = 'BigTalker'; Incidents = 500; TruePositive = 90; BenignPositive = 0; FalsePositive = 10; Unclassified = 400 }
                    # Modest volume, terrible rate, enough evidence - worst finding.
                    [pscustomobject]@{ Title = 'AllNoise'; Incidents = 10; TruePositive = 0; BenignPositive = 0; FalsePositive = 10; Unclassified = 0 }
                    # 1-of-1 = 100% proves nothing: under the floor, excluded from findings.
                    [pscustomobject]@{ Title = 'OneOff'; Incidents = 1; TruePositive = 0; BenignPositive = 0; FalsePositive = 1; Unclassified = 0 }
                )
            } else {
                @([pscustomobject]@{ Closed = 511; TruePositive = 90; BenignPositive = 0; FalsePositive = 21; Unclassified = 400 })
            }
        }
        $r = Test-ShcNoiseLeaders -Context (NewStubContext)
        $r.Findings[0].RuleOrIncidentTitle | Should -Be 'AllNoise'          # 100% beats 10%
        @($r.Findings).RuleOrIncidentTitle | Should -Not -Contain 'OneOff'  # under the 5-closure floor
        $talkers = @($r.Data['TopTalkers'])
        $talkers[0].RuleOrIncidentTitle | Should -Be 'BigTalker'            # pure volume order
        $talkers.RuleOrIncidentTitle | Should -Contain 'OneOff'             # floor does not apply here
    }
    It 'is unknown when there are no closed incidents' {
        function Test-ShcTableExists { param($WorkspaceId, $TableName) $null = $WorkspaceId, $TableName; $true }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $TimespanDays, $Timespan
            if ($Query -match 'by Title') { @() } else { @([pscustomobject]@{ Closed = 0; TruePositive = 0; BenignPositive = 0; FalsePositive = 0; Unclassified = 0 }) }
        }
        $r = Test-ShcNoiseLeaders -Context (NewStubContext)
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'unknown'
    }
    It 'is unknown when SecurityIncident is unavailable' {
        function Test-ShcTableExists { param($WorkspaceId, $TableName) $null = $WorkspaceId, $TableName; $false }
        $r = Test-ShcNoiseLeaders -Context (NewStubContext)
        $r.Status | Should -Be 'unknown'
    }
}

Describe 'Test-ShcDisabledRules (HC-05)' {
    It 'inventories disabled rules with a percentage-based status' {
        $off = [pscustomobject]@{ name = 'off1'; kind = 'Scheduled'; properties = [pscustomobject]@{
                displayName = 'Off1'; severity = 'High'; enabled = $false; lastModifiedUtc = '2026-06-01T00:00:00Z' } }
        $ctx = NewStubContext -AllRules @((NewStubRule 'On1'), (NewStubRule 'On2'), $off)
        $r = Test-ShcDisabledRules -Context $ctx
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].RuleName | Should -Be 'Off1'
        $r.Findings[0].LastModifiedUtc | Should -Be '2026-06-01'
        $r.Status | Should -Be 'critical'   # 1 of 3 = 33.3%
        $r.Headline | Should -Match '33.3'
    }
    It 'is healthy with no disabled rules' {
        $r = Test-ShcDisabledRules -Context (NewStubContext -AllRules @((NewStubRule 'On1')))
        $r.Status | Should -Be 'good'
        $r.Score | Should -Be 100
    }
}

Describe 'New-ShcReport rendering' {
    It 'neutralizes untrusted rule names in the embedded JSON (no script breakout)' {
        $check = New-ShcCheckResult -CheckId 'HC-04' -Title 'T' -Weight 15 -Score 10 -Status 'critical' -Headline 'h' `
            -Findings @([pscustomobject]@{ RuleName = '<script>alert(1)</script>'; Severity = 'High'; Kind = 'Scheduled'; LastModifiedUtc = '' }) `
            -Columns @('RuleName', 'Severity', 'Kind', 'LastModifiedUtc')
        $result = [pscustomobject]@{
            Version = '0'; WorkspaceName = 'ws'; WorkspaceId = 'id'; GeneratedUtc = 'g'
            LookbackDays = 90; WindowLabel = '90-day lookback'; Score = 10.0; Grade = 'F'
            Kpis = @(); Checks = @($check)
        }
        $path = Join-Path $TestDrive 'r.html'
        New-ShcReport -Result $result -Path $path
        $html = Get-Content $path -Raw
        # The raw payload must never appear as live markup...
        $html | Should -Not -Match '<script>alert'
        # ...it is embedded unicode-escaped inside the JSON data island instead.
        $html | Should -Match '\\u003cscript\\u003ealert'
    }
    It 'embeds both leaderboards in the report payload when provided' {
        $noiseCard = New-ShcCheckResult -CheckId 'HC-03' -Title 'Alert noise and triage discipline' -Weight 15 `
            -Score 30 -Status 'serious' -Headline 'h' `
            -Findings @([pscustomobject]@{ RuleOrIncidentTitle = 'Noisy'; Incidents = [long]50; FalsePositivePct = '80%' }) `
            -Columns @('RuleOrIncidentTitle', 'Incidents', 'FalsePositivePct')
        $result = [pscustomobject]@{
            Version = '0'; WorkspaceName = 'ws'; WorkspaceId = 'id'; GeneratedUtc = 'g'
            LookbackDays = 90; WindowLabel = '90-day lookback'; Score = 30.0; Grade = 'F'
            Kpis = @(); Checks = @($noiseCard)
            Leaderboards = [pscustomobject]@{
                Noisiest = @([pscustomobject]@{ RuleOrIncidentTitle = 'Noisy'; Incidents = [long]50; FalsePositivePct = '80%' })
                Quietest = @([pscustomobject]@{ RuleName = 'Quiet'; Alerts = [long]2; Severity = 'Low'; Kind = 'Scheduled' })
            }
        }
        $path = Join-Path $TestDrive 'r2.html'
        New-ShcReport -Result $result -Path $path
        $html = Get-Content $path -Raw
        $html | Should -Match '"RuleOrIncidentTitle":"Noisy"'
        $html | Should -Match '"RuleName":"Quiet"'
    }
    It 'suppresses the noisiest leaderboard when every row is a single incident (ties rank nothing)' {
        $result = [pscustomobject]@{
            Version = '0'; WorkspaceName = 'ws'; WorkspaceId = 'id'; GeneratedUtc = 'g'
            LookbackDays = 90; WindowLabel = '90-day lookback'; Score = 90.0; Grade = 'A'
            Kpis = @(); Checks = @()
            Leaderboards = [pscustomobject]@{
                Noisiest = @(
                    [pscustomobject]@{ RuleOrIncidentTitle = 'A'; Incidents = [long]1; FalsePositivePct = '0%' }
                    [pscustomobject]@{ RuleOrIncidentTitle = 'B'; Incidents = [long]1; FalsePositivePct = '0%' }
                )
                Quietest = @()
            }
        }
        $path = Join-Path $TestDrive 'r3.html'
        New-ShcReport -Result $result -Path $path
        $html = Get-Content $path -Raw
        $html | Should -Match '"noisiest":\[\]'
        $html | Should -Not -Match '"RuleOrIncidentTitle":"A"'
    }
}

Describe 'Invoke-SentinelHealthCheck orchestration' {
    BeforeAll {
        function script:NewStubEnvelope {
            param($Id, $Score, $Weight, $Findings = @(), $Data = @{})
            $status = if ($null -eq $Score) { 'unknown' } else { 'warning' }
            New-ShcCheckResult -CheckId $Id -Title $Id -Weight $Weight -Score $Score -Status $status `
                -Headline 'h' -Findings $Findings -Data $Data
        }
    }
    It 'weights the grade over graded checks only and assembles the leaderboards' {
        function Get-AzContext { [pscustomobject]@{ Account = 'stub' } }
        function Get-ShcWorkspace {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName
            [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'ws-id' } }
        }
        function Get-ShcAlertRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function Get-ShcAutomationRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function New-ShcReport { param($Result, $Path) $null = $Result, $Path }
        function Test-ShcObservability { param($Context) $null = $Context; NewStubEnvelope 'HC-09' $null 15 }
        function Test-ShcErroringRules { param($Context) $null = $Context; NewStubEnvelope 'HC-01' 100 20 }
        function Test-ShcDeadDataSources { param($Context) $null = $Context; NewStubEnvelope 'HC-02' 50 20 }
        function Test-ShcNeverFiredRules {
            param($Context)
            $null = $Context
            NewStubEnvelope 'HC-04' $null 15 -Data @{ LowVolume = @(
                    [pscustomobject]@{ RuleName = 'Q1'; Alerts = 1; Severity = 'Low'; Kind = 'Scheduled' }) }
        }
        function Test-ShcNoiseLeaders {
            param($Context)
            $null = $Context
            NewStubEnvelope 'HC-03' $null 15 -Data @{ TopTalkers = @(1..10 | ForEach-Object {
                        [pscustomobject]@{ RuleOrIncidentTitle = "N$_"; Incidents = [long](100 - $_); FalsePositivePct = '33%' } })
            }
        }
        function Test-ShcAutoClose { param($Context) $null = $Context; NewStubEnvelope 'HC-06' $null 15 }
        function Test-ShcDisabledRules { param($Context) $null = $Context; NewStubEnvelope 'HC-05' $null 10 }

        $r = Invoke-SentinelHealthCheck -SubscriptionId 's' -ResourceGroupName 'g' -WorkspaceName 'w' -PassThru
        $r.Score | Should -Be 75   # (100*20 + 50*20) / 40; null-score checks excluded
        $r.Grade | Should -Be 'C'
        @($r.Checks).Count | Should -Be 7
        @($r.Leaderboards.Noisiest).Count | Should -Be 10
        $r.Leaderboards.Noisiest[0].RuleOrIncidentTitle | Should -Be 'N1'
        @($r.Leaderboards.Quietest).Count | Should -Be 1
        ($r.Kpis | Where-Object Label -like 'Never fired*').Label | Should -Be 'Never fired (90d)'
    }
    It 'produces an ungraded report and empty leaderboards when no check has data' {
        function Get-AzContext { [pscustomobject]@{ Account = 'stub' } }
        function Get-ShcWorkspace {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName
            [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'ws-id' } }
        }
        function Get-ShcAlertRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function Get-ShcAutomationRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function New-ShcReport { param($Result, $Path) $null = $Result, $Path }
        function Test-ShcObservability { param($Context) $null = $Context; NewStubEnvelope 'HC-09' $null 15 }
        function Test-ShcErroringRules { param($Context) $null = $Context; NewStubEnvelope 'HC-01' $null 20 }
        function Test-ShcDeadDataSources { param($Context) $null = $Context; NewStubEnvelope 'HC-02' $null 20 }
        function Test-ShcNeverFiredRules { param($Context) $null = $Context; NewStubEnvelope 'HC-04' $null 15 }
        function Test-ShcNoiseLeaders { param($Context) $null = $Context; NewStubEnvelope 'HC-03' $null 15 }
        function Test-ShcAutoClose { param($Context) $null = $Context; NewStubEnvelope 'HC-06' $null 15 }
        function Test-ShcDisabledRules { param($Context) $null = $Context; NewStubEnvelope 'HC-05' $null 10 }

        $r = Invoke-SentinelHealthCheck -SubscriptionId 's' -ResourceGroupName 'g' -WorkspaceName 'w' -PassThru
        $r.Score | Should -BeNullOrEmpty
        $r.Grade | Should -Be '?'
        @($r.Leaderboards.Noisiest).Count | Should -Be 0
        @($r.Leaderboards.Quietest).Count | Should -Be 0
    }
    It 'survives a throwing check and keys its fallback by the real check id (regression)' {
        # One failing check must not take down the run: the fallback result must
        # carry the check's HC-## id so the KPI/leaderboard lookups still resolve.
        Set-StrictMode -Version Latest
        function Get-AzContext { [pscustomobject]@{ Account = 'stub' } }
        function Get-ShcWorkspace {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName
            [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'ws-id' } }
        }
        function Get-ShcAlertRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function Get-ShcAutomationRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function New-ShcReport { param($Result, $Path) $null = $Result, $Path }
        function Test-ShcObservability { param($Context) $null = $Context; NewStubEnvelope 'HC-09' $null 15 }
        function Test-ShcErroringRules { param($Context) $null = $Context; NewStubEnvelope 'HC-01' 100 20 }
        function Test-ShcDeadDataSources { param($Context) $null = $Context; NewStubEnvelope 'HC-02' 50 20 }
        function Test-ShcNeverFiredRules { param($Context) $null = $Context; throw 'query exploded' }
        function Test-ShcNoiseLeaders { param($Context) $null = $Context; NewStubEnvelope 'HC-03' $null 15 }
        function Test-ShcAutoClose { param($Context) $null = $Context; NewStubEnvelope 'HC-06' $null 15 }
        function Test-ShcDisabledRules { param($Context) $null = $Context; NewStubEnvelope 'HC-05' $null 10 }

        $r = Invoke-SentinelHealthCheck -SubscriptionId 's' -ResourceGroupName 'g' -WorkspaceName 'w' -PassThru -WarningAction SilentlyContinue
        $fallback = $r.Checks | Where-Object CheckId -eq 'HC-04' | Select-Object -First 1
        $fallback | Should -Not -BeNullOrEmpty
        $fallback.Status | Should -Be 'unknown'
        $fallback.Headline | Should -Be 'Check failed to run.'
        $r.Grade | Should -Be 'C'   # the throwing check is excluded; 75 from HC-01/HC-02
    }
    It 'accepts workspace objects from the pipeline and writes one report per workspace (regression)' {
        # Binds ResourceGroupName/Name by property; each iteration must compute its
        # own default report path - assigning it back to $OutputPath would reuse the
        # first workspace's path for every later one.
        function Get-AzContext { [pscustomobject]@{ Account = 'stub' } }
        function Get-ShcWorkspace {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName
            [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'ws-id' } }
        }
        function Get-ShcAlertRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function Get-ShcAutomationRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        $script:pipedReports = @()
        function New-ShcReport { param($Result, $Path) $null = $Result; $script:pipedReports += $Path }
        function Test-ShcObservability { param($Context) $null = $Context; NewStubEnvelope 'HC-09' $null 15 }
        function Test-ShcErroringRules { param($Context) $null = $Context; NewStubEnvelope 'HC-01' $null 20 }
        function Test-ShcDeadDataSources { param($Context) $null = $Context; NewStubEnvelope 'HC-02' $null 20 }
        function Test-ShcNeverFiredRules { param($Context) $null = $Context; NewStubEnvelope 'HC-04' $null 15 }
        function Test-ShcNoiseLeaders { param($Context) $null = $Context; NewStubEnvelope 'HC-03' $null 15 }
        function Test-ShcAutoClose { param($Context) $null = $Context; NewStubEnvelope 'HC-06' $null 15 }
        function Test-ShcDisabledRules { param($Context) $null = $Context; NewStubEnvelope 'HC-05' $null 10 }

        $out = @(
            [pscustomobject]@{ SubscriptionId = 's'; ResourceGroupName = 'g'; Name = 'w1' }
            [pscustomobject]@{ SubscriptionId = 's'; ResourceGroupName = 'g'; Name = 'w2' }
        ) | Invoke-SentinelHealthCheck -PassThru
        @($out).Count | Should -Be 2
        $out[0].WorkspaceName | Should -Be 'w1'
        $out[1].WorkspaceName | Should -Be 'w2'
        @($script:pipedReports).Count | Should -Be 2
        $script:pipedReports[0] | Should -Not -Be $script:pipedReports[1]
    }
}

Describe 'ConvertTo-ShcUtc' {
    It 'normalises API timestamps to UTC regardless of the host time zone (regression)' {
        # The original bug: [datetime]'...Z' yields Kind=Local, so comparing it
        # against the Kind=Utc window end skewed staleness by the local offset -
        # under-reporting dead data sources east of UTC, over-reporting west.
        (ConvertTo-ShcUtc '2026-06-01T00:00:00Z').Kind | Should -Be 'Utc'
        (ConvertTo-ShcUtc '2026-06-01T00:00:00Z').ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-06-01 00:00'
        (ConvertTo-ShcUtc '2026-06-01T00:00:00.1234567Z').ToString('yyyy-MM-dd') | Should -Be '2026-06-01'
        # An explicit offset is honoured, not assumed to be local.
        (ConvertTo-ShcUtc '2026-06-01T10:00:00+10:00').ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-06-01 00:00'
    }
    It 'passes through a Kind=Utc DateTime and converts a Kind=Local one' {
        $utc = [datetime]::SpecifyKind([datetime]'2026-06-01T00:00:00', 'Utc')
        (ConvertTo-ShcUtc $utc) | Should -Be $utc
        $local = [datetime]::SpecifyKind([datetime]'2026-06-01T00:00:00', 'Local')
        (ConvertTo-ShcUtc $local) | Should -Be $local.ToUniversalTime()
        (ConvertTo-ShcUtc $local).Kind | Should -Be 'Utc'
    }
    It 'treats an offset-less timestamp as UTC rather than shifting it' {
        # ARM *Utc properties and KQL datetime columns are UTC by contract; a
        # missing offset must label, never shift.
        (ConvertTo-ShcUtc '2026-06-01T00:00:00').ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-06-01 00:00'
    }
    It 'returns null for null and blank input' {
        ConvertTo-ShcUtc $null | Should -BeNullOrEmpty
        ConvertTo-ShcUtc '' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ShcLogAnalyticsEndpoint' {
    BeforeAll {
        function script:NewStubEnv {
            param($Resource, $BaseUri)
            [pscustomobject]@{
                AzureOperationalInsightsEndpointResourceId = $Resource
                AzureOperationalInsightsEndpoint           = $BaseUri
            }
        }
    }
    It 'resolves the sovereign-cloud host instead of hardcoding commercial (regression)' {
        # Hardcoding api.loganalytics.io failed at the token request in Azure
        # Government and China, so every KQL check degraded to "not measurable".
        function Get-AzContext {
            [CmdletBinding()] param()
            [pscustomobject]@{ Environment = NewStubEnv 'https://api.loganalytics.us' 'https://api.loganalytics.us/v1' }
        }
        $e = Get-ShcLogAnalyticsEndpoint
        $e.Resource | Should -Be 'https://api.loganalytics.us'
        $e.BaseUri  | Should -Be 'https://api.loganalytics.us/v1'
    }
    It 'resolves the commercial cloud' {
        function Get-AzContext {
            [CmdletBinding()] param()
            [pscustomobject]@{ Environment = NewStubEnv 'https://api.loganalytics.io' 'https://api.loganalytics.io/v1' }
        }
        (Get-ShcLogAnalyticsEndpoint).BaseUri | Should -Be 'https://api.loganalytics.io/v1'
    }
    It 'falls back to commercial defaults when the environment omits the endpoints' {
        # Older Az.Accounts builds leave these blank; a missing property must not
        # fail the whole scan.
        function Get-AzContext {
            [CmdletBinding()] param()
            [pscustomobject]@{ Environment = [pscustomobject]@{ Name = 'Legacy' } }
        }
        $e = Get-ShcLogAnalyticsEndpoint
        $e.Resource | Should -Be 'https://api.loganalytics.io'
        $e.BaseUri  | Should -Be 'https://api.loganalytics.io/v1'
    }
}

Describe 'Invoke-SentinelHealthCheck report path handling' {
    # Stubs are declared inline in each It: dot-sourced functions live in the
    # container scope, so only a definition in the caller's own scope shadows them.
    It 'fails on a missing output directory before spending the scan (regression)' {
        # The directory used to be validated only by Set-Content at the very end,
        # so a typo in -OutputPath threw away two ARM collections and ~10 KQL
        # queries. Nothing should be fetched before the path is checked.
        $script:armCalls = 0
        function Get-AzContext { [pscustomobject]@{ Account = 'stub' } }
        function Get-ShcWorkspace {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName
            $script:armCalls++
            [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'ws-id' } }
        }
        function Get-ShcAlertRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; $script:armCalls++; @()
        }
        function Get-ShcAutomationRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; $script:armCalls++; @()
        }
        function New-ShcReport { param($Result, $Path) $null = $Result, $Path }

        $missing = Join-Path $TestDrive 'no-such-dir/report.html'
        { Invoke-SentinelHealthCheck -SubscriptionId 's' -ResourceGroupName 'g' -WorkspaceName 'w' -OutputPath $missing } |
            Should -Throw '*does not exist*'
        $script:armCalls | Should -Be 0
    }

    It 'still returns the result when the report cannot be rendered (regression)' {
        # A completed scan must survive a rendering failure - -PassThru callers
        # would otherwise lose everything the run cost them.
        function Get-AzContext { [pscustomobject]@{ Account = 'stub' } }
        function Get-ShcWorkspace {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName
            [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'ws-id' } }
        }
        function Get-ShcAlertRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function Get-ShcAutomationRules {
            param($SubscriptionId, $ResourceGroupName, $WorkspaceName)
            $null = $SubscriptionId, $ResourceGroupName, $WorkspaceName; @()
        }
        function New-ShcReport { param($Result, $Path) $null = $Result, $Path; throw 'disk on fire' }
        function Test-ShcObservability { param($Context) $null = $Context; NewStubEnvelope 'HC-09' 80 10 }
        function Test-ShcErroringRules { param($Context) $null = $Context; NewStubEnvelope 'HC-01' 80 10 }
        function Test-ShcDeadDataSources { param($Context) $null = $Context; NewStubEnvelope 'HC-02' 80 10 }
        function Test-ShcNeverFiredRules { param($Context) $null = $Context; NewStubEnvelope 'HC-04' 80 10 }
        function Test-ShcNoiseLeaders { param($Context) $null = $Context; NewStubEnvelope 'HC-03' 80 10 }
        function Test-ShcAutoClose { param($Context) $null = $Context; NewStubEnvelope 'HC-06' 80 10 }
        function Test-ShcDisabledRules { param($Context) $null = $Context; NewStubEnvelope 'HC-05' 80 10 }

        $r = Invoke-SentinelHealthCheck -SubscriptionId 's' -ResourceGroupName 'g' -WorkspaceName 'w' `
            -OutputPath (Join-Path $TestDrive 'ok.html') -PassThru -WarningAction SilentlyContinue
        $r | Should -Not -BeNullOrEmpty
        $r.Grade | Should -Be 'B'      # every check 80 -> weighted 80
        @($r.Checks).Count | Should -Be 7
    }
}

Describe 'Rendered dates are UTC, not host-local (regression)' {
    It 'HC-05 renders the UTC date for a UTC-midnight lastModifiedUtc' {
        # Previously [datetime]'2026-06-01T00:00:00Z' became Kind=Local, so this
        # rendered as 2026-05-31 for every developer west of Greenwich.
        $off = [pscustomobject]@{ name = 'off1'; kind = 'Scheduled'; properties = [pscustomobject]@{
                displayName = 'Off1'; severity = 'High'; enabled = $false; lastModifiedUtc = '2026-06-01T00:00:00Z' } }
        $r = Test-ShcDisabledRules -Context (NewStubContext -AllRules @($off))
        $r.Findings[0].LastModifiedUtc | Should -Be '2026-06-01'
    }
    It 'HC-04 renders the UTC date for a UTC-midnight lastModifiedUtc' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan; @()
        }
        $rule = [pscustomobject]@{ name = 'r1'; kind = 'Scheduled'; properties = [pscustomobject]@{
                displayName = 'Silent'; severity = 'High'; enabled = $true; query = ''
                lastModifiedUtc = '2026-06-01T00:00:00Z' } }
        $r = Test-ShcNeverFiredRules -Context (NewStubContext -QueryRules @($rule))
        $r.Findings[0].LastModifiedUtc | Should -Be '2026-06-01'
    }
    It 'HC-02 measures staleness in UTC for a string timestamp' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            # String, not DateTime: the shape that used to land as Kind=Local.
            @([pscustomobject]@{ DataType = 'SecurityEvent'
                    LastSeenUtc = (Get-Date).ToUniversalTime().AddDays(-10).ToString('yyyy-MM-ddTHH:mm:ssZ') })
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'R1' -Query 'SecurityEvent | take 1')
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].DaysSilent | Should -Be 10
    }
}

Describe 'Get-ShcQueryTables' {
    It 'ignores table names that appear only in a comment or a string (regression)' {
        # A table named in a `// comment` used to count as watched, so a rule got
        # flagged for telemetry it never reads.
        $q = @'
// AzureActivity is deliberately not used here
AuditLogs
| where Message == "see SigninLogs for detail"
| take 1
'@
        $t = Get-ShcQueryTables -Query $q -KnownTables @('AuditLogs', 'AzureActivity', 'SigninLogs')
        $t | Should -Be @('AuditLogs')
    }
    It 'finds a table regardless of where it appears in the query' {
        $q = "let x = 5;`nAKSAudit`n| where Verb == 'list'"
        Get-ShcQueryTables -Query $q -KnownTables @('AKSAudit', 'AuditLogs') | Should -Be @('AKSAudit')
    }
    It 'does not match a table name inside a longer token' {
        Get-ShcQueryTables -Query 'MySecurityEventTable | count' -KnownTables @('SecurityEvent') | Should -BeNullOrEmpty
    }
    It 'returns nothing for an empty query' {
        Get-ShcQueryTables -Query '' -KnownTables @('AuditLogs') | Should -BeNullOrEmpty
    }
}

Describe 'Test-ShcDeadDataSources - never-ingested tables (HC-02)' {
    It 'flags a rule watching a table that has never ingested (regression)' {
        # The original miss: candidate tables came from Usage, so a table with no
        # billing rows was never even considered. Eight rules watching an empty
        # AKSAudit graded as healthy.
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ DataType = 'AzureActivity'; LastSeenUtc = (Get-Date).ToUniversalTime() })
        }
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $Timespan
            if ($TableName -eq 'AKSAudit') { NewTableState 'empty' } else { NewTableState 'present' ((Get-Date).ToUniversalTime()) }
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'K8s rule' -Query 'AKSAudit | where Verb == "list"')
        $ctx.WorkspaceTables = @('AzureActivity', 'AKSAudit')

        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Table | Should -Be 'AKSAudit'
        $r.Findings[0].Issue | Should -Be 'No data'
        $r.Findings[0].LastSeenUtc | Should -Be 'never in window'
        $r.Status | Should -Be 'critical'
        $r.Headline | Should -Match 'no data at all'
    }
    It 'probes each referenced table once, not once per rule' {
        $script:probeCount = 0
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ DataType = 'AzureActivity'; LastSeenUtc = (Get-Date).ToUniversalTime() })
        }
        function Get-ShcTableState {
            param($WorkspaceId, $TableName, $Timespan)
            $null = $WorkspaceId, $TableName, $Timespan
            $script:probeCount++; NewTableState 'empty'
        }
        $ctx = NewStubContext -QueryRules @(
            (NewStubRule 'R1' -Query 'AKSAudit | take 1'),
            (NewStubRule 'R2' -Query 'AKSAudit | take 2'),
            (NewStubRule 'R3' -Query 'AKSAudit | take 3'))
        $ctx.WorkspaceTables = @('AzureActivity', 'AKSAudit')
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 3
        $script:probeCount | Should -Be 1
    }
    It 'falls back to Usage-only candidates when the table inventory is unavailable' {
        function Invoke-ShcQuery {
            param($WorkspaceId, $Query, [int]$TimespanDays = 90, [string]$Timespan)
            $null = $WorkspaceId, $Query, $TimespanDays, $Timespan
            @([pscustomobject]@{ DataType = 'SecurityEvent'; LastSeenUtc = (Get-Date).ToUniversalTime().AddDays(-20) })
        }
        $ctx = NewStubContext -QueryRules @(NewStubRule 'R1' -Query 'SecurityEvent | take 1')
        # No WorkspaceTables key at all - the degraded path.
        $r = Test-ShcDeadDataSources -Context $ctx
        @($r.Findings).Count | Should -Be 1
        $r.MethodNote | Should -Match 'Table inventory unavailable'
    }
}

Describe 'Test-ShcNeverFiredRules blindness gate (HC-04)' {
    It 'is ungraded when SecurityAlert holds no alerts at all (regression)' {
        # 23-of-23-never-fired at 0/100 is the most alarming finding this tool
        # produces. Derived from an empty table it is not a finding, it is
        # blindness - and blindness is never health.
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'empty' }
        $ctx = NewStubContext -QueryRules @((NewStubRule 'A'), (NewStubRule 'B'))
        $r = Test-ShcNeverFiredRules -Context $ctx
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'unknown'
        $r.Headline | Should -Match 'no alerts of any kind'
    }
    It 'is ungraded when the SecurityAlert table is missing' {
        function Get-ShcTableState { param($WorkspaceId, $TableName, $Timespan) $null = $WorkspaceId, $TableName, $Timespan; NewTableState 'missing' }
        $r = Test-ShcNeverFiredRules -Context (NewStubContext -QueryRules @(NewStubRule 'A'))
        $r.Score | Should -BeNullOrEmpty
        $r.Status | Should -Be 'unknown'
        $r.Headline | Should -Match 'not available'
    }
}

Describe 'Get-ShcArmErrorMessage' {
    It 'unwraps the double-encoded SecurityInsights onboarding error (regression)' {
        # Raw, this reached the user as a wall of escaped JSON plus a full
        # subscription path - on the most likely first-run mistake there is.
        $body = '{"error":{"code":"BadRequest","message":"{\"error\":{\"code\":\"BadRequest\",\"message\":\"Workspace ''law-x'' is not onboarded to Microsoft Sentinel. Please onboard through the portal.\"}}"}}'
        $msg = Get-ShcArmErrorMessage -Content $body
        $msg | Should -Be "Workspace 'law-x' is not onboarded to Microsoft Sentinel. Please onboard through the portal."
        $msg | Should -Not -Match '\\"'
        $msg | Should -Not -Match 'subscriptions/'
    }
    It 'returns a single-level error message unchanged' {
        Get-ShcArmErrorMessage -Content '{"error":{"code":"NotFound","message":"No such thing."}}' | Should -Be 'No such thing.'
    }
    It 'passes through non-JSON and empty content without throwing' {
        Get-ShcArmErrorMessage -Content 'plain text failure' | Should -Be 'plain text failure'
        Get-ShcArmErrorMessage -Content '' | Should -Be ''
        Get-ShcArmErrorMessage -Content $null | Should -Be ''
    }
}

Describe 'Get-ShcRetryDelaySeconds' {
    It 'honours a Retry-After header over its own backoff' {
        $resp = [pscustomobject]@{ Headers = @([System.Collections.Generic.KeyValuePair[string, string[]]]::new('Retry-After', @('7'))) }
        Get-ShcRetryDelaySeconds -Response $resp -Attempt 1 | Should -Be 7
    }
    It 'caps Retry-After so a hostile value cannot stall the scan' {
        $resp = [pscustomobject]@{ Headers = @([System.Collections.Generic.KeyValuePair[string, string[]]]::new('Retry-After', @('99999'))) }
        Get-ShcRetryDelaySeconds -Response $resp -Attempt 1 | Should -Be 60
    }
    It 'backs off exponentially with a ceiling when no header is present' {
        Get-ShcRetryDelaySeconds -Response $null -Attempt 1 | Should -Be 2
        Get-ShcRetryDelaySeconds -Response $null -Attempt 3 | Should -Be 8
        Get-ShcRetryDelaySeconds -Response $null -Attempt 10 | Should -Be 30
    }
}

Describe 'Get-ShcArmCollection resilience' {
    It 'retries a 429 and succeeds (regression)' {
        # Any 429 mid-paging used to kill the whole scan.
        $script:calls = 0
        # Stub the delay, not Start-Sleep: overwriting a built-in cmdlet trips the
        # linter, and Start-Sleep -Seconds 0 returns immediately anyway.
        function Get-ShcRetryDelaySeconds { param($Response, $Attempt) $null = $Response, $Attempt; 0 }
        function Invoke-AzRestMethod {
            param($Path, $Method, $ErrorAction)
            $null = $Path, $Method, $ErrorAction
            $script:calls++
            if ($script:calls -eq 1) { return [pscustomobject]@{ StatusCode = 429; Content = '{}'; Headers = @() } }
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"name":"r1"}]}'; Headers = @() }
        }
        $r = @(Get-ShcArmCollection -Path '/x')
        $script:calls | Should -Be 2
        $r.Count | Should -Be 1
        $r[0].name | Should -Be 'r1'
    }
    It 'gives up after the attempt cap and reports the real error' {
        $script:calls = 0
        function Get-ShcRetryDelaySeconds { param($Response, $Attempt) $null = $Response, $Attempt; 0 }
        function Invoke-AzRestMethod {
            param($Path, $Method, $ErrorAction)
            $null = $Path, $Method, $ErrorAction
            $script:calls++
            [pscustomobject]@{ StatusCode = 503; Content = '{"error":{"code":"Busy","message":"Service unavailable."}}'; Headers = @() }
        }
        { Get-ShcArmCollection -Path '/x' } | Should -Throw '*Service unavailable*'
        $script:calls | Should -Be 6   # first call plus five retries
    }
    It 'does not retry a real 400, and surfaces the unwrapped message' {
        $script:calls = 0
        function Invoke-AzRestMethod {
            param($Path, $Method, $ErrorAction)
            $null = $Path, $Method, $ErrorAction
            $script:calls++
            [pscustomobject]@{ StatusCode = 400
                Content = '{"error":{"code":"BadRequest","message":"{\"error\":{\"code\":\"BadRequest\",\"message\":\"Workspace ''law-x'' is not onboarded to Microsoft Sentinel.\"}}"}}'
                Headers = @() }
        }
        { Get-ShcArmCollection -Path '/x' } | Should -Throw '*not onboarded to Microsoft Sentinel*'
        $script:calls | Should -Be 1
    }
    It 'stops instead of looping when nextLink repeats (regression)' {
        $script:calls = 0
        function Invoke-AzRestMethod {
            param($Path, $Method, $ErrorAction)
            $null = $Path, $Method, $ErrorAction
            $script:calls++
            [pscustomobject]@{ StatusCode = 200
                Content = '{"value":[{"name":"r1"}],"nextLink":"https://management.azure.com/x"}'
                Headers = @() }
        }
        $r = @(Get-ShcArmCollection -Path '/x' -WarningAction SilentlyContinue)
        $script:calls | Should -Be 1   # second page is the same link, so it stops
        $r.Count | Should -Be 1
    }
}

Describe 'Source guards' {
    It 'has no Log Analytics hostname outside Get-ShcLogAnalyticsEndpoint (regression)' {
        # The hardcoded api.loganalytics.io shipped on day one and survived a
        # commit titled "Best-practices review". Pin it so it cannot come back.
        $root = Split-Path $PSScriptRoot -Parent
        $offenders = Get-ChildItem "$root/Private", "$root/Public" -Filter '*.ps1' -Recurse |
            Where-Object { $_.Name -ne 'Invoke-ShcQuery.ps1' } |
            Where-Object { (Get-Content $_.FullName -Raw) -match 'loganalytics' } |
            ForEach-Object { $_.Name }
        $offenders | Should -BeNullOrEmpty
    }
    It 'every source file parses (the linter does not catch syntax errors)' {
        # A file that fails to parse produces no PSScriptAnalyzer diagnostics at
        # all, so the CI lint step goes green on unparseable code.
        $root = Split-Path $PSScriptRoot -Parent
        $bad = @()
        foreach ($f in Get-ChildItem "$root/Private", "$root/Public" -Filter '*.ps1' -Recurse) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errors) | Out-Null
            if ($errors.Count -gt 0) { $bad += "$($f.Name): $($errors[0].Message)" }
        }
        $bad | Should -BeNullOrEmpty
    }
}
