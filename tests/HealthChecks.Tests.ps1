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
