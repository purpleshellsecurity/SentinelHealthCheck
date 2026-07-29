function Invoke-SentinelHealthCheck {
    <#
    .SYNOPSIS
        Scans a Microsoft Sentinel workspace for detection rot and writes an HTML
        report card. Read-only: two ARM GETs and a handful of KQL queries.

    .DESCRIPTION
        Runs seven mechanical health checks against the workspace:

          HC-09  Detection observability enabled          (runs first)
          HC-01  Rules in error or failed state           (needs SentinelHealth)
          HC-02  Enabled rules watching dead data sources
          HC-03  Alert noise and triage discipline
          HC-04  Enabled rules that never fired
          HC-05  Disabled rule inventory
          HC-06  Automation rules silently closing incidents

        Check IDs follow the HC-## detection-health series (HC-07 and HC-08 are
        reserved for planned checks). Earlier releases used
        ad hoc IDs: HC-01 was OH-01, HC-02 was LS-04, HC-03 was OH-04, HC-04
        was OH-03, HC-05 was OH-02, HC-06 was OH-06, HC-09 was OH-00.

    .PARAMETER SubscriptionId
        Subscription containing the Sentinel-enabled Log Analytics workspace.

    .PARAMETER ResourceGroupName
        Resource group of the workspace. Binds from the pipeline by property name.

    .PARAMETER WorkspaceName
        Log Analytics workspace name. Binds from the pipeline by property name;
        Name (as on Get-AzOperationalInsightsWorkspace output) is an alias.

    .PARAMETER LookbackDays
        Alert/incident/ingestion history window ending now. Default 90; common
        presets (7, 14, 30, 60, 90) tab-complete, any value 7-365 is accepted.
        Mutually exclusive with -StartDate/-EndDate.

    .PARAMETER StartDate
        Start of a custom scan window (for example '2026-05-01'). Interpreted in
        your local time zone unless an offset is given; converted to UTC. Use with
        -EndDate, or alone to scan from StartDate until now.

    .PARAMETER EndDate
        End of the custom scan window. A date-only value means "through that day"
        (23:59:59). Defaults to now; cannot be in the future; the window may span
        at most 365 days. Point-in-time checks (rule health, dead tables) are
        measured as of this moment, so a historical range reports what was broken
        then, not now.

    .PARAMETER OutputPath
        Where to write the HTML report. Default: ./SentinelHealthCheck-<workspace>-<date>.html
        When piping multiple workspaces, omit this so each report gets its own
        default name; an explicit path is reused for every piped workspace.

    .PARAMETER PassThru
        Also return the full result object (all findings, ungrouped and uncapped).

    .EXAMPLE
        Connect-AzAccount
        Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName 'rg-sec' -WorkspaceName 'law-sentinel'

    .EXAMPLE
        # Quick 14-day pulse check
        Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName 'rg-sec' -WorkspaceName 'law-sentinel' -LookbackDays 14

    .EXAMPLE
        # Historical window - what did detection health look like in Q2?
        Invoke-SentinelHealthCheck -SubscriptionId $sub -ResourceGroupName 'rg-sec' -WorkspaceName 'law-sentinel' `
            -StartDate '2026-04-01' -EndDate '2026-06-30'

    .EXAMPLE
        # Pipeline: one report per workspace. SubscriptionId still comes from the
        # command line - workspace objects do not carry it.
        Get-AzOperationalInsightsWorkspace -ResourceGroupName 'rg-sec' |
            Invoke-SentinelHealthCheck -SubscriptionId $sub

    .INPUTS
        Objects with ResourceGroupName and Name (or WorkspaceName) properties -
        for example Get-AzOperationalInsightsWorkspace output - bind by property
        name.

    .OUTPUTS
        None by default (the report is written to -OutputPath). With -PassThru,
        a result object per workspace: Grade, Score, Kpis, Leaderboards (top-10
        noisiest and quietest rules), and every check with its full, uncapped
        findings.

    .LINK
        https://github.com/purpleshellsecurity/SentinelHealthCheck

    .NOTES
        Required roles: Microsoft Sentinel Reader and Log Analytics Reader on the
        workspace. Nothing is modified; nothing leaves your environment.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Lookback')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$SubscriptionId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Name')]
        [string]$WorkspaceName,

        [Parameter(ParameterSetName = 'Lookback')]
        [ValidateRange(7, 365)]
        [ArgumentCompleter({ @('7', '14', '30', '60', '90') })]
        [int]$LookbackDays = 90,

        [Parameter(Mandatory, ParameterSetName = 'DateRange')]
        [datetime]$StartDate,

        [Parameter(ParameterSetName = 'DateRange')]
        [datetime]$EndDate,

        [string]$OutputPath,
        [switch]$PassThru
    )

    process {
        if (-not (Get-AzContext)) {
            throw 'Not signed in to Azure. Run Connect-AzAccount first (an account with Microsoft Sentinel Reader + Log Analytics Reader on the workspace).'
        }

        $windowParams = if ($PSCmdlet.ParameterSetName -eq 'DateRange') {
            $p = @{ StartDate = $StartDate }
            if ($PSBoundParameters.ContainsKey('EndDate')) { $p.EndDate = $EndDate }
            $p
        } else {
            @{ LookbackDays = $LookbackDays }
        }
        $window = Get-ShcTimeWindow @windowParams

        Write-Host "SentinelHealthCheck v$script:ShcVersion - scanning '$WorkspaceName' (read-only, $($window.ShortLabel))" -ForegroundColor Cyan

        $workspace = Get-ShcWorkspace -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
        $workspaceId = $workspace.properties.customerId

        Write-Verbose 'Collecting analytics rules and automation rules'
        $allRules = @(Get-ShcAlertRules -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName)
        $automationRules = @(Get-ShcAutomationRules -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName)

        $enabledRules = @($allRules | Where-Object {
                $_.properties.PSObject.Properties['enabled'] -and [bool]$_.properties.enabled
            })
        $queryRules = @($enabledRules | Where-Object { $_.kind -in @('Scheduled', 'NRT') })

        Write-Host "  Found $($allRules.Count) analytics rules ($($enabledRules.Count) enabled, $($queryRules.Count) Scheduled/NRT), $($automationRules.Count) automation rules."

        $context = @{
            WorkspaceId      = $workspaceId
            LookbackDays     = $window.Days
            WindowEnd        = $window.EndUtc
            WindowLabel      = $window.Label
            KqlStart         = $window.KqlStart
            KqlEnd           = $window.KqlEnd
            Timespan         = $window.Timespan
            IsCustomRange    = $window.IsCustomRange
            AllRules         = $allRules
            QueryRules       = $queryRules
            EnabledRuleCount = $enabledRules.Count
            AutomationRules  = $automationRules
        }

        # Function -> canonical check identity, in run order. The catch below reuses this
        # so a check that throws still returns a result carrying its real HC-## id (not the
        # function name). Without it, the KPI/leaderboard lookups by id find nothing and
        # crash under StrictMode - i.e. one failing check would take down the whole run.
        $checkCatalog = [ordered]@{
            'Test-ShcObservability'   = @{ Id = 'HC-09'; Title = 'Detection observability enabled' }
            'Test-ShcErroringRules'   = @{ Id = 'HC-01'; Title = 'Rules in error or failed state' }
            'Test-ShcDeadDataSources' = @{ Id = 'HC-02'; Title = 'Enabled rules watching dead data sources' }
            'Test-ShcNeverFiredRules' = @{ Id = 'HC-04'; Title = 'Enabled rules that never fired' }
            'Test-ShcNoiseLeaders'    = @{ Id = 'HC-03'; Title = 'Alert noise and triage discipline' }
            'Test-ShcAutoClose'       = @{ Id = 'HC-06'; Title = 'Automation rules silently closing incidents' }
            'Test-ShcDisabledRules'   = @{ Id = 'HC-05'; Title = 'Disabled rule inventory' }
        }

        $checks = foreach ($fn in $checkCatalog.Keys) {
            Write-Verbose "Running $fn"
            try {
                & $fn -Context $context
            }
            catch {
                Write-Warning "$fn failed: $($_.Exception.Message)"
                $meta = $checkCatalog[$fn]
                New-ShcCheckResult -CheckId $meta.Id -Title $meta.Title -Weight 0 -Score $null -Status 'unknown' `
                    -Headline 'Check failed to run.' -Summary $_.Exception.Message `
                    -MethodNote 'Excluded from the grade.'
            }
        }
        $checks = @($checks)

        $graded = @($checks | Where-Object { $null -ne $_.Score })
        $score = $null
        if ($graded.Count -gt 0) {
            $weightSum = ($graded | Measure-Object -Sum -Property Weight).Sum
            $weighted = 0.0
            foreach ($check in $graded) { $weighted += $check.Score * $check.Weight }
            $score = $weighted / [Math]::Max(1, $weightSum)
        }
        $grade = if ($null -eq $score) { '?' }
        elseif ($score -ge 90) { 'A' }
        elseif ($score -ge 80) { 'B' }
        elseif ($score -ge 70) { 'C' }
        elseif ($score -ge 60) { 'D' }
        else { 'F' }

        $neverFiredCheck = $checks | Where-Object CheckId -eq 'HC-04' | Select-Object -First 1
        $deadDataCheck   = $checks | Where-Object CheckId -eq 'HC-02' | Select-Object -First 1
        $erroringCheck   = $checks | Where-Object CheckId -eq 'HC-01' | Select-Object -First 1
        $autoCloseCheck  = $checks | Where-Object CheckId -eq 'HC-06' | Select-Object -First 1
        $noiseCheck      = $checks | Where-Object CheckId -eq 'HC-03' | Select-Object -First 1

        # Volume outliers: the rules costing the most attention and the ones closest
        # to silence. Top talkers come from HC-03's Data slot (pure incident volume -
        # its findings table ranks by false-alarm rate instead); quietest from the
        # fire counts HC-04 collects on the way to its never-fired list.
        $noisiest = @()
        if ($noiseCheck -and $noiseCheck.Data -and $noiseCheck.Data.ContainsKey('TopTalkers')) {
            $noisiest = @($noiseCheck.Data['TopTalkers'])
        }
        $quietest = @()
        if ($neverFiredCheck -and $neverFiredCheck.Data -and $neverFiredCheck.Data.ContainsKey('LowVolume')) {
            $quietest = @($neverFiredCheck.Data['LowVolume'])
        }
        $leaderboards = [pscustomobject]@{
            Noisiest = $noisiest
            Quietest = $quietest
        }

        $kpis = @(
            [pscustomobject]@{ Label = 'Analytics rules';        Value = [string]$allRules.Count;                              Status = $null }
            [pscustomobject]@{ Label = 'Enabled';                Value = [string]$enabledRules.Count;                          Status = $null }
            [pscustomobject]@{ Label = "Never fired ($($window.Days)d)"; Value = [string]@($neverFiredCheck.Findings).Count;   Status = $neverFiredCheck.Status }
            [pscustomobject]@{ Label = 'Rules on dead data';     Value = [string]@($deadDataCheck.Findings | Select-Object -Unique RuleName).Count; Status = $deadDataCheck.Status }
            [pscustomobject]@{ Label = 'Rules in error state';   Value = [string]@($erroringCheck.Findings).Count;             Status = $erroringCheck.Status }
            [pscustomobject]@{ Label = 'Auto-close automations'; Value = [string]@($autoCloseCheck.Findings).Count;            Status = $autoCloseCheck.Status }
        )

        $result = [pscustomobject]@{
            Version       = $script:ShcVersion
            WorkspaceName = $WorkspaceName
            WorkspaceId   = $workspaceId
            GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
            LookbackDays  = $window.Days
            WindowLabel   = $window.ShortLabel
            Score         = $score
            Grade         = $grade
            Kpis          = $kpis
            Leaderboards  = $leaderboards
            Checks        = $checks
        }

        # Local variable, never the parameter: assigning a defaulted path back to
        # $OutputPath would leak into the next pipeline iteration and overwrite the
        # first workspace's report with every later one.
        $reportPath = if ($OutputPath) {
            $OutputPath
        } else {
            $stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
            Join-Path (Get-Location) "SentinelHealthCheck-$WorkspaceName-$stamp.html"
        }
        New-ShcReport -Result $result -Path $reportPath

        Write-Host ''
        Write-Host "  Grade: $grade  (weighted score: $(if ($null -ne $score) { [Math]::Round($score, 0) } else { 'n/a' })/100)" -ForegroundColor Cyan
        foreach ($check in $checks) {
            $scoreLabel = if ($null -ne $check.Score) { "$([Math]::Round($check.Score, 0))/100" } else { 'not graded' }
            Write-Host ("  [{0}] {1,-45} {2,-12} {3}" -f $check.CheckId, $check.Title, $scoreLabel, $check.Headline)
        }
        Write-Host ''
        Write-Host "  Report: $reportPath" -ForegroundColor Green

        if ($PassThru) { $result }
    }
}
