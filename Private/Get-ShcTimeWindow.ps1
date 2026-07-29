function Get-ShcTimeWindow {
    <#
    .SYNOPSIS
        Resolves -LookbackDays or a -StartDate/-EndDate pair into one UTC scan
        window: start/end datetimes, KQL-ready ISO strings, the query-API timespan,
        and the labels headlines and the report use. Every check reads time from
        this window, never from "now" directly, so historical ranges stay honest.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Lookback')]
    param(
        [Parameter(ParameterSetName = 'Lookback')]
        [ValidateRange(1, 365)]
        [int]$LookbackDays = 90,

        [Parameter(Mandatory, ParameterSetName = 'Range')]
        [datetime]$StartDate,

        [Parameter(ParameterSetName = 'Range')]
        [datetime]$EndDate
    )

    $nowUtc = (Get-Date).ToUniversalTime()
    $iso = 'yyyy-MM-ddTHH:mm:ssZ'

    if ($PSCmdlet.ParameterSetName -eq 'Range') {
        $start = $StartDate.ToUniversalTime()
        $end = if ($PSBoundParameters.ContainsKey('EndDate')) {
            if ($EndDate.ToUniversalTime() -gt $nowUtc) { throw '-EndDate cannot be in the future.' }
            $candidate = $EndDate.ToUniversalTime()
            # A date-only -EndDate means "through that day", not "up to its midnight".
            if ($EndDate.TimeOfDay -eq [timespan]::Zero) { $candidate = $candidate.AddDays(1).AddSeconds(-1) }
            if ($candidate -gt $nowUtc) { $candidate = $nowUtc }
            $candidate
        } else {
            $nowUtc
        }
        if ($start -ge $end) { throw '-StartDate must be earlier than -EndDate.' }

        $days = [Math]::Max(1, [int][Math]::Ceiling(($end - $start).TotalDays))
        if ($days -gt 365) { throw "The custom range spans $days days; the maximum scan window is 365 days." }

        $startLabel = $start.ToString('yyyy-MM-dd')
        $endLabel = $end.ToString('yyyy-MM-dd')
        return [pscustomobject]@{
            StartUtc      = $start
            EndUtc        = $end
            Days          = $days
            Label         = "the $startLabel to $endLabel UTC window"
            ShortLabel    = "$startLabel $([char]0x2192) $endLabel UTC"
            KqlStart      = $start.ToString($iso)
            KqlEnd        = $end.ToString($iso)
            Timespan      = "$($start.ToString($iso))/$($end.ToString($iso))"
            IsCustomRange = $true
        }
    }

    $start = $nowUtc.AddDays(-$LookbackDays)
    [pscustomobject]@{
        StartUtc      = $start
        EndUtc        = $nowUtc
        Days          = $LookbackDays
        Label         = "the last $LookbackDays days"
        ShortLabel    = "$LookbackDays-day lookback"
        KqlStart      = $start.ToString($iso)
        KqlEnd        = $nowUtc.ToString($iso)
        Timespan      = "P$($LookbackDays)D"
        IsCustomRange = $false
    }
}
