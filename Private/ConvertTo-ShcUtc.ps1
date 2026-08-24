function ConvertTo-ShcUtc {
    <#
    .SYNOPSIS
        Normalises a timestamp from ARM or the Log Analytics query API into a UTC
        DateTime. Returns $null for a null/blank input.

    .DESCRIPTION
        Both APIs return ISO-8601 strings, and PowerShell's JSON deserializer
        usually converts them to DateTime with Kind=Utc - but that is an implicit
        behaviour, not a contract. Anything that reaches [datetime] as a *string*
        lands as Kind=Local instead, and the local offset then silently skews every
        comparison against the Kind=Utc window end: a table silent for 30 hours
        reads as 20 in UTC+10, so a genuinely dead data source is missed. The
        off-by-one-day dates in rendered reports come from the same place.

        Parsing with RoundtripKind honours a trailing 'Z' or offset instead of
        assuming local time; InvariantCulture keeps behaviour identical on hosts
        with a non-English culture.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][object]$Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Utc) { return $Value }
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        # Unspecified: no offset was recorded. These come from UTC-stamped sources
        # (ARM *Utc properties, KQL datetime columns), so label rather than shift.
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }

    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $parsed = [datetime]::Parse($text, [cultureinfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind)
    if ($parsed.Kind -eq [System.DateTimeKind]::Unspecified) {
        return [datetime]::SpecifyKind($parsed, [System.DateTimeKind]::Utc)
    }
    return $parsed.ToUniversalTime()
}
