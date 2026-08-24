function Get-ShcQueryTables {
    <#
    .SYNOPSIS
        Returns the workspace tables a KQL rule query reads from.

    .DESCRIPTION
        Matching raw query text against table names has two failure modes, and
        HC-02 hit both:

          False positives - a table named in a `// comment` or inside a string
          literal counted as "watched", so a rule got flagged for telemetry it
          never reads.

          False negatives - the candidate list came from the Usage table, which
          only lists tables that have ingested. A table that has NEVER ingested
          produces no Usage row, so rules pointed at it were invisible to the very
          check meant to catch them.

        So: strip comments and string literals first, then match against the
        workspace's real table inventory (ARM /tables) rather than against what
        happens to have billing records.

        This is still identifier matching, not a KQL parser. A table name used as
        a column alias can produce a false positive; callers should treat the
        result as "referenced", not "read from".
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Query,
        [Parameter(Mandatory)][string[]]$KnownTables
    )

    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }

    # Order matters: strings first (a // inside a string is not a comment),
    # then line comments.
    $clean = [regex]::Replace($Query, '"[^"\r\n]*"', ' ')
    $clean = [regex]::Replace($clean, "'[^'\r\n]*'", ' ')
    $clean = [regex]::Replace($clean, '//[^\r\n]*', ' ')

    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($table in $KnownTables) {
        if ([string]::IsNullOrWhiteSpace($table)) { continue }
        if ($clean -match "(?<![\w-])$([regex]::Escape($table))\b") { $found.Add($table) }
    }
    return $found.ToArray()
}
