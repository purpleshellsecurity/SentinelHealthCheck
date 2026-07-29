@{
    # Linter config. Run locally:
    #   Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Write-Host is deliberate: these are interactive CLI tools whose real return
        # value goes through -PassThru/-OutputPath, not the success stream.
        'PSAvoidUsingWriteHost',
        # Private helpers return collections (rules, tables); a plural noun is correct.
        # The rule targets exported cmdlets, not internal helpers.
        'PSUseSingularNouns',
        # New-ShcCheckResult is a pure in-memory constructor; New-ShcReport writes the
        # local HTML report, which is the tool's intended, benign output (not a remote
        # or destructive state change). No ShouldProcess guard needed.
        'PSUseShouldProcessForStateChangingFunctions'
    )
    Rules        = @{
        PSPlaceOpenBrace                     = @{ Enable = $true; OnSameLine = $true }
        PSUseConsistentIndentation           = @{ Enable = $true; Kind = 'space'; IndentationSize = 4 }
        PSAvoidUsingCmdletAliases            = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }
    }
}
