Set-StrictMode -Version Latest

# Single source of truth for the version is the manifest.
$script:ShcVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'SentinelHealthCheck.psd1')).ModuleVersion

$private = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
$public  = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue

foreach ($file in @($private) + @($public)) {
    . $file.FullName
}

Export-ModuleMember -Function 'Invoke-SentinelHealthCheck'
