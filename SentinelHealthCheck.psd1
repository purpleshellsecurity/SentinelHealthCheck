@{
    RootModule        = 'SentinelHealthCheck.psm1'
    ModuleVersion     = '0.3.1'
    GUID              = '7c1f4a2e-9b3d-4e8a-a1c6-2f5d8e7b9c01'
    Author            = 'Purpleshell Security'
    CompanyName       = 'Purpleshell Security'
    Copyright         = '(c) Purpleshell Security. All rights reserved.'
    Description       = 'Free detection-health scanner for Microsoft Sentinel. Read-only. Finds the rot in your analytics rules - broken rules, dead data sources, never-fired detections, noise leaders, and silent auto-close automation - and grades the workspace in an HTML report.'
    PowerShellVersion = '7.0'
    CompatiblePSEditions = @('Core')
    RequiredModules   = @(
        @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.12.0' }
    )
    FunctionsToExport = @('Invoke-SentinelHealthCheck')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Prerelease   = 'beta'
            Tags         = @('Sentinel', 'SIEM', 'DetectionEngineering', 'Security', 'KQL',
                'PSEdition_Core', 'Windows', 'Linux', 'MacOS')
            ProjectUri   = 'https://github.com/purpleshellsecurity/SentinelHealthCheck'
            LicenseUri   = 'https://github.com/purpleshellsecurity/SentinelHealthCheck/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/purpleshellsecurity/SentinelHealthCheck/blob/main/CHANGELOG.md'
        }
    }
}
