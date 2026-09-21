#requires -Version 7.2
<#
.SYNOPSIS
    Audit complet Microsoft Intune pour PowerShell 7 / macOS. Version 1.1.

.DESCRIPTION
    Génère un rapport d'évaluation Intune de type "Maester" avec :
      - Inventaire des appareils et santé globale
      - Appareils non conformes + raisons précises de non-conformité
      - Appareils stale / très stale
      - Windows Device Health Attestation : Secure Boot, BitLocker, TPM, Code Integrity, VBS, erreurs d'attestation
      - Profils de configuration classiques + Settings Catalog / Endpoint Security
      - Politiques de conformité
      - Affectations et profils/politiques non affectés
      - Statuts de profils en erreur / conflit / non conforme
      - Applications avec échecs d'installation
      - Échecs d'enrôlement
      - Scripts PowerShell/macOS et erreurs d'exécution lorsque les rapports sont disponibles
      - Autopilot, ESP, filtres d'affectation et autres objets Intune
      - Rapport HTML interactif + exports CSV + JSON brut

    Le script utilise Microsoft Graph en lecture seule.
    Les API /beta sont utilisées uniquement pour certaines ressources Intune qui n'existent
    pas encore complètement en v1.0. Les erreurs sur une API facultative n'arrêtent pas l'audit.

.EXAMPLE
    pwsh ./Invoke-IntuneEnvironmentAssessment-Mac.ps1

.EXAMPLE
    pwsh ./Invoke-IntuneEnvironmentAssessment-Mac.ps1 -StaleDays 30 -VeryStaleDays 90

.EXAMPLE
    pwsh ./Invoke-IntuneEnvironmentAssessment-Mac.ps1 -OutputPath "$HOME/Desktop/Intune-Audit"

.NOTES
    Recommandé :
      PowerShell 7.4+
      Microsoft.Graph.Authentication 2.x+
      Un compte ayant au minimum les permissions Intune de lecture nécessaires.

    Scopes Graph demandés :
      DeviceManagementManagedDevices.Read.All
      DeviceManagementConfiguration.Read.All
      DeviceManagementApps.Read.All
      DeviceManagementServiceConfig.Read.All

    Aucune modification n'est effectuée dans Intune.

    Version 1.1:
      - Corrige les erreurs StrictMode sur les propriétés Graph facultatives (@odata.type, etc.)
      - Utilise des colonnes select explicites pour les exports Intune
      - Bascule automatiquement beta <-> v1.0 en cas d'échec d'un export
      - Les rapports facultatifs en erreur n'arrêtent jamais l'audit
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Join-Path $HOME ("Intune-Assessment-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))),

    [Parameter()]
    [ValidateRange(1,3650)]
    [int]$StaleDays = 30,

    [Parameter()]
    [ValidateRange(1,3650)]
    [int]$VeryStaleDays = 90,

    [Parameter()]
    [ValidateRange(1,60)]
    [int]$EnrollmentFailureLookbackDays = 30,

    [Parameter()]
    [switch]$SkipAppAnalysis,

    [Parameter()]
    [switch]$SkipAssignmentAnalysis,

    [Parameter()]
    [switch]$SkipOptionalReports,

    [Parameter()]
    [switch]$InteractiveBrowser,

    [Parameter()]
    [switch]$NoOpenReport
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version 2.0

if ($VeryStaleDays -lt $StaleDays) {
    throw "-VeryStaleDays doit être supérieur ou égal à -StaleDays."
}

# region Helpers

function Write-Step {
    param([string]$Message)
    Write-Host ("[>] {0}" -f $Message) -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host ("[+] {0}" -f $Message) -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("[!] {0}" -f $Message) -ForegroundColor Yellow
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function ConvertTo-SafeFileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return "Unnamed" }
    $safe = $Name -replace '[\\/:*?"<>|]', '_'
    $safe = $safe -replace '\s+', '_'
    return $safe.Trim('_')
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Names,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    foreach ($name in $Names) {
        $prop = $Object.PSObject.Properties[$name]
        if ($null -ne $prop -and $null -ne $prop.Value -and "$($prop.Value)" -ne "") {
            return $prop.Value
        }
    }
    return $Default
}

function ConvertTo-DateTimeSafe {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace("$Value")) { return $null }
    try { return [datetimeoffset]::Parse("$Value") } catch { return $null }
}

function ConvertTo-IntSafe {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq "") { return 0 }
    $n = 0
    if ([int]::TryParse("$Value", [ref]$n)) { return $n }
    return 0
}

function Test-PositiveState {
    param($Value)
    if ($null -eq $Value) { return $false }
    $s = "$Value".Trim().ToLowerInvariant()
    return $s -in @("on","enabled","enable","true","1","yes","compliant","healthy","passed","pass")
}

function Test-NegativeState {
    param($Value)
    if ($null -eq $Value) { return $false }
    $s = "$Value".Trim().ToLowerInvariant()
    return $s -in @("off","disabled","disable","false","0","no","failed","fail","error","noncompliant","non-compliant")
}

function Test-FailureLike {
    param($Value)
    if ($null -eq $Value) { return $false }
    $s = "$Value".Trim()
    if ($s -match '(?i)error|failed|failure|conflict|non.?compliant|not.?compliant|fatal|invalid') { return $true }
    return $false
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory)][ValidateSet("GET","POST","PUT","PATCH","DELETE")][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body = $null,
        [int]$MaxRetries = 6
    )

    $attempt = 0
    do {
        try {
            if ($null -eq $Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType PSObject
            } else {
                $json = $Body | ConvertTo-Json -Depth 20
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType "application/json" -OutputType PSObject
            }
        } catch {
            $attempt++
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
            $retryable = $statusCode -in @(429,500,502,503,504)
            if (-not $retryable -or $attempt -gt $MaxRetries) {
                throw
            }

            $sleep = [math]::Min(60, [math]::Pow(2, $attempt))
            Write-Warn "Graph HTTP $statusCode sur $Uri. Nouvelle tentative dans $sleep s..."
            Start-Sleep -Seconds $sleep
        }
    } while ($true)
}

function Get-GraphCollection {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$Optional
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri

    try {
        while ($next) {
            $response = Invoke-GraphRequestWithRetry -Method GET -Uri $next
            if ($null -ne $response.PSObject.Properties["value"]) {
                foreach ($item in @($response.value)) {
                    $items.Add($item)
                }
                $nextProp = $response.PSObject.Properties['@odata.nextLink']
                if ($null -ne $nextProp) {
                    $next = $nextProp.Value
                } else {
                    $next = $null
                }
            } else {
                $items.Add($response)
                $next = $null
            }
        }
    } catch {
        if ($Optional) {
            Write-Warn "API facultative non disponible: $Uri"
            Write-Warn "  $($_.Exception.Message)"
            return @()
        }
        throw
    }

    return @($items)
}

function Export-JsonData {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Data
    )
    $path = Join-Path $script:JsonPath ("{0}.json" -f (ConvertTo-SafeFileName $Name))
    @($Data) | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-CsvData {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Data
    )
    $path = Join-Path $script:CsvPath ("{0}.csv" -f (ConvertTo-SafeFileName $Name))
    @($Data) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    return $path
}

function Export-IntuneReport {
    param(
        [Parameter(Mandatory)][string]$ReportName,
        [string[]]$Select = @(),
        [string]$Filter = "",
        [int]$TimeoutSeconds = 420
    )

    Write-Step "Export du rapport Intune: $ReportName"

    $body = @{
        reportName = $ReportName
        format     = "csv"
    }

    if ($Select.Count -gt 0) { $body.select = $Select }
    if (-not [string]::IsNullOrWhiteSpace($Filter)) { $body.filter = $Filter }

    # Microsoft documente v1.0 et beta pour exportJobs. On tente beta d'abord,
    # puis v1.0 si le service de reporting retourne une erreur 4xx/5xx.
    $apiVersions = @("beta","v1.0")
    $lastError = $null

    foreach ($apiVersion in $apiVersions) {
        try {
            $baseUri = "https://graph.microsoft.com/$apiVersion/deviceManagement/reports/exportJobs"
            Write-Host "    API: $apiVersion" -ForegroundColor DarkGray

            $job = Invoke-GraphRequestWithRetry -Method POST -Uri $baseUri -Body $body
            $jobId = Get-PropertyValue -Object $job -Names @("id") -Default ""
            if ([string]::IsNullOrWhiteSpace("$jobId")) {
                throw "L'API exportJobs n'a pas retourné de job ID."
            }

            $jobUri = "$baseUri/$jobId"
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            $current = $job

            do {
                $status = Get-PropertyValue -Object $current -Names @("status") -Default "unknown"
                if ("$status" -eq "completed") { break }
                if ("$status" -eq "failed") {
                    throw "Le job d'export Intune a échoué."
                }
                if ((Get-Date) -gt $deadline) {
                    throw "Timeout après $TimeoutSeconds secondes."
                }

                Start-Sleep -Seconds 3
                $current = Invoke-GraphRequestWithRetry -Method GET -Uri $jobUri
            } while ($true)

            $downloadUrl = Get-PropertyValue -Object $current -Names @("url") -Default ""
            if ([string]::IsNullOrWhiteSpace("$downloadUrl")) {
                throw "Le rapport est terminé mais aucune URL de téléchargement n'a été retournée."
            }

            $reportFolder = Join-Path $script:RawReportsPath (ConvertTo-SafeFileName $ReportName)
            New-Directory $reportFolder

            # Nettoyer les CSV d'un précédent essai du même rapport pour éviter les doublons.
            Get-ChildItem -LiteralPath $reportFolder -Filter "*.csv" -File -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue

            $zipPath = Join-Path $reportFolder "$ReportName.zip"
            Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath
            Expand-Archive -LiteralPath $zipPath -DestinationPath $reportFolder -Force

            $csvFiles = @(Get-ChildItem -LiteralPath $reportFolder -Filter "*.csv" -File -Recurse)
            if ($csvFiles.Count -eq 0) {
                Write-Warn "Rapport $ReportName téléchargé, mais aucun CSV trouvé."
                return @()
            }

            $rows = [System.Collections.Generic.List[object]]::new()
            foreach ($csv in $csvFiles) {
                foreach ($row in @(Import-Csv -LiteralPath $csv.FullName)) {
                    $rows.Add($row)
                }
            }

            Write-Ok "$ReportName : $($rows.Count) ligne(s)"
            return @($rows)
        } catch {
            $lastError = $_
            Write-Warn "$ReportName via $apiVersion : $($_.Exception.Message)"
            if ($apiVersion -ne $apiVersions[-1]) {
                Write-Warn "Nouvel essai du rapport via l'autre version de l'API Graph..."
            }
        }
    }

    if ($lastError) {
        Write-Warn "Impossible d'exporter $ReportName après les deux endpoints Graph. Le reste de l'audit continue."
    }
    return @()
}

function Get-AssignmentRows {
    param(
        [Parameter(Mandatory)][string]$ProfileType,
        [Parameter(Mandatory)][string]$ProfileId,
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Uri
    )

    $assignments = @(Get-GraphCollection -Uri $Uri -Optional)
    if ($assignments.Count -eq 0) {
        return @([pscustomobject]@{
            ProfileType   = $ProfileType
            ProfileId     = $ProfileId
            ProfileName   = $ProfileName
            HasAssignment = $false
            TargetType    = ""
            TargetGroupId = ""
            FilterType    = ""
            FilterId      = ""
        })
    }

    $rows = foreach ($a in $assignments) {
        $target = Get-PropertyValue -Object $a -Names @("target") -Default $null
        $odataType = Get-PropertyValue -Object $target -Names @("@odata.type") -Default ""
        [pscustomobject]@{
            ProfileType   = $ProfileType
            ProfileId     = $ProfileId
            ProfileName   = $ProfileName
            HasAssignment = $true
            TargetType    = "$odataType" -replace "^#microsoft.graph\.",""
            TargetGroupId = Get-PropertyValue -Object $target -Names @("groupId") -Default ""
            FilterType    = Get-PropertyValue -Object $target -Names @("deviceAndAppManagementAssignmentFilterType") -Default ""
            FilterId      = Get-PropertyValue -Object $target -Names @("deviceAndAppManagementAssignmentFilterId") -Default ""
        }
    }
    return @($rows)
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet("Critical","High","Medium","Low","Info")][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][string]$Recommendation,
        [int]$Count = 0
    )
    $script:Findings.Add([pscustomobject]@{
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Count          = $Count
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

function Encode-Html {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode("$Value")
}

function Get-SeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { return 5 }
        "High"     { return 4 }
        "Medium"   { return 3 }
        "Low"      { return 2 }
        default    { return 1 }
    }
}

function ConvertTo-HtmlTable {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)]$Data,
        [string[]]$Properties = @(),
        [int]$MaxRows = 5000,
        [string]$EmptyMessage = "Aucune donnée."
    )

    $rows = @($Data)
    $safeId = ($Id -replace '[^a-zA-Z0-9_-]','_')
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine("<section class='section'>")
    [void]$html.AppendLine("<div class='section-head'><h2>$(Encode-Html $Title)</h2><span class='pill'>$($rows.Count)</span></div>")

    if ($rows.Count -eq 0) {
        [void]$html.AppendLine("<p class='muted'>$(Encode-Html $EmptyMessage)</p></section>")
        return $html.ToString()
    }

    if ($Properties.Count -eq 0) {
        $Properties = @($rows[0].PSObject.Properties.Name)
    }

    $shown = [math]::Min($rows.Count, $MaxRows)
    if ($rows.Count -gt $shown) {
        [void]$html.AppendLine("<p class='note'>Affichage limité à $shown ligne(s) dans le HTML. L'export CSV contient les données complètes.</p>")
    }

    [void]$html.AppendLine("<div class='table-tools'><input type='search' placeholder='Filtrer...' onkeyup=`"filterTable('$safeId', this.value)`"></div>")
    [void]$html.AppendLine("<div class='table-wrap'><table id='$safeId'><thead><tr>")
    foreach ($p in $Properties) {
        [void]$html.Append("<th>$(Encode-Html $p)</th>")
    }
    [void]$html.AppendLine("</tr></thead><tbody>")

    for ($i = 0; $i -lt $shown; $i++) {
        $row = $rows[$i]
        [void]$html.AppendLine("<tr>")
        foreach ($p in $Properties) {
            $prop = $row.PSObject.Properties[$p]
            $value = if ($null -ne $prop) { $prop.Value } else { "" }
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $value = (@($value) -join ", ")
            }
            [void]$html.Append("<td>$(Encode-Html $value)</td>")
        }
        [void]$html.AppendLine("</tr>")
    }
    [void]$html.AppendLine("</tbody></table></div></section>")
    return $html.ToString()
}

# endregion Helpers

# region Initialize

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Microsoft Intune - Complete Environment Assessment (macOS)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

New-Directory $OutputPath
$script:CsvPath = Join-Path $OutputPath "CSV"
$script:JsonPath = Join-Path $OutputPath "JSON"
$script:RawReportsPath = Join-Path $OutputPath "RawReports"
New-Directory $script:CsvPath
New-Directory $script:JsonPath
New-Directory $script:RawReportsPath

$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Warnings = [System.Collections.Generic.List[string]]::new()

$runStart = Get-Date

# endregion Initialize

# region Dependency + auth

Write-Step "Vérification de Microsoft.Graph.Authentication"
$graphAuth = Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1

if (-not $graphAuth) {
    Write-Warn "Microsoft.Graph.Authentication n'est pas installé. Installation dans CurrentUser..."
    try {
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        $graphAuth = Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    } catch {
        throw "Impossible d'installer Microsoft.Graph.Authentication. Installe-le avec: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`n$($_.Exception.Message)"
    }
}

Import-Module Microsoft.Graph.Authentication -Force
Write-Ok "Microsoft.Graph.Authentication $($graphAuth.Version)"

$scopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementServiceConfig.Read.All"
)

Write-Step "Connexion à Microsoft Graph (lecture seule)"
if ($InteractiveBrowser) {
    Connect-MgGraph -Scopes $scopes -NoWelcome
} else {
    Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome
}

$ctx = Get-MgContext
if (-not $ctx) { throw "Connexion Microsoft Graph non établie." }

$tenantId = $ctx.TenantId
$account = $ctx.Account
Write-Ok "Connecté : $account"
Write-Ok "Tenant   : $tenantId"

# endregion Dependency + auth

# region Core inventory

Write-Step "Inventaire des appareils gérés"
$deviceSelect = @(
    "id","deviceName","managedDeviceName","azureADDeviceId","serialNumber","userPrincipalName",
    "userDisplayName","operatingSystem","osVersion","manufacturer","model","complianceState",
    "managementAgent","managedDeviceOwnerType","deviceEnrollmentType","enrolledDateTime",
    "lastSyncDateTime","isEncrypted","jailBroken","partnerReportedThreatState",
    "complianceGracePeriodExpirationDateTime","enrollmentProfileName","physicalMemoryInBytes",
    "totalStorageSpaceInBytes","freeStorageSpaceInBytes","deviceHealthAttestationState"
) -join ","

$devices = @(Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=$deviceSelect")
Write-Ok "Appareils gérés : $($devices.Count)"
Export-JsonData -Name "ManagedDevices-Raw" -Data $devices | Out-Null

$now = [datetimeoffset]::Now
$deviceInventory = foreach ($d in $devices) {
    $lastSync = ConvertTo-DateTimeSafe $d.lastSyncDateTime
    $daysSinceSync = if ($lastSync) { [math]::Floor(($now - $lastSync).TotalDays) } else { $null }
    $dha = $d.deviceHealthAttestationState

    [pscustomobject]@{
        DeviceName             = $d.deviceName
        IntuneDeviceId         = $d.id
        EntraDeviceId          = $d.azureADDeviceId
        SerialNumber           = $d.serialNumber
        UserPrincipalName      = $d.userPrincipalName
        OS                     = $d.operatingSystem
        OSVersion              = $d.osVersion
        Manufacturer           = $d.manufacturer
        Model                  = $d.model
        ComplianceState        = $d.complianceState
        LastSync               = $d.lastSyncDateTime
        DaysSinceLastSync      = $daysSinceSync
        Stale                  = if ($null -eq $daysSinceSync) { "Unknown" } elseif ($daysSinceSync -ge $StaleDays) { "Yes" } else { "No" }
        VeryStale              = if ($null -eq $daysSinceSync) { "Unknown" } elseif ($daysSinceSync -ge $VeryStaleDays) { "Yes" } else { "No" }
        Encrypted              = $d.isEncrypted
        SecureBoot             = if ($dha) { $dha.secureBoot } else { "" }
        BitLockerDHA           = if ($dha) { $dha.bitLockerStatus } else { "" }
        TPMVersion             = if ($dha) { $dha.tpmVersion } else { "" }
        CodeIntegrity          = if ($dha) { $dha.codeIntegrity } else { "" }
        VirtualSecureMode      = if ($dha) { $dha.virtualSecureMode } else { "" }
        AttestationStatus      = if ($dha) { $dha.deviceHealthAttestationStatus } else { "" }
        AttestationLastUpdate  = if ($dha) { $dha.lastUpdateDateTime } else { "" }
        ManagementAgent        = $d.managementAgent
        OwnerType              = $d.managedDeviceOwnerType
        EnrollmentType         = $d.deviceEnrollmentType
        EnrollmentProfileName  = $d.enrollmentProfileName
        EnrolledDateTime       = $d.enrolledDateTime
        ThreatState            = $d.partnerReportedThreatState
        ComplianceGraceExpires = $d.complianceGracePeriodExpirationDateTime
    }
}

Export-CsvData -Name "01-ManagedDevices" -Data $deviceInventory | Out-Null

$nonCompliantDevices = @($deviceInventory | Where-Object { "$($_.ComplianceState)" -match '^(?i)noncompliant$|^(?i)error$' })
$unknownComplianceDevices = @($deviceInventory | Where-Object { "$($_.ComplianceState)" -match '^(?i)unknown$|^(?i)configmanager$|^(?i)inGracePeriod$' })
$staleDevices = @($deviceInventory | Where-Object { $_.DaysSinceLastSync -is [double] -or $_.DaysSinceLastSync -is [int] } | Where-Object { $_.DaysSinceLastSync -ge $StaleDays })
$veryStaleDevices = @($deviceInventory | Where-Object { $_.DaysSinceLastSync -is [double] -or $_.DaysSinceLastSync -is [int] } | Where-Object { $_.DaysSinceLastSync -ge $VeryStaleDays })

Export-CsvData -Name "02-NonCompliantDevices" -Data $nonCompliantDevices | Out-Null
Export-CsvData -Name "03-StaleDevices" -Data $staleDevices | Out-Null

# endregion Core inventory

# region Intune reports

$reportData = @{}

$reportData["NoncompliantDevicesAndSettingsV3"] = @(Export-IntuneReport `
    -ReportName "NoncompliantDevicesAndSettingsV3" `
    -Select @("DeviceId","DeviceName","ErrorCode","OS","OSVersion","PolicyName","SettingName","SettingNm","SettingStatus","UPN"))

$reportData["WindowsDeviceHealthAttestationReport"] = @(Export-IntuneReport `
    -ReportName "WindowsDeviceHealthAttestationReport" `
    -Select @(
        "AttestationError","BitlockerStatus","BootDebuggingStatus","CodeIntegrityStatus",
        "DeviceId","DeviceName","DeviceOS","ELAMDriverLoadedStatus","FirmwareProtectionStatus",
        "HealthCertIssuedDate","MemoryAccessProtectionStatus","MemoryIntegrityProtectionStatus",
        "OSKernelDebuggingStatus","PrimaryUser","SafeModeStatus","SecuredCorePCStatus",
        "SecureBootStatus","SystemManagementMode","TpmVersion","UPN","VSMStatus","WinPEStatus"
    ))

$reportData["DeviceConfigurationPolicyStatusesV3"] = @(Export-IntuneReport `
    -ReportName "DeviceConfigurationPolicyStatusesV3" `
    -Select @(
        "PolicyId","PolicyName","IntuneDeviceId","DeviceName","Manufacturer","Model","UPN",
        "PolicyStatus","PspdpuLastModifiedTimeUtc","UnifiedPolicyPlatformType","UnifiedPolicyType",
        "AssignmentFilterIds","TemplateVersion","ReportStatus"
    ))

if (-not $SkipAppAnalysis) {
    $reportData["OrgAppsInstallStatus"] = @(Export-IntuneReport `
        -ReportName "OrgAppsInstallStatus" `
        -Select @(
            "ApplicationId","AppVersion","DisplayName","FailedDeviceCount","FailedDevicePercentage",
            "FailedUserCount","InstalledDeviceCount","InstalledUserCount","NotApplicableDeviceCount",
            "NotApplicableUserCount","NotInstalledDeviceCount","NotInstalledUserCount",
            "PendingInstallDeviceCount","PendingInstallUserCount","Platform","Publisher"
        ))
}

if (-not $SkipOptionalReports) {
    $reportData["DeviceEnrollmentFailures"] = @(Export-IntuneReport `
        -ReportName "DeviceEnrollmentFailures" `
        -Select @("EnrollmentFailureDateTime","EnrollmentMethod","FailureGuid","FailureReason","OS","OSVersion","UPN","UserId"))

    $reportData["DeviceRunStatesByScript"] = @(Export-IntuneReport `
        -ReportName "DeviceRunStatesByScript" `
        -Select @(
            "DeviceId","DeviceName","ErrorCode","ErrorDescription","ModifiedTime","OSVersion",
            "PolicyId","PolicyResultDetail","PolicyResultState","PolicyVersion","RunState",
            "UPN","UserEmail","UserId","UserName"
        ))

    $reportData["WorkFromAnywhereDeviceList"] = @(Export-IntuneReport `
        -ReportName "WorkFromAnywhereDeviceList" `
        -Select @(
            "AutoPilotProfileAssigned","AutoPilotRegistered","CompliancePolicySetToIntune",
            "DeviceId","DeviceName","GraphDeviceIsManaged","JoinType","ManagedBy","Manufacturer",
            "Model","OSCheckFailed","OSDescription","OSVersion","OtherWorkloadsSetToIntune",
            "Ownership","Processor64BitCheckFailed","ProcessorCoreCountCheckFailed",
            "ProcessorFamilyCheckFailed","ProcessorSpeedCheckFailed","RamCheckFailed",
            "ReferenceId","SecureBootCheckFailed","SerialNumber","StorageCheckFailed",
            "TenantAttached","TPMCheckFailed","UpgradeEligibility"
        ))
}

foreach ($key in $reportData.Keys) {
    if (@($reportData[$key]).Count -gt 0) {
        Export-CsvData -Name ("Report-{0}" -f $key) -Data $reportData[$key] | Out-Null
    }
}

$nonComplianceReasons = @($reportData["NoncompliantDevicesAndSettingsV3"])
$healthReport = @($reportData["WindowsDeviceHealthAttestationReport"])
$profileStatusReport = @($reportData["DeviceConfigurationPolicyStatusesV3"])
$appReport = @($reportData["OrgAppsInstallStatus"])
$enrollmentReport = @($reportData["DeviceEnrollmentFailures"])
$scriptRunReport = @($reportData["DeviceRunStatesByScript"])
$wfaReport = @($reportData["WorkFromAnywhereDeviceList"])

# endregion Intune reports

# region Windows security posture

Write-Step "Analyse Windows Security / Device Health Attestation"

$windowsDevices = @($deviceInventory | Where-Object { "$($_.OS)" -match '(?i)windows' })

# Prefer the official report. Fall back to managedDevice.deviceHealthAttestationState.
$windowsHealth = [System.Collections.Generic.List[object]]::new()

if ($healthReport.Count -gt 0) {
    foreach ($r in $healthReport) {
        $windowsHealth.Add([pscustomobject]@{
            DeviceName               = Get-PropertyValue $r @("DeviceName")
            UPN                      = Get-PropertyValue $r @("UPN","PrimaryUser")
            SecureBoot               = Get-PropertyValue $r @("SecureBootStatus")
            BitLocker                = Get-PropertyValue $r @("BitlockerStatus","BitLockerStatus")
            TPMVersion               = Get-PropertyValue $r @("TpmVersion","TPMVersion")
            CodeIntegrity            = Get-PropertyValue $r @("CodeIntegrityStatus")
            VirtualSecureMode        = Get-PropertyValue $r @("VSMStatus")
            MemoryIntegrity          = Get-PropertyValue $r @("MemoryIntegrityProtectionStatus")
            FirmwareProtection       = Get-PropertyValue $r @("FirmwareProtectionStatus")
            SecuredCorePC            = Get-PropertyValue $r @("SecuredCorePCStatus")
            BootDebugging            = Get-PropertyValue $r @("BootDebuggingStatus")
            OSKernelDebugging        = Get-PropertyValue $r @("OSKernelDebuggingStatus")
            ELAM                     = Get-PropertyValue $r @("ELAMDriverLoadedStatus")
            AttestationError         = Get-PropertyValue $r @("AttestationError")
            HealthCertIssuedDate     = Get-PropertyValue $r @("HealthCertIssuedDate")
            Source                   = "WindowsDeviceHealthAttestationReport"
        })
    }
} else {
    foreach ($r in $windowsDevices) {
        $windowsHealth.Add([pscustomobject]@{
            DeviceName               = $r.DeviceName
            UPN                      = $r.UserPrincipalName
            SecureBoot               = $r.SecureBoot
            BitLocker                = if (-not [string]::IsNullOrWhiteSpace("$($r.BitLockerDHA)")) { $r.BitLockerDHA } else { $r.Encrypted }
            TPMVersion               = $r.TPMVersion
            CodeIntegrity            = $r.CodeIntegrity
            VirtualSecureMode        = $r.VirtualSecureMode
            MemoryIntegrity          = ""
            FirmwareProtection       = ""
            SecuredCorePC            = ""
            BootDebugging            = ""
            OSKernelDebugging        = ""
            ELAM                     = ""
            AttestationError         = $r.AttestationStatus
            HealthCertIssuedDate     = $r.AttestationLastUpdate
            Source                   = "managedDevice.deviceHealthAttestationState"
        })
    }
}

$windowsHealth = @($windowsHealth)
Export-CsvData -Name "04-WindowsSecurityPosture" -Data $windowsHealth | Out-Null

$secureBootOff = @($windowsHealth | Where-Object { Test-NegativeState $_.SecureBoot })
$secureBootUnknown = @($windowsHealth | Where-Object { [string]::IsNullOrWhiteSpace("$($_.SecureBoot)") -or "$($_.SecureBoot)" -match '(?i)unknown|not.?applicable|not.?supported' })
$bitLockerOff = @($windowsHealth | Where-Object { Test-NegativeState $_.BitLocker })
$bitLockerUnknown = @($windowsHealth | Where-Object { [string]::IsNullOrWhiteSpace("$($_.BitLocker)") -or "$($_.BitLocker)" -match '(?i)unknown|not.?applicable|not.?supported' })
$tpmProblem = @($windowsHealth | Where-Object {
    $t = "$($_.TPMVersion)".Trim()
    -not [string]::IsNullOrWhiteSpace($t) -and $t -notmatch '^2(\.0)?$|(?i)^2\.'
})
$codeIntegrityOff = @($windowsHealth | Where-Object { Test-NegativeState $_.CodeIntegrity })
$vsmOff = @($windowsHealth | Where-Object { Test-NegativeState $_.VirtualSecureMode })
$attestationErrors = @($windowsHealth | Where-Object {
    -not [string]::IsNullOrWhiteSpace("$($_.AttestationError)") -and
    "$($_.AttestationError)" -notmatch '^(?i)0$|^(?i)none$|^(?i)success$|^(?i)healthy$|^(?i)compliant$'
})

Export-CsvData -Name "05-SecureBoot-Off" -Data $secureBootOff | Out-Null
Export-CsvData -Name "06-BitLocker-Off" -Data $bitLockerOff | Out-Null
Export-CsvData -Name "07-TPM-Issues" -Data $tpmProblem | Out-Null
Export-CsvData -Name "08-Attestation-Issues" -Data $attestationErrors | Out-Null

# endregion Windows security posture

# region Policies and profiles

Write-Step "Inventaire des politiques et profils Intune"

$legacyProfiles = @(Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?`$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version" -Optional)
$settingsCatalog = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name,description,platforms,technologies,createdDateTime,lastModifiedDateTime,settingCount,templateReference,roleScopeTagIds" -Optional)
$compliancePolicies = @(Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -Optional)
$assignmentFilters = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters" -Optional)
$deviceScripts = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$select=id,displayName,description,createdDateTime,lastModifiedDateTime,runAsAccount,enforceSignatureCheck,fileName" -Optional)
$shellScripts = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?`$select=id,displayName,description,createdDateTime,lastModifiedDateTime,fileName,runAsAccount,retryCount,blockExecutionNotifications" -Optional)
$healthScripts = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=id,displayName,description,createdDateTime,lastModifiedDateTime,publisher,runAsAccount,enforceSignatureCheck" -Optional)
$autopilotProfiles = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles" -Optional)
$enrollmentConfigs = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" -Optional)
$groupPolicyConfigs = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$select=id,displayName,description,createdDateTime,lastModifiedDateTime" -Optional)
$intents = @(Get-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/intents?`$select=id,displayName,description,lastModifiedDateTime,templateId" -Optional)

$profileInventory = [System.Collections.Generic.List[object]]::new()

foreach ($p in $legacyProfiles) {
    $odataType = Get-PropertyValue -Object $p -Names @("@odata.type") -Default ""
    $profileInventory.Add([pscustomobject]@{
        Type             = "Legacy Device Configuration"
        Id               = Get-PropertyValue -Object $p -Names @("id") -Default ""
        Name             = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        Platform         = ("$odataType" -replace '^#microsoft.graph\.','')
        Technology       = ""
        SettingsCount    = ""
        Created          = Get-PropertyValue -Object $p -Names @("createdDateTime") -Default ""
        LastModified     = Get-PropertyValue -Object $p -Names @("lastModifiedDateTime") -Default ""
    })
}

foreach ($p in $settingsCatalog) {
    $platforms = Get-PropertyValue -Object $p -Names @("platforms") -Default @()
    $technologies = Get-PropertyValue -Object $p -Names @("technologies") -Default @()
    $profileInventory.Add([pscustomobject]@{
        Type             = "Settings Catalog / Endpoint Security"
        Id               = Get-PropertyValue -Object $p -Names @("id") -Default ""
        Name             = Get-PropertyValue -Object $p -Names @("name","displayName") -Default "Unnamed"
        Platform         = (@($platforms) -join ", ")
        Technology       = (@($technologies) -join ", ")
        SettingsCount    = Get-PropertyValue -Object $p -Names @("settingCount") -Default ""
        Created          = Get-PropertyValue -Object $p -Names @("createdDateTime") -Default ""
        LastModified     = Get-PropertyValue -Object $p -Names @("lastModifiedDateTime") -Default ""
    })
}

foreach ($p in $compliancePolicies) {
    $odataType = Get-PropertyValue -Object $p -Names @("@odata.type") -Default ""
    $profileInventory.Add([pscustomobject]@{
        Type             = "Compliance Policy"
        Id               = Get-PropertyValue -Object $p -Names @("id") -Default ""
        Name             = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        Platform         = ("$odataType" -replace '^#microsoft.graph\.','')
        Technology       = ""
        SettingsCount    = ""
        Created          = Get-PropertyValue -Object $p -Names @("createdDateTime") -Default ""
        LastModified     = Get-PropertyValue -Object $p -Names @("lastModifiedDateTime") -Default ""
    })
}

foreach ($p in $deviceScripts) {
    $profileInventory.Add([pscustomobject]@{
        Type             = "Windows PowerShell Script"
        Id               = Get-PropertyValue -Object $p -Names @("id") -Default ""
        Name             = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        Platform         = "Windows"
        Technology       = "Script"
        SettingsCount    = ""
        Created          = Get-PropertyValue -Object $p -Names @("createdDateTime") -Default ""
        LastModified     = Get-PropertyValue -Object $p -Names @("lastModifiedDateTime") -Default ""
    })
}

foreach ($p in $shellScripts) {
    $profileInventory.Add([pscustomobject]@{
        Type             = "macOS Shell Script"
        Id               = Get-PropertyValue -Object $p -Names @("id") -Default ""
        Name             = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        Platform         = "macOS"
        Technology       = "Script"
        SettingsCount    = ""
        Created          = Get-PropertyValue -Object $p -Names @("createdDateTime") -Default ""
        LastModified     = Get-PropertyValue -Object $p -Names @("lastModifiedDateTime") -Default ""
    })
}

foreach ($p in $healthScripts) {
    $profileInventory.Add([pscustomobject]@{
        Type             = "Remediation"
        Id               = Get-PropertyValue -Object $p -Names @("id") -Default ""
        Name             = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        Platform         = "Windows"
        Technology       = "Remediation"
        SettingsCount    = ""
        Created          = Get-PropertyValue -Object $p -Names @("createdDateTime") -Default ""
        LastModified     = Get-PropertyValue -Object $p -Names @("lastModifiedDateTime") -Default ""
    })
}

Export-CsvData -Name "09-PolicyProfileInventory" -Data @($profileInventory) | Out-Null
Export-CsvData -Name "10-AssignmentFilters" -Data $assignmentFilters | Out-Null
Export-CsvData -Name "11-AutopilotProfiles" -Data $autopilotProfiles | Out-Null
Export-CsvData -Name "12-EnrollmentConfigurations" -Data $enrollmentConfigs | Out-Null
Export-CsvData -Name "13-GroupPolicyConfigurations" -Data $groupPolicyConfigs | Out-Null
Export-CsvData -Name "14-DeviceManagementIntents" -Data $intents | Out-Null

# Assignments
$assignmentRows = [System.Collections.Generic.List[object]]::new()

if (-not $SkipAssignmentAnalysis) {
    Write-Step "Analyse des affectations de profils et politiques"

    foreach ($p in $legacyProfiles) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "Legacy Device Configuration" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }

    foreach ($p in $settingsCatalog) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("name","displayName") -Default "Unnamed"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "Settings Catalog / Endpoint Security" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }

    foreach ($p in $compliancePolicies) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "Compliance Policy" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }

    foreach ($p in $deviceScripts) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "Windows PowerShell Script" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }

    foreach ($p in $shellScripts) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "macOS Shell Script" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }

    foreach ($p in $healthScripts) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "Remediation" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }

    foreach ($p in $autopilotProfiles) {
        $id = Get-PropertyValue -Object $p -Names @("id") -Default ""
        $name = Get-PropertyValue -Object $p -Names @("displayName","name") -Default "Unnamed Autopilot profile"
        if ($id) {
            foreach ($row in @(Get-AssignmentRows -ProfileType "Autopilot Deployment Profile" -ProfileId $id -ProfileName $name -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles/$id/assignments")) {
                $assignmentRows.Add($row)
            }
        }
    }
}

$assignmentRows = @($assignmentRows)
Export-CsvData -Name "15-Assignments" -Data $assignmentRows | Out-Null
$unassignedObjects = @($assignmentRows | Where-Object { -not $_.HasAssignment })
Export-CsvData -Name "16-UnassignedProfilesPolicies" -Data $unassignedObjects | Out-Null

# Profile failures from unified report
$profileFailures = @($profileStatusReport | Where-Object {
    $status = Get-PropertyValue $_ @("PolicyStatus","ReportStatus") ""
    Test-FailureLike $status
})
Export-CsvData -Name "17-ProfileStatusFailures" -Data $profileFailures | Out-Null

# Aggregate failure hot spots by policy
$profileFailureSummary = @(
    $profileFailures |
    Group-Object { Get-PropertyValue $_ @("PolicyName") "Unknown policy" } |
    Sort-Object Count -Descending |
    ForEach-Object {
        [pscustomobject]@{
            PolicyName = $_.Name
            FailureCount = $_.Count
            Devices = ((@($_.Group | ForEach-Object { Get-PropertyValue $_ @("DeviceName") "" }) | Where-Object { $_ } | Sort-Object -Unique) -join ", ")
            Statuses = ((@($_.Group | ForEach-Object { Get-PropertyValue $_ @("PolicyStatus","ReportStatus") "" }) | Where-Object { $_ } | Sort-Object -Unique) -join ", ")
        }
    }
)
Export-CsvData -Name "18-ProfileFailureSummary" -Data $profileFailureSummary | Out-Null

# endregion Policies and profiles

# region Apps, enrollment, scripts

$appFailures = @()
if (-not $SkipAppAnalysis -and $appReport.Count -gt 0) {
    $appFailures = @($appReport | Where-Object {
        (ConvertTo-IntSafe (Get-PropertyValue $_ @("FailedDeviceCount") 0)) -gt 0 -or
        (ConvertTo-IntSafe (Get-PropertyValue $_ @("FailedUserCount") 0)) -gt 0
    })
    Export-CsvData -Name "19-AppInstallFailures" -Data $appFailures | Out-Null
}

$recentEnrollmentFailures = @()
if ($enrollmentReport.Count -gt 0) {
    $cutoff = [datetimeoffset]::Now.AddDays(-$EnrollmentFailureLookbackDays)
    $recentEnrollmentFailures = @($enrollmentReport | Where-Object {
        $dt = ConvertTo-DateTimeSafe (Get-PropertyValue $_ @("EnrollmentFailureDateTime") $null)
        $dt -and $dt -ge $cutoff
    })
    Export-CsvData -Name "20-RecentEnrollmentFailures" -Data $recentEnrollmentFailures | Out-Null
}

$scriptFailures = @()
if ($scriptRunReport.Count -gt 0) {
    $scriptFailures = @($scriptRunReport | Where-Object {
        Test-FailureLike (Get-PropertyValue $_ @("RunState","PolicyResultState","PolicyResultDetail") "")
    })
    Export-CsvData -Name "21-ScriptRunFailures" -Data $scriptFailures | Out-Null
}

# endregion Apps, enrollment, scripts

# region Non-compliance analysis

Write-Step "Analyse des causes de non-conformité"

$nonComplianceSummary = @(
    $nonComplianceReasons |
    Group-Object {
        $setting = Get-PropertyValue $_ @("SettingName","SettingNm") "Unknown setting"
        $policy = Get-PropertyValue $_ @("PolicyName") "Unknown policy"
        "$policy|||$setting"
    } |
    Sort-Object Count -Descending |
    ForEach-Object {
        $parts = $_.Name -split '\|\|\|', 2
        [pscustomobject]@{
            PolicyName = $parts[0]
            SettingName = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            AffectedDevices = $_.Count
            ErrorCodes = ((@($_.Group | ForEach-Object { Get-PropertyValue $_ @("ErrorCode") "" }) | Where-Object { $_ -and $_ -ne "0" } | Sort-Object -Unique) -join ", ")
            Statuses = ((@($_.Group | ForEach-Object { Get-PropertyValue $_ @("SettingStatus") "" }) | Where-Object { $_ } | Sort-Object -Unique) -join ", ")
        }
    }
)

Export-CsvData -Name "22-NonComplianceReasons" -Data $nonComplianceReasons | Out-Null
Export-CsvData -Name "23-NonComplianceSummary" -Data $nonComplianceSummary | Out-Null

# endregion Non-compliance analysis

# region Findings

Write-Step "Génération des constats"

$totalDevices = $deviceInventory.Count
$windowsCount = $windowsDevices.Count
$nonCompliantCount = $nonCompliantDevices.Count
$staleCount = $staleDevices.Count
$veryStaleCount = $veryStaleDevices.Count

$compliancePct = if ($totalDevices -gt 0) {
    [math]::Round(((@($deviceInventory | Where-Object { "$($_.ComplianceState)" -match '^(?i)compliant$' }).Count / $totalDevices) * 100), 1)
} else { 0 }

if ($nonCompliantCount -gt 0) {
    $pct = if ($totalDevices -gt 0) { [math]::Round(($nonCompliantCount / $totalDevices) * 100, 1) } else { 0 }
    $severity = if ($pct -ge 10) { "High" } else { "Medium" }
    Add-Finding -Severity $severity -Category "Compliance" -Title "Appareils non conformes" `
        -Detail "$nonCompliantCount appareil(s) non conforme(s), soit $pct % du parc Intune." `
        -Recommendation "Traiter en priorité les causes listées dans NonComplianceReasons; vérifier les politiques, les délais de grâce, les erreurs de remédiation et les appareils qui ne synchronisent plus." `
        -Count $nonCompliantCount
}

if ($staleCount -gt 0) {
    $pct = if ($totalDevices -gt 0) { [math]::Round(($staleCount / $totalDevices) * 100, 1) } else { 0 }
    Add-Finding -Severity "Medium" -Category "Device hygiene" -Title "Appareils sans synchronisation récente" `
        -Detail "$staleCount appareil(s) n'ont pas synchronisé depuis au moins $StaleDays jours ($pct %)." `
        -Recommendation "Valider s'ils sont encore actifs. Retirer/nettoyer les objets obsolètes selon la politique de cycle de vie afin d'améliorer la qualité des rapports et des déploiements." `
        -Count $staleCount
}

if ($veryStaleCount -gt 0) {
    Add-Finding -Severity "High" -Category "Device hygiene" -Title "Appareils très obsolètes" `
        -Detail "$veryStaleCount appareil(s) n'ont pas synchronisé depuis au moins $VeryStaleDays jours." `
        -Recommendation "Identifier les appareils retirés du service, perdus ou remplacés et appliquer le processus de nettoyage/retire/delete approprié." `
        -Count $veryStaleCount
}

if ($secureBootOff.Count -gt 0) {
    Add-Finding -Severity "High" -Category "Windows security" -Title "Secure Boot désactivé" `
        -Detail "$($secureBootOff.Count) appareil(s) Windows rapportent Secure Boot désactivé." `
        -Recommendation "Vérifier la compatibilité UEFI, activer Secure Boot et imposer l'exigence dans la stratégie de conformité Windows lorsque pertinent." `
        -Count $secureBootOff.Count
}

if ($bitLockerOff.Count -gt 0) {
    Add-Finding -Severity "High" -Category "Windows security" -Title "BitLocker / chiffrement désactivé" `
        -Detail "$($bitLockerOff.Count) appareil(s) Windows rapportent BitLocker ou le chiffrement comme désactivé." `
        -Recommendation "Vérifier la stratégie Disk Encryption/BitLocker, le stockage de la clé de récupération, les erreurs TPM et l'état de chiffrement réel du volume système." `
        -Count $bitLockerOff.Count
}

if ($tpmProblem.Count -gt 0) {
    Add-Finding -Severity "Medium" -Category "Windows security" -Title "TPM non conforme à 2.x" `
        -Detail "$($tpmProblem.Count) appareil(s) rapportent une version TPM différente de 2.x." `
        -Recommendation "Valider l'inventaire matériel, les mises à jour BIOS/firmware et les exigences Windows/Windows Hello/BitLocker." `
        -Count $tpmProblem.Count
}

if ($attestationErrors.Count -gt 0) {
    Add-Finding -Severity "Medium" -Category "Windows security" -Title "Erreurs Device Health Attestation" `
        -Detail "$($attestationErrors.Count) appareil(s) ont une erreur ou un état d'attestation inhabituel." `
        -Recommendation "Analyser l'erreur DHA, la connectivité vers les services d'attestation, le TPM, le Secure Boot et l'heure système." `
        -Count $attestationErrors.Count
}

if ($profileFailures.Count -gt 0) {
    Add-Finding -Severity "High" -Category "Configuration" -Title "Profils en erreur, conflit ou non conformes" `
        -Detail "$($profileFailures.Count) état(s) de profil indiquent une erreur, un échec, un conflit ou une non-conformité." `
        -Recommendation "Commencer par les profils les plus touchés dans ProfileFailureSummary, puis analyser les paramètres en conflit et les codes d'erreur par appareil." `
        -Count $profileFailures.Count
}

if ($unassignedObjects.Count -gt 0) {
    $unassignedCompliance = @($unassignedObjects | Where-Object { $_.ProfileType -eq "Compliance Policy" })
    if ($unassignedCompliance.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "Compliance" -Title "Politiques de conformité sans affectation" `
            -Detail "$($unassignedCompliance.Count) politique(s) de conformité n'ont aucune affectation visible." `
            -Recommendation "Confirmer qu'elles sont volontairement en attente; sinon les affecter aux groupes ciblés pour éviter une couverture de conformité incomplète." `
            -Count $unassignedCompliance.Count
    }

    $unassignedConfig = @($unassignedObjects | Where-Object { $_.ProfileType -match "Configuration|Settings Catalog|Endpoint Security" })
    if ($unassignedConfig.Count -gt 0) {
        Add-Finding -Severity "Low" -Category "Configuration" -Title "Profils de configuration sans affectation" `
            -Detail "$($unassignedConfig.Count) profil(s) de configuration n'ont aucune affectation visible." `
            -Recommendation "Vérifier s'il s'agit de profils de test/archives. Supprimer ou documenter les profils inutilisés afin de réduire la dette de configuration." `
            -Count $unassignedConfig.Count
    }
}

if ($appFailures.Count -gt 0) {
    $failedDeviceTotal = 0
    foreach ($a in $appFailures) {
        $failedDeviceTotal += ConvertTo-IntSafe (Get-PropertyValue $a @("FailedDeviceCount") 0)
    }
    Add-Finding -Severity "Medium" -Category "Applications" -Title "Applications avec échecs d'installation" `
        -Detail "$($appFailures.Count) application(s) ont au moins un échec d'installation; total déclaré de $failedDeviceTotal échec(s) appareil." `
        -Recommendation "Prioriser les applications avec le plus grand FailedDeviceCount, puis analyser code d'erreur, détection, prérequis, dépendances et contexte utilisateur/système." `
        -Count $appFailures.Count
}

if ($recentEnrollmentFailures.Count -gt 0) {
    Add-Finding -Severity "Medium" -Category "Enrollment" -Title "Échecs d'enrôlement récents" `
        -Detail "$($recentEnrollmentFailures.Count) échec(s) d'enrôlement durant les $EnrollmentFailureLookbackDays derniers jours." `
        -Recommendation "Regrouper par FailureReason et EnrollmentMethod; vérifier restrictions d'enrôlement, licences, quota, MDM authority, Autopilot/ABM/Android Enterprise et Conditional Access." `
        -Count $recentEnrollmentFailures.Count
}

if ($scriptFailures.Count -gt 0) {
    Add-Finding -Severity "Medium" -Category "Scripts" -Title "Scripts avec échecs d'exécution" `
        -Detail "$($scriptFailures.Count) état(s) d'exécution de scripts rapportent une erreur ou un échec." `
        -Recommendation "Vérifier le code d'erreur, le contexte RunAs, l'architecture, les prérequis locaux et la logique de détection/remédiation." `
        -Count $scriptFailures.Count
}

if ($secureBootUnknown.Count -gt 0 -or $bitLockerUnknown.Count -gt 0) {
    Add-Finding -Severity "Info" -Category "Data quality" -Title "Télémétrie de sécurité Windows incomplète" `
        -Detail "$($secureBootUnknown.Count) appareil(s) ont un état Secure Boot inconnu/non applicable et $($bitLockerUnknown.Count) un état BitLocker inconnu/non applicable." `
        -Recommendation "Ne pas interpréter automatiquement Unknown comme Disabled. Vérifier la fraîcheur de l'attestation, la prise en charge DHA et le type d'appareil." `
        -Count ($secureBootUnknown.Count + $bitLockerUnknown.Count)
}

if ($script:Findings.Count -eq 0) {
    Add-Finding -Severity "Info" -Category "Overview" -Title "Aucun constat automatique majeur" `
        -Detail "Les règles d'analyse automatiques de ce script n'ont pas détecté d'écart majeur dans les données accessibles." `
        -Recommendation "Effectuer tout de même une revue humaine des paramètres, affectations, exceptions, filtres et standards de sécurité de l'organisation." `
        -Count 0
}

$findings = @($script:Findings | Sort-Object @{Expression={ Get-SeverityWeight $_.Severity }; Descending=$true}, Category, Title)
Export-CsvData -Name "00-Findings" -Data $findings | Out-Null

# endregion Findings

# region Summary objects

$platformSummary = @(
    $deviceInventory |
    Group-Object OS |
    Sort-Object Count -Descending |
    ForEach-Object {
        [pscustomobject]@{
            OperatingSystem = if ([string]::IsNullOrWhiteSpace($_.Name)) { "Unknown" } else { $_.Name }
            Count = $_.Count
            Percentage = if ($totalDevices -gt 0) { [math]::Round(($_.Count / $totalDevices) * 100, 1) } else { 0 }
        }
    }
)

$complianceSummary = @(
    $deviceInventory |
    Group-Object ComplianceState |
    Sort-Object Count -Descending |
    ForEach-Object {
        [pscustomobject]@{
            State = if ([string]::IsNullOrWhiteSpace($_.Name)) { "Unknown" } else { $_.Name }
            Count = $_.Count
            Percentage = if ($totalDevices -gt 0) { [math]::Round(($_.Count / $totalDevices) * 100, 1) } else { 0 }
        }
    }
)

$securitySummary = @(
    [pscustomobject]@{ Metric = "Windows devices"; Count = $windowsCount }
    [pscustomobject]@{ Metric = "Secure Boot Off"; Count = $secureBootOff.Count }
    [pscustomobject]@{ Metric = "Secure Boot Unknown/NA"; Count = $secureBootUnknown.Count }
    [pscustomobject]@{ Metric = "BitLocker Off"; Count = $bitLockerOff.Count }
    [pscustomobject]@{ Metric = "BitLocker Unknown/NA"; Count = $bitLockerUnknown.Count }
    [pscustomobject]@{ Metric = "TPM issue"; Count = $tpmProblem.Count }
    [pscustomobject]@{ Metric = "Code Integrity Off"; Count = $codeIntegrityOff.Count }
    [pscustomobject]@{ Metric = "VSM Off"; Count = $vsmOff.Count }
    [pscustomobject]@{ Metric = "Attestation issue"; Count = $attestationErrors.Count }
)

Export-CsvData -Name "24-PlatformSummary" -Data $platformSummary | Out-Null
Export-CsvData -Name "25-ComplianceSummary" -Data $complianceSummary | Out-Null
Export-CsvData -Name "26-SecuritySummary" -Data $securitySummary | Out-Null

# endregion Summary objects

# region HTML

Write-Step "Génération du rapport HTML"

$runEnd = Get-Date
$duration = New-TimeSpan -Start $runStart -End $runEnd
$reportFile = Join-Path $OutputPath "Intune-Environment-Assessment.html"

$criticalCount = @($findings | Where-Object Severity -eq "Critical").Count
$highCount = @($findings | Where-Object Severity -eq "High").Count
$mediumCount = @($findings | Where-Object Severity -eq "Medium").Count
$lowCount = @($findings | Where-Object Severity -eq "Low").Count

$css = @'
:root {
  --bg: #0b1020;
  --panel: #11182b;
  --panel2: #151f35;
  --text: #e8edf7;
  --muted: #9aa8c2;
  --line: #26334d;
  --accent: #7db4ff;
  --ok: #52d273;
  --warn: #ffbd5b;
  --bad: #ff6b6b;
  --critical: #ff3b7a;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}
header {
  padding: 32px 36px 24px;
  background: linear-gradient(145deg, #10172a, #182746);
  border-bottom: 1px solid var(--line);
}
h1 { margin: 0 0 8px; font-size: 30px; }
h2 { margin: 0; font-size: 19px; }
.meta { color: var(--muted); font-size: 13px; }
main { padding: 24px 30px 60px; max-width: 1800px; margin: auto; }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit,minmax(170px,1fr));
  gap: 14px;
  margin-bottom: 22px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 16px;
}
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
.card .value { font-size: 28px; font-weight: 700; margin-top: 5px; }
.section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  margin: 0 0 20px;
  padding: 16px;
}
.section-head {
  display: flex; gap: 10px; align-items: center; justify-content: space-between;
  margin-bottom: 12px;
}
.pill {
  display: inline-block; padding: 3px 9px; border-radius: 999px;
  background: var(--panel2); color: var(--accent); font-size: 12px;
}
.table-tools { margin: 10px 0; }
input[type=search] {
  width: min(420px,100%); background: #0c1325; border: 1px solid var(--line);
  color: var(--text); border-radius: 8px; padding: 9px 11px;
}
.table-wrap { overflow: auto; max-height: 640px; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th {
  position: sticky; top: 0; z-index: 1; background: #1a2640; color: #dce8ff;
  text-align: left; padding: 9px; border-bottom: 1px solid var(--line);
}
td { padding: 8px 9px; border-bottom: 1px solid #1d2940; vertical-align: top; }
tr:hover td { background: #121d33; }
.muted { color: var(--muted); }
.note { color: var(--warn); font-size: 12px; }
.finding {
  display: grid;
  grid-template-columns: 90px 170px 1fr 1.2fr;
  gap: 12px;
  align-items: start;
  padding: 12px 0;
  border-bottom: 1px solid var(--line);
}
.finding:last-child { border-bottom: 0; }
.sev {
  font-weight: 700; border-radius: 999px; padding: 4px 9px; text-align: center;
  font-size: 11px; display: inline-block;
}
.sev-Critical { background: rgba(255,59,122,.18); color: #ff86aa; }
.sev-High { background: rgba(255,107,107,.18); color: #ff9d9d; }
.sev-Medium { background: rgba(255,189,91,.18); color: #ffd08a; }
.sev-Low { background: rgba(125,180,255,.15); color: #a9ccff; }
.sev-Info { background: rgba(154,168,194,.12); color: #c1cbdd; }
.small { font-size: 12px; color: var(--muted); }
@media (max-width: 900px) {
  .finding { grid-template-columns: 1fr; }
  main { padding: 14px; }
  header { padding: 24px 18px; }
}
'@

$js = @'
function filterTable(id, query) {
  query = (query || "").toLowerCase();
  const table = document.getElementById(id);
  if (!table) return;
  const rows = table.querySelectorAll("tbody tr");
  rows.forEach(r => {
    r.style.display = r.innerText.toLowerCase().includes(query) ? "" : "none";
  });
}
'@

$html = [System.Text.StringBuilder]::new()
[void]$html.AppendLine("<!doctype html><html lang='fr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>")
[void]$html.AppendLine("<title>Intune Environment Assessment</title><style>$css</style></head><body>")
[void]$html.AppendLine("<header><h1>Microsoft Intune — Environment Assessment</h1>")
[void]$html.AppendLine("<div class='meta'>Tenant: $(Encode-Html $tenantId) &nbsp;|&nbsp; Compte: $(Encode-Html $account) &nbsp;|&nbsp; Généré: $(Encode-Html ($runEnd.ToString('yyyy-MM-dd HH:mm:ss zzz'))) &nbsp;|&nbsp; Durée: $([math]::Round($duration.TotalMinutes,1)) min</div></header>")
[void]$html.AppendLine("<main>")

[void]$html.AppendLine("<div class='cards'>")
$cards = @(
    @("Devices",$totalDevices),
    @("Compliance %","$compliancePct %"),
    @("Non compliant",$nonCompliantCount),
    @("Stale ≥ $StaleDays j",$staleCount),
    @("Very stale ≥ $VeryStaleDays j",$veryStaleCount),
    @("Secure Boot Off",$secureBootOff.Count),
    @("BitLocker Off",$bitLockerOff.Count),
    @("Profile failures",$profileFailures.Count),
    @("App failures",$appFailures.Count),
    @("High findings",$highCount)
)
foreach ($c in $cards) {
    [void]$html.AppendLine("<div class='card'><div class='label'>$(Encode-Html $c[0])</div><div class='value'>$(Encode-Html $c[1])</div></div>")
}
[void]$html.AppendLine("</div>")

# Findings
[void]$html.AppendLine("<section class='section'><div class='section-head'><h2>Constats prioritaires</h2><span class='pill'>$($findings.Count)</span></div>")
[void]$html.AppendLine("<p class='small'>Critical: $criticalCount &nbsp; High: $highCount &nbsp; Medium: $mediumCount &nbsp; Low: $lowCount</p>")
foreach ($f in $findings) {
    [void]$html.AppendLine("<div class='finding'>")
    [void]$html.AppendLine("<div><span class='sev sev-$(Encode-Html $f.Severity)'>$(Encode-Html $f.Severity)</span><div class='small'>Count: $($f.Count)</div></div>")
    [void]$html.AppendLine("<div><strong>$(Encode-Html $f.Category)</strong><br>$(Encode-Html $f.Title)</div>")
    [void]$html.AppendLine("<div>$(Encode-Html $f.Detail)</div>")
    [void]$html.AppendLine("<div><strong>Action:</strong> $(Encode-Html $f.Recommendation)</div>")
    [void]$html.AppendLine("</div>")
}
[void]$html.AppendLine("</section>")

[void]$html.AppendLine((ConvertTo-HtmlTable -Id "platformSummary" -Title "Répartition par plateforme" -Data $platformSummary -Properties @("OperatingSystem","Count","Percentage")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "complianceSummary" -Title "Résumé conformité" -Data $complianceSummary -Properties @("State","Count","Percentage")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "securitySummary" -Title "Résumé sécurité Windows" -Data $securitySummary -Properties @("Metric","Count")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "noncomplianceSummary" -Title "Principales causes de non-conformité" -Data $nonComplianceSummary -Properties @("PolicyName","SettingName","AffectedDevices","ErrorCodes","Statuses")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "noncomplianceDetails" -Title "Détails appareils / paramètres non conformes" -Data $nonComplianceReasons -Properties @("DeviceName","UPN","OS","OSVersion","PolicyName","SettingName","SettingNm","SettingStatus","ErrorCode")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "windowsHealth" -Title "Windows Device Health Attestation" -Data $windowsHealth -Properties @("DeviceName","UPN","SecureBoot","BitLocker","TPMVersion","CodeIntegrity","VirtualSecureMode","MemoryIntegrity","FirmwareProtection","SecuredCorePC","AttestationError","HealthCertIssuedDate")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "profileFailureSummary" -Title "Profils avec erreurs/conflits — résumé" -Data $profileFailureSummary -Properties @("PolicyName","FailureCount","Statuses","Devices")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "profileFailures" -Title "Profils avec erreurs/conflits — détails" -Data $profileFailures -Properties @("PolicyName","DeviceName","UPN","Manufacturer","Model","PolicyStatus","ReportStatus","UnifiedPolicyPlatformType","UnifiedPolicyType","PspdpuLastModifiedTimeUtc")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "unassigned" -Title "Profils et politiques sans affectation" -Data $unassignedObjects -Properties @("ProfileType","ProfileName","ProfileId")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "appFailures" -Title "Applications avec échecs d'installation" -Data $appFailures -Properties @("DisplayName","Publisher","Platform","FailedDeviceCount","FailedUserCount","InstalledDeviceCount","PendingInstallDeviceCount","NotInstalledDeviceCount")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "enrollmentFailures" -Title "Échecs d'enrôlement récents" -Data $recentEnrollmentFailures -Properties @("EnrollmentFailureDateTime","UPN","OS","OSVersion","EnrollmentMethod","FailureReason","FailureGuid")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "scriptFailures" -Title "Échecs de scripts" -Data $scriptFailures -Properties @("DeviceName","UPN","RunState","ErrorCode","ErrorDescription","PolicyId","PolicyResultState","PolicyResultDetail","ModifiedTime")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "profileInventory" -Title "Inventaire des profils et politiques" -Data @($profileInventory) -Properties @("Type","Name","Platform","Technology","SettingsCount","Created","LastModified")))
[void]$html.AppendLine((ConvertTo-HtmlTable -Id "devices" -Title "Inventaire complet des appareils" -Data $deviceInventory -Properties @("DeviceName","UserPrincipalName","OS","OSVersion","Manufacturer","Model","ComplianceState","LastSync","DaysSinceLastSync","Encrypted","SecureBoot","BitLockerDHA","TPMVersion","ManagementAgent","OwnerType","EnrollmentType","SerialNumber")))

[void]$html.AppendLine("<section class='section'><h2>Exports</h2><p class='muted'>Les dossiers CSV, JSON et RawReports situés à côté de ce rapport contiennent les données complètes utilisées pour l'analyse. Le HTML peut limiter certaines grandes tables à 5000 lignes pour préserver les performances du navigateur.</p></section>")

[void]$html.AppendLine("</main><script>$js</script></body></html>")
$html.ToString() | Set-Content -LiteralPath $reportFile -Encoding UTF8

# Machine-readable executive summary
$summary = [pscustomobject]@{
    GeneratedAt = $runEnd.ToString("o")
    TenantId = $tenantId
    Account = $account
    TotalDevices = $totalDevices
    CompliancePercentage = $compliancePct
    NonCompliantDevices = $nonCompliantCount
    UnknownOrGraceCompliance = $unknownComplianceDevices.Count
    StaleDevices = $staleCount
    VeryStaleDevices = $veryStaleCount
    WindowsDevices = $windowsCount
    SecureBootOff = $secureBootOff.Count
    SecureBootUnknown = $secureBootUnknown.Count
    BitLockerOff = $bitLockerOff.Count
    BitLockerUnknown = $bitLockerUnknown.Count
    TPMIssues = $tpmProblem.Count
    AttestationIssues = $attestationErrors.Count
    ProfileFailures = $profileFailures.Count
    UnassignedObjects = $unassignedObjects.Count
    AppFailures = $appFailures.Count
    RecentEnrollmentFailures = $recentEnrollmentFailures.Count
    ScriptFailures = $scriptFailures.Count
    FindingsCritical = $criticalCount
    FindingsHigh = $highCount
    FindingsMedium = $mediumCount
    FindingsLow = $lowCount
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputPath "Summary.json") -Encoding UTF8

Write-Ok "Rapport HTML : $reportFile"
Write-Ok "Exports CSV  : $script:CsvPath"
Write-Ok "Exports JSON : $script:JsonPath"
Write-Ok "Rapports bruts : $script:RawReportsPath"

Write-Host ""
Write-Host "Résumé" -ForegroundColor Cyan
Write-Host "  Devices             : $totalDevices"
Write-Host "  Compliance          : $compliancePct %"
Write-Host "  Non compliant       : $nonCompliantCount"
Write-Host "  Stale >= $StaleDays jours    : $staleCount"
Write-Host "  Secure Boot Off     : $($secureBootOff.Count)"
Write-Host "  BitLocker Off       : $($bitLockerOff.Count)"
Write-Host "  Profile failures    : $($profileFailures.Count)"
Write-Host "  App failures        : $($appFailures.Count)"
Write-Host "  Findings High       : $highCount"
Write-Host ""

if (-not $NoOpenReport) {
    try {
        if ($IsMacOS) {
            & open $reportFile
        } elseif ($IsWindows) {
            Start-Process $reportFile
        } elseif ($IsLinux) {
            & xdg-open $reportFile 2>$null
        }
    } catch {
        Write-Warn "Impossible d'ouvrir automatiquement le rapport. Ouvre manuellement : $reportFile"
    }
}

Disconnect-MgGraph | Out-Null

# endregion HTML
