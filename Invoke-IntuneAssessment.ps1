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
    Authentification : connexion interactive via le navigateur (pas de Device Code).

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

    [void]$html.AppendLine("<section class='section' id='section-$safeId'>")
    [void]$html.AppendLine("<h2>$(Encode-Html $Title) <span class='pill neutral'>$($rows.Count)</span></h2>")

    if ($rows.Count -eq 0) {
        [void]$html.AppendLine("<div class='empty-card'>$(Encode-Html $EmptyMessage)</div></section>")
        return $html.ToString()
    }

    if ($Properties.Count -eq 0) {
        $Properties = @($rows[0].PSObject.Properties.Name)
    }

    $shown = [math]::Min($rows.Count, $MaxRows)
    if ($rows.Count -gt $shown) {
        [void]$html.AppendLine("<p class='note'>Affichage limité à $shown ligne(s) dans le HTML. L'export CSV contient les données complètes.</p>")
    }

    [void]$html.AppendLine("<div class='toolbar'>")
    [void]$html.AppendLine("<input type='search' placeholder='Rechercher dans cette section...' onkeyup=`"filterTable('$safeId', this.value)`">")
    [void]$html.AppendLine("<div class='result-count' id='count-$safeId'>$shown résultat(s) affiché(s)</div>")
    [void]$html.AppendLine("</div>")

    [void]$html.AppendLine("<div class='table-wrap'><table id='$safeId'><thead><tr>")
    for ($colIndex = 0; $colIndex -lt $Properties.Count; $colIndex++) {
        $p = $Properties[$colIndex]
        [void]$html.Append("<th data-sort onclick=`"sortTable('$safeId',$colIndex)`">$(Encode-Html $p)</th>")
    }
    [void]$html.AppendLine("</tr></thead><tbody>")

    for ($i = 0; $i -lt $shown; $i++) {
        $row = $rows[$i]
        [void]$html.AppendLine("<tr class='data-row'>")
        foreach ($p in $Properties) {
            $prop = $row.PSObject.Properties[$p]
            $value = if ($null -ne $prop) { $prop.Value } else { "" }

            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $value = (@($value) -join ", ")
            }

            $display = Encode-Html $value
            $state = "$value".Trim()

            if ($state -match '^(?i)(compliant|passed|success|successful|enabled|on|healthy|true)$') {
                $display = "<span class='pill good'>$display</span>"
            }
            elseif ($state -match '^(?i)(noncompliant|non-compliant|failed|failure|error|disabled|off|false|critical)$') {
                $display = "<span class='pill bad'>$display</span>"
            }
            elseif ($state -match '^(?i)(warning|warn|skipped|pending|inGracePeriod|graceperiod)$') {
                $display = "<span class='pill warn'>$display</span>"
            }
            elseif ($state -match '^(?i)(conflict|investigate|unknown)$') {
                $display = "<span class='pill investigate'>$display</span>"
            }
            elseif ($state -match '^(?i)(notApplicable|not applicable|notrun|not run|n/a|na)$') {
                $display = "<span class='pill neutral'>$display</span>"
            }

            [void]$html.Append("<td>$display</td>")
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
Write-Host " Microsoft Intune - Complete Environment Assessment (macOS) - Light HTML v1.3 / Browser Login" -ForegroundColor Cyan
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

Write-Step "Connexion à Microsoft Graph via le navigateur (lecture seule)"
Connect-MgGraph -Scopes $scopes -NoWelcome

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
  --bg:#f4f7fb;
  --surface:#ffffff;
  --surface2:#eef3f9;
  --surface3:#dde7f2;
  --border:#e2eaf3;
  --text:#0f1e33;
  --muted:#5e7292;
  --accent:#2563eb;
  --navy:#1e3a8a;
  --green:#059669;
  --green-soft:#d1fae5;
  --red:#dc2626;
  --red-soft:#fde2e2;
  --amber:#d97706;
  --amber-soft:#fef3c7;
  --purple:#9333ea;
  --purple-soft:#f3e8ff;
  --gray:#64748b;
  --gray-soft:#e8edf4;
  --radius:12px;
  --radius-sm:8px;
  --shadow:0 2px 6px rgb(30 60 120 / .06), 0 1px 2px rgb(30 60 120 / .04);
  --shadow-hover:0 8px 22px rgb(30 60 120 / .13);
  --font:Inter, "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
}

* { box-sizing:border-box; }
html { scroll-behavior:smooth; }

body {
  margin:0;
  min-height:100vh;
  background:var(--bg);
  color:var(--text);
  font:14px/1.45 var(--font);
}

button, input { font:inherit; }

header {
  position:sticky;
  top:0;
  z-index:100;
}

.topbar {
  min-height:68px;
  display:flex;
  align-items:center;
  gap:18px;
  padding:12px 28px;
  background:var(--surface);
  border-top:3px solid var(--accent);
  border-bottom:1px solid var(--border);
  box-shadow:var(--shadow);
}

.brand-left {
  min-width:0;
  display:flex;
  align-items:center;
  gap:12px;
}

.logo-fallback {
  width:42px;
  height:42px;
  min-width:42px;
  overflow:hidden;
  padding:0 7px;
  border-radius:10px;
  display:flex;
  align-items:center;
  justify-content:center;
  background:linear-gradient(135deg,var(--accent),var(--navy));
  color:#fff;
  font-size:16px;
  line-height:1.05;
  text-align:center;
  font-weight:800;
  box-shadow:var(--shadow);
}

h1 {
  margin:0;
  font-size:16px;
  line-height:1.2;
  letter-spacing:-.01em;
}

.subtitle {
  margin-top:3px;
  color:var(--muted);
  font-size:11.5px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
  max-width:900px;
}

.topbar-actions {
  margin-left:auto;
  display:flex;
  align-items:center;
  gap:10px;
}

.btn {
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  padding:8px 12px;
  background:var(--surface);
  color:var(--text);
  cursor:pointer;
  font-size:12.5px;
  font-weight:600;
  white-space:nowrap;
  transition:.15s ease;
  text-decoration:none;
  display:inline-flex;
  align-items:center;
  gap:7px;
}

.btn:hover {
  background:var(--surface2);
  transform:translateY(-1px);
}

.btn-primary {
  background:var(--accent);
  color:#fff;
  border-color:transparent;
}

.btn-primary:hover { background:var(--navy); }

.generated {
  min-width:164px;
  padding-left:12px;
  border-left:1px solid var(--border);
  color:var(--muted);
  font-size:11.5px;
  line-height:1.35;
  text-align:right;
}

.generated strong {
  color:var(--text);
  font-weight:700;
}

.layout {
  max-width:1800px;
  margin:0 auto;
  padding:26px 32px 38px;
}

.grid {
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:14px;
  margin-bottom:26px;
}

.grid > .card {
  position:relative;
  min-height:132px;
  padding:16px 17px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  overflow:hidden;
  transition:.15s ease;
}

.grid > .card:hover {
  box-shadow:var(--shadow-hover);
  transform:translateY(-1px);
}

.grid > .card::before {
  content:"";
  position:absolute;
  top:0;
  left:0;
  right:0;
  height:3px;
  background:var(--accent);
  opacity:.8;
}

.grid > .card.card-good::before { background:var(--green); }
.grid > .card.card-bad::before { background:var(--red); }
.grid > .card.card-warn::before { background:var(--amber); }
.grid > .card.card-investigate::before { background:var(--purple); }

.card-title {
  color:var(--muted);
  font-size:10.5px;
  font-weight:700;
  line-height:1.35;
  text-transform:uppercase;
  letter-spacing:.055em;
}

.card-value {
  margin-top:9px;
  color:var(--text);
  font-size:27px;
  font-weight:800;
  line-height:1;
  letter-spacing:-.025em;
}

.card-note {
  margin-top:7px;
  color:var(--muted);
  font-size:11.5px;
  line-height:1.4;
}

.good { color:var(--green) !important; }
.bad { color:var(--red) !important; }
.warn { color:var(--amber) !important; }
.info { color:var(--accent) !important; }
.investigate { color:var(--purple) !important; }

.section { margin-top:26px; }

.section h2 {
  display:flex;
  align-items:center;
  gap:8px;
  margin:0 0 13px;
  color:var(--muted);
  font-size:12.5px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.065em;
}

.section h2::before {
  content:"";
  width:4px;
  height:17px;
  border-radius:999px;
  background:var(--accent);
}

.mini-grid {
  display:grid;
  grid-template-columns:repeat(3,minmax(260px,1fr));
  gap:14px;
}

.section .card,
.empty-card {
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
}

.empty-card {
  padding:24px;
  color:var(--muted);
}

.chart-card {
  min-height:220px;
  display:grid;
  grid-template-columns:138px minmax(0,1fr);
  align-items:center;
  gap:17px;
  padding:16px;
}

.pie {
  position:relative;
  width:132px;
  height:132px;
  border-radius:50%;
  box-shadow:inset 0 0 0 1px var(--border);
}

.pie::after {
  content:"";
  position:absolute;
  inset:26px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:50%;
}

.pie-center {
  position:absolute;
  inset:0;
  z-index:1;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  color:var(--text);
  font-size:18px;
  font-weight:800;
}

.pie-center small {
  font-size:9px;
  color:var(--muted);
  text-transform:uppercase;
  letter-spacing:.06em;
}

.legend {
  display:grid;
  gap:8px;
  color:var(--text);
  font-size:12px;
  min-width:0;
}

.legend-row {
  display:grid;
  grid-template-columns:11px minmax(0,1fr) auto;
  gap:8px;
  align-items:center;
}

.legend-row span:nth-child(2) {
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}

.legend-row strong {
  color:var(--text);
  font-size:11.5px;
}

.dot {
  width:10px;
  height:10px;
  border-radius:999px;
}

.dot.green { background:var(--green); }
.dot.red { background:var(--red); }
.dot.blue { background:var(--accent); }
.dot.orange { background:var(--amber); }
.dot.purple { background:var(--purple); }
.dot.gray { background:var(--gray); }

.chart-list-card {
  min-height:220px;
  padding:16px;
}

.chart-list-title {
  margin:0 0 14px;
  color:var(--text);
  font-size:13px;
  font-weight:800;
}

.bar-list {
  display:grid;
  gap:10px;
}

.bar-row {
  display:grid;
  grid-template-columns:minmax(95px,130px) minmax(80px,1fr) 48px;
  align-items:center;
  gap:10px;
  font-size:11.5px;
}

.bar-label {
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
  color:var(--muted);
}

.bar-track {
  height:8px;
  border-radius:999px;
  background:var(--surface3);
  overflow:hidden;
}

.bar-fill {
  height:100%;
  min-width:2px;
  border-radius:999px;
  background:linear-gradient(90deg,var(--accent),var(--navy));
}

.bar-fill.green-fill { background:var(--green); }
.bar-fill.red-fill { background:var(--red); }
.bar-fill.amber-fill { background:var(--amber); }
.bar-fill.purple-fill { background:var(--purple); }

.bar-count {
  text-align:right;
  font-weight:800;
}

.findings-card {
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  overflow:hidden;
}

.finding {
  display:grid;
  grid-template-columns:95px 220px minmax(260px,1fr) minmax(300px,1.2fr);
  gap:14px;
  align-items:start;
  padding:15px 16px;
  border-bottom:1px solid var(--border);
}

.finding:last-child { border-bottom:0; }

.finding-title {
  font-weight:800;
  color:var(--text);
}

.finding-category {
  margin-bottom:3px;
  color:var(--muted);
  font-size:10px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.055em;
}

.small {
  color:var(--muted);
  font-size:11px;
}

.note {
  margin:0 0 10px;
  color:var(--amber);
  font-size:11.5px;
}

.toolbar {
  display:flex;
  gap:9px;
  flex-wrap:wrap;
  align-items:flex-start;
  padding:14px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  margin-bottom:13px;
}

input[type="search"] {
  min-height:38px;
  min-width:340px;
  flex:1 1 340px;
  padding:8px 10px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  color:var(--text);
  font-size:12.5px;
}

input[type="search"]::placeholder { color:var(--muted); }

.result-count {
  margin-left:auto;
  min-height:38px;
  display:flex;
  align-items:center;
  padding:0 6px;
  color:var(--muted);
  font-size:11.5px;
}

.table-wrap {
  overflow:auto;
  max-height:760px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
}

table {
  width:100%;
  border-collapse:collapse;
  font-size:12.5px;
  white-space:nowrap;
}

th {
  position:sticky;
  top:0;
  z-index:2;
  padding:11px 12px;
  background:var(--surface2);
  border-bottom:1px solid var(--border);
  color:var(--muted);
  text-align:left;
  font-size:10px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.045em;
  cursor:pointer;
  user-select:none;
}

th[data-sort]::after {
  content:" ↕";
  opacity:.45;
}

td {
  padding:10px 12px;
  border-bottom:1px solid var(--border);
  vertical-align:top;
  max-width:620px;
  overflow:hidden;
  text-overflow:ellipsis;
}

tbody tr.data-row:hover td { background:var(--surface2); }
tbody tr:last-child td { border-bottom:0; }

.pill {
  display:inline-flex;
  align-items:center;
  padding:3px 8px;
  border:1px solid var(--border);
  border-radius:999px;
  background:var(--surface3);
  color:var(--muted);
  font-size:10.5px;
  font-weight:700;
}

.pill.good {
  background:var(--green-soft);
  border-color:transparent;
  color:var(--green) !important;
}

.pill.bad {
  background:var(--red-soft);
  border-color:transparent;
  color:var(--red) !important;
}

.pill.warn {
  background:var(--amber-soft);
  border-color:transparent;
  color:var(--amber) !important;
}

.pill.investigate {
  background:var(--purple-soft);
  border-color:transparent;
  color:var(--purple) !important;
}

.pill.neutral {
  background:var(--gray-soft);
  border-color:transparent;
  color:var(--gray) !important;
}

.pill.critical {
  background:var(--red-soft);
  border-color:transparent;
  color:var(--red) !important;
}

.pill.high {
  background:var(--amber-soft);
  border-color:transparent;
  color:var(--amber) !important;
}

.pill.medium {
  background:var(--purple-soft);
  border-color:transparent;
  color:var(--purple) !important;
}

.pill.low {
  background:var(--green-soft);
  border-color:transparent;
  color:var(--green) !important;
}

.data-row td .pill {
  min-height:24px;
  justify-content:center;
  gap:6px;
  padding:5px 9px;
  border:0;
  border-radius:8px;
  font-size:10.5px;
  line-height:1;
}

.data-row td .pill::before,
.finding .pill::before {
  content:"";
  display:block;
  width:6px;
  height:6px;
  min-width:6px;
  flex:0 0 6px;
  border-radius:999px;
  background:currentColor;
  opacity:.78;
}

footer {
  max-width:1800px;
  margin:0 auto;
  padding:0 32px 32px;
  color:var(--muted);
  font-size:11.5px;
}

@media (max-width:1180px) {
  .mini-grid { grid-template-columns:1fr; }
  .finding { grid-template-columns:95px 1fr; }
  .finding-detail, .finding-action { grid-column:2; }
}

@media (max-width:820px) {
  .topbar {
    align-items:flex-start;
    padding:12px 16px;
    flex-wrap:wrap;
  }

  .topbar-actions {
    width:100%;
    margin-left:54px;
    flex-wrap:wrap;
  }

  .generated { margin-left:auto; }
  .layout { padding:20px 16px 30px; }
  input[type="search"] { min-width:100%; }
  .finding { grid-template-columns:1fr; }
  .finding-detail, .finding-action { grid-column:auto; }
}

@media print {
  header { position:static; }
  .topbar-actions .btn,
  .toolbar { display:none !important; }

  .table-wrap {
    max-height:none;
    overflow:visible;
  }

  .table-wrap,
  .grid > .card,
  .section .card,
  .findings-card {
    box-shadow:none;
  }

  body { background:#fff; }
}
'@

$js = @'
function filterTable(id, query) {
  query = (query || "").toLowerCase();
  const table = document.getElementById(id);
  if (!table) return;

  const rows = table.querySelectorAll("tbody tr.data-row");
  let visible = 0;

  rows.forEach(r => {
    const show = r.innerText.toLowerCase().includes(query);
    r.style.display = show ? "" : "none";
    if (show) visible++;
  });

  const counter = document.getElementById("count-" + id);
  if (counter) counter.textContent = visible + " résultat(s) affiché(s)";
}

const sortState = {};

function sortTable(id, column) {
  const table = document.getElementById(id);
  if (!table) return;

  const tbody = table.querySelector("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr.data-row"));
  const key = id + ":" + column;
  const ascending = sortState[key] !== true;
  sortState[key] = ascending;

  rows.sort((a, b) => {
    const av = (a.children[column]?.innerText || "").trim();
    const bv = (b.children[column]?.innerText || "").trim();

    const an = Number(av.replace(/[% ,]/g, ""));
    const bn = Number(bv.replace(/[% ,]/g, ""));
    const numeric = av !== "" && bv !== "" && !Number.isNaN(an) && !Number.isNaN(bn);

    if (numeric) return ascending ? an - bn : bn - an;
    return ascending
      ? av.localeCompare(bv, undefined, {numeric:true, sensitivity:"base"})
      : bv.localeCompare(av, undefined, {numeric:true, sensitivity:"base"});
  });

  rows.forEach(r => tbody.appendChild(r));
}
'@

# Build chart values
$compliantDeviceCount = @($deviceInventory | Where-Object { "$($_.ComplianceState)" -match '^(?i)compliant$' }).Count
$otherComplianceCount = [math]::Max(0, $totalDevices - $compliantDeviceCount - $nonCompliantCount)
$compliantSlice = if ($totalDevices -gt 0) { [math]::Round(($compliantDeviceCount / $totalDevices) * 100, 2) } else { 0 }
$nonCompliantSliceEnd = if ($totalDevices -gt 0) { [math]::Round((($compliantDeviceCount + $nonCompliantCount) / $totalDevices) * 100, 2) } else { 0 }

$maxPlatformCount = if ($platformSummary.Count -gt 0) { ($platformSummary | Measure-Object Count -Maximum).Maximum } else { 1 }
$platformBars = [System.Text.StringBuilder]::new()
foreach ($p in @($platformSummary | Select-Object -First 6)) {
    $width = if ($maxPlatformCount -gt 0) { [math]::Round(($p.Count / $maxPlatformCount) * 100, 1) } else { 0 }
    [void]$platformBars.AppendLine("<div class='bar-row'><div class='bar-label' title='$(Encode-Html $p.OperatingSystem)'>$(Encode-Html $p.OperatingSystem)</div><div class='bar-track'><div class='bar-fill' style='width:$width%'></div></div><div class='bar-count'>$($p.Count)</div></div>")
}

$securityBarsData = @(
    [pscustomobject]@{ Name="Secure Boot Off"; Count=$secureBootOff.Count; Class="red-fill" },
    [pscustomobject]@{ Name="BitLocker Off"; Count=$bitLockerOff.Count; Class="red-fill" },
    [pscustomobject]@{ Name="TPM Issues"; Count=$tpmProblem.Count; Class="amber-fill" },
    [pscustomobject]@{ Name="Attestation"; Count=$attestationErrors.Count; Class="purple-fill" },
    [pscustomobject]@{ Name="VSM Off"; Count=$vsmOff.Count; Class="amber-fill" }
)
$maxSecurityCount = [math]::Max(1, (($securityBarsData | Measure-Object Count -Maximum).Maximum))
$securityBars = [System.Text.StringBuilder]::new()
foreach ($s in $securityBarsData) {
    $width = [math]::Round(($s.Count / $maxSecurityCount) * 100, 1)
    [void]$securityBars.AppendLine("<div class='bar-row'><div class='bar-label'>$(Encode-Html $s.Name)</div><div class='bar-track'><div class='bar-fill $($s.Class)' style='width:$width%'></div></div><div class='bar-count'>$($s.Count)</div></div>")
}

$html = [System.Text.StringBuilder]::new()
[void]$html.AppendLine("<!doctype html><html lang='fr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>")
[void]$html.AppendLine("<title>Microsoft Intune - Environment Assessment</title><style>$css</style></head><body>")

[void]$html.AppendLine("<header><div class='topbar'>")
[void]$html.AppendLine("<div class='brand-left'><div class='logo-fallback'>IN</div><div>")
[void]$html.AppendLine("<h1>Microsoft Intune — Environment Assessment</h1>")
[void]$html.AppendLine("<div class='subtitle'>Tenant $(Encode-Html $tenantId) · $(Encode-Html $account) · Audit complet des appareils, conformité, sécurité, profils, applications et enrôlement</div>")
[void]$html.AppendLine("</div></div>")
[void]$html.AppendLine("<div class='topbar-actions'><button class='btn' onclick='window.print()'>Imprimer</button><a class='btn btn-primary' href='#findings'>Constats prioritaires</a></div>")
[void]$html.AppendLine("<div class='generated'>Généré le<br><strong>$(Encode-Html ($runEnd.ToString('yyyy-MM-dd HH:mm:ss zzz')))</strong><br>$([math]::Round($duration.TotalMinutes,1)) min</div>")
[void]$html.AppendLine("</div></header>")

[void]$html.AppendLine("<main class='layout'>")

[void]$html.AppendLine("<div class='grid'>")
$cards = @(
    [pscustomobject]@{Title="Appareils gérés"; Value=$totalDevices; Note="Inventaire Intune"; Class=""; ValueClass="" },
    [pscustomobject]@{Title="Conformité"; Value="$compliancePct %"; Note="$compliantDeviceCount appareil(s) compliant"; Class="card-good"; ValueClass="good" },
    [pscustomobject]@{Title="Non compliant"; Value=$nonCompliantCount; Note="$($nonComplianceReasons.Count) paramètre(s)/résultat(s) détecté(s)"; Class="card-bad"; ValueClass="bad" },
    [pscustomobject]@{Title="Stale ≥ $StaleDays jours"; Value=$staleCount; Note="$veryStaleCount très stale (≥ $VeryStaleDays j)"; Class="card-warn"; ValueClass="warn" },
    [pscustomobject]@{Title="Secure Boot Off"; Value=$secureBootOff.Count; Note="$($secureBootUnknown.Count) état(s) inconnu(s)/N/A"; Class="card-bad"; ValueClass="bad" },
    [pscustomobject]@{Title="BitLocker Off"; Value=$bitLockerOff.Count; Note="$($bitLockerUnknown.Count) état(s) inconnu(s)/N/A"; Class="card-bad"; ValueClass="bad" },
    [pscustomobject]@{Title="Profils en échec"; Value=$profileFailures.Count; Note="$($profileFailureSummary.Count) profil(s) concerné(s)"; Class="card-investigate"; ValueClass="investigate" },
    [pscustomobject]@{Title="Apps en échec"; Value=$appFailures.Count; Note="Applications avec au moins un échec"; Class="card-warn"; ValueClass="warn" },
    [pscustomobject]@{Title="Constats High"; Value=$highCount; Note="$criticalCount Critical · $mediumCount Medium · $lowCount Low"; Class="card-bad"; ValueClass="bad" }
)

foreach ($c in $cards) {
    [void]$html.AppendLine("<div class='card $($c.Class)'><div class='card-title'>$(Encode-Html $c.Title)</div><div class='card-value $($c.ValueClass)'>$(Encode-Html $c.Value)</div><div class='card-note'>$(Encode-Html $c.Note)</div></div>")
}
[void]$html.AppendLine("</div>")

# Visual summary
[void]$html.AppendLine("<section class='section'><h2>Vue d'ensemble</h2><div class='mini-grid'>")

[void]$html.AppendLine("<div class='card chart-card'>")
[void]$html.AppendLine("<div class='pie' style='background:conic-gradient(var(--green) 0 $compliantSlice%, var(--red) $compliantSlice% $nonCompliantSliceEnd%, var(--gray) $nonCompliantSliceEnd% 100%)'><div class='pie-center'>$compliancePct%<small>Compliance</small></div></div>")
[void]$html.AppendLine("<div class='legend'>")
[void]$html.AppendLine("<div class='legend-row'><span class='dot green'></span><span>Compliant</span><strong>$compliantDeviceCount</strong></div>")
[void]$html.AppendLine("<div class='legend-row'><span class='dot red'></span><span>Non compliant</span><strong>$nonCompliantCount</strong></div>")
[void]$html.AppendLine("<div class='legend-row'><span class='dot gray'></span><span>Autre / inconnu</span><strong>$otherComplianceCount</strong></div>")
[void]$html.AppendLine("</div></div>")

[void]$html.AppendLine("<div class='card chart-list-card'><div class='chart-list-title'>Plateformes</div><div class='bar-list'>$($platformBars.ToString())</div></div>")
[void]$html.AppendLine("<div class='card chart-list-card'><div class='chart-list-title'>Sécurité Windows — écarts</div><div class='bar-list'>$($securityBars.ToString())</div></div>")

[void]$html.AppendLine("</div></section>")

# Findings
[void]$html.AppendLine("<section class='section' id='findings'><h2>Constats prioritaires <span class='pill neutral'>$($findings.Count)</span></h2>")
[void]$html.AppendLine("<div class='findings-card'>")
foreach ($f in $findings) {
    $sevClass = switch ($f.Severity) {
        "Critical" { "critical" }
        "High"     { "high" }
        "Medium"   { "medium" }
        "Low"      { "low" }
        default    { "neutral" }
    }

    [void]$html.AppendLine("<div class='finding'>")
    [void]$html.AppendLine("<div><span class='pill $sevClass'>$(Encode-Html $f.Severity)</span><div class='small'>Count: $($f.Count)</div></div>")
    [void]$html.AppendLine("<div><div class='finding-category'>$(Encode-Html $f.Category)</div><div class='finding-title'>$(Encode-Html $f.Title)</div></div>")
    [void]$html.AppendLine("<div class='finding-detail'>$(Encode-Html $f.Detail)</div>")
    [void]$html.AppendLine("<div class='finding-action'><strong>Action :</strong> $(Encode-Html $f.Recommendation)</div>")
    [void]$html.AppendLine("</div>")
}
[void]$html.AppendLine("</div></section>")

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

[void]$html.AppendLine("<section class='section'><h2>Exports</h2><div class='empty-card'>Les dossiers <strong>CSV</strong>, <strong>JSON</strong> et <strong>RawReports</strong> situés à côté de ce rapport contiennent les données complètes utilisées pour l'analyse. Les très grandes tables HTML sont limitées à 5000 lignes afin de conserver de bonnes performances dans le navigateur.</div></section>")

[void]$html.AppendLine("</main>")
[void]$html.AppendLine("<footer>Microsoft Intune Environment Assessment · Rapport généré localement par PowerShell · Lecture seule Microsoft Graph</footer>")
[void]$html.AppendLine("<script>$js</script></body></html>")

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
