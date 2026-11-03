#Requires -Version 7.2
<#
.SYNOPSIS
 Read-only Intune assessment with Maester-inspired terminal dashboard, policy failures, Endpoint Security, tenant governance, maturity scoring, action plan and bilingual executive summary.
.DESCRIPTION
 Collects managed devices, Autopilot registration, Intune-managed apps,
 installation failure status and directory account state for associated users.
 Each optional collection fails independently and reports limitations explicitly.
.PARAMETER NoConsoleDashboard
 Disables the interactive ANSI console dashboard and uses standard line-by-line logs.
.PARAMETER InactiveDays
 Threshold for stale Intune device synchronization (default 30).
.PARAMETER CustomerName
 Customer name used for the report folder (<Customer>_yyyyMMdd-HHmmss) and the report header.
 Default: the Entra organization display name; tenant ID when unavailable.
.PARAMETER Baseline
 Configuration baseline: Prompt (default, asks at start-up), FlorianBaseline (github.com/fdaminato/IntuneBaseline)
 or OpenIntuneBaseline (github.com/SkipToTheEndpoint/OpenIntuneBaseline). Non-interactive runs use FlorianBaseline.
.PARAMETER BaselineRepo
 GitHub repository (owner/name or URL) used as configuration baseline. Overrides -Baseline and the start-up prompt.
 Every Settings Catalog JSON file of the repository is used; Windows and macOS are split by the
 'platforms' field of each file. Use SkipToTheEndpoint/OpenIntuneBaseline for the community baseline.
.PARAMETER BaselineName
 Name shown in the report (default: repository or folder name).
.PARAMETER BaselineRef
 Branch, tag or commit of the baseline repository (default: repository default branch).
.PARAMETER BaselinePath
 Local folder with Settings Catalog JSON files, used instead of GitHub (to test a baseline before pushing it).
.PARAMETER GitHubToken
 Read-only GitHub token for a private baseline repository. Never written to the report or metadata.
.PARAMETER Anonymize
 Replaces device names, serial numbers, user names, e-mail addresses, customer name and tenant ID with
 stable tokens in the HTML report, CSV, Excel workbook and executive summaries (for demos and sharing).
 Run-Metadata.json keeps the real tenant ID so run-to-run comparison still works.
.PARAMETER SkipExcelExport
 Does not create Intune-Assessment.xlsx (one sheet per CSV export).
.PARAMETER SkipIntuneReview
 Skips the Intune configuration review (compliance actions, clean-up rule, apps, OS updates per platform,
 enrollment profiles, Intune Suite, Endpoint analytics, audit log).
.PARAMETER SkipAuditLog
 Skips the Intune audit log (destructive device actions).
.PARAMETER SkipZeroTrust
 Skips the Zero Trust Assessment device tests (Zero Trust view).
.PARAMETER AuditDays
 Audit log period in days (default 30).
.PARAMETER OutputPath
 Output root; creates a timestamped folder.
.PARAMETER SkipAppStatuses
 Skip per-app device install status retrieval, useful for large tenants.
.PARAMETER SkipDirectoryUsers
 Skip primary-user accountEnabled validation (avoids User.Read.All scope).
.PARAMETER SkipAutopilot
 Skip Autopilot registration enumeration.
.PARAMETER MaxAppsForStatus
 Maximum number of apps queried for per-device install status, 0 = all (default 0).
.PARAMETER IncludeComplianceDetails
 Legacy switch (details now run by default).
.PARAMETER SkipComplianceDetails
 Skip detailed compliance collection for a faster inventory-only run.
.PARAMETER ComplianceMaxWaitSeconds
 Maximum cumulative wait (seconds) on Graph throttling while collecting compliance details (default 900).
.PARAMETER MaxComplianceDevices
 Maximum noncompliant devices to query in detail (default 0 = all).
.PARAMETER DisableCache
 Disables the local reference cache (OpenIntuneBaseline files and Graph setting definitions). Live tenant data is never cached.
.PARAMETER ReportLanguage
 Initial language of the HTML report: fr (default) or en. A FR/EN button in the report switches at any time.
.PARAMETER SkipGovernance
 Skips tenant governance and integration checks (connectors, Conditional Access, enrollment, RBAC,
 multi-admin approval, MAM, scripts, Autopilot profiles, filters, assignment hygiene, LAPS).
.PARAMETER SkipConditionalAccess
 Skips Conditional Access analysis (avoids the Policy.Read.All scope).
.PARAMETER SkipEntraDevices
 Skips the Entra device cross-check (avoids the Device.Read.All scope).
.PARAMETER SkipHardware
 Skips TPM / Secure Boot / Windows 11 readiness collection.
.PARAMETER SkipExecutiveDocuments
 Does not generate the bilingual DOCX/PDF executive summaries.
.PARAMETER PreviousRunPath
 Folder (or Run-Metadata.json) of a previous run to compare with. By default the latest
 previous run of the same tenant in -OutputPath is used.
.PARAMETER NoRunComparison
 Disables the automatic comparison with the previous run.
.PARAMETER MinIosVersion
 Minimum iOS/iPadOS version expected (default 17.0). Same for -MinMacOSVersion and -MinAndroidVersion.
.PARAMETER StaleEntraDays
 Entra devices without sign-in for this many days and not in Intune are reported as stale (default 90).
.PARAMETER InstallModules
 Install Microsoft.Graph.Authentication module for current user if missing.
.EXAMPLE
 .\Invoke-IntuneAssessmentDashboard.ps1 -InactiveDays 30 -OpenReport
.EXAMPLE
 .\Invoke-IntuneAssessmentDashboard.ps1 -InactiveDays 45 -SkipAppStatuses -SkipDirectoryUsers -OpenReport
.NOTES
 Version 3.74 (consolidated build: no separate patch files required).
 Requires PowerShell 7.2+ (ForEach-Object -Parallel, ConvertFrom-Json -AsHashtable, .NET 6 SHA256.HashData).
 Layout: 1 Parameters / 2 Console UI / 3 Helpers (Graph, CSV, report exports) / 4 Connection /
 5 Collections / 6 Analysis & findings / 7 Scoring & action plan / 8 HTML report / 9 Executive documents.
 Changelog (summary):
  3.74 Baseline choice: OpenIntuneBaseline (latest) or Windows Baseline 24H2 / 25H2 / 26H2 (fdaminato).
  3.73 Zero Trust view: Microsoft Zero Trust Assessment device tests (Windows, macOS, iOS, Android, tenant);
       Intune apps read from Graph beta (Store apps (new) / winGetApp now listed); -SkipZeroTrust.
  3.72 Start-up prompt to choose FlorianBaseline (default) or OpenIntuneBaseline; new -Baseline parameter.
  3.71 Configurable baseline: -BaselineRepo (default fdaminato/IntuneBaseline), -BaselineName, -BaselineRef,
       -BaselinePath (local folder), -GitHubToken (private repository). Report labels follow the baseline name.
  3.70 New HTML design: sidebar navigation, hero score ring, domain bars, quick wins, KPI icons and
       trends, light/dark theme (system default + switch), print button, refreshed tables and cards.
  3.60 Reliability: Intune RBAC per role definition, custom roles, LAPS 'not verified' state, Android AOSP
       platform, export-report log in Data quality. New Intune review: compliance actions, clean-up rule,
       app install summary, Win32 supersedence, OS updates per platform, enrollment tokens and ADE profiles,
       Intune Suite, audit log, Endpoint analytics. Excel workbook, -Anonymize, fuller FR translation,
       scoring helpers for Pester tests.
  3.51 Report folder named <Customer>_yyyyMMdd-HHmmss; new -CustomerName parameter.
  3.50 Consolidation: report-export helpers defined once and reused, dead code removed, approved verbs,
       null comparisons and hashtable expressions made parser/lint-safe.
  3.44 Noncompliance details from one Intune export report; per-device lookup only as fallback.
  3.43 Adaptive Graph throttling (chunk size, pacing, Retry-After, one-by-one fallback).
  3.42 FR/EN switch in the HTML report (French by default, -ReportLanguage).
  3.41 Executive PDF: wait for file, classic headless retry, Word fallback on Windows.
  3.40 Multi-view HTML report (Overview, Action plan, Findings, Baseline, Inventory, Data quality).
 Graph calls are batched ($batch, 20 requests per call) and honour Retry-After on HTTP 429/5xx.
 Read-only for tenant resources. An export-job POST creates a temporary reporting job, not a configuration change.
 Account disabled is validated only when directory users retrieval succeeds.
 Last device check-in is not a measure of user's own sign-in activity.
 An absent Autopilot record is not proof of missing or invalid hardware hash.
#>
# =====================================================================================
# SECTION 1 - Parameters
# =====================================================================================
[CmdletBinding()]
param(
 [ValidateRange(1,365)][int]$InactiveDays = 30,
 [string]$OutputPath = (Join-Path (Get-Location).Path 'IntuneAssessmentReports'),
 [string]$CustomerName = '',
 [switch]$Anonymize,
 [switch]$SkipExcelExport,
 [switch]$SkipIntuneReview,
 [switch]$SkipAuditLog,
 [switch]$SkipZeroTrust,
 [ValidateRange(1,90)][int]$AuditDays = 30,
 [switch]$OpenReport,
 [switch]$NoConsoleDashboard,
 [switch]$InstallModules,
 [switch]$SkipAppStatuses,
 [switch]$SkipDirectoryUsers,
 [switch]$SkipAutopilot,
 [switch]$IncludeComplianceDetails,
 [switch]$SkipComplianceDetails,
 [ValidateRange(0,100000)][int]$MaxComplianceDevices = 0,
 [ValidateRange(30,3600)][int]$ComplianceMaxWaitSeconds = 900,
 [ValidateRange(0,100000)][int]$MaxAppsForStatus = 0,
 [switch]$SkipDeploymentReports,
 [switch]$SkipBitLockerEscrow,
 [switch]$SkipDefenderHealth,
 [switch]$SkipSettingFailures,
 [switch]$SkipOpenIntuneBaseline,
 [string]$OpenIntuneBaselineRef = "main",
 [string]$OpenIntuneBaselineMacRef = "main",
 [ValidateSet('Prompt','OpenIntuneBaseline','Windows24H2','Windows25H2','Windows26H2')][string]$Baseline = 'Prompt',
 [string]$BaselineRepo = '',
 [string]$BaselineName = '',
 [string]$BaselineRef = '',
 [string]$BaselinePath = '',
 [string]$GitHubToken = '',
 [ValidateRange(1,180)][int]$ReportTimeoutSeconds = 90,
 [ValidateRange(1,12)][int]$MaxConcurrentRequests = 5,
 [switch]$DisableCache,
 [ValidateSet('fr','en')][string]$ReportLanguage = 'fr',
 [switch]$SkipGovernance,
 [switch]$SkipConditionalAccess,
 [switch]$SkipEntraDevices,
 [switch]$SkipHardware,
 [switch]$SkipExecutiveDocuments,
 [switch]$NoRunComparison,
 [string]$PreviousRunPath,
 [string]$MinIosVersion = '17.0',
 [string]$MinMacOSVersion = '14.0',
 [string]$MinAndroidVersion = '13',
 [ValidateRange(30,730)][int]$StaleEntraDays = 90,
 [ValidateRange(0,100000)][int]$MaxGroupsToCheck = 500,
 [ValidateRange(0,100000)][int]$MaxHardwareDevices = 2000,
 [ValidateRange(1,720)][int]$CacheMaxAgeHours = 24,
 [string]$CachePath = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'IntuneAssessment\ReferenceCache')
)
# =====================================================================================
# SECTION 2 - Runtime state and console UI
# =====================================================================================
$ErrorActionPreference = 'Stop'
$EnableCache = -not $DisableCache
# Baseline selection (v3.74): asked once at start-up unless -Baseline, -BaselineRepo or -BaselinePath is given.
# OpenIntuneBaseline always uses the latest commit of its default branch (main).
$baselineExplicit=$PSBoundParameters.ContainsKey('BaselineRepo') -or $PSBoundParameters.ContainsKey('BaselinePath')
$BaselinePathFilter=''
$baselinePlatforms=@('Windows','macOS')
if(-not $baselineExplicit -and -not $SkipOpenIntuneBaseline){
 if($Baseline -eq 'Prompt'){
  $nonInteractiveArg=@([Environment]::GetCommandLineArgs() | Where-Object {$_ -match '(?i)^-noni'}).Count -gt 0
  if([Environment]::UserInteractive -and -not $nonInteractiveArg -and -not [Console]::IsInputRedirected){
   Write-Host ''
   Write-Host 'Choose the configuration baseline to compare with:' -ForegroundColor Cyan
   Write-Host '  [1] OpenIntuneBaseline       (SkipToTheEndpoint, latest version, Windows + macOS) - default'
   Write-Host '  [2] Windows Baseline 24H2    (fdaminato/Microsoft-Intune-Assessment, Windows only)'
   Write-Host '  [3] Windows Baseline 25H2    (fdaminato/Microsoft-Intune-Assessment, Windows only)'
   Write-Host '  [4] Windows Baseline 26H2    (fdaminato/Microsoft-Intune-Assessment, Windows only)'
   do{$baselineAnswer=([string](Read-Host 'Baseline [1-4] (Enter = 1)')).Trim()}while($baselineAnswer -notin @('','1','2','3','4'))
   $Baseline=switch($baselineAnswer){'2'{'Windows24H2'};'3'{'Windows25H2'};'4'{'Windows26H2'};default{'OpenIntuneBaseline'}}
  }else{$Baseline='OpenIntuneBaseline'}
 }
 if($Baseline -eq 'OpenIntuneBaseline'){
  $BaselineRepo='SkipToTheEndpoint/OpenIntuneBaseline'
  if(-not $PSBoundParameters.ContainsKey('OpenIntuneBaselineRef')){$OpenIntuneBaselineRef='main'}
  if(-not $PSBoundParameters.ContainsKey('OpenIntuneBaselineMacRef')){$OpenIntuneBaselineMacRef='main'}
  if(-not $BaselineName){$BaselineName='OpenIntuneBaseline'}
 }else{
  $winRelease=$Baseline.Substring(7)
  $BaselineRepo='fdaminato/Microsoft-Intune-Assessment'
  $BaselinePathFilter='(?i)^Windows Baseline/.*'+$winRelease+'.*\.json$'
  $baselinePlatforms=@('Windows')
  if(-not $BaselineName){$BaselineName="Windows Baseline $winRelease"}
 }
 Write-Host "Baseline selected: $BaselineName" -ForegroundColor Green
}elseif(-not $BaselineRepo){$BaselineRepo='SkipToTheEndpoint/OpenIntuneBaseline'}
$ProgressPreference = 'SilentlyContinue'
$base = 'https://graph.microsoft.com/v1.0'
$warnings = [System.Collections.Generic.List[string]]::new()
$collection = [ordered]@{}
$now = [DateTime]::UtcNow
$cutoff = $now.AddDays(-$InactiveDays)

# Interactive ANSI terminal UI (no extra modules or separate windows required).
# Falls back to conventional logs for redirected output and limited hosts.
$script:GraphStats=[ordered]@{Requests=0;Retries=0;Pages=0;CacheHits=0;BaselineFiles=0;PhaseStart=(Get-Date)}
$script:uiStart = Get-Date
$script:uiEvents = [System.Collections.Generic.List[string]]::new()
$script:uiWarnings = [System.Collections.Generic.List[string]]::new()
$script:uiPhase = 0
$script:uiMessage = 'Starting assessment'
$script:uiTick = 0
$script:uiPhases = @(
 'Connect & identify tenant',
 'Managed device inventory',
 'Autopilot, apps & users',
 'Compliance & application checks',
 'Configuration & updates',
 'OpenIntuneBaseline comparison',
 'Policy deployment & update reports',
 'BitLocker recovery key escrow',
 'Policy setting error analysis',
 'Defender health signals',
 'Findings & HTML report'
)
$script:uiEnabled = $false
if (-not $NoConsoleDashboard) {
 try {
  $raw = $Host.UI.RawUI
  $null = $raw.WindowSize.Width
  $script:uiEnabled = (-not [Console]::IsOutputRedirected) -and ($raw.WindowSize.Width -ge 80) -and ($raw.WindowSize.Height -ge 32)
 } catch { $script:uiEnabled = $false }
}
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
$script:uiEsc = [string][char]27
function Get-ConsoleClippedText([string]$Value,[int]$Max) {
 if ($Max -le 1) { return '' }
 if ($null -eq $Value) { return '' }
 $clean = $Value -replace '[\r\n\t]+',' ' -replace '\x1b\[[0-9;]*[A-Za-z]',''
 if ($clean.Length -gt $Max) { return ($clean.Substring(0,$Max-1) + [string][char]0x2026) }
 return $clean
}
function Format-ConsoleColor([string]$Kind,[string]$Value) {
 $e = $script:uiEsc
 $code = switch($Kind) {
  'cyan' {'38;5;81'} 'green' {'38;5;114'} 'amber' {'38;5;215'}
  'red' {'38;5;203'} 'muted' {'38;5;245'} 'purple' {'38;5;141'}
  'white' {'1;97'} default {'37'}
 }
 return "${e}[${code}m${Value}${e}[0m"
}
function Get-ConsoleCount([string]$VarName) {
 $v=Get-Variable -Name $VarName -Scope Script -ErrorAction SilentlyContinue
 if($null -eq $v -or $null -eq $v.Value) { return '-' }
 try { return [string]@($v.Value).Count } catch { return '-' }
}
function Set-ConsolePhase([string]$Message) {
 $m=$Message.ToLowerInvariant()
 $stage=0
 if($m -match 'report saved|html report|generating.*report'){$stage=11}
 elseif($m -match 'defender health'){$stage=10}
 elseif($m -match 'per-setting|policy setting|setting failures'){$stage=9}
 elseif($m -match 'bitlocker escrow'){$stage=8}
 elseif($m -match 'policy deployment|feature update policy ids|feature update|exporting .* policy'){$stage=7}
 elseif($m -match 'openintunebaseline|baseline comparison|settings catalog values'){$stage=6}
 elseif($m -match 'configuration|windows update|update profiles|settings catalog|update rings'){$stage=5}
 elseif($m -match 'compliance|app status|install status'){$stage=4}
 elseif($m -match 'autopilot|application|directory users'){$stage=3}
 elseif($m -match 'managed devices|device inventory'){$stage=2}
 elseif($m -match 'tenant|connect'){$stage=1}
 if($stage -gt $script:uiPhase){$script:uiPhase=$stage;$script:GraphStats.PhaseStart=Get-Date}
}
# Slate console UI: compact, quiet, high-contrast, event-driven.
# ANSI color is optional; all layout characters are ASCII for broad terminal support.
$script:uiSpin = @('.','o','O','o')
$script:uiFramesPerEvent = 1
function Get-ConsoleTint([string]$Text,[int]$Color=75) {
 $e=$script:uiEsc
 return "${e}[38;5;${Color}m${Text}${e}[0m"
}
function Get-ConsoleGauge([int]$Width,[int]$Filled,[int]$Shift) {
 $Width=[Math]::Max(6,$Width)
 $Filled=[Math]::Max(0,[Math]::Min($Width,$Filled))
 $line=''
 for($j=0;$j -lt $Width;$j++) {
  if($j -lt $Filled) { $line += Get-ConsoleTint '=' 79 }
  elseif($j -eq $Filled -and $Filled -lt $Width) { $line += Get-ConsoleTint '>' 75 }
  else { $line += Get-ConsoleTint '-' 239 }
 }
 return $line
}
function Write-ConsoleDashboard {
 if(-not $script:uiEnabled){return}
 try {
  $ws=$Host.UI.RawUI.WindowSize
  if([int]$ws.Height -lt 32 -or [int]$ws.Width -lt 80){return}
  $width=[Math]::Min(120,[Math]::Max(78,[int]$ws.Width-3))
  $script:uiTick++
  $e=$script:uiEsc
  $elapsed=(Get-Date)-$script:uiStart
  $clock=('{0:00}:{1:00}:{2:00}' -f [int][Math]::Floor($elapsed.TotalHours),$elapsed.Minutes,$elapsed.Seconds)
  $phase=[Math]::Max(0,[Math]::Min($script:uiPhases.Count,$script:uiPhase))
  $done=if($phase -eq 11 -and $script:uiMessage -match 'report saved|complete|finished'){11}else{[Math]::Max(0,$phase-1)}
  $percent=[int][Math]::Round($done*100.0/$script:uiPhases.Count)
  $line='-'*($width-2)
  $lines=[System.Collections.Generic.List[string]]::new()
  $lines.Add('')
  $lines.Add('  '+(Get-ConsoleTint 'INTUNE' 81)+'  '+(Get-ConsoleTint '/ ASSESSMENT' 255)+(' '*7)+(Get-ConsoleTint 'READ-ONLY   |   MICROSOFT GRAPH' 245))
  $lines.Add('  '+(Get-ConsoleTint 'Endpoint management  /  Security posture  /  Configuration' 245))
  $lines.Add('  '+(Get-ConsoleTint $line 239))
  $ctxVar=Get-Variable -Name ctx -Scope Script -ErrorAction SilentlyContinue
  $tenant=if($ctxVar -and $ctxVar.Value -and $ctxVar.Value.TenantId){[string]$ctxVar.Value.TenantId}else{'Connecting...'}
  $lines.Add('  '+(Get-ConsoleTint 'TENANT  ' 245)+(Get-ConsoleTint (Get-ConsoleClippedText $tenant 38) 255)+'     '+(Get-ConsoleTint 'RUNTIME  ' 245)+(Get-ConsoleTint $clock 81))
  $dv=Get-ConsoleCount 'managed'; $pr=Get-ConsoleCount 'policyDeployment'; $fi=Get-ConsoleCount 'findings';$wn=[string]$script:uiWarnings.Count
  $lines.Add('  '+(Get-ConsoleTint 'DEVICES  ' 245)+(Get-ConsoleTint $dv 255)+'     '+(Get-ConsoleTint 'POLICY RESULTS  ' 245)+(Get-ConsoleTint $pr 255)+'     '+(Get-ConsoleTint 'FINDINGS  ' 245)+(Get-ConsoleTint $fi 255)+'     '+(Get-ConsoleTint 'WARNINGS  ' 245)+(Get-ConsoleTint $wn $(if($script:uiWarnings.Count){209}else{79})))
  $lines.Add('  '+(Get-ConsoleTint $line 239))
  $lines.Add('  '+(Get-ConsoleTint 'PROGRESS' 255)+'     '+(Get-ConsoleTint ('{0,3}%' -f $percent) 81)+'  '+(Get-ConsoleTint ('{0} of {1} phases completed' -f $done,$script:uiPhases.Count) 245))
  $barWidth=[Math]::Max(24,[Math]::Min(70,$width-25))
  $bar=Get-ConsoleGauge $barWidth ([int][Math]::Floor($barWidth*$done/$script:uiPhases.Count)) $script:uiTick
  $lines.Add('  '+$bar)
  $lines.Add('')
  $leftWidth=[Math]::Max(36,[Math]::Min(48,[int][Math]::Floor($width*.46)))
  $rightWidth=[Math]::Max(24,$width-$leftWidth-7)
  $lines.Add('  '+(Get-ConsoleTint 'PHASES' 255)+(' '*[Math]::Max(1,$leftWidth-6))+(Get-ConsoleTint 'LATEST ACTIVITY' 255))
  $lines.Add('  '+(Get-ConsoleTint ('-'*($leftWidth-1)) 239)+' '+(Get-ConsoleTint ('-'*$rightWidth) 239))
  $eventStart=[Math]::Max(0,$script:uiEvents.Count-11)
  for($i=0;$i -lt 11;$i++) {
   $n=$i+1
   $mark=if($n -lt $phase){'[OK]'}elseif($n -eq $phase){'[>>]'}else{'[  ]'}
   $shade=if($n -lt $phase){79}elseif($n -eq $phase){81}else{242}
   $label=Get-ConsoleClippedText ('{0,2}. {1}' -f $n,$script:uiPhases[$i]) ($leftWidth-7)
   $plain=$mark+' '+$label
   $left=(Get-ConsoleTint $mark $shade)+' '+(Get-ConsoleTint $label $(if($n -eq $phase){255}else{$shade}))
   $gap=' '*[Math]::Max(1,$leftWidth-$plain.Length)
   $right=''
   if(($eventStart+$i) -lt $script:uiEvents.Count) {
    $entry=Get-ConsoleClippedText $script:uiEvents[$eventStart+$i] $rightWidth
    $entryColor=if($entry -match '(?i)warning|failed|unavailable|error'){209}else{245}
    $right=Get-ConsoleTint $entry $entryColor
   }
   $lines.Add('  '+$left+$gap+$right)
  }
  $lines.Add('  '+(Get-ConsoleTint $line 239))
  $task=Get-ConsoleClippedText $script:uiMessage ($width-18)
  $lines.Add('  '+(Get-ConsoleTint 'IN PROGRESS  ' 81)+(Get-ConsoleTint $task 255))
  if($script:uiWarnings.Count) {
   $latest=Get-ConsoleClippedText $script:uiWarnings[$script:uiWarnings.Count-1] ($width-15)
   $lines.Add('  '+(Get-ConsoleTint 'WARNING      ' 209)+(Get-ConsoleTint $latest 245))
  }else{
   $lines.Add('  '+(Get-ConsoleTint 'STATUS       ' 245)+(Get-ConsoleTint 'No collection warnings' 79))
  }
  $lines.Add('  '+(Get-ConsoleTint 'API STATS    ' 245)+(Get-ConsoleTint ('GET {0}  |  PAGES {1}  |  RETRIES {2}  |  CACHE HITS {3}  |  PHASE {4:n0}s' -f $script:GraphStats.Requests,$script:GraphStats.Pages,$script:GraphStats.Retries,$script:GraphStats.CacheHits,((Get-Date)-$script:GraphStats.PhaseStart).TotalSeconds) 81))
  $lines.Add('  '+(Get-ConsoleTint $line 239))
  $lines.Add('  '+(Get-ConsoleTint 'INTUNE ASSESSMENT' 245)+'  '+(Get-ConsoleTint '  |  Plain output: -NoConsoleDashboard' 245))
  $render="${e}[?25l${e}[H${e}[J"+($lines -join "`n")+"${e}[0m${e}[?25h`n"
  [Console]::Write($render)
 }catch{
  $script:uiEnabled=$false
  try{[Console]::Write("$($script:uiEsc)[0m$($script:uiEsc)[?25h")}catch{}
  Write-Host '[Console dashboard unavailable; switching to plain output.]' -ForegroundColor Yellow
 }
}
function Write-ConsoleEvent([string]$Message) {
 $script:uiMessage=$Message
 $script:uiEvents.Add(('['+(Get-Date -Format 'HH:mm:ss')+'] '+$Message))
 if($script:uiEvents.Count -gt 50){$script:uiEvents.RemoveAt(0)}
 Set-ConsolePhase $Message
 if($script:uiEnabled){
  Write-ConsoleDashboard
 }else{Write-Host ('[{0}] {1}' -f (Get-Date -Format HH:mm:ss),$Message) -ForegroundColor Cyan}
}
function Write-ConsoleWarning([string]$Message) {
 $script:uiWarnings.Add($Message)
 $script:uiEvents.Add(('['+(Get-Date -Format 'HH:mm:ss')+'] WARNING: '+$Message))
 if($script:uiEvents.Count -gt 50){$script:uiEvents.RemoveAt(0)}
 if($script:uiEnabled){Write-ConsoleDashboard}else{Write-Warning $Message}
}
# =====================================================================================
# SECTION 3 - Helpers (text, Graph requests, batching, CSV, Intune report exports)
# =====================================================================================
function Say([string]$Message) { Write-ConsoleEvent $Message }
function AsText($Value) { if ($null -eq $Value) {return ''}; return [string]$Value }
function SafeDate($Value) {
 if (-not $Value) {return $null}
 try {return ([DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture)).UtcDateTime} catch {return $null}
}
function ToIso($Value) { if ($null -eq $Value) {return ''}; return ([DateTime]$Value).ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Get-HttpStatus($ErrorRecord) {
 $status=0
 try {$status=[int]$ErrorRecord.Exception.Response.StatusCode} catch {}
 return $status
}
function Get-RetryDelaySeconds($ErrorRecord,[int]$Attempt,[string]$RetryAfterHeader='') {
 # Honour Retry-After (seconds or HTTP date) before falling back to exponential backoff.
 $delay=[int][Math]::Min(30,[Math]::Pow(2,$Attempt))
 try {
  if($RetryAfterHeader){
   $sec=0
   if([int]::TryParse($RetryAfterHeader,[ref]$sec)){$delay=$sec}
   else{$delay=[int][Math]::Ceiling(([DateTimeOffset]::Parse($RetryAfterHeader)-[DateTimeOffset]::UtcNow).TotalSeconds)}
  }elseif($ErrorRecord){
   $ra=$ErrorRecord.Exception.Response.Headers.RetryAfter
   if($ra -and $ra.Delta){$delay=[int][Math]::Ceiling($ra.Delta.TotalSeconds)}
   elseif($ra -and $ra.Date){$delay=[int][Math]::Ceiling(($ra.Date-[DateTimeOffset]::UtcNow).TotalSeconds)}
  }
 } catch {}
 return [Math]::Max(1,[Math]::Min(120,$delay))
}
function Invoke-GraphJson {
 param([string]$Method='GET',[Parameter(Mandatory)][string]$Uri,[string]$Body,[string]$Label='Graph request',[hashtable]$Headers)
 $retry=0
 while ($true) {
  try {
   $script:GraphStats.Requests++
   $call=@{Method=$Method;Uri=$Uri;OutputType='Json';ErrorAction='Stop'}
   if($Body){$call.Body=$Body;$call.ContentType='application/json'}
   if($Headers){$call.Headers=$Headers}
   $json=Invoke-MgGraphRequest @call
   return (ConvertFrom-Json -InputObject ([string]$json) -ErrorAction Stop)
  } catch {
   $retry++
   $status=Get-HttpStatus $_
   if ($retry -ge 6 -or ($status -ge 400 -and $status -lt 500 -and $status -notin @(408,429))) {
    throw ('Graph {0} failed (HTTP {1}): {2}' -f $Label,$status,$_.Exception.Message)
   }
   $script:GraphStats.Retries++
   Start-Sleep -Seconds (Get-RetryDelaySeconds $_ $retry)
  }
 }
}
function Read-GraphPages {
 param([Parameter(Mandatory)][string]$Uri,[string]$Label='Records',[hashtable]$Headers)
 $next=$Uri; $page=0; $total=0
 while ($next) {
  $page++
  $body=Invoke-GraphJson -Uri $next -Label ('{0} page {1}' -f $Label,$page) -Headers $Headers
  $script:GraphStats.Pages++
  if ($null -eq $body -or $null -eq $body.value) {throw "Missing Graph value collection for $Label page $page"}
  foreach($entry in $body.value) {if($null -ne $entry){$total++; Write-Output $entry}}
  $next=AsText $body.'@odata.nextLink'
  if($page -eq 1 -or ($page % 5 -eq 0)) {Write-ConsoleEvent ("{0}: {1} records / {2} pages" -f $Label,$total,$page)}
 }
}
function Invoke-GraphBatchGet {
 # JSON $batch with adaptive pacing (v3.43):
 # - a throttled chunk stops the current round (no hammering), honours Retry-After, then the chunk
 #   size is halved and the pause between chunks doubled;
 # - retries continue until -MaxWaitSeconds of cumulative throttling wait is reached;
 # - requests still throttled are finally retried one by one (Invoke-GraphJson honours Retry-After).
 param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Urls,[ValidateSet('v1.0','beta')][string]$Version='v1.0',[string]$Label='Batch',
  [ValidateRange(1,20)][int]$ChunkSize=20,[ValidateRange(0,10000)][int]$PauseMs=0,[ValidateRange(30,3600)][int]$MaxWaitSeconds=600)
 $results=@{}
 if($Urls.Count -eq 0){return $results}
 $pending=[System.Collections.Generic.List[int]]::new()
 for($k=0;$k -lt $Urls.Count;$k++){$pending.Add($k)}
 $endpoint="https://graph.microsoft.com/$Version/`$batch"
 $round=0; $waited=0; $chunk=$ChunkSize; $pause=$PauseMs
 while($pending.Count -gt 0 -and $waited -lt $MaxWaitSeconds){
  $round++
  $retryLater=[System.Collections.Generic.List[int]]::new(); $wait=0; $throttled=$false
  for($o=0;$o -lt $pending.Count;$o+=$chunk){
   $ids=@($pending.GetRange($o,[Math]::Min($chunk,$pending.Count-$o)))
   if($throttled){foreach($k in $ids){$retryLater.Add($k)};continue}
   $body=@{requests=@($ids | ForEach-Object {@{id=[string]$_;method='GET';url=$Urls[$_]}})} | ConvertTo-Json -Depth 6 -Compress
   try {
    $resp=Invoke-GraphJson -Method POST -Uri $endpoint -Body $body -Label "$Label (batch)"
   } catch {
    foreach($k in $ids){$results[$k]=[pscustomobject]@{Status=0;Body=$null;Error=$_.Exception.Message}}
    continue
   }
   foreach($r in @($resp.responses)){
    $k=[int]$r.id; $st=[int]$r.status
    if($st -eq 429 -or $st -ge 500){
     $retryLater.Add($k); if($st -eq 429){$throttled=$true}
     $ra=''; try{$ra=AsText $r.headers.'Retry-After'}catch{}
     $wait=[Math]::Max($wait,(Get-RetryDelaySeconds $null $round $ra))
     continue
    }
    $err=''
    if($st -ge 400){$err=AsText $r.body.error.message; if(-not $err){$err="HTTP $st"}}
    $results[$k]=[pscustomobject]@{Status=$st;Body=$r.body;Error=$err}
   }
   if($pause -gt 0 -and -not $throttled){Start-Sleep -Milliseconds $pause}
  }
  $pending=$retryLater
  Write-ConsoleEvent ('{0}: {1}/{2} responses (chunk {3}, pause {4} ms)' -f $Label,$results.Count,$Urls.Count,$chunk,$pause)
  if($pending.Count -gt 0){
   $script:GraphStats.Retries+=$pending.Count
   if($throttled){$chunk=[Math]::Max(4,[int][Math]::Floor($chunk/2)); $pause=[Math]::Min(8000,[Math]::Max(1000,$pause*2))}
   $sleep=[Math]::Max(2,$wait); $waited+=$sleep
   Write-ConsoleEvent ('{0}: throttled by Graph, waiting {1}s ({2} remaining)' -f $Label,$sleep,$pending.Count)
   Start-Sleep -Seconds $sleep
  }
 }
 if($pending.Count -gt 0){
  Write-ConsoleEvent ('{0}: retrying {1} throttled requests one by one' -f $Label,$pending.Count)
  foreach($k in $pending){
   try{
    $b=Invoke-GraphJson -Uri ("https://graph.microsoft.com/$Version"+$Urls[$k]) -Label $Label
    $results[$k]=[pscustomobject]@{Status=200;Body=$b;Error=''}
   }catch{
    $results[$k]=[pscustomobject]@{Status=429;Body=$null;Error='Throttled after repeated retries'}
   }
   Start-Sleep -Milliseconds ([Math]::Max(500,$pause))
  }
 }
 return $results
}
# Returns the value collection from one batch result, following @odata.nextLink when present.
function Get-BatchCollection {
 param($Result,[string]$Label='Records')
 if($null -eq $Result){throw "No batch response for $Label"}
 if($Result.Status -ne 200){throw ('Graph {0} failed (HTTP {1}): {2}' -f $Label,$Result.Status,$Result.Error)}
 if($null -eq $Result.Body -or $null -eq $Result.Body.value){throw "Missing Graph value collection for $Label"}
 foreach($entry in @($Result.Body.value)){if($null -ne $entry){Write-Output $entry}}
 $next=AsText $Result.Body.'@odata.nextLink'
 if($next){Read-GraphPages -Uri $next -Label $Label}
}
function Get-OptionalCollection([string]$Name,[string]$Uri,[string]$FallbackUri='') {
 Say "Collecting $Name ..."
 try {
  try { $r=@(Read-GraphPages -Uri $Uri -Label $Name) }
  catch {
   if(-not $FallbackUri){throw}
   Say "$Name : optimized query unavailable, using standard query"
   $r=@(Read-GraphPages -Uri $FallbackUri -Label $Name)
  }
  $script:collection[$Name]='Complete'
  Say "$Name collected: $($r.Count)"
  return $r
 } catch {
  $script:collection[$Name]='Unavailable'
  $script:warnings.Add("$Name unavailable: $($_.Exception.Message)")
  Write-ConsoleWarning "$Name unavailable: $($_.Exception.Message)"
  return
 }
}
function Export-Data([string]$Name,[object[]]$Rows,[string[]]$Fields) {
 $out=Join-Path $script:runPath $Name
 $Rows=@($Rows | Where-Object {$null -ne $_} | Select-Object -Property $Fields)
 if($script:Anon.Enabled){
  $Rows=@($Rows | ForEach-Object {$src=$_;$o=[ordered]@{};foreach($f in $Fields){$v=$src.$f;$o[$f]=if($v -is [string]){ConvertTo-AnonymizedText $v}else{$v}};[pscustomobject]$o})
 }
 $script:WorkbookSheets.Add([pscustomobject]@{Name=$Name;Rows=$Rows;Fields=$Fields})
 if(@($Rows).Count -gt 0) { $Rows | Export-Csv -Path $out -Encoding utf8BOM -NoTypeInformation }
 else { ('"'+($Fields -join '","')+'"') | Set-Content -Path $out -Encoding utf8BOM }
}
function JsonSafe($Obj,[int]$Depth=8) {
 $json=ConvertTo-Json -InputObject $Obj -Compress -Depth $Depth
 # Escape HTML-sensitive characters before embedding in <script type="application/json">.
 return $json.Replace('&','\u0026').Replace('<','\u003c').Replace('>','\u003e').Replace([string][char]0x2028,'\u2028').Replace([string][char]0x2029,'\u2029')
}
# Supported Intune report export. The POST creates only a temporary report job.
$script:ReportJobsApi='https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs'
$script:PrestartedReportJobs=@{}
function Start-IntuneReportJob {
 param([Parameter(Mandatory)][string]$ReportName,[string]$Filter='',[string[]]$Select=@())
 $body=@{reportName=$ReportName;format='csv';localizationType='ReplaceLocalizableValues'}
 if($Filter){$body.filter=$Filter}
 if($Select.Count -gt 0){$body.select=$Select}
 $job=Invoke-GraphJson -Method POST -Uri $script:ReportJobsApi -Body ($body | ConvertTo-Json -Compress) -Label "Export $ReportName"
 $id=AsText $job.id
 if(-not $id){throw "Graph did not return an export job ID for $ReportName"}
 return $id
}
# Non-throwing variant used to queue jobs early; failures are retried by Get-IntuneReportRows.
function Start-IntuneReportJobSafe([string]$ReportName,[string]$Filter='') {
 try {return (Start-IntuneReportJob -ReportName $ReportName -Filter $Filter)} catch {return $null}
}
function Get-IntuneReportRowsCore {
 param([Parameter(Mandatory)][string]$ReportName,[string]$Filter = "",[string]$JobId = "")
 if(-not $JobId -and -not $Filter -and $script:PrestartedReportJobs[$ReportName]){
  $JobId=$script:PrestartedReportJobs[$ReportName]; $script:PrestartedReportJobs.Remove($ReportName)
 }
 if(-not $JobId){$JobId=Start-IntuneReportJob -ReportName $ReportName -Filter $Filter}
 # One folder per job: avoids mixing CSVs of different PolicyId filters for the same report.
 $folder=Join-Path $script:runPath ('GraphExport-{0}-{1}' -f $ReportName,$JobId.Substring(0,[Math]::Min(8,$JobId.Length)))
 New-Item -Path $folder -ItemType Directory -Force | Out-Null
 $started=Get-Date; $delay=2; $state=''
 do {
  $status=Invoke-GraphJson -Uri ("{0}/{1}" -f $script:ReportJobsApi,$JobId) -Label "Export $ReportName status"
  $state=(AsText $status.status).ToLowerInvariant()
  if($state -eq 'completed'){break}
  if($state -in @('failed','error')){throw "Intune export $ReportName failed ($state)"}
  Start-Sleep -Seconds $delay
  $delay=[Math]::Min(6,$delay+1)
 }while(((Get-Date)-$started).TotalSeconds -lt $ReportTimeoutSeconds)
 if($state -ne 'completed'){throw "Intune export $ReportName timed out after $ReportTimeoutSeconds seconds"}
 $url=AsText $status.url
 if(-not $url){throw "No download URL in completed $ReportName export"}
 $archive=Join-Path $folder 'report.zip'
 Invoke-WebRequest -Uri $url -OutFile $archive -ErrorAction Stop
 Expand-Archive -Path $archive -DestinationPath $folder -Force -ErrorAction Stop
 Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
 $files=@(Get-ChildItem -Path $folder -Filter '*.csv' -Recurse -File)
 if($files.Count -eq 0){throw "No CSV found in $ReportName export archive"}
 $records=[System.Collections.Generic.List[object]]::new()
 foreach($f in $files){foreach($r in @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop)){$records.Add($r)}}
 return $records.ToArray()
}
function PropertyText($Record,[string[]]$Names) {
 if($null -eq $Record){return ''}
 foreach($n in $Names){
  $p=$Record.PSObject.Properties | Where-Object {$_.Name -ieq $n} | Select-Object -First 1
  if($p -and $null -ne $p.Value -and ([string]$p.Value).Trim()){return ([string]$p.Value).Trim()}
 }
 return ''
}
# Microsoft Graph complianceStatus numeric enum used by Intune policy reports.
# Keep the original code alongside the readable label for auditability.
function Resolve-PolicyDeploymentStatus([string]$RawStatus) {
 $value=($RawStatus.Trim() -replace '[\s_-]','').ToLowerInvariant()
 switch ($value) {
  '0' {return 'Unknown'}
  '1' {return 'Not applicable'}
  '2' {return 'Succeeded'}
  '3' {return 'Remediated'}
  '4' {return 'Noncompliant'}
  '5' {return 'Error'}
  '6' {return 'Conflict'}
  '7' {return 'Not assigned'}
  'success' {return 'Succeeded'}
  'succeeded' {return 'Succeeded'}
  'compliant' {return 'Succeeded'}
  'remediated' {return 'Remediated'}
  'noncompliant' {return 'Noncompliant'}
  'failed' {return 'Error'}
  'failure' {return 'Error'}
  'error' {return 'Error'}
  'conflict' {return 'Conflict'}
  'pending' {return 'Pending'}
  'inprogress' {return 'Pending'}
  'notapplicable' {return 'Not applicable'}
  'notassigned' {return 'Not assigned'}
  default {return 'Unknown'}
 }
}
function Test-ReportedFailure([string]$Value){
 $s=($Value.Trim().ToLowerInvariant() -replace '[\s_-]','')
 return $s -in @('error','failed','failure','conflict','noncompliant','notapplicableerror')
}

# ---------- v3.60 helpers: platform, parsing, anonymization, Excel workbook ----------
# Platform used for compliance coverage, MAM and OS checks. Android AOSP is reported separately:
# it has no Google Play services, no MAM support and OEM-controlled firmware versions.
function Get-DevicePlatform([string]$OperatingSystem,[string]$EnrollmentType,[string]$DeviceName) {
 if($OperatingSystem -match '(?i)aosp' -or $EnrollmentType -match '(?i)aosp' -or $DeviceName -match '(?i)_AndroidAOSP_'){return 'Android AOSP'}
 if($OperatingSystem -match '(?i)^windows'){return 'Windows'}
 if($OperatingSystem -match '(?i)ios|ipados'){return 'iOS'}
 if($OperatingSystem -match '(?i)mac'){return 'macOS'}
 if($OperatingSystem -match '(?i)android'){return 'Android'}
 if($OperatingSystem -match '(?i)linux|ubuntu|rhel'){return 'Linux'}
 if($OperatingSystem){return $OperatingSystem}
 return 'Unknown'
}
function ConvertTo-IntOrZero($Value) {
 $n=0
 $text=(AsText $Value).Trim() -replace '[\s,]',''
 if([int]::TryParse($text,[ref]$n)){return $n}
 $d=0.0
 if([double]::TryParse($text,[System.Globalization.NumberStyles]::Float,[System.Globalization.CultureInfo]::InvariantCulture,[ref]$d)){return [int][Math]::Round($d)}
 return 0
}
# Base name used to detect several uploaded versions of the same Win32 application.
function Get-AppBaseName([string]$Name) {
 $base=($Name -replace '(?i)[\s_\-\(]*v?\d+(\.\d+)+.*$','' -replace '(?i)\s*\((x64|x86|64-bit|32-bit)\)\s*$','').Trim()
 return $base.ToLowerInvariant()
}
# Domain score: 100 minus weighted findings (High 25, Medium 10, Low 4, Informational 1), floor 0.
function Get-DomainScoreValue([string[]]$Severities) {
 $weights=@{High=25;Medium=10;Low=4;Informational=1}
 $penalty=0
 foreach($s in @($Severities)){if($s -and $weights.ContainsKey($s)){$penalty+=$weights[$s]}}
 return [int][Math]::Max(0,100-$penalty)
}
function Get-ScoreRating([int]$Score) {
 if($Score -ge 85){return 'Strong'}
 if($Score -ge 70){return 'Good'}
 if($Score -ge 50){return 'Needs improvement'}
 return 'At risk'
}

# Anonymization (-Anonymize): device names, serial numbers, user names and e-mail addresses are
# replaced by stable tokens (device-0001, user-0001...) in the HTML report, CSV, Excel and warnings.
$script:Anon=@{Enabled=[bool]$Anonymize;Map=@{};Counters=@{};Regex=$null}
function Register-AnonymizedValue([string]$Value,[string]$Kind,[string]$Token='') {
 if(-not $script:Anon.Enabled){return}
 $v=([string]$Value).Trim()
 if($v.Length -lt 4){return}
 if($v -match '(?i)^(windows|macos|ios|ipados|android|linux|unknown|none|true|false|compliant|noncompliant|default string|system serial number|to be filled by o\.e\.m\.)$'){return}
 $key=$v.ToLowerInvariant()
 if($script:Anon.Map.ContainsKey($key)){return}
 if(-not $Token){
  $script:Anon.Counters[$Kind]=1+[int]$script:Anon.Counters[$Kind]
  $Token='{0}-{1:D4}' -f $Kind,$script:Anon.Counters[$Kind]
 }
 $script:Anon.Map[$key]=$Token
 $script:Anon.Regex=$null
}
function ConvertTo-AnonymizedText([string]$Text) {
 if(-not $script:Anon.Enabled -or [string]::IsNullOrEmpty($Text)){return $Text}
 if($null -eq $script:Anon.Regex -and $script:Anon.Map.Count -gt 0){
  $alternatives=@($script:Anon.Map.Keys | Sort-Object Length -Descending | ForEach-Object {[regex]::Escape($_)})
  $pattern='(?<![\p{L}\p{N}])(?:'+($alternatives -join '|')+')(?![\p{L}\p{N}])'
  $script:Anon.Regex=[regex]::new($pattern,[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')
 }
 $out=$Text
 if($script:Anon.Regex){
  $out=$script:Anon.Regex.Replace($out,[System.Text.RegularExpressions.MatchEvaluator]{param($m) $script:Anon.Map[$m.Value.ToLowerInvariant()]})
 }
 # Any remaining e-mail address / UPN (administrators, audit actors...).
 $out=[regex]::Replace($out,'[A-Za-z0-9._%+''-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}',[System.Text.RegularExpressions.MatchEvaluator]{
  param($m)
  $k=$m.Value.ToLowerInvariant()
  if($k.EndsWith('@example.invalid')){return $m.Value}
  if(-not $script:Anon.Map.ContainsKey($k)){
   $script:Anon.Counters['email']=1+[int]$script:Anon.Counters['email']
   $script:Anon.Map[$k]=('user-{0:D4}@example.invalid' -f $script:Anon.Counters['email'])
   $script:Anon.Regex=$null
  }
  $script:Anon.Map[$k]
 })
 return $out
}

# Excel workbook (-SkipExcelExport to disable): one sheet per CSV export, header row frozen and
# filtered. Minimal Office Open XML writer, no Excel or module dependency.
$script:WorkbookSheets=[System.Collections.Generic.List[object]]::new()
function ConvertTo-XlsxColumnName([int]$Index) {
 $name=''
 $n=$Index+1
 while($n -gt 0){$r=($n-1)%26;$name=[char](65+$r)+$name;$n=[int][Math]::Floor(($n-1)/26)}
 return $name
}
function ConvertTo-XlsxText([string]$Text) {
 if($null -eq $Text){return ''}
 $clean=[regex]::Replace($Text,'[\x00-\x08\x0B\x0C\x0E-\x1F]','')
 if($clean.Length -gt 32000){$clean=$clean.Substring(0,32000)+' [truncated]'}
 return [System.Security.SecurityElement]::Escape($clean)
}
function New-SimpleXlsx {
 param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object[]]$Sheets)
 Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
 if(Test-Path -LiteralPath $Path){Remove-Item -LiteralPath $Path -Force}
 $usedNames=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 $parts=[ordered]@{}
 $sheetEntries=[System.Text.StringBuilder]::new(); $sheetRels=[System.Text.StringBuilder]::new(); $sheetTypes=[System.Text.StringBuilder]::new()
 $index=0
 foreach($sheet in $Sheets){
  $index++
  $base=([string]$sheet.Name -replace '\.csv$','' -replace '[\[\]\:\*\?/\\]','')
  if($base.Length -gt 31){$base=$base.Substring(0,31)}
  if(-not $base){$base="Sheet$index"}
  $sheetName=$base; $suffix=1
  while(-not $usedNames.Add($sheetName)){$suffix++;$tail="~$suffix";$sheetName=$base.Substring(0,[Math]::Min($base.Length,31-$tail.Length))+$tail}
  $fields=@($sheet.Fields)
  $rows=@($sheet.Rows)
  $lastCol=ConvertTo-XlsxColumnName ([Math]::Max(0,$fields.Count-1))
  $sb=[System.Text.StringBuilder]::new()
  [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
  [void]$sb.Append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>')
  for($c=0;$c -lt $fields.Count;$c++){
   $maxLen=[Math]::Max(8,([string]$fields[$c]).Length+2)
   foreach($r in @($rows | Select-Object -First 200)){$len=(AsText $r.($fields[$c])).Length;if($len -gt $maxLen){$maxLen=$len}}
   [void]$sb.Append(('<col min="{0}" max="{0}" width="{1}" customWidth="1"/>' -f ($c+1),[Math]::Min(60,$maxLen+2)))
  }
  [void]$sb.Append('</cols><sheetData><row r="1">')
  for($c=0;$c -lt $fields.Count;$c++){[void]$sb.Append(('<c r="{0}1" t="inlineStr" s="1"><is><t xml:space="preserve">{1}</t></is></c>' -f (ConvertTo-XlsxColumnName $c),(ConvertTo-XlsxText ([string]$fields[$c]))))}
  [void]$sb.Append('</row>')
  $rowNumber=1
  foreach($r in $rows){
   $rowNumber++
   [void]$sb.Append("<row r=`"$rowNumber`">")
   for($c=0;$c -lt $fields.Count;$c++){
    $ref=(ConvertTo-XlsxColumnName $c)+$rowNumber
    $v=$r.($fields[$c])
    if($null -eq $v){continue}
    if($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [single]){
     [void]$sb.Append(('<c r="{0}"><v>{1}</v></c>' -f $ref,([double]$v).ToString([System.Globalization.CultureInfo]::InvariantCulture)))
    }else{
     $text=if($v -is [System.Collections.IEnumerable] -and $v -isnot [string]){(@($v) | ForEach-Object {AsText $_}) -join '; '}else{AsText $v}
     [void]$sb.Append(('<c r="{0}" t="inlineStr"><is><t xml:space="preserve">{1}</t></is></c>' -f $ref,(ConvertTo-XlsxText $text)))
    }
   }
   [void]$sb.Append('</row>')
  }
  [void]$sb.Append('</sheetData>')
  if($fields.Count -gt 0){[void]$sb.Append(('<autoFilter ref="A1:{0}{1}"/>' -f $lastCol,[Math]::Max(1,$rowNumber)))}
  [void]$sb.Append('</worksheet>')
  $parts["xl/worksheets/sheet$index.xml"]=$sb.ToString()
  [void]$sheetEntries.Append(('<sheet name="{0}" sheetId="{1}" r:id="rId{1}"/>' -f [System.Security.SecurityElement]::Escape($sheetName),$index))
  [void]$sheetRels.Append(('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{0}.xml"/>' -f $index))
  [void]$sheetTypes.Append(('<Override PartName="/xl/worksheets/sheet{0}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' -f $index))
 }
 $stylesId=$index+1
 $parts['[Content_Types].xml']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'+$sheetTypes.ToString()+'</Types>'
 $parts['_rels/.rels']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
 $parts['xl/workbook.xml']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+$sheetEntries.ToString()+'</sheets></workbook>'
 $parts['xl/_rels/workbook.xml.rels']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+$sheetRels.ToString()+('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' -f $stylesId)+'</Relationships>'
 $parts['xl/styles.xml']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Segoe UI"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17263A"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'
 $zip=[System.IO.Compression.ZipFile]::Open($Path,[System.IO.Compression.ZipArchiveMode]::Create)
 try{
  foreach($name in $parts.Keys){
   $entry=$zip.CreateEntry($name,[System.IO.Compression.CompressionLevel]::Optimal)
   $writer=[System.IO.StreamWriter]::new($entry.Open(),[System.Text.UTF8Encoding]::new($false))
   try{$writer.Write($parts[$name])}finally{$writer.Dispose()}
  }
 }finally{$zip.Dispose()}
}
# Every Intune export report used is logged (rows, columns, error) and shown in Data quality.
$script:ReportSources=[System.Collections.Generic.List[object]]::new()
function Get-IntuneReportRows {
 param([Parameter(Mandatory)][string]$ReportName,[string]$Filter='',[string]$JobId='')
 try{
  $rows=@(Get-IntuneReportRowsCore -ReportName $ReportName -Filter $Filter -JobId $JobId)
  $cols=if($rows.Count){(@($rows[0].PSObject.Properties.Name) -join ', ')}else{''}
  $script:ReportSources.Add([pscustomobject]@{Report=$ReportName;Filter=$Filter;Status='Complete';Rows=$rows.Count;Columns=$cols;Error=''})
  return $rows
 }catch{
  $script:ReportSources.Add([pscustomobject]@{Report=$ReportName;Filter=$Filter;Status='Unavailable';Rows=0;Columns='';Error=$_.Exception.Message})
  throw
 }
}
# First CSV column whose name matches the pattern (Intune export column names vary by report version).
function Get-NoncomplianceColumn($Row,[string]$Pattern){ return @($Row.PSObject.Properties.Name | Where-Object {$_ -match $Pattern} | Select-Object -First 1)[0] }
# =====================================================================================
# SECTION 4 - Module and Microsoft Graph connection (read-only scopes)
# =====================================================================================
if(-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
 if(-not $InstallModules) {throw 'Install Microsoft.Graph.Authentication with Install-Module Microsoft.Graph.Authentication -Scope CurrentUser, or specify -InstallModules.'}
 Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
 $scopes=@('DeviceManagementManagedDevices.Read.All','DeviceManagementApps.Read.All','DeviceManagementServiceConfig.Read.All')
$scopes+= 'DeviceManagementConfiguration.Read.All'
if(-not $SkipBitLockerEscrow){$scopes+= 'BitlockerKey.ReadBasic.All'}
if(-not $SkipDirectoryUsers){$scopes+= 'User.Read.All'}
if(-not $SkipGovernance){$scopes+=@('DeviceManagementRBAC.Read.All','RoleManagement.Read.Directory','GroupMember.Read.All','DeviceLocalCredential.ReadBasic.All')}
if(-not $SkipGovernance -and -not $SkipConditionalAccess){$scopes+='Policy.Read.All'}
if(-not $SkipEntraDevices){$scopes+='Device.Read.All'}
$scopes=@($scopes|Select-Object -Unique)
Say 'Connecting to Microsoft Graph (read only)...'
Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
$ctx=Get-MgContext

# Retrieve the organization's Entra sign-in branding logo and embed it in the offline HTML.
# Prefer the header logo (horizontal); fall back to the square logo and banner logo.
# Image data never leaves the generated local report; no remote image URL is needed.
$tenantBrandLogo = ''
$tenantBrandName = ''
$tenantBrandSource = 'Fallback'
try {
 $orgResult = Invoke-MgGraphRequest -Method GET -Uri "$base/organization?`$select=id,displayName" -ErrorAction Stop
 if ($orgResult.value -and $orgResult.value.Count -gt 0) {
  $tenantBrandName = [string]$orgResult.value[0].displayName
 }
} catch { Say ('Tenant display name unavailable: {0}' -f $_.Exception.Message) }
if($CustomerName.Trim()){$tenantBrandName=$CustomerName.Trim()}
# Run folder: <Customer>_yyyyMMdd-HHmmss (characters invalid in Windows/macOS file names removed).
$folderCustomer=if($tenantBrandName){$tenantBrandName}else{[string]$ctx.TenantId}
$folderCustomer=($folderCustomer -replace '[\\/:*?"<>|]','' -replace '\s+','-' -replace '[^\p{L}\p{N}._-]','').Trim('.','-','_')
if(-not $folderCustomer){$folderCustomer='Tenant'}
if($folderCustomer.Length -gt 60){$folderCustomer=$folderCustomer.Substring(0,60).TrimEnd('.','-','_')}
$runPath=Join-Path $OutputPath ('{0}_{1}' -f $folderCustomer,(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -Path $runPath -ItemType Directory -Force | Out-Null
Say "Tenant: $($ctx.TenantId) | Customer: $tenantBrandName | Export: $runPath"
foreach ($imageType in @('headerLogo','squareLogo','bannerLogo')) {
 $logoFile = Join-Path $runPath ('tenant-branding-{0}.bin' -f $imageType)  # temporary, deleted below
 try {
  # GET .../branding/localizations/0/{stream} returns binary PNG or JPEG.
  Invoke-MgGraphRequest -Method GET -Uri "$base/organization/$($ctx.TenantId)/branding/localizations/0/$imageType" -OutputFilePath $logoFile -ErrorAction Stop | Out-Null
  if (-not (Test-Path -LiteralPath $logoFile)) { continue }
  $logoBytes = [System.IO.File]::ReadAllBytes($logoFile)
  if ($logoBytes.Length -lt 16 -or $logoBytes.Length -gt 5242880) { continue }
  $mime = ''
  if ($logoBytes[0] -eq 137 -and $logoBytes[1] -eq 80 -and $logoBytes[2] -eq 78 -and $logoBytes[3] -eq 71) { $mime = 'image/png' }
  elseif ($logoBytes[0] -eq 255 -and $logoBytes[1] -eq 216 -and $logoBytes[2] -eq 255) { $mime = 'image/jpeg' }
  if ($mime) {
   $tenantBrandLogo = 'data:{0};base64,{1}' -f $mime, [Convert]::ToBase64String($logoBytes)
   $tenantBrandSource = $imageType
   Say ('Tenant branding logo collected ({0})' -f $imageType)
   break
  }
 } catch { } finally { Remove-Item -LiteralPath $logoFile -Force -ErrorAction SilentlyContinue }
}
if (-not $tenantBrandLogo) {
 Say 'Tenant branding logo unavailable; using customer name / default header.'
}
if($script:Anon.Enabled){
 # Report shows a neutral customer; the local folder keeps the real name for the consultant.
 Register-AnonymizedValue $tenantBrandName 'customer' 'Customer'
 Register-AnonymizedValue ([string]$ctx.TenantId) 'tenant' '00000000-0000-0000-0000-000000000000'
 $tenantBrandName='Customer'; $tenantBrandLogo=''; $tenantBrandSource='Anonymized'
 Say 'Anonymization enabled: device, user and customer names are replaced by tokens in report outputs.'
}


# =====================================================================================
# SECTION 5 - Collections (inventory, users, apps, compliance, policies, baseline, reports)
# =====================================================================================
# Required collection. Do not produce misleading empty dashboards when this fails.
Say 'Collecting managed devices...'
$managed=@(Read-GraphPages -Uri "$base/deviceManagement/managedDevices?`$top=500" -Label 'Managed devices')
if($managed.Count -eq 0){throw 'No managed devices returned. Aborting rather than producing a misleading dashboard.'}
$collection['Managed devices']='Complete'
# Optional inventory collections MUST be initialized before device processing.
# v2.4 accidentally omitted these lookups, causing null-valued method calls
# such as $autoByManaged.ContainsKey() when the first managed device was processed.
$autopilot=@()
if(-not $SkipAutopilot){
 $autopilot=@(Get-OptionalCollection -Name 'Autopilot devices' -Uri "$base/deviceManagement/windowsAutopilotDeviceIdentities?`$top=500")
}else{$collection['Autopilot devices']='Skipped'}
$appList=@(Get-OptionalCollection -Name 'Managed applications' -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$top=500")

$userLookup=@{}
$userLookupFailed=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if(-not $SkipDirectoryUsers){
 # Only the primary users referenced by managed devices are resolved (batched GET /users/{id}).
 $primaryIds=@($managed | ForEach-Object {(AsText $_.userId).ToLowerInvariant()} | Where-Object {$_ -match '^[0-9a-f-]{36}$' -and $_ -ne '00000000-0000-0000-0000-000000000000'} | Select-Object -Unique)
 Say "Resolving $($primaryIds.Count) primary users ..."
 $userResults=Invoke-GraphBatchGet -Urls @($primaryIds | ForEach-Object {"/users/$_`?`$select=id,displayName,userPrincipalName,accountEnabled"}) -Version 'v1.0' -Label 'Directory users'
 for($k=0;$k -lt $primaryIds.Count;$k++){
  $res=$userResults[$k]
  if($res -and $res.Status -eq 200 -and $res.Body.id){$userLookup[$primaryIds[$k]]=$res.Body}
  elseif($res -and $res.Status -eq 404){}  # deleted / not found: reported as 'Not found'
  else{[void]$userLookupFailed.Add($primaryIds[$k])}
 }
 $collection['Directory users']=if($primaryIds.Count -eq 0 -or $userLookupFailed.Count -eq 0){'Complete'}elseif($userLookupFailed.Count -lt $primaryIds.Count){'Partial'}else{'Unavailable'}
 if($userLookupFailed.Count -gt 0){$warnings.Add("Directory users: $($userLookupFailed.Count) of $($primaryIds.Count) primary users could not be resolved; their account state is Unknown.")}
 Say "Directory users resolved: $($userLookup.Count) found, $($userLookupFailed.Count) failed"
}else{$collection['Directory users']='Skipped'}

$autoByManaged=@{}; $autoBySerial=@{}
foreach($a in $autopilot){
 if($a.managedDeviceId){$autoByManaged[([string]$a.managedDeviceId).ToLowerInvariant()]=$a}
 if($a.serialNumber){$autoBySerial[([string]$a.serialNumber).Trim().ToUpperInvariant()]=$a}
}

function Get-ManagedBy([string]$Agent) {
 switch ($Agent) {
  'mdm' { return 'Microsoft Intune (MDM)' }
  'intuneClient' { return 'Microsoft Intune client' }
  'configurationManagerClient' { return 'Configuration Manager' }
  'configurationManagerClientMdm' { return 'Configuration Manager + Intune MDM' }
  'configurationManagerClientMdmEas' { return 'Configuration Manager + Intune MDM + Exchange' }
  'eas' { return 'Exchange ActiveSync' }
  'easMdm' { return 'Exchange + Intune MDM' }
  'easIntuneClient' { return 'Exchange + Intune client' }
  'jamf' { return 'Jamf' }
  'googleCloudDevicePolicyController' { return 'Google CloudDPC' }
  'google' { return 'Google' }
  'msSense' { return 'Microsoft Defender for Endpoint' }
  'intuneAosp' { return 'Intune (AOSP)' }
  'microsoft365ManagedMdm' { return 'Microsoft 365 managed (MDM)' }
  'unknown' { return 'Unknown' }
  '' { return 'Unknown' }
  default { return $Agent }
 }
}

$devices=[System.Collections.Generic.List[object]]::new()
foreach($m in $managed){
 $sync=SafeDate $m.lastSyncDateTime
 $days=if($null -eq $sync){$null}else{[math]::Floor(($now-$sync).TotalDays)}
 $stale=($null -eq $sync -or $sync -lt $cutoff)
 $deviceIsWindows=([string]$m.operatingSystem -match '^Windows')
 $ap=$null; $matchMethod=''
 $mdid=([string]$m.id).ToLowerInvariant()
 $serial=([string]$m.serialNumber).Trim().ToUpperInvariant()
 if($autoByManaged.ContainsKey($mdid)){$ap=$autoByManaged[$mdid];$matchMethod='ManagedDeviceId'}
 elseif($serial -and $autoBySerial.ContainsKey($serial)){$ap=$autoBySerial[$serial];$matchMethod='Serial number'}
 $apStatus=if(-not $deviceIsWindows){'Not applicable'} elseif($collection['Autopilot devices'] -ne 'Complete'){'Unknown'} elseif($ap){'Registered'}else{'No matching record'}
 $uid=([string]$m.userId).ToLowerInvariant()
 $primary=$null; if($uid -and $userLookup.ContainsKey($uid)){$primary=$userLookup[$uid]}
 $accountState=if(-not $uid){'No user ID'} elseif($collection['Directory users'] -notin @('Complete','Partial') -or $userLookupFailed.Contains($uid)){'Unknown'} elseif($primary){if($primary.accountEnabled -eq $true){'Enabled'}elseif($primary.accountEnabled -eq $false){'Disabled'}else{'Unknown'}} else {'Not found'}
 $encryption=if($m.isEncrypted -eq $true){'Encrypted'}elseif($m.isEncrypted -eq $false){'Not encrypted'}else{'Unknown'}
 $osFamily=AsText $m.operatingSystem
 $edition=AsText $m.skuFamily
 if(-not $edition){$edition=AsText $m.osVersion; $edition=if($edition){'Edition unavailable ('+$edition+')'}else{'Edition unavailable'}}
 $devices.Add([pscustomobject]@{
  Id=AsText $m.id;Name=AsText $m.deviceName;OS=$osFamily;Platform=(Get-DevicePlatform $osFamily (AsText $m.deviceEnrollmentType) (AsText $m.deviceName));EnrollmentType=AsText $m.deviceEnrollmentType;OSVersion=AsText $m.osVersion;Edition=$edition
  Compliance=AsText $m.complianceState;Encrypted=$encryption;LastSync=if($sync){ToIso $sync}else{''};DaysSinceSync=$days;Inactive=$stale
  Enrolled=AsText $m.enrolledDateTime;ManagedBy=Get-ManagedBy (AsText $m.managementAgent);Management=AsText $m.managementAgent;Ownership=AsText $m.managedDeviceOwnerType
  Serial=AsText $m.serialNumber;Manufacturer=AsText $m.manufacturer;Model=AsText $m.model
  PrimaryUser=AsText $m.userPrincipalName;PrimaryUserId=AsText $m.userId;PrimaryAccount=$accountState
  Autopilot=$apStatus;AutopilotMatch=$matchMethod;GroupTag=if($ap){AsText $ap.groupTag}else{''}
  AzureADDeviceId=AsText $m.azureADDeviceId;DeviceCategory=AsText $m.deviceCategoryDisplayName
 })
}

# App install failures: calls on each app can take time; skip or cap through parameters.
$appStatuses=[System.Collections.Generic.List[object]]::new()
$appSummary=[System.Collections.Generic.List[object]]::new()
$appTargets=@($appList | Where-Object {$_.id -and $_.'@odata.type' -notmatch 'managedApp' })
if($MaxAppsForStatus -gt 0){$appTargets=@($appTargets | Select-Object -First $MaxAppsForStatus)}
$partialApps=$MaxAppsForStatus -gt 0 -and $appTargets.Count -lt @($appList).Count
if($SkipAppStatuses) {$collection['App install states']='Skipped'}
elseif($collection['Managed applications'] -ne 'Complete') {$collection['App install states']='Unavailable'}
else {
 Say "Collecting per-device app install statuses for $($appTargets.Count) apps (batched)..."
 $successfulApps=0
 # Per-device status is documented for Graph beta only. Requests are grouped 20 per $batch call.
 $appQuery=@($appTargets | Where-Object {[string]$_.'@odata.type' -ne '#microsoft.graph.macOSMicrosoftDefenderApp'})
 $appBatch=Invoke-GraphBatchGet -Urls @($appQuery | ForEach-Object {"/deviceAppManagement/mobileApps/$($_.id)/deviceStatuses?`$top=500"}) -Version 'beta' -Label 'App install status'
 $appResultById=@{}
 for($k=0;$k -lt $appQuery.Count;$k++){$appResultById[[string]$appQuery[$k].id]=$appBatch[$k]}
 for($i=0;$i -lt $appTargets.Count;$i++) {
  $a=$appTargets[$i]
  # The macOS Microsoft Defender application is an Intune-managed app, but
  # its deviceStatuses request returns HTTP 400 in some tenants. Graph does
  # not guarantee availability of this relationship for each concrete type.
  # Avoid calling the endpoint and clearly show that status was NOT checked.
  if ([string]$a.'@odata.type' -eq '#microsoft.graph.macOSMicrosoftDefenderApp') {
   $appSummary.Add([pscustomobject]@{
    Id=AsText $a.id; Name=AsText $a.displayName; Publisher=AsText $a.publisher
    Type=AsText $a.'@odata.type'; Publishing=AsText $a.publishingState
    Status='Not supported'; DevicesReported=$null; Failures=$null
   })
   Say ("App status skipped (unsupported app type): {0}" -f (AsText $a.displayName))
   continue
  }
  try {
   # Do not abort all apps on an unsupported app type.
   try {
    $statuses=@(Get-BatchCollection -Result $appResultById[[string]$a.id] -Label ("App {0}" -f ($i+1)))
   } catch {
    $firstError=$_.Exception.Message
    # Some app types do not expose deviceStatuses. Retain status as unavailable rather than zero failures.
    throw "Graph beta deviceStatuses unavailable ($firstError)"
   }
   $successfulApps++
   foreach($s in $statuses) {
    $state=AsText $s.installState
    if(-not $state){$state=AsText $s.mobileAppInstallStatusValue}
    if($state -match '(?i)(fail|error)') {
     $appStatuses.Add([pscustomobject]@{App=AsText $a.displayName;AppId=AsText $a.id;Device=AsText $s.deviceName;DeviceId=AsText $s.deviceId;User=AsText $s.userPrincipalName;State=$state;ErrorCode=AsText $s.errorCode;LastUpdated=AsText $s.lastSyncDateTime})
    }
   }
   $appSummary.Add([pscustomobject]@{Id=AsText $a.id;Name=AsText $a.displayName;Publisher=AsText $a.publisher;Type=AsText $a.'@odata.type';Publishing=AsText $a.publishingState;Status='Collected';DevicesReported=$statuses.Count;Failures=@($statuses|Where-Object {[string]$_.installState -match '(?i)(fail|error)'}).Count})
  } catch {
   $warnings.Add("App status unavailable for '$($a.displayName)' (app type: $($a.'@odata.type')): $($_.Exception.Message). This does not mean installation succeeded or failed.")
   $appSummary.Add([pscustomobject]@{Id=AsText $a.id;Name=AsText $a.displayName;Publisher=AsText $a.publisher;Type=AsText $a.'@odata.type';Publishing=AsText $a.publishingState;Status='Unavailable';DevicesReported=$null;Failures=$null})
  }
  if(($i+1) % 10 -eq 0 -or ($i+1) -eq $appTargets.Count){Say ('App status progress: {0}/{1}, failures {2}' -f ($i+1),$appTargets.Count,$appStatuses.Count)}
 }
 $unsupportedApps=@($appSummary | Where-Object {$_.Status -eq 'Not supported'}).Count
 $collection['App install states']=if($successfulApps -eq $appTargets.Count -and -not $partialApps){'Complete'}elseif($successfulApps -gt 0){'Partial'}elseif($unsupportedApps -gt 0 -and $unsupportedApps -eq $appTargets.Count){'Not supported'}else{'Unavailable'}
 if($partialApps){$warnings.Add("App device-status collection capped at $MaxAppsForStatus apps; failure totals are incomplete.")}
}
if($SkipAppStatuses -or $collection['Managed applications'] -ne 'Complete'){
 foreach($a in $appList){$appSummary.Add([pscustomobject]@{Id=AsText $a.id;Name=AsText $a.displayName;Publisher=AsText $a.publisher;Type=AsText $a.'@odata.type';Publishing=AsText $a.publishingState;Status='Not collected';DevicesReported=$null;Failures=$null})}
}
if($collection['App install states'] -eq 'Complete' -and $appSummary.Count -lt $appList.Count) {$collection['App install states']='Partial'}

# Compliance explanations translate known Intune setting names into understandable language.
# Only failed setting data from Microsoft Graph is evidence; mapping never invents a failure.
function Get-ComplianceSettingExplanation([string]$Setting,[string]$State,[string]$ErrorDescription) {
 $name=$Setting.Trim()
 $description='Intune reports this compliance setting as '+$State+'. Review the assigned policy and device status.'
 $action='Open the device compliance policy in Intune, check the requirement, and sync the device.'
 switch -Regex ($name) {
  '(?i)(bitlocker|filevault|encrypt)' { $description='Device storage encryption does not meet the assigned compliance requirement.'; $action='Verify BitLocker/FileVault or platform encryption is enabled and healthy, then sync Intune.'; break }
  '(?i)(secure.boot|secureboot)' { $description='Secure Boot does not meet the policy requirement.'; $action='Verify UEFI Secure Boot is enabled and correctly reported, then sync the device.'; break }
  '(?i)(tpm|trusted.platform)' { $description='The device TPM/security processor does not meet the policy requirement.'; $action='Check the TPM status and firmware, then review the compliance policy requirement.'; break }
  '(?i)(antivirus|anti.virus|defender|anti.malware|antimalware)' { $description='Antivirus or Microsoft Defender protection is not meeting the required state.'; $action='Check Defender/AV health, signatures and real-time protection before syncing Intune.'; break }
  '(?i)(firewall)' { $description='The device firewall does not meet the compliance policy requirement.'; $action='Check firewall profiles and settings, then re-evaluate compliance.'; break }
  '(?i)(password|passcode|pin|lock.screen)' { $description='The configured password, PIN or device-lock requirement is not satisfied.'; $action='Review the password or screen-lock requirements and update the device configuration.'; break }
  '(?i)(os.version|operating.system|minimumos|maximumos|build)' { $description='The operating system version/build does not meet the allowed range.'; $action='Compare the installed OS version with the policy minimum and maximum, then update the device if required.'; break }
  '(?i)(jailbreak|rooted|rooting)' { $description='The device is flagged as rooted or jailbroken, contrary to policy.'; $action='Investigate device integrity and replace or restore the device if needed.'; break }
  '(?i)(threat|risk.level|machine.risk|defender.for.endpoint)' { $description='The device risk level reported by the connected security service exceeds policy requirements.'; $action='Review the device in Microsoft Defender and resolve the detected risk.'; break }
  '(?i)(code.integrity|health.attestation|attestation)' { $description='Device health attestation or code integrity does not satisfy policy.'; $action='Check security/attestation status, firmware and boot protection.'; break }
  '(?i)(update|patch|security.patch)' { $description='The device does not meet the update or security patch requirement.'; $action='Install missing required updates and sync Intune.'; break }
 }
 if(-not $name){$description='Intune reports a failed setting without a readable setting name.'}
 if($ErrorDescription){$description += ' Graph detail: '+$ErrorDescription}
 return [pscustomobject]@{Explanation=$description;SuggestedAction=$action}
}
$complianceDetails=[System.Collections.Generic.List[object]]::new()
$failedStates=@('noncompliant','error','conflict')
$noncompliantDevices=@($devices | Where-Object {$_.Compliance -eq 'noncompliant'})
$detailResults=@{}
foreach($d in $noncompliantDevices){
 $detailResults[$d.Id]=[pscustomobject]@{Reason='Not checked';Explanation='Detailed compliance collection was skipped.';SuggestedAction='Run without -SkipComplianceDetails.';DetailStatus='Skipped';FailedSettings=0}
}
if(-not $SkipComplianceDetails){
 $targets=$noncompliantDevices
 if($MaxComplianceDevices -gt 0){$targets=@($targets | Select-Object -First $MaxComplianceDevices)}
 Say ('Collecting detailed compliance reasons for {0} of {1} noncompliant devices...' -f $targets.Count,$noncompliantDevices.Count)
 $done=0; $failed=0
 $failedDevices=[System.Collections.Generic.List[string]]::new()
 # settingStates is a property of deviceCompliancePolicyState (not a navigation): no $expand needed.
 # One Intune export for all noncompliant devices/settings; the per-device endpoint is
 # only used for devices missing from the report (it is heavily throttled by Graph).
 $reportStates=@{}
 $targetIds=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($t in $targets){[void]$targetIds.Add([string]$t.Id)}
 foreach($reportName in @('NoncompliantDevicesAndSettings','DeviceNonCompliance')){
  if($targets.Count -eq 0){break}
  try{
   Say "Exporting Intune report $reportName (one request for all devices)..."
   $exportRows=@(Get-IntuneReportRows -ReportName $reportName)
   if($exportRows.Count -eq 0){Say "$reportName returned no rows";continue}
   $colId=Get-NoncomplianceColumn $exportRows[0] '^(DeviceId|IntuneDeviceId|ManagedDeviceId)$'
   $colSetting=Get-NoncomplianceColumn $exportRows[0] '^(SettingName|SettingNm|Setting|SettingDisplayName|SettingInstanceDisplayName)$'
   $colPolicy=Get-NoncomplianceColumn $exportRows[0] '^(PolicyName|Policy|PolicyDisplayName)$'
   $colState=Get-NoncomplianceColumn $exportRows[0] '^(SettingStatus|SettingState|ComplianceState|ComplianceStatus|Status|State)$'
   $colValue=Get-NoncomplianceColumn $exportRows[0] '^(CurrentValue|ActualValue|Value)$'
   $colError=Get-NoncomplianceColumn $exportRows[0] '^(ErrorCode|Error)$'
   if(-not $colId -or -not $colSetting){Say "$reportName has no device/setting columns ($((@($exportRows[0].PSObject.Properties.Name)) -join ', ')); trying next source";continue}
   $grouped=@{}
   foreach($r in $exportRows){
    $id=(AsText $r.$colId).Trim()
    if(-not $id -or -not $targetIds.Contains($id)){continue}
    $st=if($colState){AsText $r.$colState}else{''}
    if($st -match '(?i)^(compliant|conforme|not applicable|notapplicable|non applicable)$'){continue}
    $policyName=if($colPolicy){AsText $r.$colPolicy}else{'Compliance policy'}
    $key=$id.ToLowerInvariant()
    if(-not $grouped.ContainsKey($key)){$grouped[$key]=@{}}
    if(-not $grouped[$key].ContainsKey($policyName)){$grouped[$key][$policyName]=[System.Collections.Generic.List[object]]::new()}
    $grouped[$key][$policyName].Add([pscustomobject]@{settingName=AsText $r.$colSetting;state='nonCompliant';currentValue=$(if($colValue){AsText $r.$colValue}else{''});errorCode=$(if($colError){AsText $r.$colError}else{''});errorDescription=''})
   }
   foreach($key in $grouped.Keys){
    if($reportStates.ContainsKey($key)){continue}
    $reportStates[$key]=@($grouped[$key].Keys | ForEach-Object {[pscustomobject]@{displayName=$_;state='nonCompliant';settingStates=@($grouped[$key][$_])}})
   }
   Say "$reportName : failing settings found for $($reportStates.Count) of $($targets.Count) devices"
   break
  }catch{
   $warnings.Add("Noncompliance export $reportName unavailable: $($_.Exception.Message)")
   Say "$reportName unavailable, trying next source"
  }
 }
 $batchTargets=@($targets | Where-Object {-not $reportStates.ContainsKey(([string]$_.Id).ToLowerInvariant())})
 $batchIndex=@{}; for($bi=0;$bi -lt $batchTargets.Count;$bi++){$batchIndex[[string]$batchTargets[$bi].Id]=$bi}
 if($batchTargets.Count -gt 0){Say "Per-device compliance lookup for $($batchTargets.Count) devices not covered by the report..."}
 $complianceBatch=if($batchTargets.Count -gt 0){Invoke-GraphBatchGet -Urls @($batchTargets | ForEach-Object {"/deviceManagement/managedDevices/$($_.Id)/deviceCompliancePolicyStates"}) -Version 'v1.0' -Label 'Compliance policy states' -ChunkSize 10 -PauseMs 1500 -MaxWaitSeconds $ComplianceMaxWaitSeconds}else{@{}}
 $targetIndex=-1
 foreach($d in $targets){
  $targetIndex++
  $detailResults[$d.Id]=[pscustomobject]@{Reason='Reason not provided';Explanation='Intune marks this device noncompliant, but no failing setting was returned.';SuggestedAction='Open Device > Device compliance in the Intune admin center and review the evaluated settings.';DetailStatus='No failed setting returned';FailedSettings=0}
  try{
   $states=if($reportStates.ContainsKey(([string]$d.Id).ToLowerInvariant())){@($reportStates[([string]$d.Id).ToLowerInvariant()])}else{@(Get-BatchCollection -Result $complianceBatch[$batchIndex[[string]$d.Id]] -Label 'Compliance policy states')}
   $issues=[System.Collections.Generic.List[object]]::new()
   foreach($stateItem in $states){
    $policyName=AsText $stateItem.displayName
    $policyState=AsText $stateItem.state
    $settingStates=@($stateItem.settingStates | Where-Object {$null -ne $_})
    foreach($item in $settingStates){
     $status=AsText $item.state
     if($status.ToLowerInvariant() -notin $failedStates){continue}
     $name=AsText $item.settingName
     if(-not $name){$name=AsText $item.instanceDisplayName}
     if(-not $name){$name=AsText $item.setting}
     $info=Get-ComplianceSettingExplanation -Setting $name -State $status -ErrorDescription (AsText $item.errorDescription)
     $row=[pscustomobject]@{Device=$d.Name;DeviceId=$d.Id;Manufacturer=$d.Manufacturer;Model=$d.Model;Policy=$policyName;State=$status;Setting=$name;CurrentValue=AsText $item.currentValue;ErrorCode=AsText $item.errorCode;Explanation=$info.Explanation;SuggestedAction=$info.SuggestedAction;Evidence='Failed setting';DetailStatus='Available'}
     $complianceDetails.Add($row);$issues.Add($row)
    }
    if($settingStates.Count -eq 0 -and $policyState.ToLowerInvariant() -in $failedStates){
     $row=[pscustomobject]@{Device=$d.Name;DeviceId=$d.Id;Manufacturer=$d.Manufacturer;Model=$d.Model;Policy=$policyName;State=$policyState;Setting='Setting not exposed by Graph';CurrentValue='';ErrorCode='';Explanation='Intune identifies this policy as failing but did not expose the failing setting.';SuggestedAction='Open the named compliance policy for this device in Intune to identify its failed settings.';Evidence='Policy state only';DetailStatus='Policy only'}
     $complianceDetails.Add($row);$issues.Add($row)
    }
   }
   if($issues.Count -gt 0){
    $first=$issues[0]
    $detailResults[$d.Id]=[pscustomobject]@{Reason=if($first.Setting -ne 'Setting not exposed by Graph'){$first.Setting}else{$first.Policy+' (policy state only)'};Explanation=$first.Explanation;SuggestedAction=$first.SuggestedAction;DetailStatus=if(@($issues|Where-Object Evidence -eq 'Failed setting').Count -gt 0){'Setting details available'}else{'Policy only'};FailedSettings=$issues.Count}
   }
   $done++
  }catch{
   $failed++
   $detailResults[$d.Id]=[pscustomobject]@{Reason='Reason unavailable';Explanation='Microsoft Graph could not retrieve policy details for this device.';SuggestedAction='Check Intune permissions and open this device in the Intune admin center.';DetailStatus='Request failed';FailedSettings=0}
   $failedDevices.Add($d.Name)
  }
  if(($done+$failed)%25 -eq 0 -or ($done+$failed) -eq $targets.Count){Say ("Compliance details: {0}/{1} checked; {2} failed requests" -f ($done+$failed),$targets.Count,$failed)}
 }
 # One summary warning instead of one line per device.
 if($failedDevices.Count -gt 0){
  $sample=(@($failedDevices | Select-Object -First 10) -join ', ')
  $more=if($failedDevices.Count -gt 10){" (+$($failedDevices.Count-10) more)"}else{''}
  $warnings.Add("Compliance details unavailable for $($failedDevices.Count) of $($targets.Count) devices (Graph throttling). Their reason is shown as 'Reason unavailable'. Rerun later or use -MaxComplianceDevices. Devices: $sample$more")
 }
 $coverageComplete=($done -eq $noncompliantDevices.Count)
 $collection['Compliance policy states']=if($coverageComplete){'Complete'}elseif($done -gt 0){'Partial'}else{'Unavailable'}
 if($MaxComplianceDevices -gt 0 -and $targets.Count -lt $noncompliantDevices.Count){$warnings.Add("Compliance details capped at $MaxComplianceDevices of $($noncompliantDevices.Count) noncompliant devices. Remaining device reasons are not checked.")}
}else{$collection['Compliance policy states']='Skipped'}
# Populate per-device summary for readable report, including explicit collection limitations.
foreach($d in $devices){
 $info=if($detailResults.ContainsKey($d.Id)){$detailResults[$d.Id]}else{$null}
 $d | Add-Member -NotePropertyName 'ComplianceReason' -NotePropertyValue $(if($info){$info.Reason}else{''}) -Force
 $d | Add-Member -NotePropertyName 'ComplianceExplanation' -NotePropertyValue $(if($info){$info.Explanation}else{''}) -Force
 $d | Add-Member -NotePropertyName 'ComplianceAction' -NotePropertyValue $(if($info){$info.SuggestedAction}else{''}) -Force
 $d | Add-Member -NotePropertyName 'ComplianceDetailStatus' -NotePropertyValue $(if($info){$info.DetailStatus}else{''}) -Force
 $d | Add-Member -NotePropertyName 'FailedComplianceSettings' -NotePropertyValue $(if($info){$info.FailedSettings}else{0}) -Force
}

# Export complete, explicit CSVs. Device secrets/hashes are NOT exported.
if($script:Anon.Enabled){
 foreach($d in $devices){Register-AnonymizedValue $d.Name 'device';Register-AnonymizedValue $d.Serial 'serial'}
 foreach($u in @($userLookup.Values)){Register-AnonymizedValue (AsText $u.displayName) 'user'}
}
$deviceFields=@('Name','OS','Platform','OSVersion','Edition','Compliance','Encrypted','LastSync','DaysSinceSync','Inactive','PrimaryUser','PrimaryAccount','Autopilot','AutopilotMatch','GroupTag','Serial','Manufacturer','Model','ComplianceReason','ComplianceExplanation','ComplianceAction','ComplianceDetailStatus','FailedComplianceSettings','ManagedBy','Management','Ownership','Enrolled','Id','AzureADDeviceId')
Export-Data 'Managed-Devices.csv' @($devices) $deviceFields
Export-Data 'Noncompliant-Devices.csv' @($devices|Where-Object {$_.Compliance -eq 'noncompliant'}) $deviceFields
Export-Data 'Inactive-Devices.csv' @($devices|Where-Object {$_.Inactive}) $deviceFields
Export-Data 'Unencrypted-Devices.csv' @($devices|Where-Object {$_.Encrypted -eq 'Not encrypted'}) $deviceFields
Export-Data 'Autopilot-No-Match.csv' @($devices|Where-Object {$_.Autopilot -eq 'No matching record'}) $deviceFields
Export-Data 'Disabled-Primary-Users.csv' @($devices|Where-Object {$_.PrimaryAccount -eq 'Disabled'}) $deviceFields
Export-Data 'App-Install-Failures.csv' @($appStatuses) @('App','AppId','Device','DeviceId','User','State','ErrorCode','LastUpdated')
Export-Data 'Managed-Applications.csv' @($appSummary) @('Name','Type','Publisher','Publishing','Status','DevicesReported','Failures','Id')
Export-Data 'Compliance-Policy-States.csv' @($complianceDetails) @('Device','DeviceId','Manufacturer','Model','Policy','State','Setting','CurrentValue','ErrorCode','Explanation','SuggestedAction','Evidence','DetailStatus')



# --- 5.1 Policy configuration and Windows Update configuration ---
# All calls are read-only; each optional area fails independently.
$policyInventory=[System.Collections.Generic.List[object]]::new()
$updateInventory=[System.Collections.Generic.List[object]]::new()
$findings=[System.Collections.Generic.List[object]]::new()
function Add-Finding {
 param([string]$Severity,[string]$Area,[string]$Title,[int]$Affected,[string]$Evidence,[string]$Recommendation,[string]$Coverage='Verified')
 $findings.Add([pscustomobject]@{Severity=$Severity; Area=$Area; Finding=$Title; Affected=$Affected; Evidence=$Evidence; Recommendation=$Recommendation; Coverage=$Coverage})
}
# Raw assignment targets of every collected object (filters, groups, All users/devices hygiene).
$script:AssignmentTargets=[System.Collections.Generic.List[object]]::new()
function Register-AssignmentTargets {
 param([string]$ObjectName,[string]$ObjectId,[string]$ObjectKind,[object[]]$Assignments)
 foreach($a in @($Assignments)){
  if($null -eq $a){continue}
  $t=$a.target
  if($null -eq $t){continue}
  $type=(AsText $t.'@odata.type') -replace '^#microsoft\.graph\.',''
  $script:AssignmentTargets.Add([pscustomobject]@{
   Object=$ObjectName;ObjectId=$ObjectId;ObjectKind=$ObjectKind;TargetType=$type
   GroupId=AsText $t.groupId;FilterId=AsText $t.deviceAndAppManagementAssignmentFilterId
   FilterType=AsText $t.deviceAndAppManagementAssignmentFilterType;Intent=AsText $a.intent
  })
 }
}
function Add-AssessmentPolicy {
 param([object[]]$Entries,[string]$Kind,[ValidateSet('v1.0','beta')][string]$Version='v1.0',[string]$TargetList='Policy')
 $Entries=@($Entries | Where-Object {AsText $_.id})
 # Use assignments already returned by $expand; batch-fetch only the remaining ones.
 $needFetch=@($Entries | Where-Object {-not $_.PSObject.Properties['assignments']})
 $fetched=@{}
 if($needFetch.Count -gt 0){
  $batch=Invoke-GraphBatchGet -Urls @($needFetch | ForEach-Object {"/deviceManagement/$Kind/$($_.id)/assignments"}) -Version $Version -Label "$TargetList assignments"
  for($k=0;$k -lt $needFetch.Count;$k++){$fetched[[string]$needFetch[$k].id]=$batch[$k]}
 }
 foreach($p in $Entries){
  $id=AsText $p.id
  $name=AsText $p.displayName
  if(-not $name){$name=AsText $p.name}
  $assignments=@();$assignmentState='Unavailable'
  try {
   if($p.PSObject.Properties['assignments']){$assignments=@($p.assignments | Where-Object {$null -ne $_})}
   else{$assignments=@(Get-BatchCollection -Result $fetched[$id] -Label 'Policy assignments')}
   $assignmentState='Complete'
   Register-AssignmentTargets -ObjectName $name -ObjectId $id -ObjectKind $TargetList -Assignments $assignments
  }catch {
   $warnings.Add(("Assignments unavailable for '{0}': {1}" -f $name,(AsText $_.Exception.Message)))
  }
  $type=AsText $p.'@odata.type'
  $row=[pscustomobject]@{
   Name=$name; Kind=$TargetList; Type=$type; Id=$id; Assignments=$assignments.Count
   AssignmentCoverage=$assignmentState; Modified=AsText $p.lastModifiedDateTime
   Created=AsText $p.createdDateTime; Description=AsText $p.description
   TemplateFamily=AsText $p.templateReference.templateFamily
   QualityPaused=AsText $p.qualityUpdatesPaused; FeaturePaused=AsText $p.featureUpdatesPaused
   FeatureTarget=AsText $p.featureUpdateVersion; QualityDeferralDays=AsText $p.qualityUpdatesDeferralPeriodInDays
   FeatureDeferralDays=AsText $p.featureUpdatesDeferralPeriodInDays
  }
  if($TargetList -eq 'Windows Update') {$updateInventory.Add($row)}else{$policyInventory.Add($row)}
 }
}
$classic=@(Get-OptionalCollection -Name 'Classic configuration policies' -Uri "$base/deviceManagement/deviceConfigurations?`$expand=assignments" -FallbackUri "$base/deviceManagement/deviceConfigurations?`$top=500")
# Windows Update rings are deviceConfigurations too: inventory them ONCE, under Windows Update only.
if($collection['Classic configuration policies'] -eq 'Complete') {
 Add-AssessmentPolicy -Entries @($classic | Where-Object {(AsText $_.'@odata.type') -notmatch 'windowsUpdateForBusinessConfiguration'}) -Kind 'deviceConfigurations' -Version 'v1.0' -TargetList 'Configuration'
}
$catalog=@(Get-OptionalCollection -Name 'Settings catalog policies' -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=100&$expand=assignments' -FallbackUri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=100')
if($collection['Settings catalog policies'] -eq 'Complete') {
 Add-AssessmentPolicy -Entries $catalog -Kind 'configurationPolicies' -Version 'beta' -TargetList 'Settings catalog'
}
$updateRings=@($classic | Where-Object {(AsText $_.'@odata.type') -match 'windowsUpdateForBusinessConfiguration'})
if($collection['Classic configuration policies'] -eq 'Complete') {
 Add-AssessmentPolicy -Entries $updateRings -Kind 'deviceConfigurations' -Version 'v1.0' -TargetList 'Windows Update'
 $collection['Windows Update rings']='Complete'
}else{$collection['Windows Update rings']='Unavailable'}
$featureProfiles=@(Get-OptionalCollection -Name 'Feature update profiles' -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?$expand=assignments' -FallbackUri 'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles')
if($collection['Feature update profiles'] -eq 'Complete') {
 Add-AssessmentPolicy -Entries $featureProfiles -Kind 'windowsFeatureUpdateProfiles' -Version 'beta' -TargetList 'Windows Update'
}
$qualityProfiles=@(Get-OptionalCollection -Name 'Quality update profiles' -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles?$expand=assignments' -FallbackUri 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles')
if($collection['Quality update profiles'] -eq 'Complete') {
 Add-AssessmentPolicy -Entries $qualityProfiles -Kind 'windowsQualityUpdateProfiles' -Version 'beta' -TargetList 'Windows Update'
}
# --- 5.2 Baseline (default fdaminato/IntuneBaseline) Windows / macOS Settings Catalog value comparison ---
$BaselineRepo=(([string]$BaselineRepo).Trim() -replace '^https?://github\.com/','' -replace '\.git$','').Trim('/')
$isOibRepo=(-not $BaselinePath) -and ($BaselineRepo -ieq 'SkipToTheEndpoint/OpenIntuneBaseline')
if(-not $BaselineName){
 if($BaselinePath){$BaselineName=Split-Path -Path $BaselinePath -Leaf}
 elseif($isOibRepo){$BaselineName='OpenIntuneBaseline'}
 else{$BaselineName=@($BaselineRepo -split '/')[-1]}
}
$BaselineName=([string]$BaselineName -replace '[^\p{L}\p{N} ._()-]','').Trim()
if(-not $BaselineName){$BaselineName='Baseline'}
$baselineSourceLabel=if($BaselinePath){'Local folder: '+$BaselinePath}else{'github.com/'+$BaselineRepo}
$script:GitHubHeaders=@{'User-Agent'='IntuneAssessmentDashboard';'Accept'='application/vnd.github+json'}
if($GitHubToken){$script:GitHubHeaders['Authorization']='token '+$GitHubToken}
$ghHeadersForParallel=$script:GitHubHeaders
Say "Baseline: $BaselineName ($baselineSourceLabel)"
# This compares configured Intune policy settings; it does NOT prove device application.
# Default to the current GitHub main branch for each run; pin its resolved SHA for all files in this run.
$oibRows=[System.Collections.Generic.List[object]]::new()
$oibTenantGuiRows=[System.Collections.Generic.List[object]]::new()
$oibTenantGuiSeen=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$oibSummary=[ordered]@{Reference=$OpenIntuneBaselineRef;Commit='';Source=$baselineSourceLabel;Name=$BaselineName;Status='Not assessed';BaselinePolicies=0;BaselineSettings=0;TenantPolicies=0;Matched=0;Different=0;Missing=0;Conflicting=0;Unassessed=0}
# Versioned, persistent reference cache: never caches live device results.
function Get-AssessmentCacheFile([string]$Key) {
 $bytes=[System.Text.Encoding]::UTF8.GetBytes($Key)
 $sha=[System.Security.Cryptography.SHA256]::HashData($bytes)
 return (Join-Path $CachePath (([Convert]::ToHexString($sha)).ToLowerInvariant()+'.json'))
}
function Get-AssessmentCachedJson([string]$Key,[int]$TtlHours=24) {
 if(-not $EnableCache){return $null}
 $file=Get-AssessmentCacheFile $Key
 if(-not (Test-Path -LiteralPath $file)){return $null}
 try {
  $cached=Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
  if($cached.Key -ne $Key -or ([DateTime]::UtcNow-([DateTime]$cached.StoredUtc)).TotalHours -gt $TtlHours){return $null}
  $script:GraphStats.CacheHits++
  return $cached.Data
 }catch{return $null}
}
function Set-AssessmentCachedJson([string]$Key,$Data) {
 if(-not $EnableCache -or $null -eq $Data){return}
 try {
  New-Item -ItemType Directory -Path $CachePath -Force | Out-Null
  $file=Get-AssessmentCacheFile $Key
  $temp=$file+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
  @{Key=$Key;StoredUtc=[DateTime]::UtcNow.ToString('o');Data=$Data} | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $temp -Encoding UTF8
  Move-Item -LiteralPath $temp -Destination $file -Force
 }catch{Write-ConsoleWarning ('Reference cache write failed: '+$_.Exception.Message)}
}
function Get-OIBJson([string]$Uri) {
 # Resolve refs on every run; content URLs are commit-addressed and immutable.
 $isImmutable=($Uri -match '/git/trees/[a-f0-9]{40}' -or $Uri -match 'raw.githubusercontent.com/.+?/[a-f0-9]{40}/')
 $cached=if($isImmutable){Get-AssessmentCachedJson -Key ('github:'+ $Uri) -TtlHours 720}else{$null}
 if($null -ne $cached){return $cached}
 $request=@{Uri=$Uri;Headers=$script:GitHubHeaders;TimeoutSec=45;ErrorAction='Stop'}
 for($attempt=0;$attempt -lt 5;$attempt++){
  try {
   $script:GraphStats.Requests++
   $response=Invoke-RestMethod @request
   if($isImmutable){Set-AssessmentCachedJson -Key ('github:'+ $Uri) -Data $response}
   return $response
  }catch{
   $status=0;try{$status=[int]$_.Exception.Response.StatusCode}catch{}
   if($attempt -ge 4 -or ($status -ge 400 -and $status -lt 500 -and $status -notin @(408,429))){throw}
   $script:GraphStats.Retries++
   Start-Sleep -Seconds ([Math]::Min(20,[int][Math]::Pow(2,$attempt+1)))
  }
 }
}
function Get-OIBDeepValue($Node,[int]$Depth=0) {
 # Compare actual configuration data, not Microsoft Graph serialization metadata.
 # Preserve nonempty children, values and collection elements: those may affect behavior.
 if ($Depth -gt 14 -or $null -eq $Node) {return $null}
 if ($Node -is [System.Collections.IDictionary]) {
  $result=[ordered]@{}
  foreach($k in @($Node.Keys | Sort-Object)) {
   $name=[string]$k
   # Graph may serialize absent audit metadata as auditRuleInformation:null.
   # This is not a configured setting and must not cause a baseline mismatch.
   # Keep any non-null audit information and all meaningful setting values.
   if($name -in @('auditRuleInformation','settingInstanceTemplateReference','settingValueTemplateReference') -and $null -eq $Node[$k]) {continue}
   if($name -match '(?i)(^@odata\.|@odata\.type$)' -or $name -in @('settingInstanceTemplateReference','settingValueTemplateReference','id','createdDateTime','lastModifiedDateTime')) {continue}
   $normalized=Get-OIBDeepValue $Node[$k] ($Depth+1)
   # Graph may emit an empty children array on one side but omit it on the other.
   # Only empty children may be ignored; configured nested settings must remain.
   if($name -eq 'children' -and $null -ne $normalized -and $normalized -is [array] -and $normalized.Count -eq 0){continue}
   $result[$name]=$normalized
  }
  return $result
 }
 if ($Node -is [array]) {return ,@($Node | ForEach-Object {Get-OIBDeepValue $_ ($Depth+1)})}
 return $Node
}
function Get-OIBSettingValue($Instance) {
 $v=$null
 foreach($field in @('choiceSettingValue','simpleSettingValue','simpleSettingCollectionValue','groupSettingCollectionValue','groupSettingValue','value')) {
  if($Instance -is [System.Collections.IDictionary] -and $Instance.Contains($field) -and $null -ne $Instance[$field]){$v=$Instance[$field];break}
 }
 if($null -eq $v){return ''}
 $canonical=Get-OIBDeepValue $v
 return (ConvertTo-Json -InputObject $canonical -Compress -Depth 35)
}
function Get-OIBDisplayNameFromNode($Node) {
 if($Node -isnot [System.Collections.IDictionary]){return ''}
 foreach($field in @('settingDisplayName','settingDefinitionDisplayName','displayName','settingName')){
  if($Node.Contains($field) -and $Node[$field] -is [string] -and -not [string]::IsNullOrWhiteSpace($Node[$field])){
   return [string]$Node[$field]
  }
 }
 return ''
}
function Get-OIBSettingInstances($Node,[string]$Policy,[string]$File,[int]$Depth=0) {
 if($Depth -gt 24 -or $null -eq $Node){return}
 if($Node -is [System.Collections.IDictionary]) {
  if($Node.Contains('settingDefinitionId') -and $Node.Contains('settingInstance')) {
   # Typically a setting shell contains a nested instance; recurse rather than double-count.
  }
  if($Node.Contains('settingDefinitionId')) {
   $id=[string]$Node['settingDefinitionId']
   $val=Get-OIBSettingValue $Node
   if($id -and $val) { Write-Output ([pscustomobject]@{SettingId=$id;SettingName=(Get-OIBDisplayNameFromNode $Node);Value=$val;Policy=$Policy;File=$File}) }
  }
  foreach($key in @($Node.Keys)) {
   $child=$Node[$key]
   if($null -ne $child -and ($child -is [System.Collections.IDictionary] -or $child -is [array])) {
    Get-OIBSettingInstances -Node $child -Policy $Policy -File $File -Depth ($Depth+1)
   }
  }
 }elseif($Node -is [array]){foreach($x in $Node){Get-OIBSettingInstances -Node $x -Policy $Policy -File $File -Depth ($Depth+1)}}
}
function ConvertTo-OIBNormalizedValue([string]$Text) {
 if(-not $Text){return ''}
 try {
  # Re-normalize historical rows too; comparison uses semantic values only.
  $parsed=ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 60
  $canonical=Get-OIBDeepValue $parsed
  return (ConvertTo-Json -InputObject $canonical -Compress -Depth 60)
 }catch{return $Text.Trim()}
}
# Readable labels are presentation-only. They never affect the baseline comparison.
function Get-OIBDefinitionName($Definition) {
 if($null -eq $Definition){return ''}
 foreach($field in @('displayName','name')){
  if($Definition -is [System.Collections.IDictionary]){$val=AsText $Definition[$field]}
  else{$val=AsText $Definition.$field}
  if($val){return $val}
 }
 return ''
}
function Get-OIBGuiValue([string]$Raw,$Options) {
 if([string]::IsNullOrWhiteSpace($Raw)){return 'Not configured / unavailable'}
 try{$parsed=ConvertFrom-Json -InputObject $Raw -AsHashtable -Depth 60}catch{return $Raw}
 $lines=[System.Collections.Generic.List[string]]::new()
 $optionMap=@{}
 foreach($o in @($Options)){
  if($null -eq $o){continue}
  $oid=AsText $o.itemId;if(-not $oid){$oid=AsText $o.id}
  $label=AsText $o.displayName;if(-not $label){$label=AsText $o.name}
  if($oid -and $label){$optionMap[$oid.ToLowerInvariant()]=$label}
 }
 function Add-OIBGuiParts($Part,$Lines,$Map,[int]$Depth=0){
  if($Depth -gt 20 -or $null -eq $Part){return}
  if($Part -is [System.Collections.IDictionary]){
   if($Part.Contains('value') -and $null -ne $Part['value'] -and $Part['value'] -isnot [System.Collections.IDictionary] -and $Part['value'] -isnot [array]){
    $val=[string]$Part['value'];$label=$val
    if($Map.ContainsKey($val.ToLowerInvariant())){$label=$Map[$val.ToLowerInvariant()]}
    if(-not $Lines.Contains($label)){$Lines.Add($label)}
   }
   foreach($k in @('choiceSettingValue','simpleSettingValue','simpleSettingCollectionValue','groupSettingValue','groupSettingCollectionValue','children','settingInstance')){
    if($Part.Contains($k)){Add-OIBGuiParts $Part[$k] $Lines $Map ($Depth+1)}
   }
  }elseif($Part -is [array]){foreach($item in $Part){Add-OIBGuiParts $item $Lines $Map ($Depth+1)}}
 }
 Add-OIBGuiParts $parsed $lines $optionMap
 if($lines.Count -gt 0){return ($lines -join ' | ')}
 return $Raw
}
function Add-OIBGraphDefinition($Definition,$Names,$OptionCache,$Metadata) {
 if($null -eq $Definition){return}
 $id=AsText $Definition.id
 if(-not $id){return}
 $key=$id.ToLowerInvariant()
 $label=AsText $Definition.displayName
 if(-not $label){$label=AsText $Definition.name}
 if($label){$Names[$key]=$label}
 $options=@($Definition.options | Where-Object {$null -ne $_})
 if($options.Count -gt 0){$OptionCache[$key]=$options}
 $Metadata[$key]=[pscustomobject]@{
  CategoryId=(AsText $Definition.categoryId)
  Description=(AsText $Definition.description)
  HelpText=(AsText $Definition.helpText)
  RootDefinitionId=(AsText $Definition.rootDefinitionId)
  DefinitionType=(AsText $Definition.'@odata.type')
 }
}
function Get-OIBCategoryPath([string]$CategoryId,$CategoryCache){
 if(-not $CategoryId -or -not $CategoryCache.ContainsKey($CategoryId.ToLowerInvariant())){return ''}
 $parts=[System.Collections.Generic.List[string]]::new()
 $seen=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 $current=$CategoryId
 for($i=0;$i -lt 12 -and $current;$i++){
  $key=$current.ToLowerInvariant()
  if(-not $seen.Add($key) -or -not $CategoryCache.ContainsKey($key)){break}
  $category=$CategoryCache[$key]
  $name=AsText $category.displayName;if(-not $name){$name=AsText $category.name}
  if($name){$parts.Insert(0,$name)}
  $parent=AsText $category.parentCategoryId
  if(-not $parent -or $parent -eq $current){break}
  $current=$parent
 }
 return ($parts -join ' > ')
}
function Get-OIBDefinitionDetails([string]$Id,$Metadata,$Categories){
 $result=[ordered]@{Category='';Description='';HelpText='';DefinitionType=''}
 if(-not $Id){return $result}
 $key=$Id.ToLowerInvariant()
 if($Metadata.ContainsKey($key)){
  $info=$Metadata[$key]
  $result.Category=Get-OIBCategoryPath -CategoryId ([string]$info.CategoryId) -CategoryCache $Categories
  $result.Description=[string]$info.Description
  $result.HelpText=[string]$info.HelpText
  $result.DefinitionType=[string]$info.DefinitionType
 }
 return $result
}
function Get-OIBResolvedGuiLabel([string]$Id,$CachedNames,[string]$Fallback) {
 if($Id -and $CachedNames.ContainsKey($Id.ToLowerInvariant())){return [string]$CachedNames[$Id.ToLowerInvariant()]}
 if($Fallback){return $Fallback}
 return $Id
}
# Fetch live tenant policy settings once per assessment, reuse across OS reference comparisons.
$script:SharedTenantSettingRows=[System.Collections.Generic.List[object]]::new()
$script:SharedTenantSettingErrors=[System.Collections.Generic.List[string]]::new()
if(-not $SkipOpenIntuneBaseline -and $collection['Settings catalog policies'] -eq 'Complete') {
 Say 'Collecting tenant Settings Catalog once for Windows + macOS (batched)...'
 $catalogWithId=@($catalog | Where-Object {AsText $_.id})
 $settingsBatch=Invoke-GraphBatchGet -Urls @($catalogWithId | ForEach-Object {"/deviceManagement/configurationPolicies/$($_.id)/settings?`$top=100"}) -Version 'beta' -Label 'Tenant policy settings'
 $settingsById=@{}
 for($k=0;$k -lt $catalogWithId.Count;$k++){$settingsById[[string]$catalogWithId[$k].id]=$settingsBatch[$k]}
 foreach($tenantPolicy in $catalogWithId) {
  $tenantPolicyId=AsText $tenantPolicy.id
  if(-not $tenantPolicyId){continue}
  $tenantPolicyName=AsText $tenantPolicy.name
  if(-not $tenantPolicyName){$tenantPolicyName=AsText $tenantPolicy.displayName}
  $tenantPlatform=AsText $tenantPolicy.platforms
  try {
   $settings=@(Get-BatchCollection -Result $settingsById[$tenantPolicyId] -Label 'Tenant policy settings')
   foreach($entry in $settings){
    $entryHash=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $entry -Depth 60 -Compress) -AsHashtable -Depth 60
    foreach($settingRow in @(Get-OIBSettingInstances -Node $entryHash -Policy $tenantPolicyName -File $tenantPolicyId)) {
     $script:SharedTenantSettingRows.Add([pscustomobject]@{Platform=$tenantPlatform;Setting=$settingRow})
    }
   }
  }catch{
   $script:SharedTenantSettingErrors.Add(('Policy {0}: {1}' -f $tenantPolicyName,$_.Exception.Message))
   $warnings.Add(('Tenant settings unavailable for policy {0}: {1}' -f $tenantPolicyName,$_.Exception.Message))
  }
 }
 Say ('Shared Settings Catalog collected: {0} setting records, {1} policies unavailable' -f $script:SharedTenantSettingRows.Count,$script:SharedTenantSettingErrors.Count)
}
$oibSummaries=@{}
if($SkipOpenIntuneBaseline){$collection['OpenIntuneBaseline']='Skipped';$oibSummary.Status='Skipped'}
elseif($collection['Settings catalog policies'] -ne 'Complete'){
 $collection['OpenIntuneBaseline']='Unavailable';$oibSummary.Status='Not assessed: Settings Catalog enumeration unavailable'
}else{
 foreach($oibPlatform in @($baselinePlatforms)) {
 $platformRef=if($BaselineRef){$BaselineRef}elseif($isOibRepo -and $oibPlatform -eq 'Windows'){$OpenIntuneBaselineRef}elseif($isOibRepo){$OpenIntuneBaselineMacRef}else{'HEAD'}
 $platformPattern=if(-not $isOibRepo){if($BaselinePathFilter){$BaselinePathFilter}else{'(?i)\.json$'}}elseif($oibPlatform -eq 'Windows'){'^WINDOWS/IntuneManagement/SettingsCatalog/.+\.json$'}else{'(?i)^MACOS/(?:IntuneManagement/)?(?:SettingsCatalog/|.*?/SettingsCatalog/).+\.json$'}
 $platformRows=[System.Collections.Generic.List[object]]::new()
 $oibSummary=[ordered]@{Reference=$platformRef;Commit='';Platform=$oibPlatform;Source=$baselineSourceLabel;Name=$BaselineName;Status='Not assessed';BaselinePolicies=0;BaselineSettings=0;TenantPolicies=0;Matched=0;Different=0;Missing=0;Conflicting=0;Unassessed=0}
 Say ("Collecting $BaselineName $oibPlatform Settings Catalog reference...")
 try {
  if($BaselinePath){
   # Local folder baseline: same parsing as GitHub files, no network access.
   if(-not (Test-Path -LiteralPath $BaselinePath -PathType Container)){throw "Baseline folder not found: $BaselinePath"}
   $oibSummary.Reference='Local folder';$oibSummary.Commit='local'
   $baseRoot=(Resolve-Path -LiteralPath $BaselinePath).Path
   $files=[System.Collections.Generic.List[object]]::new()
   foreach($localFile in @(Get-ChildItem -LiteralPath $baseRoot -Filter '*.json' -Recurse -File)){
    if($localFile.FullName -match '(?i)manifest'){continue}
    $relative=$localFile.FullName.Substring($baseRoot.Length).TrimStart([char[]]@('\','/'))
    $files.Add([pscustomobject]@{path=$relative;full=$localFile.FullName})
   }
   if($files.Count -eq 0){throw "No JSON baseline files found in $BaselinePath"}
   $baselineSettings=[System.Collections.Generic.List[object]]::new()
   $failedFiles=0
   $baselineDownloads=[System.Collections.Generic.List[object]]::new()
   foreach($file in $files){
    try{
     $localData=Get-Content -LiteralPath $file.full -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
     $baselineDownloads.Add([pscustomobject]@{Path=$file.path;Data=$localData;Error=''})
    }catch{$baselineDownloads.Add([pscustomobject]@{Path=$file.path;Data=$null;Error=$_.Exception.Message})}
   }
  }else{
  $encodedRef=[uri]::EscapeDataString($platformRef)
  $gitRef=Get-OIBJson "https://api.github.com/repos/$BaselineRepo/commits/$encodedRef"
  $commit=[string]$gitRef.sha
  if($commit -notmatch '^[a-f0-9]{40}$'){throw 'Unable to resolve a 40-character Git commit SHA from the selected GitHub reference.'}
  $oibSummary.Commit=$commit
  $tree=Get-OIBJson "https://api.github.com/repos/$BaselineRepo/git/trees/$commit`?recursive=1"
  if($tree.truncated){throw 'GitHub returned a truncated repository tree; refusing partial baseline.'}
  $files=@($tree.tree | Where-Object { $_.type -eq 'blob' -and $_.path -match $platformPattern -and $_.path -notmatch 'manifest' -and $_.path -notmatch '(?i)(^|/)\.github/' })
  if($files.Count -eq 0){throw ("No $oibPlatform Settings Catalog baseline JSON files found at this release.")}
  $baselineSettings=[System.Collections.Generic.List[object]]::new()
  $failedFiles=0
  # GitHub reference files are independent and safe to fetch concurrently.
  # Cached commit-addressed copies are used first; only cache misses enter the bounded pool.
  $baselineDownloads=[System.Collections.Generic.List[object]]::new()
  $toFetch=[System.Collections.Generic.List[object]]::new()
  foreach($file in $files){
   $rawUrl=('https://raw.githubusercontent.com/'+$BaselineRepo+'/')+$commit+'/'+$file.path
   $cachedBlob=Get-AssessmentCachedJson -Key ('github:'+$rawUrl) -TtlHours 720
   if($null -ne $cachedBlob){$baselineDownloads.Add([pscustomobject]@{Path=$file.path;Data=$cachedBlob;Error=''})}
   else{$toFetch.Add([pscustomobject]@{Path=$file.path;Url=$rawUrl})}
  }
  if($toFetch.Count -gt 0){
   Say ('OpenIntuneBaseline {0}: {1} cached, {2} downloads (max {3} concurrent)' -f $oibPlatform,$baselineDownloads.Count,$toFetch.Count,$MaxConcurrentRequests)
   try {
    $fresh=@($toFetch.ToArray() | ForEach-Object -Parallel {
     $target=$_
     $last=''
     for($attempt=0;$attempt -lt 5;$attempt++){
      try {
       $response=Invoke-RestMethod -Uri $target.Url -Headers $using:ghHeadersForParallel -TimeoutSec 45 -ErrorAction Stop
       [pscustomobject]@{Path=$target.Path;Data=$response;Error='';Attempts=($attempt+1)}
       break
      }catch{
       $last=$_.Exception.Message
       $status=0;try{$status=[int]$_.Exception.Response.StatusCode}catch{}
       if($attempt -eq 4 -or ($status -ge 400 -and $status -lt 500 -and $status -notin @(408,429))){
        [pscustomobject]@{Path=$target.Path;Data=$null;Error=$last;Attempts=($attempt+1)}
        break
       }
       Start-Sleep -Seconds ([Math]::Min(20,[int][Math]::Pow(2,$attempt+1)))
      }
     }
    } -ThrottleLimit $MaxConcurrentRequests)
    foreach($item in $fresh){
     $script:GraphStats.Requests += [int]$item.Attempts
     $script:GraphStats.Retries += [Math]::Max(0,[int]$item.Attempts-1)
     $baselineDownloads.Add($item)
     if(-not $item.Error){
      $cacheUrl=('https://raw.githubusercontent.com/'+$BaselineRepo+'/')+$commit+'/'+$item.Path
      Set-AssessmentCachedJson -Key ('github:'+$cacheUrl) -Data $item.Data
     }
    }
   }catch{
    # Network/threading problems should not prevent the supported sequential path.
    $warnings.Add(('Parallel GitHub download unavailable; sequential fallback: '+$_.Exception.Message))
    $baselineDownloads.Clear()
    foreach($file in $files){
     try{$value=Get-OIBJson (('https://raw.githubusercontent.com/'+$BaselineRepo+'/')+$commit+'/'+$file.path);$baselineDownloads.Add([pscustomobject]@{Path=$file.path;Data=$value;Error=''})}
     catch{$baselineDownloads.Add([pscustomobject]@{Path=$file.path;Data=$null;Error=$_.Exception.Message})}
    }
   }
  }
  }
  $keptFiles=0;$skippedFiles=0
  foreach($download in $baselineDownloads){
   if($download.Error){$failedFiles++;$warnings.Add(('OIB baseline file unavailable: {0}: {1}' -f $download.Path,$download.Error));continue}
   try {
    $json=ConvertTo-Json -InputObject $download.Data -Depth 60 -Compress
    $data=ConvertFrom-Json -InputObject $json -AsHashtable -Depth 60
    if(-not $isOibRepo){
     # Generic baseline repository: keep Settings Catalog policies of the current platform only.
     if(-not ($data -is [System.Collections.IDictionary]) -or -not $data.ContainsKey('settings')){$skippedFiles++;continue}
     $filePlatform=[string]$data['platforms']
     $fileIsMac=($filePlatform -match '(?i)mac')
     $fileIsWindows=($filePlatform -match '(?i)windows')
     if(($oibPlatform -eq 'macOS' -and -not $fileIsMac) -or ($oibPlatform -eq 'Windows' -and -not $fileIsWindows)){$skippedFiles++;continue}
    }
    $keptFiles++
    $policyName=[string]$data['name'];if(-not $policyName){$policyName=[string]$data['displayName']};if(-not $policyName){$policyName=Split-Path $download.Path -Leaf}
    $instances=@(Get-OIBSettingInstances -Node $data -Policy $policyName -File ([string]$download.Path))
    foreach($item in $instances){$baselineSettings.Add($item)}
   }catch{$failedFiles++;$warnings.Add(('OIB baseline file parse error: {0}: {1}' -f $download.Path,$_.Exception.Message))}
  }
  $script:GraphStats.BaselineFiles += $baselineDownloads.Count
  if($failedFiles -gt 0){throw "Failed to parse $failedFiles baseline files; baseline marked incomplete."}
  if($keptFiles -eq 0){throw "No $oibPlatform Settings Catalog policy found in baseline $BaselineName ($skippedFiles files ignored)."}
  if($baselineSettings.Count -eq 0){throw 'No comparable Settings Catalog settingDefinitionId values found in the baseline files.'}
  $oibSummary.BaselinePolicies=$keptFiles
  $oibSummary.BaselineSettings=$baselineSettings.Count
  $tenantSettings=[System.Collections.Generic.List[object]]::new()
  $tenantErrors=$script:SharedTenantSettingErrors.Count
  foreach($record in $script:SharedTenantSettingRows){
   $platformString=AsText $record.Platform
   if($platformString){
    if($oibPlatform -eq 'macOS' -and $platformString -notmatch '(?i)mac'){continue}
    if($oibPlatform -eq 'Windows' -and $platformString -notmatch '(?i)windows'){continue}
   }
   $tenantSettings.Add($record.Setting)
  }
  $oibSummary.TenantPolicies=$catalog.Count
  # Graph beta definition catalog: labels, available choices and category tree.
  # Cached for both platforms; lookup failure never changes comparison results.
  if($null -eq $script:OibSettingDefinitionCache){$script:OibSettingDefinitionCache=@{}}
  if($null -eq $script:OibSettingOptions){$script:OibSettingOptions=@{}}
  if($null -eq $script:OibSettingMetadata){$script:OibSettingMetadata=@{}}
  if($null -eq $script:OibCategoryCache){$script:OibCategoryCache=@{}}
  if($null -eq $script:OibSettingDefinitionAttempts){$script:OibSettingDefinitionAttempts=0}
  if($null -eq $script:OibSettingDefinitionIndexLoaded){$script:OibSettingDefinitionIndexLoaded=$false}
  $oibDefinitionNames=$script:OibSettingDefinitionCache
  Say 'Loading Graph beta Intune setting names, options and categories...'
  if(-not $script:OibSettingDefinitionIndexLoaded){
   $script:OibSettingDefinitionIndexLoaded=$true
   $definitionsKey='graphbeta:configurationSettings:definitions:v1'
   $categoriesKey='graphbeta:configurationCategories:v1'
   try {
    $cachedDefinitions=Get-AssessmentCachedJson -Key $definitionsKey -TtlHours $CacheMaxAgeHours
    $definitions=if($null -ne $cachedDefinitions){@($cachedDefinitions)}else{@(Read-GraphPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationSettings' -Label 'Graph beta setting definitions')}
    if($null -eq $cachedDefinitions){Set-AssessmentCachedJson -Key $definitionsKey -Data $definitions}
    foreach($definition in $definitions){
     Add-OIBGraphDefinition -Definition $definition -Names $oibDefinitionNames -OptionCache $script:OibSettingOptions -Metadata $script:OibSettingMetadata
    }
    Say ("Graph beta setting definitions: {0} names / {1} option maps" -f $oibDefinitionNames.Count,$script:OibSettingOptions.Count)
   }catch {
    $warnings.Add(('Graph beta setting definition catalog unavailable; targeted lookups will be attempted: {0}' -f $_.Exception.Message))
   }
   try {
    $cachedCategories=Get-AssessmentCachedJson -Key $categoriesKey -TtlHours $CacheMaxAgeHours
    $categories=if($null -ne $cachedCategories){@($cachedCategories)}else{@(Read-GraphPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationCategories' -Label 'Graph beta setting categories')}
    if($null -eq $cachedCategories){Set-AssessmentCachedJson -Key $categoriesKey -Data $categories}
    foreach($cat in $categories){$cid=AsText $cat.id;if($cid){$script:OibCategoryCache[$cid.ToLowerInvariant()]=$cat}}
    Say ("Graph beta configuration categories: {0}" -f $script:OibCategoryCache.Count)
   }catch {$warnings.Add(('Graph beta category paths unavailable: {0}' -f $_.Exception.Message))}
  }
  # Targeted resolution is bounded across both Windows and macOS.
  $unresolvedIds=@($baselineSettings | ForEach-Object {$_.SettingId.ToLowerInvariant()} | Select-Object -Unique | Where-Object {-not $oibDefinitionNames.ContainsKey($_)})
  $lookupBudget=[Math]::Max(0,300-$script:OibSettingDefinitionAttempts)
  $lookupCount=0
  foreach($definitionId in $unresolvedIds){
   if($lookupCount -ge $lookupBudget){break}
   $lookupCount++;$script:OibSettingDefinitionAttempts++
   $targetKey='graphbeta:definition:'+ $definitionId
   $previous=Get-AssessmentCachedJson -Key $targetKey -TtlHours $CacheMaxAgeHours
   if($null -ne $previous){
    if((AsText $previous.state) -eq 'missing'){continue}
    if($previous.definition){Add-OIBGraphDefinition -Definition $previous.definition -Names $oibDefinitionNames -OptionCache $script:OibSettingOptions -Metadata $script:OibSettingMetadata;continue}
   }
   try {
    $encodedId=[uri]::EscapeDataString([string]$definitionId)
    $one=Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings/$encodedId" -ErrorAction Stop
    Add-OIBGraphDefinition -Definition $one -Names $oibDefinitionNames -OptionCache $script:OibSettingOptions -Metadata $script:OibSettingMetadata
    Set-AssessmentCachedJson -Key $targetKey -Data @{state='found';definition=$one}
   }catch { # Some definitions cannot be addressed individually.
    $status=0;try{$status=[int]$_.Exception.Response.StatusCode}catch{}
    if($status -eq 404){Set-AssessmentCachedJson -Key $targetKey -Data @{state='missing'}}
   }
  }
  if($lookupCount){Say ("Targeted definition lookups: {0}; names resolved: {1}" -f $lookupCount,$oibDefinitionNames.Count)}
  $map=@{}
  foreach($item in $tenantSettings){
   # Normalize each tenant value once (was recomputed for every baseline comparison).
   if(-not $item.PSObject.Properties['Norm']){$item | Add-Member -NotePropertyName Norm -NotePropertyValue (ConvertTo-OIBNormalizedValue $item.Value) -Force}
   $key=$item.SettingId.ToLowerInvariant();if(-not $map.ContainsKey($key)){$map[$key]=[System.Collections.Generic.List[object]]::new()};$map[$key].Add($item)
  }
  # Settings Catalog policies with at least one assignment (collected through $expand / batch).
  $assignedCatalog=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($pol in @($policyInventory | Where-Object {$_.Kind -eq 'Settings catalog' -and $_.AssignmentCoverage -eq 'Complete' -and $_.Assignments -gt 0})){[void]$assignedCatalog.Add([string]$pol.Id)}
  # Compare each tenant policy independently; cross-policy differences are not Intune conflicts.
  foreach($expected in $baselineSettings){
   $key=$expected.SettingId.ToLowerInvariant()
   $baselineMatches=@();if($map.ContainsKey($key)){$baselineMatches=@($map[$key])}
   $matchedByPolicy=@($baselineMatches | Group-Object -Property File)
   if($matchedByPolicy.Count -eq 0){$matchedByPolicy=@($null)}
   # Potential conflict: two or more ASSIGNED tenant policies set this setting to different values.
   $assignedValues=@{}
   foreach($candidate in $matchedByPolicy){
    if($null -eq $candidate -or -not $assignedCatalog.Contains([string]$candidate.Name)){continue}
    $candidateValues=@($candidate.Group | ForEach-Object {$_.Norm} | Select-Object -Unique)
    if($candidateValues.Count -eq 1){$assignedValues[[string]$candidate.Name]=[string]$candidateValues[0]}
   }
   $settingConflict=(@($assignedValues.Values | Select-Object -Unique).Count -gt 1)
   $expectedNorm=ConvertTo-OIBNormalizedValue $expected.Value
   foreach($tenantPolicyGroup in $matchedByPolicy){
    $result='Missing';$actual='';$tenantPolicy='';$tenantPolicyId=''
    $explanation='No matching Settings Catalog setting ID found in collected tenant policies.'
    if($null -ne $tenantPolicyGroup){
     $tenantPolicyId=[string]$tenantPolicyGroup.Name
     $policyMatches=@($tenantPolicyGroup.Group)
     $tenantPolicy=[string]$policyMatches[0].Policy
     $policyValues=@($policyMatches | ForEach-Object {$_.Norm} | Select-Object -Unique)
     if($policyValues.Count -gt 1){
      $result='Not assessed';$actual=($policyValues -join ' | ')
      $explanation='Multiple values for the same setting within this tenant policy; inspect nested instances.'
     }else{
      $actual=[string]$policyValues[0]
      if($expectedNorm -eq $actual){$result='Match';$explanation='This tenant policy matches the baseline value.'}
      else{$result='Different';$explanation='This tenant policy configures a different value from the baseline.'}
      if($settingConflict -and $assignedValues.ContainsKey($tenantPolicyId)){
       $result='Conflicting'
       $explanation='Potential conflict: at least two assigned Settings Catalog policies set this setting to different values. Intune reports an actual conflict only where assignments overlap on a device.'
      }
     }
    }elseif($tenantErrors -gt 0){$result='Not assessed';$explanation='Tenant settings collection incomplete; absence cannot be verified.'}
   $settingName=''
   $settingNameSource='Technical ID'
   if($oibDefinitionNames.ContainsKey($key)){$settingName=$oibDefinitionNames[$key];$settingNameSource='Microsoft Graph setting definition'}
   elseif($expected.SettingName){$settingName=[string]$expected.SettingName;$settingNameSource='OpenIntuneBaseline metadata'}
   elseif($baselineMatches.Count -gt 0){
    $availableName=@($baselineMatches | Where-Object { $_.SettingName } | Select-Object -First 1)
    if($availableName.Count -gt 0){$settingName=[string]$availableName[0].SettingName;$settingNameSource='Intune policy metadata'}
   }
   if(-not $settingName){
    # Best-effort readable label if the Graph catalog doesn't expose a displayName.
    # Clearly mark it as derived, not as an authoritative Intune GUI label.
    $rawId=[string]$expected.SettingId
    $candidate=($rawId -replace '^.*?_policy_config_', '' -replace '^vendor_msft_', '' -replace '_', ' ').Trim()
    if($candidate -and $candidate -ne $rawId -and $candidate.Length -gt 8){
     $settingName=(Get-Culture).TextInfo.ToTitleCase($candidate.ToLowerInvariant())
     $settingNameSource='Readable label derived from technical ID (not verified GUI name)'
    }else{$settingName=$rawId}
   }
   $options=@();if($script:OibSettingOptions.ContainsKey($key)){$options=@($script:OibSettingOptions[$key])}
   $detail=Get-OIBDefinitionDetails -Id $key -Metadata $script:OibSettingMetadata -Categories $script:OibCategoryCache
   $expectedGui=Get-OIBGuiValue -Raw $expected.Value -Options $options
   $tenantGui=if($result -eq 'Missing' -or $result -eq 'Not assessed'){'Not verified'}else{Get-OIBGuiValue -Raw $actual -Options $options}
   $platformRows.Add([pscustomobject]@{OS=$oibPlatform;Status=$result;BaselinePolicy=$expected.Policy;SettingName=$settingName;SettingNameSource=$settingNameSource;SettingId=$expected.SettingId;SettingCategory=$detail.Category;SettingDescription=$detail.Description;SettingHelpText=$detail.HelpText;BaselineDisplayValue=$expectedGui;TenantDisplayValue=$tenantGui;BaselineValue=$expected.Value;TenantValue=$actual;TenantPolicy=$tenantPolicy;TenantPolicyId=$tenantPolicyId;Evidence=$explanation;BaselineFile=$expected.File;Commit=$commit})
   }
  }
  foreach($tsetting in $tenantSettings){
   $tkey=[string]$tsetting.SettingId
   $unique="$oibPlatform|$($tsetting.File)|$tkey|$($tsetting.Value)"
   if(-not $oibTenantGuiSeen.Add($unique)){continue}
   $optionSet=@();if($script:OibSettingOptions.ContainsKey($tkey.ToLowerInvariant())){$optionSet=@($script:OibSettingOptions[$tkey.ToLowerInvariant()])}
   $friendly=Get-OIBResolvedGuiLabel -Id $tkey -CachedNames $oibDefinitionNames -Fallback ([string]$tsetting.SettingName)
   $tenantDetail=Get-OIBDefinitionDetails -Id $tkey -Metadata $script:OibSettingMetadata -Categories $script:OibCategoryCache
   $oibTenantGuiRows.Add([pscustomobject]@{OS=$oibPlatform;Policy=$tsetting.Policy;SettingName=$friendly;SettingId=$tkey;SettingCategory=$tenantDetail.Category;SettingDescription=$tenantDetail.Description;ConfiguredValue=(Get-OIBGuiValue -Raw $tsetting.Value -Options $optionSet);RawValue=$tsetting.Value;PolicyId=$tsetting.File})
  }
  foreach($key in @('Match','Different','Missing','Conflicting','Not assessed')){
   $count=@($platformRows | Where-Object Status -eq $key).Count
   switch($key){'Match'{$oibSummary.Matched=$count};'Different'{$oibSummary.Different=$count};'Missing'{$oibSummary.Missing=$count};'Conflicting'{$oibSummary.Conflicting=$count};'Not assessed'{$oibSummary.Unassessed=$count}}
  }
  $oibSummary.Status= if($tenantErrors -gt 0){"Partial: $tenantErrors tenant policies unavailable"}else{'Complete: configured policies only'}
  $collection['OpenIntuneBaseline']=$oibSummary.Status
  Say ("$BaselineName : {0} matching; {1} different; {2} missing; {3} conflicts; {4} unassessed" -f $oibSummary.Matched,$oibSummary.Different,$oibSummary.Missing,$oibSummary.Conflicting,$oibSummary.Unassessed)
  if($tenantErrors -eq 0){
   if($oibSummary.Different -gt 0){Add-Finding -Severity 'Medium' -Area 'OpenIntuneBaseline' -Title "$oibPlatform baseline settings configured differently" -Affected $oibSummary.Different -Evidence "$BaselineName setting ID/value comparison" -Recommendation 'Review differences against business requirements; baseline values are advisory.'}
   if($oibSummary.Conflicting -gt 0){Add-Finding -Severity 'Medium' -Area 'OpenIntuneBaseline' -Title "$oibPlatform baseline settings configured with different values in several assigned policies" -Affected $oibSummary.Conflicting -Evidence 'OpenIntuneBaseline-Comparison.csv (Status = Conflicting)' -Recommendation 'Consolidate the setting into a single policy or confirm the assignment groups never overlap.'}
   if($oibSummary.Missing -gt 0){Add-Finding -Severity 'Informational' -Area 'OpenIntuneBaseline' -Title "$BaselineName settings not found in Settings Catalog" -Affected $oibSummary.Missing -Evidence 'No matching setting ID in collected Intune Settings Catalog profiles' -Recommendation 'Validate whether settings are applied by GPO, other policy channels or accepted exceptions.'}
  }
 }catch{
  $platformRows.Clear();$oibSummary.Status='Not assessed: '+$_.Exception.Message
  $collection['OpenIntuneBaseline']='Unavailable';$warnings.Add($oibSummary.Status);Write-ConsoleWarning $oibSummary.Status
 }
 $oibSummaries[$oibPlatform]=$oibSummary
 foreach($item in $platformRows){$oibRows.Add($item)}
 }
 # Keep the real per-platform outcome instead of overwriting partial/failed results.
 $platformStates=@($oibSummaries.Keys | Sort-Object | ForEach-Object {'{0}: {1}' -f $_,$oibSummaries[$_].Status})
 $collection['OpenIntuneBaseline']=$platformStates -join ' | '
 $oibSummary=$oibSummaries['Windows']
}

# --- 5.3 Intune export reports: policy deployment and feature updates ---
$policyDeployment=[System.Collections.Generic.List[object]]::new()
$featureUpdateStates=[System.Collections.Generic.List[object]]::new()
$featureUpdateFailures=[System.Collections.Generic.List[object]]::new()
# Feature Update device-state/failure reports REQUIRE a PolicyId filter (Microsoft Learn).
# Collect IDs from the feature update profiles or the unfiltered policy-status summary.
# A 400 on a beta listing is nonfatal, and we do not fabricate feature-update evidence.
$featurePolicyIds=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($featureProfile in @($featureProfiles)) {
 $id=AsText $featureProfile.id
 if($id -match '^[0-9a-fA-F-]{36}$'){[void]$featurePolicyIds.Add($id)}
}
if($SkipDeploymentReports){
 $collection['Policy deployment status']='Skipped'
 $collection['Feature update device state']='Skipped'
 $collection['Feature update failures']='Skipped'
}else{
 # Queue independent export jobs now so Intune generates them in parallel.
 $prestart=@('DeviceConfigurationPolicyStatusesV3','FeatureUpdatePolicyStatusSummary')
 if(-not $SkipSettingFailures){$prestart+='DevicePolicySettingsComplianceReportV3'}
 foreach($reportName in $prestart){$script:PrestartedReportJobs[$reportName]=Start-IntuneReportJobSafe -ReportName $reportName}
 Say 'Exporting Policy deployment status via Intune Graph reports ...'
 try {
  $rows=@(Get-IntuneReportRows -ReportName 'DeviceConfigurationPolicyStatusesV3')
  $collection['Policy deployment status']="Complete ($($rows.Count) rows)"
  foreach($r in $rows){
   $policyDeployment.Add([pscustomobject]@{
    Device=(PropertyText $r @('DeviceName','ManagedDeviceName'))
    DeviceId=(PropertyText $r @('IntuneDeviceId','DeviceId','ManagedDeviceId'))
    Policy=(PropertyText $r @('PolicyName','DisplayName'))
    PolicyId=(PropertyText $r @('PolicyId'))
    Status=(Resolve-PolicyDeploymentStatus (PropertyText $r @('PolicyStatus','ReportStatus','Status')))
    RawStatus=(PropertyText $r @('PolicyStatus','ReportStatus','Status'))
    Error=(PropertyText $r @('ErrorCode','Error'))
    LastReported=(PropertyText $r @('PspdpuLastModifiedTimeUtc','LastReportedDateTime'))
    Source='DeviceConfigurationPolicyStatusesV3'
   })
  }
  Say "Policy deployment status: $($rows.Count) rows"
 }catch{
  $collection['Policy deployment status']='Unavailable'
  $warnings.Add("Policy deployment status: $($_.Exception.Message)")
  Write-ConsoleWarning "Policy deployment status unavailable: $($_.Exception.Message)"
 }
 # This summary does not require a PolicyId, and supports discovery when beta profile listing fails.
 Say 'Discovering feature update policy IDs from Intune report ...'
 try {
  $summaryRows=@(Get-IntuneReportRows -ReportName 'FeatureUpdatePolicyStatusSummary')
  foreach($r in $summaryRows){
   $id=PropertyText $r @('PolicyId')
   if($id -match '^[0-9a-fA-F-]{36}$'){[void]$featurePolicyIds.Add($id)}
  }
  $collection['Feature update policy summary']="Complete ($($summaryRows.Count) rows)"
 }catch{
  $collection['Feature update policy summary']='Unavailable'
  $warnings.Add("Feature update policy summary: $($_.Exception.Message)")
  Write-ConsoleWarning "Feature update policy summary unavailable: $($_.Exception.Message)"
 }
 if($featurePolicyIds.Count -eq 0){
  $collection['Feature update device state']='Not assessed (no feature update policy IDs available)'
  $collection['Feature update failures']='Not assessed (no feature update policy IDs available)'
  Say 'No feature update policy IDs available; skipping reports that require a PolicyId filter.'
 }else{
  $reportSpecs=@(
   @{Label='Feature update device state';Name='FeatureUpdateDeviceState';Bucket='updates'},
   @{Label='Feature update failures';Name='DeviceFailuresByFeatureUpdatePolicy';Bucket='failures'}
  )
  # Queue every per-policy export first, then collect: jobs run concurrently on the Intune side.
  $featureJobs=@{}
  foreach($spec in $reportSpecs){foreach($policyId in $featurePolicyIds){$featureJobs["$($spec.Name)|$policyId"]=Start-IntuneReportJobSafe -ReportName $spec.Name -Filter "(PolicyId eq '$policyId')"}}
  foreach($spec in $reportSpecs){
   $successful=0; $failed=0; $total=0
   foreach($policyId in $featurePolicyIds){
    # Escaping is not needed for validated UUIDs; the filter is required by the report API.
    $filter="(PolicyId eq '$policyId')"
    Say "Exporting $($spec.Label) for policy $policyId ..."
    try{
     $rows=@(Get-IntuneReportRows -ReportName $spec.Name -Filter $filter -JobId ([string]$featureJobs["$($spec.Name)|$policyId"]))
     $successful++;$total+=$rows.Count
     foreach($r in $rows){
      $device=PropertyText $r @('DeviceName')
      $deviceId=PropertyText $r @('DeviceId','AADDeviceId')
      $policy=PropertyText $r @('PolicyName')
      $reportPolicyId=PropertyText $r @('PolicyId')
      if(-not $reportPolicyId){$reportPolicyId=$policyId}
      $status=PropertyText $r @('AggregateState','CurrentDeviceUpdateStatus','AlertStatus','Status')
      $reportError=PropertyText $r @('LatestAlertMessage','AlertMessage','Win32ErrorCode','LatestAlertMessageDescription')
      $date=PropertyText $r @('EventDateTimeUTC','CurrentDeviceUpdateStatusEventDateTimeUTC','LastUpdatedAlertStatusDateTimeUTC')
      $record=[pscustomobject]@{Device=$device;DeviceId=$deviceId;Policy=$policy;PolicyId=$reportPolicyId;Status=$status;Error=$reportError;LastReported=$date;Source=$spec.Name}
      if($spec.Bucket -eq 'updates'){$featureUpdateStates.Add($record)}else{$featureUpdateFailures.Add($record)}
     }
    }catch{
     $failed++
     $warnings.Add("$($spec.Label), policy $policyId : $($_.Exception.Message)")
     Write-ConsoleWarning "$($spec.Label) for policy $policyId unavailable: $($_.Exception.Message)"
    }
   }
   $collection[$spec.Label]=if($failed -eq 0){"Complete ($total rows, $successful policies)"}elseif($successful -gt 0){"Partial ($total rows, $successful succeeded, $failed failed)"}else{'Unavailable'}
   Say "$($spec.Label): $total records ($successful policies succeeded, $failed failed)"
  }
 }
}
# --- 5.4 BitLocker escrow, setting-level diagnostics, Defender signals ---
# Recovery-key metadata only: never fetch recovery-key secrets or use $select=key.
$escrowRows=[System.Collections.Generic.List[object]]::new()
$settingFailureRows=[System.Collections.Generic.List[object]]::new()
$defenderRows=[System.Collections.Generic.List[object]]::new()
$escrowByAAD=@{}
$escrowAvailable=$false
if($SkipBitLockerEscrow){$collection['BitLocker escrow metadata']='Skipped'}else{
 Say 'Collecting BitLocker escrow metadata (no passwords) ...'
 try {
  # Graph BitLocker recoveryKeys listing explicitly does NOT support $top.
  $keyRows=@(Read-GraphPages -Uri "$base/informationProtection/bitlocker/recoveryKeys" -Label 'BitLocker recovery key metadata')
  $escrowAvailable=$true
  foreach($key in $keyRows){
   $aad=(AsText $key.deviceId).ToLowerInvariant()
   if(-not $aad){continue}
   if(-not $escrowByAAD.ContainsKey($aad)){$escrowByAAD[$aad]=0}
   $escrowByAAD[$aad]++
  }
  $collection['BitLocker escrow metadata']="Complete ($($keyRows.Count) key records; no secrets)"
 }catch{
  $collection['BitLocker escrow metadata']='Not assessed (Graph access unavailable)'
  $warnings.Add("BitLocker escrow metadata unavailable: $($_.Exception.Message)")
 }
}
foreach($dev in @($devices | Where-Object {$_.OS -match '^Windows'})){
 $keyCount=0; $state='Not assessed'
 $aad=(AsText $dev.AzureADDeviceId).ToLowerInvariant()
 if($escrowAvailable){
  if(-not $aad){$state='Unknown device ID'}
  elseif($escrowByAAD.ContainsKey($aad)){$keyCount=$escrowByAAD[$aad];$state='Escrow record found'}
  else{$state='No escrow record found'}
 }
 $escrowRows.Add([pscustomobject]@{
  Device=$dev.Name;DeviceId=$dev.Id;EntraDeviceId=$aad;Encryption=$dev.Encrypted
  EscrowStatus=$state;RecoveryKeyRecords=$keyCount
  Note='Key metadata only; a recovery-key record does not prove current encryption or key usability.'
 })
}
if($escrowAvailable){
 $encryptedWithout=@($escrowRows | Where-Object {$_.Encryption -eq 'Encrypted' -and $_.EscrowStatus -eq 'No escrow record found'})
 if($encryptedWithout.Count -gt 0){Add-Finding 'High' 'BitLocker' 'Encrypted Windows devices have no visible Entra recovery-key escrow record' $encryptedWithout.Count 'BitLocker-Escrow-Audit.csv' 'Check whether recovery keys are backed up to Entra and whether Graph permissions can see all tenant keys. This does not establish that no recovery method exists.'}
}

# Name lookup for policy setting diagnostics. Match Intune and Entra device IDs, and
# both policy inventory and deployment-export IDs. Unknown IDs remain visible.
$settingDeviceNames=[System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($deviceRecord in @($devices)) {
 $displayDeviceName=AsText $deviceRecord.Name
 if(-not $displayDeviceName){continue}
 foreach($key in @((AsText $deviceRecord.Id),(AsText $deviceRecord.AzureADDeviceId))) {
  if($key -and -not $settingDeviceNames.ContainsKey($key)){$settingDeviceNames[$key]=$displayDeviceName}
 }
}
$settingPolicyNames=[System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($policyRecord in @($policyInventory)) {
 $key=AsText $policyRecord.Id;$name=AsText $policyRecord.Name
 if($key -and $name -and -not $settingPolicyNames.ContainsKey($key)){$settingPolicyNames[$key]=$name}
}
foreach($deploymentRecord in @($policyDeployment)) {
 $key=AsText $deploymentRecord.PolicyId;$name=AsText $deploymentRecord.Policy
 if($key -and $name -and -not $settingPolicyNames.ContainsKey($key)){$settingPolicyNames[$key]=$name}
 $key=AsText $deploymentRecord.DeviceId;$name=AsText $deploymentRecord.Device
 if($key -and $name -and -not $settingDeviceNames.ContainsKey($key)){$settingDeviceNames[$key]=$name}
}
if($SkipSettingFailures -or $SkipDeploymentReports){$collection['Policy setting failures']='Skipped'}else{
 Say 'Exporting Intune policy per-setting compliance report ...'
 try{
  $rawSettings=@(Get-IntuneReportRows -ReportName 'DevicePolicySettingsComplianceReportV3')
  foreach($r in $rawSettings){
   $rawState=PropertyText $r @('SettingStatus','Status')
   $mapped=Resolve-PolicyDeploymentStatus $rawState
   $err=PropertyText $r @('ErrorCode')
   # Only explicit failures, conflicts, or nonzero error codes constitute evidence.
   $isError=Test-ReportedFailure $mapped
   if(-not $isError -and $err -and $err -notmatch '^(0|0x0+)$'){$isError=$true}
   if(-not $isError){continue}
   $settingDeviceId=PropertyText $r @('DeviceId','IntuneDeviceId','ManagedDeviceId','AzureADDeviceId')
   $settingPolicyId=PropertyText $r @('PolicyId','ConfigurationPolicyId')
   $settingDeviceName=PropertyText $r @('DeviceName','ManagedDeviceName')
   $settingPolicyName=PropertyText $r @('PolicyName','DisplayName')
   if(-not $settingDeviceName -and $settingDeviceId -and $settingDeviceNames.ContainsKey($settingDeviceId)){$settingDeviceName=$settingDeviceNames[$settingDeviceId]}
   if(-not $settingPolicyName -and $settingPolicyId -and $settingPolicyNames.ContainsKey($settingPolicyId)){$settingPolicyName=$settingPolicyNames[$settingPolicyId]}
   if(-not $settingDeviceName){$settingDeviceName='Unknown device'}
   if(-not $settingPolicyName){$settingPolicyName='Unknown policy'}
   $settingFailureRows.Add([pscustomobject]@{
    Device=$settingDeviceName;DeviceId=$settingDeviceId;Policy=$settingPolicyName;PolicyId=$settingPolicyId
    Setting=PropertyText $r @('SettingName','SettingNm','SettingId')
    SettingId=PropertyText $r @('SettingId');Status=$mapped;RawStatus=$rawState
    ErrorCode=$err;ErrorType=PropertyText $r @('ErrorType');StateDetails=PropertyText $r @('StateDetails')
    SettingValue=PropertyText $r @('SettingValue')
    Recommendation='Inspect this setting in the assigned Intune policy and investigate the reported error/conflict.'
   })
  }
  $collection['Policy setting failures']="Complete ($($rawSettings.Count) setting records, $($settingFailureRows.Count) explicit failures)"
  if($settingFailureRows.Count -gt 0){Add-Finding 'High' 'Configuration policies' 'Policy settings report errors or conflicts' $settingFailureRows.Count 'Policy-Setting-Failures.csv' 'Review the setting-level error code and state details; correlate PolicyId and DeviceId with assigned policies.'}
 }catch{
  $collection['Policy setting failures']='Not assessed (report unavailable)'
  $warnings.Add("Policy setting report unavailable: $($_.Exception.Message)")
 }
}

# Defender status is not inferred from assigned policies. Try an optional Graph beta
# relationship expansion; if not populated do not generate security findings.
if($SkipDefenderHealth){$collection['Defender device health']='Skipped'}else{
 Say 'Attempting Defender health through managed-device protection state ...'
 try{
  $protectionDevices=@(Read-GraphPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem&$expand=windowsProtectionState' -Label 'Defender managed-device health')
  foreach($pd in $protectionDevices){
   $state=$pd.windowsProtectionState
   if($null -eq $state){continue}
   $defenderRows.Add([pscustomobject]@{
    Device=AsText $pd.deviceName;DeviceId=AsText $pd.id
    RealTimeProtection=if($null -eq $state.realTimeProtectionEnabled){'Unknown'}else{AsText $state.realTimeProtectionEnabled}
    MalwareProtection=if($null -eq $state.malwareProtectionEnabled){'Unknown'}else{AsText $state.malwareProtectionEnabled}
    TamperProtection=if($null -eq $state.tamperProtectionEnabled){'Unknown'}else{AsText $state.tamperProtectionEnabled}
    SignatureOverdue=if($null -eq $state.signatureUpdateOverdue){'Unknown'}else{AsText $state.signatureUpdateOverdue}
    ProductStatus=AsText $state.productStatus;LastReported=AsText $state.lastReportedDateTime
    Evidence='Graph windowsProtectionState'
   })
  }
  $collection['Defender device health']=if($defenderRows.Count -gt 0){"Complete ($($defenderRows.Count) devices reporting protection state)"}else{'Not assessed (no populated protection states)'}
  $badDefender=@($defenderRows | Where-Object {$_.RealTimeProtection -eq 'False' -or $_.MalwareProtection -eq 'False' -or $_.SignatureOverdue -eq 'True'})
  if($badDefender.Count -gt 0){Add-Finding 'High' 'Microsoft Defender' 'Devices report disabled protection or overdue signatures' $badDefender.Count 'Defender-Device-Health.csv' 'Check security health in Defender portal and resolve real-time protection, antimalware or signature-update issues.'}
 }catch{
  $collection['Defender device health']='Not assessed (Graph relationship unavailable)'
  $warnings.Add("Defender device health unavailable: $($_.Exception.Message)")
 }
}

# --- 5.5 Endpoint Security inventory and failure triage ---
# The inventory is configuration evidence, not proof of endpoint enforcement.
function Get-SecurityFamily([string]$Name,[string]$Type,[string]$Description) {
 $n=($Name+' '+$Type+' '+$Description).ToLowerInvariant()
 if($n -match 'attack.surface.reduction|\basr\b|asr rule'){return 'Attack Surface Reduction'}
 if($n -match '\blaps\b|local.administrator.password'){return 'Windows LAPS'}
 if($n -match 'bitlocker|disk.encryption|filevault|encrypt'){return 'Disk encryption'}
 if($n -match 'firewall'){return 'Firewall'}
 if($n -match 'defender|antivirus|antimalware|endpoint.detection|\bedr\b'){return 'Defender / EDR'}
 if($n -match 'security.baseline|baseline'){return 'Security baseline'}
 return ''
}
$endpointSecurity=[System.Collections.Generic.List[object]]::new()
function Get-TemplateFamilyLabel([string]$TemplateFamily,[string]$Name) {
 switch -Regex ($TemplateFamily) {
  '^endpointSecurityAntivirus$' {return 'Defender / EDR'}
  '^endpointSecurityEndpointDetectionAndResponse$' {return 'Defender / EDR'}
  '^endpointSecurityAttackSurfaceReduction$' {return 'Attack Surface Reduction'}
  '^endpointSecurityDiskEncryption$' {return 'Disk encryption'}
  '^endpointSecurityFirewall$' {return 'Firewall'}
  '^endpointSecurityAccountProtection$' {if($Name -match '(?i)\blaps\b|local.administrator.password'){return 'Windows LAPS'};return 'Account protection'}
  '^endpointSecurityApplicationControl$' {return 'Application control'}
  '^endpointSecurityEndpointPrivilegeManagement$' {return 'Endpoint Privilege Management'}
  '(?i)baseline' {return 'Security baseline'}
 }
 return ''
}
foreach($p in @($policyInventory)) {
 # Authoritative: Settings Catalog templateReference.templateFamily; fallback: name heuristics.
 $family=Get-TemplateFamilyLabel (AsText $p.TemplateFamily) (AsText $p.Name)
 if(-not $family){$family=Get-SecurityFamily (AsText $p.Name) (AsText $p.Type) (AsText $p.Description)}
 if(-not $family){continue}
 $endpointSecurity.Add([pscustomobject]@{
  Family=$family;Policy=$p.Name;Source=$p.Kind;PolicyId=$p.Id
  Assignments=$p.Assignments;AssignmentCoverage=$p.AssignmentCoverage
  LastModified=$p.Modified;DeploymentFailures=0;ProtectionState='Not assessed (configuration only)'
 })
}
# Intune Endpoint Security intents are a separate policy family in some tenants.
$securityIntents=@(Get-OptionalCollection -Name 'Endpoint Security intents' -Uri 'https://graph.microsoft.com/beta/deviceManagement/intents')
if($collection['Endpoint Security intents'] -eq 'Complete') {
 $intentList=@($securityIntents | Where-Object {AsText $_.id})
 $intentBatch=Invoke-GraphBatchGet -Urls @($intentList | ForEach-Object {"/deviceManagement/intents/$($_.id)/assignments"}) -Version 'beta' -Label 'Endpoint Security assignments'
 $intentAssign=@{}
 for($k=0;$k -lt $intentList.Count;$k++){$intentAssign[[string]$intentList[$k].id]=$intentBatch[$k]}
 foreach($intent in $intentList){
  $id=AsText $intent.id; if(-not $id){continue}
  $name=AsText $intent.displayName
  $family=Get-SecurityFamily $name (AsText $intent.'@odata.type') (AsText $intent.description)
  if(-not $family){$family='Other Endpoint Security'}
  $count=0;$coverage='Unavailable'
  try{$list=@(Get-BatchCollection -Result $intentAssign[$id] -Label 'Endpoint Security assignments');$count=$list.Count;$coverage='Complete';Register-AssignmentTargets -ObjectName (AsText $intent.displayName) -ObjectId $id -ObjectKind 'Endpoint Security intent' -Assignments $list}
  catch{$warnings.Add("Endpoint Security intent assignments unavailable for $name : $($_.Exception.Message)")}
  $endpointSecurity.Add([pscustomobject]@{Family=$family;Policy=$name;Source='Endpoint Security intent';PolicyId=$id;Assignments=$count;AssignmentCoverage=$coverage;LastModified=(AsText $intent.lastModifiedDateTime);DeploymentFailures=0;ProtectionState='Not assessed (configuration only)'})
 }
}
# Match deployment outcomes by policy ID where available; fall back to exact name.
$securityFailures=[System.Collections.Generic.List[object]]::new()
# Index deployment records once (O(n)) instead of scanning all rows for every policy.
$deployById=@{}; $deployByNameNoId=@{}
foreach($rec in $policyDeployment){
 if($rec.PolicyId){$k=$rec.PolicyId.ToLowerInvariant();if(-not $deployById.ContainsKey($k)){$deployById[$k]=[System.Collections.Generic.List[object]]::new()};$deployById[$k].Add($rec)}
 if($rec.Policy){$k=$rec.Policy.ToLowerInvariant();if(-not $deployByNameNoId.ContainsKey($k)){$deployByNameNoId[$k]=[System.Collections.Generic.List[object]]::new()};$deployByNameNoId[$k].Add($rec)}
}
foreach($sec in $endpointSecurity){
 $deploymentMatches=[System.Collections.Generic.List[object]]::new()
 if($sec.PolicyId -and $deployById.ContainsKey($sec.PolicyId.ToLowerInvariant())){$deploymentMatches.AddRange($deployById[$sec.PolicyId.ToLowerInvariant()])}
 # Name fallback only for records where one side has no ID (same rule as before).
 if($sec.Policy -and $deployByNameNoId.ContainsKey($sec.Policy.ToLowerInvariant())){
  foreach($rec in $deployByNameNoId[$sec.Policy.ToLowerInvariant()]){if(-not $rec.PolicyId -or -not $sec.PolicyId){$deploymentMatches.Add($rec)}}
 }
 $failed=@($deploymentMatches | Where-Object {Test-ReportedFailure $_.Status})
 $sec.DeploymentFailures=$failed.Count
 foreach($f in $failed){$securityFailures.Add([pscustomobject]@{Family=$sec.Family;Policy=$sec.Policy;Device=$f.Device;DeviceId=$f.DeviceId;Status=$f.Status;RawStatus=$f.RawStatus;Error=$f.Error;LastReported=$f.LastReported})}
}
# Group explicit failures by policy/status/error for a practical remediation queue.
$policyFailureAnalysis=[System.Collections.Generic.List[object]]::new()
$failedForTriage=@($policyDeployment | Where-Object {Test-ReportedFailure $_.Status})
foreach($group in @($failedForTriage | Group-Object -Property PolicyId,Policy,Status,Error)) {
 $first=$group.Group[0]
 $unique=@($group.Group | Where-Object {$_.DeviceId -or $_.Device} | ForEach-Object {if($_.DeviceId){$_.DeviceId}else{$_.Device}} | Sort-Object -Unique).Count
 $guidance=switch ($first.Status){
  'Conflict' {'Inspect per-setting policy results and overlapping assignments; resolve incompatible settings.'}
  'Error' {'Review the reported error code, assignment eligibility, and device management event logs.'}
  'Noncompliant' {'Inspect evaluated settings on the affected devices; confirm policy applicability.'}
  default {'Review device-level policy deployment evidence.'}
 }
 $policyFailureAnalysis.Add([pscustomobject]@{
  Policy=$first.Policy;PolicyId=$first.PolicyId;Status=$first.Status;Error=$first.Error
  ResultRecords=$group.Count;DistinctDevices=$unique;ExampleDevice=$first.Device
  Recommendation=$guidance;Source=$first.Source
 })
}
if($securityFailures.Count -gt 0){Add-Finding 'High' 'Endpoint Security' 'Endpoint Security policies have reported deployment failures' $securityFailures.Count 'Endpoint-Security-Deployment-Failures.csv (result records, not distinct devices)' 'Review reported policy states, error codes and conflicting assignments; verify protection state on endpoints.'}
$unassignedSecurity=@($endpointSecurity | Where-Object {$_.AssignmentCoverage -eq 'Complete' -and $_.Assignments -eq 0})
if($unassignedSecurity.Count -gt 0){Add-Finding 'Medium' 'Endpoint Security' 'Endpoint Security policies have no assignments' $unassignedSecurity.Count 'Endpoint-Security-Policies.csv' 'Confirm whether these policies are intentionally staged or no longer needed. An unassigned policy is not proof of an unprotected device.'}
$collection['Endpoint Security policy inventory']="Discovered $($endpointSecurity.Count) policy records; configuration only"

$policyDeploymentFailed=@($policyDeployment|Where-Object {Test-ReportedFailure $_.Status})
# The dedicated failure report is an explicit error source, even if it has no Status column.
$featureFailureRows=@($featureUpdateFailures | Where-Object {$_.Device -or $_.DeviceId -or $_.Error})
$featureStateFailures=@($featureUpdateStates|Where-Object {Test-ReportedFailure $_.Status})
if($policyDeploymentFailed.Count -gt 0){
 Add-Finding 'High' 'Policy deployment' 'Configuration policies report device-level failures or conflicts' $policyDeploymentFailed.Count 'Policy-Deployment-Failures.csv (policy/device records, not distinct endpoints)' 'Review policy error or conflict on the affected device, then re-evaluate policy assignment and overlapping settings.'
}
if($featureFailureRows.Count -gt 0){
 Add-Finding 'High' 'Windows Update' 'Feature update failure report contains affected records' $featureFailureRows.Count 'Feature-Update-Failures.csv; records may represent repeat failures' 'Review reported Windows Update errors and validate WUfB deployment prerequisites and assignments.'
}elseif($featureStateFailures.Count -gt 0){
 Add-Finding 'High' 'Windows Update' 'Feature update device states explicitly report failures' $featureStateFailures.Count 'Feature-Update-Device-States.csv; only explicit failure states counted' 'Inspect device-level feature update status and troubleshoot reported errors.'
}

$settingConflictCount=@($settingFailureRows | Where-Object {$_.Status -eq 'Conflict'}).Count
$collection['Policy conflicts']=if(([string]$collection['Policy setting failures']) -like 'Complete*'){"Assessed from setting-level report ($settingConflictCount conflict records)"}else{'Not assessed (setting-level report unavailable)'}
# =====================================================================================
# SECTION 6 - Core findings (evidence-based; unavailable data never creates a finding)
# =====================================================================================
# Findings are evidence-based; unavailable collections NEVER create negative findings.
$inactiveAffected=@($devices | Where-Object {$_.Inactive}).Count
if($inactiveAffected -gt 0){Add-Finding 'High' 'Device hygiene' 'Devices have not checked in within the defined inactivity threshold' $inactiveAffected "LastSyncDateTime compared against $InactiveDays days; see Inactive-Devices.csv" 'Investigate device ownership and last contact; retire stale records after validation.'}
$unencryptedAffected=@($devices | Where-Object {$_.Encrypted -eq 'Not encrypted'}).Count
if($unencryptedAffected -gt 0){Add-Finding 'High' 'Encryption' 'Windows and other managed devices explicitly report encryption disabled' $unencryptedAffected 'Intune managedDevice.isEncrypted = false; see Unencrypted-Devices.csv' 'Validate BitLocker/FileVault deployment and encryption policy assignments.'}
if($noncompliantDevices.Count -gt 0){Add-Finding 'High' 'Compliance' 'Devices currently report noncompliant' $noncompliantDevices.Count 'Intune managedDevice.complianceState = noncompliant; see Noncompliant-Devices.csv' 'Prioritize failed compliance controls; collect settings detail without -SkipComplianceDetails for root cause.'}
$failedApps=@($appStatuses).Count
if($failedApps -gt 0){Add-Finding 'Medium' 'Applications' 'Application install failures were returned by Intune' $failedApps 'App-Install-Failures.csv; counts are installation records, not unique devices' 'Review application detection rules, dependencies, and installation error codes.'}
if($collection['Directory users'] -in @('Complete','Partial')) {
 $disabledAffected=@($devices|Where-Object {$_.PrimaryAccount -eq 'Disabled'}).Count
 if($disabledAffected -gt 0){Add-Finding 'Medium' 'Identity' 'Managed devices reference disabled primary users' $disabledAffected 'Directory accountEnabled = false; Disabled-Primary-Users.csv' 'Confirm reassignment or device retirement.'}
}
if($collection['Autopilot devices'] -eq 'Complete') {
 $missingAuto=@($devices|Where-Object {$_.Autopilot -eq 'No matching record'}).Count
 if($missingAuto -gt 0){Add-Finding 'Informational' 'Autopilot' 'Windows devices have no matching Autopilot identity in collected records' $missingAuto 'Join by managed-device ID or serial; Autopilot-No-Match.csv' 'Validate whether these devices are intended to use Autopilot before taking action.'}
}
$allPolicies=@($policyInventory)+@($updateInventory)
$unassigned=@($allPolicies|Where-Object {$_.AssignmentCoverage -eq 'Complete' -and $_.Assignments -eq 0})
if($unassigned.Count -gt 0){Add-Finding 'Medium' 'Policy configuration' 'Policies with no reported assignments' $unassigned.Count 'Graph assignments relationship returned zero entries; Policy-Inventory.csv / Windows-Update-Policies.csv' 'Review whether these are intentional templates, retired policies, or coverage gaps.'}
$pausedRings=@($updateInventory|Where-Object {$_.Kind -eq 'Windows Update' -and ($_.QualityPaused -eq 'True' -or $_.FeaturePaused -eq 'True')})
if($pausedRings.Count -gt 0){Add-Finding 'Medium' 'Windows Update' 'Windows Update rings have feature or quality updates paused' $pausedRings.Count 'windowsUpdateForBusinessConfiguration pause values; Windows-Update-Policies.csv' 'Confirm pause is approved, time-bound, and monitored.'}
# OS build distribution is inventory evidence, not proof of patch compliance or assigned feature targets.
$windowsBuilds=[System.Collections.Generic.List[object]]::new()
foreach($g in @($devices|Where-Object {$_.OS -match '^Windows'}|Group-Object OSVersion)) {
 $windowsBuilds.Add([pscustomobject]@{OSVersion=$g.Name; Devices=$g.Count})
}
Export-Data 'Policy-Failure-Analysis.csv' @($policyFailureAnalysis) @('Policy','PolicyId','Status','Error','ResultRecords','DistinctDevices','ExampleDevice','Recommendation','Source')
Export-Data 'Endpoint-Security-Policies.csv' @($endpointSecurity) @('Family','Policy','Source','PolicyId','Assignments','AssignmentCoverage','LastModified','DeploymentFailures','ProtectionState')
Export-Data 'Endpoint-Security-Deployment-Failures.csv' @($securityFailures) @('Family','Policy','Device','DeviceId','Status','RawStatus','Error','LastReported')
Export-Data 'Policy-Inventory.csv' @($policyInventory) @('Name','Kind','Type','Id','Assignments','AssignmentCoverage','Modified','Created','Description')
Export-Data 'Windows-Update-Policies.csv' @($updateInventory) @('Name','Type','Id','Assignments','AssignmentCoverage','FeatureTarget','QualityPaused','FeaturePaused','QualityDeferralDays','FeatureDeferralDays')
Export-Data 'Windows-Build-Distribution.csv' @($windowsBuilds) @('OSVersion','Devices')
Export-Data 'Policy-Deployment-Status.csv' @($policyDeployment) @('Device','DeviceId','Policy','PolicyId','Status','RawStatus','Error','LastReported','Source')
Export-Data 'Policy-Deployment-Failures.csv' @($policyDeploymentFailed) @('Device','DeviceId','Policy','PolicyId','Status','RawStatus','Error','LastReported','Source')
Export-Data 'Feature-Update-Device-States.csv' @($featureUpdateStates) @('Device','DeviceId','Policy','PolicyId','Status','RawStatus','Error','LastReported','Source')
Export-Data 'Feature-Update-Failures.csv' @($featureFailureRows) @('Device','DeviceId','Policy','PolicyId','Status','RawStatus','Error','LastReported','Source')
Export-Data 'BitLocker-Escrow-Audit.csv' @($escrowRows) @('Device','DeviceId','EntraDeviceId','Encryption','EscrowStatus','RecoveryKeyRecords','Note')
Export-Data 'Policy-Setting-Failures.csv' @($settingFailureRows) @('Device','DeviceId','Policy','PolicyId','Setting','SettingId','Status','RawStatus','ErrorCode','ErrorType','StateDetails','SettingValue','Recommendation')
Export-Data 'Defender-Device-Health.csv' @($defenderRows) @('Device','DeviceId','RealTimeProtection','MalwareProtection','TamperProtection','SignatureOverdue','ProductStatus','LastReported','Evidence')
Export-Data 'OpenIntuneBaseline-Comparison.csv' @($oibRows) @('OS','Status','BaselinePolicy','SettingName','SettingNameSource','SettingId','SettingCategory','SettingDescription','SettingHelpText','BaselineDisplayValue','TenantDisplayValue','BaselineValue','TenantValue','TenantPolicy','TenantPolicyId','Evidence','BaselineFile','Commit')
Export-Data 'Tenant-Settings-Catalog-GUI.csv' @($oibTenantGuiRows) @('OS','Policy','SettingName','SettingCategory','SettingDescription','ConfiguredValue','SettingId','RawValue','PolicyId')
# Export the Graph beta setting catalog mapping for audit and troubleshooting.
$oibDefinitionExport=[System.Collections.Generic.List[object]]::new()
if($null -ne $script:OibSettingDefinitionCache){
 foreach($definitionKey in @($script:OibSettingDefinitionCache.Keys | Sort-Object)){
  $name=[string]$script:OibSettingDefinitionCache[$definitionKey]
  $detail=Get-OIBDefinitionDetails -Id $definitionKey -Metadata $script:OibSettingMetadata -Categories $script:OibCategoryCache
  $choiceLabels=[System.Collections.Generic.List[string]]::new()
  if($script:OibSettingOptions.ContainsKey($definitionKey)){
   foreach($choice in @($script:OibSettingOptions[$definitionKey])){
    $choiceId=AsText $choice.itemId
    $choiceName=AsText $choice.displayName
    if($choiceId){$choiceLabels.Add(('{0} = {1}' -f $choiceId,$choiceName))}
   }
  }
  $oibDefinitionExport.Add([pscustomobject]@{SettingId=$definitionKey;SettingName=$name;Category=$detail.Category;Description=$detail.Description;HelpText=$detail.HelpText;Choices=($choiceLabels -join ' | ');Source='Microsoft Graph beta'})
 }
}
Export-Data 'Intune-GraphBeta-Settings-Mapping.csv' @($oibDefinitionExport) @('SettingId','SettingName','Category','Description','HelpText','Choices','Source')

# =====================================================================================
# SECTION 6b - Extended assessment: tenant governance, integrations, MAM, Conditional Access,
# scripts, assignment hygiene, Autopilot, LAPS/Defender coverage, fleet state.
# Every collection is read-only, optional and fails independently (status in $collection).
# =====================================================================================
$script:FindingFr=@{}
function Add-FindingFr {
 # Adds a finding with its French title/recommendation (used by the FR executive summary).
 param([string]$Severity,[string]$Area,[string]$Title,[int]$Affected,[string]$Evidence,[string]$Recommendation,[string]$TitleFr,[string]$RecommendationFr,[string]$Coverage='Verified')
 Add-Finding -Severity $Severity -Area $Area -Title $Title -Affected $Affected -Evidence $Evidence -Recommendation $Recommendation -Coverage $Coverage
 if($TitleFr){$script:FindingFr[$Title]=[pscustomobject]@{Title=$TitleFr;Recommendation=$RecommendationFr}}
}
function Get-DaysUntil($Value){ $d=SafeDate $Value; if($null -eq $d -or $d.Year -lt 2000){return $null}; return [int][Math]::Floor(($d-$now).TotalDays) }
function Add-TargetsFromList([object[]]$Items,[string]$Kind){
 foreach($i in @($Items)){ if($i.PSObject.Properties['assignments']){Register-AssignmentTargets -ObjectName (AsText $(if($i.displayName){$i.displayName}else{$i.name})) -ObjectId (AsText $i.id) -ObjectKind $Kind -Assignments @($i.assignments)} }
}
# Returns $null when assignments were not returned (unknown is never treated as unassigned).
function Get-AssignmentCount($Item){ if($Item.PSObject.Properties['assignments']){return @($Item.assignments | Where-Object {$null -ne $_}).Count}; return $null }
$beta='https://graph.microsoft.com/beta'
$noPolicyDevices=@()

# ---------- P1. Connector and token expiration ----------
$connectorRows=[System.Collections.Generic.List[object]]::new()
function Add-ConnectorRow([string]$Connector,[string]$Name,[string]$State,$Expiration,$LastSync){
 $days=Get-DaysUntil $Expiration
 $health=if($null -eq $days){'No expiration reported'}elseif($days -lt 0){'Expired'}elseif($days -le 30){'Expires within 30 days'}elseif($days -le 60){'Expires within 60 days'}else{'Healthy'}
 $connectorRows.Add([pscustomobject]@{Connector=$Connector;Name=$Name;State=$State;Expiration=if(SafeDate $Expiration){ToIso (SafeDate $Expiration)}else{''};DaysRemaining=$days;LastSync=if(SafeDate $LastSync){ToIso (SafeDate $LastSync)}else{''};Health=$health})
}
if($SkipGovernance){$collection['Connectors and tokens']='Skipped'}else{
 Say 'Collecting connector and token expiration (APNs, ADE, VPP, Managed Google Play, MTD)...'
 $connectorErrors=0
 try{
  $apns=Invoke-GraphJson -Uri "$base/deviceManagement/applePushNotificationCertificate" -Label 'APNs certificate'
  if($apns -and (AsText $apns.expirationDateTime)){Add-ConnectorRow 'Apple MDM push certificate (APNs)' (AsText $apns.appleIdentifier) 'Configured' $apns.expirationDateTime $apns.lastModifiedDateTime}
 }catch{ if((Get-HttpStatus $_) -ne 404){$connectorErrors++;$warnings.Add("APNs certificate unavailable: $($_.Exception.Message)")} }
 try{ foreach($t in @(Read-GraphPages -Uri "$beta/deviceManagement/depOnboardingSettings" -Label 'ADE tokens')){Add-ConnectorRow 'Apple Automated Device Enrollment (ADE) token' (AsText $t.tokenName) (AsText $t.lastSyncErrorCode) $t.tokenExpirationDateTime $t.lastSuccessfulSyncDateTime} }catch{$connectorErrors++;$warnings.Add("ADE tokens unavailable: $($_.Exception.Message)")}
 try{ foreach($t in @(Read-GraphPages -Uri "$base/deviceAppManagement/vppTokens" -Label 'VPP tokens')){Add-ConnectorRow 'Apple VPP token' ((AsText $t.organizationName)+' '+(AsText $t.appleId)).Trim() (AsText $t.state) $t.expirationDateTime $t.lastSyncDateTime} }catch{$connectorErrors++;$warnings.Add("VPP tokens unavailable: $($_.Exception.Message)")}
 try{
  $mgp=Invoke-GraphJson -Uri "$beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings" -Label 'Managed Google Play'
  if($mgp -and (AsText $mgp.bindStatus) -and (AsText $mgp.bindStatus) -ne 'notBound'){Add-ConnectorRow 'Managed Google Play' (AsText $mgp.ownerUserPrincipalName) ('{0} / last app sync: {1}' -f (AsText $mgp.bindStatus),(AsText $mgp.lastAppSyncStatus)) $null $mgp.lastAppSyncDateTime}
 }catch{$connectorErrors++;$warnings.Add("Managed Google Play unavailable: $($_.Exception.Message)")}
 $mtdConnectors=@()
 try{
  $mtdConnectors=@(Read-GraphPages -Uri "$base/deviceManagement/mobileThreatDefenseConnectors" -Label 'Mobile Threat Defense connectors')
  foreach($c in $mtdConnectors){
   $partner=if((AsText $c.id) -eq 'fc780465-2017-40d4-a0c5-307022471b92'){'Microsoft Defender for Endpoint'}else{'Partner '+(AsText $c.id)}
   $hb=SafeDate $c.lastHeartbeatDateTime
   $connectorRows.Add([pscustomobject]@{Connector='Mobile Threat Defense connector';Name=$partner;State=AsText $c.partnerState;Expiration='';DaysRemaining=$null;LastSync=if($hb){ToIso $hb}else{''};Health=if((AsText $c.partnerState) -ne 'enabled'){'Not enabled'}elseif($hb -and ($now-$hb).TotalDays -gt 7){'No heartbeat for 7+ days'}else{'Healthy'}})
  }
 }catch{$connectorErrors++;$warnings.Add("MTD connectors unavailable: $($_.Exception.Message)")}
 $collection['Connectors and tokens']=if($connectorErrors -eq 0){"Complete ($($connectorRows.Count) connectors)"}else{"Partial ($connectorErrors sources unavailable)"}
 $expired=@($connectorRows|Where-Object Health -eq 'Expired')
 $soon30=@($connectorRows|Where-Object Health -eq 'Expires within 30 days')
 $soon60=@($connectorRows|Where-Object Health -eq 'Expires within 60 days')
 if($expired.Count){Add-FindingFr 'High' 'Connectors' 'Intune connector certificate or token expired' $expired.Count (($expired|ForEach-Object Connector) -join '; ') 'Renew immediately. An expired APNs certificate must be renewed with the SAME Apple ID or every Apple device must re-enroll.' 'Certificat ou jeton de connecteur Intune expiré' 'Renouveler immédiatement. Un certificat APNs expiré doit être renouvelé avec le MÊME Apple ID, sinon tous les appareils Apple doivent être réinscrits.'}
 if($soon30.Count){Add-FindingFr 'High' 'Connectors' 'Intune connector certificate or token expires within 30 days' $soon30.Count (($soon30|ForEach-Object {'{0} ({1} d)' -f $_.Connector,$_.DaysRemaining}) -join '; ') 'Plan renewal now and document the owning Apple ID / account.' 'Certificat ou jeton de connecteur Intune expirant dans moins de 30 jours' 'Planifier le renouvellement maintenant et documenter le compte Apple ID propriétaire.'}
 if($soon60.Count){Add-FindingFr 'Medium' 'Connectors' 'Intune connector certificate or token expires within 60 days' $soon60.Count (($soon60|ForEach-Object {'{0} ({1} d)' -f $_.Connector,$_.DaysRemaining}) -join '; ') 'Schedule renewal and add a calendar reminder.' 'Certificat ou jeton de connecteur Intune expirant dans moins de 60 jours' 'Planifier le renouvellement et ajouter un rappel.'}
 $badMtd=@($connectorRows|Where-Object {$_.Connector -eq 'Mobile Threat Defense connector' -and $_.Health -ne 'Healthy'})
 if($badMtd.Count){Add-FindingFr 'Medium' 'Connectors' 'Mobile Threat Defense connector not enabled or without recent heartbeat' $badMtd.Count (($badMtd|ForEach-Object {'{0}: {1}' -f $_.Name,$_.Health}) -join '; ') 'Check the Defender for Endpoint / partner connector in Intune and the connection on the partner side.' 'Connecteur Mobile Threat Defense inactif ou sans heartbeat récent' 'Vérifier le connecteur Defender for Endpoint / partenaire dans Intune et la connexion côté partenaire.'}
}

# ---------- P1. Compliance tenant settings and devices without a compliance policy ----------
$complianceSettings=$null
$complianceCoverageRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance){$collection['Compliance tenant settings']='Skipped'}else{
 try{
  $dm=Invoke-GraphJson -Uri "$beta/deviceManagement?`$select=settings" -Label 'Device management settings'
  $complianceSettings=$dm.settings
  $collection['Compliance tenant settings']='Complete'
  if($null -ne $complianceSettings -and (AsText $complianceSettings.secureByDefault) -eq 'False'){
   Add-FindingFr 'High' 'Compliance' 'Devices with no compliance policy assigned are marked Compliant' 1 'deviceManagement/settings.secureByDefault = false' 'Set "Mark devices with no compliance policy assigned as" to Not compliant (Endpoint security > Device compliance > Compliance settings).' 'Les appareils sans stratégie de conformité sont considérés conformes' 'Régler « Marquer les appareils sans stratégie de conformité comme » sur Non conforme (Sécurité des points de terminaison > Conformité > Paramètres).'
  }
  $threshold=0;[void][int]::TryParse((AsText $complianceSettings.deviceComplianceCheckinThresholdDays),[ref]$threshold)
  if($threshold -gt 30){Add-FindingFr 'Low' 'Compliance' 'Compliance status validity period is longer than 30 days' $threshold "deviceComplianceCheckinThresholdDays = $threshold" 'Reduce the validity period (14-30 days) so devices that stop checking in become noncompliant.' 'Période de validité de l''état de conformité supérieure à 30 jours' 'Réduire la période (14 à 30 jours) pour que les appareils qui ne se synchronisent plus deviennent non conformes.'}
 }catch{$collection['Compliance tenant settings']='Unavailable';$warnings.Add("Compliance tenant settings unavailable: $($_.Exception.Message)")}
 $compliancePolicies=@(Get-OptionalCollection -Name 'Compliance policies' -Uri "$base/deviceManagement/deviceCompliancePolicies?`$expand=assignments" -FallbackUri "$base/deviceManagement/deviceCompliancePolicies")
 Add-TargetsFromList $compliancePolicies 'Compliance policy'
 foreach($cp in $compliancePolicies){
  $cpType=(AsText $cp.'@odata.type').Replace('#microsoft.graph.','')
  $complianceCoverageRows.Add([pscustomobject]@{Policy=AsText $cp.displayName;Type=$cpType;Assignments=Get-AssignmentCount $cp;Modified=AsText $cp.lastModifiedDateTime})
 }
 $platformsWithPolicy=@($compliancePolicies | Where-Object {(Get-AssignmentCount $_) -ne 0} | ForEach-Object {
  $t=AsText $_.'@odata.type'
  if($t -match '(?i)aosp'){'Android AOSP'}elseif($t -match 'windows'){'Windows'}elseif($t -match 'ios'){'iOS'}elseif($t -match 'macOS'){'macOS'}elseif($t -match 'android'){'Android'}elseif($t -match 'linux'){'Linux'}
 } | Select-Object -Unique)
 $platformsInFleet=@($devices | Where-Object {$_.Platform} | Group-Object Platform | ForEach-Object {[pscustomobject]@{Platform=$_.Name;Devices=$_.Count}})
 if($collection['Compliance policies'] -eq 'Complete'){
  $uncovered=@($platformsInFleet | Where-Object {$_.Platform -in @('Windows','iOS','macOS','Android','Android AOSP') -and $_.Platform -notin $platformsWithPolicy})
  if($uncovered.Count){Add-FindingFr 'High' 'Compliance' 'Managed platforms without any assigned compliance policy' (($uncovered|Measure-Object Devices -Sum).Sum) (($uncovered|ForEach-Object {'{0} ({1} devices)' -f $_.Platform,$_.Devices}) -join '; ') 'Create and assign a compliance policy per managed platform; without it Conditional Access cannot rely on device compliance.' 'Plateformes gérées sans aucune stratégie de conformité assignée' 'Créer et assigner une stratégie de conformité par plateforme gérée ; sans elle, Conditional Access ne peut pas s''appuyer sur la conformité.'}
 }
 $noPolicyDevices=@()
 if(-not $SkipDeploymentReports){
  try{
   $noPolicyDevices=@(Get-IntuneReportRows -ReportName 'DevicesWithoutCompliancePolicy')
   $collection['Devices without compliance policy']="Complete ($($noPolicyDevices.Count) devices)"
   if($noPolicyDevices.Count){Add-FindingFr 'Medium' 'Compliance' 'Devices without any compliance policy' $noPolicyDevices.Count 'Intune report DevicesWithoutCompliancePolicy; Devices-Without-Compliance-Policy.csv' 'Target these devices with a compliance policy (or confirm they are out of scope) and keep the tenant setting on Not compliant.' 'Appareils sans aucune stratégie de conformité' 'Cibler ces appareils avec une stratégie de conformité (ou confirmer qu''ils sont hors périmètre) et garder le paramètre du tenant sur Non conforme.'}
  }catch{$collection['Devices without compliance policy']='Unavailable';$warnings.Add("DevicesWithoutCompliancePolicy report unavailable: $($_.Exception.Message)")}
 }else{$collection['Devices without compliance policy']='Skipped'}
}

# ---------- P1. Conditional Access link with device compliance ----------
$caRows=[System.Collections.Generic.List[object]]::new()
if($SkipConditionalAccess -or $SkipGovernance){$collection['Conditional Access']='Skipped'}else{
 $caPolicies=@(Get-OptionalCollection -Name 'Conditional Access' -Uri "$base/identity/conditionalAccess/policies")
 foreach($p in $caPolicies){
  $controls=@($p.grantControls.builtInControls | ForEach-Object {AsText $_})
  $users=$p.conditions.users; $apps=$p.conditions.applications
  # Values are computed before the hashtable (avoids comma parsing issues inside @{}).
  $caUserCount=@($users.includeUsers).Count; $caGroupCount=@($users.includeGroups).Count; $caRoleCount=@($users.includeRoles).Count
  if(@($users.includeUsers) -contains 'All'){$caUsersText='All users'}else{$caUsersText="$caUserCount users / $caGroupCount groups / $caRoleCount roles"}
  if(@($apps.includeApplications) -contains 'All'){$caAppsText='All cloud apps'}else{$caAppsText=(@($apps.includeApplications) -join ', ')}
  $caRows.Add([pscustomobject]@{
   Policy=AsText $p.displayName;State=AsText $p.state
   RequiresCompliantDevice=($controls -contains 'compliantDevice');RequiresHybridJoin=($controls -contains 'domainJoinedDevice')
   RequiresAppProtection=($controls -contains 'compliantApplication' -or $controls -contains 'approvedApplication')
   RequiresMfa=($controls -contains 'mfa' -or [bool](AsText $p.grantControls.authenticationStrength.id))
   Operator=AsText $p.grantControls.operator;Controls=($controls -join ', ')
   Users=$caUsersText
   ExcludedPrincipals=(@($users.excludeUsers).Count+@($users.excludeGroups).Count)
   Applications=$caAppsText
   Platforms=(@($p.conditions.platforms.includePlatforms) -join ', ')
  })
 }
 if($collection['Conditional Access'] -eq 'Complete'){
  $deviceCa=@($caRows|Where-Object {$_.RequiresCompliantDevice -or $_.RequiresHybridJoin})
  $enforced=@($deviceCa|Where-Object State -eq 'enabled')
  $reportOnly=@($deviceCa|Where-Object State -eq 'enabledForReportingButNotEnforced')
  if($enforced.Count -eq 0){Add-FindingFr 'High' 'Conditional Access' 'No enforced Conditional Access policy requires a compliant or hybrid-joined device' 1 ("$($deviceCa.Count) device-based policies, $($reportOnly.Count) in report-only; Conditional-Access-Device-Controls.csv") 'Without an enforced "Require device to be marked as compliant" policy, Intune compliance has no effect on access. Pilot it in report-only, then enforce.' 'Aucune stratégie Conditional Access active n''exige un appareil conforme ou joint hybride' 'Sans stratégie active « Exiger un appareil conforme », la conformité Intune n''a aucun effet sur l''accès. Piloter en report-only, puis activer.'}
  if($reportOnly.Count){Add-FindingFr 'Medium' 'Conditional Access' 'Device-based Conditional Access policies left in report-only mode' $reportOnly.Count (($reportOnly|ForEach-Object Policy) -join '; ') 'Review the report-only sign-in impact and move to On when the noncompliant population is understood.' 'Stratégies Conditional Access basées sur l''appareil restées en mode report-only' 'Analyser l''impact en report-only puis activer une fois la population non conforme maîtrisée.'}
  $allUserCompliance=@($enforced|Where-Object {$_.Users -eq 'All users' -and $_.Applications -eq 'All cloud apps'})
  if($enforced.Count -gt 0 -and $allUserCompliance.Count -eq 0){Add-FindingFr 'Low' 'Conditional Access' 'Device compliance is enforced only for a subset of users or applications' $enforced.Count (($enforced|ForEach-Object Policy) -join '; ') 'Confirm the scope is intentional; broaden progressively to all users and cloud apps with documented exclusions.' 'La conformité de l''appareil n''est exigée que pour une partie des utilisateurs ou des applications' 'Confirmer que ce périmètre est voulu ; l''élargir progressivement à tous les utilisateurs et applications avec des exclusions documentées.'}
 }
}

# ---------- P1. Enrollment restrictions, ESP, device limits ----------
$enrollmentRows=[System.Collections.Generic.List[object]]::new()
$espRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance){$collection['Enrollment restrictions']='Skipped'}else{
 $enrollConfigs=@(Get-OptionalCollection -Name 'Enrollment restrictions' -Uri "$beta/deviceManagement/deviceEnrollmentConfigurations?`$expand=assignments" -FallbackUri "$beta/deviceManagement/deviceEnrollmentConfigurations")
 Add-TargetsFromList $enrollConfigs 'Enrollment configuration'
 foreach($c in $enrollConfigs){
  $type=(AsText $c.'@odata.type') -replace '^#microsoft\.graph\.',''
  $common=@{Name=AsText $c.displayName;Type=$type;Priority=AsText $c.priority;Assignments=Get-AssignmentCount $c}
  switch -Regex ($type){
   '^deviceEnrollmentPlatformRestrictionsConfiguration$' {
    foreach($pl in @(@('Windows','windowsRestriction'),@('iOS','iosRestriction'),@('macOS','macOSRestriction'),@('Android device admin','androidRestriction'),@('Android Enterprise work profile','androidForWorkRestriction'))){
     $r=$c.($pl[1]); if($null -eq $r){continue}
     $enrollmentRows.Add([pscustomobject]($common+@{Platform=$pl[0];PlatformBlocked=AsText $r.platformBlocked;PersonalBlocked=AsText $r.personalDeviceEnrollmentBlocked;MinOS=AsText $r.osMinimumVersion;Limit=''}))
    }
   }
   '^deviceEnrollmentPlatformRestrictionConfiguration$' {
    $r=$c.platformRestriction
    $enrollmentRows.Add([pscustomobject]($common+@{Platform=AsText $c.platformType;PlatformBlocked=AsText $r.platformBlocked;PersonalBlocked=AsText $r.personalDeviceEnrollmentBlocked;MinOS=AsText $r.osMinimumVersion;Limit=''}))
   }
   '^deviceEnrollmentLimitConfiguration$' {
    $enrollmentRows.Add([pscustomobject]($common+@{Platform='All';PlatformBlocked='';PersonalBlocked='';MinOS='';Limit=AsText $c.limit}))
   }
   '^windows10EnrollmentCompletionPageConfiguration$' {
    $espRows.Add([pscustomobject]@{Name=AsText $c.displayName;Priority=AsText $c.priority;Assignments=Get-AssignmentCount $c;ShowProgress=AsText $c.showInstallationProgress;TimeoutMinutes=AsText $c.installProgressTimeoutInMinutes;BlockUntilAllAppsInstalled=AsText $c.blockDeviceSetupRetryByUser;AllowResetOnFailure=AsText $c.allowDeviceResetOnInstallFailure;AllowUseOnFailure=AsText $c.allowDeviceUseOnInstallFailure;BlockingApps=@($c.selectedMobileAppIds).Count})
   }
  }
 }
 if($collection['Enrollment restrictions'] -eq 'Complete'){
  $personalWin=@($enrollmentRows|Where-Object {$_.Platform -match '^windows' -and $_.PlatformBlocked -ne 'True' -and $_.PersonalBlocked -eq 'False'})
  if($personalWin.Count){Add-FindingFr 'Medium' 'Enrollment' 'Personal Windows devices can enroll in Intune' $personalWin.Count (($personalWin|ForEach-Object Name) -join '; ') 'Block personally owned Windows enrollment unless BYOD is a documented requirement (use Autopilot / corporate identifiers).' 'Les appareils Windows personnels peuvent s''inscrire dans Intune' 'Bloquer l''inscription des appareils Windows personnels sauf si le BYOD est un besoin documenté (Autopilot / identifiants d''entreprise).'}
  $highLimit=@($enrollmentRows|Where-Object {$_.Limit -and [int]$_.Limit -gt 10})
  if($highLimit.Count){Add-FindingFr 'Low' 'Enrollment' 'Device enrollment limit above 10 devices per user' $highLimit.Count (($highLimit|ForEach-Object {'{0}: {1}' -f $_.Name,$_.Limit}) -join '; ') 'Lower the per-user device limit (typically 5) to reduce uncontrolled enrollments.' 'Limite d''inscription supérieure à 10 appareils par utilisateur' 'Réduire la limite par utilisateur (souvent 5) pour limiter les inscriptions non contrôlées.'}
  $longEsp=@($espRows|Where-Object {$_.ShowProgress -eq 'True' -and $_.TimeoutMinutes -and [int]$_.TimeoutMinutes -gt 120})
  if($longEsp.Count){Add-FindingFr 'Low' 'Autopilot' 'Enrollment Status Page timeout longer than 120 minutes' $longEsp.Count (($longEsp|ForEach-Object {'{0}: {1} min' -f $_.Name,$_.TimeoutMinutes}) -join '; ') 'Reduce the ESP timeout and keep only critical blocking apps.' 'Délai de la page d''état d''inscription (ESP) supérieur à 120 minutes' 'Réduire le délai ESP et ne garder que les applications bloquantes essentielles.'}
 }
}

# ---------- P1. Intune RBAC, privileged directory roles, multi-admin approval ----------
$rbacRows=[System.Collections.Generic.List[object]]::new()
$customRoleRows=[System.Collections.Generic.List[object]]::new()
$maaRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance){$collection['Intune RBAC']='Skipped';$collection['Privileged directory roles']='Skipped';$collection['Multi-admin approval']='Skipped'}else{
 # Intune RBAC (v3.60): read role definitions, then the assignments of each role (built-in and custom).
 # The flat /roleAssignments list does not reliably return assignments of built-in roles.
 $roleDefs=@(Get-OptionalCollection -Name 'Intune RBAC' -Uri "$beta/deviceManagement/roleDefinitions")
 if($collection['Intune RBAC'] -eq 'Complete'){
  $defsWithId=@($roleDefs | Where-Object {AsText $_.id})
  $raBatch=Invoke-GraphBatchGet -Urls @($defsWithId | ForEach-Object {"/deviceManagement/roleDefinitions/$($_.id)/roleAssignments"}) -Version 'beta' -Label 'Intune role assignments'
  $assignList=[System.Collections.Generic.List[object]]::new(); $raFail=0
  for($k=0;$k -lt $defsWithId.Count;$k++){
   try{foreach($ra in @(Get-BatchCollection -Result $raBatch[$k] -Label 'Intune role assignments')){$assignList.Add([pscustomobject]@{Assignment=$ra;Definition=$defsWithId[$k]})}}catch{$raFail++}
  }
  $raDetail=Invoke-GraphBatchGet -Urls @($assignList | ForEach-Object {"/deviceManagement/roleAssignments/$($_.Assignment.id)"}) -Version 'beta' -Label 'Intune role assignment details'
  for($k=0;$k -lt $assignList.Count;$k++){
   $ra=if($raDetail[$k] -and $raDetail[$k].Status -eq 200){$raDetail[$k].Body}else{$assignList[$k].Assignment}
   $def=$assignList[$k].Definition
   $raScopes=@($ra.resourceScopes | ForEach-Object {AsText $_})
   $raScopeText=if((AsText $ra.scopeType) -match '(?i)all'){AsText $ra.scopeType}elseif($raScopes.Count){"$($raScopes.Count) scope group(s)"}else{'All devices / users'}
   $raMembers="$(@($ra.members).Count) member group(s)"
   $raTags=(@($ra.roleScopeTagIds) -join ', ')
   $rbacRows.Add([pscustomobject]@{Source='Intune RBAC';Role=AsText $def.displayName;BuiltIn=AsText $def.isBuiltIn;Assignment=AsText $ra.displayName;Principal=$raMembers;Scope=$raScopeText;ScopeTags=$raTags;Type='Assignment'})
  }
  foreach($def in @($defsWithId | Where-Object {(AsText $_.isBuiltIn) -ne 'True'})){
   $actions=@($def.rolePermissions | ForEach-Object {@($_.resourceActions)} | ForEach-Object {@($_.allowedResourceActions)} | Where-Object {$_} | ForEach-Object {AsText $_})
   $risky=@($actions | Where-Object {$_ -match '(?i)wipe|retire|_delete|cleanwindowsdevice|factoryreset|devicemanagementscripts|managementscripts|_rbac|roleassignments'})
   $assignedCount=@($assignList | Where-Object {(AsText $_.Definition.id) -eq (AsText $def.id)}).Count
   $riskyText=(@($risky | ForEach-Object {$_ -replace '^Microsoft\.Intune_',''}) -join ', ')
   $customRoleRows.Add([pscustomobject]@{Role=AsText $def.displayName;Permissions=$actions.Count;DestructivePermissions=$risky.Count;Detail=$riskyText;Assignments=$assignedCount})
  }
  $collection['Intune RBAC']=if($raFail -eq 0){"Complete ($($defsWithId.Count) role definitions, $($assignList.Count) assignments)"}else{"Partial ($raFail roles unreadable)"}
  $riskyAssigned=@($customRoleRows | Where-Object {$_.DestructivePermissions -gt 0 -and $_.Assignments -gt 0})
  if($riskyAssigned.Count){Add-FindingFr 'Low' 'Governance' 'Custom Intune roles grant destructive permissions (wipe, retire, delete, scripts)' $riskyAssigned.Count ((@($riskyAssigned | ForEach-Object {"$($_.Role) ($($_.DestructivePermissions))"})) -join '; ') 'Confirm these permissions are needed, limit the role with scope groups and scope tags, and protect the actions with multi-admin approval.' 'Des rôles Intune personnalisés accordent des permissions destructives (effacement, mise hors service, suppression, scripts)' 'Confirmer que ces permissions sont nécessaires, limiter le rôle par des groupes et balises d''étendue et protéger les actions par l''approbation multi-administrateurs.'}
  $script:IntuneRbacAssignmentCount=$assignList.Count
 }
 $privRoles=[ordered]@{'62e90394-69f5-4237-9190-012177145e10'='Global Administrator';'3a2c62db-5318-420d-8d74-23affee5d9d5'='Intune Administrator';'7698a772-787b-4ac8-901f-60d6b08affd2'='Cloud Device Administrator'}
 $privOk=$true; $roleCounts=@{}
 foreach($rid in $privRoles.Keys){
  try{
   $list=@(Read-GraphPages -Uri ("$base/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '{0}'&`$expand=principal" -f $rid) -Label $privRoles[$rid])
   $roleCounts[$privRoles[$rid]]=$list.Count
   foreach($a in $list){$rbacRows.Add([pscustomobject]@{Source='Entra directory role';Role=$privRoles[$rid];BuiltIn='True';Assignment='Active (permanent or activated)';Principal=if(AsText $a.principal.userPrincipalName){AsText $a.principal.userPrincipalName}else{AsText $a.principal.displayName};Scope=AsText $a.directoryScopeId;ScopeTags='';Type=(AsText $a.principal.'@odata.type').Replace('#microsoft.graph.','')})}
  }catch{$privOk=$false;$warnings.Add("$($privRoles[$rid]) assignments unavailable: $($_.Exception.Message)")}
 }
 $collection['Privileged directory roles']=if($privOk){'Complete (active assignments; PIM eligible assignments not counted)'}else{'Partial'}
 if($collection['Intune RBAC'] -like 'Complete*' -and [int]$script:IntuneRbacAssignmentCount -eq 0 -and ([int]$roleCounts['Intune Administrator']+[int]$roleCounts['Global Administrator']) -gt 0){Add-FindingFr 'Low' 'Governance' 'Intune is administered only through Entra directory roles (no scoped Intune RBAC)' ([int]$roleCounts['Intune Administrator']+[int]$roleCounts['Global Administrator']) 'No Intune role assignment; administration relies on Global / Intune Administrator directory roles' 'Create Intune RBAC role assignments (for example Help Desk Operator, Endpoint Security Manager) with scope groups so day-to-day admins do not need tenant-wide directory roles.' 'Intune est administré uniquement par des rôles d''annuaire Entra (aucun RBAC Intune délimité)' 'Créer des attributions de rôles RBAC Intune (par exemple Opérateur du support technique, Gestionnaire de la sécurité des points de terminaison) avec des groupes d''étendue, pour que l''administration courante ne nécessite pas de rôles d''annuaire globaux.'}
 foreach($row in @($rbacRows | Where-Object {$_.Source -ne 'Intune RBAC' -and ([string]$_.Principal) -notmatch '@'})){Register-AnonymizedValue ([string]$row.Principal) 'principal'}
 if($roleCounts.ContainsKey('Global Administrator')){
  $ga=$roleCounts['Global Administrator']
  if($ga -gt 4){Add-FindingFr 'Medium' 'Governance' 'More than four active Global Administrators' $ga 'roleManagement/directory/roleAssignments (Global Administrator); Admin-Roles.csv' 'Keep fewer than five Global Administrators; use Intune Administrator or Intune RBAC roles and PIM for day-to-day administration.' 'Plus de quatre administrateurs globaux actifs' 'Garder moins de cinq administrateurs globaux ; utiliser Intune Administrator ou les rôles RBAC Intune et PIM pour l''administration courante.'}
  elseif($ga -lt 2){Add-FindingFr 'Medium' 'Governance' 'Fewer than two active Global Administrators (no break-glass redundancy visible)' $ga 'Active assignments only; PIM eligible assignments are not counted' 'Maintain at least two emergency access accounts excluded from Conditional Access with phishing-resistant credentials.' 'Moins de deux administrateurs globaux actifs (pas de redondance de comptes d''urgence visible)' 'Maintenir au moins deux comptes d''accès d''urgence exclus de Conditional Access avec des identifiants résistants à l''hameçonnage.'}
 }
 if($roleCounts.ContainsKey('Intune Administrator') -and $roleCounts['Intune Administrator'] -gt 5){Add-FindingFr 'Low' 'Governance' 'Many active Intune Administrator assignments' $roleCounts['Intune Administrator'] 'Active directory role assignments' 'Prefer scoped Intune RBAC roles with scope tags, and PIM just-in-time activation.' 'Nombreuses attributions actives du rôle Intune Administrator' 'Privilégier les rôles RBAC Intune avec balises d''étendue, et l''activation juste-à-temps avec PIM.'}
 $maa=@(Get-OptionalCollection -Name 'Multi-admin approval' -Uri "$beta/deviceManagement/operationApprovalPolicies")
 foreach($m in $maa){$maaRows.Add([pscustomobject]@{Policy=AsText $m.displayName;Type=AsText $m.policyType;Platform=AsText $m.policyPlatform;ApproverGroups=@($m.approverGroupIds).Count;Modified=AsText $m.lastModifiedDateTime})}
 if($collection['Multi-admin approval'] -eq 'Complete'){
  if($maaRows.Count -eq 0){Add-FindingFr 'Medium' 'Governance' 'Multi-admin approval is not configured' 1 'deviceManagement/operationApprovalPolicies returned no policy' 'Protect device wipe/retire/delete and script deployment with multi-admin approval (Tenant administration > Multi admin approval).' 'L''approbation multi-administrateurs n''est pas configurée' 'Protéger l''effacement, la mise hors service et la suppression d''appareils ainsi que le déploiement de scripts avec l''approbation multi-administrateurs.'}
  else{
   $types=@($maaRows.Type)
   $missing=@(@('deviceWipe','script')|Where-Object {$types -notcontains $_ -and -not ($types -match $_)})
   if($missing.Count){Add-FindingFr 'Low' 'Governance' 'Multi-admin approval does not cover device wipe or scripts' $missing.Count ("Missing policy types: "+($missing -join ', ')) 'Extend multi-admin approval to device actions and script deployments.' 'L''approbation multi-administrateurs ne couvre pas l''effacement ou les scripts' 'Étendre l''approbation multi-administrateurs aux actions sur les appareils et aux scripts.'}
  }
 }
}

# ---------- P2. App protection (MAM) ----------
$mamRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance){$collection['App protection policies']='Skipped'}else{
 $mamErrors=0
 foreach($src in @(@('iOS',"$base/deviceAppManagement/iosManagedAppProtections?`$expand=assignments"),@('Android',"$base/deviceAppManagement/androidManagedAppProtections?`$expand=assignments"),@('Windows',"$beta/deviceAppManagement/windowsManagedAppProtections?`$expand=assignments"))){
  try{
   foreach($m in @(Read-GraphPages -Uri $src[1] -Label "App protection $($src[0])")){
    Register-AssignmentTargets -ObjectName (AsText $m.displayName) -ObjectId (AsText $m.id) -ObjectKind 'App protection' -Assignments @($m.assignments)
    $mamRows.Add([pscustomobject]@{Policy=AsText $m.displayName;Platform=$src[0];Assignments=Get-AssignmentCount $m;PinRequired=AsText $m.pinRequired;Clipboard=AsText $m.allowedOutboundClipboardSharingLevel;DataTransfer=AsText $m.allowedOutboundDataTransferDestinations;BackupBlocked=AsText $m.dataBackupBlocked;SaveAsBlocked=AsText $m.saveAsBlocked;MinOS=AsText $m.minimumRequiredOsVersion;OfflineWipe=AsText $m.periodOfflineBeforeWipeIsEnforced;Modified=AsText $m.lastModifiedDateTime})
   }
  }catch{ if($src[0] -ne 'Windows'){$mamErrors++}; $warnings.Add("App protection $($src[0]) unavailable: $($_.Exception.Message)") }
 }
 $collection['App protection policies']=if($mamErrors -eq 0){"Complete ($($mamRows.Count) policies)"}else{'Partial'}
 if($mamErrors -eq 0){
  $mobileDevices=@($devices|Where-Object {$_.Platform -in @('iOS','Android')}).Count
  foreach($pf in @('iOS','Android')){
   if(@($mamRows|Where-Object {$_.Platform -eq $pf -and $_.Assignments -ne 0}).Count -eq 0){Add-FindingFr 'Medium' 'App protection' "No assigned $pf app protection (MAM) policy" 1 "$mobileDevices managed iOS/Android devices; personal devices are not visible to Intune MDM" "Create a $pf app protection policy (PIN, no backup, restricted copy/paste) and require it with Conditional Access for unmanaged devices." "Aucune stratégie de protection d'application (MAM) $pf assignée" "Créer une stratégie de protection d'application $pf (code PIN, pas de sauvegarde, copier-coller restreint) et l'exiger avec Conditional Access pour les appareils non gérés."}
  }
  $noPin=@($mamRows|Where-Object {$_.Platform -ne 'Windows' -and $_.PinRequired -eq 'False'})
  if($noPin.Count){Add-FindingFr 'Medium' 'App protection' 'App protection policies without PIN requirement' $noPin.Count (($noPin|ForEach-Object Policy) -join '; ') 'Require an app PIN (or biometrics) for access to corporate data.' 'Stratégies de protection d''application sans code PIN' 'Exiger un code PIN d''application (ou la biométrie) pour accéder aux données de l''entreprise.'}
  $openClip=@($mamRows|Where-Object {$_.Platform -ne 'Windows' -and $_.Clipboard -eq 'allApps'})
  if($openClip.Count){Add-FindingFr 'Low' 'App protection' 'App protection allows copy/paste to any app' $openClip.Count (($openClip|ForEach-Object Policy) -join '; ') 'Restrict cut/copy/paste to policy-managed apps (paste in allowed).' 'La protection d''application autorise le copier-coller vers toute application' 'Restreindre le copier-coller aux applications gérées par stratégie (coller entrant autorisé).'}
  $backup=@($mamRows|Where-Object {$_.Platform -ne 'Windows' -and $_.BackupBlocked -eq 'False'})
  if($backup.Count){Add-FindingFr 'Low' 'App protection' 'App protection allows backup of corporate data to personal cloud' $backup.Count (($backup|ForEach-Object Policy) -join '; ') 'Block backup of org data to iTunes/iCloud/Android backup services.' 'La protection d''application autorise la sauvegarde des données d''entreprise' 'Bloquer la sauvegarde des données de l''organisation vers iCloud/iTunes/Android.'}
 }
}

# ---------- P2. Scripts and remediations ----------
$scriptRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance){$collection['Scripts and remediations']='Skipped'}else{
 $scriptErrors=0
 foreach($src in @(@('PowerShell script','deviceManagementScripts'),@('Remediation','deviceHealthScripts'),@('macOS shell script','deviceShellScripts'))){
  try{
   $items=@()
   try{$items=@(Read-GraphPages -Uri "$beta/deviceManagement/$($src[1])?`$expand=assignments" -Label $src[0])}catch{$items=@(Read-GraphPages -Uri "$beta/deviceManagement/$($src[1])" -Label $src[0])}
   Add-TargetsFromList $items $src[0]
   $items=@($items|Where-Object {AsText $_.id})
   $sum=Invoke-GraphBatchGet -Urls @($items|ForEach-Object {"/deviceManagement/$($src[1])/$($_.id)/runSummary"}) -Version 'beta' -Label "$($src[0]) run summary"
   for($k=0;$k -lt $items.Count;$k++){
    $s=$items[$k]; $r=if($sum[$k] -and $sum[$k].Status -eq 200){$sum[$k].Body}else{$null}
    $ok=0;$err=0
    if($r){
     if($src[1] -eq 'deviceHealthScripts'){$ok=[int]$r.noIssueDetectedDeviceCount+[int]$r.issueRemediatedDeviceCount;$err=[int]$r.detectionScriptErrorDeviceCount+[int]$r.remediationScriptErrorDeviceCount+[int]$r.issueReoccurredDeviceCount}
     else{$ok=[int]$r.successDeviceCount+[int]$r.successUserCount;$err=[int]$r.errorDeviceCount+[int]$r.errorUserCount}
    }
    $total=$ok+$err
    $scriptRows.Add([pscustomobject]@{Script=AsText $s.displayName;Kind=$src[0];Publisher=AsText $s.publisher;MicrosoftPublished=AsText $s.isGlobalScript;RunAs=AsText $s.runAsAccount;SignatureCheck=AsText $s.enforceSignatureCheck;Assignments=Get-AssignmentCount $s;Success=$ok;Errors=$err;ErrorRate=if($total){[Math]::Round(100*$err/$total,1)}else{$null};SummaryCoverage=if($r){'Complete'}else{'Unavailable'}})
   }
  }catch{ if($src[1] -ne 'deviceShellScripts'){$scriptErrors++}; $warnings.Add("$($src[0]) unavailable: $($_.Exception.Message)") }
 }
 $collection['Scripts and remediations']=if($scriptErrors -eq 0){"Complete ($($scriptRows.Count) scripts)"}else{'Partial'}
 $failing=@($scriptRows|Where-Object {$null -ne $_.ErrorRate -and $_.ErrorRate -ge 10 -and $_.Errors -ge 3})
 if($failing.Count){Add-FindingFr 'Medium' 'Scripts' 'Scripts or remediations with an error rate of 10% or more' $failing.Count (($failing|Select-Object -First 8|ForEach-Object {'{0} ({1}%)' -f $_.Script,$_.ErrorRate}) -join '; ') 'Review script output in the device status, fix detection logic and exit codes, and retire obsolete scripts.' 'Scripts ou remédiations avec un taux d''erreur de 10 % ou plus' 'Analyser le résultat par appareil, corriger la logique de détection et les codes de sortie, et retirer les scripts obsolètes.'}
 $unsigned=@($scriptRows|Where-Object {$_.Kind -ne 'macOS shell script' -and $_.MicrosoftPublished -ne 'True' -and $_.RunAs -eq 'system' -and $_.SignatureCheck -ne 'True'})
 if($unsigned.Count){Add-FindingFr 'Low' 'Scripts' 'Custom scripts run as SYSTEM without signature enforcement' $unsigned.Count (($unsigned|Select-Object -First 8|ForEach-Object Script) -join '; ') 'Sign scripts and enable "Enforce script signature check", and protect script deployment with multi-admin approval.' 'Scripts personnalisés exécutés en SYSTEM sans vérification de signature' 'Signer les scripts, activer la vérification de signature et protéger leur déploiement avec l''approbation multi-administrateurs.'}
}

# ---------- P2. Autopilot deployment profiles ----------
$autopilotProfileRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance -or $SkipAutopilot){$collection['Autopilot profiles']='Skipped'}else{
 $profiles=@(Get-OptionalCollection -Name 'Autopilot profiles' -Uri "$beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments" -FallbackUri "$beta/deviceManagement/windowsAutopilotDeploymentProfiles")
 Add-TargetsFromList $profiles 'Autopilot profile'
 foreach($p in $profiles){
  $oobe=if($p.outOfBoxExperienceSetting){$p.outOfBoxExperienceSetting}else{$p.outOfBoxExperienceSettings}
  $type=(AsText $p.'@odata.type') -replace '^#microsoft\.graph\.',''
  $autopilotProfileRows.Add([pscustomobject]@{Profile=AsText $p.displayName;Join=if($type -match 'activeDirectory'){'Hybrid Entra join'}else{'Entra join'};Mode=if((AsText $oobe.deviceUsageType) -eq 'shared'){'Self-deploying'}else{'User-driven'};UserType=AsText $oobe.userType;PreProvisioning=AsText $p.enableWhiteGlove;ConvertDevices=AsText $p.extractHardwareHash;NameTemplate=AsText $p.deviceNameTemplate;Assignments=Get-AssignmentCount $p;Modified=AsText $p.lastModifiedDateTime})
 }
 if($collection['Autopilot profiles'] -eq 'Complete'){
  $adminProfiles=@($autopilotProfileRows|Where-Object {$_.UserType -eq 'administrator'})
  if($adminProfiles.Count){Add-FindingFr 'Medium' 'Autopilot' 'Autopilot profiles make the user a local administrator' $adminProfiles.Count (($adminProfiles|ForEach-Object Profile) -join '; ') 'Set user account type to Standard and use Windows LAPS / Endpoint Privilege Management for elevation.' 'Les profils Autopilot rendent l''utilisateur administrateur local' 'Régler le type de compte sur Standard et utiliser Windows LAPS / Endpoint Privilege Management pour l''élévation.'}
  $hybrid=@($autopilotProfileRows|Where-Object {$_.Join -eq 'Hybrid Entra join'})
  if($hybrid.Count){Add-FindingFr 'Informational' 'Autopilot' 'Autopilot profiles use hybrid Entra join' $hybrid.Count (($hybrid|ForEach-Object Profile) -join '; ') 'Microsoft recommends Entra join for new Autopilot deployments; plan migration when on-premises dependencies allow.' 'Les profils Autopilot utilisent la jonction Entra hybride' 'Microsoft recommande la jonction Entra pour les nouveaux déploiements ; planifier la migration quand les dépendances locales le permettent.'}
  $apDevices=@($devices|Where-Object {$_.Autopilot -eq 'Registered'}).Count
  if($apDevices -gt 0 -and @($autopilotProfileRows|Where-Object {$_.Assignments -ne 0}).Count -eq 0){Add-FindingFr 'Medium' 'Autopilot' 'Autopilot devices exist but no deployment profile is assigned' $apDevices 'windowsAutopilotDeploymentProfiles assignments' 'Assign a deployment profile to the Autopilot device groups.' 'Des appareils Autopilot existent mais aucun profil de déploiement n''est assigné' 'Assigner un profil de déploiement aux groupes d''appareils Autopilot.'}
 }
}

# ---------- P2. Assignment filters and assignment hygiene ----------
$filterRows=[System.Collections.Generic.List[object]]::new()
$hygieneRows=[System.Collections.Generic.List[object]]::new()
if($SkipGovernance){$collection['Assignment hygiene']='Skipped'}else{
 $filters=@(Get-OptionalCollection -Name 'Assignment filters' -Uri "$beta/deviceManagement/assignmentFilters")
 $targets=@($script:AssignmentTargets)
 $filterUse=@{}; foreach($t in $targets){if($t.FilterId -and $t.FilterId -ne '00000000-0000-0000-0000-000000000000'){$filterUse[$t.FilterId]=1+[int]$filterUse[$t.FilterId]}}
 foreach($f in $filters){$filterRows.Add([pscustomobject]@{Filter=AsText $f.displayName;Platform=AsText $f.platform;Rule=AsText $f.rule;ReferencedBy=[int]$filterUse[(AsText $f.id)];Modified=AsText $f.lastModifiedDateTime})}
 $orphanFilters=@($filterRows|Where-Object ReferencedBy -eq 0)
 if($orphanFilters.Count){Add-FindingFr 'Informational' 'Assignment hygiene' 'Assignment filters not referenced by any collected assignment' $orphanFilters.Count (($orphanFilters|ForEach-Object Filter) -join '; ') 'Remove unused filters (apps and some policy types are not in scope of this check; verify "Associated assignments" in the portal).' 'Filtres d''assignation non utilisés par les assignations collectées' 'Supprimer les filtres inutilisés (les applications et certains types de stratégies ne sont pas couverts ; vérifier les assignations associées dans le portail).' 'Partial coverage'}
 # Broad assignments without filter
 foreach($t in $targets){
  if($t.TargetType -in @('allDevicesAssignmentTarget','allLicensedUsersAssignmentTarget')){
   $hygieneRows.Add([pscustomobject]@{Issue=if($t.TargetType -match 'allDevices'){'Assigned to All devices'}else{'Assigned to All users'};Object=$t.Object;ObjectKind=$t.ObjectKind;Group='';Detail=if($t.FilterId -and $t.FilterId -ne '00000000-0000-0000-0000-000000000000'){"Filter ($($t.FilterType))"}else{'No filter'}})
  }
 }
 # Same group included and excluded on the same object
 foreach($g in @($targets|Where-Object GroupId|Group-Object ObjectId,GroupId)){
  $kinds=@($g.Group.TargetType)
  if(($kinds -match '^exclusionGroup').Count -and ($kinds -notmatch '^exclusionGroup').Count){$hygieneRows.Add([pscustomobject]@{Issue='Group both included and excluded';Object=$g.Group[0].Object;ObjectKind=$g.Group[0].ObjectKind;Group=$g.Group[0].GroupId;Detail='Exclusion wins: the object never applies to this group'})}
 }
 # Deleted or empty groups (batched, capped)
 $groupIds=@($targets|Where-Object GroupId|ForEach-Object {$_.GroupId.ToLowerInvariant()}|Select-Object -Unique)
 $checkIds=@($groupIds|Select-Object -First $MaxGroupsToCheck)
 if($checkIds.Count){
  Say "Validating $($checkIds.Count) assignment groups ..."
  $gInfo=Invoke-GraphBatchGet -Urls @($checkIds|ForEach-Object {"/groups/$_`?`$select=id,displayName,groupTypes,membershipRule"}) -Version 'v1.0' -Label 'Assignment groups'
  $gMembers=Invoke-GraphBatchGet -Urls @($checkIds|ForEach-Object {"/groups/$_/members?`$top=1&`$select=id"}) -Version 'v1.0' -Label 'Assignment group members'
  $groupFail=0; $groupNames=@{}
  $targetsByGroup=@{}; foreach($tg in $targets){if($tg.GroupId){$gk=$tg.GroupId.ToLowerInvariant();if(-not $targetsByGroup.ContainsKey($gk)){$targetsByGroup[$gk]=[System.Collections.Generic.List[object]]::new()};$targetsByGroup[$gk].Add($tg)}}
  for($k=0;$k -lt $checkIds.Count;$k++){
   $gid=$checkIds[$k]; $objs=@($targetsByGroup[$gid])
   if($gInfo[$k].Status -eq 404){foreach($o in $objs){$hygieneRows.Add([pscustomobject]@{Issue='Assigned group no longer exists';Object=$o.Object;ObjectKind=$o.ObjectKind;Group=$gid;Detail='Deleted group: remove the orphaned assignment'})};continue}
   if($gInfo[$k].Status -ne 200){$groupFail++;continue}
   $groupNames[$gid]=AsText $gInfo[$k].Body.displayName
   if($gMembers[$k].Status -eq 200 -and @($gMembers[$k].Body.value).Count -eq 0){foreach($o in $objs){$hygieneRows.Add([pscustomobject]@{Issue='Assigned group is empty';Object=$o.Object;ObjectKind=$o.ObjectKind;Group=$groupNames[$gid];Detail=if(AsText $gInfo[$k].Body.membershipRule){'Dynamic rule matches no object'}else{'No members'}})}}
  }
  foreach($h in $hygieneRows){if($h.Group -and $groupNames.ContainsKey($h.Group.ToLowerInvariant())){$h.Group=$groupNames[$h.Group.ToLowerInvariant()]}}
  $collection['Assignment hygiene']=if($groupFail -eq 0 -and $checkIds.Count -eq $groupIds.Count){"Complete ($($targets.Count) assignments, $($groupIds.Count) groups)"}else{"Partial ($groupFail groups unreadable, $($groupIds.Count-$checkIds.Count) not checked)"}
 }else{$collection['Assignment hygiene']="Complete ($($targets.Count) assignments)"}
 $byIssue=$hygieneRows|Group-Object Issue
 foreach($i in $byIssue){
  switch($i.Name){
   'Assigned group no longer exists' {Add-FindingFr 'Medium' 'Assignment hygiene' 'Assignments target deleted groups' $i.Count 'Assignment-Hygiene.csv' 'Remove orphaned assignments; they hide the real targeting and can break after group ID reuse in tooling.' 'Des assignations ciblent des groupes supprimés' 'Supprimer les assignations orphelines ; elles masquent le ciblage réel.'}
   'Assigned group is empty' {Add-FindingFr 'Low' 'Assignment hygiene' 'Assignments target empty groups' $i.Count 'Assignment-Hygiene.csv' 'Confirm the group is still needed or fix the dynamic membership rule.' 'Des assignations ciblent des groupes vides' 'Confirmer que le groupe est encore utile ou corriger la règle d''appartenance dynamique.'}
   'Group both included and excluded' {Add-FindingFr 'Medium' 'Assignment hygiene' 'Same group both included and excluded on an object' $i.Count 'Assignment-Hygiene.csv' 'Exclusion takes precedence; remove the contradictory assignment.' 'Un même groupe est à la fois inclus et exclu sur un objet' 'L''exclusion l''emporte ; supprimer l''assignation contradictoire.'}
  }
 }
 $broadNoFilter=@($hygieneRows|Where-Object {$_.Issue -like 'Assigned to All*' -and $_.Detail -eq 'No filter'})
 if($broadNoFilter.Count -gt 15){Add-FindingFr 'Informational' 'Assignment hygiene' 'Many objects assigned to All users / All devices without a filter' $broadNoFilter.Count 'Assignment-Hygiene.csv' 'Use groups or assignment filters (platform, ownership) so pilots and exclusions remain possible.' 'Nombreux objets assignés à Tous les utilisateurs / Tous les appareils sans filtre' 'Utiliser des groupes ou des filtres (plateforme, propriété) pour permettre les pilotes et les exclusions.'}
}

# ---------- P2. Windows LAPS and Defender coverage (measured, not configured) ----------
$coverageRows=[System.Collections.Generic.List[object]]::new()
$windowsDevices=@($devices|Where-Object {$_.OS -match '^Windows' -and $_.AzureADDeviceId})
$lapsBackups=@{}
if($SkipGovernance){$collection['Windows LAPS backup']='Skipped'}else{
 try{
  $lapsHeaders=@{'ocp-client-name'='IntuneAssessment';'ocp-client-version'='3.60'}
  foreach($l in @(Read-GraphPages -Uri "$base/directory/deviceLocalCredentials?`$select=id,deviceName,lastBackupDateTime" -Label 'Windows LAPS' -Headers $lapsHeaders)){$lapsBackups[(AsText $l.id).ToLowerInvariant()]=SafeDate $l.lastBackupDateTime}
  $collection['Windows LAPS backup']="Complete ($($lapsBackups.Count) devices with a backed-up password; passwords are not read)"
  $lapsPolicy=(@($endpointSecurity|Where-Object {$_.Family -eq 'Windows LAPS'}).Count -gt 0) -or (@($script:SharedTenantSettingRows|Where-Object {(AsText $_.Setting.SettingId) -match '(?i)laps'}).Count -gt 0)
  $lapsScopeGranted=(@(@((Get-MgContext).Scopes) | Where-Object {$_ -match '^DeviceLocalCredential\.'}).Count -gt 0)
  if($lapsBackups.Count -eq 0 -and $lapsPolicy){
   # Zero backups while a LAPS policy exists is more likely a permission or API issue than a real gap.
   $collection['Windows LAPS backup']="Not verified (0 backups returned although a LAPS policy exists; DeviceLocalCredential scope granted: $lapsScopeGranted)"
   Add-FindingFr 'Informational' 'Windows LAPS' 'Windows LAPS backups could not be verified' $windowsDevices.Count "A LAPS policy exists but Graph returned no backup metadata. DeviceLocalCredential scope granted: $lapsScopeGranted" 'Check that DeviceLocalCredential.ReadBasic.All is consented and that devices report LAPS backups in Entra (Devices > Local administrator password recovery).' 'Les sauvegardes Windows LAPS n''ont pas pu être vérifiées' 'Vérifier le consentement DeviceLocalCredential.ReadBasic.All et que les appareils remontent leurs sauvegardes LAPS dans Entra (Appareils > Récupération du mot de passe administrateur local).' 'Unverified'
  }else{
  $noLaps=@($windowsDevices|Where-Object {-not $lapsBackups.ContainsKey($_.AzureADDeviceId.ToLowerInvariant())})
  $staleLaps=@($windowsDevices|Where-Object {$d=$lapsBackups[$_.AzureADDeviceId.ToLowerInvariant()];$d -and ($now-$d).TotalDays -gt 60})
  $coverageRows.Add([pscustomobject]@{Control='Windows LAPS password backed up to Entra';Population='Windows devices with an Entra device ID';Total=$windowsDevices.Count;Covered=$windowsDevices.Count-$noLaps.Count;Gap=$noLaps.Count;Coverage=if($windowsDevices.Count){[Math]::Round(100*($windowsDevices.Count-$noLaps.Count)/$windowsDevices.Count,1)}else{$null};Note=if($lapsPolicy){'LAPS policy present'}else{'No LAPS policy identified'}})
  if($windowsDevices.Count -and $noLaps.Count){
   $sev=if(-not $lapsPolicy){'High'}elseif($noLaps.Count/$windowsDevices.Count -gt 0.1){'Medium'}else{'Low'}
   Add-FindingFr $sev 'Windows LAPS' 'Windows devices without a Windows LAPS password backed up in Entra' $noLaps.Count ("$($noLaps.Count) of $($windowsDevices.Count); LAPS policy identified: $lapsPolicy") 'Deploy a Windows LAPS policy (backup to Entra ID) to all Windows devices and verify the backup.' 'Appareils Windows sans mot de passe Windows LAPS sauvegardé dans Entra' 'Déployer une stratégie Windows LAPS (sauvegarde vers Entra ID) sur tous les appareils Windows et vérifier la sauvegarde.'
  }
  if($staleLaps.Count){Add-FindingFr 'Low' 'Windows LAPS' 'Windows LAPS password not rotated/backed up for 60+ days' $staleLaps.Count 'deviceLocalCredentials.lastBackupDateTime' 'Check the password age setting and devices that no longer contact Entra.' 'Mot de passe Windows LAPS non renouvelé depuis plus de 60 jours' 'Vérifier le paramètre d''âge du mot de passe et les appareils qui ne contactent plus Entra.'}
 }
 }catch{$collection['Windows LAPS backup']='Unavailable';$warnings.Add("Windows LAPS backup metadata unavailable: $($_.Exception.Message)")}
}
if(@($defenderRows).Count -gt 0){
 $winAll=@($devices|Where-Object {$_.OS -match '^Windows'})
 $defIds=@{}; foreach($r in $defenderRows){$defIds[(AsText $r.DeviceId).ToLowerInvariant()]=$true}
 $reporting=@($winAll|Where-Object {$defIds.ContainsKey($_.Id.ToLowerInvariant())}).Count
 $coverageRows.Add([pscustomobject]@{Control='Microsoft Defender protection state reported to Intune';Population='Windows managed devices';Total=$winAll.Count;Covered=$reporting;Gap=$winAll.Count-$reporting;Coverage=if($winAll.Count){[Math]::Round(100*$reporting/$winAll.Count,1)}else{$null};Note='Signal reported by Intune; MDE onboarding itself is not queried'})
}
$encWin=@($devices|Where-Object {$_.OS -match '^Windows'})
if($encWin.Count){$coverageRows.Add([pscustomobject]@{Control='BitLocker / disk encryption reported';Population='Windows managed devices';Total=$encWin.Count;Covered=@($encWin|Where-Object Encrypted -eq 'Encrypted').Count;Gap=@($encWin|Where-Object Encrypted -ne 'Encrypted').Count;Coverage=[Math]::Round(100*@($encWin|Where-Object Encrypted -eq 'Encrypted').Count/$encWin.Count,1);Note='Unknown encryption values counted as gap here'})}
$cmpAll=@($devices)
if($cmpAll.Count){$coverageRows.Add([pscustomobject]@{Control='Device compliant';Population='All managed devices';Total=$cmpAll.Count;Covered=@($cmpAll|Where-Object Compliance -eq 'compliant').Count;Gap=@($cmpAll|Where-Object Compliance -ne 'compliant').Count;Coverage=[Math]::Round(100*@($cmpAll|Where-Object Compliance -eq 'compliant').Count/$cmpAll.Count,1);Note=''})}

# ---------- P3. Operating system support, patch level, hardware ----------
# Lifecycle table (end of servicing). Verify against Microsoft lifecycle pages when it ages.
$winLifecycle=@{
 '22000'=@{Name='Windows 11 21H2';Pro='2023-10-10';Ent='2024-10-08'}
 '22621'=@{Name='Windows 11 22H2';Pro='2024-10-08';Ent='2025-10-14'}
 '22631'=@{Name='Windows 11 23H2';Pro='2025-11-11';Ent='2026-11-10'}
 '26100'=@{Name='Windows 11 24H2';Pro='2026-10-13';Ent='2027-10-12'}
 '26200'=@{Name='Windows 11 25H2';Pro='2027-10-12';Ent='2028-10-10'}
}
$win10Ltsc=@{'17763'=@{Name='Windows 10 LTSC 2019';End='2029-01-09'};'19044'=@{Name='Windows 10 LTSC 2021';End='2027-01-12'};'14393'=@{Name='Windows 10 LTSB 2016';End='2026-10-13'}}
$osRows=[System.Collections.Generic.List[object]]::new()
$patchRows=[System.Collections.Generic.List[object]]::new()
$verKey={param($v) $p=@(([string]$v) -split '\.' | ForEach-Object {$n=0;[void][int]::TryParse(($_ -replace '\D',''),[ref]$n);$n}); while($p.Count -lt 4){$p+=0}; ($p[0..3]|ForEach-Object {'{0:D6}' -f $_}) -join '.'}
$winParsed=foreach($d in @($devices|Where-Object {$_.OS -match '^Windows' -and $_.OSVersion})){
 $parts=$d.OSVersion -split '\.'
 if($parts.Count -ge 3 -and $parts[2] -match '^\d+$'){
  $ubrVal=0; if($parts.Count -ge 4){[void][int]::TryParse(($parts[3] -replace '\D',''),[ref]$ubrVal)}
  [pscustomobject]@{Device=$d;Build=$parts[2];Ubr=$ubrVal}
 }
}
foreach($w in @($winParsed)){
 $d=$w.Device; $isEnt=($d.Edition -match 'Enterprise|Education') ; $isLtsc=($d.Edition -match 'LTSC|EnterpriseS|IoTEnterpriseS|LTSB')
 $release='';$end=$null
 if([int]$w.Build -lt 22000){
  if($isLtsc -and $win10Ltsc.ContainsKey($w.Build)){$release=$win10Ltsc[$w.Build].Name;$end=[datetime]$win10Ltsc[$w.Build].End}
  else{$release='Windows 10 (build {0})' -f $w.Build;$end=[datetime]'2025-10-14'}
 }elseif($winLifecycle.ContainsKey($w.Build)){
  $release=$winLifecycle[$w.Build].Name
  if($isLtsc -and $w.Build -eq '26100'){$release='Windows 11 LTSC 2024';$end=[datetime]'2029-10-09'}else{$end=[datetime]$(if($isEnt){$winLifecycle[$w.Build].Ent}else{$winLifecycle[$w.Build].Pro})}
 }else{$release="Windows build $($w.Build)"}
 $days=if($end){[int]($end-$now).TotalDays}else{$null}
 $state=if($null -eq $days){'Unknown release'}elseif($days -lt 0){'Out of support'}elseif($days -le 90){'Ending within 90 days'}else{'Supported'}
 $osRows.Add([pscustomobject]@{Device=$d.Name;Platform='Windows';Release=$release;Version=$d.OSVersion;Edition=$d.Edition;EndOfServicing=if($end){$end.ToString('yyyy-MM-dd')}else{''};DaysRemaining=$days;State=$state;LastSync=$d.LastSync})
}
$minVersions=@{'iOS'=$MinIosVersion;'macOS'=$MinMacOSVersion;'Android'=$MinAndroidVersion}
foreach($d in @($devices|Where-Object {$_.Platform -eq 'Android AOSP'})){
 $osRows.Add([pscustomobject]@{Device=$d.Name;Platform='Android AOSP';Release="AOSP $($d.OSVersion)";Version=$d.OSVersion;Edition='';EndOfServicing='';DaysRemaining=$null;State='Not assessed (OEM firmware)';LastSync=$d.LastSync})
}
foreach($d in @($devices|Where-Object {$_.OS -match 'iOS|iPadOS|mac|Android' -and $_.OSVersion -and $_.Platform -ne 'Android AOSP'})){
 $pf=if($d.OS -match 'iOS|iPadOS'){'iOS'}elseif($d.OS -match 'mac'){'macOS'}else{'Android'}
 $min=$minVersions[$pf]; $below=((& $verKey $d.OSVersion) -lt (& $verKey $min))
 $osRows.Add([pscustomobject]@{Device=$d.Name;Platform=$pf;Release="$pf $($d.OSVersion)";Version=$d.OSVersion;Edition='';EndOfServicing='';DaysRemaining=$null;State=if($below){"Below minimum ($min)"}else{'At or above minimum'};LastSync=$d.LastSync})
}
$collection['OS lifecycle']="Complete (reference date $($now.ToString('yyyy-MM-dd')); lifecycle table embedded in script)"
$oos=@($osRows|Where-Object State -eq 'Out of support')
$oosWin10=@($oos|Where-Object {$_.Release -like 'Windows 10*'})
if($oosWin10.Count){Add-FindingFr 'High' 'Operating system' 'Windows 10 devices past end of support' $oosWin10.Count 'OS-Lifecycle.csv (Windows 10 support ended 2025-10-14; ESU enrollment is not visible in Graph)' 'Upgrade to Windows 11 or confirm Extended Security Updates enrollment for each device.' 'Appareils Windows 10 dont le support est terminé' 'Migrer vers Windows 11 ou confirmer l''inscription aux mises à jour de sécurité étendues (ESU) pour chaque appareil.'}
$oosWin11=@($oos|Where-Object {$_.Release -notlike 'Windows 10*' -and $_.Platform -eq 'Windows'})
if($oosWin11.Count){Add-FindingFr 'High' 'Operating system' 'Windows 11 devices on a release past end of servicing' $oosWin11.Count (($oosWin11|Group-Object Release|ForEach-Object {'{0}: {1}' -f $_.Name,$_.Count}) -join '; ') 'Deploy a feature update policy targeting a supported release (24H2 or later).' 'Appareils Windows 11 sur une version dont le support est terminé' 'Déployer une stratégie de mise à jour de fonctionnalité vers une version prise en charge (24H2 ou plus récente).'}
$ending=@($osRows|Where-Object State -eq 'Ending within 90 days')
if($ending.Count){Add-FindingFr 'Medium' 'Operating system' 'Windows release reaches end of servicing within 90 days' $ending.Count (($ending|Group-Object Release|ForEach-Object {'{0}: {1}' -f $_.Name,$_.Count}) -join '; ') 'Schedule the feature update now to avoid running unsupported builds.' 'Version de Windows en fin de support dans moins de 90 jours' 'Planifier la mise à jour de fonctionnalité dès maintenant.'}
$belowMin=@($osRows|Where-Object {$_.State -like 'Below minimum*'})
if($belowMin.Count){Add-FindingFr 'Medium' 'Operating system' 'Mobile/macOS devices below the minimum OS version' $belowMin.Count (($belowMin|Group-Object Platform|ForEach-Object {'{0}: {1}' -f $_.Name,$_.Count}) -join '; ') 'Enforce minimum OS versions in compliance policies and use OS update policies (DDM for Apple).' 'Appareils mobiles/macOS sous la version minimale de l''OS' 'Imposer les versions minimales dans les stratégies de conformité et utiliser les stratégies de mise à jour (DDM pour Apple).'}
# Patch level: compare each device to the most recent revision observed for the same build in this tenant.
foreach($g in @($winParsed|Group-Object Build)){
 $top=($g.Group|Measure-Object Ubr -Maximum).Maximum
 foreach($w in $g.Group){
  $recent=($null -ne $w.Device.DaysSinceSync -and [int]$w.Device.DaysSinceSync -le 7)
  if($w.Ubr -lt $top -and $recent){$patchRows.Add([pscustomobject]@{Device=$w.Device.Name;Build=$w.Build;Revision=$w.Ubr;NewestRevisionInTenant=$top;RevisionGap=$top-$w.Ubr;LastSync=$w.Device.LastSync})}
 }
}
$farBehind=@($patchRows|Where-Object {$_.RevisionGap -ge 200})
$collection['Patch level']='Complete (heuristic: compared with newest revision observed per build in this tenant)'
if($farBehind.Count){Add-FindingFr 'Medium' 'Windows Update' 'Active Windows devices well behind the newest patch level seen in the tenant' $farBehind.Count 'Windows-Patch-Lag.csv (revision gap >= 200, device synced in last 7 days; heuristic)' 'Investigate update ring assignment, pauses, deferrals and Windows Update health on these devices.' 'Appareils Windows actifs très en retard sur le niveau de correctif le plus récent du tenant' 'Vérifier l''assignation des anneaux, les pauses, les reports et la santé de Windows Update sur ces appareils.' 'Heuristic'}
# Hardware readiness (Endpoint analytics Work from anywhere), then per-device TPM / Secure Boot fallback.
$hardwareRows=[System.Collections.Generic.List[object]]::new()
if($SkipHardware){$collection['Hardware readiness']='Skipped'}else{
 try{
  $wfa=@(Read-GraphPages -Uri "$beta/deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics('allDevices')/metricDevices" -Label 'Windows 11 readiness')
  foreach($r in $wfa){$hardwareRows.Add([pscustomobject]@{Device=AsText $r.deviceName;Serial=AsText $r.serialNumber;Model=AsText $r.model;OS=AsText $r.osDescription;Windows11=AsText $r.upgradeEligibility;TPM=if((AsText $r.tpmCheckFailed) -eq 'True'){'Failed'}else{'OK'};SecureBoot=if((AsText $r.secureBootCheckFailed) -eq 'True'){'Failed'}else{'OK'};Processor=if((AsText $r.processorFamilyCheckFailed) -eq 'True' -or (AsText $r.processorCoreCountCheckFailed) -eq 'True' -or (AsText $r.processorSpeedCheckFailed) -eq 'True'){'Failed'}else{'OK'};RAM=if((AsText $r.ramCheckFailed) -eq 'True'){'Failed'}else{'OK'};Source='Endpoint analytics'})}
  if($hardwareRows.Count -eq 0){throw 'No Endpoint analytics data (Endpoint analytics may not be enabled)'}
  $collection['Hardware readiness']="Complete (Endpoint analytics, $($hardwareRows.Count) devices)"
 }catch{
  $warnings.Add("Endpoint analytics readiness unavailable, using per-device hardware data: $($_.Exception.Message)")
  $hwTargets=@($devices|Where-Object {$_.OS -match '^Windows'}|Select-Object -First $MaxHardwareDevices)
  $hw=Invoke-GraphBatchGet -Urls @($hwTargets|ForEach-Object {"/deviceManagement/managedDevices/$($_.Id)?`$select=id,deviceName,hardwareInformation,deviceHealthAttestationState"}) -Version 'beta' -Label 'Device hardware'
  $hwOk=0
  for($k=0;$k -lt $hwTargets.Count;$k++){
   if($hw[$k].Status -ne 200){continue};$hwOk++;$b=$hw[$k].Body
   $tpm=AsText $b.hardwareInformation.tpmSpecificationVersion; $sb=AsText $b.deviceHealthAttestationState.secureBoot
   $hardwareRows.Add([pscustomobject]@{Device=$hwTargets[$k].Name;Serial=$hwTargets[$k].Serial;Model=$hwTargets[$k].Model;OS=$hwTargets[$k].OSVersion;Windows11='';TPM=if(-not $tpm){'Not reported'}elseif($tpm -match '^\s*2'){'OK (2.0)'}else{"Failed ($tpm)"};SecureBoot=if(-not $sb){'Not reported'}elseif($sb -match 'enabled'){'OK'}else{'Failed'};Processor='';RAM='';Source='Intune hardware inventory'})
  }
  $collection['Hardware readiness']=if($hwOk -gt 0){"Partial (Intune hardware inventory, $hwOk of $(@($devices|Where-Object {$_.OS -match '^Windows'}).Count) Windows devices)"}else{'Unavailable'}
 }
 $tpmFail=@($hardwareRows|Where-Object {$_.TPM -like 'Failed*'}); $sbFail=@($hardwareRows|Where-Object SecureBoot -eq 'Failed')
 $notCapable=@($hardwareRows|Where-Object {$_.Windows11 -match 'notCapable|upgradeNotEligible|Ineligible'})
 if($tpmFail.Count){Add-FindingFr 'Medium' 'Hardware' 'Windows devices without TPM 2.0' $tpmFail.Count 'Hardware-Readiness.csv' 'Enable TPM 2.0 in firmware or plan hardware replacement; TPM is required for Windows 11, BitLocker TPM protectors and Windows Hello.' 'Appareils Windows sans TPM 2.0' 'Activer le TPM 2.0 dans le firmware ou planifier le remplacement ; il est requis pour Windows 11, BitLocker et Windows Hello.'}
 if($sbFail.Count){Add-FindingFr 'Medium' 'Hardware' 'Windows devices without Secure Boot enabled' $sbFail.Count 'Hardware-Readiness.csv' 'Enable UEFI Secure Boot (required for Windows 11 and boot-chain protection).' 'Appareils Windows sans Secure Boot activé' 'Activer UEFI Secure Boot (requis pour Windows 11 et la protection de la chaîne de démarrage).'}
 if($notCapable.Count){Add-FindingFr 'Medium' 'Hardware' 'Windows devices not capable of Windows 11' $notCapable.Count 'Endpoint analytics Work from anywhere' 'Plan hardware refresh or ESU for these devices.' 'Appareils Windows non compatibles avec Windows 11' 'Planifier le renouvellement matériel ou les ESU pour ces appareils.'}
}

# ---------- P3. Duplicates and cross-source consistency (Intune / Entra / Defender) ----------
$duplicateRows=[System.Collections.Generic.List[object]]::new()
$badSerials=@('','0','none','default string','to be filled by o.e.m.','system serial number','unknown','0123456789')
foreach($g in @($devices|Where-Object {$_.Serial -and ($_.Serial.Trim().ToLowerInvariant() -notin $badSerials)}|Group-Object {$_.Serial.Trim().ToUpperInvariant()}|Where-Object Count -gt 1)){
 foreach($d in ($g.Group|Sort-Object LastSync -Descending)){$duplicateRows.Add([pscustomobject]@{Serial=$g.Name;Device=$d.Name;LastSync=$d.LastSync;Enrolled=$d.Enrolled;PrimaryUser=$d.PrimaryUser;Records=$g.Count})}
}
$dupSerials=@($duplicateRows|Select-Object -ExpandProperty Serial -Unique)
if($dupSerials.Count){Add-FindingFr 'Low' 'Device hygiene' 'Same serial number enrolled more than once in Intune' $dupSerials.Count 'Duplicate-Devices.csv' 'Delete stale duplicate records (keep the most recent check-in) and review device cleanup rules.' 'Même numéro de série inscrit plusieurs fois dans Intune' 'Supprimer les doublons obsolètes (garder la synchronisation la plus récente) et revoir les règles de nettoyage.'}
$crossRows=[System.Collections.Generic.List[object]]::new()
if($SkipEntraDevices){$collection['Entra devices']='Skipped'}else{
 $entraDevices=@(Get-OptionalCollection -Name 'Entra devices' -Uri "$base/devices?`$select=id,deviceId,displayName,operatingSystem,trustType,isManaged,accountEnabled,approximateLastSignInDateTime&`$top=999")
 if($collection['Entra devices'] -eq 'Complete'){
  $intuneByEntra=@{}; foreach($d in $devices){if($d.AzureADDeviceId){$intuneByEntra[$d.AzureADDeviceId.ToLowerInvariant()]=$d}}
  $entraById=@{}; foreach($e in $entraDevices){$entraById[(AsText $e.deviceId).ToLowerInvariant()]=$e}
  foreach($d in @($devices|Where-Object {$_.AzureADDeviceId -and $_.AzureADDeviceId -ne '00000000-0000-0000-0000-000000000000'})){
   if(-not $entraById.ContainsKey($d.AzureADDeviceId.ToLowerInvariant())){$crossRows.Add([pscustomobject]@{Issue='Intune device without Entra object';Device=$d.Name;OS=$d.OS;Detail="Entra device ID $($d.AzureADDeviceId) not found";LastActivity=$d.LastSync})}
  }
  foreach($e in $entraDevices){
   $os=AsText $e.operatingSystem; if($os -notmatch 'Windows|iOS|iPadOS|Mac|Android'){continue}
   $last=SafeDate $e.approximateLastSignInDateTime
   Register-AnonymizedValue (AsText $e.displayName) 'device'
   if(-not $intuneByEntra.ContainsKey((AsText $e.deviceId).ToLowerInvariant()) -and $last -and ($now-$last).TotalDays -gt $StaleEntraDays -and (AsText $e.accountEnabled) -eq 'True'){
    $crossRows.Add([pscustomobject]@{Issue="Stale Entra device ($StaleEntraDays+ days) not in Intune";Device=AsText $e.displayName;OS=$os;Detail=('Join type: '+(AsText $e.trustType));LastActivity=ToIso $last})
   }
  }
  $orphanIntune=@($crossRows|Where-Object Issue -eq 'Intune device without Entra object')
  $staleEntra=@($crossRows|Where-Object Issue -like 'Stale Entra*')
  if($orphanIntune.Count){Add-FindingFr 'Medium' 'Device hygiene' 'Intune devices whose Entra device object no longer exists' $orphanIntune.Count 'Cross-Source-Consistency.csv' 'These devices cannot satisfy device-based Conditional Access; re-register or retire them.' 'Appareils Intune dont l''objet Entra n''existe plus' 'Ces appareils ne peuvent pas satisfaire Conditional Access ; les réinscrire ou les retirer.'}
  if($staleEntra.Count){Add-FindingFr 'Low' 'Device hygiene' "Enabled Entra devices without sign-in for $StaleEntraDays+ days and not managed by Intune" $staleEntra.Count 'Cross-Source-Consistency.csv' 'Disable then delete stale device objects through a documented cleanup process.' "Appareils Entra activés sans connexion depuis plus de $StaleEntraDays jours et non gérés par Intune" 'Désactiver puis supprimer les objets obsolètes selon un processus de nettoyage documenté.'}
 }
}
if(@($defenderRows).Count -gt 0){
 $defIds2=@{}; foreach($r in $defenderRows){$defIds2[(AsText $r.DeviceId).ToLowerInvariant()]=$true}
 foreach($d in @($devices|Where-Object {$_.OS -match '^Windows' -and -not $_.Inactive -and -not $defIds2.ContainsKey($_.Id.ToLowerInvariant())})){
  $crossRows.Add([pscustomobject]@{Issue='Active Windows device without Defender signal in Intune';Device=$d.Name;OS=$d.OS;Detail='No windowsProtectionState returned';LastActivity=$d.LastSync})
 }
}

$payloadSummaryForCompare=[ordered]@{
 total=$devices.Count
 noncompliant=@($devices|Where-Object {$_.Compliance -eq 'noncompliant'}).Count
 inactive=@($devices|Where-Object {$_.Inactive}).Count
 unencrypted=@($devices|Where-Object {$_.Encrypted -eq 'Not encrypted'}).Count
 disabled=@($devices|Where-Object {$_.PrimaryAccount -eq 'Disabled'}).Count
 missingAutopilot=@($devices|Where-Object {$_.Autopilot -eq 'No matching record'}).Count
}

# =====================================================================================
# SECTION 6c - Intune configuration review (v3.60): compliance actions, device clean-up,
# applications, OS updates for every platform, enrollment profiles, Intune Suite,
# audit log and Endpoint analytics. Read-only; each collection fails independently.
# =====================================================================================
$tenantReviewRows=[System.Collections.Generic.List[object]]::new()
$complianceActionRows=[System.Collections.Generic.List[object]]::new()
$appAggregateRows=[System.Collections.Generic.List[object]]::new()
$updateCoverageRows=[System.Collections.Generic.List[object]]::new()
$enrollProfileRows=[System.Collections.Generic.List[object]]::new()
$auditRows=[System.Collections.Generic.List[object]]::new()
function Add-ReviewRow([string]$Area,[string]$Check,[string]$Result,[string]$Status,[string]$Detail) {
 $tenantReviewRows.Add([pscustomobject]@{Area=$Area;Check=$Check;Result=$Result;Status=$Status;Detail=$Detail})
}
$platformCounts=@{}
foreach($d in $devices){$platformCounts[$d.Platform]=1+[int]$platformCounts[$d.Platform]}
$countWin=[int]$platformCounts['Windows']; $countIos=[int]$platformCounts['iOS']; $countMac=[int]$platformCounts['macOS']
$countAndroid=[int]$platformCounts['Android']; $countAosp=[int]$platformCounts['Android AOSP']
$inactiveTotal=@($devices | Where-Object {$_.Inactive}).Count

if($SkipIntuneReview){
 $collection['Intune configuration review']='Skipped'
}else{
 Say 'Reviewing Intune configuration (compliance actions, apps, updates, enrollment, Intune Suite, audit)...'

 # ---------- Compliance policy actions: grace period and user notification ----------
 if($collection['Compliance policies'] -ne 'Complete'){
  $collection['Compliance actions']='Unavailable (compliance policies not collected)'
 }else{
  $cpWithId=@($compliancePolicies | Where-Object {AsText $_.id})
  $actBatch=Invoke-GraphBatchGet -Urls @($cpWithId | ForEach-Object {"/deviceManagement/deviceCompliancePolicies/$($_.id)/scheduledActionsForRule?`$expand=scheduledActionConfigurations"}) -Version 'v1.0' -Label 'Compliance actions'
  $actFail=0
  for($k=0;$k -lt $cpWithId.Count;$k++){
   $cp=$cpWithId[$k]
   try{$rules=@(Get-BatchCollection -Result $actBatch[$k] -Label 'Compliance actions')}catch{$actFail++;continue}
   $configs=@($rules | ForEach-Object {@($_.scheduledActionConfigurations)} | Where-Object {$null -ne $_})
   $block=@($configs | Where-Object {(AsText $_.actionType) -eq 'block'}) | Select-Object -First 1
   $graceHours=if($block){[double]$block.gracePeriodHours}else{$null}
   $notify=@($configs | Where-Object {(AsText $_.actionType) -match '^(notification|pushNotification)$'}).Count
   $retire=@($configs | Where-Object {(AsText $_.actionType) -match 'retire'}).Count
   $graceText=if($null -eq $graceHours){'No block action'}elseif($graceHours -eq 0){'Immediately'}else{"$([Math]::Round($graceHours/24,1)) days"}
   $cpType=(AsText $cp.'@odata.type').Replace('#microsoft.graph.','')
   $cpActions=(@($configs | ForEach-Object {AsText $_.actionType}) -join ', ')
   $complianceActionRows.Add([pscustomobject]@{Policy=AsText $cp.displayName;Type=$cpType;Assignments=Get-AssignmentCount $cp;MarkNoncompliant=$graceText;GraceHours=$graceHours;Notifications=$notify;Retire=$retire;Actions=$cpActions})
  }
  $collection['Compliance actions']=if($actFail -eq 0){"Complete ($($complianceActionRows.Count) policies)"}else{"Partial ($actFail policies unreadable)"}
  $assignedActions=@($complianceActionRows | Where-Object {$_.Assignments -ne 0})
  $longGrace=@($assignedActions | Where-Object {$null -ne $_.GraceHours -and $_.GraceHours -gt 168})
  $noNotify=@($assignedActions | Where-Object {$_.Notifications -eq 0})
  if($longGrace.Count){Add-FindingFr 'Low' 'Compliance' 'Compliance policies wait more than 7 days before marking devices noncompliant' $longGrace.Count (($longGrace | ForEach-Object {"$($_.Policy) ($($_.MarkNoncompliant))"}) -join '; ') 'Reduce the grace period (0 to 3 days is common) so Conditional Access reacts to noncompliance in time.' 'Stratégies de conformité attendant plus de 7 jours avant de marquer un appareil non conforme' 'Réduire le délai de grâce (0 à 3 jours en général) pour que l''accès conditionnel réagisse à temps.'}
  if($noNotify.Count){Add-FindingFr 'Informational' 'Compliance' 'Assigned compliance policies do not notify users' $noNotify.Count ((@($noNotify | Select-Object -First 8 | ForEach-Object {$_.Policy})) -join '; ') 'Add an e-mail or push notification action so users know how to become compliant again.' 'Les stratégies de conformité assignées ne notifient pas les utilisateurs' 'Ajouter une action de notification (courriel ou push) pour que les utilisateurs sachent comment redevenir conformes.'}
 }

 # ---------- Device clean-up rule ----------
 $cleanupDays=$null; $cleanupSource=''
 try{
  $cleanRules=@(Read-GraphPages -Uri "$beta/deviceManagement/managedDeviceCleanupRules" -Label 'Device clean-up rules')
  if($cleanRules.Count){
   $cleanupDays=[int](@($cleanRules | ForEach-Object {ConvertTo-IntOrZero $_.deviceInactivityBeforeRetirementInDays}) | Measure-Object -Minimum).Minimum
   $cleanupSource="managedDeviceCleanupRules ($($cleanRules.Count) rules)"
  }
 }catch{}
 if($null -eq $cleanupDays){
  try{
   $cleanSettings=Invoke-GraphJson -Uri "$beta/deviceManagement/managedDeviceCleanupSettings" -Label 'Device clean-up settings'
   $cleanupDays=ConvertTo-IntOrZero $cleanSettings.deviceInactivityBeforeRetirementInDays
   $cleanupSource='managedDeviceCleanupSettings'
  }catch{}
 }
 if($null -eq $cleanupDays){
  $collection['Device clean-up rules']='Unavailable'
 }else{
  $collection['Device clean-up rules']="Complete ($cleanupSource)"
  $cleanupText=if($cleanupDays -gt 0){"$cleanupDays days"}else{'Not configured'}
  Add-ReviewRow 'Device hygiene' 'Device clean-up rule' $cleanupText $(if($cleanupDays -gt 0){'Configured'}else{'Not configured'}) $cleanupSource
  if($cleanupDays -le 0 -and $inactiveTotal -gt 0){Add-FindingFr 'Low' 'Device hygiene' 'No device clean-up rule removes inactive devices' $inactiveTotal "Inactive devices: $inactiveTotal; $cleanupSource" 'Configure a device clean-up rule (for example 90 to 180 days) so stale records stop distorting compliance and inventory.' 'Aucune règle de nettoyage ne retire les appareils inactifs' 'Configurer une règle de nettoyage des appareils (par exemple 90 à 180 jours) pour que les enregistrements obsolètes ne faussent plus la conformité et l''inventaire.'}
 }

 # ---------- Device categories, terms and conditions, scope tags ----------
 try{
  $cats=@(Read-GraphPages -Uri "$base/deviceManagement/deviceCategories" -Label 'Device categories')
  $catNames=(@($cats | Select-Object -First 10 | ForEach-Object {AsText $_.displayName}) -join ', ')
  Add-ReviewRow 'Enrollment' 'Device categories' "$($cats.Count)" $(if($cats.Count){'Configured'}else{'Not configured'}) $catNames
 }catch{Add-ReviewRow 'Enrollment' 'Device categories' '' 'Unavailable' $_.Exception.Message}
 try{
  $terms=@(Read-GraphPages -Uri "$base/deviceManagement/termsAndConditions" -Label 'Terms and conditions')
  $termNames=(@($terms | ForEach-Object {AsText $_.displayName}) -join ', ')
  Add-ReviewRow 'Enrollment' 'Intune terms and conditions' "$($terms.Count)" $(if($terms.Count){'Configured'}else{'Not configured'}) $termNames
 }catch{Add-ReviewRow 'Enrollment' 'Intune terms and conditions' '' 'Unavailable' $_.Exception.Message}
 try{
  $scopeTags=@(Read-GraphPages -Uri "$beta/deviceManagement/roleScopeTags" -Label 'Scope tags')
  $customTags=@($scopeTags | Where-Object {(AsText $_.id) -ne '0'})
  $usedTagIds=@($rbacRows | Where-Object {$_.Source -eq 'Intune RBAC'} | ForEach-Object {@(([string]$_.ScopeTags) -split ',\s*')} | Where-Object {$_} | Select-Object -Unique)
  $unusedTags=@($customTags | Where-Object {(AsText $_.id) -notin $usedTagIds})
  $tagDetail=(@($customTags | ForEach-Object {AsText $_.displayName}) -join ', ')
  Add-ReviewRow 'Governance' 'Custom scope tags' "$($customTags.Count) ($($unusedTags.Count) not used in Intune RBAC)" $(if($customTags.Count){'Configured'}else{'Not configured'}) $tagDetail
  if($unusedTags.Count -and $collection['Intune RBAC'] -like 'Complete*'){Add-FindingFr 'Informational' 'Governance' 'Scope tags are not used by any Intune role assignment' $unusedTags.Count ((@($unusedTags | ForEach-Object {AsText $_.displayName})) -join ', ') 'Use scope tags in Intune role assignments to limit what each admin team can see and change, or remove unused tags.' 'Des balises d''étendue ne sont utilisées par aucune attribution de rôle Intune' 'Utiliser les balises d''étendue dans les attributions de rôles Intune pour limiter ce que chaque équipe peut voir et modifier, ou supprimer les balises inutilisées.'}
 }catch{Add-ReviewRow 'Governance' 'Custom scope tags' '' 'Unavailable' $_.Exception.Message}

 # ---------- Applications: install summary, required apps failing, unassigned apps, Win32 supersedence ----------
 $requiredAppIds=@{}
 foreach($a in @($appList)){
  if($a.PSObject.Properties['assignments'] -and @($a.assignments | Where-Object {(AsText $_.intent) -eq 'required'}).Count){$requiredAppIds[(AsText $a.id).ToLowerInvariant()]=$true}
 }
 if($SkipAppStatuses){$collection['App install summary']='Skipped'}else{
  try{
   $agg=@(Get-IntuneReportRows -ReportName 'AppInstallStatusAggregate')
   if($agg.Count -gt 0){
    $f0=$agg[0]
    $cId=Get-NoncomplianceColumn $f0 '^(ApplicationId|AppId)$'
    $cName=Get-NoncomplianceColumn $f0 '^(DisplayName|AppName|ApplicationName)$'
    $cPlat=Get-NoncomplianceColumn $f0 '^(Platform|AppPlatform)$'
    $cInst=Get-NoncomplianceColumn $f0 '^(InstalledDeviceCount|Installed)$'
    $cFail=Get-NoncomplianceColumn $f0 '^(FailedDeviceCount|Failed)$'
    $cPend=Get-NoncomplianceColumn $f0 '^(PendingInstallDeviceCount|Pending)$'
    $cNot=Get-NoncomplianceColumn $f0 '^(NotInstalledDeviceCount|NotInstalled)$'
    foreach($r in $agg){
     $installed=if($cInst){ConvertTo-IntOrZero $r.$cInst}else{0}
     $failed=if($cFail){ConvertTo-IntOrZero $r.$cFail}else{0}
     $pending=if($cPend){ConvertTo-IntOrZero $r.$cPend}else{0}
     $notInstalled=if($cNot){ConvertTo-IntOrZero $r.$cNot}else{0}
     $targeted=$installed+$failed+$pending+$notInstalled
     $failedPct=if($targeted -gt 0){[Math]::Round(100*$failed/$targeted,1)}else{0}
     $appId=if($cId){AsText $r.$cId}else{''}
     $isRequired=$requiredAppIds.ContainsKey($appId.ToLowerInvariant())
     $appAggregateRows.Add([pscustomobject]@{App=$(if($cName){AsText $r.$cName}else{$appId});Platform=$(if($cPlat){AsText $r.$cPlat}else{''});Required=$isRequired;Installed=$installed;Failed=$failed;Pending=$pending;NotInstalled=$notInstalled;FailedPercent=$failedPct;AppId=$appId})
    }
   }
   $collection['App install summary']="Complete ($($appAggregateRows.Count) apps; report AppInstallStatusAggregate)"
   $failingRequired=@($appAggregateRows | Where-Object {$_.Required -and $_.Failed -ge 5 -and $_.FailedPercent -ge 10})
   if($failingRequired.Count){Add-FindingFr 'Medium' 'Applications' 'Required applications fail on many devices' (($failingRequired | Measure-Object Failed -Sum).Sum) ((@($failingRequired | Select-Object -First 8 | ForEach-Object {"$($_.App) ($($_.Failed) devices, $($_.FailedPercent)%)"})) -join '; ') 'Review the install error codes, detection rules and requirements of these apps; failed required apps often block Autopilot or leave users without tools.' 'Des applications requises échouent sur de nombreux appareils' 'Analyser les codes d''erreur, les règles de détection et les exigences de ces applications ; une application requise en échec bloque souvent Autopilot ou prive les utilisateurs d''outils.'}
  }catch{$collection['App install summary']='Unavailable'; $warnings.Add("App install summary (AppInstallStatusAggregate) unavailable: $($_.Exception.Message)")}
 }
 $appsWithAssignInfo=@($appList | Where-Object {$_.PSObject.Properties['assignments']})
 if($appsWithAssignInfo.Count -gt 0){
  $unassignedApps=@($appsWithAssignInfo | Where-Object {@($_.assignments | Where-Object {$null -ne $_}).Count -eq 0 -and (AsText $_.'@odata.type') -notmatch '(?i)managedApp|webApp|officeSuiteApp$'})
  Add-ReviewRow 'Applications' 'Applications without assignment' "$($unassignedApps.Count) of $($appsWithAssignInfo.Count)" $(if($unassignedApps.Count){'Review'}else{'OK'}) ((@($unassignedApps | Select-Object -First 15 | ForEach-Object {AsText $_.displayName})) -join ', ')
  if($unassignedApps.Count -ge 3){Add-FindingFr 'Informational' 'Applications' 'Applications are published in Intune without any assignment' $unassignedApps.Count ((@($unassignedApps | Select-Object -First 10 | ForEach-Object {AsText $_.displayName})) -join '; ') 'Assign or delete unused applications so the catalog only contains packages that are maintained.' 'Des applications sont publiées dans Intune sans aucune assignation' 'Assigner ou supprimer les applications inutilisées pour que le catalogue ne contienne que des paquets maintenus.'}
 }
 try{
  $win32=@(Read-GraphPages -Uri "$beta/deviceAppManagement/mobileApps?`$filter=isof('microsoft.graph.win32LobApp')" -Label 'Win32 apps')
  $groups=@($win32 | Group-Object {Get-AppBaseName (AsText $_.displayName)} | Where-Object {$_.Count -gt 1 -and $_.Name})
  $noSupersedence=@($groups | Where-Object {@($_.Group | Where-Object {(ConvertTo-IntOrZero $_.supersedingAppCount) -gt 0 -or (ConvertTo-IntOrZero $_.supersededAppCount) -gt 0}).Count -eq 0})
  Add-ReviewRow 'Applications' 'Win32 apps with several versions and no supersedence' "$($noSupersedence.Count) of $($groups.Count) multi-version apps" $(if($noSupersedence.Count){'Review'}else{'OK'}) ((@($noSupersedence | Select-Object -First 10 | ForEach-Object {"$($_.Name) ($($_.Count))"})) -join ', ')
  $collection['Win32 supersedence']="Complete ($($win32.Count) Win32 apps)"
  if($noSupersedence.Count){Add-FindingFr 'Low' 'Applications' 'Several Win32 versions of the same application exist without supersedence' $noSupersedence.Count ((@($noSupersedence | Select-Object -First 8 | ForEach-Object {"$($_.Name) ($($_.Count) versions)"})) -join '; ') 'Link new versions to old ones with supersedence (update or replace) and retire old packages, so devices do not keep or reinstall outdated versions.' 'Plusieurs versions Win32 d''une même application existent sans remplacement (supersedence)' 'Lier les nouvelles versions aux anciennes avec le remplacement (mise à jour ou remplacement) et retirer les anciens paquets, pour éviter que des appareils conservent ou réinstallent des versions obsolètes.' 'Heuristic'}
 }catch{$collection['Win32 supersedence']='Unavailable'}

 # ---------- OS updates for every platform ----------
 $driverProfiles=@()
 try{$driverProfiles=@(Read-GraphPages -Uri "$beta/deviceManagement/windowsDriverUpdateProfiles" -Label 'Driver update profiles');$collection['Driver update profiles']="Complete ($($driverProfiles.Count))"}catch{$collection['Driver update profiles']='Unavailable'}
 $winMechanisms=[System.Collections.Generic.List[string]]::new()
 if(@($updateRings).Count){$winMechanisms.Add("$(@($updateRings).Count) update ring(s)")}
 if(@($featureProfiles).Count){$winMechanisms.Add("$(@($featureProfiles).Count) feature update profile(s)")}
 if(@($qualityProfiles).Count){$winMechanisms.Add("$(@($qualityProfiles).Count) expedited quality update profile(s)")}
 if($driverProfiles.Count){$winMechanisms.Add("$($driverProfiles.Count) driver update profile(s)")}
 $updateCoverageRows.Add([pscustomobject]@{Platform='Windows';Devices=$countWin;Mechanism='Windows Update for Business / Autopatch';Policies=($winMechanisms -join '; ');Status=$(if($countWin -eq 0){'No devices'}elseif(@($updateRings).Count -or @($featureProfiles).Count){'Covered'}else{'No update policy'})})
 if($countWin -gt 0 -and $driverProfiles.Count -eq 0 -and $collection['Driver update profiles'] -like 'Complete*'){Add-FindingFr 'Informational' 'Windows Update' 'No Windows driver and firmware update policy' $countWin 'windowsDriverUpdateProfiles returned no profile' 'Create a driver update policy (automatic or manual approval) to control driver and firmware updates from Windows Update.' 'Aucune stratégie de mise à jour des pilotes et micrologiciels Windows' 'Créer une stratégie de mise à jour des pilotes (approbation automatique ou manuelle) pour contrôler les pilotes et micrologiciels distribués par Windows Update.'}
 $appleClassic=@($classic | Where-Object {(AsText $_.'@odata.type') -match 'iosUpdateConfiguration|macOSSoftwareUpdateConfiguration'})
 $ddmRows=@($script:SharedTenantSettingRows | Where-Object {(AsText $_.Platform) -match '(?i)ios|macos' -and (AsText $_.Setting.SettingId) -match '(?i)softwareupdate'})
 $catalogRead=($script:SharedTenantSettingRows.Count -gt 0)
 foreach($apple in @(@('iOS',$countIos,'iosUpdateConfiguration','(?i)ios'),@('macOS',$countMac,'macOSSoftwareUpdateConfiguration','(?i)macos'))){
  $classicFor=@($appleClassic | Where-Object {(AsText $_.'@odata.type') -match $apple[2]})
  $ddmFor=@($ddmRows | Where-Object {(AsText $_.Platform) -match $apple[3]} | ForEach-Object {AsText $_.Setting.Policy} | Select-Object -Unique)
  $names=@(@($classicFor | ForEach-Object {AsText $_.displayName})+$ddmFor)
  $state=if($apple[1] -eq 0){'No devices'}elseif($names.Count){'Covered'}elseif($catalogRead){'No update policy'}else{'Not verified (Settings Catalog not read)'}
  $updateCoverageRows.Add([pscustomobject]@{Platform=$apple[0];Devices=$apple[1];Mechanism='Declarative device management (DDM) or update policy';Policies=($names -join '; ');Status=$state})
  if($state -eq 'No update policy'){Add-FindingFr 'Medium' 'OS updates' "No OS update policy for $($apple[0]) devices" $apple[1] "No $($apple[2]) and no Settings Catalog software update (DDM) setting found" "Create a Settings Catalog policy with the declarative software update settings (enforced version and date) for $($apple[0])." "Aucune stratégie de mise à jour de l'OS pour les appareils $($apple[0])" "Créer une stratégie Settings Catalog avec les paramètres de mise à jour déclaratifs (version et date imposées) pour $($apple[0])."}
 }
 $corpAndroid=@($managed | Where-Object {(AsText $_.deviceEnrollmentType) -match '(?i)androidEnterpriseDedicatedDevice|androidEnterpriseFullyManaged|androidEnterpriseCorporateWorkProfile'}).Count
 $androidUpdatePolicies=@($classic | Where-Object {(AsText $_.'@odata.type') -match 'androidDeviceOwnerGeneralDeviceConfiguration' -and (AsText $_.systemUpdateInstallType) -and (AsText $_.systemUpdateInstallType) -ne 'deviceDefault'})
 $androidState=if($corpAndroid -eq 0){'No corporate devices'}elseif($androidUpdatePolicies.Count){'Covered'}else{'No update policy'}
 $updateCoverageRows.Add([pscustomobject]@{Platform='Android Enterprise (corporate)';Devices=$corpAndroid;Mechanism='System update policy (device restrictions)';Policies=((@($androidUpdatePolicies | ForEach-Object {"$(AsText $_.displayName) ($(AsText $_.systemUpdateInstallType))"})) -join '; ');Status=$androidState})
 if($androidState -eq 'No update policy'){Add-FindingFr 'Low' 'OS updates' 'No system update policy for corporate Android devices' $corpAndroid 'No androidDeviceOwnerGeneralDeviceConfiguration with systemUpdateInstallType other than deviceDefault' 'Set the system update behaviour (automatic or maintenance window) in a device restrictions profile for fully managed, dedicated and corporate work profile devices.' 'Aucune stratégie de mise à jour système pour les appareils Android d''entreprise' 'Définir le comportement des mises à jour système (automatique ou fenêtre de maintenance) dans un profil de restrictions pour les appareils entièrement gérés, dédiés et profil professionnel d''entreprise.'}
 if($countAosp -gt 0){$updateCoverageRows.Add([pscustomobject]@{Platform='Android AOSP';Devices=$countAosp;Mechanism='OEM firmware (not managed by Intune update policies)';Policies='';Status='Not assessed (OEM)'})}

 # ---------- Enrollment profiles: Android Enterprise / AOSP tokens, Apple ADE profiles ----------
 try{
  $androidProfiles=@(Read-GraphPages -Uri "$beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles?`$select=id,displayName,enrollmentMode,tokenExpirationDateTime,enrolledDeviceCount" -Label 'Android enrollment profiles')
  foreach($p in $androidProfiles){
   $mode=AsText $p.enrollmentMode
   $days=Get-DaysUntil $p.tokenExpirationDateTime
   $tokenState=if($null -eq $days){'No token'}elseif($days -lt 0){'Expired'}elseif($days -le 30){'Expires within 30 days'}else{'Valid'}
   $enrollProfileRows.Add([pscustomobject]@{Platform=$(if($mode -match '(?i)aosp'){'Android AOSP'}else{'Android Enterprise'});Profile=AsText $p.displayName;Mode=$mode;TokenExpires=$(if(SafeDate $p.tokenExpirationDateTime){ToIso (SafeDate $p.tokenExpirationDateTime)}else{''});DaysLeft=$days;EnrolledDevices=ConvertTo-IntOrZero $p.enrolledDeviceCount;Supervised='';Mandatory='';Status=$tokenState})
  }
  $collection['Android enrollment profiles']="Complete ($($androidProfiles.Count))"
 }catch{$collection['Android enrollment profiles']='Unavailable'}
 try{
  $depTokens=@(Read-GraphPages -Uri "$beta/deviceManagement/depOnboardingSettings" -Label 'ADE tokens (profiles)')
  $depWithId=@($depTokens | Where-Object {AsText $_.id})
  $depBatch=Invoke-GraphBatchGet -Urls @($depWithId | ForEach-Object {"/deviceManagement/depOnboardingSettings/$($_.id)/enrollmentProfiles"}) -Version 'beta' -Label 'Apple ADE enrollment profiles'
  for($k=0;$k -lt $depWithId.Count;$k++){
   foreach($p in @(Get-BatchCollection -Result $depBatch[$k] -Label 'Apple ADE enrollment profiles')){
    $isIos=((AsText $p.'@odata.type') -match '(?i)ios')
    $supervised=if($isIos){AsText $p.supervisedModeEnabled}else{'n/a'}
    $enrollProfileRows.Add([pscustomobject]@{Platform=$(if($isIos){'iOS (ADE)'}else{'macOS (ADE)'});Profile=AsText $p.displayName;Mode=$(if((AsText $p.requiresUserAuthentication) -eq 'True'){'User affinity'}else{'No user affinity'});TokenExpires='';DaysLeft=$null;EnrolledDevices=$null;Supervised=$supervised;Mandatory=AsText $p.isMandatory;Status=$(if($isIos -and $supervised -eq 'False'){'Not supervised'}else{'OK'})})
   }
  }
  $collection['Apple ADE profiles']="Complete ($($depWithId.Count) tokens)"
 }catch{$collection['Apple ADE profiles']='Unavailable'}
 $expiredTokens=@($enrollProfileRows | Where-Object {$_.Status -eq 'Expired'})
 $soonTokens=@($enrollProfileRows | Where-Object {$_.Status -eq 'Expires within 30 days' -and $_.EnrolledDevices -gt 0})
 $unsupervised=@($enrollProfileRows | Where-Object {$_.Status -eq 'Not supervised'})
 if($soonTokens.Count){Add-FindingFr 'Low' 'Enrollment' 'Android enrollment tokens in use expire within 30 days' $soonTokens.Count ((@($soonTokens | ForEach-Object {"$($_.Profile) ($($_.DaysLeft) d)"})) -join '; ') 'Renew the tokens (or the QR codes printed for staging) before they expire to avoid enrollment failures.' 'Des jetons d''inscription Android utilisés expirent dans moins de 30 jours' 'Renouveler les jetons (ou les codes QR imprimés pour la préparation) avant leur expiration pour éviter les échecs d''inscription.'}
 if($expiredTokens.Count){Add-FindingFr 'Informational' 'Enrollment' 'Android enrollment profiles have an expired token' $expiredTokens.Count ((@($expiredTokens | ForEach-Object {$_.Profile})) -join '; ') 'Regenerate the token if the profile is still used, otherwise delete the profile.' 'Des profils d''inscription Android ont un jeton expiré' 'Régénérer le jeton si le profil est encore utilisé, sinon supprimer le profil.'}
 if($unsupervised.Count){Add-FindingFr 'Medium' 'Enrollment' 'Apple ADE profiles enroll iOS devices without supervision' $unsupervised.Count ((@($unsupervised | ForEach-Object {$_.Profile})) -join '; ') 'Enable supervised mode in ADE profiles: most iOS security restrictions and silent app installs require supervision.' 'Des profils ADE Apple inscrivent des appareils iOS sans supervision' 'Activer le mode supervisé dans les profils ADE : la plupart des restrictions de sécurité iOS et l''installation silencieuse des applications l''exigent.'}

 # ---------- Intune Suite: Endpoint Privilege Management, Remote Help, Cloud PKI ----------
 $epmPolicies=@($endpointSecurity | Where-Object {$_.Family -eq 'Endpoint Privilege Management'}).Count
 Add-ReviewRow 'Intune Suite' 'Endpoint Privilege Management policies' "$epmPolicies" $(if($epmPolicies){'Configured'}else{'Not configured'}) 'Requires an Intune Suite or EPM licence'
 try{
  $rh=Invoke-GraphJson -Uri "$beta/deviceManagement/remoteAssistanceSettings" -Label 'Remote Help'
  $rhState=AsText $rh.remoteAssistanceState
  Add-ReviewRow 'Intune Suite' 'Remote Help' $rhState $(if($rhState -eq 'enabled'){'Configured'}else{'Not configured'}) ('Unenrolled devices allowed: '+(AsText $rh.allowSessionsToUnenrolledDevices))
 }catch{Add-ReviewRow 'Intune Suite' 'Remote Help' '' 'Unavailable' $_.Exception.Message}
 try{
  $cas=@(Read-GraphPages -Uri "$beta/deviceManagement/cloudCertificationAuthority" -Label 'Cloud PKI')
  foreach($ca in $cas){
   $caName=AsText $ca.displayName
   Add-ConnectorRow 'Cloud PKI certification authority' $caName (AsText $ca.certificationAuthorityStatus) $ca.validityEndDateTime $ca.lastModifiedDateTime
   $caDays=Get-DaysUntil $ca.validityEndDateTime
   if($null -ne $caDays -and $caDays -ge 0 -and $caDays -le 180){Add-FindingFr 'Medium' 'Intune Suite' 'Cloud PKI certification authority expires within 180 days' 1 "$caName ($caDays days)" 'Plan the CA renewal and the redeployment of trusted certificate and SCEP profiles before expiry.' 'Une autorité de certification Cloud PKI expire dans moins de 180 jours' 'Planifier le renouvellement de l''autorité et le redéploiement des profils de certificat approuvé et SCEP avant l''expiration.'}
  }
  Add-ReviewRow 'Intune Suite' 'Cloud PKI certification authorities' "$($cas.Count)" $(if($cas.Count){'Configured'}else{'Not configured'}) ((@($cas | ForEach-Object {AsText $_.displayName})) -join ', ')
 }catch{Add-ReviewRow 'Intune Suite' 'Cloud PKI certification authorities' '' 'Unavailable' $_.Exception.Message}

 # ---------- Endpoint analytics ----------
 try{
  $ea=Invoke-GraphJson -Uri "$beta/deviceManagement/userExperienceAnalyticsOverview" -Label 'Endpoint analytics'
  $eaScore=ConvertTo-IntOrZero $ea.overallScore
  Add-ReviewRow 'Operations' 'Endpoint analytics score' "$eaScore" $(if($eaScore -gt 0){'Configured'}else{'Not configured'}) ('State: '+(AsText $ea.state))
  $collection['Endpoint analytics']='Complete'
  if($eaScore -gt 0 -and $eaScore -lt 50){Add-FindingFr 'Low' 'Operations' 'Endpoint analytics overall score is below 50' $eaScore "userExperienceAnalyticsOverview.overallScore = $eaScore" 'Review startup performance and application reliability in Endpoint analytics and act on the lowest scoring models and apps.' 'Le score global Endpoint analytics est inférieur à 50' 'Analyser les performances de démarrage et la fiabilité des applications dans Endpoint analytics et agir sur les modèles et applications les moins bien notés.'}
 }catch{$collection['Endpoint analytics']='Unavailable'}

 # ---------- Intune audit log: destructive device actions ----------
 if($SkipAuditLog){$collection['Intune audit log']='Skipped'}else{
  try{
   $since=$now.AddDays(-$AuditDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
   $events=@(Read-GraphPages -Uri "$base/deviceManagement/auditEvents?`$filter=activityDateTime ge $since" -Label 'Intune audit log')
   foreach($ev in $events){
    $text=((AsText $ev.activity)+' '+(AsText $ev.activityType)+' '+(AsText $ev.displayName))
    $action=switch -Regex ($text){
     '(?i)wipe'{'Wipe';break}
     '(?i)retire'{'Retire';break}
     '(?i)(autopilot reset|fresh ?start|factory reset)'{'Reset';break}
     '(?i)delete.*manageddevice|manageddevice.*delete|remove.*manageddevice'{'Delete device';break}
     default{''}
    }
    if(-not $action){continue}
    $actor=AsText $ev.actor.userPrincipalName
    if(-not $actor){$actor=AsText $ev.actor.applicationDisplayName}
    $target=(@($ev.resources | ForEach-Object {AsText $_.displayName}) -join ', ')
    $auditRows.Add([pscustomobject]@{Date=$(if(SafeDate $ev.activityDateTime){ToIso (SafeDate $ev.activityDateTime)}else{''});Action=$action;Actor=$actor;Target=$target;Result=AsText $ev.activityResult;Activity=AsText $ev.activity})
   }
   $collection['Intune audit log']="Complete ($($events.Count) events in $AuditDays days)"
   $wipeCount=@($auditRows | Where-Object {$_.Action -in @('Wipe','Delete device','Reset')}).Count
   if($auditRows.Count){
    $summaryText=(@($auditRows | Group-Object Action | ForEach-Object {"$($_.Name): $($_.Count)"}) -join ', ')
    Add-FindingFr 'Informational' 'Operations' "Destructive device actions were performed in the last $AuditDays days" $auditRows.Count $summaryText 'Confirm each action was requested and approved; keep the audit export as evidence.' "Des actions destructives sur des appareils ont été effectuées au cours des $AuditDays derniers jours" 'Confirmer que chaque action a été demandée et approuvée ; conserver l''export d''audit comme preuve.'
   }
   if($wipeCount -gt 0 -and $collection['Multi-admin approval'] -eq 'Complete' -and @($maaRows).Count -eq 0){Add-FindingFr 'Medium' 'Operations' 'Wipe, reset or delete actions were performed without multi-admin approval' $wipeCount 'Intune audit log; no operationApprovalPolicies configured' 'Protect wipe, reset and delete with multi-admin approval so one compromised admin account cannot erase devices.' 'Des effacements, réinitialisations ou suppressions ont été effectués sans approbation multi-administrateurs' 'Protéger l''effacement, la réinitialisation et la suppression par l''approbation multi-administrateurs pour qu''un seul compte compromis ne puisse pas effacer les appareils.'}
  }catch{$collection['Intune audit log']='Unavailable';$warnings.Add("Intune audit log unavailable: $($_.Exception.Message)")}
 }
 $collection['Intune configuration review']="Complete ($($tenantReviewRows.Count) checks)"
}

# =====================================================================================
# SECTION 6d - Zero Trust Assessment: Devices pillar (v3.73)
# Re-implements the Microsoft Zero Trust Assessment device tests from the Intune data already
# collected in this run, plus a few read-only lookups. Results are shown in the Zero Trust view;
# they do not change the maturity score. Pass = matching policy found AND assigned.
# =====================================================================================
$ztRows=[System.Collections.Generic.List[object]]::new()
function Get-ZtValue([string]$Name){ return (Get-Variable -Name $Name -Scope Script -ValueOnly -ErrorAction SilentlyContinue) }
function Get-ZtAssignedCount($Item,$Lookup){
 if($null -eq $Item){return $null}
 if($Item.PSObject.Properties['assignments']){return @($Item.assignments | Where-Object {$null -ne $_}).Count}
 $itemId=[string]$Item.id
 if($itemId -and $Lookup.ContainsKey($itemId)){return $Lookup[$itemId]}
 return $null
}
if($SkipZeroTrust){
 $collection['Zero Trust device tests']='Skipped'
}else{
 Say 'Evaluating Zero Trust Assessment device tests...'
 $ztDeviceCount=@{}
 foreach($d in @(Get-ZtValue 'devices')){
  $ztPlat=[string]$d.Platform
  if(-not $ztPlat){$ztPlat=[string]$d.OS}
  if($ztPlat -match '(?i)^android'){$ztPlat='Android'}
  $ztDeviceCount[$ztPlat]=1+[int]$ztDeviceCount[$ztPlat]
 }
 $ztAssign=@{}
 foreach($p in @(Get-ZtValue 'policyInventory')){
  if(-not $p.Id){continue}
  $ztAssign[[string]$p.Id]=if($p.AssignmentCoverage -eq 'Complete'){[int]$p.Assignments}else{$null}
 }
 $ztCatalogKnown=($collection['Settings catalog policies'] -eq 'Complete')
 $ztSettingsByPolicy=@{}
 $ztSettingsKnown=$false
 foreach($r in @(Get-ZtValue 'SharedTenantSettingRows')){
  $ztSettingsKnown=$true
  $polId=[string]$r.Setting.File
  if(-not $polId){continue}
  if(-not $ztSettingsByPolicy.ContainsKey($polId)){$ztSettingsByPolicy[$polId]=[System.Collections.Generic.List[string]]::new()}
  $ztSettingsByPolicy[$polId].Add(([string]$r.Setting.SettingId).ToLowerInvariant())
 }
 $ztSettingsUnknown=(-not $ztCatalogKnown) -or (-not $ztSettingsKnown)
 $ztCatalog=@(foreach($c in @(Get-ZtValue 'catalog')){
  $cid=AsText $c.id
  if(-not $cid){continue}
  $cName=AsText $c.name
  if(-not $cName){$cName=AsText $c.displayName}
  $cCount=Get-ZtAssignedCount $c $ztAssign
  [pscustomobject]@{Id=$cid;Name=$cName;Platforms=(AsText $c.platforms);Family=(AsText $c.templateReference.templateFamily);Template=(AsText $c.templateReference.templateDisplayName);Assigned=$cCount}
 })
 $ztClassic=@(foreach($c in @(Get-ZtValue 'classic')){
  $cid=AsText $c.id
  if(-not $cid){continue}
  $cCount=Get-ZtAssignedCount $c $ztAssign
  $cType=(AsText $c.'@odata.type').Replace('#microsoft.graph.','')
  [pscustomobject]@{Id=$cid;Name=(AsText $c.displayName);Type=$cType;Assigned=$cCount;Raw=$c}
 })
 $ztCompliance=@(foreach($c in @(Get-ZtValue 'compliancePolicies')){
  $cCount=Get-ZtAssignedCount $c @{}
  $cType=(AsText $c.'@odata.type').Replace('#microsoft.graph.','')
  [pscustomobject]@{Id=(AsText $c.id);Name=(AsText $c.displayName);Type=$cType;Assigned=$cCount}
 })
 $ztW='(?i)windows'; $ztM='(?i)macos'; $ztI='(?i)^ios'

 function Find-ZtCatalog {
  param([string]$Platform,[string]$Family,[string]$Template,[string]$Setting)
  foreach($c in $ztCatalog){
   if($Platform -and $c.Platforms -notmatch $Platform){continue}
   $hit=$false
   if($Family -and $c.Family -match $Family){$hit=$true}
   if(-not $hit -and $Template -and $c.Template -match $Template){$hit=$true}
   if(-not $hit -and $Setting -and $ztSettingsByPolicy.ContainsKey($c.Id)){
    if(@($ztSettingsByPolicy[$c.Id] | Where-Object {$_ -match $Setting}).Count -gt 0){$hit=$true}
   }
   if($hit){$c}
  }
 }
 function Find-ZtClassic([string]$TypeRegex,[scriptblock]$Filter){
  foreach($c in $ztClassic){
   if($c.Type -notmatch $TypeRegex){continue}
   if($null -eq $Filter -or (& $Filter $c.Raw)){$c}
  }
 }
 function Find-ZtCompliance([string]$TypeRegex){
  foreach($c in $ztCompliance){if($c.Type -match $TypeRegex){$c}}
 }
 function Find-ZtIntent([string]$FamilyRegex,[string]$NameRegex){
  foreach($e in @(Get-ZtValue 'endpointSecurity')){
   if($e.Source -ne 'Endpoint Security intent'){continue}
   if($e.Family -notmatch $FamilyRegex){continue}
   if($NameRegex -and $e.Policy -notmatch $NameRegex){continue}
   $eCount=if($e.AssignmentCoverage -eq 'Complete'){[int]$e.Assignments}else{$null}
   [pscustomobject]@{Name=$e.Policy;Assigned=$eCount}
  }
 }
 function Add-ZtTest {
  param([string]$Id,[string]$Category,[string]$Test,[string]$TestFr,[string]$Status,[string]$Evidence,[string]$Policies,[string]$PlatformKey,[string]$Recommendation,[string]$RecommendationFr)
  if($PlatformKey -and [int]$ztDeviceCount[$PlatformKey] -eq 0 -and $Status -ne 'Pass'){
   $Status='Not applicable'
   $Evidence="No managed $PlatformKey device. $Evidence"
  }
  $ztRows.Add([pscustomobject]@{Id=$Id;Category=$Category;Test=$Test;TestFr=$TestFr;Status=$Status;Evidence=$Evidence;Policies=$Policies;Recommendation=$Recommendation;RecommendationFr=$RecommendationFr})
 }
 function Add-ZtFromPolicies {
  param([string]$Id,[string]$Category,[string]$Test,[string]$TestFr,[object[]]$Matched,[bool]$Unverifiable,[string]$PlatformKey,[string]$Rec,[string]$RecFr)
  $m=@($Matched | Where-Object {$null -ne $_})
  $names=(@($m | Select-Object -First 6 | ForEach-Object {[string]$_.Name}) -join '; ')
  $assigned=@($m | Where-Object {$_.Assigned -gt 0})
  $unknown=@($m | Where-Object {$null -eq $_.Assigned})
  if($m.Count -eq 0){
   if($Unverifiable){$st='Not verified';$ev='Settings Catalog content was not collected in this run (baseline comparison skipped or unavailable).'}
   else{$st='Fail';$ev='No matching policy found.'}
  }elseif($assigned.Count -gt 0){
   $st='Pass';$ev=('{0} matching policy(ies), {1} assigned.' -f $m.Count,$assigned.Count)
  }elseif($unknown.Count -gt 0){
   $st='Warning';$ev=('{0} matching policy(ies); assignment could not be verified.' -f $m.Count)
  }else{
   $st='Fail';$ev=('{0} matching policy(ies) found but none is assigned.' -f $m.Count)
  }
  Add-ZtTest -Id $Id -Category $Category -Test $Test -TestFr $TestFr -Status $st -Evidence $ev -Policies $names -PlatformKey $PlatformKey -Recommendation $Rec -RecommendationFr $RecFr
 }

 # ---------- Windows ----------
 $m=@(Find-ZtCatalog -Platform $ztW -Template '(?i)local user group' -Setting 'localusersandgroups')
 Add-ZtFromPolicies -Id 'ZT-W01' -Category 'Windows' -Test 'Intune Local Users and Groups policy is created and assigned' -TestFr "Une stratégie Utilisateurs et groupes locaux est créée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'Windows' -Rec 'Create an Account protection > Local user group membership policy to control local Administrators membership.' -RecFr "Créer une stratégie Protection du compte > Appartenance aux groupes locaux pour contrôler le groupe Administrateurs local."

 $m=@(Find-ZtCatalog -Platform $ztW -Setting 'passportforwork')
 $m+=@(Find-ZtClassic '^windowsIdentityProtectionConfiguration$' $null)
 foreach($cfg in @(Get-ZtValue 'enrollConfigs')){
  if((AsText $cfg.'@odata.type') -match 'WindowsHelloForBusinessConfiguration' -and (AsText $cfg.state) -eq 'enabled'){$m+=[pscustomobject]@{Name='Tenant Windows Hello for Business enrollment setting';Assigned=1}}
 }
 Add-ZtFromPolicies -Id 'ZT-W02' -Category 'Windows' -Test 'Windows Hello for Business Policy is Configured and Assigned' -TestFr "Une stratégie Windows Hello Entreprise est configurée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'Windows' -Rec 'Configure Windows Hello for Business (Settings Catalog or Account protection) and assign it to all Windows devices.' -RecFr "Configurer Windows Hello Entreprise (Settings Catalog ou Protection du compte) et l'assigner à tous les appareils Windows."

 $m=@(Find-ZtCatalog -Platform $ztW -Family 'endpointSecurityApplicationControl' -Template '(?i)application control|app control' -Setting 'applicationcontrol')
 $m+=@(Find-ZtIntent 'Application control' '')
 Add-ZtFromPolicies -Id 'ZT-W03' -Category 'Windows' -Test 'Windows App Control for Business (WDAC) is configured and assigned via Intune' -TestFr "Windows App Control for Business (WDAC) est configuré et assigné par Intune" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'Windows' -Rec 'Deploy an App Control for Business policy (audit mode first, then enforce) with the managed installer option.' -RecFr "Déployer une stratégie App Control for Business (mode audit d'abord, puis application) avec le programme d'installation géré."

 $m=@(Find-ZtCatalog -Platform $ztW -Family 'endpointSecurityEndpointPrivilegeManagement' -Template '(?i)privilege management')
 Add-ZtFromPolicies -Id 'ZT-W04' -Category 'Windows' -Test 'Windows Endpoint Privilege Management is configured and assigned' -TestFr "Endpoint Privilege Management Windows est configuré et assigné" -Matched $m -Unverifiable (-not $ztCatalogKnown) -PlatformKey 'Windows' -Rec 'Configure Endpoint Privilege Management (elevation settings and rules) so standard users can elevate approved apps without admin rights. Requires an EPM or Intune Suite licence.' -RecFr "Configurer Endpoint Privilege Management (paramètres et règles d'élévation) pour élever les applications approuvées sans droits d'administrateur. Nécessite une licence EPM ou Intune Suite."

 $m=@(Find-ZtCatalog -Platform $ztW -Family '(?i)baseline')
 $m+=@(Find-ZtIntent 'Security baseline' '')
 Add-ZtFromPolicies -Id 'ZT-W05' -Category 'Windows' -Test 'Windows Security Baseline is Configured and Assigned' -TestFr "Une baseline de sécurité Windows est configurée et assignée" -Matched $m -Unverifiable (-not $ztCatalogKnown) -PlatformKey 'Windows' -Rec 'Assign a Windows security baseline (Intune security baselines or an equivalent baseline such as OpenIntuneBaseline).' -RecFr "Assigner une baseline de sécurité Windows (baselines de sécurité Intune ou équivalent, comme OpenIntuneBaseline)."

 $m=@(Find-ZtCatalog -Platform $ztW -Template '(?i)laps|local admin password' -Setting '^device_vendor_msft_laps')
 $m+=@(Find-ZtIntent 'Windows LAPS' '')
 Add-ZtFromPolicies -Id 'ZT-W06' -Category 'Windows' -Test 'Windows Cloud LAPS policy is created and assigned' -TestFr "Une stratégie Windows LAPS (cloud) est créée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'Windows' -Rec 'Create an Account protection > Local admin password solution (Windows LAPS) policy with backup to Microsoft Entra ID.' -RecFr "Créer une stratégie Protection du compte > Windows LAPS avec sauvegarde dans Microsoft Entra ID."

 $m=@(Find-ZtCatalog -Platform $ztW -Family 'endpointSecurityAntivirus' -Template '(?i)antivirus')
 $m+=@(Find-ZtIntent 'Defender' '(?i)antivirus|\bav\b')
 Add-ZtFromPolicies -Id 'ZT-W07' -Category 'Windows' -Test 'A Windows Defender Antivirus policy is created and assigned' -TestFr "Une stratégie Microsoft Defender Antivirus Windows est créée et assignée" -Matched $m -Unverifiable (-not $ztCatalogKnown) -PlatformKey 'Windows' -Rec 'Create an Endpoint security > Antivirus policy (real-time protection, cloud protection, PUA) and assign it to all Windows devices.' -RecFr "Créer une stratégie Sécurité des points de terminaison > Antivirus (protection en temps réel, cloud, PUA) et l'assigner à tous les appareils Windows."

 $m=@(Find-ZtCatalog -Platform $ztW -Family 'endpointSecurityAttackSurfaceReduction' -Template '(?i)attack surface' -Setting 'attacksurfacereductionrules')
 $m+=@(Find-ZtIntent 'Attack Surface Reduction' '')
 Add-ZtFromPolicies -Id 'ZT-W08' -Category 'Windows' -Test 'Attack Surface Reduction rules are applied to Windows devices to prevent exploitation of vulnerable system components' -TestFr "Les règles de réduction de la surface d'attaque (ASR) sont appliquées aux appareils Windows" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'Windows' -Rec 'Deploy ASR rules (audit first, then block) with documented exclusions.' -RecFr "Déployer les règles ASR (audit d'abord, puis blocage) avec des exclusions documentées."

 $m=@(Find-ZtCatalog -Platform $ztW -Family 'endpointSecurityFirewall' -Template '(?i)firewall')
 $m+=@(Find-ZtIntent 'Firewall' '')
 Add-ZtFromPolicies -Id 'ZT-W09' -Category 'Windows' -Test 'Windows Firewall Policy is Created and Assigned' -TestFr "Une stratégie Pare-feu Windows est créée et assignée" -Matched $m -Unverifiable (-not $ztCatalogKnown) -PlatformKey 'Windows' -Rec 'Create an Endpoint security > Firewall policy enabling all three profiles and assign it to all Windows devices.' -RecFr "Créer une stratégie Sécurité des points de terminaison > Pare-feu activant les trois profils et l'assigner à tous les appareils Windows."

 $m=@(Find-ZtCatalog -Platform $ztW -Family 'endpointSecurityDiskEncryption' -Template '(?i)bitlocker' -Setting 'bitlocker')
 $m+=@(Find-ZtIntent 'Disk encryption' '')
 $m+=@(Find-ZtClassic '^windows10EndpointProtectionConfiguration$' {param($r) $r.bitLockerEncryptDevice -eq $true})
 Add-ZtFromPolicies -Id 'ZT-W10' -Category 'Windows' -Test 'Data on Windows is protected by BitLocker encryption' -TestFr "Les données Windows sont protégées par le chiffrement BitLocker" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'Windows' -Rec 'Create an Endpoint security > Disk encryption (BitLocker) policy with recovery key backup to Entra ID.' -RecFr "Créer une stratégie Chiffrement de disque (BitLocker) avec sauvegarde de la clé de récupération dans Entra ID."

 $m=@(Find-ZtCompliance '^windows10CompliancePolicy$')
 Add-ZtFromPolicies -Id 'ZT-W11' -Category 'Windows' -Test 'Windows Compliance Policy is Created and Assigned' -TestFr "Une stratégie de conformité Windows est créée et assignée" -Matched $m -Unverifiable ($collection['Compliance policies'] -ne 'Complete') -PlatformKey 'Windows' -Rec 'Create and assign a Windows compliance policy (BitLocker, Secure Boot, Defender, minimum OS).' -RecFr "Créer et assigner une stratégie de conformité Windows (BitLocker, Secure Boot, Defender, OS minimal)."

 $wu=@(foreach($u in @(Get-ZtValue 'updateInventory')){$uCount=if($u.AssignmentCoverage -eq 'Complete'){[int]$u.Assignments}else{$null};[pscustomobject]@{Name=$u.Name;Assigned=$uCount}})
 Add-ZtFromPolicies -Id 'ZT-W12' -Category 'Windows' -Test 'Windows Update policies are enforced to reduce risk from unpatched vulnerabilities' -TestFr "Des stratégies Windows Update sont appliquées pour réduire les risques liés aux vulnérabilités non corrigées" -Matched $wu -Unverifiable ($collection['Classic configuration policies'] -ne 'Complete') -PlatformKey 'Windows' -Rec 'Assign Windows Update rings (or Autopatch) with quality update deadlines, and feature update policies.' -RecFr "Assigner des anneaux Windows Update (ou Autopatch) avec des échéances de mises à jour qualité, ainsi que des stratégies de mises à jour de fonctionnalité."

 $mdmScope=$null
 try{
  $mdmPolicy=Invoke-GraphJson -Uri 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000' -Label 'MDM user scope'
  $mdmScope=AsText $mdmPolicy.appliesTo
 }catch{}
 if(-not $mdmScope){$st='Not verified';$ev='MDM user scope could not be read (Policy.Read.All required).'}
 elseif($mdmScope -eq 'all'){$st='Pass';$ev='MDM user scope: All.'}
 elseif($mdmScope -eq 'selected'){$st='Pass';$ev='MDM user scope: selected groups.'}
 else{$st='Fail';$ev="MDM user scope: $mdmScope."}
 Add-ZtTest -Id 'ZT-W13' -Category 'Windows' -Test 'Windows Automatic Enrollment is enabled' -TestFr "L'inscription automatique Windows est activée" -Status $st -Evidence $ev -Policies '' -PlatformKey '' -Recommendation 'Set Entra ID > Mobility (MDM and WIP) > Microsoft Intune > MDM user scope to All (or the target groups).' -RecommendationFr "Régler Entra ID > Mobilité (MDM et WIP) > Microsoft Intune > Étendue de l'utilisateur MDM sur Tous (ou les groupes cibles)."

 $m=@(Find-ZtClassic '^windowsHealthMonitoringConfiguration$' $null)
 Add-ZtFromPolicies -Id 'ZT-W14' -Category 'Windows' -Test 'Intune Endpoint Analytics policy is created and assigned' -TestFr "Une stratégie Endpoint Analytics est créée et assignée" -Matched $m -Unverifiable ($collection['Classic configuration policies'] -ne 'Complete') -PlatformKey 'Windows' -Rec 'Assign the Intune data collection policy (Windows health monitoring) to enable Endpoint analytics.' -RecFr "Assigner la stratégie de collecte de données Intune (surveillance de l'intégrité Windows) pour activer Endpoint analytics."

 # ---------- macOS ----------
 $m=@(Find-ZtCatalog -Platform $ztM -Family 'endpointSecurityAntivirus' -Template '(?i)antivirus')
 Add-ZtFromPolicies -Id 'ZT-M01' -Category 'macOS' -Test 'A Microsoft Defender Antivirus policy is created and assigned in Intune for macOS' -TestFr "Une stratégie Microsoft Defender Antivirus est créée et assignée pour macOS" -Matched $m -Unverifiable (-not $ztCatalogKnown) -PlatformKey 'macOS' -Rec 'Create an Endpoint security > Antivirus policy for macOS (Defender for Endpoint) and assign it to all Macs.' -RecFr "Créer une stratégie Antivirus macOS (Defender for Endpoint) et l'assigner à tous les Mac."

 $hasAde=@(Get-ZtValue 'connectorRows' | Where-Object {[string]$_.Connector -match 'Automated Device Enrollment'}).Count -gt 0
 $macLaps=@(Find-ZtCatalog -Platform $ztM -Setting '(?i)laps|localadminpassword')
 $adeLaps=[System.Collections.Generic.List[object]]::new()
 if($hasAde){
  try{
   foreach($tok in @(Read-GraphPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings' -Label 'ADE tokens (Zero Trust)')){
    foreach($prof in @(Read-GraphPages -Uri ("https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings/{0}/enrollmentProfiles" -f (AsText $tok.id)) -Label 'ADE profiles (Zero Trust)')){
     if((AsText $prof.'@odata.type') -notmatch '(?i)macos'){continue}
     $adminProps=@($prof.PSObject.Properties | Where-Object {$_.Name -match '(?i)adminAccount' -and (AsText $_.Value) -and (AsText $_.Value) -notin @('False','0','none')})
     if($adminProps.Count){$adeLaps.Add([pscustomobject]@{Name=('ADE profile: '+(AsText $prof.displayName));Assigned=1})}
    }
   }
  }catch{}
 }
 $m=@($macLaps)+@($adeLaps)
 if($m.Count -eq 0 -and -not $hasAde){
  Add-ZtTest -Id 'ZT-M02' -Category 'macOS' -Test 'A macOS Cloud LAPS Policy is Created and Assigned' -TestFr "Une stratégie macOS LAPS (cloud) est créée et assignée" -Status 'Fail' -Evidence 'No Apple ADE token: macOS local admin password management requires Automated Device Enrollment.' -Policies '' -PlatformKey 'macOS' -Recommendation 'Configure a local admin account with password rotation in the macOS ADE enrollment profile.' -RecommendationFr "Configurer un compte administrateur local avec rotation du mot de passe dans le profil d'inscription ADE macOS."
 }else{
  Add-ZtFromPolicies -Id 'ZT-M02' -Category 'macOS' -Test 'A macOS Cloud LAPS Policy is Created and Assigned' -TestFr "Une stratégie macOS LAPS (cloud) est créée et assignée" -Matched $m -Unverifiable $false -PlatformKey 'macOS' -Rec 'Configure a local admin account with password rotation in the macOS ADE enrollment profile.' -RecFr "Configurer un compte administrateur local avec rotation du mot de passe dans le profil d'inscription ADE macOS."
 }

 $m=@(Find-ZtCatalog -Platform $ztM -Family 'endpointSecurityDiskEncryption' -Template '(?i)filevault' -Setting 'filevault')
 $m+=@(Find-ZtClassic '^macOSEndpointProtectionConfiguration$' {param($r) $r.fileVaultEnabled -eq $true})
 Add-ZtFromPolicies -Id 'ZT-M03' -Category 'macOS' -Test 'Intune macOS FileVault policy is created and Assigned' -TestFr "Une stratégie FileVault macOS est créée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'macOS' -Rec 'Create an Endpoint security > Disk encryption (FileVault) policy with recovery key escrow to Intune.' -RecFr "Créer une stratégie Chiffrement de disque (FileVault) avec dépôt de la clé de récupération dans Intune."

 $m=@(Find-ZtCatalog -Platform $ztM -Setting 'softwareupdate')
 $m+=@(Find-ZtClassic '^macOSSoftwareUpdateConfiguration$' $null)
 Add-ZtFromPolicies -Id 'ZT-M04' -Category 'macOS' -Test 'macOS update policy is configured and assigned' -TestFr "Une stratégie de mise à jour macOS est configurée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'macOS' -Rec 'Configure declarative software update settings (target version and date) in a Settings Catalog policy.' -RecFr "Configurer les paramètres de mise à jour déclaratifs (version et date cibles) dans une stratégie Settings Catalog."

 $m=@(Find-ZtClassic '^macOSEnterpriseWiFiConfiguration$' $null)
 $m+=@(Find-ZtClassic '^macOSWiFiConfiguration$' {param($r) (AsText $r.wiFiSecurityType) -match '(?i)enterprise'})
 Add-ZtFromPolicies -Id 'ZT-M05' -Category 'macOS' -Test 'Corporate Wi-Fi Network on macOS Devices is Securely Managed' -TestFr "Le réseau Wi-Fi d'entreprise des appareils macOS est géré de façon sécurisée" -Matched $m -Unverifiable ($collection['Classic configuration policies'] -ne 'Complete') -PlatformKey 'macOS' -Rec 'Deploy an enterprise (802.1X, certificate-based) Wi-Fi profile for macOS instead of a pre-shared key.' -RecFr "Déployer un profil Wi-Fi d'entreprise macOS (802.1X par certificat) plutôt qu'une clé partagée."

 $m=@(Find-ZtCompliance '^macOSCompliancePolicy$')
 Add-ZtFromPolicies -Id 'ZT-M06' -Category 'macOS' -Test 'macOS Compliance Policy is Created and Assigned' -TestFr "Une stratégie de conformité macOS est créée et assignée" -Matched $m -Unverifiable ($collection['Compliance policies'] -ne 'Complete') -PlatformKey 'macOS' -Rec 'Create and assign a macOS compliance policy (FileVault, firewall, minimum OS, password).' -RecFr "Créer et assigner une stratégie de conformité macOS (FileVault, pare-feu, OS minimal, mot de passe)."

 $m=@(Find-ZtCatalog -Platform $ztM -Family 'endpointSecurityFirewall' -Template '(?i)firewall' -Setting 'com\.apple\.security\.firewall')
 $m+=@(Find-ZtClassic '^macOSEndpointProtectionConfiguration$' {param($r) $r.firewallEnabled -eq $true})
 Add-ZtFromPolicies -Id 'ZT-M07' -Category 'macOS' -Test 'macOS - Firewall policy is created and assigned' -TestFr "macOS : une stratégie de pare-feu est créée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'macOS' -Rec 'Create an Endpoint security > macOS firewall policy (enable firewall, stealth mode) and assign it.' -RecFr "Créer une stratégie de pare-feu macOS (pare-feu et mode furtif activés) et l'assigner."

 $m=@(Find-ZtCatalog -Platform $ztM -Setting 'extensiblesso|platformsso')
 Add-ZtFromPolicies -Id 'ZT-M08' -Category 'macOS' -Test 'macOS - Platform SSO is configured and assigned' -TestFr "macOS : Platform SSO est configuré et assigné" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'macOS' -Rec 'Configure Platform SSO (Extensible Single Sign-On with the Company Portal SSO extension) in a Settings Catalog policy.' -RecFr "Configurer Platform SSO (Extensible Single Sign-On avec l'extension SSO du Portail d'entreprise) dans une stratégie Settings Catalog."

 # ---------- iOS / iPadOS ----------
 $m=@(Find-ZtClassic '^iosEnterpriseWiFiConfiguration$' $null)
 $m+=@(Find-ZtClassic '^iosWiFiConfiguration$' {param($r) (AsText $r.wiFiSecurityType) -match '(?i)enterprise'})
 Add-ZtFromPolicies -Id 'ZT-I01' -Category 'iOS' -Test 'Corporate Wi-Fi network on iOS devices is securely managed' -TestFr "Le réseau Wi-Fi d'entreprise des appareils iOS est géré de façon sécurisée" -Matched $m -Unverifiable ($collection['Classic configuration policies'] -ne 'Complete') -PlatformKey 'iOS' -Rec 'Deploy an enterprise (802.1X, certificate-based) Wi-Fi profile for iOS/iPadOS.' -RecFr "Déployer un profil Wi-Fi d'entreprise iOS/iPadOS (802.1X par certificat)."

 $m=@(Find-ZtClassic '^iosUpdateConfiguration$' $null)
 $m+=@(Find-ZtCatalog -Platform $ztI -Setting 'softwareupdate')
 Add-ZtFromPolicies -Id 'ZT-I02' -Category 'iOS' -Test 'An iOS update policy is created and assigned' -TestFr "Une stratégie de mise à jour iOS est créée et assignée" -Matched $m -Unverifiable $ztSettingsUnknown -PlatformKey 'iOS' -Rec 'Configure declarative software update settings (or an iOS update policy) for supervised devices.' -RecFr "Configurer les mises à jour déclaratives (ou une stratégie de mise à jour iOS) pour les appareils supervisés."

 $m=@(Find-ZtCompliance '^iosCompliancePolicy$')
 Add-ZtFromPolicies -Id 'ZT-I03' -Category 'iOS' -Test 'Compliance policy assignment for iOS/iPadOS devices' -TestFr "Une stratégie de conformité iOS/iPadOS est assignée" -Matched $m -Unverifiable ($collection['Compliance policies'] -ne 'Complete') -PlatformKey 'iOS' -Rec 'Create and assign an iOS/iPadOS compliance policy (minimum OS, passcode, jailbreak detection).' -RecFr "Créer et assigner une stratégie de conformité iOS/iPadOS (OS minimal, code d'accès, détection de jailbreak)."

 $mamIos=@(foreach($r in @(Get-ZtValue 'mamRows')){if($r.Platform -eq 'iOS'){[pscustomobject]@{Name=$r.Policy;Assigned=$r.Assignments}}})
 $mamKnown=([string]$collection['App protection policies']) -like 'Complete*'
 Add-ZtFromPolicies -Id 'ZT-I04' -Category 'iOS' -Test 'An app protection policy for iOS devices exists' -TestFr "Une stratégie de protection des applications iOS existe" -Matched $mamIos -Unverifiable (-not $mamKnown) -PlatformKey '' -Rec 'Create an iOS app protection policy (PIN, no backup, restricted copy/paste) and assign it to all users.' -RecFr "Créer une stratégie de protection des applications iOS (code PIN, pas de sauvegarde, copier-coller restreint) et l'assigner à tous les utilisateurs."

 # ---------- Android ----------
 $m=@(Find-ZtClassic '(?i)^(android|aosp).*EnterpriseWiFiConfiguration$' $null)
 Add-ZtFromPolicies -Id 'ZT-A01' -Category 'Android' -Test 'Secure Wi-Fi profiles protect Android devices from unauthorized network access' -TestFr "Des profils Wi-Fi sécurisés protègent les appareils Android des accès réseau non autorisés" -Matched $m -Unverifiable ($collection['Classic configuration policies'] -ne 'Complete') -PlatformKey 'Android' -Rec 'Deploy an enterprise (802.1X, certificate-based) Wi-Fi profile for Android Enterprise devices.' -RecFr "Déployer un profil Wi-Fi d'entreprise (802.1X par certificat) pour les appareils Android Enterprise."

 $m=@(Find-ZtCompliance '^androidDeviceOwnerCompliancePolicy$')
 Add-ZtFromPolicies -Id 'ZT-A02' -Category 'Android' -Test 'Compliance policy assignment for Android Enterprise Fully managed device is configured and assigned' -TestFr "Une stratégie de conformité Android Enterprise entièrement géré est configurée et assignée" -Matched $m -Unverifiable ($collection['Compliance policies'] -ne 'Complete') -PlatformKey 'Android' -Rec 'Create and assign a compliance policy for fully managed, dedicated and corporate work profile devices.' -RecFr "Créer et assigner une stratégie de conformité pour les appareils entièrement gérés, dédiés et profil professionnel d'entreprise."

 $m=@(Find-ZtCompliance '^androidWorkProfileCompliancePolicy$')
 Add-ZtFromPolicies -Id 'ZT-A03' -Category 'Android' -Test 'Compliance Policy for Android Enterprise Personally-Owned Work Profile is configured and assigned' -TestFr "Une stratégie de conformité Android Enterprise profil professionnel personnel est configurée et assignée" -Matched $m -Unverifiable ($collection['Compliance policies'] -ne 'Complete') -PlatformKey 'Android' -Rec 'Create and assign a compliance policy for personally-owned work profile devices.' -RecFr "Créer et assigner une stratégie de conformité pour les appareils personnels avec profil professionnel."

 $mamAnd=@(foreach($r in @(Get-ZtValue 'mamRows')){if($r.Platform -eq 'Android'){[pscustomobject]@{Name=$r.Policy;Assigned=$r.Assignments}}})
 Add-ZtFromPolicies -Id 'ZT-A04' -Category 'Android' -Test 'An app protection policy for Android devices exists' -TestFr "Une stratégie de protection des applications Android existe" -Matched $mamAnd -Unverifiable (-not $mamKnown) -PlatformKey '' -Rec 'Create an Android app protection policy (PIN, no backup, restricted copy/paste) and assign it to all users.' -RecFr "Créer une stratégie de protection des applications Android (code PIN, pas de sauvegarde, copier-coller restreint) et l'assigner à tous les utilisateurs."

 $mde=@(Get-ZtValue 'mtdConnectors' | Where-Object {(AsText $_.id) -eq 'fc780465-2017-40d4-a0c5-307022471b92'}) | Select-Object -First 1
 if($null -eq $mde){$st=if($collection['Connectors and tokens'] -like 'Complete*'){'Fail'}else{'Not verified'};$ev='Microsoft Defender for Endpoint connector not found.'}
 elseif((AsText $mde.partnerState) -eq 'enabled' -and $mde.androidEnabled -eq $true){$st='Pass';$ev='Defender for Endpoint connector enabled for Android.'}
 else{$st='Fail';$ev=('Defender connector state: {0}; Android enabled: {1}' -f (AsText $mde.partnerState),(AsText $mde.androidEnabled))}
 Add-ZtTest -Id 'ZT-A05' -Category 'Android' -Test 'Automatic Enrollment to Defender is enabled for Android Devices' -TestFr "L'intégration automatique à Defender est activée pour les appareils Android" -Status $st -Evidence $ev -Policies '' -PlatformKey 'Android' -Recommendation 'Enable Android in the Microsoft Defender for Endpoint connector and deploy the Defender app with auto-onboarding.' -RecommendationFr "Activer Android dans le connecteur Microsoft Defender for Endpoint et déployer l'application Defender avec intégration automatique."

 # ---------- Tenant ----------
 $pimEligible=$null
 try{$pimEligible=@(Read-GraphPages -Uri "$base/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '3a2c62db-5318-420d-8d74-23affee5d9d5'" -Label 'PIM eligibility (Intune Administrator)').Count}catch{}
 $roleCountsZt=Get-ZtValue 'roleCounts'
 $pimActive=if($roleCountsZt -and $roleCountsZt.ContainsKey('Intune Administrator')){[int]$roleCountsZt['Intune Administrator']}else{$null}
 if($null -eq $pimEligible){$st='Not verified';$ev='PIM eligibility could not be read (RoleManagement.Read.Directory and Entra ID P2 required).'}
 elseif($pimEligible -gt 0 -and $pimActive -eq 0){$st='Pass';$ev="$pimEligible eligible assignment(s), no active assignment."}
 elseif($pimEligible -gt 0){$st='Warning';$ev="$pimEligible eligible assignment(s), $pimActive active (permanent or currently activated)."}
 else{$st='Fail';$ev="No eligible assignment; active assignments: $pimActive."}
 Add-ZtTest -Id 'ZT-T01' -Category 'Tenant' -Test 'Privileged Identity Management is enforced for Intune Administrator role assignments' -TestFr "Privileged Identity Management est imposé pour les attributions du rôle Administrateur Intune" -Status $st -Evidence $ev -Policies '' -PlatformKey '' -Recommendation 'Convert permanent Intune Administrator assignments to PIM eligible assignments with approval and MFA on activation.' -RecommendationFr "Convertir les attributions permanentes Administrateur Intune en attributions éligibles PIM avec approbation et MFA à l'activation."

 $caKnown=($collection['Conditional Access'] -eq 'Complete')
 $caDev=@(Get-ZtValue 'caRows' | Where-Object {$_.RequiresCompliantDevice})
 $caOn=@($caDev | Where-Object {$_.State -eq 'enabled'})
 if(-not $caKnown){$st='Not verified';$ev='Conditional Access not collected.'}
 elseif($caOn.Count){$st='Pass';$ev=('{0} enabled policy(ies) require a compliant device.' -f $caOn.Count)}
 elseif($caDev.Count){$st='Warning';$ev='Device compliance is required only in report-only or disabled policies.'}
 else{$st='Fail';$ev='No Conditional Access policy requires a compliant device.'}
 $caNames=(@($caDev | Select-Object -First 6 | ForEach-Object {$_.Policy}) -join '; ')
 Add-ZtTest -Id 'ZT-T02' -Category 'Tenant' -Test 'Non-compliant Devices are Restricted from Accessing Corporate Data' -TestFr "Les appareils non conformes ne peuvent pas accéder aux données de l'entreprise" -Status $st -Evidence $ev -Policies $caNames -PlatformKey '' -Recommendation 'Enforce a Conditional Access policy requiring a compliant device for corporate apps.' -RecommendationFr "Appliquer une stratégie d'accès conditionnel exigeant un appareil conforme pour les applications de l'entreprise."

 $caApp=@(Get-ZtValue 'caRows' | Where-Object {$_.RequiresAppProtection})
 $caAppOn=@($caApp | Where-Object {$_.State -eq 'enabled'})
 if(-not $caKnown){$st='Not verified';$ev='Conditional Access not collected.'}
 elseif($caAppOn.Count){$st='Pass';$ev=('{0} enabled policy(ies) require an app protection policy or approved app.' -f $caAppOn.Count)}
 elseif($caApp.Count){$st='Warning';$ev='App protection is required only in report-only or disabled policies.'}
 else{$st='Fail';$ev='No Conditional Access policy requires app protection.'}
 $caAppNames=(@($caApp | Select-Object -First 6 | ForEach-Object {$_.Policy}) -join '; ')
 Add-ZtTest -Id 'ZT-T03' -Category 'Tenant' -Test 'Unmanaged and unprotected Apps are restricted from Accessing Corporate Data' -TestFr "Les applications non gérées et non protégées ne peuvent pas accéder aux données de l'entreprise" -Status $st -Evidence $ev -Policies $caAppNames -PlatformKey '' -Recommendation 'Enforce a Conditional Access policy requiring an app protection policy on iOS and Android.' -RecommendationFr "Appliquer une stratégie d'accès conditionnel exigeant une stratégie de protection des applications sur iOS et Android."

 try{
  $termsZt=@(Read-GraphPages -Uri "$base/deviceManagement/termsAndConditions?`$expand=assignments" -Label 'Terms and conditions (Zero Trust)')
  $m=@(foreach($t in $termsZt){$tCount=@($t.assignments | Where-Object {$null -ne $_}).Count;[pscustomobject]@{Name=(AsText $t.displayName);Assigned=$tCount}})
  Add-ZtFromPolicies -Id 'ZT-T04' -Category 'Tenant' -Test 'Intune Terms and Conditions Policy is configured and assigned' -TestFr "Les conditions générales Intune sont configurées et assignées" -Matched $m -Unverifiable $false -PlatformKey '' -Rec 'Create Intune terms and conditions (or Entra terms of use) and assign them to enrolling users.' -RecFr "Créer des conditions générales Intune (ou des conditions d'utilisation Entra) et les assigner aux utilisateurs qui inscrivent un appareil."
 }catch{Add-ZtTest -Id 'ZT-T04' -Category 'Tenant' -Test 'Intune Terms and Conditions Policy is configured and assigned' -TestFr "Les conditions générales Intune sont configurées et assignées" -Status 'Not verified' -Evidence $_.Exception.Message -Policies '' -PlatformKey '' -Recommendation 'Create Intune terms and conditions and assign them.' -RecommendationFr "Créer des conditions générales Intune et les assigner."}

 try{
  $tagsZt=@(Read-GraphPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/roleScopeTags' -Label 'Scope tags (Zero Trust)')
  $customTagsZt=@($tagsZt | Where-Object {(AsText $_.id) -ne '0'})
  $usedTagsZt=@(Get-ZtValue 'rbacRows' | Where-Object {$_.Source -eq 'Intune RBAC'} | ForEach-Object {@(([string]$_.ScopeTags) -split ',\s*')} | Where-Object {$_ -and $_ -ne '0'} | Select-Object -Unique)
  if($customTagsZt.Count -eq 0){$st='Fail';$ev='Only the Default scope tag exists.'}
  elseif($usedTagsZt.Count){$st='Pass';$ev=('{0} custom scope tag(s), {1} used in Intune role assignments.' -f $customTagsZt.Count,$usedTagsZt.Count)}
  else{$st='Warning';$ev=('{0} custom scope tag(s), none used in Intune role assignments.' -f $customTagsZt.Count)}
  $tagNamesZt=(@($customTagsZt | Select-Object -First 8 | ForEach-Object {AsText $_.displayName}) -join '; ')
 }catch{$st='Not verified';$ev=$_.Exception.Message;$tagNamesZt=''}
 Add-ZtTest -Id 'ZT-T05' -Category 'Tenant' -Test 'Intune Scope Tags are Configured for Delegated Administration' -TestFr "Des balises d'étendue Intune sont configurées pour l'administration déléguée" -Status $st -Evidence $ev -Policies $tagNamesZt -PlatformKey '' -Recommendation 'Create scope tags per site or team and use them in Intune role assignments.' -RecommendationFr "Créer des balises d'étendue par site ou par équipe et les utiliser dans les attributions de rôles Intune."

 try{
  $brandsZt=@(Read-GraphPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles' -Label 'Company Portal branding')
  $defBrand=@($brandsZt | Where-Object {$_.isDefaultProfile -eq $true}) | Select-Object -First 1
  if($null -eq $defBrand){$defBrand=$brandsZt | Select-Object -First 1}
  $brandFields=@('contactITName','contactITPhoneNumber','contactITEmailAddress','onlineSupportSiteUrl','privacyUrl')
  $setFields=@($brandFields | Where-Object {$defBrand -and (AsText $defBrand.$_)})
  if($setFields.Count -ge 2){$st='Pass'}elseif($setFields.Count -eq 1){$st='Warning'}else{$st='Fail'}
  $ev=if($setFields.Count){'Configured: '+($setFields -join ', ')}else{'No support contact or privacy URL configured.'}
 }catch{$st='Not verified';$ev=$_.Exception.Message}
 Add-ZtTest -Id 'ZT-T06' -Category 'Tenant' -Test 'Company Portal branding and support settings enhance user experience and trust' -TestFr "La personnalisation et le support du Portail d'entreprise renforcent l'expérience et la confiance des utilisateurs" -Status $st -Evidence $ev -Policies '' -PlatformKey '' -Recommendation 'Set the company name, logo, IT contact, support website and privacy URL in Tenant administration > Customization.' -RecommendationFr "Renseigner le nom, le logo, le contact informatique, le site de support et l'URL de confidentialité dans Administration du locataire > Personnalisation."

 $notif=@(foreach($cfg in @(Get-ZtValue 'enrollConfigs')){if((AsText $cfg.'@odata.type') -match 'deviceEnrollmentNotificationConfiguration'){$nCount=Get-ZtAssignedCount $cfg @{};[pscustomobject]@{Name=(AsText $cfg.displayName);Assigned=$nCount}}})
 Add-ZtFromPolicies -Id 'ZT-T07' -Category 'Tenant' -Test 'Device enrollment notification is configured and assigned' -TestFr "La notification d'inscription des appareils est configurée et assignée" -Matched $notif -Unverifiable ($collection['Enrollment restrictions'] -ne 'Complete') -PlatformKey '' -Rec 'Create an enrollment notification (e-mail or push) so users are warned when a device is enrolled with their account.' -RecFr "Créer une notification d'inscription (courriel ou push) pour avertir l'utilisateur quand un appareil est inscrit avec son compte."

 $cleanZt=Get-ZtValue 'cleanupDays'
 if($null -eq $cleanZt){$st='Not verified';$ev='Device clean-up rule not read (Intune configuration review skipped or unavailable).'}
 elseif([int]$cleanZt -gt 0){$st='Pass';$ev="Devices are removed after $cleanZt days of inactivity."}
 else{$st='Fail';$ev='No device clean-up rule.'}
 Add-ZtTest -Id 'ZT-T08' -Category 'Tenant' -Test 'Device Clean-up Rule is Created' -TestFr "Une règle de nettoyage des appareils est créée" -Status $st -Evidence $ev -Policies '' -PlatformKey '' -Recommendation 'Create a device clean-up rule (for example 90 to 180 days of inactivity).' -RecommendationFr "Créer une règle de nettoyage des appareils (par exemple 90 à 180 jours d'inactivité)."

 $ztPass=@($ztRows | Where-Object {$_.Status -eq 'Pass'}).Count
 $ztFail=@($ztRows | Where-Object {$_.Status -eq 'Fail'}).Count
 $ztWarn=@($ztRows | Where-Object {$_.Status -eq 'Warning'}).Count
 $collection['Zero Trust device tests']="Complete ($($ztRows.Count) tests: $ztPass pass, $ztFail fail, $ztWarn warning)"
 Say "Zero Trust device tests: $ztPass pass, $ztFail fail, $ztWarn warning"
}

# =====================================================================================
# SECTION 7 - Restitution: domain scores, prioritized action plan, framework mapping,
# comparison with previous run, bilingual executive summary (DOCX + PDF).
# =====================================================================================
# French titles for findings created by earlier sections (dynamic titles matched by pattern).
$frKnown=[ordered]@{
 'baseline settings configured differently$'=@('Paramètres OpenIntuneBaseline configurés différemment','Comparer avec la baseline et documenter les écarts acceptés.')
 'baseline settings configured with different values in several assigned policies$'=@('Paramètres de baseline configurés avec des valeurs différentes dans plusieurs stratégies assignées','Regrouper le paramètre dans une seule stratégie ou confirmer que les groupes ne se chevauchent pas.')
 ' settings not found in Settings Catalog$'=@('Paramètres de la baseline absents du Settings Catalog','Vérifier s''ils sont appliqués par GPO ou un autre canal, ou s''il s''agit d''exceptions acceptées.')
 '^Encrypted Windows devices have no visible Entra recovery-key escrow record$'=@('Appareils Windows chiffrés sans clé de récupération visible dans Entra','Forcer la sauvegarde de la clé BitLocker dans Entra ID (BackupToAAD) et vérifier la présence des clés.')
 '^Policy settings report errors or conflicts$'=@('Des paramètres de stratégie signalent des erreurs ou des conflits','Corriger les conflits en regroupant les paramètres et analyser les codes d''erreur.')
 '^Devices report disabled protection or overdue signatures$'=@('Des appareils signalent une protection désactivée ou des signatures en retard','Réactiver la protection en temps réel et corriger la mise à jour des signatures.')
 '^Endpoint Security policies have reported deployment failures$'=@('Des stratégies Endpoint Security signalent des échecs de déploiement','Analyser les erreurs par appareil et corriger les paramètres en échec.')
 '^Endpoint Security policies have no assignments$'=@('Des stratégies Endpoint Security ne sont pas assignées','Assigner ou supprimer les stratégies inutilisées.')
 '^Configuration policies report device-level failures or conflicts$'=@('Des stratégies de configuration signalent des échecs ou conflits sur les appareils','Analyser les erreurs par stratégie et corriger les paramètres en conflit.')
 '^Feature update failure report contains affected records$'=@('Le rapport d''échecs des mises à jour de fonctionnalité contient des appareils','Analyser les codes d''erreur (espace disque, compatibilité, pilotes).')
 '^Feature update device states explicitly report failures$'=@('Des appareils signalent un échec de mise à jour de fonctionnalité','Analyser les codes d''erreur et relancer la mise à jour.')
 '^Devices have not checked in within the defined inactivity threshold$'=@('Appareils sans synchronisation depuis le seuil d''inactivité','Vérifier ces appareils puis les retirer selon un processus de nettoyage documenté.')
 '^Windows and other managed devices explicitly report encryption disabled$'=@('Des appareils gérés signalent que le chiffrement est désactivé','Déployer une stratégie BitLocker / FileVault et suivre le chiffrement.')
 '^Devices currently report noncompliant$'=@('Des appareils sont actuellement non conformes','Corriger les exigences en échec et informer les utilisateurs concernés.')
 '^Application install failures were returned by Intune$'=@('Des échecs d''installation d''applications sont signalés','Analyser les codes d''erreur par application et corriger les paquets ou les exigences.')
 '^Managed devices reference disabled primary users$'=@('Des appareils gérés ont un utilisateur principal désactivé','Réaffecter, réinitialiser ou retirer ces appareils.')
 '^Windows devices have no matching Autopilot identity in collected records$'=@('Appareils Windows sans enregistrement Autopilot correspondant','Enregistrer les appareils dans Autopilot (ou activer la conversion automatique) si c''est la cible.')
 '^Policies with no reported assignments$'=@('Stratégies sans aucune assignation','Assigner ou supprimer les stratégies inutilisées.')
 '^Windows Update rings have feature or quality updates paused$'=@('Des anneaux Windows Update ont des mises à jour en pause','Confirmer que la pause est voulue et la lever dès que possible.')
}
function Get-FindingFr($f){
 if($script:FindingFr.ContainsKey($f.Finding)){return $script:FindingFr[$f.Finding]}
 foreach($k in $frKnown.Keys){if($f.Finding -match $k){return [pscustomobject]@{Title=$(if($f.Finding -match '^(Windows|macOS) '){('{0} : {1}' -f @($Matches[1],$frKnown[$k][0]))}else{$frKnown[$k][0]});Recommendation=$frKnown[$k][1]}}}
 return [pscustomobject]@{Title=$f.Finding;Recommendation=$f.Recommendation}
}
function Get-FindingDomain([string]$Area){
 switch -Regex ($Area){
  '^(Compliance|Conditional Access|Identity)$' {return 'Compliance'}
  '^(Encryption|BitLocker|Endpoint Security|Microsoft Defender|Windows LAPS|OpenIntuneBaseline|Hardware|App protection)$' {return 'Security'}
  '^(Windows Update|Operating system|OS updates)$' {return 'Updates'}
  '^(Applications|Scripts)$' {return 'Applications'}
  default {return 'Governance'}
 }
}
$domainLabels=[ordered]@{Compliance=@('Compliance','Conformité');Security=@('Security','Sécurité');Updates=@('Updates','Mises à jour');Applications=@('Applications','Applications');Governance=@('Governance','Gouvernance')}
$areaEffort=@{
 'OS updates'='Medium';'Intune Suite'='Medium';'Operations'='Low';
 'Compliance'='Low';'Connectors'='Low';'Governance'='Low';'Enrollment'='Low';'Assignment hygiene'='Low';'Policy configuration'='Low';'Identity'='Low';'Endpoint Security'='Medium'
 'Conditional Access'='Medium';'App protection'='Medium';'Windows LAPS'='Medium';'Scripts'='Medium';'Autopilot'='Medium';'Windows Update'='Medium';'Device hygiene'='Low';'Microsoft Defender'='Medium';'BitLocker'='Medium';'Configuration policies'='Medium';'Policy deployment'='Medium';'Applications'='Medium'
 'Operating system'='High';'Hardware'='High';'Encryption'='Medium';'OpenIntuneBaseline'='High'
}
$frameworks=@{
 'OS updates'=@('CIS 7 - Continuous Vulnerability Management','Patch operating systems','ID.RA, PR.PS')
 'Intune Suite'=@('CIS 4 - Secure Configuration','Restrict administrative privileges','PR.AA, PR.PS')
 'Operations'=@('CIS 8 - Audit Log Management','—','DE.CM, DE.AE')
 'Compliance'=@('CIS 4 - Secure Configuration','—','PR.PS, DE.CM')
 'Conditional Access'=@('CIS 6 - Access Control Management','—','PR.AA')
 'Identity'=@('CIS 5 - Account Management','—','PR.AA')
 'Governance'=@('CIS 5/6 - Account & Access Control Management','Restrict administrative privileges','GV.RR, PR.AA')
 'Connectors'=@('CIS 4 - Secure Configuration','—','PR.PS')
 'Enrollment'=@('CIS 1 - Inventory and Control of Enterprise Assets','—','ID.AM')
 'Assignment hygiene'=@('CIS 4 - Secure Configuration','—','PR.PS')
 'Autopilot'=@('CIS 4 - Secure Configuration','Restrict administrative privileges','PR.AA, PR.PS')
 'App protection'=@('CIS 3 - Data Protection','—','PR.DS')
 'Scripts'=@('CIS 2 - Inventory and Control of Software Assets','Application control','PR.PS')
 'Windows LAPS'=@('CIS 5 - Account Management','Restrict administrative privileges','PR.AA')
 'Operating system'=@('CIS 7 - Continuous Vulnerability Management','Patch operating systems','ID.RA, PR.PS')
 'Windows Update'=@('CIS 7 - Continuous Vulnerability Management','Patch operating systems','ID.RA, PR.PS')
 'Hardware'=@('CIS 4 - Secure Configuration','—','PR.PS')
 'Device hygiene'=@('CIS 1 - Inventory and Control of Enterprise Assets','—','ID.AM')
 'Encryption'=@('CIS 3 - Data Protection','—','PR.DS')
 'BitLocker'=@('CIS 3 - Data Protection / CIS 11 - Data Recovery','—','PR.DS')
 'Microsoft Defender'=@('CIS 10 - Malware Defenses','—','DE.CM')
 'Endpoint Security'=@('CIS 10 - Malware Defenses','User application hardening','PR.PS, DE.CM')
 'OpenIntuneBaseline'=@('CIS 4 - Secure Configuration','User application hardening','PR.PS')
 'Configuration policies'=@('CIS 4 - Secure Configuration','—','PR.PS')
 'Policy configuration'=@('CIS 4 - Secure Configuration','—','PR.PS')
 'Policy deployment'=@('CIS 4 - Secure Configuration','—','PR.PS')
 'Applications'=@('CIS 2 - Inventory and Control of Software Assets','Patch applications','ID.AM, PR.PS')
}
$sevWeight=@{High=25;Medium=10;Low=4;Informational=1}
$sevRank=@{High=0;Medium=1;Low=2;Informational=3}

# ---------- Action plan ----------
$actionPlan=[System.Collections.Generic.List[object]]::new()
foreach($f in @($findings|Sort-Object @{e={$sevRank[$_.Severity]}},@{e={-[int]$_.Affected}})){
 $effort=if($areaEffort.ContainsKey($f.Area)){$areaEffort[$f.Area]}else{'Medium'}
 $impact=switch($f.Severity){'High'{'High'}'Medium'{'Medium'}default{'Low'}}
 $horizon=if($effort -eq 'Low' -and $f.Severity -in @('High','Medium')){'Quick wins'}elseif($f.Severity -eq 'High' -or ($f.Severity -eq 'Medium' -and $effort -eq 'Medium')){'30 days'}else{'90 days'}
 $fw=if($frameworks.ContainsKey($f.Area)){$frameworks[$f.Area]}else{@('CIS 4 - Secure Configuration','—','PR.PS')}
 $fr=Get-FindingFr $f
 $actionPlan.Add([pscustomobject]@{Priority=$actionPlan.Count+1;Horizon=$horizon;Severity=$f.Severity;Domain=Get-FindingDomain $f.Area;Area=$f.Area;Finding=$f.Finding;FindingFr=$fr.Title;Affected=$f.Affected;Impact=$impact;Effort=$effort;Recommendation=$f.Recommendation;RecommendationFr=$fr.Recommendation;CIS=$fw[0];EssentialEight=$fw[1];NIST=$fw[2];Coverage=$f.Coverage})
}
$horizonRank=@{'Quick wins'=0;'30 days'=1;'90 days'=2}
$actionPlan=[System.Collections.Generic.List[object]]@($actionPlan|Sort-Object @{e={$horizonRank[$_.Horizon]}},@{e={$sevRank[$_.Severity]}},@{e={-[int]$_.Affected}})
$apIdx=0; foreach($apItem in $actionPlan){$apIdx++;$apItem.Priority=$apIdx}

# ---------- Domain scores ----------
$domainScores=[System.Collections.Generic.List[object]]::new()
foreach($dom in $domainLabels.Keys){
 $df=@($findings|Where-Object {(Get-FindingDomain $_.Area) -eq $dom})
 $score=Get-DomainScoreValue @($df | ForEach-Object {[string]$_.Severity})
 $domainScores.Add([pscustomobject]@{Domain=$dom;DomainFr=$domainLabels[$dom][1];Score=$score;Rating=(Get-ScoreRating $score);High=@($df|Where-Object Severity -eq 'High').Count;Medium=@($df|Where-Object Severity -eq 'Medium').Count;Low=@($df|Where-Object {$_.Severity -in @('Low','Informational')}).Count;Trend=$null})
}
$overallScore=[int][Math]::Round((($domainScores|Measure-Object Score -Average).Average))
$incomplete=@($collection.Keys|Where-Object {([string]$collection[$_]) -match '^(Unavailable|Partial)'})
$scoreNote="Score = 100 minus weighted findings per domain (High 25, Medium 10, Low 4, Informational 1). Unavailable data is never scored as healthy or unhealthy; $($incomplete.Count) collections were incomplete."

# ---------- Comparison with previous run ----------
$comparison=[ordered]@{Available=$false;PreviousGenerated='';PreviousPath='';Kpis=@();Findings=@()}
$prevMetaFile=''
if($PreviousRunPath){
 $prevMetaFile=if(Test-Path -LiteralPath $PreviousRunPath -PathType Container){Join-Path $PreviousRunPath 'Run-Metadata.json'}else{$PreviousRunPath}
}elseif(-not $NoRunComparison){
 $prevMetaFile=Get-ChildItem -LiteralPath $OutputPath -Directory -ErrorAction SilentlyContinue|Where-Object {$_.FullName -ne $runPath}|Sort-Object LastWriteTime -Descending|ForEach-Object {Join-Path $_.FullName 'Run-Metadata.json'}|Where-Object {
  if(-not (Test-Path -LiteralPath $_)){return $false}
  try{(Get-Content -LiteralPath $_ -Raw|ConvertFrom-Json).TenantId -eq $ctx.TenantId}catch{$false}
 }|Select-Object -First 1
}
if($prevMetaFile -and (Test-Path -LiteralPath $prevMetaFile)){
 try{
  $prev=Get-Content -LiteralPath $prevMetaFile -Raw -Encoding UTF8|ConvertFrom-Json
  if($prev.TenantId -and $prev.TenantId -ne $ctx.TenantId){throw "Previous run belongs to another tenant ($($prev.TenantId))"}
  $comparison.Available=$true;$comparison.PreviousGenerated=AsText $prev.Generated;$comparison.PreviousPath=Split-Path $prevMetaFile -Parent
  $kpiList=[System.Collections.Generic.List[object]]::new()
  foreach($k in @('total','noncompliant','inactive','unencrypted','disabled','missingAutopilot')){
   $old=$prev.Counts.$k; $new=$payloadSummaryForCompare[$k]
   if($null -ne $old -and $null -ne $new){$kpiList.Add([pscustomobject]@{Metric=$k;Previous=[int]$old;Current=[int]$new;Delta=[int]$new-[int]$old})}
  }
  if($null -ne $prev.OverallScore){$kpiList.Add([pscustomobject]@{Metric='overallScore';Previous=[int]$prev.OverallScore;Current=$overallScore;Delta=$overallScore-[int]$prev.OverallScore})}
  foreach($ds in $domainScores){
   $p=@($prev.DomainScores|Where-Object Domain -eq $ds.Domain)|Select-Object -First 1
   if($p){$ds.Trend=$ds.Score-[int]$p.Score;$kpiList.Add([pscustomobject]@{Metric="score:$($ds.Domain)";Previous=[int]$p.Score;Current=$ds.Score;Delta=$ds.Score-[int]$p.Score})}
  }
  $comparison.Kpis=@($kpiList)
  $prevFindings=@{}; foreach($pf in @($prev.Findings)){$prevFindings["$($pf.Area)|$($pf.Finding)"]=$pf}
  $curKeys=@{}
  $fl=[System.Collections.Generic.List[object]]::new()
  foreach($f in $findings){
   $key="$($f.Area)|$($f.Finding)";$curKeys[$key]=$true
   if($prevFindings.ContainsKey($key)){
    $o=[int]$prevFindings[$key].Affected; $n=[int]$f.Affected
    $fl.Add([pscustomobject]@{Change=if($n -gt $o){'Worse'}elseif($n -lt $o){'Improved'}else{'Unchanged'};Severity=$f.Severity;Area=$f.Area;Finding=$f.Finding;Previous=$o;Current=$n})
   }else{$fl.Add([pscustomobject]@{Change='New';Severity=$f.Severity;Area=$f.Area;Finding=$f.Finding;Previous=$null;Current=[int]$f.Affected})}
  }
  foreach($k in $prevFindings.Keys){if(-not $curKeys.ContainsKey($k)){$pf=$prevFindings[$k];$fl.Add([pscustomobject]@{Change='Resolved';Severity=AsText $pf.Severity;Area=AsText $pf.Area;Finding=AsText $pf.Finding;Previous=[int]$pf.Affected;Current=0})}}
  $changeRank=@{New=0;Worse=1;Resolved=2;Improved=3;Unchanged=4}
  $comparison.Findings=@($fl|Sort-Object @{e={$changeRank[$_.Change]}},@{e={$sevRank[$_.Severity]}})
  $collection['Run comparison']="Complete (previous run $($comparison.PreviousGenerated))"
 }catch{$collection['Run comparison']='Unavailable';$warnings.Add("Previous run comparison unavailable: $($_.Exception.Message)")}
}else{$collection['Run comparison']=if($NoRunComparison){'Skipped'}else{'No previous run found'}}

# ---------- CSV exports for the new sections ----------
Export-Data 'Connectors-And-Tokens.csv' @($connectorRows) @('Connector','Name','State','Expiration','DaysRemaining','LastSync','Health')
Export-Data 'Conditional-Access-Device-Controls.csv' @($caRows) @('Policy','State','RequiresCompliantDevice','RequiresHybridJoin','RequiresAppProtection','RequiresMfa','Operator','Controls','Users','ExcludedPrincipals','Applications','Platforms')
Export-Data 'Compliance-Policies.csv' @($complianceCoverageRows) @('Policy','Type','Assignments','Modified')
Export-Data 'Devices-Without-Compliance-Policy.csv' @($noPolicyDevices) @($(if(@($noPolicyDevices).Count){@($noPolicyDevices[0].PSObject.Properties.Name)}else{@('DeviceName')}))
Export-Data 'Enrollment-Restrictions.csv' @($enrollmentRows) @('Name','Type','Platform','PlatformBlocked','PersonalBlocked','MinOS','Limit','Priority','Assignments')
Export-Data 'Enrollment-Status-Page.csv' @($espRows) @('Name','Priority','Assignments','ShowProgress','TimeoutMinutes','BlockUntilAllAppsInstalled','AllowResetOnFailure','AllowUseOnFailure','BlockingApps')
Export-Data 'Admin-Roles.csv' @($rbacRows) @('Source','Role','BuiltIn','Assignment','Principal','Type','Scope','ScopeTags')
Export-Data 'Multi-Admin-Approval.csv' @($maaRows) @('Policy','Type','Platform','ApproverGroups','Modified')
Export-Data 'App-Protection-Policies.csv' @($mamRows) @('Policy','Platform','Assignments','PinRequired','Clipboard','DataTransfer','BackupBlocked','SaveAsBlocked','MinOS','OfflineWipe','Modified')
Export-Data 'Scripts-And-Remediations.csv' @($scriptRows) @('Script','Kind','Publisher','MicrosoftPublished','RunAs','SignatureCheck','Assignments','Success','Errors','ErrorRate','SummaryCoverage')
Export-Data 'Autopilot-Profiles.csv' @($autopilotProfileRows) @('Profile','Join','Mode','UserType','PreProvisioning','ConvertDevices','NameTemplate','Assignments','Modified')
Export-Data 'Assignment-Filters.csv' @($filterRows) @('Filter','Platform','Rule','ReferencedBy','Modified')
Export-Data 'Assignment-Hygiene.csv' @($hygieneRows) @('Issue','Object','ObjectKind','Group','Detail')
Export-Data 'Security-Control-Coverage.csv' @($coverageRows) @('Control','Population','Total','Covered','Gap','Coverage','Note')
Export-Data 'OS-Lifecycle.csv' @($osRows) @('Device','Platform','Release','Version','Edition','EndOfServicing','DaysRemaining','State','LastSync')
Export-Data 'Windows-Patch-Lag.csv' @($patchRows) @('Device','Build','Revision','NewestRevisionInTenant','RevisionGap','LastSync')
Export-Data 'Hardware-Readiness.csv' @($hardwareRows) @('Device','Serial','Model','OS','Windows11','TPM','SecureBoot','Processor','RAM','Source')
Export-Data 'Duplicate-Devices.csv' @($duplicateRows) @('Serial','Device','LastSync','Enrolled','PrimaryUser','Records')
Export-Data 'Cross-Source-Consistency.csv' @($crossRows) @('Issue','Device','OS','Detail','LastActivity')
Export-Data 'Domain-Scores.csv' @($domainScores) @('Domain','DomainFr','Score','Rating','High','Medium','Low','Trend')
Export-Data 'Action-Plan.csv' @($actionPlan) @('Priority','Horizon','Severity','Domain','Area','Finding','FindingFr','Affected','Impact','Effort','Recommendation','RecommendationFr','CIS','EssentialEight','NIST','Coverage')
Export-Data 'Intune-Settings-Review.csv' @($tenantReviewRows) @('Area','Check','Result','Status','Detail')
Export-Data 'Compliance-Actions.csv' @($complianceActionRows) @('Policy','Type','Assignments','MarkNoncompliant','GraceHours','Notifications','Retire','Actions')
Export-Data 'App-Install-Summary.csv' @($appAggregateRows) @('App','Platform','Required','Installed','Failed','Pending','NotInstalled','FailedPercent','AppId')
Export-Data 'Update-Coverage.csv' @($updateCoverageRows) @('Platform','Devices','Mechanism','Policies','Status')
Export-Data 'Enrollment-Profiles.csv' @($enrollProfileRows) @('Platform','Profile','Mode','TokenExpires','DaysLeft','EnrolledDevices','Supervised','Mandatory','Status')
Export-Data 'Audit-Destructive-Actions.csv' @($auditRows) @('Date','Action','Actor','Target','Result','Activity')
Export-Data 'Intune-Custom-Roles.csv' @($customRoleRows) @('Role','Permissions','DestructivePermissions','Detail','Assignments')
Export-Data 'Intune-Export-Reports.csv' @($script:ReportSources) @('Report','Filter','Status','Rows','Columns','Error')
Export-Data 'Zero-Trust-Devices.csv' @($ztRows) @('Id','Category','Test','Status','Evidence','Policies','Recommendation')
Export-Data 'Run-Comparison.csv' @($comparison.Findings) @('Change','Severity','Area','Finding','Previous','Current')

Export-Data 'Prioritized-Findings.csv' @($findings) @('Severity','Area','Finding','Affected','Evidence','Recommendation','Coverage')

$compliantCount=@($devices|Where-Object {$_.Compliance -eq 'compliant'}).Count
$noncompliantCount=@($devices|Where-Object {$_.Compliance -eq 'noncompliant'}).Count
$inactiveCount=@($devices|Where-Object {$_.Inactive}).Count
$unknownComplianceCount=@($devices|Where-Object {$_.Compliance -notin @('compliant','noncompliant')}).Count
$payload=[ordered]@{
 reportLanguage=$ReportLanguage;
 tenant=$(if($script:Anon.Enabled){'00000000-0000-0000-0000-000000000000'}else{AsText $ctx.TenantId}); tenantBrandLogo=$tenantBrandLogo; tenantBrandName=$tenantBrandName; generated=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'); inactivityDays=$InactiveDays
 collections=$collection;warnings=@($warnings)
 summary=[ordered]@{total=$devices.Count;compliant=$compliantCount;noncompliant=$noncompliantCount;otherCompliance=$unknownComplianceCount;inactive=$inactiveCount;unencrypted=@($devices|Where-Object {$_.Encrypted -eq 'Not encrypted'}).Count;disabled=@($devices|Where-Object {$_.PrimaryAccount -eq 'Disabled'}).Count;missingAutopilot=@($devices|Where-Object {$_.Autopilot -eq 'No matching record'}).Count;appFailures=$appStatuses.Count;apps=$appList.Count}
 oibSummary=$oibSummary;oibSummaries=$oibSummaries;oibComparison=@($oibRows);tenantGuiSettings=@($oibTenantGuiRows);
 devices=@($devices);apps=@($appSummary);policies=@($policyInventory);updates=@($updateInventory);findings=@($findings);windowsBuilds=@($windowsBuilds);policyDeployment=@($policyDeployment);policyFailureAnalysis=@($policyFailureAnalysis);endpointSecurity=@($endpointSecurity);securityFailures=@($securityFailures);bitLockerEscrow=@($escrowRows);settingFailures=@($settingFailureRows);defenderHealth=@($defenderRows);featureUpdateStates=@($featureUpdateStates);featureUpdateFailures=@($featureFailureRows)
 failures=@($appStatuses);complianceDetails=@($complianceDetails)
 scores=[ordered]@{overall=$overallScore;domains=@($domainScores);note=$scoreNote}
 actionPlan=@($actionPlan);comparison=$comparison
 connectors=@($connectorRows);conditionalAccess=@($caRows);enrollment=@($enrollmentRows);esp=@($espRows);adminRoles=@($rbacRows);multiAdminApproval=@($maaRows)
 appProtection=@($mamRows);scripts=@($scriptRows);autopilotProfiles=@($autopilotProfileRows);assignmentFilters=@($filterRows);assignmentHygiene=@($hygieneRows)
 controlCoverage=@($coverageRows);osLifecycle=@($osRows);patchLag=@($patchRows);hardware=@($hardwareRows);duplicates=@($duplicateRows);crossSource=@($crossRows);zeroTrust=@($ztRows)
 tenantReview=@($tenantReviewRows);complianceActions=@($complianceActionRows);appAggregate=@($appAggregateRows);updateCoverage=@($updateCoverageRows);enrollProfiles=@($enrollProfileRows);auditActions=@($auditRows);customRoles=@($customRoleRows);reportSources=@($script:ReportSources)
}
$payloadJson=JsonSafe $payload 14
if($script:Anon.Enabled){$payloadJson=ConvertTo-AnonymizedText $payloadJson}
# =====================================================================================
# SECTION 8 - Offline HTML report (multi-view, FR/EN)
# =====================================================================================
# HTML document title is embedded in the dashboard template
$html=@'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Intune Assessment</title>
<script>try{var t=localStorage.getItem("ia-theme");if(t==="dark"||t==="light")document.documentElement.setAttribute("data-theme",t)}catch(e){}</script>
<style>
/* =====================================================================
   Intune Assessment report - v3.70 UI
   Fluent-inspired design system: tokens, light / dark themes, app shell
   with sidebar navigation, hero score, cards, tables and print layout.
   Single offline file: no external fonts, images or scripts.
   ===================================================================== */
:root{
 --font:'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,'Helvetica Neue',Arial,sans-serif;
 --mono:'Cascadia Code',Consolas,'SF Mono',Menlo,monospace;
 --radius:12px;--radius-sm:8px;--radius-xs:6px;
 --bg:#f4f6f9;--surface:#ffffff;--surface-2:#f8fafc;--surface-3:#eef2f7;
 --ink:#111827;--ink-2:#374151;--muted:#6b7a90;--faint:#94a3b8;
 --border:#e3e8ef;--border-strong:#cfd7e2;
 --accent:#0f6cbd;--blue:var(--accent);--accent-hover:#115ea3;--accent-soft:#e8f2fc;--accent-ink:#0b5aa1;
 --green:#107c41;--green-soft:#e6f4ea;--amber:#a35f00;--amber-soft:#fff4e0;--red:#c42b1c;--red-soft:#fde7e9;--purple:#8a3ffc;--purple-soft:#f3ebff;--neutral-soft:#eef1f5;
 --shadow-1:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.04);
 --shadow-2:0 4px 16px rgba(16,24,40,.08),0 1px 3px rgba(16,24,40,.05);
 --sidebar-w:252px;--topbar-h:60px;
 --ring-track:#e6ebf2;
 color-scheme:light;
}
:root[data-theme="dark"]{
 --bg:#0e1420;--surface:#151d2b;--surface-2:#1a2333;--surface-3:#222d40;
 --ink:#e7edf6;--ink-2:#c3cddb;--muted:#93a1b5;--faint:#6b7a90;
 --border:#263248;--border-strong:#33415a;
 --accent:#4ea1f3;--accent-hover:#6cb2f6;--accent-soft:#132c47;--accent-ink:#8cc4fa;
 --green:#5ec58a;--green-soft:#123524;--amber:#f0b45c;--amber-soft:#3a2a10;--red:#ff8a80;--red-soft:#3d1a1d;--purple:#c2a2ff;--purple-soft:#2c2142;--neutral-soft:#222d40;
 --shadow-1:0 1px 2px rgba(0,0,0,.35);--shadow-2:0 6px 22px rgba(0,0,0,.45);
 --ring-track:#26324a;
 color-scheme:dark;
}
@media (prefers-color-scheme:dark){
 :root:not([data-theme="light"]){
  --bg:#0e1420;--surface:#151d2b;--surface-2:#1a2333;--surface-3:#222d40;
  --ink:#e7edf6;--ink-2:#c3cddb;--muted:#93a1b5;--faint:#6b7a90;
  --border:#263248;--border-strong:#33415a;
  --accent:#4ea1f3;--accent-hover:#6cb2f6;--accent-soft:#132c47;--accent-ink:#8cc4fa;
  --green:#5ec58a;--green-soft:#123524;--amber:#f0b45c;--amber-soft:#3a2a10;--red:#ff8a80;--red-soft:#3d1a1d;--purple:#c2a2ff;--purple-soft:#2c2142;--neutral-soft:#222d40;
  --shadow-1:0 1px 2px rgba(0,0,0,.35);--shadow-2:0 6px 22px rgba(0,0,0,.45);
  --ring-track:#26324a;
  color-scheme:dark;
 }
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
button{font-family:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.hidden{display:none!important}
.muted{color:var(--muted)}.micro{font-size:12px;line-height:1.6}.small{font-size:11px;color:var(--faint);overflow-wrap:anywhere}
.overline{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
code{font-family:var(--mono);font-size:11px;background:var(--surface-3);padding:1px 6px;border-radius:4px}

/* ---------- App shell ---------- */
.app-shell{display:grid;grid-template-columns:var(--sidebar-w) minmax(0,1fr);min-height:100vh}
.app-sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:6px;background:var(--surface);border-right:1px solid var(--border);padding:18px 14px;z-index:20}
.brand{display:flex;align-items:center;gap:11px;padding:4px 8px 18px;border-bottom:1px solid var(--border);margin-bottom:10px;min-width:0}
.tenant-brand-image{display:block;max-height:38px;max-width:100%;object-fit:contain}
.brand-text{min-width:0;display:flex;flex-direction:column}
.brand-text strong{font-size:15px;font-weight:650;letter-spacing:-.01em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.brand-text span{font-size:10px;letter-spacing:.04em;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.msmark{display:grid;grid-template-columns:repeat(2,10px);grid-template-rows:repeat(2,10px);gap:2px;flex:none}
.msmark i:nth-child(1){background:#f25022}.msmark i:nth-child(2){background:#7fba00}.msmark i:nth-child(3){background:#00a4ef}.msmark i:nth-child(4){background:#ffb900}
.side-nav{display:flex;flex-direction:column;gap:2px}
.side-nav-label{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);padding:8px 10px 6px}
.side-nav a{display:flex;align-items:center;gap:11px;padding:9px 10px;border-radius:var(--radius-sm);color:var(--ink-2);text-decoration:none;font-size:13px;font-weight:550;position:relative;transition:background .12s,color .12s}
.side-nav a svg{width:18px;height:18px;flex:none;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round;opacity:.85}
.side-nav a:hover{background:var(--surface-3);color:var(--ink)}
.side-nav a.active{background:var(--accent-soft);color:var(--accent-ink);font-weight:650}
.side-nav a.active::before{content:'';position:absolute;left:-14px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
.side-nav a .nav-label{flex:1;min-width:0}
.nav-count{font-size:10px;font-weight:700;background:var(--surface-3);color:var(--muted);border-radius:10px;padding:1px 8px;font-variant-numeric:tabular-nums}
.nav-count:empty{display:none}
.side-nav a.active .nav-count{background:var(--surface);color:var(--accent-ink)}
.sidebar-foot{margin-top:auto;padding:12px 10px 4px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);line-height:1.6}
.sidebar-foot b{display:block;color:var(--ink-2);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.app-main{min-width:0;display:flex;flex-direction:column}
.app-topbar{position:sticky;top:0;z-index:15;height:var(--topbar-h);display:flex;align-items:center;gap:12px;padding:0 clamp(18px,3vw,40px);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:saturate(1.4) blur(10px);-webkit-backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--border)}
.crumb{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);min-width:0}
.crumb strong{color:var(--ink);font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.crumb .sep{opacity:.5}
.top-actions{margin-left:auto;display:flex;align-items:center;gap:6px}
.icon-btn,.lang-toggle{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:34px;min-width:34px;padding:0 10px;border:1px solid var(--border);background:var(--surface);color:var(--ink-2);border-radius:var(--radius-sm);cursor:pointer;font-size:12px;font-weight:650;letter-spacing:.03em;transition:background .12s,border-color .12s}
.icon-btn:hover,.lang-toggle:hover{background:var(--surface-3);border-color:var(--border-strong)}
.icon-btn svg{width:17px;height:17px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.theme-icon-dark{display:none}
:root[data-theme="dark"] .theme-icon-dark{display:block}:root[data-theme="dark"] .theme-icon-light{display:none}
.wrap{width:100%;max-width:1680px;margin:0 auto;padding:28px clamp(18px,3vw,40px) 60px}
.foot{font-size:11px;color:var(--faint);padding:24px 0 0;text-align:center}

/* ---------- Views & headings ---------- */
.view-head{margin:4px 0 22px}
.view-head h1{font-size:26px;line-height:1.2;font-weight:700;letter-spacing:-.02em;margin:6px 0 6px}
.view-head p{margin:0;max-width:880px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px 24px;margin-bottom:18px;box-shadow:var(--shadow-1);min-width:0}
.panel h2{font-size:15px;font-weight:650;letter-spacing:-.005em;margin:0 0 16px}
.panel h3{font-size:13px;font-weight:650;margin:0 0 10px}
.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.panel-head h2{margin:0}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.panels>.panel{margin-bottom:0}
.charts-grid{grid-template-columns:repeat(2,minmax(0,1fr));margin-bottom:18px}
@media (min-width:1640px){.charts-grid{grid-template-columns:repeat(4,minmax(0,1fr))}.charts-grid .donut-layout{grid-template-columns:1fr;justify-items:center}.charts-grid .donut-legend{width:100%}}
.ov-split{grid-template-columns:minmax(0,3fr) minmax(0,2fr);margin-bottom:18px}
.link-more{font-size:12px;font-weight:600;color:var(--accent);text-decoration:none}
.link-more:hover{text-decoration:underline}

/* ---------- Hero ---------- */
.hero{display:grid;grid-template-columns:auto minmax(0,1.3fr) minmax(280px,1fr);gap:28px;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:26px 28px;margin-bottom:18px;box-shadow:var(--shadow-1);position:relative;overflow:hidden}
.hero::after{content:'';position:absolute;inset:0 0 auto 0;height:4px;background:linear-gradient(90deg,var(--accent),#7a5af8 55%,#00b7c3)}
.hero h1{font-size:28px;font-weight:700;letter-spacing:-.025em;line-height:1.15;margin:8px 0 8px}
.hero-sub{margin:0 0 14px;font-size:14px;color:var(--ink-2);display:flex;flex-wrap:wrap;gap:6px 14px}
.hero-sub span{display:inline-flex;align-items:center;gap:6px}
.hero-sub span::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--dot,var(--faint))}
.hero-meta{display:flex;flex-wrap:wrap;gap:6px}
.meta-chip{display:inline-flex;gap:5px;align-items:center;font-size:11px;color:var(--muted);background:var(--surface-2);border:1px solid var(--border);border-radius:20px;padding:4px 10px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta-chip b{color:var(--ink-2);font-weight:650;letter-spacing:.04em;font-size:10px}
.score-ring-wrap{display:flex;flex-direction:column;align-items:center;gap:10px;flex:none}
.ring-meta{display:flex;flex-direction:column;align-items:center;gap:4px}
.ring-meta .grade{font-size:11px;font-weight:700;padding:3px 11px;border-radius:12px;white-space:nowrap}
.score-ring{position:relative;width:148px;height:148px;flex:none}
.score-ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.score-ring .track{fill:none;stroke:var(--ring-track);stroke-width:12}
.score-ring .value{fill:none;stroke-width:12;stroke-linecap:round;transition:stroke-dasharray .6s ease}
.score-ring .center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.score-ring .center b{font-size:40px;font-weight:700;letter-spacing:-.04em;line-height:1;font-variant-numeric:tabular-nums}
.score-ring .center small{font-size:11px;color:var(--muted);margin-top:2px}
.domain-bars{display:flex;flex-direction:column;gap:11px}
.domain-row{display:grid;grid-template-columns:minmax(90px,120px) minmax(0,1fr) 36px 46px;gap:10px;align-items:center;font-size:12px}
.domain-row .dn{font-weight:600;color:var(--ink-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.domain-row .bar{height:8px;border-radius:6px;background:var(--surface-3);overflow:hidden}
.domain-row .bar i{display:block;height:100%;border-radius:6px}
.domain-row .ds{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.domain-row .dt{font-size:11px;text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.domain-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px}
.domain-head span{font-size:11px;color:var(--muted)}
.fd-trend{font-size:11px;font-weight:650}
.score-note{margin:-6px 4px 18px}

/* ---------- KPI cards ---------- */
.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px;margin:0 0 18px}
.kpi{position:relative;display:flex;flex-direction:column;align-items:flex-start;gap:4px;text-align:left;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px 14px;min-height:112px;box-shadow:var(--shadow-1);color:inherit;font:inherit;cursor:pointer;overflow:hidden;transition:transform .12s,box-shadow .12s,border-color .12s}
.kpi::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--kpi-accent,var(--accent))}
.kpi:hover{transform:translateY(-1px);box-shadow:var(--shadow-2);border-color:var(--border-strong)}
.kpi .kpi-top{display:flex;align-items:center;gap:8px;width:100%}
.kpi .kpi-icon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;background:var(--kpi-soft,var(--accent-soft));color:var(--kpi-accent,var(--accent));flex:none}
.kpi .kpi-icon svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.kpi .cap{font-size:12px;font-weight:600;color:var(--muted);line-height:1.3}
.kpi b{font-size:30px;font-weight:700;letter-spacing:-.03em;line-height:1.1;margin-top:6px;font-variant-numeric:tabular-nums}
.kpi .kpi-sub{font-size:11px;color:var(--muted)}
.kpi .go{position:absolute;right:14px;bottom:12px;font-size:11px;font-weight:650;color:var(--accent);opacity:0;transition:opacity .12s}
.kpi:hover .go,.kpi:focus-visible .go{opacity:1}
.kpi.tone-bad{--kpi-accent:var(--red);--kpi-soft:var(--red-soft)}
.kpi.tone-warn{--kpi-accent:var(--amber);--kpi-soft:var(--amber-soft)}
.kpi.tone-good{--kpi-accent:var(--green);--kpi-soft:var(--green-soft)}
.kpi.tone-neutral{--kpi-accent:var(--faint);--kpi-soft:var(--neutral-soft)}

/* ---------- Donut charts ---------- */
.donut-layout{display:grid;grid-template-columns:118px minmax(0,1fr);gap:16px;align-items:center;min-height:128px}
.donut-svg{width:100%;max-width:118px;height:auto;display:block;margin:auto;overflow:visible}
.donut-track{fill:none;stroke:var(--ring-track);stroke-width:16}
.donut-arc{fill:none;stroke-width:16;stroke-linecap:butt}
.donut-center{font-size:24px;font-weight:700;fill:var(--ink);text-anchor:middle}
.donut-center-caption{font-size:11px;fill:var(--muted);text-anchor:middle}
.donut-legend{display:flex;flex-direction:column;gap:7px;min-width:0}
.legend-item{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--ink-2)}
.legend-swatch{width:9px;height:9px;border-radius:3px;flex:none}
.legend-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.legend-count{font-weight:650;font-variant-numeric:tabular-nums}
.legend-pct{font-size:11px;color:var(--muted);min-width:42px;text-align:right;font-variant-numeric:tabular-nums}

/* ---------- Pills, chips, status ---------- */
.pill{display:inline-flex;align-items:center;gap:5px;border-radius:20px;padding:3px 10px;font-size:11px;font-weight:650;white-space:nowrap;background:var(--neutral-soft);color:var(--ink-2);line-height:1.5}
.pill::before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.75}
.pill.good,.pill.health-good,.pill.assignment-good{background:var(--green-soft);color:var(--green)}
.pill.bad,.pill.health-bad{background:var(--red-soft);color:var(--red)}
.pill.warn,.pill.assignment-zero{background:var(--amber-soft);color:var(--amber)}
.pill.info{background:var(--accent-soft);color:var(--accent-ink)}
.pill.health-neutral,.pill.assignment-unknown{background:var(--neutral-soft);color:var(--muted)}
.statuschip{display:inline-block;border-radius:var(--radius-xs);padding:4px 10px;font-size:11px;font-weight:600;background:var(--neutral-soft);color:var(--muted)}
.statuschip.complete{background:var(--green-soft);color:var(--green)}
.statuschip.partial{background:var(--amber-soft);color:var(--amber)}
.statuschip.unavailable{background:var(--red-soft);color:var(--red)}
.smallcount{font-size:10px;font-weight:700;background:var(--surface-3);color:var(--muted);border-radius:10px;padding:1px 7px;margin-left:6px;font-variant-numeric:tabular-nums}

/* ---------- Risks, findings, plan ---------- */
.risk-row{display:flex;gap:12px;align-items:center;padding:12px 4px;border-bottom:1px solid var(--border);font-size:13px;color:inherit;text-decoration:none;border-radius:6px;transition:background .12s}
.risk-row:hover{background:var(--surface-2)}
.risk-row:last-child{border-bottom:0}
.risk-row .t{flex:1;min-width:0}
.risk-row strong{font-variant-numeric:tabular-nums;background:var(--surface-3);border-radius:8px;padding:2px 9px;font-size:12px}
.fd-cmp{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:14px;padding-top:14px;border-top:1px dashed var(--border)}
.finding-card{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--sev,var(--faint));border-radius:var(--radius-sm);padding:14px 18px;margin-bottom:10px}
.finding-card.sev-bad{--sev:var(--red)}.finding-card.sev-warn{--sev:var(--amber)}.finding-card.sev-info{--sev:var(--accent)}
.finding-card h3{font-size:14px;font-weight:650;margin:8px 0 6px;line-height:1.4}
.finding-meta{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:11px;color:var(--muted)}
.finding-card p{font-size:13px;margin:6px 0 0;line-height:1.55;color:var(--ink-2)}
.finding-card .ev{color:var(--muted);font-size:12px}
.fd-plan{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.fd-plan>div{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius);padding:16px}
.fd-plan h3{display:flex;align-items:center;font-size:13px;margin:0 0 12px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.fd-plan ol{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:9px}
.fd-plan li{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;font-size:13px;line-height:1.45}
.fd-plan li small{display:block;color:var(--muted);font-size:11px;margin-top:6px}
.fd-plan li .pill{margin-right:4px}

/* ---------- Forms & controls ---------- */
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 14px;align-items:center}
.controls input,.controls select,.panel-head select{font:inherit;font-size:12px;height:34px;border:1px solid var(--border);background:var(--surface);color:var(--ink);border-radius:var(--radius-sm);padding:0 10px;min-width:120px;max-width:200px}
.controls input{flex:1 1 240px;max-width:420px;padding-left:32px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m20 20-3.5-3.5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:10px center}
.controls input:focus,.controls select:focus,.panel-head select:focus{outline:2px solid var(--accent);outline-offset:0;border-color:transparent}
.btn{font:inherit;font-size:12px;font-weight:600;height:34px;padding:0 14px;background:var(--surface);color:var(--ink-2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer}
.btn:hover{background:var(--surface-3)}
.seg{display:inline-flex;background:var(--surface-3);border-radius:var(--radius-sm);padding:3px;gap:2px;margin-bottom:16px}
.seg-btn{font-size:12px;font-weight:650;padding:6px 18px;border:0;background:transparent;color:var(--muted);border-radius:6px;cursor:pointer}
.seg-btn.active{background:var(--surface);color:var(--ink);box-shadow:var(--shadow-1)}

/* ---------- Tables ---------- */
.tablebox{max-height:72vh;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:12.5px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}
th{position:sticky;top:0;z-index:1;background:var(--surface-2);color:var(--muted);font-size:11px;font-weight:650;letter-spacing:.03em;white-space:nowrap}
tbody tr:nth-child(even) td{background:color-mix(in srgb,var(--surface-2) 55%,transparent)}
tbody tr:hover td{background:var(--accent-soft)}
tbody tr:last-child td{border-bottom:0}
td:first-child{white-space:nowrap;font-weight:600;color:var(--ink)}
td{min-width:84px}
.empty{padding:36px 16px;text-align:center;color:var(--muted);font-size:13px}
.warn-list{margin:0;padding-left:20px;font-size:12.5px;line-height:1.6;color:var(--ink-2)}
.warn-list li{margin-bottom:6px;overflow-wrap:anywhere}

/* ---------- Inventory ---------- */
.inventory-shell{display:grid;grid-template-columns:250px minmax(0,1fr);gap:18px;align-items:start}
.inventory-sidebar{position:sticky;top:calc(var(--topbar-h) + 16px);max-height:calc(100vh - var(--topbar-h) - 32px);overflow:auto;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px;scrollbar-width:thin}
.sidebar-heading{display:flex;justify-content:space-between;align-items:center;font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--faint);padding:8px 10px}
.inventory-sidebar .tabs{display:flex;flex-direction:column;gap:2px}
.tab-group+.tab-group{margin-top:8px;padding-top:8px;border-top:1px solid var(--border)}
.tab-group{display:flex;flex-direction:column;gap:1px}
.tab-group-title{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);padding:6px 10px 4px}
.tab{display:flex;width:100%;align-items:center;justify-content:space-between;gap:8px;padding:7px 10px;border:0;border-radius:6px;background:transparent;color:var(--ink-2);text-align:left;font-size:12.5px;font-weight:550;cursor:pointer;line-height:1.3}
.tab:hover{background:var(--surface-3)}
.tab.active{background:var(--accent-soft);color:var(--accent-ink);font-weight:650}
.tab .smallcount{margin-left:auto;flex:none}
.tab.active .smallcount{background:var(--surface);color:var(--accent-ink)}
.inventory-main{min-width:0}.inventory-main>.panel{margin-bottom:0}
.sidebar-toggle,.sidebar-close{display:none}

/* ---------- OpenIntuneBaseline ---------- */
.oib-hero{display:grid;grid-template-columns:minmax(200px,1fr) 3fr;gap:20px;align-items:center;margin:12px 0 16px}
.oib-score{background:var(--accent-soft);border-radius:var(--radius);padding:18px 20px}
.oib-score b{display:block;font-size:34px;font-weight:700;letter-spacing:-.03em;color:var(--accent-ink);line-height:1.2}
.oib-score span{font-size:12px;color:var(--muted)}
.oib-stat-row{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.oib-stat{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;border-top:3px solid var(--faint)}
.oib-stat span{font-size:11px;color:var(--muted)}
.oib-stat b{display:block;font-size:22px;font-weight:700;margin-top:4px}
.oib-stat.good{border-top-color:var(--green)}.oib-stat.bad{border-top-color:var(--red)}.oib-stat.warn{border-top-color:var(--amber)}.oib-stat.info{border-top-color:var(--accent)}
.oib-meter{height:8px;display:flex;overflow:hidden;background:var(--surface-3);border-radius:8px;margin:12px 0 4px}
.oib-meter>span{height:100%}
.oib-count{display:inline-flex;justify-content:center;align-items:center;min-width:40px;padding:4px 10px;font-size:12px;font-weight:700;border-radius:20px;font-variant-numeric:tabular-nums;border:0}
.oib-count-good{background:var(--green-soft);color:var(--green)}.oib-count-bad{background:var(--red-soft);color:var(--red)}.oib-count-missing{background:var(--amber-soft);color:var(--amber)}.oib-count-conflict{background:var(--purple-soft);color:var(--purple)}.oib-count-zero{background:var(--surface-3);color:var(--faint)}
.oib-detail-trigger{cursor:pointer;font:inherit;transition:filter .12s,box-shadow .12s}
.oib-detail-trigger:hover{box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 35%,transparent)}
.oib-tenant-list{display:flex;flex-direction:column;gap:6px;min-width:260px;max-width:600px}
.oib-tenant-entry{border:1px solid var(--border);background:var(--surface-2);border-radius:var(--radius-sm);padding:8px 10px}
.oib-tenant-name{font-size:12px;font-weight:600;color:var(--ink-2);overflow-wrap:anywhere}
.oib-tenant-metrics{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.oib-mini{display:inline-flex;align-items:center;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:12px;border:0;background:var(--surface-3);color:var(--muted)}
.oib-mini.match{background:var(--green-soft);color:var(--green)}.oib-mini.different{background:var(--red-soft);color:var(--red)}.oib-mini.conflicting{background:var(--purple-soft);color:var(--purple)}
.oib-tenant-empty,.oib-empty{font-size:12px;color:var(--faint);font-style:italic}
.oib-setting-name{font-weight:650;color:var(--ink-2);overflow-wrap:anywhere}
.oib-setting-id{display:block;margin-top:4px;color:var(--faint);font:10.5px var(--mono);overflow-wrap:anywhere}
.oib-setting-source{display:block;margin-top:2px;color:var(--faint);font-size:10.5px}
.oib-value details summary{cursor:pointer;color:var(--accent);font-weight:600}
.oib-value pre,.oib-value-panel pre{font:11px/1.5 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;max-height:200px;overflow:auto;background:var(--surface-3);padding:10px;border-radius:6px;margin:6px 0 0;color:var(--ink-2)}
.oib-backdrop{position:fixed;inset:0;background:rgba(8,14,26,.5);z-index:99;opacity:0;transition:opacity .18s}
.oib-backdrop.open{opacity:1}
.oib-drawer{position:fixed;top:0;right:0;height:100vh;width:min(860px,94vw);z-index:100;background:var(--surface);color:var(--ink);box-shadow:-16px 0 50px rgba(0,0,0,.25);display:flex;flex-direction:column;transform:translateX(102%);transition:transform .2s ease;border-left:1px solid var(--border)}
.oib-drawer.open{transform:translateX(0)}
.oib-drawer-head{padding:22px 26px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;gap:16px}
.oib-drawer-kicker{font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--muted)}
.oib-drawer-head h2{font-size:20px;margin:6px 0;overflow-wrap:anywhere}
.oib-drawer-meta{font-size:12px;color:var(--muted);line-height:1.65;overflow-wrap:anywhere}
.oib-drawer-close{flex:none;width:34px;height:34px;border:1px solid var(--border);background:var(--surface);color:var(--ink-2);border-radius:var(--radius-sm);font-size:20px;cursor:pointer}
.oib-drawer-tools{padding:12px 26px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.oib-drawer-tools input{flex:1;min-width:160px;height:34px;border:1px solid var(--border);background:var(--surface);color:var(--ink);border-radius:var(--radius-sm);padding:0 12px;font:inherit;font-size:12px}
.oib-drawer-body{padding:16px 26px 36px;overflow-y:auto;flex:1;background:var(--bg)}
.oib-setting-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;margin-bottom:12px}
.oib-setting-card-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.oib-setting-title{font-size:14px;font-weight:650;line-height:1.4;overflow-wrap:anywhere}
.oib-setting-category{color:var(--muted)}
.oib-setting-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
.oib-value-panel{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;min-width:0}
.oib-value-panel span{display:block;font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.oib-friendly-value{display:block;font-size:13px;color:var(--ink);overflow-wrap:anywhere;margin-bottom:6px}
.oib-value-panel details{font-size:11px;color:var(--accent)}
.oib-setting-policy,.oib-setting-note{font-size:12px;color:var(--muted);margin-top:10px;line-height:1.6;overflow-wrap:anywhere}
body.oib-drawer-active{overflow:hidden}

/* ---------- Responsive ---------- */
@media (max-width:1400px){.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}.charts-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:1180px){.hero{grid-template-columns:auto minmax(0,1fr)}.hero-domains{grid-column:1/-1}.ov-split{grid-template-columns:1fr}.fd-plan{grid-template-columns:1fr}.oib-hero{grid-template-columns:1fr}.oib-stat-row{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:960px){
 :root{--sidebar-w:72px}
 .app-sidebar{padding:14px 8px;align-items:center}
 .brand{padding:4px 0 14px;justify-content:center}.brand-text,.side-nav-label,.side-nav a .nav-label,.sidebar-foot{display:none}
 .side-nav a{justify-content:center;padding:10px}
 .side-nav a .nav-count{position:absolute;top:2px;right:2px;padding:0 5px;font-size:9px}
 .side-nav a.active::before{left:-8px}
 .inventory-shell{grid-template-columns:1fr}
 .inventory-sidebar{display:none;position:relative;top:auto;max-height:50vh;margin-bottom:12px}
 .inventory-sidebar.sidebar-open{display:block}
 .sidebar-toggle{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 14px;margin-bottom:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--ink-2);font-size:12px;font-weight:600;cursor:pointer}
 .sidebar-close{display:inline-block;background:transparent;border:0;font-size:20px;color:var(--muted);cursor:pointer}
}
@media (max-width:640px){
 .app-shell{grid-template-columns:1fr}
 .app-sidebar{position:fixed;top:auto;bottom:0;left:0;right:0;height:auto;flex-direction:row;padding:6px 8px calc(6px + env(safe-area-inset-bottom));border-right:0;border-top:1px solid var(--border);box-shadow:0 -4px 16px rgba(0,0,0,.08)}
 .brand,.sidebar-foot{display:none}
 .side-nav{flex-direction:row;justify-content:space-around;width:100%}
 .side-nav a.active::before{display:none}
 .wrap{padding:20px 14px 96px}
 .hero{grid-template-columns:1fr;justify-items:center;text-align:center;padding:22px}
 .hero-sub,.hero-meta{justify-content:center}.hero-domains{width:100%}
 .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.charts-grid,.panels{grid-template-columns:1fr}
 .crumb .sep,.crumb .crumb-root{display:none}
 .oib-stat-row{grid-template-columns:repeat(2,minmax(0,1fr))}.oib-setting-grid{grid-template-columns:1fr}
 .donut-layout{grid-template-columns:100px minmax(0,1fr)}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}

/* ---------- Print: Overview + Action plan only ---------- */
@media print{
 :root{--bg:#fff;--surface:#fff;--surface-2:#f8fafc;--shadow-1:none;--shadow-2:none;color-scheme:light}
 .app-shell{display:block}.app-sidebar,.app-topbar,.link-more,.kpi .go,.sidebar-toggle{display:none!important}
 .view{display:none!important}#view-overview,#view-plan{display:block!important}#view-plan{break-before:page}
 .panel,.kpi,.hero,.finding-card,.fd-plan li{break-inside:avoid;box-shadow:none}
 .tablebox{max-height:none;overflow:visible}.wrap{padding:0;max-width:none}
 .kpis{grid-template-columns:repeat(3,1fr)}.charts-grid{grid-template-columns:repeat(2,1fr)}
}
</style></head><body><div class="app-shell"><aside class="app-sidebar" aria-label="Report navigation"><div class="brand"><img class="tenant-brand-image hidden" id="tenantBrandLogo" alt="Customer logo"><span id="tenantBrandFallback" class="msmark"><i></i><i></i><i></i><i></i></span><div class="brand-text"><strong id="tenantBrandName">Intune Assessment</strong><span>DEVICE MANAGEMENT REPORT</span></div></div><div class="side-nav-label">Report</div><nav class="side-nav" id="mainNav" aria-label="Report sections"><a href="#overview" data-view="overview"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg><span class="nav-label">Overview</span></a><a href="#plan" data-view="plan"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 6h10M10 12h10M10 18h10"/><path d="m3.5 6 1.5 1.5L7.5 5M3.5 12l1.5 1.5L7.5 11M3.5 18l1.5 1.5L7.5 17"/></svg><span class="nav-label">Action plan</span></a><a href="#findings" data-view="findings"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3z"/><path d="M12 8v5M12 16.5v.01"/></svg><span class="nav-label">Findings</span><span class="nav-count" id="navFindings"></span></a><a href="#baseline" data-view="baseline"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v16M6 20h12M5 8h14"/><path d="M5 8 2.5 14a2.6 2.6 0 0 0 5 0L5 8zM19 8l-2.5 6a2.6 2.6 0 0 0 5 0L19 8z"/></svg><span class="nav-label">Baseline</span></a><a href="#inventory" data-view="inventory"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/></svg><span class="nav-label">Inventory</span></a><a href="#zerotrust" data-view="zerotrust"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg><span class="nav-label">Zero Trust</span><span class="nav-count" id="navZt"></span></a><a href="#quality" data-view="quality"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg><span class="nav-label">Data quality</span><span class="nav-count" id="navWarnings"></span></a></nav><div class="sidebar-foot"><span>Tenant</span><b id="tenantShort"></b><span id="sideGenerated"></span></div></aside><div class="app-main"><header class="app-topbar"><div class="crumb"><span class="crumb-root">Intune Assessment</span><span class="sep">/</span><strong id="pageTitle">Overview</strong></div><div class="top-actions"><button type="button" class="lang-toggle" id="langToggle" aria-label="Afficher le rapport en français">FR</button><button type="button" class="icon-btn" id="themeToggle" aria-label="Switch to dark theme" title="Switch to dark theme"><svg class="theme-icon-light" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/></svg><svg class="theme-icon-dark" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button><button type="button" class="icon-btn" id="printBtn" aria-label="Print report" title="Print report"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/></svg></button></div></header><main id="dashboard" class="wrap">
<section class="view" id="view-overview"><section class="hero" aria-label="Assessment summary"><div class="score-ring-wrap" id="heroRing"></div><div class="hero-main"><div class="overline">INTUNE &nbsp;/&nbsp; ENDPOINT SECURITY</div><h1>Managed Devices Assessment</h1><p class="hero-sub" id="heroSummary"></p><div class="hero-meta" id="headerMeta"></div></div><div class="hero-domains"><div class="domain-head"><strong class="micro">Maturity score</strong><span>Score by domain</span></div><div id="overviewScores"></div></div></section>
<p class="micro muted score-note" id="scoreNote"></p>
<div class="kpis" id="kpis"></div><div class="panels charts-grid"><section class="panel"><h2>Device compliance</h2><div id="complianceGraph"></div></section><section class="panel"><h2>Operating systems</h2><div id="osGraph"></div></section><section class="panel"><h2>Management platforms</h2><div id="managementGraph"></div></section><section class="panel"><h2>Device encryption</h2><div id="encryptionGraph"></div></section></div>
<div class="panels ov-split"><section class="panel"><div class="panel-head"><h2>Top risks</h2><a class="link-more" href="#findings">All findings →</a></div><div id="topRisks"></div><div id="overviewDelta"></div></section><section class="panel"><div class="panel-head"><h2>Quick wins</h2><a class="link-more" href="#plan">Action plan →</a></div><div id="quickWins"></div></section></div>
</section>
<section class="view hidden" id="view-plan"><div class="view-head"><div class="overline">REMEDIATION</div><h1>Prioritized action plan</h1><p class="muted micro">Quick wins first, then 30 and 90 days. Effort and impact are indicative.</p></div>
<section class="panel"><div id="planBoard"></div></section>
<section class="panel"><h2>Change since previous run</h2><div id="planComparison"></div></section>
<section class="panel"><h2>All actions · framework mapping</h2><p class="micro muted">Indicative mapping to CIS Controls v8, Essential Eight and NIST CSF 2.0.</p><div class="tablebox"><table><thead id="planThead"></thead><tbody id="planTbody"></tbody></table></div></section>
</section>
<section class="view hidden" id="view-findings"><div class="view-head"><div class="overline">EVIDENCE</div><h1>Assessment findings</h1><p class="muted micro">Evidence-based findings. Unavailable Graph data is never reported as noncompliant.</p></div>
<section class="panel"><div class="controls"><input id="fSearch" type="search" placeholder="Search findings..." aria-label="Search findings"><select id="fSeverity" aria-label="Severity"></select><select id="fDomain" aria-label="Domain"></select><select id="fHorizon" aria-label="Horizon"></select></div><div class="micro muted" id="fCount" style="margin-bottom:10px"></div><div id="findingsList"></div></section>
</section>
<section class="view hidden" id="view-baseline"><div class="view-head"><div class="overline">OPENINTUNEBASELINE</div><h1>Baseline comparison</h1><p class="muted micro">Configured Settings Catalog values compared with the OpenIntuneBaseline reference. Not a measure of device enforcement.</p></div>
<section class="panel"><div class="seg" role="group" aria-label="Platform"><button type="button" class="seg-btn active" data-oib-platform="Windows">Windows</button><button type="button" class="seg-btn" data-oib-platform="macOS">macOS</button></div><div id="oibSnapshot"></div></section>
<section class="panel"><div class="panel-head"><h2>Baseline policies</h2><select id="oibViewStatus" aria-label="Baseline result"><option value="">All results</option><option value="Different">Different</option><option value="Conflicting">Conflicting</option><option value="Missing">Missing</option><option value="Match">Match</option></select></div><p class="micro muted">One row per baseline policy. Select a count to see the impacted settings. Full detail: OpenIntuneBaseline-Comparison.csv.</p><div class="tablebox"><table><thead id="oibThead"></thead><tbody id="oibTbody"></tbody></table></div><div class="empty hidden" id="oibEmpty">No baseline policy for this selection.</div></section>
</section>
<section class="view hidden" id="view-inventory"><div class="view-head"><div class="overline">INVENTORY</div><h1>Explore inventory</h1><p class="muted micro">Filter your inventory, investigate issues, and export CSV evidence.</p></div>
<div class="inventory-shell"><aside class="inventory-sidebar" id="inventorySidebar" aria-label="Inventory navigation"><div class="sidebar-heading"><span>INVENTORY SECTIONS</span><button type="button" class="sidebar-close" id="sidebarClose" aria-label="Close inventory menu">×</button></div><nav class="tabs" id="tabs" aria-label="Assessment sections"></nav></aside><div class="inventory-main"><button type="button" class="sidebar-toggle" id="sidebarToggle" aria-controls="inventorySidebar" aria-expanded="false">☰ &nbsp; Inventory sections</button>
<section class="panel"><h2 id="sectionTitle">Device overview</h2><p id="sectionInfo" class="micro muted"></p><div id="controls" class="controls"><input id="search" type="search" placeholder="Search device, user, serial, application..." aria-label="Search"><select id="osFilter" aria-label="Operating system"></select><select id="complianceFilter" aria-label="Compliance"></select><select id="stateFilter" aria-label="Account state"></select><select id="managedFilter" aria-label="Managed by"></select><select id="manufacturerFilter" aria-label="Manufacturer"></select><select id="ownershipFilter" aria-label="Ownership"></select><select id="encryptionFilter" aria-label="Encryption"></select><select id="autopilotFilter" aria-label="Autopilot"></select><select id="policyStatusFilter" aria-label="Policy deployment status" class="hidden"></select><select id="oibStatusFilter" aria-label="Baseline comparison status" class="hidden"></select><button class="btn" id="clear">Clear filters</button></div><div class="micro muted" id="resultCount" style="margin-bottom:12px"></div><div class="tablebox"><table><thead id="thead"></thead><tbody id="tbody"></tbody></table></div><div class="empty hidden" id="empty">No matching records for the selected filters.</div></section></div></div>
</section>
<section class="view hidden" id="view-zerotrust"><div class="view-head"><div class="overline">ZERO TRUST</div><h1>Zero Trust Assessment · Devices</h1><p class="muted micro">Device tests from the Microsoft Zero Trust Assessment, evaluated from the Intune configuration collected in this run. Pass means a matching policy exists and is assigned. Informational: these tests do not change the maturity score.</p></div>
<section class="panel"><div id="ztSummary"></div></section>
<section class="panel"><div class="controls"><input id="ztSearch" type="search" placeholder="Search tests..." aria-label="Search tests"><select id="ztCategory" aria-label="Platform"></select><select id="ztStatus" aria-label="Result"></select></div><div class="micro muted" id="ztCount" style="margin-bottom:10px"></div><div class="tablebox"><table><thead><tr><th>Result</th><th>Platform</th><th>Test</th><th>Evidence</th><th>Policies</th><th>Recommendation</th></tr></thead><tbody id="ztTbody"></tbody></table></div></section>
</section>
<section class="view hidden" id="view-quality"><div class="view-head"><div class="overline">DATA QUALITY</div><h1>Collection status &amp; limitations</h1><p class="muted micro">What was collected, what was partial and why. Unavailable data is never scored as healthy or unhealthy.</p></div>
<section class="panel"><h2>Collection status</h2><div id="qualityStatus"></div></section>
<section class="panel"><h2>Intune export reports</h2><div id="qualityReports"></div></section>
<section class="panel"><h2>Warnings</h2><div id="qualityWarnings"></div></section>
</section>
<footer class="foot">Generated by Florian Daminato - ITI - Modern workplace specialist · Read-only</footer></main></div></div>
<div id="oibBackdrop" class="oib-backdrop hidden" aria-hidden="true"></div>
<aside id="oibDrawer" class="oib-drawer" role="dialog" aria-modal="true" aria-labelledby="oibDrawerTitle" aria-hidden="true" tabindex="-1">
 <div class="oib-drawer-head"><div><div class="oib-drawer-kicker">OPENINTUNEBASELINE · SETTINGS EVIDENCE</div><h2 id="oibDrawerTitle">Impacted settings</h2><div id="oibDrawerMeta" class="oib-drawer-meta"></div></div><button type="button" id="oibDrawerClose" class="oib-drawer-close" aria-label="Close panel">×</button></div>
 <div class="oib-drawer-tools"><input type="search" id="oibDrawerSearch" placeholder="Filter setting name, ID, or value..." aria-label="Filter impacted settings"><span id="oibDrawerCount" class="micro muted"></span></div>
 <div id="oibDrawerBody" class="oib-drawer-body"></div>
</aside>
<script id="dataset" type="application/json">__DATA__</script>
<script>
'use strict';
const D=JSON.parse(document.getElementById('dataset').textContent), by=id=>document.getElementById(id);
// Tenant logo is embedded at report generation, so the report works offline.
if(D.tenantBrandLogo && /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(D.tenantBrandLogo)){
 const logo=by('tenantBrandLogo');logo.src=D.tenantBrandLogo;logo.classList.remove('hidden');
 by('tenantBrandFallback').classList.add('hidden');
 by('tenantBrandName').textContent=D.tenantBrandName||'';
}else if(D.tenantBrandName){by('tenantBrandName').textContent=D.tenantBrandName;}

const safe=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const nice=s=>safe(s || 'Unknown');
function badge(value){const s=String(value??'Unknown');const low=s.toLowerCase();let tone='';if(['compliant','encrypted','registered','enabled','success','succeeded','remediated','installed','match'].includes(low))tone='good';else if(['noncompliant','not encrypted','disabled','failed','error','conflict','conflicting','different'].includes(low))tone='bad';else if(['unknown','no matching record','in grace period','not found','pending','missing'].includes(low))tone='warn';else if(['in progress','not applicable','not assigned'].includes(low))tone='info';return `<span class="pill ${tone}">${safe(s)}</span>`}
// Defender booleans are contextual: true for overdue signatures is BAD,
// while true for enabled protection is GOOD. Unknown is always neutral.
function defenderBadge(value,field){
 const s=String(value??'Unknown').trim(),lower=s.toLowerCase();
 let tone='health-neutral';
 if(lower==='true'||lower==='false'){
  const healthy=(field==='SignatureOverdue')?(lower==='false'):(lower==='true');
  tone=healthy?'health-good':'health-bad';
 }
 return `<span class="pill ${tone}">${safe(s)}</span>`;
}
function oibSettingCell(row){
 const name=String(row.SettingName||row.SettingId||'Unknown');
 const origin=String(row.SettingNameSource||'');
 const technical=String(row.SettingId||'');
 return `<div class="oib-setting-name">${safe(name)}</div>${name!==technical?`<span class="oib-setting-id">${safe(technical)}</span>`:''}${origin&&origin!=='Technical ID'?`<span class="oib-setting-source">${safe(origin)}</span>`:''}`;
}
function oibValueCell(value){
 if(value===undefined||value===null||String(value).trim()==='')return '<span class="oib-empty">Not configured / unavailable</span>';
 const raw=String(value);
 let pretty=raw;
 try{const obj=JSON.parse(raw);pretty=JSON.stringify(obj,null,2)}catch{}
 const short=raw.length>85?raw.slice(0,80)+'…':raw;
 return `<div class="oib-value"><details><summary>${safe(short)}</summary><pre>${safe(pretty)}</pre></details></div>`;
}
function assignmentBadge(value,row){
 const n=Number(value),coverage=String(row.AssignmentCoverage||'').toLowerCase();
 const known=Number.isFinite(n)&&String(value??'').trim()!==''&&coverage==='complete';
 const tone=!known?'assignment-unknown':n>0?'assignment-good':'assignment-zero';
 const label=!known?'Unknown':n>0?`Success (${n})`:'No assignment';
 return `<span class="pill ${tone}">${safe(label)}</span>`;
}

function donutChart(node,rows,colors){
 const total=rows.reduce((n,r)=>n+Number(r[1]||0),0);
 const palette=colors||['#ef6b54','#279b86','#406b86','#f5a24e','#7682c6','#a781bb','#8eabc0','#d2a664'];
 const radius=76,circumference=2*Math.PI*radius;
 let offset=0;
 const arcs=rows.map(([name,count],i)=>{
  const value=Math.max(0,Number(count)||0),frac=total?value/total:0;
  if(!frac)return '';
  const length=Math.max(0,frac*circumference-3);
  const arc=`<circle class="donut-arc" cx="110" cy="110" r="${radius}" stroke="${palette[i%palette.length]}" stroke-dasharray="${length} ${circumference-length}" stroke-dashoffset="${-offset}" transform="rotate(-90 110 110)"><title>${safe(name)}: ${value.toLocaleString()} (${(frac*100).toFixed(1)}%)</title></circle>`;
  offset+=frac*circumference;
  return arc;
 }).join('');
 const svg=`<svg class="donut-svg" viewBox="0 0 220 220" role="img" aria-label="${safe(rows.map(([n,v])=>n+': '+v).join(', '))}"><circle class="donut-track" cx="110" cy="110" r="${radius}"/>${arcs}<text class="donut-center" x="110" y="108">${total.toLocaleString()}</text><text class="donut-center-caption" x="110" y="127">devices</text></svg>`;
 const legend=rows.map(([name,count],i)=>`<div class="legend-item"><span class="legend-swatch" style="background:${palette[i%palette.length]}"></span><span class="legend-name" title="${safe(name)}">${safe(name)}</span><span class="legend-count">${Number(count).toLocaleString()}</span><span class="legend-pct">${total?(100*count/total).toFixed(1):'0.0'}%</span></div>`).join('');
 by(node).innerHTML=`<div class="donut-layout">${svg}<div class="donut-legend">${legend||'<span class="muted">No data available</span>'}</div></div>`;
}
by('headerMeta').innerHTML=`<span class="meta-chip"><b>TENANT:</b><span>${safe(D.tenant)}</span></span><span class="meta-chip"><b>GENERATED:</b><span>${safe(D.generated)}</span></span><span class="meta-chip"><b>INACTIVE THRESHOLD:</b><span>${safe(D.inactivityDays)}</span><span>DAYS</span></span>`;
by('sideGenerated').textContent=String(D.generated||'').slice(0,16);
by('tenantShort').textContent=D.tenant||'Tenant';
let summary=D.summary;
const kIco={devices:'<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/>',shield:'<path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3z"/><path d="m9.5 10 5 5m0-5-5 5"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/>',app:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="m15 15 5 5m0-5-5 5"/>',user:'<circle cx="10" cy="8" r="4"/><path d="M3 21a7 7 0 0 1 12-5"/><path d="m17 15 4 4m0-4-4 4"/>'};
const kpct=v=>Number.isFinite(Number(v))&&summary.total?`${Math.round(100*Number(v)/summary.total)}% of devices`:'';
const kTone=(v,bad)=>!Number.isFinite(Number(v))?'tone-neutral':Number(v)===0?'tone-good':bad;
const kpis=[['Managed devices',summary.total,'Overview','devices','',''],['Noncompliant',summary.noncompliant,'Noncompliant','shield',kTone(summary.noncompliant,'tone-bad'),kpct(summary.noncompliant)],['Inactive devices',summary.inactive,'Inactive Devices','clock',kTone(summary.inactive,'tone-warn'),kpct(summary.inactive)],['Not encrypted',summary.unencrypted,'Not Encrypted','lock',kTone(summary.unencrypted,'tone-bad'),kpct(summary.unencrypted)],['App failures',D.collections['App install states']==='Complete'?summary.appFailures:'—','Application Failures','app',D.collections['App install states']==='Complete'?kTone(summary.appFailures,'tone-warn'):'tone-neutral',''],['Disabled primary users',['Complete','Partial'].includes(D.collections['Directory users'])?summary.disabled:'—','Disabled Primary Users','user',['Complete','Partial'].includes(D.collections['Directory users'])?kTone(summary.disabled,'tone-warn'):'tone-neutral','']];
by('kpis').innerHTML=kpis.map(([n,v,t,icon,tone,sub])=>`<button type="button" class="kpi ${tone}" data-goto="${safe(t)}"><span class="kpi-top"><span class="kpi-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${kIco[icon]}</svg></span><span class="cap">${safe(n)}</span></span><b>${safe(v)}</b>${sub?`<span class="kpi-sub">${safe(sub)}</span>`:''}<span class="go">View in inventory →</span></button>`).join('');
const oibSummaries=D.oibSummaries||{Windows:D.oibSummary||{}};
let oibPlatformSel='Windows';
function renderOibSummary(){
 const platform=oibPlatformSel;
 const oib=oibSummaries[platform]||{};
 const stats=[['Matched','Matching','good'],['Different','Different','bad'],['Missing','Missing','warn'],['Conflicting','Conflicts','bad'],['Unassessed','Not assessed','info']];
 const assessed=Number(oib.Matched||0)+Number(oib.Different||0)+Number(oib.Missing||0)+Number(oib.Conflicting||0);
 const rate=assessed?Math.round(Number(oib.Matched||0)*100/assessed):null;
 const total=stats.reduce((n,[key])=>n+Number(oib[key]||0),0);
 by('oibSnapshot').innerHTML=`<p class="micro muted"><strong>${safe(platform)} reference:</strong> ${safe(oib.Reference||'Not available')} · Git commit: <code>${safe((oib.Commit||'unavailable').slice(0,12))}</code> · ${safe(oib.Status||'Not assessed')}</p><div class="oib-hero"><div class="oib-score"><span>Configured-settings alignment</span><b>${rate===null?'—':rate+'%'}</b><span>${safe(oib.Matched||0)} matches out of ${assessed.toLocaleString()} assessable comparisons</span></div><div><div class="oib-stat-row">${stats.map(([key,label,tone])=>`<div class="oib-stat ${tone}"><span>${label}</span><b>${Number(oib[key]||0).toLocaleString()}</b></div>`).join('')}</div><div class="oib-meter" title="Baseline status distribution">${stats.map(([key,label,tone],i)=>`<span style="width:${total?100*Number(oib[key]||0)/total:0}%;background:${['#2b8060','#be5254','#d6a34d','#9f4f78','#8b9eb6'][i]}"></span>`).join('')}</div></div></div><p class="micro muted">Results compare configured Settings Catalog values, not device enforcement or assignment targeting. Use the Windows / macOS toggle to switch references. Missing and unassessed settings are counted here and detailed in the CSV.</p>`;
}
const groups=(arr,key)=>{const m={};for(const x of arr){let k=x[key]||'Unknown';m[k]=(m[k]||0)+1}return Object.entries(m).sort((a,b)=>b[1]-a[1])};
donutChart('complianceGraph',groups(D.devices,'Compliance'),['#28a483','#ed715e','#f0b05e','#93a3b5','#796ec5']);
donutChart('osGraph',groups(D.devices,'OS').slice(0,8),['#377ad3','#28a483','#a77bcc','#ed9861','#697d97','#cfb26c']);
donutChart('managementGraph',groups(D.devices,'ManagedBy').slice(0,8),['#377ad3','#29a78c','#ed9861','#9a83d2','#607a94','#d7b66d']);
donutChart('encryptionGraph',groups(D.devices,'Encrypted'),['#29a78c','#ed715e','#e3a44d','#93a3b5']);
const severityOrder={Critical:0,High:1,Medium:2,Low:3,Informational:4};
const sortedFindings=[...(D.findings||[])].sort((a,b)=>(severityOrder[a.Severity]??9)-(severityOrder[b.Severity]??9)||b.Affected-a.Affected);


const tabs=[
 ['Tenant GUI Settings','Tenant Settings Catalog · GUI names and values','All collected Settings Catalog configurations, with display names and configured values.'],
 ['BitLocker Escrow','BitLocker recovery-key escrow evidence','Entra recovery key metadata only; no recovery passwords are retrieved.'],
 ['Defender Health','Defender device protection signals','Actual Graph-reported protection signals when available; missing devices are not treated as healthy.'],
 ['Setting Failures','Policy setting failures','Setting-level errors/conflicts reported by Intune, not inferred from policy assignment.'],
 ['Policy Failure Analysis','Policy failure analysis','Grouped explicit policy errors and conflicts with affected-device counts and remediation guidance.'],
 ['Endpoint Security','Endpoint Security policy inventory','Defender, Firewall, ASR, BitLocker, LAPS and security baselines: configuration evidence only, not measured protection.'],
 ['Endpoint Security Failures','Endpoint Security deployment failures','Explicitly failed policy/device records matched to identified security policies.'],
 ['Policy Deployment','Policy deployment results','Device-level policy result records from Graph report export; only explicit failures are flagged.'],
 ['Feature Update Status','Feature update device status','Windows feature update status and failures when supported by Intune reporting.'],
 ['Configuration Policies','Configuration policy inventory','Classic and Settings Catalog profiles, assignment collection coverage and timestamps.'],
 ['Windows Updates','Windows Update configuration','Update rings and feature/quality update policy configurations, not deployment success.'],
 ['Windows Builds','Windows build distribution','Device OS build counts; not equivalent to quality update compliance.'],
 ['Overview','All managed devices','All managed-device records from Intune.'],
 ['Application Failures','App installation failures','Requires successful application device-status collection; partial or skipped collections are marked.'],
 ['Multiple Users','Multiple users / devices','Users associated with more than one managed device (not proof of multiple device owners).'],
 ['Not Encrypted','Devices not encrypted','Only records where Intune explicitly reports isEncrypted = false. Unknown values are not counted as unencrypted.'],
 ['No Autopilot Record','No matching Autopilot registration','Windows devices without a matching Autopilot identity by managed-device ID or serial. This does not verify hardware hash presence.'],
 ['Inactive Devices','Inactive managed devices',`Devices without an Intune check-in within ${D.inactivityDays} days, or with no reported check-in.`],
 ['Noncompliant','Noncompliant devices','Detailed failed compliance settings when Intune returns them; policy-only and unavailable results are labeled explicitly.'],
 ['OS Edition Overview','Windows operating system editions','Intune skuFamily values where available; missing editions are labeled as unavailable.'],
 ['Disabled Primary Users','Disabled primary-user accounts','Only directory accounts explicitly reported disabled. Requires successful User.Read.All collection.'],
 ['Inactive Primary Users','Users associated with inactive devices','A device synchronization proxy, NOT proof of user inactivity or absence of sign-ins.'],
 ['Applications','Intune managed applications','Applications published and managed through Intune, with installation result counts when collected.'],
 ['Connectors & Tokens','Connector and token expiration','APNs, ADE, VPP, Managed Google Play and Mobile Threat Defense connectors.'],
 ['Conditional Access','Conditional Access device controls','Policies and whether they require a compliant / hybrid-joined device or app protection.'],
 ['Enrollment Restrictions','Enrollment restrictions and limits','Platform restrictions, personal device blocking, minimum OS and device limits.'],
 ['Enrollment Status Page','Enrollment Status Page (ESP) profiles','Progress display, timeout and failure behaviour.'],
 ['Admin Roles','Intune RBAC and privileged directory roles','Active assignments only; PIM eligible assignments are not included.'],
 ['Multi-Admin Approval','Multi-admin approval policies','Access policies requiring a second administrator approval.'],
 ['App Protection','App protection (MAM) policies','iOS, Android and Windows app protection settings and assignments.'],
 ['Scripts & Remediations','Scripts and remediations','Run summary, error rate, execution context and signature enforcement.'],
 ['Autopilot Profiles','Autopilot deployment profiles','Join type, deployment mode, user account type and assignments.'],
 ['Assignment Filters','Assignment filters','Filters and number of collected assignments that reference them.'],
 ['Assignment Hygiene','Assignment hygiene','Broad assignments, deleted or empty groups, contradictory include/exclude.'],
 ['Control Coverage','Measured security control coverage','Measured coverage (LAPS backup, Defender signal, encryption, compliance), not policy existence.'],
 ['OS Lifecycle','Operating system support status','End of servicing per Windows release and edition; minimum OS for mobile and macOS.'],
 ['Patch Lag','Windows patch lag (heuristic)','Active devices behind the newest revision of the same build observed in this tenant.'],
 ['Hardware Readiness','TPM, Secure Boot and Windows 11 readiness','Endpoint analytics when available, otherwise Intune hardware inventory.'],
 ['Duplicate Devices','Duplicate serial numbers','Same serial number enrolled more than once.'],
 ['Intune Settings Review','Intune settings review','Tenant-level Intune settings: clean-up rule, categories, terms, scope tags, Remote Help, Endpoint analytics, Intune Suite.'],
 ['Compliance Actions','Compliance policy actions','Grace period before noncompliance, user notifications and other scheduled actions per policy.'],
 ['App Install Summary','Application install summary','Installed, failed and pending device counts per app from the Intune AppInstallStatusAggregate report.'],
 ['Update Coverage','OS update coverage by platform','Update mechanism and policies found for Windows, Apple and Android devices.'],
 ['Enrollment Profiles','Enrollment profiles and tokens','Android Enterprise / AOSP enrollment tokens and Apple ADE enrollment profiles.'],
 ['Audit Actions','Destructive device actions (audit log)','Wipe, retire, delete and reset actions from the Intune audit log for the selected period.'],
 ['Custom Roles','Intune custom roles','Custom Intune RBAC roles, permissions count and destructive permissions.'],
 ['Cross-Source','Intune / Entra / Defender consistency','Devices missing from one source or stale in Entra.']
];
// Inventory navigation is grouped by domain; unknown tabs fall into "Other".
const tabGroups=[
 ['Devices',['Overview','Noncompliant','Inactive Devices','Not Encrypted','No Autopilot Record','Multiple Users','OS Edition Overview','Duplicate Devices','Cross-Source','Hardware Readiness','Compliance Actions']],
 ['Identity & access',['Disabled Primary Users','Inactive Primary Users','Admin Roles','Custom Roles','Conditional Access','Audit Actions']],
 ['Applications',['Applications','App Install Summary','Application Failures','App Protection','Scripts & Remediations']],
 ['Configuration',['Configuration Policies','Tenant GUI Settings','Policy Deployment','Policy Failure Analysis','Setting Failures','Assignment Filters','Assignment Hygiene','Intune Settings Review']],
 ['Security',['Endpoint Security','Endpoint Security Failures','Defender Health','BitLocker Escrow','Control Coverage']],
 ['Updates & lifecycle',['Update Coverage','Windows Updates','Feature Update Status','Windows Builds','OS Lifecycle','Patch Lag']],
 ['Enrollment & tenant',['Enrollment Restrictions','Enrollment Status Page','Autopilot Profiles','Connectors & Tokens','Enrollment Profiles','Multi-Admin Approval']]
];
{const known=new Set(tabGroups.flatMap(g=>g[1]));const other=tabs.map(t=>t[0]).filter(t=>!known.has(t));if(other.length)tabGroups.push(['Other',other]);}
const tabLabel=t=>t==='Overview'?'All devices':t;
const inventorySidebar=by('inventorySidebar');
const sidebarToggle=by('sidebarToggle');
const sidebarClose=by('sidebarClose');
function closeInventorySidebar(){inventorySidebar.classList.remove('sidebar-open');sidebarToggle.setAttribute('aria-expanded','false')}
sidebarToggle.addEventListener('click',()=>{const open=inventorySidebar.classList.toggle('sidebar-open');sidebarToggle.setAttribute('aria-expanded',String(open))});
sidebarClose.addEventListener('click',closeInventorySidebar);
// Compact baseline view: aggregate setting-level evidence per platform and baseline policy.
// Aggregation affects the HTML only; the detailed OpenIntuneBaseline-Comparison.csv is unchanged.
const oibPolicySummary=(()=>{
 const index=new Map();
 for(const record of (D.oibComparison||[])){
  const platform=String(record.OS||'Windows');
  const policy=String(record.BaselinePolicy||'Unnamed baseline policy');
  const key=JSON.stringify([platform,policy]);
  if(!index.has(key))index.set(key,{OS:platform,BaselinePolicy:policy,Total:0,Match:0,Different:0,Conflicting:0,Missing:0,Unassessed:0,TenantPolicies:[],_settings:new Map()});
  const entry=index.get(key);
  const settingId=String(record.SettingId||record.SettingName||'unknown');
  const status=String(record.Status||'Not assessed');
  if(!entry._settings.has(settingId))entry._settings.set(settingId,new Set());
  entry._settings.get(settingId).add(status);
  const name=String(record.TenantPolicy||'').trim();
  if(!name)continue;
  const id=String(record.TenantPolicyId||name);
  let target=entry.TenantPolicies.find(x=>x.Id===id);
  if(!target){target={Id:id,Name:name,Match:new Set(),Different:new Set(),Conflicting:new Set(),Unassessed:new Set()};entry.TenantPolicies.push(target)}
  if(target[status] instanceof Set)target[status].add(settingId);
 }
 for(const entry of index.values()){
  entry.Total=entry._settings.size;
  for(const statuses of entry._settings.values()){
   if(statuses.has('Different'))entry.Different++;
   else if(statuses.has('Conflicting'))entry.Conflicting++;
   else if(statuses.has('Match'))entry.Match++;
   else if(statuses.has('Missing'))entry.Missing++;
   else entry.Unassessed++;
  }
  delete entry._settings;
  entry.TenantPolicies=entry.TenantPolicies.map(x=>({Id:x.Id,Name:x.Name,Match:x.Match.size,Different:x.Different.size,Conflicting:x.Conflicting.size,Unassessed:x.Unassessed.size}))
   .sort((a,b)=>(b.Different+b.Match)-(a.Different+a.Match)||a.Name.localeCompare(b.Name));
 }
 return [...index.values()].sort((a,b)=>a.OS.localeCompare(b.OS)||a.BaselinePolicy.localeCompare(b.BaselinePolicy)).map((x,i)=>({...x,SummaryIndex:i}));
})();
function oibCountBadge(value,kind,record){
 const n=Number(value)||0;
 const tone=n===0?'oib-count-zero':kind==='oibcountgood'?'oib-count-good':kind==='oibcountbad'?'oib-count-bad':kind==='oibcountmissing'?'oib-count-missing':'oib-count-conflict';
 const status=kind==='oibcountgood'?'Match':kind==='oibcountbad'?'Different':kind==='oibcountmissing'?'Missing':'Conflicting';
 if(!n)return `<span class="oib-count ${tone}">0</span>`;
 return `<button type="button" class="oib-count oib-detail-trigger ${tone}" data-oib-row="${record.SummaryIndex}" data-oib-status="${status}" aria-label="Show ${n} ${status.toLowerCase()} settings in ${safe(record.BaselinePolicy)}" title="View impacted settings">${n.toLocaleString()}</button>`;
}
function oibTenantPoliciesCell(record){
 const policies=record.TenantPolicies||[];
 if(!policies.length)return '<span class="oib-tenant-empty">No matching tenant policy identified</span>';
 return `<div class="oib-tenant-list">${policies.map((p,i)=>`<div class="oib-tenant-entry"><div class="oib-tenant-name">${safe(p.Name)}</div><div class="oib-tenant-metrics">${[['Match','match'],['Different','different'],['Conflicting','conflicting']].map(([status,tone])=>p[status]?`<button type="button" class="oib-mini oib-detail-trigger ${tone}" data-oib-row="${record.SummaryIndex}" data-oib-tenant="${i}" data-oib-status="${status}" title="View ${status.toLowerCase()} settings in this policy">${p[status]} ${status.toLowerCase()}</button>`:'').join('')}</div></div>`).join('')}</div>`;
}
// Everything in the drawer comes from the existing offline comparison dataset.
// Matching by setting ID, baseline, platform and (optionally) tenant policy avoids network calls.
let oibActiveDetails=[],oibPreviousFocus=null;
function formatOibValue(value){
 if(value===null||value===undefined||value==='')return 'Not provided';
 const raw=String(value);
 try{
  const parsed=JSON.parse(raw);
  if(parsed && typeof parsed==='object' && !Array.isArray(parsed) && Object.keys(parsed).length===1 && Object.hasOwn(parsed,'value'))return String(parsed.value);
  return JSON.stringify(parsed,null,2)
 }catch{return raw}
}
function renderOibDrawerList(){
 const q=by('oibDrawerSearch').value.trim().toLowerCase();
 const list=oibActiveDetails.filter(r=>!q||[r.SettingName,r.SettingId,r.BaselineDisplayValue,r.TenantDisplayValue,r.BaselineValue,r.TenantValue,r.TenantPolicy].some(v=>String(v||'').toLowerCase().includes(q)));
 by('oibDrawerCount').textContent=`${list.length.toLocaleString()} of ${oibActiveDetails.length.toLocaleString()} settings`;
 by('oibDrawerBody').innerHTML=list.length?list.map((r,i)=>`<article class="oib-setting-card"><div class="oib-setting-card-top"><div class="oib-setting-title">${safe(r.SettingName||r.SettingId||'Unnamed setting')}</div>${badge(r.Status)}</div><div class="oib-setting-id">${r.SettingCategory?`<span class="oib-setting-category">${safe(r.SettingCategory)}</span> · `:""}${safe(r.SettingId||'No setting ID')}${r.SettingNameSource&&r.SettingNameSource!=='Technical ID'?` · ${safe(r.SettingNameSource)}`:''}</div><div class="oib-setting-grid"><div class="oib-value-panel"><span>OpenIntuneBaseline expected</span><strong class="oib-friendly-value">${safe(r.BaselineDisplayValue||formatOibValue(r.BaselineValue))}</strong><details><summary>Technical JSON</summary><pre>${safe(formatOibValue(r.BaselineValue))}</pre></details></div><div class="oib-value-panel"><span>Intune tenant value</span><strong class="oib-friendly-value">${safe(r.TenantDisplayValue||formatOibValue(r.TenantValue))}</strong><details><summary>Technical JSON</summary><pre>${safe(formatOibValue(r.TenantValue))}</pre></details></div></div>${r.TenantPolicy?`<div class="oib-setting-policy"><strong>Tenant configurations:</strong> ${safe(r.TenantPolicy)}</div>`:''}${r.Evidence?`<div class="oib-setting-note">${safe(r.Evidence)}</div>`:''}</article>`).join(''):'<div class="oib-empty">No settings match this filter.</div>';
}
function openOibDrawer(summaryIndex,status,tenantIndex){
 const entry=oibPolicySummary[summaryIndex];if(!entry)return;
 const tenant=(tenantIndex!==null&&tenantIndex!==undefined)?entry.TenantPolicies[tenantIndex]?.Name:null;
 const allRows=(D.oibComparison||[]).filter(r=>String(r.OS||'Windows')===entry.OS&&String(r.BaselinePolicy||'Unnamed baseline policy')===entry.BaselinePolicy);
 const filteredTenantRows=tenant?allRows.filter(r=>String(r.TenantPolicyId||r.TenantPolicy||'')===String(entry.TenantPolicies[tenantIndex]?.Id||'')):allRows;
 const effectiveStatus=new Map();
 if(!tenant){
  const grouped=new Map();for(const r of allRows){const key=String(r.SettingId||r.SettingName||'');if(!grouped.has(key))grouped.set(key,new Set());grouped.get(key).add(String(r.Status||'Not assessed'))}
  for(const [id,states] of grouped){effectiveStatus.set(id,states.has('Different')?'Different':states.has('Conflicting')?'Conflicting':states.has('Match')?'Match':states.has('Missing')?'Missing':'Not assessed')}
 }
 const rows=filteredTenantRows.filter(r=>String(r.Status||'').toLowerCase()===status.toLowerCase()&&(!tenant?effectiveStatus.get(String(r.SettingId||r.SettingName||''))===status:true));
 // Deduplicate by setting identifier, as the summary counters use setting records.
 const seen=new Set();oibActiveDetails=rows.filter(r=>{const key=String(r.SettingId||r.SettingName||'')+(tenant?'|'+String(r.TenantPolicyId||''):'');if(seen.has(key))return false;seen.add(key);return true});
 oibPreviousFocus=document.activeElement;
 by('oibDrawerTitle').textContent=`${status} settings`;
 by('oibDrawerMeta').innerHTML=`<strong>Baseline:</strong> ${safe(entry.BaselinePolicy)}<div><strong>Platform:</strong> ${safe(entry.OS)}</div>${tenant?`<div><strong>Tenant policy:</strong> ${safe(tenant)}</div>`:''}`;
 by('oibDrawerSearch').value='';renderOibDrawerList();
 by('oibBackdrop').classList.remove('hidden');by('oibDrawer').classList.add('open');document.body.classList.add('oib-drawer-active');by('oibDrawer').setAttribute('aria-hidden','false');
 requestAnimationFrame(()=>by('oibBackdrop').classList.add('open'));
 by('oibDrawerClose').focus();
}
function closeOibDrawer(){
 by('oibDrawer').classList.remove('open');by('oibBackdrop').classList.remove('open');by('oibBackdrop').classList.add('hidden');by('oibDrawer').setAttribute('aria-hidden','true');document.body.classList.remove('oib-drawer-active');if(oibPreviousFocus&&oibPreviousFocus.isConnected)oibPreviousFocus.focus();
}
by('oibDrawerClose').addEventListener('click',closeOibDrawer);
by('oibBackdrop').addEventListener('click',closeOibDrawer);
by('oibDrawerSearch').addEventListener('input',renderOibDrawerList);
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&by('oibDrawer').classList.contains('open'))closeOibDrawer()});
let selected='Overview';
const commonCols=[['Name','Device','text'],['Manufacturer','Manufacturer','text'],['Model','Model','text'],['ManagedBy','Managed by','text'],['PrimaryUser','Primary user','text'],['OS','OS','text'],['Compliance','Compliance','badge'],['Encrypted','Encryption','badge'],['Ownership','Ownership','text'],['DaysSinceSync','Sync age (days)','text'],['Autopilot','Autopilot','badge']];
function rowsFor(tab){switch(tab){
 case 'Tenant GUI Settings':return [D.tenantGuiSettings||[],[['Policy','Tenant configuration','text'],['SettingName','Intune GUI setting','oibsetting'],['SettingCategory','Intune category','text'],['ConfiguredValue','Configured value','text'],['SettingId','Technical ID','text']]];
 case 'BitLocker Escrow':return [D.bitLockerEscrow||[],[['Device','Device','text'],['Encryption','Encryption','badge'],['EscrowStatus','Escrow status','badge'],['RecoveryKeyRecords','Key records','text'],['Note','Interpretation','text']]];
 case 'Defender Health':return [D.defenderHealth||[],[['Device','Device','text'],['RealTimeProtection','Real-time protection','defender'],['MalwareProtection','Antimalware','defender'],['TamperProtection','Tamper protection','defender'],['SignatureOverdue','Signatures overdue','defender'],['ProductStatus','Product status','text'],['LastReported','Last reported','text']]];
 case 'Setting Failures':return [D.settingFailures||[],[['Device','Device','text'],['DeviceId','Device ID','text'],['Policy','Policy','text'],['PolicyId','Policy ID','text'],['Setting','Setting','text'],['Status','Status','badge'],['ErrorCode','Error code','text'],['StateDetails','Details','text'],['Recommendation','Recommended action','text']]];
 case 'Policy Failure Analysis':return [D.policyFailureAnalysis||[],[['Policy','Policy','text'],['Status','Status','badge'],['Error','Error code','text'],['ResultRecords','Failed records','text'],['DistinctDevices','Distinct devices','text'],['ExampleDevice','Example device','text'],['Recommendation','Recommended action','text']]];
 case 'Endpoint Security':return [D.endpointSecurity||[],[['Family','Security area','text'],['Policy','Policy','text'],['Source','Policy type','text'],['Assignments','Assignments','assignment'],['AssignmentCoverage','Assignment coverage','badge'],['DeploymentFailures','Failed records','text'],['ProtectionState','Endpoint protection','text']]];
 case 'Endpoint Security Failures':return [D.securityFailures||[],[['Family','Security area','text'],['Policy','Policy','text'],['Device','Device','text'],['Status','Status','badge'],['Error','Error code','text'],['LastReported','Last reported','text']]];
 case 'Policy Deployment':return [D.policyDeployment||[],[['Device','Device','text'],['Policy','Policy','text'],['Status','Status','badge'],['RawStatus','Raw code','text'],['Error','Error','text'],['LastReported','Last reported','text'],['Source','Source report','text']]];
 case 'Feature Update Status':return [[...(D.featureUpdateStates||[]),...(D.featureUpdateFailures||[])],[['Device','Device','text'],['Policy','Policy','text'],['Status','Status','badge'],['Error','Error','text'],['LastReported','Last reported','text'],['Source','Source report','text']]];
 case 'Configuration Policies':return [D.policies||[],[['Name','Policy','text'],['Kind','Policy family','text'],['Type','Type','text'],['Assignments','Assignments','assignment'],['AssignmentCoverage','Assignment coverage','badge'],['Modified','Last modified','text']]];
 case 'Windows Updates':return [D.updates||[],[['Name','Update policy','text'],['Type','Type','text'],['FeatureTarget','Feature target','text'],['QualityPaused','Quality paused','badge'],['FeaturePaused','Feature paused','badge'],['QualityDeferralDays','Quality deferral (days)','text'],['FeatureDeferralDays','Feature deferral (days)','text'],['Assignments','Assignments','assignment'],['AssignmentCoverage','Coverage','badge']]];
 case 'Windows Builds':return [D.windowsBuilds||[],[['OSVersion','Windows build','text'],['Devices','Device count','text']]];
 case 'Application Failures':return [D.failures,[['App','Application','text'],['Device','Device','text'],['User','User','text'],['State','Install state','badge'],['ErrorCode','Error code','text']]];
 case 'Multiple Users':{const count={};for(const x of D.devices){if(x.PrimaryUserId)count[x.PrimaryUserId]=(count[x.PrimaryUserId]||0)+1}return [D.devices.filter(x=>x.PrimaryUserId&&count[x.PrimaryUserId]>1),commonCols]}
 case 'Not Encrypted':return [D.devices.filter(x=>x.Encrypted==='Not encrypted'),commonCols];
 case 'No Autopilot Record':return [D.devices.filter(x=>x.Autopilot==='No matching record'),commonCols];
 case 'Inactive Devices':return [D.devices.filter(x=>x.Inactive),commonCols];
 case 'Noncompliant':return [D.devices.filter(x=>x.Compliance==='noncompliant'),[['Name','Device','text'],['Manufacturer','Make','text'],['Model','Model','text'],['ManagedBy','Managed by','text'],['PrimaryUser','Primary user','text'],['Compliance','State','badge'],['ComplianceReason','Failed requirement','text'],['ComplianceExplanation','Explanation','text'],['ComplianceAction','Suggested action','text'],['ComplianceDetailStatus','Detail coverage','text']]];
 case 'OS Edition Overview':return [D.devices.filter(x=>/^windows/i.test(x.OS)),[['Name','Device','text'],['OS','OS','text'],['Manufacturer','Manufacturer','text'],['Model','Model','text'],['ManagedBy','Managed by','text'],['Edition','Windows edition','text'],['OSVersion','Version','text'],['Compliance','Compliance','badge']]];
 case 'Disabled Primary Users':return [D.devices.filter(x=>x.PrimaryAccount==='Disabled'),[['Name','Device','text'],['Model','Model','text'],['ManagedBy','Managed by','text'],['PrimaryUser','Primary user','text'],['PrimaryAccount','Account','badge'],['LastSync','Last sync','text'],['OS','OS','text']]];
 case 'Inactive Primary Users':return [D.devices.filter(x=>x.Inactive&&x.PrimaryUserId),[['PrimaryUser','Associated user','text'],['Name','Inactive device','text'],['Model','Model','text'],['ManagedBy','Managed by','text'],['DaysSinceSync','Device sync age','text'],['PrimaryAccount','Account state','badge']]];
 case 'Applications':return [D.apps,[['Name','Application','text'],['Publisher','Publisher','text'],['Type','App type','text'],['Publishing','Publishing','text'],['Failures','Failures observed','text'],['Status','Coverage','badge']]];
 case 'Connectors & Tokens':return [D.connectors||[],[['Connector','Connector','text'],['Name','Name','text'],['State','State','text'],['Expiration','Expiration','text'],['DaysRemaining','Days left','text'],['LastSync','Last sync','text'],['Health','Health','badge']]];
 case 'Conditional Access':return [D.conditionalAccess||[],[['Policy','Policy','text'],['State','State','badge'],['RequiresCompliantDevice','Compliant device','badge'],['RequiresHybridJoin','Hybrid join','badge'],['RequiresAppProtection','App protection','badge'],['RequiresMfa','MFA / strength','badge'],['Users','Users','text'],['Applications','Apps','text'],['Platforms','Platforms','text']]];
 case 'Enrollment Restrictions':return [D.enrollment||[],[['Name','Restriction','text'],['Platform','Platform','text'],['PlatformBlocked','Platform blocked','badge'],['PersonalBlocked','Personal blocked','badge'],['MinOS','Min OS','text'],['Limit','Device limit','text'],['Priority','Priority','text'],['Assignments','Assignments','text']]];
 case 'Enrollment Status Page':return [D.esp||[],[['Name','Profile','text'],['ShowProgress','Show progress','badge'],['TimeoutMinutes','Timeout (min)','text'],['BlockingApps','Blocking apps','text'],['AllowResetOnFailure','Reset on failure','badge'],['AllowUseOnFailure','Use on failure','badge'],['Assignments','Assignments','text']]];
 case 'Admin Roles':return [D.adminRoles||[],[['Source','Source','text'],['Role','Role','text'],['Principal','Principal','text'],['Type','Type','text'],['Assignment','Assignment','text'],['Scope','Scope','text'],['ScopeTags','Scope tags','text']]];
 case 'Multi-Admin Approval':return [D.multiAdminApproval||[],[['Policy','Policy','text'],['Type','Protected operation','text'],['Platform','Platform','text'],['ApproverGroups','Approver groups','text'],['Modified','Last modified','text']]];
 case 'App Protection':return [D.appProtection||[],[['Policy','Policy','text'],['Platform','Platform','text'],['Assignments','Assignments','text'],['PinRequired','PIN','badge'],['Clipboard','Copy/paste','text'],['DataTransfer','Send data to','text'],['BackupBlocked','Backup blocked','badge'],['MinOS','Min OS','text'],['OfflineWipe','Offline wipe','text']]];
 case 'Scripts & Remediations':return [D.scripts||[],[['Script','Script','text'],['Kind','Kind','text'],['RunAs','Run as','text'],['SignatureCheck','Signature check','badge'],['Assignments','Assignments','text'],['Success','Success','text'],['Errors','Errors','text'],['ErrorRate','Error %','text'],['SummaryCoverage','Coverage','badge']]];
 case 'Autopilot Profiles':return [D.autopilotProfiles||[],[['Profile','Profile','text'],['Join','Join type','text'],['Mode','Mode','text'],['UserType','User account type','text'],['PreProvisioning','Pre-provisioning','badge'],['ConvertDevices','Convert all targeted','badge'],['NameTemplate','Name template','text'],['Assignments','Assignments','text']]];
 case 'Assignment Filters':return [D.assignmentFilters||[],[['Filter','Filter','text'],['Platform','Platform','text'],['Rule','Rule','text'],['ReferencedBy','Referenced by','text']]];
 case 'Assignment Hygiene':return [D.assignmentHygiene||[],[['Issue','Issue','text'],['Object','Object','text'],['ObjectKind','Object type','text'],['Group','Group','text'],['Detail','Detail','text']]];
 case 'Control Coverage':return [D.controlCoverage||[],[['Control','Control','text'],['Population','Population','text'],['Total','Total','text'],['Covered','Covered','text'],['Gap','Gap','text'],['Coverage','Coverage %','text'],['Note','Note','text']]];
 case 'OS Lifecycle':return [D.osLifecycle||[],[['Device','Device','text'],['Platform','Platform','text'],['Release','Release','text'],['Version','Version','text'],['Edition','Edition','text'],['EndOfServicing','End of servicing','text'],['DaysRemaining','Days left','text'],['State','State','badge']]];
 case 'Patch Lag':return [D.patchLag||[],[['Device','Device','text'],['Build','Build','text'],['Revision','Revision','text'],['NewestRevisionInTenant','Newest in tenant','text'],['RevisionGap','Gap','text'],['LastSync','Last sync','text']]];
 case 'Hardware Readiness':return [D.hardware||[],[['Device','Device','text'],['Model','Model','text'],['Windows11','Windows 11','badge'],['TPM','TPM','badge'],['SecureBoot','Secure Boot','badge'],['Processor','Processor','badge'],['RAM','RAM','badge'],['Source','Source','text']]];
 case 'Duplicate Devices':return [D.duplicates||[],[['Serial','Serial','text'],['Device','Device','text'],['LastSync','Last sync','text'],['Enrolled','Enrolled','text'],['PrimaryUser','Primary user','text'],['Records','Records','text']]];
 case 'Intune Settings Review':return [D.tenantReview||[],[['Area','Area','text'],['Check','Check','text'],['Result','Result','text'],['Status','Status','badge'],['Detail','Detail','text']]];
 case 'Compliance Actions':return [D.complianceActions||[],[['Policy','Policy','text'],['Type','Type','text'],['Assignments','Assignments','text'],['MarkNoncompliant','Mark noncompliant','text'],['Notifications','Notifications','text'],['Retire','Retire','text'],['Actions','Actions','text']]];
 case 'App Install Summary':return [D.appAggregate||[],[['App','Application','text'],['Platform','Platform','text'],['Required','Required','badge'],['Installed','Installed','text'],['Failed','Failed','text'],['Pending','Pending','text'],['NotInstalled','Not installed','text'],['FailedPercent','Failed %','text']]];
 case 'Update Coverage':return [D.updateCoverage||[],[['Platform','Platform','text'],['Devices','Devices','text'],['Mechanism','Mechanism','text'],['Policies','Policies','text'],['Status','Status','badge']]];
 case 'Enrollment Profiles':return [D.enrollProfiles||[],[['Platform','Platform','text'],['Profile','Profile','text'],['Mode','Mode','text'],['TokenExpires','Token expires','text'],['DaysLeft','Days left','text'],['EnrolledDevices','Enrolled devices','text'],['Supervised','Supervised','badge'],['Mandatory','Mandatory','badge'],['Status','Status','badge']]];
 case 'Audit Actions':return [D.auditActions||[],[['Date','Date','text'],['Action','Action','badge'],['Actor','Actor','text'],['Target','Target','text'],['Result','Result','text'],['Activity','Activity','text']]];
 case 'Custom Roles':return [D.customRoles||[],[['Role','Role','text'],['Permissions','Permissions','text'],['DestructivePermissions','Destructive permissions','text'],['Assignments','Assignments','text'],['Detail','Detail','text']]];
 case 'Cross-Source':return [D.crossSource||[],[['Issue','Issue','text'],['Device','Device','text'],['OS','OS','text'],['Detail','Detail','text'],['LastActivity','Last activity','text']]];
 default:return [D.devices,commonCols]
}}
function selectTab(t){selected=t;by('search').value='';by('policyStatusFilter').value='';by('oibStatusFilter').value='';by('policyStatusFilter').classList.toggle('hidden',selected!=='Policy Deployment');by('oibStatusFilter').classList.add('hidden');for(const k of ['osFilter','complianceFilter','stateFilter','managedFilter','manufacturerFilter','ownershipFilter','encryptionFilter','autopilotFilter'])by(k).value='';redrawTabs();draw();if(window.matchMedia('(max-width:850px)').matches)closeInventorySidebar()}
function redrawTabs(){by('tabs').innerHTML=tabGroups.map(([g,list])=>`<div class="tab-group"><div class="tab-group-title">${safe(g)}</div>${list.filter(t=>tabs.some(x=>x[0]===t)).map(t=>`<button type="button" class="tab ${t===selected?'active':''}" data-tab="${safe(t)}">${safe(tabLabel(t))}<span class="smallcount">${rowsFor(t)[0].length}</span></button>`).join('')}</div>`).join('');by('tabs').querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>selectTab(b.dataset.tab)))}
function fillSelect(el,values,label){el.innerHTML=`<option value="">${safe(label)}</option>`+[...new Set(values.filter(Boolean))].sort().map(v=>`<option value="${safe(v)}">${safe(v)}</option>`).join('')}
fillSelect(by('osFilter'),D.devices.map(x=>x.OS),'All operating systems');fillSelect(by('complianceFilter'),D.devices.map(x=>x.Compliance),'All compliance states');fillSelect(by('stateFilter'),D.devices.map(x=>x.PrimaryAccount),'All account states');
fillSelect(by('managedFilter'),D.devices.map(x=>x.ManagedBy),'All management types');
fillSelect(by('manufacturerFilter'),D.devices.map(x=>x.Manufacturer),'All manufacturers');
fillSelect(by('ownershipFilter'),D.devices.map(x=>x.Ownership),'All ownership types');
fillSelect(by('encryptionFilter'),D.devices.map(x=>x.Encrypted),'All encryption states');
fillSelect(by('autopilotFilter'),D.devices.map(x=>x.Autopilot),'All Autopilot states');
fillSelect(by('policyStatusFilter'),(D.policyDeployment||[]).map(x=>x.Status),'All policy statuses');
fillSelect(by('oibStatusFilter'),(D.oibComparison||[]).map(x=>x.Status),'All baseline results');
function draw(){let t=tabs.find(x=>x[0]===selected);by('sectionTitle').textContent=t[1];by('sectionInfo').textContent=t[2];let [rows,cols]=rowsFor(selected),q=by('search').value.trim().toLowerCase(),os=by('osFilter').value,comp=by('complianceFilter').value,state=by('stateFilter').value, managed=by('managedFilter').value, manufacturer=by('manufacturerFilter').value, ownership=by('ownershipFilter').value, encryption=by('encryptionFilter').value, autopilot=by('autopilotFilter').value;let policyStatus=by('policyStatusFilter').value,oibStatus=by('oibStatusFilter').value;
rows=rows.filter(r=>(!q||Object.values(r).some(v=>String(v??'').toLowerCase().includes(q)))&&(!os||(selected==='OpenIntuneBaseline' ? r.OS===os : (!r.OS||r.OS===os)))&&(!comp||!r.Compliance||r.Compliance===comp)&&(!state||!r.PrimaryAccount||r.PrimaryAccount===state)&&(!managed||!r.ManagedBy||r.ManagedBy===managed)&&(!manufacturer||!r.Manufacturer||r.Manufacturer===manufacturer)&&(!ownership||!r.Ownership||r.Ownership===ownership)&&(!encryption||!r.Encrypted||r.Encrypted===encryption)&&(!autopilot||!r.Autopilot||r.Autopilot===autopilot)&&(!policyStatus||selected!=='Policy Deployment'||r.Status===policyStatus)&&(!oibStatus||selected!=='OpenIntuneBaseline'||(oibStatus==='Match'?r.Match>0:oibStatus==='Different'?r.Different>0:oibStatus==='Conflicting'?r.Conflicting>0:oibStatus==='Missing'?r.Missing>0:oibStatus==='Not assessed'?r.Unassessed>0:true)));
by('resultCount').textContent=selected==='OpenIntuneBaseline'?`${rows.length.toLocaleString()} baseline policies · detailed setting results available in OpenIntuneBaseline-Comparison.csv`:`${rows.length.toLocaleString()} results`;
by('thead').innerHTML='<tr>'+cols.map(c=>`<th>${safe(c[1])}</th>`).join('')+'</tr>';
by('tbody').innerHTML=rows.map(r=>'<tr>'+cols.map(c=>{let v=r[c[0]];return `<td>${c[2]==='badge'?badge(v):c[2]==='defender'?defenderBadge(v,c[0]):c[2]==='assignment'?assignmentBadge(v,r):c[2].startsWith('oibcount')?oibCountBadge(v,c[2],r):c[2]==='oibtenant'?oibTenantPoliciesCell(r):c[2]==='oibsetting'?oibSettingCell(r):c[2]==='oibvalue'?oibValueCell(v):(v===null||v===undefined||v==='')?'<span class="small">—</span>':safe(v)}</td>`}).join('')+'</tr>').join('');
by('empty').classList.toggle('hidden',rows.length!==0);}
by('search').addEventListener('input',draw);['osFilter','complianceFilter','stateFilter','managedFilter','manufacturerFilter','ownershipFilter','encryptionFilter','autopilotFilter','policyStatusFilter','oibStatusFilter'].forEach(id=>by(id).addEventListener('change',()=>{draw();if(id==='osFilter')renderOibSummary()}));by('clear').addEventListener('click',()=>{['search','osFilter','complianceFilter','stateFilter','managedFilter','manufacturerFilter','ownershipFilter','encryptionFilter','autopilotFilter','policyStatusFilter','oibStatusFilter'].forEach(id=>by(id).value='');if(selected==='OpenIntuneBaseline')by('osFilter').value='Windows';draw();renderOibSummary()});
redrawTabs();draw();
// ===================== v3.40 views =====================
const sevTone=s=>s==='High'||s==='Critical'?'bad':s==='Medium'?'warn':'info';
const scoreCol=v=>v>=85?'var(--green)':v>=70?'var(--blue)':v>=50?'var(--amber)':'var(--red)';
const trendHtml=d=>d===null||d===undefined?'':`<span class="fd-trend" style="color:${d>0?'var(--green)':d<0?'var(--red)':'var(--muted)'}">${d>0?'▲ +'+d:d<0?'▼ '+d:'■ 0'}</span>`;
(function(){
 const S=D.scores||{domains:[]};by('scoreNote').textContent=S.note||'';
 const overallTrend=((D.comparison&&D.comparison.Kpis)||[]).filter(k=>k.Metric==='overallScore').map(k=>k.Delta)[0];
 const ov=Number(S.overall)||0,rating=ov>=85?'Strong':ov>=70?'Good':ov>=50?'Needs improvement':'At risk',rc=scoreCol(ov),circ=2*Math.PI*64;
 by('heroRing').innerHTML=`<div class="score-ring"><svg viewBox="0 0 156 156" role="img" aria-label="Overall score ${ov} / 100"><circle class="track" cx="78" cy="78" r="64"/><circle class="value" cx="78" cy="78" r="64" stroke="${rc}" stroke-dasharray="${(circ*Math.max(0,Math.min(100,ov))/100).toFixed(1)} ${circ.toFixed(1)}"/></svg><div class="center"><b style="color:${rc}">${ov}</b><small>/ 100</small></div></div><div class="ring-meta"><span class="grade" style="background:color-mix(in srgb,${rc} 16%,transparent);color:${rc}">${safe(rating)}</span>${trendHtml(overallTrend)}</div>`;
 const hi=(D.findings||[]).filter(f=>f.Severity==='High').length;
 by('heroSummary').innerHTML=`<span style="--dot:var(--red)">${safe(`${summary.noncompliant} of ${summary.total} devices noncompliant`)}</span><span style="--dot:var(--amber)">${safe(`${hi} high-severity findings`)}</span><span style="--dot:var(--accent)">${safe(`${(D.actionPlan||[]).filter(a=>a.Horizon==='Quick wins').length} quick wins`)}</span>`;
 by('overviewScores').innerHTML='<div class="domain-bars">'+(S.domains||[]).map(c=>{const v=Math.max(0,Math.min(100,Number(c.Score)||0));return `<div class="domain-row" title="H ${c.High} / M ${c.Medium} / L ${c.Low}"><span class="dn">${safe(c.Domain)}</span><span class="bar"><i style="width:${v}%;background:${scoreCol(v)}"></i></span><span class="ds" style="color:${scoreCol(v)}">${v}</span><span class="dt">${trendHtml(c.Trend)||'—'}</span></div>`}).join('')+'</div>';
 const qw=(D.actionPlan||[]).filter(a=>a.Horizon==='Quick wins').slice(0,5);
 by('quickWins').innerHTML=qw.length?qw.map(a=>`<a class="risk-row" href="#plan"><span class="pill ${sevTone(a.Severity)}">${safe(a.Severity)}</span><span class="t">${safe(a.Recommendation)}</span><strong>${safe(a.Affected)}</strong></a>`).join(''):'<p class="micro muted">Nothing in this horizon.</p>';
 by('topRisks').innerHTML=sortedFindings.length?sortedFindings.slice(0,5).map(f=>`<a class="risk-row" href="#findings"><span class="pill ${sevTone(f.Severity)}">${safe(f.Severity)}</span><span class="t">${safe(f.Finding)}</span><strong>${safe(f.Affected)}</strong></a>`).join(''):'<p class="micro muted">No findings produced from the available evidence.</p>';
 const C=D.comparison||{};
 if(C.Available){const g={};(C.Findings||[]).forEach(f=>g[f.Change]=(g[f.Change]||0)+1);by('overviewDelta').innerHTML=`<div class="fd-cmp"><span class="micro muted">Since previous run</span><span class="micro muted">${safe(C.PreviousGenerated)}</span>`+['New','Worse','Resolved','Improved'].map(k=>`<span class="pill ${k==='New'||k==='Worse'?'bad':'good'}"><span>${k}</span> ${g[k]||0}</span>`).join('')+'</div>'}
})();
(function(){
 const plan=D.actionPlan||[];
 by('planBoard').innerHTML='<div class="fd-plan">'+['Quick wins','30 days','90 days'].map(hz=>{const it=plan.filter(a=>a.Horizon===hz);return `<div><h3><span>${safe(hz)}</span> <span class="smallcount">${it.length}</span></h3>${it.length?'<ol>'+it.map(a=>`<li><span class="pill ${sevTone(a.Severity)}">${safe(a.Severity)}</span> <span>${safe(a.Recommendation)}</span><small><span>${safe(a.Finding)}</span> · ${safe(a.Affected)} · <span>Effort</span> <span>${safe(a.Effort)}</span></small></li>`).join('')+'</ol>':'<p class="micro muted">Nothing in this horizon.</p>'}</div>`}).join('')+'</div>';
 const C=D.comparison||{};
 if(C.Available&&(C.Findings||[]).length){by('planComparison').innerHTML=`<p class="micro muted"><span>Previous run</span> ${safe(C.PreviousGenerated)}</p><div class="tablebox"><table><thead><tr><th>Change</th><th>Severity</th><th>Area</th><th>Finding</th><th>Previous</th><th>Current</th></tr></thead><tbody>${C.Findings.map(f=>`<tr><td><span class="pill ${f.Change==='New'||f.Change==='Worse'?'bad':f.Change==='Unchanged'?'info':'good'}">${safe(f.Change)}</span></td><td>${badge(f.Severity)}</td><td>${safe(f.Area)}</td><td>${safe(f.Finding)}</td><td>${safe(f.Previous??'—')}</td><td>${safe(f.Current)}</td></tr>`).join('')}</tbody></table></div>`}
 else{by('planComparison').innerHTML='<p class="micro muted">No previous run of this tenant found for comparison. Keep the output folder: the next run will compare automatically.</p>'}
 const cols=[['Priority','#'],['Horizon','Horizon'],['Severity','Severity'],['Domain','Domain'],['Finding','Finding'],['Affected','Affected'],['Effort','Effort'],['Recommendation','Recommended action'],['CIS','CIS v8'],['EssentialEight','Essential Eight'],['NIST','NIST CSF 2.0']];
 by('planThead').innerHTML='<tr>'+cols.map(c=>`<th>${safe(c[1])}</th>`).join('')+'</tr>';
 by('planTbody').innerHTML=plan.map(a=>'<tr>'+cols.map(c=>`<td>${c[0]==='Severity'?badge(a[c[0]]):safe(a[c[0]]??'—')}</td>`).join('')+'</tr>').join('')||'<tr><td colspan="11" class="empty">No actions.</td></tr>';
})();
(function(){
 const plan=D.actionPlan||[];const ev={};for(const f of (D.findings||[]))ev[f.Area+'|'+f.Finding]=f;
 const sevOrder={High:0,Medium:1,Low:2,Informational:3};
 const all=[...plan].sort((a,b)=>(sevOrder[a.Severity]??9)-(sevOrder[b.Severity]??9)||b.Affected-a.Affected);
 fillSelect(by('fSeverity'),all.map(x=>x.Severity),'All severities');fillSelect(by('fDomain'),all.map(x=>x.Domain),'All domains');fillSelect(by('fHorizon'),all.map(x=>x.Horizon),'All horizons');
 by('navFindings').textContent=all.length||'';
 function drawFindings(){const q=by('fSearch').value.trim().toLowerCase(),sv=by('fSeverity').value,dm=by('fDomain').value,hz=by('fHorizon').value;
  const rows=all.filter(a=>(!sv||a.Severity===sv)&&(!dm||a.Domain===dm)&&(!hz||a.Horizon===hz)&&(!q||[a.Finding,a.FindingFr,a.Area,a.Recommendation,a.RecommendationFr,(ev[a.Area+'|'+a.Finding]||{}).Evidence].some(v=>String(v||'').toLowerCase().includes(q))));
  by('fCount').textContent=`${rows.length} / ${all.length}`;
  by('findingsList').innerHTML=rows.length?rows.map(a=>{const e=ev[a.Area+'|'+a.Finding]||{};return `<article class="finding-card sev-${sevTone(a.Severity)}"><div class="finding-meta"><span class="pill ${sevTone(a.Severity)}">${safe(a.Severity)}</span><span>${safe(a.Domain)}</span><span>· ${safe(a.Area)}</span><span>·</span><span>${safe(a.Horizon)}</span><span>· </span><span>Effort</span><span>${safe(a.Effort)}</span>${e.Coverage&&e.Coverage!=='Verified'?`<span class="pill info">${safe(e.Coverage)}</span>`:''}</div><h3><span>${safe(a.Finding)}</span> <span class="muted">(${safe(a.Affected)})</span></h3><p><strong>Action:</strong> <span>${safe(a.Recommendation)}</span></p>${e.Evidence?`<p class="ev"><strong>Evidence:</strong> ${safe(e.Evidence)}</p>`:''}</article>`}).join(''):'<div class="empty">No findings match these filters.</div>';}
 ['fSeverity','fDomain','fHorizon'].forEach(id=>by(id).addEventListener('change',drawFindings));by('fSearch').addEventListener('input',drawFindings);drawFindings();
})();
function renderBaselineTable(){
 const st=by('oibViewStatus').value;
 const rows=oibPolicySummary.filter(r=>r.OS===oibPlatformSel&&(!st||(st==='Match'?r.Match>0:st==='Different'?r.Different>0:st==='Conflicting'?r.Conflicting>0:r.Missing>0)));
 const cols=[['BaselinePolicy','OpenIntuneBaseline policy'],['TenantPolicies','Matching tenant configuration'],['Total','Settings'],['Match','Match'],['Different','Different'],['Conflicting','Conflicting'],['Missing','Missing']];
 by('oibThead').innerHTML='<tr>'+cols.map(c=>`<th>${safe(c[1])}</th>`).join('')+'</tr>';
 by('oibTbody').innerHTML=rows.map(r=>'<tr>'+cols.map(([k])=>`<td>${k==='TenantPolicies'?oibTenantPoliciesCell(r):k==='Match'?oibCountBadge(r.Match,'oibcountgood',r):k==='Different'?oibCountBadge(r.Different,'oibcountbad',r):k==='Conflicting'?oibCountBadge(r.Conflicting,'oibcountconflict',r):k==='Missing'?oibCountBadge(r.Missing,'oibcountmissing',r):safe(r[k])}</td>`).join('')+'</tr>').join('');
 by('oibEmpty').classList.toggle('hidden',rows.length!==0);
}
document.querySelectorAll('[data-oib-platform]').forEach(b=>b.addEventListener('click',()=>{oibPlatformSel=b.dataset.oibPlatform;document.querySelectorAll('[data-oib-platform]').forEach(x=>x.classList.toggle('active',x===b));renderOibSummary();renderBaselineTable()}));
by('oibViewStatus').addEventListener('change',renderBaselineTable);
by('oibTbody').addEventListener('click',e=>{const btn=e.target.closest('[data-oib-row][data-oib-status]');if(!btn)return;openOibDrawer(Number(btn.dataset.oibRow),btn.dataset.oibStatus,btn.hasAttribute('data-oib-tenant')?Number(btn.dataset.oibTenant):null)});
renderOibSummary();renderBaselineTable();
(function(){
 const entries=Object.entries(D.collections||{});
 const cls=v=>/^(complete|discovered|assessed)/i.test(v)?'complete':/^(partial|docx only|not verified)/i.test(v)?'partial':/^(unavailable|not assessed)/i.test(v)?'unavailable':'';
 by('qualityStatus').innerHTML=entries.length?`<div class="tablebox"><table><thead><tr><th>Collection</th><th>Status</th></tr></thead><tbody>${entries.sort((a,b)=>{const r={unavailable:0,partial:1,'':2,complete:3};return r[cls(String(a[1]))]-r[cls(String(b[1]))]||a[0].localeCompare(b[0])}).map(([k,v])=>`<tr><td>${safe(k)}</td><td><span class="statuschip ${cls(String(v))}">${safe(v)}</span></td></tr>`).join('')}</tbody></table></div>`:'<p class="micro muted">No collection status recorded.</p>';
 const rs=D.reportSources||[];
 by('qualityReports').innerHTML=rs.length?`<div class="tablebox"><table><thead><tr><th>Report</th><th>Status</th><th>Rows</th><th>Filter used</th><th>Columns</th></tr></thead><tbody>${rs.map(r=>`<tr><td>${safe(r.Report)}</td><td><span class="statuschip ${r.Status==='Complete'?'complete':'unavailable'}">${safe(r.Status)}</span>${r.Error?`<div class="micro muted">${safe(r.Error)}</div>`:''}</td><td>${safe(r.Rows)}</td><td class="micro">${safe(r.Filter||'—')}</td><td class="micro">${safe(r.Columns||'—')}</td></tr>`).join('')}</tbody></table></div>`:'<p class="micro muted">No Intune export report was used.</p>';
 const w=D.warnings||[];by('navWarnings').textContent=w.length||'';
 by('qualityWarnings').innerHTML=w.length?`<ol class="warn-list">${w.map(x=>`<li>${safe(x)}</li>`).join('')}</ol>`:'<p class="micro muted">No collection warnings.</p>';
})();
by('kpis').addEventListener('click',e=>{const b=e.target.closest('[data-goto]');if(!b)return;selectTab(b.dataset.goto);location.hash='#inventory'});
const views=['overview','plan','findings','baseline','inventory','zerotrust','quality'];
function showView(){let v=(location.hash||'#overview').slice(1);if(!views.includes(v))v='overview';const navA=document.querySelector(`#mainNav a[data-view="${v}"] .nav-label`);if(navA)by('pageTitle').textContent=navA.getAttribute('data-en')||navA.textContent;for(const id of views)by('view-'+id).classList.toggle('hidden',id!==v);document.querySelectorAll('#mainNav a').forEach(a=>{const on=a.dataset.view===v;a.classList.toggle('active',on);if(on)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')});window.scrollTo(0,0)}
// ===================== v3.73 Zero Trust view =====================
(function(){
 const Z=D.zeroTrust||[];
 const tone=s=>s==='Pass'?'good':s==='Fail'?'bad':s==='Warning'?'warn':'info';
 const order={'Fail':0,'Warning':1,'Not verified':2,'Pass':3,'Not applicable':4};
 const cnt=k=>Z.filter(r=>r.Status===k).length;
 const pass=cnt('Pass'),fail=cnt('Fail'),warn=cnt('Warning'),na=cnt('Not applicable'),nv=cnt('Not verified');
 const scored=pass+fail+warn,pct=scored?Math.round(100*pass/scored):null;
 by('navZt').textContent=fail||'';
 const seg=(v,c)=>Z.length&&v?`<span style="width:${(100*v/Z.length).toFixed(2)}%;background:${c}"></span>`:'';
 const stats=[['Pass','good',pass],['Fail','bad',fail],['Warning','warn',warn],['Not verified','info',nv],['Not applicable','info',na]];
 by('ztSummary').innerHTML=Z.length?`<div class="oib-hero"><div class="oib-score"><span>Tests passed</span><b>${pct===null?'—':pct+'%'}</b><span>${pass} / ${scored}</span></div><div><div class="oib-stat-row">${stats.map(([l,t,v])=>`<div class="oib-stat ${t}"><span>${l}</span><b>${v}</b></div>`).join('')}</div><div class="oib-meter">${seg(pass,'var(--green)')}${seg(warn,'var(--amber)')}${seg(fail,'var(--red)')}${seg(nv,'var(--accent)')}${seg(na,'var(--faint)')}</div></div></div><p class="micro muted">Score = passed / (passed + failed + warning). Not applicable and not verified tests are excluded.</p>`:'<p class="micro muted">Zero Trust device tests were not run.</p>';
 fillSelect(by('ztCategory'),Z.map(r=>r.Category),'All platforms');
 fillSelect(by('ztStatus'),Z.map(r=>r.Status),'All results');
 function drawZt(){
  const q=by('ztSearch').value.trim().toLowerCase(),c=by('ztCategory').value,s=by('ztStatus').value;
  const rows=Z.filter(r=>(!c||r.Category===c)&&(!s||r.Status===s)&&(!q||[r.Test,r.TestFr,r.Evidence,r.Policies,r.Recommendation].some(v=>String(v||'').toLowerCase().includes(q)))).sort((a,b)=>(order[a.Status]??9)-(order[b.Status]??9)||String(a.Category).localeCompare(String(b.Category)));
  by('ztCount').textContent=`${rows.length} / ${Z.length}`;
  by('ztTbody').innerHTML=rows.length?rows.map(r=>`<tr><td><span class="pill ${tone(r.Status)}">${safe(r.Status)}</span></td><td>${safe(r.Category)}</td><td>${safe(r.Test)}</td><td class="micro">${safe(r.Evidence)}</td><td class="micro">${safe(r.Policies||'—')}</td><td class="micro">${safe(r.Recommendation)}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No test matches these filters.</td></tr>';
 }
 ['ztCategory','ztStatus'].forEach(id=>by(id).addEventListener('change',drawZt));by('ztSearch').addEventListener('input',drawZt);drawZt();
})();
window.addEventListener('hashchange',showView);
showView();
// ===================== v3.42 FR / EN language switch =====================
// The report is rendered in English, then translated in place. Original English text is kept per
// node, so switching back is lossless and re-rendered content (filters, tabs) is translated again.
const I18N_FR={
// navigation & headings
'Overview':'Vue d\'ensemble','Action plan':'Plan d\'action','Findings':'Constats','Baseline':'Baseline','Inventory':'Inventaire','Data quality':'Qualité des données',
'Report sections':'Sections du rapport','DEVICE MANAGEMENT REPORT':'RAPPORT DE GESTION DES APPAREILS','Intune Assessment':'Évaluation Intune',
'Managed Devices Assessment':'Évaluation des appareils gérés','Security posture, enrollment hygiene, application health and device inventory':'Posture de sécurité, hygiène d\'inscription, santé des applications et inventaire des appareils',
'TENANT:':'TENANT :','GENERATED:':'GÉNÉRÉ :','INACTIVE THRESHOLD:':'SEUIL D\'INACTIVITÉ :','DAYS':'JOURS',
'Device compliance':'Conformité des appareils','Operating systems':'Systèmes d\'exploitation','Management platforms':'Plateformes de gestion','Device encryption':'Chiffrement des appareils',
'Maturity score':'Score de maturité','Top risks':'Principaux risques','All findings →':'Tous les constats →','Since previous run':'Depuis le passage précédent','Previous run':'Passage précédent',
'REMEDIATION':'REMÉDIATION','Prioritized action plan':'Plan d\'action priorisé','Quick wins first, then 30 and 90 days. Effort and impact are indicative.':'Gains rapides d\'abord, puis 30 et 90 jours. L\'effort et l\'impact sont indicatifs.',
'Change since previous run':'Évolution depuis le passage précédent','All actions · framework mapping':'Toutes les actions · correspondance avec les référentiels',
'Indicative mapping to CIS Controls v8, Essential Eight and NIST CSF 2.0.':'Correspondance indicative avec CIS Controls v8, Essential Eight et NIST CSF 2.0.',
'EVIDENCE':'PREUVES','Assessment findings':'Constats de l\'évaluation','Evidence-based findings. Unavailable Graph data is never reported as noncompliant.':'Constats fondés sur les preuves. Les données Graph indisponibles ne sont jamais considérées comme non conformes.',
'Search findings...':'Rechercher un constat...','Search findings':'Rechercher un constat','OPENINTUNEBASELINE':'OPENINTUNEBASELINE','Baseline comparison':'Comparaison avec la baseline',
'Configured Settings Catalog values compared with the OpenIntuneBaseline reference. Not a measure of device enforcement.':'Valeurs configurées du Settings Catalog comparées à la référence OpenIntuneBaseline. Ne mesure pas l\'application réelle sur les appareils.',
'Platform':'Plateforme','Baseline policies':'Stratégies de la baseline','Baseline result':'Résultat de la baseline','All results':'Tous les résultats',
'One row per baseline policy. Select a count to see the impacted settings. Full detail: OpenIntuneBaseline-Comparison.csv.':'Une ligne par stratégie de la baseline. Sélectionnez un nombre pour voir les paramètres concernés. Détail complet : OpenIntuneBaseline-Comparison.csv.',
'No baseline policy for this selection.':'Aucune stratégie de baseline pour cette sélection.','INVENTORY':'INVENTAIRE','Explore inventory':'Explorer l\'inventaire',
'Filter your inventory, investigate issues, and export CSV evidence.':'Filtrez l\'inventaire, analysez les problèmes et exportez les preuves en CSV.',
'DATA QUALITY':'QUALITÉ DES DONNÉES','Collection status & limitations':'État des collectes et limites','Collection status':'État des collectes','Warnings':'Avertissements',
'What was collected, what was partial and why. Unavailable data is never scored as healthy or unhealthy.':'Ce qui a été collecté, ce qui est partiel et pourquoi. Les données indisponibles ne sont jamais notées comme saines ou non saines.',
'Generated by Invoke-IntuneAssessmentDashboard.ps1 v3.60 · Microsoft Graph v1.0 + beta · Read-only':'Généré par Invoke-IntuneAssessmentDashboard.ps1 v3.60 · Microsoft Graph v1.0 + beta · Lecture seule',
'INVENTORY SECTIONS':'SECTIONS DE L\'INVENTAIRE','☰   Inventory sections':'☰   Sections de l\'inventaire','Inventory navigation':'Navigation de l\'inventaire','Close inventory menu':'Fermer le menu',
'Assessment sections':'Sections de l\'évaluation','Search device, user, serial, application...':'Rechercher un appareil, utilisateur, numéro de série, application...','Search':'Rechercher',
'Clear filters':'Effacer les filtres','No matching records for the selected filters.':'Aucun résultat pour ces filtres.','Close panel':'Fermer le panneau',
'Impacted settings':'Paramètres concernés','Filter impacted settings':'Filtrer les paramètres concernés','Filter setting name, ID, or value...':'Filtrer par nom, ID ou valeur...',
'OPENINTUNEBASELINE · SETTINGS EVIDENCE':'OPENINTUNEBASELINE · PREUVES PAR PARAMÈTRE','Baseline comparison status':'État de la comparaison','View in inventory →':'Voir dans l\'inventaire →',
'Configured-settings alignment':'Alignement des paramètres configurés','reference:':'référence :','Platform:':'Plateforme :','Baseline:':'Baseline :','Tenant policy:':'Stratégie du tenant :','Tenant configurations:':'Configurations du tenant :',
// KPIs
'Managed devices':'Appareils gérés','Noncompliant':'Non conformes','Inactive devices':'Appareils inactifs','Not encrypted':'Non chiffrés','App failures':'Échecs d\'applications','Disabled primary users':'Utilisateurs principaux désactivés',
// filters
'All severities':'Toutes les sévérités','All domains':'Tous les domaines','All horizons':'Tous les horizons','All Autopilot states':'Tous les états Autopilot','All account states':'Tous les états de compte',
'All baseline results':'Tous les résultats','All compliance states':'Tous les états de conformité','All encryption states':'Tous les états de chiffrement','All management types':'Tous les types de gestion',
'All manufacturers':'Tous les fabricants','All operating systems':'Tous les systèmes','All ownership types':'Tous les types de propriété','All policy statuses':'Tous les états de stratégie',
'Severity':'Sévérité','Domain':'Domaine','Horizon':'Horizon','Operating system':'Système d\'exploitation','Compliance':'Conformité','Account state':'État du compte','Managed by':'Géré par','Manufacturer':'Fabricant','Ownership':'Propriété','Encryption':'Chiffrement','Autopilot':'Autopilot',
// inventory groups & tabs
'Devices':'Appareils','Identity & access':'Identité et accès','Applications':'Applications','Configuration':'Configuration','Security':'Sécurité','Updates & lifecycle':'Mises à jour et cycle de vie','Enrollment & tenant':'Inscription et tenant','Other':'Autres',
'All devices':'Tous les appareils','Inactive Devices':'Appareils inactifs','Not Encrypted':'Non chiffrés','No Autopilot Record':'Sans enregistrement Autopilot','Multiple Users':'Utilisateurs multiples','OS Edition Overview':'Éditions de l\'OS',
'Duplicate Devices':'Appareils en double','Cross-Source':'Cohérence entre sources','Hardware Readiness':'Préparation matérielle','Disabled Primary Users':'Utilisateurs principaux désactivés','Inactive Primary Users':'Utilisateurs d\'appareils inactifs',
'Admin Roles':'Rôles d\'administration','Conditional Access':'Accès conditionnel','Application Failures':'Échecs d\'applications','App Protection':'Protection des applications','Scripts & Remediations':'Scripts et remédiations',
'Configuration Policies':'Stratégies de configuration','Tenant GUI Settings':'Paramètres du tenant','Policy Deployment':'Déploiement des stratégies','Policy Failure Analysis':'Analyse des échecs de stratégies','Setting Failures':'Échecs de paramètres',
'Assignment Filters':'Filtres d\'assignation','Assignment Hygiene':'Hygiène des assignations','Endpoint Security':'Sécurité des points de terminaison','Endpoint Security Failures':'Échecs Endpoint Security','Defender Health':'Santé Defender',
'BitLocker Escrow':'Sauvegarde BitLocker','Control Coverage':'Couverture des contrôles','Windows Updates':'Windows Update','Feature Update Status':'Mises à jour de fonctionnalité','Windows Builds':'Builds Windows','OS Lifecycle':'Cycle de vie de l\'OS','Patch Lag':'Retard de correctifs',
'Enrollment Restrictions':'Restrictions d\'inscription','Enrollment Status Page':'Page d\'état d\'inscription','Autopilot Profiles':'Profils Autopilot','Connectors & Tokens':'Connecteurs et jetons','Multi-Admin Approval':'Approbation multi-administrateurs',
// tab titles
'All managed devices':'Tous les appareils gérés','Noncompliant devices':'Appareils non conformes','Inactive managed devices':'Appareils gérés inactifs','Devices not encrypted':'Appareils non chiffrés','No matching Autopilot registration':'Aucun enregistrement Autopilot correspondant',
'Multiple users / devices':'Utilisateurs avec plusieurs appareils','Windows operating system editions':'Éditions de Windows','Duplicate serial numbers':'Numéros de série en double','Intune / Entra / Defender consistency':'Cohérence Intune / Entra / Defender',
'TPM, Secure Boot and Windows 11 readiness':'TPM, Secure Boot et préparation à Windows 11','Disabled primary-user accounts':'Comptes d\'utilisateurs principaux désactivés','Users associated with inactive devices':'Utilisateurs associés à des appareils inactifs',
'Intune RBAC and privileged directory roles':'RBAC Intune et rôles d\'annuaire privilégiés','Conditional Access device controls':'Contrôles d\'appareil de l\'accès conditionnel','App installation failures':'Échecs d\'installation d\'applications',
'App protection (MAM) policies':'Stratégies de protection des applications (MAM)','Scripts and remediations':'Scripts et remédiations','Configuration policy inventory':'Inventaire des stratégies de configuration',
'Tenant Settings Catalog · GUI names and values':'Settings Catalog du tenant · noms et valeurs','Policy deployment results':'Résultats de déploiement des stratégies','Policy failure analysis':'Analyse des échecs de stratégies','Policy setting failures':'Échecs de paramètres de stratégie',
'Assignment filters':'Filtres d\'assignation','Assignment hygiene':'Hygiène des assignations','Endpoint Security policy inventory':'Inventaire des stratégies Endpoint Security','Endpoint Security deployment failures':'Échecs de déploiement Endpoint Security',
'Defender device protection signals':'Signaux de protection Defender','BitLocker recovery-key escrow evidence':'Preuves de sauvegarde des clés BitLocker','Measured security control coverage':'Couverture mesurée des contrôles de sécurité',
'Windows Update configuration':'Configuration Windows Update','Feature update device status':'État des mises à jour de fonctionnalité','Windows build distribution':'Répartition des builds Windows','Operating system support status':'État du support des systèmes d\'exploitation',
'Windows patch lag (heuristic)':'Retard de correctifs Windows (estimation)','Enrollment restrictions and limits':'Restrictions et limites d\'inscription','Enrollment Status Page (ESP) profiles':'Profils de page d\'état d\'inscription (ESP)',
'Autopilot deployment profiles':'Profils de déploiement Autopilot','Connector and token expiration':'Expiration des connecteurs et jetons','Multi-admin approval policies':'Stratégies d\'approbation multi-administrateurs','Intune managed applications':'Applications gérées par Intune',
// tab descriptions
'All managed-device records from Intune.':'Tous les enregistrements d\'appareils gérés dans Intune.',
'Detailed failed compliance settings when Intune returns them; policy-only and unavailable results are labeled explicitly.':'Paramètres de conformité en échec quand Intune les retourne ; les résultats au niveau stratégie ou indisponibles sont indiqués.',
'Only records where Intune explicitly reports isEncrypted = false. Unknown values are not counted as unencrypted.':'Seulement les appareils pour lesquels Intune indique isEncrypted = false. Les valeurs inconnues ne sont pas comptées.',
'Windows devices without a matching Autopilot identity by managed-device ID or serial. This does not verify hardware hash presence.':'Appareils Windows sans identité Autopilot correspondante (ID ou numéro de série). Ne vérifie pas la présence du hachage matériel.',
'Users associated with more than one managed device (not proof of multiple device owners).':'Utilisateurs associés à plus d\'un appareil géré (ne prouve pas plusieurs propriétaires).',
'Intune skuFamily values where available; missing editions are labeled as unavailable.':'Valeurs skuFamily d\'Intune si disponibles ; les éditions manquantes sont indiquées comme indisponibles.',
'Only directory accounts explicitly reported disabled. Requires successful User.Read.All collection.':'Seulement les comptes explicitement désactivés. Nécessite la collecte User.Read.All.',
'A device synchronization proxy, NOT proof of user inactivity or absence of sign-ins.':'Basé sur la synchronisation des appareils, ce n\'est PAS une preuve d\'inactivité de l\'utilisateur.',
'Applications published and managed through Intune, with installation result counts when collected.':'Applications publiées et gérées par Intune, avec les résultats d\'installation quand ils sont collectés.',
'Requires successful application device-status collection; partial or skipped collections are marked.':'Nécessite la collecte de l\'état des applications ; les collectes partielles ou ignorées sont indiquées.',
'All collected Settings Catalog configurations, with display names and configured values.':'Toutes les configurations Settings Catalog collectées, avec noms et valeurs configurées.',
'Entra recovery key metadata only; no recovery passwords are retrieved.':'Métadonnées des clés de récupération Entra seulement ; aucune clé n\'est lue.',
'Actual Graph-reported protection signals when available; missing devices are not treated as healthy.':'Signaux de protection réellement remontés par Graph ; les appareils absents ne sont pas considérés comme sains.',
'Setting-level errors/conflicts reported by Intune, not inferred from policy assignment.':'Erreurs et conflits signalés par Intune au niveau des paramètres, non déduits des assignations.',
'Grouped explicit policy errors and conflicts with affected-device counts and remediation guidance.':'Erreurs et conflits de stratégies regroupés, avec le nombre d\'appareils touchés et des pistes de correction.',
'Defender, Firewall, ASR, BitLocker, LAPS and security baselines: configuration evidence only, not measured protection.':'Defender, pare-feu, ASR, BitLocker, LAPS et baselines de sécurité : preuve de configuration seulement, pas de protection mesurée.',
'Explicitly failed policy/device records matched to identified security policies.':'Échecs explicites par appareil rattachés aux stratégies de sécurité identifiées.',
'Device-level policy result records from Graph report export; only explicit failures are flagged.':'Résultats par appareil issus des rapports Graph ; seuls les échecs explicites sont signalés.',
'Windows feature update status and failures when supported by Intune reporting.':'État et échecs des mises à jour de fonctionnalité Windows quand Intune les rapporte.',
'Classic and Settings Catalog profiles, assignment collection coverage and timestamps.':'Profils classiques et Settings Catalog, couverture des assignations et dates.',
'Update rings and feature/quality update policy configurations, not deployment success.':'Anneaux et stratégies de mise à jour : configuration, pas le succès du déploiement.',
'Device OS build counts; not equivalent to quality update compliance.':'Nombre d\'appareils par build ; n\'équivaut pas à la conformité des mises à jour qualité.',
'APNs, ADE, VPP, Managed Google Play and Mobile Threat Defense connectors.':'Connecteurs APNs, ADE, VPP, Managed Google Play et Mobile Threat Defense.',
'Policies and whether they require a compliant / hybrid-joined device or app protection.':'Stratégies et exigence d\'un appareil conforme / joint hybride ou d\'une protection d\'application.',
'Platform restrictions, personal device blocking, minimum OS and device limits.':'Restrictions de plateforme, blocage des appareils personnels, OS minimal et limites d\'appareils.',
'Progress display, timeout and failure behaviour.':'Affichage de la progression, délai et comportement en cas d\'échec.',
'Active assignments only; PIM eligible assignments are not included.':'Attributions actives seulement ; les attributions éligibles PIM ne sont pas incluses.',
'Access policies requiring a second administrator approval.':'Stratégies exigeant l\'approbation d\'un second administrateur.',
'iOS, Android and Windows app protection settings and assignments.':'Paramètres et assignations de protection des applications iOS, Android et Windows.',
'Run summary, error rate, execution context and signature enforcement.':'Résumé d\'exécution, taux d\'erreur, contexte d\'exécution et vérification de signature.',
'Join type, deployment mode, user account type and assignments.':'Type de jonction, mode de déploiement, type de compte et assignations.',
'Filters and number of collected assignments that reference them.':'Filtres et nombre d\'assignations collectées qui les utilisent.',
'Broad assignments, deleted or empty groups, contradictory include/exclude.':'Assignations larges, groupes supprimés ou vides, inclusions et exclusions contradictoires.',
'Measured coverage (LAPS backup, Defender signal, encryption, compliance), not policy existence.':'Couverture mesurée (sauvegarde LAPS, signal Defender, chiffrement, conformité), pas la simple existence d\'une stratégie.',
'End of servicing per Windows release and edition; minimum OS for mobile and macOS.':'Fin de support par version et édition de Windows ; OS minimal pour mobile et macOS.',
'Active devices behind the newest revision of the same build observed in this tenant.':'Appareils actifs en retard sur la révision la plus récente de la même build dans ce tenant.',
'Endpoint analytics when available, otherwise Intune hardware inventory.':'Endpoint analytics si disponible, sinon l\'inventaire matériel Intune.',
'Same serial number enrolled more than once.':'Même numéro de série inscrit plusieurs fois.','Devices missing from one source or stale in Entra.':'Appareils absents d\'une source ou obsolètes dans Entra.',
// columns
'Name':'Nom','Device':'Appareil','Device ID':'ID d\'appareil','User':'Utilisateur','Users':'Utilisateurs','Primary user':'Utilisateur principal','Associated user':'Utilisateur associé','Account':'Compte','Edition':'Édition','Version':'Version','Model':'Modèle','Make':'Marque','Serial':'Numéro de série',
'Last sync':'Dernière synchro','Sync age (days)':'Jours depuis la synchro','Device sync age':'Âge de la synchro','Enrolled':'Inscrit le','Last modified':'Dernière modification','Last reported':'Dernier rapport','Last activity':'Dernière activité',
'Status':'État','State':'État','Type':'Type','Policy':'Stratégie','Policy ID':'ID de stratégie','Policy type':'Type de stratégie','Policy family':'Famille de stratégie','Assignments':'Assignations','Assignment':'Assignation','Assignment coverage':'Couverture des assignations',
'Setting':'Paramètre','Settings':'Paramètres','Configured value':'Valeur configurée','Intune GUI setting':'Paramètre Intune','Intune category':'Catégorie Intune','Technical ID':'ID technique','Technical JSON':'JSON technique','Tenant configuration':'Configuration du tenant',
'OpenIntuneBaseline policy':'Stratégie OpenIntuneBaseline','Matching tenant configuration':'Configuration correspondante du tenant','OpenIntuneBaseline expected':'Attendu par OpenIntuneBaseline','Intune tenant value':'Valeur dans le tenant',
'Finding':'Constat','Affected':'Touchés','Effort':'Effort','Recommended action':'Action recommandée','Priority':'Priorité','Area':'Zone','Change':'Évolution','Previous':'Précédent','Current':'Actuel','Score':'Score','Rating':'Appréciation','Trend':'Tendance','Low / Info':'Faible / Info',
'Error':'Erreur','Errors':'Erreurs','Error %':'Erreurs %','Error code':'Code d\'erreur','Raw code':'Code brut','Explanation':'Explication','Interpretation':'Interprétation','Details':'Détails','Detail':'Détail','Detail coverage':'Couverture du détail','Failed requirement':'Exigence en échec','Suggested action':'Action suggérée',
'Failed records':'Enregistrements en échec','Failures observed':'Échecs observés','Records':'Enregistrements','Key records':'Clés enregistrées','Escrow status':'État de la sauvegarde','Distinct devices':'Appareils distincts','Device count':'Nombre d\'appareils','Example device':'Exemple d\'appareil',
'Application':'Application','App type':'Type d\'application','Publisher':'Éditeur','Publishing':'Publication','Install state':'État d\'installation','Success':'Succès','Apps':'Applications',
'Real-time protection':'Protection en temps réel','Antimalware':'Anti-malware','Tamper protection':'Protection contre les falsifications','Signatures overdue':'Signatures en retard','Product status':'État du produit','Endpoint protection':'Protection des points de terminaison','Security area':'Domaine de sécurité',
'Feature paused':'Fonctionnalités en pause','Quality paused':'Qualité en pause','Feature target':'Version cible','Feature deferral (days)':'Report fonctionnalité (jours)','Quality deferral (days)':'Report qualité (jours)','Update policy':'Stratégie de mise à jour','Windows build':'Build Windows','Windows edition':'Édition Windows','Build':'Build','Revision':'Révision','Newest in tenant':'Plus récente du tenant','Gap':'Écart',
'Connector':'Connecteur','Expiration':'Expiration','Days left':'Jours restants','Health':'Santé','Compliant device':'Appareil conforme','Hybrid join':'Jonction hybride','App protection':'Protection d\'application','MFA / strength':'MFA / force','Platforms':'Plateformes',
'Restriction':'Restriction','Platform blocked':'Plateforme bloquée','Personal blocked':'Personnel bloqué','Min OS':'OS minimal','Device limit':'Limite d\'appareils','Profile':'Profil','Show progress':'Afficher la progression','Timeout (min)':'Délai (min)','Blocking apps':'Applications bloquantes','Reset on failure':'Réinitialiser si échec','Use on failure':'Utiliser si échec',
'Source':'Source','Role':'Rôle','Principal':'Principal','Scope':'Étendue','Scope tags':'Balises d\'étendue','Protected operation':'Opération protégée','Approver groups':'Groupes d\'approbateurs','PIN':'Code PIN','Copy/paste':'Copier-coller','Send data to':'Envoi des données vers','Backup blocked':'Sauvegarde bloquée','Offline wipe':'Effacement hors ligne',
'Script':'Script','Kind':'Type','Run as':'Exécuté en tant que','Signature check':'Vérification de signature','Coverage':'Couverture','Join type':'Type de jonction','Mode':'Mode','User account type':'Type de compte','Pre-provisioning':'Pré-provisionnement','Convert all targeted':'Convertir tous les ciblés','Name template':'Modèle de nom',
'Filter':'Filtre','Rule':'Règle','Referenced by':'Utilisé par','Issue':'Problème','Object':'Objet','Object type':'Type d\'objet','Group':'Groupe','Control':'Contrôle','Population':'Population','Total':'Total','Covered':'Couverts','Coverage %':'Couverture %','Note':'Note',
'Release':'Version','End of servicing':'Fin de support','Processor':'Processeur','Inactive device':'Appareil inactif','Source report':'Rapport source','Collection':'Collecte','Matching':'Correspondances','Conflicts':'Conflits','Unassessed':'Non évalués',
// values
'High':'Élevée','Medium':'Moyenne','Low':'Faible','Informational':'Information','Critical':'Critique','Quick wins':'Gains rapides','30 days':'30 jours','90 days':'90 jours',
'Strong':'Solide','Good':'Bon','Needs improvement':'À améliorer','At risk':'À risque','Overall':'Global','Updates':'Mises à jour','Governance':'Gouvernance',
'New':'Nouveaux','Worse':'Aggravés','Resolved':'Résolus','Improved':'Améliorés','Unchanged':'Inchangés',
'Match':'Identique','Different':'Différent','Missing':'Absent','Conflicting':'En conflit','Not assessed':'Non évalué','match':'identique','different':'différent','conflicting':'en conflit',
'compliant':'conforme','noncompliant':'non conforme','Compliant':'Conforme','unknown':'inconnu','Unknown':'Inconnu','in grace period':'en période de grâce','in progress':'en cours','not applicable':'non applicable','not assigned':'non assigné',
'Encrypted':'Chiffré','Not configured / unavailable':'Non configuré / indisponible','Registered':'Enregistré','No matching record':'Aucun enregistrement','Enabled':'Activé','Disabled':'Désactivé','Not found':'Introuvable','No user ID':'Aucun ID utilisateur',
'Complete':'Complet','Partial':'Partiel','Unavailable':'Indisponible','Skipped':'Ignoré','Verified':'Vérifié','Heuristic':'Estimation','Partial coverage':'Couverture partielle',
'Yes':'Oui','No':'Non','True':'Oui','False':'Non','Healthy':'Sain','Expired':'Expiré','Expires within 30 days':'Expire dans moins de 30 jours','Expires within 60 days':'Expire dans moins de 60 jours','Not enabled':'Non activé',
'Out of support':'Hors support','Ending within 90 days':'Fin de support dans moins de 90 jours','Supported':'Pris en charge','Unknown release':'Version inconnue','At or above minimum':'Au minimum ou plus',
'Assigned to All devices':'Assigné à Tous les appareils','Assigned to All users':'Assigné à Tous les utilisateurs','Assigned group no longer exists':'Le groupe assigné n\'existe plus','Assigned group is empty':'Le groupe assigné est vide','Group both included and excluded':'Groupe à la fois inclus et exclu','No filter':'Sans filtre',
'All users':'Tous les utilisateurs','All cloud apps':'Toutes les applications cloud','Entra join':'Jonction Entra','Hybrid Entra join':'Jonction Entra hybride','User-driven':'Piloté par l\'utilisateur','Self-deploying':'Auto-déploiement',
// empty states
'No findings produced from the available evidence.':'Aucun constat produit à partir des preuves disponibles.','Nothing in this horizon.':'Rien dans cet horizon.','No actions.':'Aucune action.','No findings match these filters.':'Aucun constat ne correspond à ces filtres.',
'No previous run of this tenant found for comparison. Keep the output folder: the next run will compare automatically.':'Aucun passage précédent trouvé pour ce tenant. Conservez le dossier de sortie : le prochain passage fera la comparaison automatiquement.',
'No collection status recorded.':'Aucun état de collecte enregistré.','No collection warnings.':'Aucun avertissement de collecte.','No data available':'Aucune donnée disponible','No settings match this filter.':'Aucun paramètre ne correspond à ce filtre.',
'Not available':'Non disponible','No matching tenant policy identified':'Aucune stratégie correspondante dans le tenant','No assignment':'Aucune assignation','Unnamed baseline policy':'Stratégie sans nom','Unnamed setting':'Paramètre sans nom','No setting ID':'Aucun ID de paramètre',
'Action:':'Action :','Evidence:':'Preuve :','devices':'appareils','results':'résultats','settings':'paramètres'
};
const I18N_PATTERNS=[
 [/^([\d\s,.]+) results?$/,'$1 résultat(s)'],
 [/^([\d\s,.]+) matches out of ([\d\s,.]+) assessable comparisons$/,'$1 correspondances sur $2 comparaisons évaluables'],
 [/^([\d\s,.]+) baseline policies · detailed setting results available in OpenIntuneBaseline-Comparison\.csv$/,'$1 stratégies de baseline · détail par paramètre dans OpenIntuneBaseline-Comparison.csv'],
 [/^Devices without an Intune check-in within ([\d]+) days, or with no reported check-in\.$/,'Appareils sans synchronisation Intune depuis $1 jours, ou sans synchronisation signalée.'],
 [/^· H (\d+) \/ M (\d+) \/ L (\d+)$/,'· É $1 / M $2 / F $3'],
 [/^· (.+)$/,(m,x)=>'· '+i18nLookup(x)],
 [/^Score = 100 minus weighted findings per domain.*?(\d+) collections were incomplete\.$/,'Score = 100 moins les constats pondérés par domaine (Élevée 25, Moyenne 10, Faible 4, Information 1). Les données indisponibles ne sont jamais comptées ; $1 collectes étaient incomplètes.'],
 [/^Results compare configured Settings Catalog values.*$/,'Les résultats comparent les valeurs configurées du Settings Catalog, pas leur application sur les appareils ni le ciblage. Utilisez le sélecteur Windows / macOS pour changer de référence. Les paramètres absents ou non évalués sont comptés ici et détaillés dans le CSV.'],
 [/^\((\d+)\)$/,'($1)']
];
// ---- v3.60 translations: new sections, collection names, statuses and warnings ----
Object.assign(I18N_FR,{
'Intune Settings Review':'Revue des paramètres Intune','Intune settings review':'Revue des paramètres Intune','Compliance Actions':'Actions de conformité','Compliance policy actions':'Actions des stratégies de conformité',
'App Install Summary':'Synthèse des installations','Application install summary':'Synthèse des installations d\'applications','Update Coverage':'Couverture des mises à jour','OS update coverage by platform':'Couverture des mises à jour de l\'OS par plateforme',
'Enrollment Profiles':'Profils d\'inscription','Enrollment profiles and tokens':'Profils et jetons d\'inscription','Audit Actions':'Actions auditées','Destructive device actions (audit log)':'Actions destructives sur les appareils (journal d\'audit)',
'Custom Roles':'Rôles personnalisés','Intune custom roles':'Rôles Intune personnalisés','Intune export reports':'Rapports d\'export Intune',
'Tenant-level Intune settings: clean-up rule, categories, terms, scope tags, Remote Help, Endpoint analytics, Intune Suite.':'Paramètres Intune du tenant : règle de nettoyage, catégories, conditions d\'utilisation, balises d\'étendue, Remote Help, Endpoint analytics, Intune Suite.',
'Grace period before noncompliance, user notifications and other scheduled actions per policy.':'Délai de grâce avant non-conformité, notifications des utilisateurs et autres actions planifiées par stratégie.',
'Installed, failed and pending device counts per app from the Intune AppInstallStatusAggregate report.':'Nombre d\'appareils installés, en échec et en attente par application, depuis le rapport Intune AppInstallStatusAggregate.',
'Update mechanism and policies found for Windows, Apple and Android devices.':'Mécanisme et stratégies de mise à jour trouvés pour les appareils Windows, Apple et Android.',
'Android Enterprise / AOSP enrollment tokens and Apple ADE enrollment profiles.':'Jetons d\'inscription Android Enterprise / AOSP et profils d\'inscription ADE Apple.',
'Wipe, retire, delete and reset actions from the Intune audit log for the selected period.':'Effacements, mises hors service, suppressions et réinitialisations du journal d\'audit Intune sur la période choisie.',
'Custom Intune RBAC roles, permissions count and destructive permissions.':'Rôles RBAC Intune personnalisés, nombre de permissions et permissions destructives.',
'Check':'Contrôle','Result':'Résultat','Mark noncompliant':'Marquer non conforme','Notifications':'Notifications','Retire':'Mise hors service','Actions':'Actions','Required':'Requise','Installed':'Installés','Failed':'Échecs','Pending':'En attente','Not installed':'Non installés','Failed %':'Échecs %',
'Mechanism':'Mécanisme','Policies':'Stratégies','Token expires':'Expiration du jeton','Enrolled devices':'Appareils inscrits','Supervised':'Supervisé','Mandatory':'Obligatoire','Date':'Date','Actor':'Auteur','Target':'Cible','Activity':'Activité','Action':'Action',
'Permissions':'Permissions','Destructive permissions':'Permissions destructives','Report':'Rapport','Rows':'Lignes','Columns':'Colonnes','Filter used':'Filtre',
'Configured':'Configuré','Not configured':'Non configuré','Review':'À revoir','OK':'OK','Covered':'Couvert','No update policy':'Aucune stratégie de mise à jour','No devices':'Aucun appareil','No corporate devices':'Aucun appareil d\'entreprise',
'Not assessed (OEM)':'Non évalué (OEM)','Not verified (Settings Catalog not read)':'Non vérifié (Settings Catalog non lu)','No token':'Aucun jeton','Valid':'Valide','Not supervised':'Non supervisé','Immediately':'Immédiatement','No block action':'Aucune action de blocage',
'Wipe':'Effacement','Reset':'Réinitialisation','Delete device':'Suppression d\'appareil','Device hygiene':'Hygiène du parc','Intune Suite':'Intune Suite','Operations':'Exploitation','Enrollment':'Inscription','Governance':'Gouvernance',
'Android AOSP':'Android AOSP','Android Enterprise':'Android Enterprise','Android Enterprise (corporate)':'Android Enterprise (entreprise)','User affinity':'Affinité utilisateur','No user affinity':'Sans affinité utilisateur',
// collection names
'Managed devices':'Appareils gérés','Autopilot devices':'Appareils Autopilot','Managed applications':'Applications gérées','App install states':'États d\'installation des applications','App install summary':'Synthèse des installations','Directory users':'Utilisateurs de l\'annuaire',
'Compliance policy states':'États de conformité par appareil','Compliance policies':'Stratégies de conformité','Compliance tenant settings':'Paramètres de conformité du tenant','Compliance actions':'Actions de conformité','Devices without compliance policy':'Appareils sans stratégie de conformité',
'Classic configuration policies':'Profils de configuration classiques','Settings catalog policies':'Stratégies Settings Catalog','Feature update profiles':'Profils de mises à jour de fonctionnalité','Quality update profiles':'Profils de mises à jour qualité','Windows Update rings':'Anneaux Windows Update','Driver update profiles':'Profils de mises à jour des pilotes',
'Policy deployment status':'État de déploiement des stratégies','Feature update policy summary':'Synthèse des mises à jour de fonctionnalité','Feature update device state':'État des mises à jour de fonctionnalité par appareil','Feature update failures':'Échecs des mises à jour de fonctionnalité',
'BitLocker escrow metadata':'Métadonnées de sauvegarde BitLocker','Policy setting failures':'Échecs de paramètres de stratégie','Policy conflicts':'Conflits de stratégies','Defender device health':'Santé Defender des appareils','Endpoint Security intents':'Intents Endpoint Security','Endpoint Security policy inventory':'Inventaire Endpoint Security',
'Connectors and tokens':'Connecteurs et jetons','Enrollment restrictions':'Restrictions d\'inscription','Intune RBAC':'RBAC Intune','Privileged directory roles':'Rôles d\'annuaire privilégiés','Multi-admin approval':'Approbation multi-administrateurs','App protection policies':'Stratégies de protection des applications',
'Scripts and remediations':'Scripts et remédiations','Autopilot profiles':'Profils Autopilot','Assignment hygiene':'Hygiène des assignations','Windows LAPS backup':'Sauvegarde Windows LAPS','OS lifecycle':'Cycle de vie de l\'OS','Patch level':'Niveau de correctifs','Hardware readiness':'Préparation matérielle',
'Entra devices':'Appareils Entra','Run comparison':'Comparaison des passages','Executive summary documents':'Documents de synthèse','Device clean-up rules':'Règles de nettoyage des appareils','Win32 supersedence':'Remplacement des applications Win32','Android enrollment profiles':'Profils d\'inscription Android',
'Apple ADE profiles':'Profils ADE Apple','Endpoint analytics':'Endpoint analytics','Intune audit log':'Journal d\'audit Intune','Intune configuration review':'Revue de la configuration Intune'
});
Object.assign(I18N_FR,{'Report':'Rapport','Report navigation':'Navigation du rapport','Tenant':'Tenant','Score by domain':'Score par domaine','Quick wins':'Gains rapides','Action plan →':'Plan d\'action →','Customer logo':'Logo du client','inGracePeriod':'en période de grâce','configManager':'Configuration Manager'});
I18N_PATTERNS.push([/^([\d\s,.]+)% of devices$/,'$1 % des appareils'],[/^(\d+) of (\d+) devices noncompliant$/,'$1 appareils non conformes sur $2'],[/^(\d+) high-severity findings?$/,'$1 constat(s) de sévérité élevée'],[/^(\d+) quick wins?$/,'$1 gain(s) rapide(s)']);
Object.assign(I18N_FR,{'Zero Trust':'Zero Trust','ZERO TRUST':'ZERO TRUST','Zero Trust Assessment · Devices':'Évaluation Zero Trust · Appareils','Tests passed':'Tests réussis','Pass':'Réussi','Fail':'Échec','Warning':'Avertissement','Not applicable':'Non applicable','Not verified':'Non vérifié','All platforms':'Toutes les plateformes','Search tests...':'Rechercher un test...','Search tests':'Rechercher un test','Recommendation':'Recommandation','Policies':'Stratégies','Evidence':'Preuve','Result':'Résultat','No test matches these filters.':'Aucun test ne correspond à ces filtres.','Zero Trust device tests were not run.':'Les tests Zero Trust des appareils n\'ont pas été exécutés.','Zero Trust device tests':'Tests Zero Trust des appareils',
'Score = passed / (passed + failed + warning). Not applicable and not verified tests are excluded.':'Score = réussis / (réussis + échecs + avertissements). Les tests non applicables et non vérifiés sont exclus.',
'Device tests from the Microsoft Zero Trust Assessment, evaluated from the Intune configuration collected in this run. Pass means a matching policy exists and is assigned. Informational: these tests do not change the maturity score.':'Tests Appareils de l\'évaluation Zero Trust de Microsoft, évalués à partir de la configuration Intune collectée. Réussi signifie qu\'une stratégie correspondante existe et est assignée. Informatif : ces tests ne modifient pas le score de maturité.'});
for(const r of (D.zeroTrust||[])){if(r.TestFr&&r.Test)I18N_FR[r.Test]=r.TestFr;if(r.RecommendationFr&&r.Recommendation)I18N_FR[r.Recommendation]=r.RecommendationFr}
const I18N_STATUS_HEAD={'Complete':'Complet','Partial':'Partiel','Unavailable':'Indisponible','Skipped':'Ignoré','Not assessed':'Non évalué','Not verified':'Non vérifié','Not configured':'Non configuré','Not supported':'Non pris en charge','Not collected':'Non collecté','Not requested':'Non demandé'};
I18N_PATTERNS.unshift(
 [/^(Complete|Partial|Unavailable|Skipped|Not assessed|Not verified|Not configured|Not supported|Not collected|Not requested)( \(.*\))?$/,(m,h,d)=>I18N_STATUS_HEAD[h]+(d||'')],
 [/^Compliance details unavailable for (\d+) of (\d+) devices \(Graph throttling\)\.[\s\S]*?Devices: ([\s\S]*)$/,'Détails de conformité indisponibles pour $1 appareils sur $2 (limitation Graph). Leur raison est « Raison indisponible ». Relancer plus tard ou utiliser -MaxComplianceDevices. Appareils : $3'],
 [/^Compliance details capped at (\d+) of (\d+) noncompliant devices\.[\s\S]*$/,'Détails de conformité limités à $1 appareils non conformes sur $2. Les autres raisons ne sont pas vérifiées.'],
 [/^App device-status collection capped at (\d+) apps; failure totals are incomplete\.$/,'Collecte de l\'état des applications limitée à $1 applications ; les totaux d\'échecs sont incomplets.'],
 [/^Directory users: (\d+) of (\d+) primary users could not be resolved; their account state is Unknown\.$/,'Utilisateurs de l\'annuaire : $1 utilisateurs principaux sur $2 n\'ont pas pu être lus ; leur état de compte est inconnu.'],
 [/^Executive summary PDF \((fr|en)\) not generated or empty \((\d+) bytes\); printable HTML kept: ([\s\S]+)$/,'PDF du résumé exécutif ($1) non généré ou vide ($2 octets) ; HTML imprimable conservé : $3'],
 [/^Assignments unavailable for '([\s\S]+)': ([\s\S]+)$/,'Assignations indisponibles pour « $1 » : $2'],
 [/^App status unavailable for '([\s\S]+)' \(app type: ([^)]*)\): ([\s\S]+?)\. This does not mean installation succeeded or failed\.$/,'État indisponible pour l\'application « $1 » (type : $2) : $3. Cela ne signifie pas que l\'installation a réussi ou échoué.'],
 [/^([\s\S]+?) unavailable: ([\s\S]+)$/,(m,n,e)=>(i18nLookup(n)||n)+' indisponible : '+e]
);

// Findings, recommendations and domains carry their own French text from the PowerShell collection.
for(const a of (D.actionPlan||[])){if(a.FindingFr&&a.Finding&&!I18N_FR[a.Finding])I18N_FR[a.Finding]=a.FindingFr;if(a.RecommendationFr&&a.Recommendation&&!I18N_FR[a.Recommendation])I18N_FR[a.Recommendation]=a.RecommendationFr}
for(const d of ((D.scores&&D.scores.domains)||[])){if(d.DomainFr&&!I18N_FR[d.Domain])I18N_FR[d.Domain]=d.DomainFr}
function i18nLookup(t){
 if(Object.prototype.hasOwnProperty.call(I18N_FR,t))return I18N_FR[t];
 const nb=t.replace(/\u00a0/g,' ');if(nb!==t&&Object.prototype.hasOwnProperty.call(I18N_FR,nb))return I18N_FR[nb];
 for(const [re,to] of I18N_PATTERNS){if(re.test(t))return t.replace(re,to)}
 return null;
}
let reportLang='en';
const i18nOrig=new WeakMap();
const I18N_SKIP=new Set(['SCRIPT','STYLE','CODE','PRE','TEXTAREA']);
function i18nNode(n){
 const cur=n.nodeValue;let rec=i18nOrig.get(n);
 if(!rec||(cur!==rec.en&&cur!==rec.out)){rec={en:cur,out:cur};i18nOrig.set(n,rec)}
 let out=rec.en;
 if(reportLang==='fr'){const m=rec.en.match(/^(\s*)([\s\S]*?)(\s*)$/);if(m[2]){const tr=i18nLookup(m[2]);if(tr!==null)out=m[1]+tr+m[3]}}
 rec.out=out;if(cur!==out)n.nodeValue=out;
}
function i18nAttrs(el){
 for(const at of ['placeholder','aria-label','title']){
  if(!el.hasAttribute||!el.hasAttribute(at))continue;
  const key='data-i18n-'+at;let en=el.getAttribute(key);const cur=el.getAttribute(at);
  if(en===null||(cur!==en&&cur!==el.getAttribute(key+'-out'))){en=cur;el.setAttribute(key,en)}
  const tr=reportLang==='fr'?i18nLookup(en):null;const out=tr===null?en:tr;
  el.setAttribute(key+'-out',out);if(cur!==out)el.setAttribute(at,out);
 }
}
function i18nApply(root){
 if(!root)return;
 if(root.nodeType===3){if(!I18N_SKIP.has(root.parentNode&&root.parentNode.nodeName))i18nNode(root);return}
 if(root.nodeType!==1||I18N_SKIP.has(root.nodeName))return;
 i18nAttrs(root);
 const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT|NodeFilter.SHOW_ELEMENT,{acceptNode:n=>n.nodeType===1&&I18N_SKIP.has(n.nodeName)?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT});
 let n;while((n=w.nextNode())){if(n.nodeType===3)i18nNode(n);else i18nAttrs(n)}
}
let i18nBusy=false;
const i18nObserver=new MutationObserver(muts=>{
 if(i18nBusy)return;i18nBusy=true;
 try{for(const m of muts){if(m.type==='characterData')i18nApply(m.target);else for(const n of m.addedNodes)i18nApply(n)}}
 finally{i18nObserver.takeRecords();i18nBusy=false}
});
function setReportLang(l){
 reportLang=l==='fr'?'fr':'en';
 i18nBusy=true;try{i18nApply(document.body);document.title=reportLang==='fr'?'Évaluation Intune':'Intune Assessment';i18nObserver.takeRecords()}finally{i18nBusy=false}
 document.documentElement.lang=reportLang==='fr'?'fr-CA':'en';
 const b=by('langToggle');b.textContent=reportLang==='fr'?'EN':'FR';b.setAttribute('aria-label',reportLang==='fr'?'Switch report to English':'Afficher le rapport en français');b.setAttribute('data-i18n-aria-label',b.getAttribute('aria-label'));b.setAttribute('data-i18n-aria-label-out',b.getAttribute('aria-label'));
}
by('langToggle').addEventListener('click',()=>setReportLang(reportLang==='fr'?'en':'fr'));
i18nObserver.observe(document.body,{childList:true,subtree:true,characterData:true});
// ===================== v3.70 theme and print =====================
document.querySelectorAll('#mainNav a .nav-label').forEach(n=>n.setAttribute('data-en',n.textContent));
function currentTheme(){const t=document.documentElement.getAttribute('data-theme');if(t)return t;return window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'}
function updateThemeButton(){const dark=currentTheme()==='dark',fr=reportLang==='fr';const label=dark?(fr?'Passer au thème clair':'Switch to light theme'):(fr?'Passer au thème sombre':'Switch to dark theme');const b=by('themeToggle');b.setAttribute('aria-label',label);b.setAttribute('title',label);const pl=fr?'Imprimer le rapport':'Print report';by('printBtn').setAttribute('aria-label',pl);by('printBtn').setAttribute('title',pl)}
by('themeToggle').addEventListener('click',()=>{const next=currentTheme()==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',next);try{localStorage.setItem('ia-theme',next)}catch(e){}updateThemeButton()});
by('printBtn').addEventListener('click',()=>window.print());
const setReportLangBase=setReportLang;
setReportLang=function(l){setReportLangBase(l);updateThemeButton()};
setReportLang(D.reportLanguage==='fr'?'fr':'en');

</script></body></html>
'@
$html=$html.Replace('__DATA__',$payloadJson)
if($BaselineName -cne 'OpenIntuneBaseline'){
 # Report labels follow the selected baseline; the CSV file keeps its name (OpenIntuneBaseline-Comparison.csv).
 $html=$html.Replace('OpenIntuneBaseline-Comparison\.csv','~~OIBCSVRX~~').Replace('OpenIntuneBaseline-Comparison.csv','~~OIBCSV~~')
 $html=$html.Replace('OpenIntuneBaseline',$BaselineName).Replace('OPENINTUNEBASELINE',$BaselineName.ToUpperInvariant())
 $html=$html.Replace('~~OIBCSVRX~~','OpenIntuneBaseline-Comparison\.csv').Replace('~~OIBCSV~~','OpenIntuneBaseline-Comparison.csv')
}
$reportPath=Join-Path $runPath 'Intune-Assessment.html'
$html | Set-Content -Encoding UTF8 -Path $reportPath

# =====================================================================================
# SECTION 9 - Bilingual executive summary: DOCX (always) + PDF (Edge/Chrome headless when present)
# =====================================================================================
$execFiles=[System.Collections.Generic.List[string]]::new()
function Get-ExecText([string]$Lang){
 $fr=($Lang -eq 'fr')
 return @{
  Title=if($fr){'Évaluation Intune — Résumé exécutif'}else{'Intune assessment — Executive summary'}
  Tenant=if($fr){'Organisation'}else{'Organization'}; Date=if($fr){'Date de génération'}else{'Generated'}
  Devices=if($fr){'Appareils gérés'}else{'Managed devices'}
  Overall=if($fr){'Score global'}else{'Overall score'}
  Domains=if($fr){'Score par domaine'}else{'Score by domain'}
  Domain=if($fr){'Domaine'}else{'Domain'}; Score='Score'; Rating=if($fr){'Appréciation'}else{'Rating'}; Trend=if($fr){'Tendance'}else{'Trend'}
  Findings=if($fr){'Constats (É/M/F)'}else{'Findings (H/M/L)'}
  KeyFigures=if($fr){'Indicateurs clés'}else{'Key figures'}
  Compliant=if($fr){'Conformes'}else{'Compliant'}; Noncompliant=if($fr){'Non conformes'}else{'Noncompliant'}
  Unencrypted=if($fr){'Non chiffrés'}else{'Not encrypted'}; Inactive=if($fr){'Inactifs'}else{'Inactive'}
  TopRisks=if($fr){'Principaux risques'}else{'Top risks'}
  Severity=if($fr){'Sévérité'}else{'Severity'}; Finding=if($fr){'Constat'}else{'Finding'}; Affected=if($fr){'Touchés'}else{'Affected'}
  Plan=if($fr){'Plan d''action priorisé'}else{'Prioritized action plan'}
  Action='Action'; Effort='Effort'; Impact='Impact'
  Comparison=if($fr){'Évolution depuis le dernier passage'}else{'Change since previous run'}
  Frameworks=if($fr){'Correspondance avec les référentiels'}else{'Framework mapping'}
  FrameworksNote=if($fr){'Correspondance indicative au niveau des contrôles CIS v8, des stratégies Essential Eight et des catégories NIST CSF 2.0. Détail par constat : Action-Plan.csv.'}else{'Indicative mapping to CIS Controls v8, Essential Eight strategies and NIST CSF 2.0 categories. Per-finding detail: Action-Plan.csv.'}
  Limits=if($fr){'Limites de l''évaluation'}else{'Assessment limitations'}
  LimitsIntro=if($fr){'Les données indisponibles ne sont jamais comptées comme saines ou non conformes. Collectes incomplètes :'}else{'Unavailable data is never counted as healthy or unhealthy. Incomplete collections:'}
  None=if($fr){'Aucune'}else{'None'}
  ScoreNote=if($fr){'Score = 100 moins les constats pondérés par domaine (Élevée 25, Moyenne 10, Faible 4, Information 1).'}else{'Score = 100 minus weighted findings per domain (High 25, Medium 10, Low 4, Informational 1).'}
  NoPrevious=if($fr){'Aucun passage précédent disponible pour ce tenant.'}else{'No previous run available for this tenant.'}
 }
}
$tr=@{
 fr=@{'Strong'='Solide';'Good'='Bon';'Needs improvement'='À améliorer';'At risk'='À risque';'Quick wins'='Gains rapides';'30 days'='30 jours';'90 days'='90 jours';'High'='Élevée';'Medium'='Moyenne';'Low'='Faible';'Informational'='Information';'New'='Nouveaux';'Resolved'='Résolus';'Worse'='Aggravés';'Improved'='Améliorés';'Unchanged'='Inchangés'}
 en=@{}
}
function T([string]$Lang,[string]$Value){ if($tr[$Lang].ContainsKey($Value)){return $tr[$Lang][$Value]}; return $Value }
function EffortT([string]$Lang,[string]$Value){ if($Lang -ne 'fr'){return $Value}; switch($Value){'Low'{'Faible'}'Medium'{'Moyen'}'High'{'Élevé'}default{$Value}} }
function Get-ExecModel([string]$Lang){
 $t=Get-ExecText $Lang; $fr=($Lang -eq 'fr')
 $total=[int]$payloadSummaryForCompare.total
 $model=[ordered]@{T=$t;Lang=$Lang
  Tenant=if($tenantBrandName){$tenantBrandName}else{AsText $ctx.TenantId};Generated=(Get-Date).ToString('yyyy-MM-dd HH:mm');Devices=$total
  Overall=$overallScore;OverallRating=T $Lang $(if($overallScore -ge 85){'Strong'}elseif($overallScore -ge 70){'Good'}elseif($overallScore -ge 50){'Needs improvement'}else{'At risk'})
  Domains=@($domainScores|ForEach-Object {,@($(if($fr){$_.DomainFr}else{$_.Domain}),[string]$_.Score,(T $Lang $_.Rating),('{0} / {1} / {2}' -f @($_.High,$_.Medium,$_.Low)),$(if($null -eq $_.Trend){'—'}elseif($_.Trend -gt 0){"+$($_.Trend)"}else{[string]$_.Trend}))})
  Kpis=@(
   ,@($t.Devices,[string]$total)
   ,@($t.Compliant,$(if($total){('{0} ({1} %)' -f @($compliantCount,[Math]::Round(100*$compliantCount/$total)))}else{'0'}))
   ,@($t.Noncompliant,[string]$payloadSummaryForCompare.noncompliant)
   ,@($t.Unencrypted,[string]$payloadSummaryForCompare.unencrypted)
   ,@($t.Inactive,[string]$payloadSummaryForCompare.inactive))
  Risks=@($actionPlan|Where-Object {$_.Severity -in @('High','Medium')}|Sort-Object @{e={$sevRank[$_.Severity]}},@{e={-[int]$_.Affected}}|Select-Object -First 8|ForEach-Object {,@((T $Lang $_.Severity),$(if($fr){$_.FindingFr}else{$_.Finding}),[string]$_.Affected)})
  Plan=[ordered]@{}
  Comparison=@()
  Limits=@($incomplete|ForEach-Object {'{0}: {1}' -f $_,$collection[$_]})
 }
 foreach($h in @('Quick wins','30 days','90 days')){
  $model.Plan[(T $Lang $h)]=@($actionPlan|Where-Object Horizon -eq $h|Select-Object -First 10|ForEach-Object {,@([string]$_.Priority,$(if($fr){$_.RecommendationFr}else{$_.Recommendation}),$(if($fr){$_.FindingFr}else{$_.Finding}),[string]$_.Affected,(EffortT $Lang $_.Effort))})
 }
 if($comparison.Available){
  $model.Comparison=@($comparison.Findings|Group-Object Change|ForEach-Object {,@((T $Lang $_.Name),[string]$_.Count)})
  $o=@($comparison.Kpis|Where-Object Metric -eq 'overallScore')|Select-Object -First 1
  if($o){$model.Comparison+=,@($t.Overall,('{0} → {1} ({2:+0;-0;0})' -f $o.Previous,$o.Current,$o.Delta))}
 }
 return $model
}
# ---- DOCX (minimal OpenXML package, no Word or module dependency) ----
function X([string]$s){ return [System.Security.SecurityElement]::Escape([string]$s) }
function DocP([string]$Text,[string]$Style='',[switch]$Bold,[string]$Color='',[int]$Size=0){
 $ppr=if($Style){"<w:pPr><w:pStyle w:val=`"$Style`"/></w:pPr>"}else{''}
 $rpr=''; if($Bold -or $Color -or $Size){$rpr='<w:rPr>'+$(if($Bold){'<w:b/>'})+$(if($Color){"<w:color w:val=`"$Color`"/>"})+$(if($Size){"<w:sz w:val=`"$Size`"/>"})+'</w:rPr>'}
 return "<w:p>$ppr<w:r>$rpr<w:t xml:space=`"preserve`">$(X $Text)</w:t></w:r></w:p>"
}
function DocTable([string[]]$Header,[object[]]$Rows,[int[]]$Widths){
 $grid=($Widths|ForEach-Object {"<w:gridCol w:w=`"$_`"/>"}) -join ''
 $sb=[System.Text.StringBuilder]::new()
 [void]$sb.Append("<w:tbl><w:tblPr><w:tblStyle w:val=`"AssessTable`"/><w:tblW w:w=`"$(($Widths|Measure-Object -Sum).Sum)`" w:type=`"dxa`"/><w:tblLayout w:type=`"fixed`"/></w:tblPr><w:tblGrid>$grid</w:tblGrid>")
 $cell={param($txt,$w,$hdr)
  $shd=if($hdr){'<w:shd w:val="clear" w:color="auto" w:fill="17263A"/>'}else{''}
  $rpr=if($hdr){'<w:rPr><w:b/><w:color w:val="FFFFFF"/></w:rPr>'}else{''}
  "<w:tc><w:tcPr><w:tcW w:w=`"$w`" w:type=`"dxa`"/>$shd</w:tcPr><w:p><w:pPr><w:spacing w:before=`"40`" w:after=`"40`"/></w:pPr><w:r>$rpr<w:t xml:space=`"preserve`">$(X $txt)</w:t></w:r></w:p></w:tc>"
 }
 [void]$sb.Append('<w:tr><w:trPr><w:tblHeader/></w:trPr>')
 for($c=0;$c -lt $Header.Count;$c++){[void]$sb.Append((& $cell $Header[$c] $Widths[$c] $true))}
 [void]$sb.Append('</w:tr>')
 foreach($r in $Rows){[void]$sb.Append('<w:tr><w:trPr><w:cantSplit/></w:trPr>');for($c=0;$c -lt $Header.Count;$c++){[void]$sb.Append((& $cell ([string]$r[$c]) $Widths[$c] $false))};[void]$sb.Append('</w:tr>')}
 [void]$sb.Append('</w:tbl>')
 return $sb.ToString()+(DocP '')
}
function New-ExecDocx([string]$Path,$M){
 $t=$M.T; $b=[System.Text.StringBuilder]::new()
 [void]$b.Append((DocP $t.Title 'Title'))
 [void]$b.Append((DocP ("{0} : {1}    {2} : {3}    {4} : {5}" -f $t.Tenant,$M.Tenant,$t.Date,$M.Generated,$t.Devices,$M.Devices) 'Subtle'))
 [void]$b.Append((DocP ("{0} : {1} / 100 — {2}" -f $t.Overall,$M.Overall,$M.OverallRating) 'Score'))
 [void]$b.Append((DocP $t.ScoreNote 'Subtle'))
 [void]$b.Append((DocP $t.Domains 'Heading1'))
 [void]$b.Append((DocTable @($t.Domain,$t.Score,$t.Rating,$t.Findings,$t.Trend) $M.Domains @(2800,1300,2300,2300,1600)))
 [void]$b.Append((DocP $t.KeyFigures 'Heading1'))
 [void]$b.Append((DocTable @($t.KeyFigures,'') $M.Kpis @(5000,5300)))
 [void]$b.Append((DocP $t.TopRisks 'Heading1'))
 [void]$b.Append((DocTable @($t.Severity,$t.Finding,$t.Affected) $M.Risks @(1500,7400,1400)))
 [void]$b.Append((DocP $t.Plan 'Heading1'))
 foreach($h in $M.Plan.Keys){
  if(@($M.Plan[$h]).Count -eq 0){continue}
  [void]$b.Append((DocP $h 'Heading2'))
  [void]$b.Append((DocTable @('#',$t.Action,$t.Finding,$t.Affected,$t.Effort) $M.Plan[$h] @(500,4600,3300,900,1000)))
 }
 [void]$b.Append((DocP $t.Comparison 'Heading1'))
 if(@($M.Comparison).Count){[void]$b.Append((DocTable @($t.Comparison,'') $M.Comparison @(5000,5300)))}else{[void]$b.Append((DocP $t.NoPrevious))}
 [void]$b.Append((DocP $t.Frameworks 'Heading1'))
 [void]$b.Append((DocP $t.FrameworksNote))
 [void]$b.Append((DocP $t.Limits 'Heading1'))
 [void]$b.Append((DocP $t.LimitsIntro))
 if(@($M.Limits).Count){foreach($l in $M.Limits){[void]$b.Append((DocP ('• '+$l)))}}else{[void]$b.Append((DocP $t.None))}
 $ns='xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
 $document="<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><w:document $ns><w:body>$($b.ToString())<w:sectPr><w:pgSz w:w=`"12240`" w:h=`"15840`"/><w:pgMar w:top=`"1000`" w:right=`"960`" w:bottom=`"1000`" w:left=`"960`" w:header=`"500`" w:footer=`"500`" w:gutter=`"0`"/></w:sectPr></w:body></w:document>"
 $styles=@"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:cs="Segoe UI"/><w:sz w:val="19"/><w:color w:val="142035"/><w:lang w:val="$(if($M.Lang -eq 'fr'){'fr-CA'}else{'en-CA'})"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="80"/></w:pPr><w:rPr><w:b/><w:color w:val="17263A"/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="100"/><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="2" w:color="0878D7"/></w:pBdr><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="0878D7"/><w:sz w:val="27"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:color w:val="17263A"/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtle"><w:name w:val="Subtle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="697386"/><w:sz w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Score"><w:name w:val="Score"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="200" w:after="60"/></w:pPr><w:rPr><w:b/><w:color w:val="0878D7"/><w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="AssessTable"><w:name w:val="Assessment Table"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="E3E7ED"/><w:left w:val="single" w:sz="4" w:color="E3E7ED"/><w:bottom w:val="single" w:sz="4" w:color="E3E7ED"/><w:right w:val="single" w:sz="4" w:color="E3E7ED"/><w:insideH w:val="single" w:sz="4" w:color="E3E7ED"/><w:insideV w:val="single" w:sz="4" w:color="E3E7ED"/></w:tblBorders><w:tblCellMar><w:left w:w="90" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>
"@
 $parts=[ordered]@{
  '[Content_Types].xml'='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'
  '_rels/.rels'='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
  'word/_rels/document.xml.rels'='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
  'word/document.xml'=$document
  'word/styles.xml'=$styles.Trim()
 }
 Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
 if(Test-Path -LiteralPath $Path){Remove-Item -LiteralPath $Path -Force}
 $zip=[System.IO.Compression.ZipFile]::Open($Path,[System.IO.Compression.ZipArchiveMode]::Create)
 try{
  foreach($name in $parts.Keys){
   $entry=$zip.CreateEntry($name,[System.IO.Compression.CompressionLevel]::Optimal)
   $w=[System.IO.StreamWriter]::new($entry.Open(),[System.Text.UTF8Encoding]::new($false))
   try{$w.Write($parts[$name])}finally{$w.Dispose()}
  }
 }finally{$zip.Dispose()}
}
# ---- HTML (print layout) used for PDF ----
function New-ExecHtml($M){
 $t=$M.T
 $h={param($s) [System.Net.WebUtility]::HtmlEncode([string]$s)}
 $tbl={param($hdr,$rows) '<table><thead><tr>'+(($hdr|ForEach-Object {'<th>'+(& $h $_)+'</th>'}) -join '')+'</tr></thead><tbody>'+(($rows|ForEach-Object {'<tr>'+((@($_)|ForEach-Object {'<td>'+(& $h $_)+'</td>'}) -join '')+'</tr>'}) -join '')+'</tbody></table>'}
 $sb=[System.Text.StringBuilder]::new()
 [void]$sb.Append("<!doctype html><html lang=`"$($M.Lang)`"><head><meta charset=`"utf-8`"><title>$(& $h $t.Title)</title><style>@page{size:Letter;margin:14mm}body{font-family:'Segoe UI',Arial,sans-serif;color:#142035;font-size:10pt}h1{color:#17263a;font-size:20pt;margin:0 0 4px}h2{color:#0878d7;font-size:13pt;border-bottom:1px solid #0878d7;padding-bottom:2px;margin:18px 0 8px;break-after:avoid}h3{font-size:11pt;margin:10px 0 6px;break-after:avoid}.muted{color:#697386;font-size:8.5pt}.score{font-size:16pt;font-weight:700;color:#0878d7;margin:12px 0 2px}table{width:100%;border-collapse:collapse;margin-bottom:8px}th{background:#17263a;color:#fff;text-align:left;padding:4px 6px;font-size:9pt}td{border:1px solid #e3e7ed;padding:4px 6px;vertical-align:top;font-size:9pt}tr{break-inside:avoid}</style></head><body>")
 [void]$sb.Append("<h1>$(& $h $t.Title)</h1><div class=`"muted`">$(& $h $t.Tenant) : $(& $h $M.Tenant) · $(& $h $t.Date) : $(& $h $M.Generated) · $(& $h $t.Devices) : $($M.Devices)</div>")
 [void]$sb.Append("<div class=`"score`">$(& $h $t.Overall) : $($M.Overall) / 100 — $(& $h $M.OverallRating)</div><div class=`"muted`">$(& $h $t.ScoreNote)</div>")
 [void]$sb.Append("<h2>$(& $h $t.Domains)</h2>"+(& $tbl @($t.Domain,$t.Score,$t.Rating,$t.Findings,$t.Trend) $M.Domains))
 [void]$sb.Append("<h2>$(& $h $t.KeyFigures)</h2>"+(& $tbl @($t.KeyFigures,'') $M.Kpis))
 [void]$sb.Append("<h2>$(& $h $t.TopRisks)</h2>"+(& $tbl @($t.Severity,$t.Finding,$t.Affected) $M.Risks))
 [void]$sb.Append("<h2>$(& $h $t.Plan)</h2>")
 foreach($k in $M.Plan.Keys){if(@($M.Plan[$k]).Count){[void]$sb.Append("<h3>$(& $h $k)</h3>"+(& $tbl @('#',$t.Action,$t.Finding,$t.Affected,$t.Effort) $M.Plan[$k]))}}
 [void]$sb.Append("<h2>$(& $h $t.Comparison)</h2>"+$(if(@($M.Comparison).Count){& $tbl @($t.Comparison,'') $M.Comparison}else{"<p>$(& $h $t.NoPrevious)</p>"}))
 [void]$sb.Append("<h2>$(& $h $t.Frameworks)</h2><p>$(& $h $t.FrameworksNote)</p>")
 [void]$sb.Append("<h2>$(& $h $t.Limits)</h2><p>$(& $h $t.LimitsIntro)</p><ul>"+$(if(@($M.Limits).Count){($M.Limits|ForEach-Object {"<li>$(& $h $_)</li>"}) -join ''}else{"<li>$(& $h $t.None)</li>"})+'</ul></body></html>')
 return $sb.ToString()
}
function Find-HeadlessBrowser{
 $c=@('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge','/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',"${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")
 foreach($p in $c){if($p -and (Test-Path -LiteralPath $p)){return $p}}
 foreach($n in @('msedge','google-chrome','chromium','chrome')){$cmd=Get-Command $n -ErrorAction SilentlyContinue;if($cmd){return $cmd.Source}}
 return $null
}
if($SkipExecutiveDocuments){$collection['Executive summary documents']='Skipped'}else{
 Say 'Generating bilingual executive summary (DOCX / PDF)...'
 $browser=Find-HeadlessBrowser; $pdfCount=0
 foreach($lang in @('fr','en')){
  try{
   $m=Get-ExecModel $lang
   $suffix=$lang.ToUpperInvariant()
   $docx=Join-Path $runPath "Executive-Summary-$suffix.docx"
   New-ExecDocx -Path $docx -M $m; $execFiles.Add($docx)
   $htmlPath=Join-Path $runPath "Executive-Summary-$suffix.html"
   New-ExecHtml $m | Set-Content -LiteralPath $htmlPath -Encoding utf8BOM
   if($browser){
    $pdf=Join-Path $runPath "Executive-Summary-$suffix.pdf"
    # The browser renders from a local temp folder: on macOS, Edge/Chrome cannot read files
    # under ~/Library/CloudStorage (OneDrive) and silently prints a blank page.
    $work=Join-Path ([System.IO.Path]::GetTempPath()) ("intune-exec-"+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try{
     $tmpHtml=Join-Path $work "exec-$lang.html"; $tmpPdf=Join-Path $work "exec-$lang.pdf"
     Copy-Item -LiteralPath $htmlPath -Destination $tmpHtml -Force
     $uri=([System.Uri]$tmpHtml).AbsoluteUri
     $psi=[System.Diagnostics.ProcessStartInfo]::new($browser)
     foreach($arg in @('--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-crash-reporter','--disable-breakpad','--log-level=3','--no-pdf-header-footer',"--user-data-dir=$(Join-Path $work 'profile')","--print-to-pdf=$tmpPdf",$uri)){$psi.ArgumentList.Add($arg)}
     # Browser diagnostics are captured (not shown) to keep the console clean.
     $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardError=$true; $psi.RedirectStandardOutput=$true
     $proc=[System.Diagnostics.Process]::Start($psi)
     $errTask=$proc.StandardError.ReadToEndAsync(); $outTask=$proc.StandardOutput.ReadToEndAsync()
     
if(-not $proc.WaitForExit(90000)){try{$proc.Kill($true)}catch{}}
     # v3.41 - On Windows msedge.exe can exit before its child process writes the PDF: wait for the file.
     $pdfDeadline=(Get-Date).AddSeconds(45)
     while(-not (Test-Path -LiteralPath $tmpPdf) -and (Get-Date) -lt $pdfDeadline){Start-Sleep -Milliseconds 500}
     # Retry with classic headless mode (some managed Edge/Chrome builds ignore --headless=new).
     if(-not (Test-Path -LiteralPath $tmpPdf)){
      $psi2=[System.Diagnostics.ProcessStartInfo]::new($browser)
      foreach($arg in @('--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-crash-reporter','--disable-breakpad','--log-level=3','--print-to-pdf-no-header',"--user-data-dir=$(Join-Path $work 'profile2')","--print-to-pdf=$tmpPdf",$uri)){$psi2.ArgumentList.Add($arg)}
      $psi2.UseShellExecute=$false; $psi2.CreateNoWindow=$true
      $proc2=[System.Diagnostics.Process]::Start($psi2)
      if(-not $proc2.WaitForExit(90000)){try{$proc2.Kill($true)}catch{}}
      $pdfDeadline=(Get-Date).AddSeconds(45)
      while(-not (Test-Path -LiteralPath $tmpPdf) -and (Get-Date) -lt $pdfDeadline){Start-Sleep -Milliseconds 500}
     }
     # Last resort on Windows: Microsoft Word converts the DOCX already generated (wdExportFormatPDF = 17).
     if(-not (Test-Path -LiteralPath $tmpPdf) -and $IsWindows){
      $word=$null
      try{
       $word=New-Object -ComObject Word.Application; $word.Visible=$false; $word.DisplayAlerts=0
       $wdoc=$word.Documents.Open($docx,$false,$true)
       $wdoc.ExportAsFixedFormat($tmpPdf,17)
       $wdoc.Close(0)
      }catch{$warnings.Add("Word PDF fallback ($lang) failed: $($_.Exception.Message)")}
      finally{if($word){try{$word.Quit()}catch{};[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word)}}
     }
     # Wait until the file size is stable (browser may still be flushing).
     $lastSize=-1
     for($n=0;$n -lt 20;$n++){if(Test-Path -LiteralPath $tmpPdf){$cur=(Get-Item -LiteralPath $tmpPdf).Length;if($cur -gt 0 -and $cur -eq $lastSize){break};$lastSize=$cur};Start-Sleep -Milliseconds 500}
     $pdfSize=if(Test-Path -LiteralPath $tmpPdf){(Get-Item -LiteralPath $tmpPdf).Length}else{0}
     if($pdfSize -gt 5000){
      Move-Item -LiteralPath $tmpPdf -Destination $pdf -Force
      $execFiles.Add($pdf);$pdfCount++
      Remove-Item -LiteralPath $htmlPath -Force -ErrorAction SilentlyContinue
     }else{
      $warnings.Add("Executive summary PDF ($lang) not generated or empty ($pdfSize bytes); printable HTML kept: $htmlPath")
     }
    }finally{Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
   }
  }catch{$warnings.Add("Executive summary ($lang) failed: $($_.Exception.Message)")}
 }
 $collection['Executive summary documents']=if($browser -and $pdfCount -eq 2){"Complete ($($execFiles.Count) files; PDF via $(Split-Path $browser -Leaf))"}elseif($browser){"Partial ($pdfCount of 2 PDF; DOCX and printable HTML kept)"}else{"DOCX only ($($execFiles.Count) files): Edge/Chrome not found, printable HTML kept for PDF"}
}

if(-not $SkipExcelExport){
 try{
  $sheetOrder=@('Action-Plan.csv','Prioritized-Findings.csv','Domain-Scores.csv','Managed-Devices.csv','Noncompliant-Devices.csv')
  $orderedSheets=@($sheetOrder | ForEach-Object {$n=$_;$script:WorkbookSheets | Where-Object {$_.Name -eq $n} | Select-Object -First 1} | Where-Object {$_})
  $orderedSheets+=@($script:WorkbookSheets | Where-Object {$_.Name -notin $sheetOrder})
  $xlsxPath=Join-Path $runPath 'Intune-Assessment.xlsx'
  New-SimpleXlsx -Path $xlsxPath -Sheets $orderedSheets
  $collection['Excel workbook']="Complete ($($orderedSheets.Count) sheets)"
  Say "Excel workbook saved: $xlsxPath"
 }catch{$collection['Excel workbook']='Unavailable';$warnings.Add("Excel workbook not created: $($_.Exception.Message)")}
}else{$collection['Excel workbook']='Skipped'}
if($script:Anon.Enabled){
 # Raw Intune export CSV files contain real names: removed from anonymized runs.
 Get-ChildItem -LiteralPath $runPath -Directory -Filter 'GraphExport-*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
$meta=[ordered]@{ScriptVersion='3.74';BaselineName=$BaselineName;BaselineSource=$baselineSourceLabel;OverallScore=$overallScore;DomainScores=@($domainScores|Select-Object Domain,Score,Rating,High,Medium,Low);Findings=@($findings|Select-Object Severity,Area,Finding,Affected);TenantId=$ctx.TenantId;Generated=$now.ToString('o');InactiveDays=$InactiveDays;Counts=$payload.summary;OpenIntuneBaseline=$oibSummaries;TenantBranding=$tenantBrandSource;Collection=$collection;Performance=$script:GraphStats;ReportSources=@($script:ReportSources);Anonymized=[bool]$Anonymize;Warnings=@($warnings | ForEach-Object {ConvertTo-AnonymizedText $_})}
$meta | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path (Join-Path $runPath 'Run-Metadata.json')
Say "Report saved: $reportPath"
Write-ConsoleEvent ('Devices: {0} | Noncompliant: {1} | Inactive: {2} | App failures: {3}' -f $devices.Count,$noncompliantCount,$inactiveCount,$appStatuses.Count)
if($script:uiEnabled){
 [Console]::Write("${script:uiEsc}[0m`n")
 Write-Host ('Assessment complete | Report: {0}' -f $reportPath) -ForegroundColor Green
 Write-Host ('Warnings: {0} (see Run-Metadata.json)' -f $warnings.Count) -ForegroundColor Yellow
}else{foreach($warning in $warnings){Write-Warning $warning}}
try { $savedWarnPref=$WarningPreference; $WarningPreference='SilentlyContinue'; Disconnect-MgGraph -ErrorAction SilentlyContinue 3>$null | Out-Null } catch { } finally { $WarningPreference=$savedWarnPref }
if($OpenReport){
 # Opens with the default application (Start-Process cannot launch an .html file on macOS/Linux).
 try{
  if($IsMacOS){& /usr/bin/open $reportPath}
  elseif($IsLinux){& xdg-open $reportPath}
  else{Invoke-Item -LiteralPath $reportPath}
 }catch{Write-Warning "Could not open the report automatically: $reportPath"}
}

