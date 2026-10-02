<#
  Packaged-installer smoke test (Windows, admin — GitHub windows runners are).

  Installs the NSIS installer from dist/ silently, checks files, shortcuts,
  registry and firewall rules, starts the packaged app briefly (with the e2e
  variables set, which a packaged build must ignore), then uninstalls silently
  and checks that everything is gone.

  Usage: pwsh test/e2e/installer-smoke.ps1 -Edition pro|community [-Dist dist]
#>
param(
  [Parameter(Mandatory = $true)][ValidateSet('pro', 'community')][string]$Edition,
  [string]$Dist = 'dist'
)

$ErrorActionPreference = 'Stop'

$cfg = @{
  pro = @{
    Product       = 'GateControl Pro Client'
    Shortcut      = 'GateControl Pro'
    RulePrefix    = 'GateControl_Pro'
    # Created by build/installer.nsh customInstall, removed by customUnInstall.
    InstallRules  = @('GateControl Pro WireGuard', 'GateControl Pro RDP')
    CrashLog      = 'gatecontrol-pro-crash.log'
  }
  community = @{
    Product       = 'GateControl Community Client'
    Shortcut      = 'GateControl'
    RulePrefix    = 'GateControl_Community'
    InstallRules  = @()
    CrashLog      = $null
  }
}[$Edition]

$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$what) {
  if ($ok) { Write-Host "  ok   $what" } else { Write-Host "  FAIL $what"; $failures.Add($what) }
}
function GcRules { @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'GateControl*' }) }
function OutboundPolicy { (Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object { "$($_.Name)=$($_.DefaultOutboundAction)" }) -join ',' }

$product = $cfg.Product
$instDir = Join-Path $env:ProgramFiles $product
$exe = Join-Path $instDir "$product.exe"
$uninstaller = Join-Path $instDir "Uninstall $product.exe"
$desktopLnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) "$($cfg.Shortcut).lnk"
$startMenuLnk = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) "$($cfg.Shortcut).lnk"

$setup = @(Get-ChildItem -Path $Dist -Filter '*Setup*.exe' -File)
if ($setup.Count -ne 1) { throw "expected exactly one *Setup*.exe in $Dist, found $($setup.Count)" }
$setup = $setup[0].FullName
Write-Host "Installer: $setup"

if (Test-Path $exe) { throw "$exe already exists before the install" }
$rulesBefore = GcRules
$policyBefore = OutboundPolicy
Write-Host "GateControl firewall rules before install: $($rulesBefore.Count); outbound policy: $policyBefore"

# ── Install ──────────────────────────────────────────────
Write-Host "`n== Silent install"
$p = Start-Process -FilePath $setup -ArgumentList '/S' -Wait -PassThru
Check ($p.ExitCode -eq 0) "installer exit code 0 (got $($p.ExitCode))"
Check (Test-Path $exe) "app exe installed at $exe"
Check (Test-Path $uninstaller) "uninstaller present"
Check (Test-Path (Join-Path $instDir 'resources\app.asar')) "resources\app.asar present"
Check (Test-Path (Join-Path $instDir 'resources\update-signing.pub')) "resources\update-signing.pub present"
Check (Test-Path (Join-Path $instDir 'resources\resources\bin\wireguard.dll')) "WireGuard DLL shipped (resources\resources\bin\wireguard.dll)"
Check (Test-Path $desktopLnk) "desktop shortcut $desktopLnk"
Check (Test-Path $startMenuLnk) "start menu shortcut $startMenuLnk"

$uninstKeys = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
  Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -like "$product*" })
Check ($uninstKeys.Count -ge 1) "uninstall registry entry present"

# The e2e test hooks must not be packaged.
$asarList = node -e "console.log(require('@electron/asar').listPackage(process.argv[1]).join('\n'))" (Join-Path $instDir 'resources\app.asar')
Check ($LASTEXITCODE -eq 0) "app.asar readable"
Check (-not ($asarList | Where-Object { $_ -match '^[\\/]test([\\/]|$)' })) "app.asar contains no test/ (e2e hooks not shipped)"
Check ([bool]($asarList | Where-Object { $_ -match 'e2e-guard\.js$' })) "app.asar contains src/main/e2e-guard.js"

# Firewall: only the rules the installer is designed to create.
$rulesAfter = GcRules
$newRules = @($rulesAfter | Where-Object { $n = $_.Name; -not ($rulesBefore | Where-Object { $_.Name -eq $n }) })
Write-Host "New GateControl rules after install: $(($newRules | ForEach-Object DisplayName) -join ', ')"
foreach ($r in $cfg.InstallRules) {
  Check ([bool]($newRules | Where-Object DisplayName -eq $r)) "install-time rule '$r' created"
}
$unexpected = @($newRules | Where-Object { $cfg.InstallRules -notcontains $_.DisplayName })
Check ($unexpected.Count -eq 0) "no other GateControl rules at install time (kill switch / RDP allow): $(($unexpected | ForEach-Object DisplayName) -join ', ')"
Check ((OutboundPolicy) -eq $policyBefore) "outbound firewall policy unchanged by install"
$wgRule = $newRules | Where-Object DisplayName -eq 'GateControl Pro WireGuard'
if ($wgRule) {
  $prog = ($wgRule | Get-NetFirewallApplicationFilter).Program
  Check ($prog -eq $exe) "WireGuard rule points at the installed exe ($prog)"
}

# ── Launch the packaged app briefly ──────────────────────
Write-Host "`n== Launch packaged app (with GC_E2E set, must be ignored)"
$e2eDir = Join-Path $env:RUNNER_TEMP "gc-packaged-e2e-probe"
New-Item -ItemType Directory -Force -Path $e2eDir | Out-Null
$env:GC_E2E = '1'
$env:GC_E2E_DIR = $e2eDir
$env:GC_E2E_UPDATE_PUBKEY = Join-Path $e2eDir 'attacker.pub'
'-----BEGIN PUBLIC KEY-----' | Set-Content $env:GC_E2E_UPDATE_PUBKEY
$userData = Join-Path $env:APPDATA $product
$app = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 15
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($instDir, [StringComparison]::OrdinalIgnoreCase) })
Write-Host "Launcher process exited: $($app.HasExited) $(if ($app.HasExited) { "(exit code $($app.ExitCode))" }); app processes: $($running.Count)"
Get-ChildItem $env:APPDATA, $env:LOCALAPPDATA -Directory -ErrorAction SilentlyContinue | Where-Object Name -like '*gatecontrol*' | ForEach-Object { Write-Host "  data dir: $($_.FullName)" }
$crashLog = Join-Path $env:USERPROFILE $cfg.CrashLog
if ($cfg.CrashLog -and (Test-Path $crashLog)) { Write-Host "--- $crashLog (tail)"; Get-Content $crashLog -Tail 40 | ForEach-Object { Write-Host "  $_" } }
Check ($running.Count -ge 1) "packaged app is running after 15 s"
Check (-not (Test-Path (Join-Path $e2eDir 'events.jsonl'))) "packaged app ignored GC_E2E (no e2e hooks)"
Check (-not (Test-Path (Join-Path $e2eDir 'userData'))) "packaged app ignored GC_E2E_DIR"
Check (Test-Path $userData) "packaged app uses its normal userData ($userData)"
Remove-Item Env:GC_E2E, Env:GC_E2E_DIR, Env:GC_E2E_UPDATE_PUBKEY
$ksRules = @(GcRules | Where-Object { $_.DisplayName -like "$($cfg.RulePrefix)_*" })
Check ($ksRules.Count -eq 0) "no kill-switch/RDP-allow rules after app start"
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($instDir, [StringComparison]::OrdinalIgnoreCase) } | Stop-Process -Force
Start-Sleep -Seconds 3

# ── Uninstall ────────────────────────────────────────────
Write-Host "`n== Silent uninstall"
$p = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru
Check ($p.ExitCode -eq 0) "uninstaller exit code 0 (got $($p.ExitCode))"
# The NSIS uninstaller re-launches itself from %TEMP%; wait for the files to go.
$deadline = (Get-Date).AddSeconds(120)
while ((Test-Path $exe) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
Start-Sleep -Seconds 3
Check (-not (Test-Path $exe)) "app exe removed"
Check (-not (Test-Path $uninstaller)) "uninstaller removed"
Check (-not (Test-Path (Join-Path $instDir 'resources'))) "resources removed"
Check (-not (Test-Path $desktopLnk)) "desktop shortcut removed"
Check (-not (Test-Path $startMenuLnk)) "start menu shortcut removed"
$uninstKeys = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
  Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -like "$product*" })
Check ($uninstKeys.Count -eq 0) "uninstall registry entry removed"
$left = @(GcRules | Where-Object { $n = $_.Name; -not ($rulesBefore | Where-Object { $_.Name -eq $n }) })
Check ($left.Count -eq 0) "all GateControl firewall rules removed: $(($left | ForEach-Object DisplayName) -join ', ')"
Check ((OutboundPolicy) -eq $policyBefore) "outbound firewall policy unchanged after uninstall"

# Informational: leftovers outside the install dir (not failures).
if ($Edition -eq 'pro') {
  schtasks /Query /TN GateControlProAutostart *> $null
  if ($LASTEXITCODE -eq 0) { Write-Host "::warning::Autostart task GateControlProAutostart still exists after uninstall" }
}
if (Test-Path $instDir) { Write-Host "Note: $instDir still exists: $((Get-ChildItem -Recurse $instDir | ForEach-Object FullName) -join ', ')" }

if ($failures.Count -gt 0) {
  Write-Host "`n$($failures.Count) check(s) failed:"
  $failures | ForEach-Object { Write-Host "::error::$_" }
  exit 1
}
Write-Host "`nInstaller smoke test passed."
