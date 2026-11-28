# Builds gc-rdp-host.exe (rdp-host/, C# .NET Framework 4.8) on Windows and checks it:
#   1. aximp.exe (Windows SDK) makes the interop assemblies from the mstscax.dll of this machine,
#   2. dotnet build -c Release (net48 reference assemblies from NuGet, no developer pack needed),
#   3. --version, and --selftest: creates the RDP control and sets what a connect sets, no connection.
# Used by .github/workflows/rdp-host.yml, release.yml and e2e-windows.yml (installer smoke).
# Output: rdp-host/bin/Release/net48/ (electron-builder copies it to resources\rdp-host\).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root 'rdp-host'

$mstscax = Join-Path $env:WINDIR 'System32\mstscax.dll'
if (-not (Test-Path $mstscax)) { throw "mstscax.dll fehlt: $mstscax" }
Write-Host "mstscax.dll $((Get-Item $mstscax).VersionInfo.FileVersion)"

$aximp = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\*\bin\NETFX 4.8* Tools\x64\aximp.exe" -ErrorAction SilentlyContinue |
  Sort-Object FullName -Descending | Select-Object -First 1
if (-not $aximp) {
  $aximp = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\*\bin\NETFX 4.* Tools\x64\aximp.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
}
if (-not $aximp) { throw 'aximp.exe nicht gefunden (Windows SDK, NETFX 4.8 Tools)' }
Write-Host "aximp: $($aximp.FullName)"

$interop = Join-Path $dir 'interop'
New-Item -ItemType Directory -Force $interop | Out-Null
Push-Location $interop
try {
  & $aximp.FullName $mstscax /silent   # -> MSTSCLib.dll, AxMSTSCLib.dll
  if ($LASTEXITCODE -ne 0) { throw "aximp exit $LASTEXITCODE" }
} finally { Pop-Location }
foreach ($f in 'MSTSCLib.dll', 'AxMSTSCLib.dll') {
  if (-not (Test-Path (Join-Path $interop $f))) { throw "aximp hat $f nicht erzeugt" }
}

dotnet build -c Release --nologo (Join-Path $dir 'GateControl.RdpHost.csproj')
if ($LASTEXITCODE -ne 0) { throw "dotnet build exit $LASTEXITCODE" }

$out = Join-Path $dir 'bin\Release\net48'
$exe = Join-Path $out 'gc-rdp-host.exe'
foreach ($f in 'gc-rdp-host.exe', 'gc-rdp-host.exe.config', 'MSTSCLib.dll', 'AxMSTSCLib.dll') {
  if (-not (Test-Path (Join-Path $out $f))) { throw "$f fehlt in $out" }
}

# a WinExe: started as a process so its output is read and its exit awaited
function Invoke-Host([string]$arg) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = $arg
  $psi.RedirectStandardOutput = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $text = $p.StandardOutput.ReadToEnd()
  if (-not $p.WaitForExit(60000)) { $p.Kill(); throw "gc-rdp-host $arg hängt" }
  return @{ Text = $text.Trim(); Code = $p.ExitCode }
}

$version = (Invoke-Host '--version').Text
Write-Host "gc-rdp-host --version: $version"
if (-not $version) { throw '--version ohne Ausgabe' }

$r = Invoke-Host '--selftest'
$line = $r.Text
Write-Host "selftest: $line"
$json = $line | ConvertFrom-Json
if ($r.Code -ne 0 -or -not $json.ok) { throw "Selbsttest fehlgeschlagen (exit $($r.Code))" }
if (-not $json.checks.redirectionWarningDialogVersion) {
  Write-Host "::warning title=RedirectionWarningDialogVersion::Das Control kennt die Eigenschaft nicht ($($json.notes -join '; '))"
}
if ($env:GITHUB_STEP_SUMMARY) {
  "### gc-rdp-host $version" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
  "mstscax $($json.mstscax) · Prüfungen: $(($json.checks | ConvertTo-Json -Compress))" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
}
