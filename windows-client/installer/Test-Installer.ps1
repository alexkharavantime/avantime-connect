param([Parameter(Mandatory)][string]$Setup)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Installer smoke test is restricted to a disposable GitHub-hosted runner'
}
$app = Join-Path $env:ProgramFiles 'Avantime Connect'
$wg = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
if (Test-Path $wg) { throw 'Fresh-install test requires a runner without WireGuard' }
$profile = Join-Path $env:LOCALAPPDATA 'AvantimeConnect\enrollment.dpapi'
if (Test-Path $profile) { throw 'Unexpected existing profile on disposable runner' }
New-Item -ItemType Directory -Path (Split-Path $profile) -Force | Out-Null
[IO.File]::WriteAllBytes($profile, [byte[]](1..64))
$profileHash = (Get-FileHash $profile).Hash
# Reproduce Windows client default policy, regardless of the CI runner defaults.
# Each installer child inherits Restricted; only its own helper may narrow the
# override to RemoteSigned. No machine/user policy is changed by the installer.
function Invoke-RestrictedInstaller([string]$File, [string[]]$Arguments) {
    $savedPolicy = $env:PSExecutionPolicyPreference
    try {
        $env:PSExecutionPolicyPreference = 'Restricted'
        $effective = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command 'Get-ExecutionPolicy'
        if ($effective.Trim() -ne 'Restricted') { throw 'Restricted-policy precondition failed' }
        $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru
        $after = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command 'Get-ExecutionPolicy'
        if ($after.Trim() -ne 'Restricted') { throw 'Installer changed inherited execution policy' }
        return $process
    } finally { $env:PSExecutionPolicyPreference = $savedPolicy }
}
function Run-Setup {
    $p = Invoke-RestrictedInstaller $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-')
    if ($p.ExitCode -notin @(0, 3010)) { throw "Setup failed: $($p.ExitCode)" }
}
Run-Setup
foreach ($file in @('AvantimeConnect.App.exe', 'coreclr.dll', 'PresentationFramework.dll', 'unins000.exe')) {
    if (!(Test-Path (Join-Path $app $file))) { throw "Installed file missing: $file" }
}
if (!(Test-Path $wg)) { throw 'WireGuard prerequisite was not installed' }
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Avantime Connect.lnk'
if (!(Test-Path $shortcut)) { throw 'Desktop shortcut missing' }
if ((Get-FileHash $profile).Hash -ne $profileHash) { throw 'Existing profile changed' }
Write-Host 'PASS: fresh install installs app, runtime, WireGuard, shortcut; preserves profile'
# Suppress global .NET discovery: installed app must use its bundled runtime.
$env:DOTNET_ROOT = Join-Path $env:RUNNER_TEMP 'no-global-dotnet'
$env:DOTNET_MULTILEVEL_LOOKUP = '0'
$probe = Start-Process (Join-Path $app 'AvantimeConnect.App.exe') -ArgumentList '--installer-probe' -Wait -PassThru
if ($probe.ExitCode -ne 26) { throw 'Installed apphost could not reach its safe argument-validation path' }
Write-Host 'PASS: installed self-contained app starts without launching the UI or enrolling'
if ((Get-Service AvantimeConnectBroker).Status -ne 'Running') { throw 'Broker is not running' }
& (Join-Path $PSScriptRoot 'Test-StandardUser.ps1') -Setup $Setup
$wgHash = (Get-FileHash $wg).Hash
Run-Setup
if ((Get-FileHash $profile).Hash -ne $profileHash -or (Get-FileHash $wg).Hash -ne $wgHash) { throw 'Repair/update changed profile or existing WireGuard' }
Write-Host 'PASS: repeat install preserves profile and existing WireGuard'
$remove = Invoke-RestrictedInstaller (Join-Path $app 'unins000.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')
if ($remove.ExitCode -ne 0 -or (Test-Path (Join-Path $app 'AvantimeConnect.App.exe'))) { throw 'Uninstall failed' }
if (!(Test-Path $wg) -or (Get-FileHash $profile).Hash -ne $profileHash) { throw 'Uninstall removed prerequisites or profile' }
if (Get-Service AvantimeConnectBroker -ErrorAction SilentlyContinue) { throw 'Broker was not removed' }
if (Test-Path $shortcut) { throw 'Uninstall left desktop shortcut' }
Write-Host 'PASS: uninstall removes app and shortcut; preserves profile and WireGuard'
Remove-Item $profile
