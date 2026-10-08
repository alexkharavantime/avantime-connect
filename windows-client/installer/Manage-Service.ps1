param([ValidateSet('prepare','install','remove')][string]$Action)
$ErrorActionPreference = 'Stop'
$name = 'AvantimeConnectBroker'
$expected = '"' + (Join-Path $env:ProgramFiles 'Avantime Connect\service\AvantimeConnect.Service.exe') + '"'
if (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
try {
    $existing = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($existing) {
        if ($existing.PathName -ne $expected -or $existing.StartName -ne 'LocalSystem') { throw 'Unexpected broker service identity' }
        $svc = Get-Service $name
        if ($svc.Status -ne 'Stopped') {
            Stop-Service $name -ErrorAction Stop
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }
    if ($Action -eq 'prepare') { exit 0 }
    if ($Action -eq 'remove') {
        if ($existing) { & "$env:SystemRoot\System32\sc.exe" delete $name | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Delete failed' } }
        exit 0
    }
    if (!$existing) {
        New-Service -Name $name -BinaryPathName $expected -DisplayName 'Avantime Connect VPN Broker' -StartupType Automatic | Out-Null
    } else { Set-Service $name -StartupType Automatic }
    # Only administrators and SYSTEM control/configure the broker. Users can query
    # its identity/status, then send narrow authenticated commands through the pipe.
    & "$env:SystemRoot\System32\sc.exe" sdset $name 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLOCRRC;;;AU)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service permissions failed' }
    Start-Service $name
    (Get-Service $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    exit 0
} catch { Write-Error 'Avantime Connect service setup failed. Repair the installation.'; exit 1 }
