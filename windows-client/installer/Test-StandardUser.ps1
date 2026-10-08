param([Parameter(Mandatory)][string]$Setup)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Disposable CI only' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$bin = Join-Path $env:ProgramFiles 'AvantimeBrokerChecks'
$exchange = Join-Path $env:PUBLIC ('AvantimeBrokerChecks-' + [guid]::NewGuid().ToString('N'))
New-Item $exchange -ItemType Directory | Out-Null
& icacls.exe $exchange /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
dotnet publish (Join-Path $repo 'windows-client\tests\AvantimeConnect.Checks') -c Release -r win-x64 --self-contained true -o $bin
if ($LASTEXITCODE -ne 0) { throw 'Test client publish failed' }
$users = @()
try {
    foreach ($suffix in @('A','B')) {
        $user = 'avtCI' + $suffix + ([guid]::NewGuid().ToString('N').Substring(0,6))
        $password = ConvertTo-SecureString ('Aa1!' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
        New-LocalUser -Name $user -Password $password | Out-Null
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
        $users += [pscustomobject]@{ Name=$user; Credential=[pscredential]::new("$env:COMPUTERNAME\$user",$password) }
    }
    function Probe($who, $phase) {
        $stdout = Join-Path $exchange ($phase + '.out')
        $stderr = Join-Path $exchange ($phase + '.err')
        $p = Start-Process (Join-Path $bin 'AvantimeConnect.Checks.exe') -Credential $who.Credential -LoadUserProfile -WorkingDirectory $bin -ArgumentList @('--broker-smoke', $phase, "`"$exchange`"") -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
        Get-Content $stdout
        if ($p.ExitCode -ne 0) { Get-Content $stderr; throw "Standard-user test failed: $phase ($($p.ExitCode))" }
    }
    Probe $users[0] 'connect'
    Probe $users[1] 'foreign'
    $p = Start-Process $Setup -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-') -Wait -PassThru
    if ($p.ExitCode -notin @(0,3010)) { throw 'Upgrade failed' }
    Probe $users[0] 'after-upgrade'
    $name = Get-Content (Join-Path $exchange 'name')
    if ($name -notmatch '^avt-[a-f0-9]{24}$') { throw 'Invalid synthetic tunnel name' }
    & "$env:ProgramFiles\WireGuard\wireguard.exe" /uninstalltunnelservice $name
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic tunnel cleanup failed' }
} finally {
    foreach ($u in $users) { Remove-LocalUser -Name $u.Name -ErrorAction SilentlyContinue }
}
