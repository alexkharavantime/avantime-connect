# Isolated elevated Windows CI only; no VPN/network or external DNS required.
param([Parameter(Mandatory=$true)][string]$Script)
$ErrorActionPreference = 'Stop'
$targets = @('ad.avantime.lv', '.ad.avantime.lv')
if (@(Get-DnsClientNrptRule | Where-Object { @($_.Namespace | Where-Object { $targets -contains $_ }).Count }).Count) { throw 'Requires clean test host' }
function Run-Dns([string]$Mode, [int]$Expected = 0) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -Action $Mode
    if ($LASTEXITCODE -ne $Expected) { throw "Unexpected DNS result: $LASTEXITCODE" }
}
function Own-Rules { @(Get-DnsClientNrptRule | Where-Object DisplayName -eq 'Avantime Connect split DNS v1') }
$manual = $null
$foreign = $null
try {
    $foreign = Add-DnsClientNrptRule -Namespace '.unrelated.invalid' -NameServers '192.0.2.53' -PassThru
    Run-Dns enable
    if (@(Own-Rules).Count -ne 2) { throw 'Missing apex/suffix rules' }
    Run-Dns enable
    if (@(Own-Rules).Count -ne 2) { throw 'Duplicate managed rules' }
    Run-Dns remove
    if (@(Own-Rules).Count -ne 0) { throw 'Managed cleanup failed' }
    $manual = Add-DnsClientNrptRule -Namespace '.ad.avantime.lv' -NameServers '10.40.0.10' -PassThru
    Run-Dns enable
    if (@(Own-Rules).Count -ne 1) { throw 'Manual suffix duplicated' }
    Run-Dns remove
    if (!(Get-DnsClientNrptRule -Name $manual.Name)) { throw 'Manual rule deleted' }
    Remove-DnsClientNrptRule -Name $manual.Name -Force
    $manual = Add-DnsClientNrptRule -Namespace '.ad.avantime.lv' -NameServers '192.0.2.54' -PassThru
    Run-Dns enable 27
    if (@(Own-Rules).Count -ne 0) { throw 'Conflict modified DNS' }
    if (!(Get-DnsClientNrptRule -Name $foreign.Name)) { throw 'Foreign rule deleted' }
    'Split DNS smoke OK: clean/repeat/cleanup/manual/conflict/foreign preservation'
} finally {
    Run-Dns remove
    foreach ($rule in @($manual, $foreign)) {
        if ($null -ne $rule) { Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction SilentlyContinue }
    }
}
