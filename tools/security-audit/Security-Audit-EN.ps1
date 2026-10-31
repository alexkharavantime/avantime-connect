<#
Security-Audit-EN.ps1 - Windows Server security audit (read-only, changes nothing)
ASCII-only: works regardless of file encoding.
Run: PowerShell as Administrator.
Report: C:\SecurityAudit\<HOSTNAME>_<date>.txt
#>

$ErrorActionPreference = 'SilentlyContinue'
$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([ValidateSet('OK','WARN','CRIT','INFO')]$Level, [string]$Area, [string]$Message)
    $Results.Add([pscustomobject]@{Level=$Level; Area=$Area; Message=$Message})
    $color = @{OK='Green'; WARN='Yellow'; CRIT='Red'; INFO='Cyan'}[$Level]
    Write-Host ("[{0,-4}] {1,-10} : {2}" -f $Level, $Area, $Message) -ForegroundColor $color
}

# --- Admin check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run PowerShell as Administrator." -ForegroundColor Red; return }

$hostName = $env:COMPUTERNAME
Write-Host "`n=== Security audit: $hostName ($(Get-Date -Format 'yyyy-MM-dd HH:mm')) ===`n" -ForegroundColor White

# --- 1. System ---
$os = Get-CimInstance Win32_OperatingSystem
$uptime = (Get-Date) - $os.LastBootUpTime
Add-Result INFO 'System' "$($os.Caption) build $($os.BuildNumber), uptime $([int]$uptime.TotalDays) days"

# --- 2. Updates ---
$lastUpd = $null
try { $lastUpd = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate } catch {}
if (-not $lastUpd -or $lastUpd.Year -lt 2000) {
    $lastUpd = (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
}
if ($lastUpd) {
    $days = [int]((Get-Date) - $lastUpd).TotalDays
    if ($days -gt 60) { Add-Result CRIT 'Updates' "Last install $days days ago ($($lastUpd.ToString('yyyy-MM-dd')))" }
    elseif ($days -gt 35) { Add-Result WARN 'Updates' "Last install $days days ago ($($lastUpd.ToString('yyyy-MM-dd')))" }
    else { Add-Result OK 'Updates' "Last install $days days ago" }
} else { Add-Result WARN 'Updates' 'Could not determine last update date' }

$pendingReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
if ($pendingReboot) { Add-Result WARN 'Updates' 'Reboot pending to finish installing updates' }

# --- 3. Firewall ---
foreach ($p in Get-NetFirewallProfile) {
    if ($p.Enabled) { Add-Result OK 'Firewall' "Profile $($p.Name) enabled" }
    else { Add-Result CRIT 'Firewall' "Profile $($p.Name) is DISABLED" }
}

# --- 4. Listening ports ---
$risky = @{
    21='FTP'; 23='Telnet'; 135='RPC'; 139='NetBIOS'; 445='SMB'; 1433='MS SQL'; 1434='SQL Browser';
    3389='RDP'; 5985='WinRM HTTP'; 5986='WinRM HTTPS'; 1540='1C cluster agent'; 1541='1C cluster manager';
    1545='1C RAS'; 5432='PostgreSQL'; 3306='MySQL'
}
$listen = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') }
$seen = @{}
foreach ($c in ($listen | Sort-Object LocalPort)) {
    $key = "$($c.LocalPort)"
    if ($seen[$key]) { continue }; $seen[$key] = $true
    $proc = (Get-Process -Id $c.OwningProcess).ProcessName
    $name = $risky[[int]$c.LocalPort]
    if (-not $name -and $c.LocalPort -ge 1560 -and $c.LocalPort -le 1591) { $name = '1C worker processes' }
    if ($name) { Add-Result WARN 'Ports' "Listening $($c.LocalPort) ($name, $proc) on $($c.LocalAddress) - make sure it is NOT forwarded to the internet" }
    else { Add-Result INFO 'Ports' "Listening $($c.LocalPort) ($proc) on $($c.LocalAddress)" }
}

# --- 5. RDP ---
$rdpOff = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
$rdpKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
if ($rdpOff -eq 0) {
    Add-Result INFO 'RDP' "RDP enabled, port $($rdpKey.PortNumber)"
    if ($rdpKey.UserAuthentication -eq 1) { Add-Result OK 'RDP' 'NLA (Network Level Authentication) enabled' }
    else { Add-Result CRIT 'RDP' 'NLA is DISABLED - enable it' }
    if ($rdpKey.MinEncryptionLevel -lt 3) { Add-Result WARN 'RDP' "RDP encryption level: $($rdpKey.MinEncryptionLevel) (recommended 3 = High)" }
} else { Add-Result OK 'RDP' 'RDP disabled' }

# --- 6. Local accounts ---
$admins = Get-LocalGroupMember -SID 'S-1-5-32-544'
Add-Result INFO 'Accounts' "Local administrators: $(($admins | ForEach-Object Name) -join ', ')"
if (($admins | Measure-Object).Count -gt 4) { Add-Result WARN 'Accounts' "$(($admins | Measure-Object).Count) administrators - check that all are needed" }

foreach ($u in Get-LocalUser) {
    $sid = $u.SID.Value
    if ($sid -like '*-501' -and $u.Enabled) { Add-Result CRIT 'Accounts' "Guest account '$($u.Name)' is ENABLED" }
    if ($sid -like '*-500' -and $u.Enabled) { Add-Result WARN 'Accounts' "Built-in administrator '$($u.Name)' is enabled - main target for password guessing; rename or disable" }
    if ($u.Enabled -and -not $u.PasswordRequired) { Add-Result CRIT 'Accounts' "'$($u.Name)': password NOT required" }
    if ($u.Enabled -and -not $u.PasswordExpires -and $sid -notlike '*-503' -and $sid -notlike '*-504') {
        Add-Result INFO 'Accounts' "'$($u.Name)': password never expires"
    }
    if ($u.Enabled -and $u.LastLogon -and ((Get-Date) - $u.LastLogon).TotalDays -gt 90) {
        Add-Result WARN 'Accounts' "'$($u.Name)' enabled but no logon for $([int]((Get-Date) - $u.LastLogon).TotalDays) days - disable?"
    }
}

# --- 7. Password and lockout policy ---
$cfg = Join-Path $env:TEMP 'secpol_audit.cfg'
secedit /export /cfg $cfg /areas SECURITYPOLICY | Out-Null
$pol = @{}
Get-Content $cfg | Where-Object { $_ -match '^\s*(\w+)\s*=\s*(.+)$' } | ForEach-Object { $pol[$Matches[1]] = $Matches[2].Trim() }
Remove-Item $cfg -Force

$lock = [int]$pol['LockoutBadCount']
if ($lock -eq 0) { Add-Result CRIT 'Passwords' 'Account lockout is DISABLED - passwords can be guessed endlessly' }
elseif ($lock -gt 10) { Add-Result WARN 'Passwords' "Lockout after $lock attempts (recommended 5-10)" }
else { Add-Result OK 'Passwords' "Lockout after $lock failed attempts" }

$minLen = [int]$pol['MinimumPasswordLength']
if ($minLen -lt 12) { Add-Result WARN 'Passwords' "Minimum password length: $minLen (recommended 12+)" }
else { Add-Result OK 'Passwords' "Minimum password length: $minLen" }
if ($pol['PasswordComplexity'] -ne '1') { Add-Result WARN 'Passwords' 'Password complexity requirement is disabled' }

# --- 8. Failed logons (password guessing), last 24 h ---
Write-Host "Reading Security log, this can take a minute..." -ForegroundColor DarkGray
$since = (Get-Date).AddHours(-24)
$fail = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -MaxEvents 5000
$failCount = ($fail | Measure-Object).Count
if ($failCount -gt 0) {
    $top = $fail | ForEach-Object { $_.Properties[19].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
    $topStr = ($top | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
    $lvl = if ($failCount -gt 100) { 'CRIT' } elseif ($failCount -gt 20) { 'WARN' } else { 'INFO' }
    Add-Result $lvl 'Logons' "Failed logons in 24 h: $failCount. Top IPs: $topStr"
} else { Add-Result OK 'Logons' 'No failed logons in 24 h' }

# --- 9. Successful RDP logons, last 7 days ---
$rdpOk = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20000 |
    Where-Object { $_.Properties[8].Value -eq 10 }
if ($rdpOk) {
    $grp = $rdpOk | ForEach-Object { "$($_.Properties[5].Value) from $($_.Properties[18].Value)" } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10
    Add-Result INFO 'Logons' "RDP logons in 7 days: $(($grp | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; ') - check all IPs and users are known"
}

# --- 10. Antivirus ---
$mp = Get-MpComputerStatus
if ($mp) {
    if ($mp.RealTimeProtectionEnabled) { Add-Result OK 'Antivirus' 'Defender real-time protection enabled' }
    else { Add-Result CRIT 'Antivirus' 'Defender real-time protection is DISABLED' }
    $sigAge = [int]((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays
    if ($sigAge -gt 7) { Add-Result WARN 'Antivirus' "Signatures are $sigAge days old" }
    else { Add-Result OK 'Antivirus' "Signatures updated $sigAge days ago" }
} else { Add-Result WARN 'Antivirus' 'Defender not available - verify another antivirus is installed' }

# --- 11. SMB ---
$smb = Get-SmbServerConfiguration
if ($smb.EnableSMB1Protocol) { Add-Result CRIT 'SMB' 'SMBv1 is ENABLED (WannaCry vector) - disable it' }
else { Add-Result OK 'SMB' 'SMBv1 disabled' }

$everyone = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0').Translate([System.Security.Principal.NTAccount]).Value
foreach ($s in Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' }) {
    $acc = Get-SmbShareAccess -Name $s.Name | Where-Object { ($_.AccountName -eq $everyone -or $_.AccountName -eq 'Everyone') -and $_.AccessRight -in 'Full','Change' }
    if ($acc) { Add-Result WARN 'SMB' "Share '$($s.Name)' ($($s.Path)): write access for Everyone" }
    else { Add-Result INFO 'SMB' "Share '$($s.Name)' ($($s.Path))" }
}

# --- 12. 1C and SQL services ---
$svc = Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'ragent|1cv8' -or $_.Name -like 'MSSQL*' -or $_.Name -like 'SQLAgent*' -or $_.Name -like 'postgresql*' }
foreach ($s in $svc) {
    if ($s.StartName -match '^LocalSystem$') { Add-Result WARN 'Services' "$($s.Name) runs as LocalSystem - use a dedicated low-privilege account" }
    else { Add-Result OK 'Services' "$($s.Name) runs as $($s.StartName)" }
}

# --- 13. Scheduled tasks (non-Microsoft) ---
foreach ($t in Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }) {
    $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
    Add-Result INFO 'Tasks' "$($t.TaskPath)$($t.TaskName): $act"
}

# --- Summary and report ---
$crit = ($Results | Where-Object Level -eq 'CRIT' | Measure-Object).Count
$warn = ($Results | Where-Object Level -eq 'WARN' | Measure-Object).Count
Write-Host "`n=== SUMMARY: critical $crit, warnings $warn ===" -ForegroundColor White

$dir = 'C:\SecurityAudit'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$file = Join-Path $dir ("{0}_{1}.txt" -f $hostName, (Get-Date -Format 'yyyyMMdd_HHmm'))
$header = "Security audit $hostName, $(Get-Date -Format 'yyyy-MM-dd HH:mm')`r`nCritical: $crit, Warnings: $warn`r`n"
$body = $Results | Sort-Object @{e={@{CRIT=0;WARN=1;INFO=2;OK=3}[$_.Level]}}, Area |
    ForEach-Object { "{0,-4} | {1,-10} | {2}" -f $_.Level, $_.Area, $_.Message }
($header, ($body -join "`r`n")) -join "`r`n" | Out-File -FilePath $file -Encoding UTF8
Write-Host "Report saved: $file`n" -ForegroundColor White
Write-Host "Reminder: this script cannot see what is open from the INTERNET. Check router port forwarding and scan your external IP (nmap)." -ForegroundColor Yellow
