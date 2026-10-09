param([ValidateSet('enable','remove')][string]$Action)
$ErrorActionPreference = 'Stop'
$label = 'Avantime Connect split DNS v1'
$comment = 'Managed by Avantime Connect; ad.avantime.lv; 10.40.0.10; v1'
$changed = $false
$targets = @('ad.avantime.lv', '.ad.avantime.lv')
function ServersMatch($rule) {
    $servers = @($rule.NameServers | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
    return ($servers.Count -eq 1 -and $servers[0] -eq '10.40.0.10' -and !$rule.DirectAccessEnabled -and !$rule.DnsSecValidationRequired)
}
function Owned($rule) {
    return ($rule.DisplayName -ceq $label -and $rule.Comment -ceq $comment -and
        @($rule.Namespace).Count -eq 1 -and $targets -contains $rule.Namespace[0] -and (ServersMatch $rule))
}
function Relevant($ns) {
    $n = $ns.ToLowerInvariant().TrimEnd('.')
    return ($n -eq '' -or $n -eq 'ad.avantime.lv' -or $n.EndsWith('.ad.avantime.lv') -or
        ($n.StartsWith('.') -and 'ad.avantime.lv'.EndsWith($n)))
}
try {
    $rules = @(Get-DnsClientNrptRule)
    if ($Action -eq 'remove') {
        foreach ($r in $rules) { if (Owned $r) { Remove-DnsClientNrptRule -Name $r.Name -Force; $changed = $true } }
        if ($changed) { Clear-DnsClientCache }
        exit 0
    }
    # Respect both local/manual rules and domain policy. Never overwrite foreign rules.
    $effectiveBefore = @(Get-DnsClientNrptPolicy -Effective)
    foreach ($r in @($rules) + $effectiveBefore) {
        foreach ($ns in @($r.Namespace)) {
            if ((Relevant $ns) -and !(ServersMatch $r)) { throw 'Conflicting DNS policy' }
        }
    }
    foreach ($ns in $targets) {
        $existing = @(@($rules) + $effectiveBefore | Where-Object { @($_.Namespace) -contains $ns })
        if (!$existing.Count) {
            Add-DnsClientNrptRule -Namespace $ns -NameServers '10.40.0.10' -DisplayName $label -Comment $comment
            $changed = $true
        }
    }
    $effective = @(Get-DnsClientNrptPolicy -Effective)
    foreach ($ns in $targets) {
        $matching = @($effective | Where-Object { @($_.Namespace) -contains $ns })
        if (!$matching.Count) { throw 'DNS policy not effective' }
        foreach ($r in $matching) { if (!(ServersMatch $r)) { throw 'DNS policy conflict' } }
    }
    if ($changed) { Clear-DnsClientCache }
    exit 0
} catch { exit 27 }
