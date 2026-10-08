param([string]$Version = '0.2.0')
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid version' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$compiler = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
if (!(Test-Path $compiler)) { throw 'Inno Setup 6 is required on the build machine only' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('AvantimeBuild-' + [guid]::NewGuid().ToString('N'))
$output = Join-Path $repo 'artifacts\windows-installer'
New-Item -ItemType Directory -Path $stage, $output -Force | Out-Null
try {
    $publish = Join-Path $stage 'app'
    dotnet publish (Join-Path $repo 'windows-client\src\AvantimeConnect.App') -c Release -r win-x64 --self-contained true "-p:Version=$Version" -o $publish
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
    # Verify the official prerequisite now; embed its hash into Setup for runtime verification.
    $msi = Join-Path $stage 'wireguard-amd64-1.1.1.msi'
    Invoke-WebRequest 'https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi' -OutFile $msi
    $signature = Get-AuthenticodeSignature $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
        throw 'Unexpected WireGuard signature'
    }
    $msiHash = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    foreach ($project in @('runtime', 'wpf')) {
        foreach ($notice in @('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT')) {
            Invoke-WebRequest "https://raw.githubusercontent.com/dotnet/$project/v8.0.31/$notice" -OutFile (Join-Path $publish "$project-$notice")
        }
    }
    & $compiler "/DAppVersion=$Version" "/DPublishDir=$publish" "/DOutputDir=$output" "/DWireGuardSha256=$msiHash" (Join-Path $PSScriptRoot 'AvantimeConnect.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed' }
    $setup = Join-Path $output "AvantimeConnect-Setup-$Version-x64.exe"
    $sha = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    "$sha  $([IO.Path]::GetFileName($setup))" | Set-Content (Join-Path $output 'SHA256SUMS.txt') -Encoding ascii
    Write-Host "SETUP: $setup"
} finally {
    Remove-Item $stage -Recurse -Force
}
