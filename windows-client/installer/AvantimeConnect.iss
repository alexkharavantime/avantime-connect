#ifndef AppVersion
  #error AppVersion required
#endif
#ifndef PublishDir
  #error PublishDir required
#endif
#ifndef WireGuardSha256
  #error WireGuardSha256 required
#endif

[Setup]
AppId={{F423F378-C5E4-4A54-914F-C92CEB6604F2}
AppName=Avantime Connect
AppVersion={#AppVersion}
AppPublisher=Avantime
DefaultDirName={autopf}\Avantime Connect
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=AvantimeConnect-Setup-{#AppVersion}-x64
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\AvantimeConnect.App.exe
AppMutex=Local\AvantimeConnect.Enrollment
SetupMutex=AvantimeConnect.Setup
CloseApplications=no
RestartApplications=no
InfoBeforeFile=BeforeInstall.txt
InfoAfterFile=AfterInstall.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "{#PublishDir}\service\Manage-Service.ps1"; Flags: dontcopy
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{commonprograms}\Avantime Connect"; Filename: "{app}\AvantimeConnect.App.exe"; WorkingDir: "{app}"
Name: "{commondesktop}\Avantime Connect"; Filename: "{app}\AvantimeConnect.App.exe"; WorkingDir: "{app}"

; No launch under installer credentials. The user opens the desktop shortcut
; normally, so enrollment DPAPI belongs to that user rather than an admin account.
; No uninstall hooks delete user profiles, tunnel configurations or WireGuard.
[Code]
var
  WireGuardRestart: Boolean;

function ManageService(Script: String; Action: String): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' + Script + '" -Action ' + Action,
    '', SW_HIDE, ewWaitUntilTerminated, Code);
  Log('Service setup action ' + Action + ': started=' + IntToStr(Ord(Result)) + ', exit=' + IntToStr(Code));
  Result := Result and (Code = 0);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if not ManageService(ExpandConstant('{app}\service\Manage-Service.ps1'), 'install') then
      RaiseException('Could not install/start the Avantime Connect service. Run Setup again to repair.');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  MsiPath: String;
  Code: Integer;
begin
  Result := '';
  ExtractTemporaryFile('Manage-Service.ps1');
  if not ManageService(ExpandConstant('{tmp}\Manage-Service.ps1'), 'prepare') then
  begin
    Result := 'Could not prepare the Avantime Connect service. Check PowerShell policy and service permissions. Installation stopped.';
    exit;
  end;
  if FileExists(ExpandConstant('{pf64}\WireGuard\wireguard.exe')) and
     FileExists(ExpandConstant('{pf64}\WireGuard\wg.exe')) then
  begin
    Log('Existing WireGuard preserved.');
    exit;
  end;
  if DirExists(ExpandConstant('{pf64}\WireGuard')) then
  begin
    Result := 'An incomplete WireGuard installation exists. Repair it before continuing.';
    exit;
  end;
  try
    WizardForm.PreparingLabel.Caption := 'Downloading and installing WireGuard. Please wait...';
    DownloadTemporaryFile('https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi',
      'wireguard-amd64-1.1.1.msi', '{#WireGuardSha256}', nil);
    MsiPath := ExpandConstant('{tmp}\wireguard-amd64-1.1.1.msi');
    if not Exec(ExpandConstant('{sys}\msiexec.exe'), '/i "' + MsiPath + '" /qn /norestart DO_NOT_LAUNCH=1',
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
      Result := 'Could not start the WireGuard installer.'
    else if (Code <> 0) and (Code <> 3010) then
      Result := 'WireGuard installation failed. Code: ' + IntToStr(Code)
    else
    begin
      WireGuardRestart := Code = 3010;
      if not FileExists(ExpandConstant('{pf64}\WireGuard\wireguard.exe')) or
         not FileExists(ExpandConstant('{pf64}\WireGuard\wg.exe')) then
        Result := 'WireGuard files were not found after installation.';
    end;
  except
    Result := 'WireGuard could not be downloaded or verified. Check your Internet connection and retry.';
  end;
end;

function NeedRestart: Boolean;
begin
  Result := WireGuardRestart;
end;

function InitializeUninstall: Boolean;
var
  Code: Integer;
  Params: String;
begin
  // Refuse removal while a managed VPN is active. Never stop another user's tunnel.
  Params := '-NoProfile -NonInteractive -Command "try { $s = Get-Service -ErrorAction Stop | Where-Object { $_.Name -like ''WireGuardTunnel$avt-*'' -and $_.Status -ne ''Stopped'' }; if ($s) { exit 2 }; exit 0 } catch { exit 3 }"';
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params,
    '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Result and (Code = 0);
  if Result then
    Result := ManageService(ExpandConstant('{app}\service\Manage-Service.ps1'), 'remove');
  if not Result then
    MsgBox('Disconnect Avantime VPN in all Windows sessions before uninstalling. Profiles and WireGuard will be preserved.', mbError, MB_OK);
end;
