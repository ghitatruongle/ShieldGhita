#define MyAppName "Shield Ghita"
#define MyAppVersion "0.1.0-beta1"
#define MyAppPublisher "ShieldGhita"
#define MyAppExeName "shield_ghita.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=installer_output
OutputBaseFilename=ShieldGhita_Setup_v{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
CloseApplications=force
CloseApplicationsFilter=*.exe,{#MyAppExeName}
RestartApplications=no
DirExistsWarning=no
EnableDirDoesntExistWarning=no
SetupIconFile=assets\app_icon.ico
UninstallDisplayIcon={app}\app_icon.ico
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "vietnamese"; MessagesFile: "installer\lang\Vietnamese.isl"
Name: "chinesesimplified"; MessagesFile: "installer\lang\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "autostart"; Description: "Start Shield Ghita when Windows starts"; GroupDescription: "Additional options:"

[InstallDelete]
Type: files; Name: "{app}\{#MyAppExeName}"
Type: files; Name: "{app}\*.dll"
Type: files; Name: "{app}\*.exe"
Type: files; Name: "{app}\local_*.json"
Type: files; Name: "{app}\local_*.log"
Type: filesandordirs; Name: "{app}\local"
Type: filesandordirs; Name: "{app}\assets"

[Files]
Source: "target\release_std\shield_ghita.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\app_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\app_icon.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\app_icon.ico"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ShieldGhita"; ValueData: """{app}\{#MyAppExeName}"" --autostart"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[Code]
function MapAppLanguage(): String;
var
  L: String;
begin
  L := ActiveLanguage();
  if L = 'vietnamese' then
    Result := 'vi'
  else if L = 'chinesesimplified' then
    Result := 'zh'
  else
    Result := 'en';
end;

procedure KillRunningInstances();
var
  I: Integer;
  EC: Integer;
begin
  for I := 1 to 8 do
  begin
    Exec('taskkill.exe', '/F /IM {#MyAppExeName} /T', '', SW_HIDE, ewWaitUntilTerminated, EC);
    Sleep(500);
    Exec('cmd.exe', '/C tasklist /NH /FI "IMAGENAME eq {#MyAppExeName}" | find /I "{#MyAppExeName}" > nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, EC);
    if EC <> 0 then
      Break;
  end;
end;

procedure BackupUserData();
var
  EC: Integer;
begin
  if DirExists(ExpandConstant('{userappdata}\ShieldGhita')) then
    Exec('cmd.exe',
      '/C xcopy /E /I /Y "' + ExpandConstant('{userappdata}\ShieldGhita') + '" "' + ExpandConstant('{userappdata}\ShieldGhita_Backup') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, EC);
end;

function GetUninstallString(): String;
var
  sUnInstPath: String;
  sUnInstallString: String;
begin
  sUnInstPath := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppId")}_is1';
  sUnInstallString := '';
  
  if not RegQueryStringValue(HKLM64, sUnInstPath, 'UninstallString', sUnInstallString) then
    if not RegQueryStringValue(HKLM32, sUnInstPath, 'UninstallString', sUnInstallString) then
      if not RegQueryStringValue(HKCU64, sUnInstPath, 'UninstallString', sUnInstallString) then
        RegQueryStringValue(HKCU32, sUnInstPath, 'UninstallString', sUnInstallString);
        
  Result := sUnInstallString;
end;

function InitializeSetup(): Boolean;
var
  iResultCode: Integer;
  sUnInstallString: String;
  ErrorCode: Integer;
begin
  Result := True;

  KillRunningInstances();

  sUnInstallString := GetUninstallString();
  if sUnInstallString <> '' then
  begin
    sUnInstallString := RemoveQuotes(sUnInstallString);
    Exec(sUnInstallString, '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES', '', SW_HIDE, ewWaitUntilTerminated, iResultCode);
    Sleep(1000);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    KillRunningInstances();
    BackupUserData();
    DeleteFile(ExpandConstant('{app}\{#MyAppExeName}'));
    DeleteFile(ExpandConstant('{app}\local_behavior.json'));
    DeleteFile(ExpandConstant('{app}\local_devices.json'));
    DeleteFile(ExpandConstant('{app}\local_security.json'));
    DelTree(ExpandConstant('{app}\local'), True, True, True);
  end;
  if CurStep = ssPostInstall then
  begin
    KillRunningInstances();
    RegWriteStringValue(HKCU, 'Software\ShieldGhita', 'Language', MapAppLanguage());
  end;
end;

