; Inno Setup script for PDFSafe.
;
; Build:  iscc /DMyAppVersion=0.1.0 packaging\installer.iss
;
; Per-user install by design: no UAC prompt, no admin rights, and uninstalling
; removes everything the app wrote. A security tool that demands elevation to
; install is a worse security proposition than one that does not.

#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif

#define MyAppName "PDFSafe"
#define MyAppPublisher "PDFSafe"
#define MyAppURL "https://pdfsafe.app"
#define MyAppExeName "PDFSafe.exe"
#define SourceDir "..\dist\PDFSafe"

[Setup]
AppId={{8E3C1A64-2F7B-4D91-9C5E-7A1B0F2D6E43}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/download
VersionInfoVersion={#MyAppVersion}

; --- per-user install, no elevation ---
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UsePreviousAppDir=yes

; --- output ---
OutputDir=..\dist\installer
OutputBaseFilename=PDFSafe-{#MyAppVersion}-setup
SetupIconFile=assets\pdfsafe.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0.17763
LicenseFile=..\LICENSE.txt
InfoBeforeFile=
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
CloseApplications=yes
CloseApplicationsFilter=*.exe
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; \
  GroupDescription: "Shortcuts:"
Name: "startupicon"; Description: "Start {#MyAppName} when I sign in"; \
  GroupDescription: "Startup:"; Flags: unchecked
Name: "contextmenu"; Description: "Add ""Scan with {#MyAppName}"" to the right-click menu for PDFs"; \
  GroupDescription: "Integration:"

[Files]
Source: "{#SourceDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*"; DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; DestName: "README.txt"; Flags: ignoreversion isreadme

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
  Parameters: "--minimized"; Tasks: startupicon

[Registry]
; "Scan with PDFSafe" on .pdf files. HKCU only - no admin rights needed.
Root: HKCU; Subkey: "Software\Classes\SystemFileAssociations\.pdf\shell\PDFSafeScan"; \
  ValueType: string; ValueName: ""; ValueData: "Scan with {#MyAppName}"; \
  Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\SystemFileAssociations\.pdf\shell\PDFSafeScan"; \
  ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"; \
  Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\SystemFileAssociations\.pdf\shell\PDFSafeScan\command"; \
  ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; \
  Flags: uninsdeletekey; Tasks: contextmenu

; Application registration, so Windows can resolve PDFSafe.exe by name.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; \
  ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; \
  Description: "Launch {#MyAppName}"; \
  Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Caches and logs are disposable. Scan history and quarantine are NOT removed
; automatically - see CurUninstallStepChanged below, which asks first.
Type: filesandordirs; Name: "{localappdata}\PDFSafe\cache"
Type: filesandordirs; Name: "{localappdata}\PDFSafe\logs"
Type: filesandordirs; Name: "{localappdata}\PDFSafe\handoff"

[Code]
function IsAppRunning(const FileName: string): Boolean;
var
  FSWbemLocator, FWMIService, FWbemObjectSet: Variant;
begin
  Result := False;
  try
    FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
    FWMIService := FSWbemLocator.ConnectServer('', 'root\CIMV2', '', '');
    FWbemObjectSet := FWMIService.ExecQuery(
      Format('SELECT * FROM Win32_Process WHERE Name = "%s"', [FileName]));
    Result := (FWbemObjectSet.Count > 0);
  except
    Result := False;
  end;
end;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if IsAppRunning('{#MyAppExeName}') then
  begin
    if MsgBox('PDFSafe is currently running and must be closed before installing.' + #13#10 + #13#10 +
              'Close it now and continue?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      Exec('taskkill.exe', '/F /IM {#MyAppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Sleep(1500);
    end
    else
      Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: string;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\PDFSafe');
    if DirExists(DataDir) then
    begin
      if MsgBox('Remove your PDFSafe scan history and quarantined files as well?' + #13#10 + #13#10 +
                'Quarantined files are ones PDFSafe judged malicious. Choose No if you ' +
                'want to keep them isolated on disk.',
                mbConfirmation, MB_YESNO) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
        DelTree(ExpandConstant('{userappdata}\PDFSafe'), True, True, True);
      end;
    end;
  end;
end;
