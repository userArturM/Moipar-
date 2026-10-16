#define MyAppName "Bitora Password Manager"
#define MyAppExe "MoiParoli.exe"
#define MyAppVersion "4.11.0"

[Setup]
AppId={{B7E1C0A2-6D54-4C57-9A3E-5F2D1A9C7E31}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppName}
DefaultDirName={autopf}\MoiParoli
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=installer_out
OutputBaseFilename=MoiParoli-Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\bitora-{#MyAppVersion}.ico
UninstallDisplayName={#MyAppName}
VersionInfoDescription=Bitora Password Manager
VersionInfoProductName=Bitora Password Manager
UsePreviousAppDir=yes
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
ArchitecturesInstallIn64BitMode=x64

[Languages]
#if FileExists(CompilerPath + "Languages\Russian.isl")
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
#else
Name: "english"; MessagesFile: "compiler:Default.isl"
#endif

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительно:"; Flags: unchecked

[Files]
Source: "icon.ico"; DestDir: "{app}"; DestName: "bitora-{#MyAppVersion}.ico"; Flags: ignoreversion
Source: "dist\MoiParoli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\browser_host.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "browser_extension\*"; DestDir: "{app}\browser_extension"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "register_browser_host.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; IconFilename: "{app}\bitora-{#MyAppVersion}.ico"; AppUserModelID: "Bitora.Password"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; IconFilename: "{app}\bitora-{#MyAppVersion}.ico"; AppUserModelID: "Bitora.Password"; Check: ShouldCreateDesktopShortcut

[InstallDelete]
Type: files; Name: "{autoprograms}\Bitora Paswword Manager.lnk"
Type: files; Name: "{autodesktop}\Bitora Paswword Manager.lnk"
Type: files; Name: "{autoprograms}\Bitora password.lnk"
Type: files; Name: "{autodesktop}\Bitora password.lnk"
Type: files; Name: "{autoprograms}\Мои пароли.lnk"
Type: files; Name: "{autodesktop}\Мои пароли.lnk"

[Run]
Filename: "{app}\browser_host.exe"; Parameters: "--register"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Description: "Запустить «{#MyAppName}»"; Flags: nowait postinstall skipifsilent

[Code]
var
  HadDesktopShortcut: Boolean;

procedure InitializeWizard;
begin
  HadDesktopShortcut := FileExists(ExpandConstant('{autodesktop}\Bitora Paswword Manager.lnk')) or
    FileExists(ExpandConstant('{autodesktop}\Bitora password.lnk')) or
    FileExists(ExpandConstant('{autodesktop}\Мои пароли.lnk')) or
    FileExists(ExpandConstant('{autodesktop}\{#MyAppName}.lnk'));
end;

function ShouldCreateDesktopShortcut: Boolean;
begin
  Result := HadDesktopShortcut or WizardIsTaskSelected('desktopicon');
end;

procedure SHChangeNotify(wEventId: Integer; uFlags: Cardinal; dwItem1, dwItem2: Integer);
  external 'SHChangeNotify@shell32.dll stdcall';

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    SHChangeNotify($08000000, 0, 0, 0);
end;

