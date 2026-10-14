#define MyAppName "Мои пароли"
#define MyAppExe "MoiParoli.exe"
#define MyAppVersion "4.0"

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
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}
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
Source: "dist\MoiParoli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\browser_host.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "browser_extension\*"; DestDir: "{app}\browser_extension"; Flags: ignoreversion
Source: "register_browser_host.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Запустить «{#MyAppName}»"; Flags: nowait postinstall skipifsilent
