; Inno Setup script for Network Sentinel.
; Build:  ISCC.exe installer\NetworkSentinel.iss   (expects artifacts\publish\NetworkSentinel.exe)

#define AppName "Network Sentinel"
#define AppVersion "1.0.0"
#define AppPublisher "Network Sentinel Project"
#define AppURL "https://github.com/unupunct/Network-Sentinel"
#define AppExe "NetworkSentinel.exe"

[Setup]
AppId={{7B3F9A1C-4E52-4B8D-9A6F-3C1D5E7B9F28}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes
LicenseFile=..\release\LICENSE.txt
OutputDir=..\release
OutputBaseFilename=NetworkSentinel_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Per-user install by default (no admin needed); the dialog lets users choose an all-users install.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
; Same AppId => running the new setup upgrades in place. User data lives in %LOCALAPPDATA%\NetworkSentinel and is never touched here.
AppMutex=Local\NetworkSentinel.SingleInstance
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\artifacts\publish\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\release\LICENSE.txt"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

; Deliberately no [Registry] Run entry: Network Sentinel never starts with Windows on its own.

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\NetworkSentinel');
    if DirExists(DataDir) and not UninstallSilent then
    begin
      if MsgBox('Also delete your Network Sentinel settings, connection history database and logs?' + #13#10 + #13#10 +
                DataDir + #13#10 + #13#10 + 'Choose No to keep them for a future reinstall.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
