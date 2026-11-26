; Pulse VPN - Inno Setup Windows Installer Script
; packaging/windows/installer.iss
; Builds standalone signed/elevated installer: PulseVPN-Setup.exe (v1.2.0)

#define MyAppName "Pulse VPN"
#define MyAppVersion "1.2.0"
#define MyAppPublisher "Shivansh Dimri"
#define MyAppURL "https://github.com/shiv677/pulse-vpn"
#define MyAppExeName "pulse_vpn.exe"

[Setup]
AppId={{6B84F2A1-4E53-4A9E-9A7D-2C3E4F5A6B7C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\dist
OutputBaseFilename=PulseVPN-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Core Flutter Windows Release Application & Runtime Libraries
Source: "..\..\build\windows\x64\runner\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\build\windows\x64\runner\Release\*.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\build\windows\x64\runner\Release\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; Signed Wintun Layer-3 TUN Driver DLL, Tunnel Helper Runner, and Loader Manifest
Source: "..\..\windows\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\windows\wireguard.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\windows\wg.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\windows\pulse-tunnel-helper.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\windows\wintun.manifest"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\windows\packaging_config.json"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Ensure any active WireGuard tunnel service, split-default routes, and WFP killswitch rules are cleaned up on uninstall
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""wireguard.exe /uninstalltunnelservice pulse_vpn 2>$null; route.exe delete 0.0.0.0 mask 128.0.0.0 2>$null; route.exe delete 128.0.0.0 mask 128.0.0.0 2>$null; Get-NetFirewallRule -DisplayName 'PulseVPN_Killswitch_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"""; Flags: runhidden; RunOnceId: "CleanupPulseVpnKillswitchAndRoutes"
