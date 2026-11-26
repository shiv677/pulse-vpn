# Pulse VPN - Native Windows WireGuard Tunnel & Split-Default Route Helper
# windows/pulse-tunnel-helper.ps1
# Manages %TEMP%\pulse_vpn.conf tunnel service installation, /1 split-default routing,
# and 0ms make-before-break Fast-Hop endpoint switching via wg.exe.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "rotate", "stop")]
    [string]$Action,

    [string]$TunnelName = "pulse_vpn",
    [string]$ConfigPath = "$env:TEMP\pulse_vpn.conf",
    [string]$TunnelIp = "172.16.0.2",
    [string]$EndpointHost = "162.159.192.1",
    [string]$PhysicalGateway = "",
    [string]$PeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
    [string]$NewEndpoint = "162.159.193.1:2408"
)

$ErrorActionPreference = "SilentlyContinue"
$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$WireGuardProgramDir = "$env:ProgramFiles\WireGuard"

function Resolve-ToolPath([string]$ExeName) {
    foreach ($candidate in @("$AppDir\$ExeName", "$WireGuardProgramDir\$ExeName", $ExeName)) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }
    return $ExeName
}

$WireGuardExe = Resolve-ToolPath "wireguard.exe"
$WgExe = Resolve-ToolPath "wg.exe"

if ($Action -eq "start") {
    & $WireGuardExe /installtunnelservice "$ConfigPath"
    if ($PhysicalGateway -ne "") {
        & route.exe add $EndpointHost mask 255.255.255.255 $PhysicalGateway metric 1
    }
    & route.exe add 0.0.0.0 mask 128.0.0.0 $TunnelIp metric 5
    & route.exe add 128.0.0.0 mask 128.0.0.0 $TunnelIp metric 5
    & netsh.exe interface ip set dns name="$TunnelName" static 1.1.1.1 primary
}
elseif ($Action -eq "rotate") {
    & $WgExe set $TunnelName peer $PeerPublicKey endpoint $NewEndpoint
}
elseif ($Action -eq "stop") {
    & $WireGuardExe /uninstalltunnelservice $TunnelName
    & route.exe delete 0.0.0.0 mask 128.0.0.0
    & route.exe delete 128.0.0.0 mask 128.0.0.0
}
