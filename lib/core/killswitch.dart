// Pulse VPN - Dual-Platform Killswitch Rules Engine
// lib/core/killswitch.dart

/// Windows Filtering Platform (WFP) & Windows Firewall Rules Generator
class WindowsKillswitchEngine {
  final String rulePrefix;

  const WindowsKillswitchEngine({this.rulePrefix = 'PulseVPN_Killswitch'});

  /// Generates PowerShell commands configuring WFP / Windows Firewall lockdown
  String generateEnableScript({
    required String serverEndpointIp,
    required int serverEndpointPort,
    String interfaceAlias = 'PulseVPN',
    bool allowLocalLan = true,
  }) {
    final buffer = StringBuffer();
    buffer.writeln('# Enable Pulse VPN Killswitch via Windows Advanced Firewall');
    buffer.writeln('\$ErrorActionPreference = "Stop"');

    // 1. Block outbound by default
    buffer.writeln('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound');

    // 2. Allow Loopback (127.0.0.1/8, ::1)
    buffer.writeln('New-NetFirewallRule -DisplayName "${rulePrefix}_Allow_Loopback" '
        '-Direction Outbound -Action Allow -RemoteAddress "127.0.0.1/8","::1" -Profile Any');

    // 3. Allow WireGuard tunnel interface traffic
    buffer.writeln('New-NetFirewallRule -DisplayName "${rulePrefix}_Allow_Tunnel" '
        '-Direction Outbound -Action Allow -InterfaceAlias "$interfaceAlias" -Profile Any');

    // 4. Allow WireGuard handshake endpoint UDP traffic
    buffer.writeln('New-NetFirewallRule -DisplayName "${rulePrefix}_Allow_Handshake" '
        '-Direction Outbound -Action Allow -Protocol UDP -RemoteAddress "$serverEndpointIp" '
        '-RemotePort $serverEndpointPort -Profile Any');

    // 5. Allow Local LAN Subnets if enabled
    if (allowLocalLan) {
      buffer.writeln('New-NetFirewallRule -DisplayName "${rulePrefix}_Allow_LAN" '
          '-Direction Outbound -Action Allow '
          '-RemoteAddress "192.168.0.0/16","10.0.0.0/8","172.16.0.0/12","169.254.0.0/16" -Profile Any');
    }

    // 6. Allow DHCP & DNS essential handshake (ports 67, 68)
    buffer.writeln('New-NetFirewallRule -DisplayName "${rulePrefix}_Allow_DHCP" '
        '-Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any');

    return buffer.toString();
  }

  /// Generates PowerShell commands removing all killswitch firewall rules and restoring default policy
  String generateDisableScript() {
    final buffer = StringBuffer();
    buffer.writeln('# Disable Pulse VPN Killswitch');
    buffer.writeln('\$ErrorActionPreference = "SilentlyContinue"');
    buffer.writeln('Get-NetFirewallRule -DisplayName "${rulePrefix}_*" | Remove-NetFirewallRule');
    buffer.writeln('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound');
    return buffer.toString();
  }
}

/// Android VpnService Blocking State & Lockdown Engine
class AndroidVpnBlockingState {
  final bool isAlwaysOnVpn;
  final bool isLockdownMode;
  final List<String> allowedApplications;
  final List<String> disallowedApplications;

  const AndroidVpnBlockingState({
    this.isAlwaysOnVpn = false,
    this.isLockdownMode = false,
    this.allowedApplications = const [],
    this.disallowedApplications = const [],
  });

  /// Check whether outbound traffic without VPN is completely blocked
  bool get isTrafficBlockedOutsideVpn => isLockdownMode || isAlwaysOnVpn;

  /// Validates split tunneling configuration
  bool validate() {
    if (allowedApplications.isNotEmpty && disallowedApplications.isNotEmpty) {
      return false; // Cannot have both allowlist and disallowlist active simultaneously
    }
    return true;
  }

  /// Exports configuration as intent bundle arguments for Android VpnService.Builder
  Map<String, dynamic> toVpnServiceParams() {
    return {
      'always_on': isAlwaysOnVpn,
      'lockdown': isLockdownMode,
      'blocking': isTrafficBlockedOutsideVpn,
      'allowed_packages': allowedApplications,
      'disallowed_packages': disallowedApplications,
      'blocking_enabled': isLockdownMode,
    };
  }
}
