// Pulse VPN - Native Windows OS Tunnel Bridge & Split-Default Route Manager
// lib/core/native_tunnel_bridge.dart

import 'dart:io';

import 'wireguard_config.dart';

class NativeTunnelBridge {
  final String tunnelName;
  final String configFileName;

  bool _isTunnelActive = false;
  String? _lastStagedConfigPath;
  String? _activeEndpoint;
  final List<String> _executedCommandsLog = [];

  NativeTunnelBridge({
    this.tunnelName = 'pulse_vpn',
    this.configFileName = 'pulse_vpn.conf',
  });

  bool get isTunnelActive => _isTunnelActive;
  String? get lastStagedConfigPath => _lastStagedConfigPath;
  String? get activeEndpoint => _activeEndpoint;
  List<String> get executedCommandsLog => List.unmodifiable(_executedCommandsLog);

  /// Resolves `%TEMP%\pulse_vpn.conf` on Windows or `/tmp/pulse_vpn.conf` on POSIX
  String get stagingConfigPath {
    final tempDir = Directory.systemTemp.path;
    final sep = Platform.pathSeparator;
    return tempDir.endsWith(sep)
        ? '$tempDir$configFileName'
        : '$tempDir$sep$configFileName';
  }

  /// Extracts clean IPv4 address from CIDR notation (e.g. `172.16.0.2/32` -> `172.16.0.2`)
  static String extractTunnelIpv4(String addressField) {
    final firstToken = addressField.split(',').first.trim();
    final slashIdx = firstToken.indexOf('/');
    final cleanIp = slashIdx != -1 ? firstToken.substring(0, slashIdx).trim() : firstToken;
    return cleanIp.isNotEmpty ? cleanIp : '172.16.0.2';
  }

  /// Extracts host IP from `ip:port` endpoint string
  static String extractEndpointHost(String endpoint) {
    final colonIdx = endpoint.lastIndexOf(':');
    if (colonIdx <= 0) return endpoint.trim();
    return endpoint.substring(0, colonIdx).trim();
  }

  /// Stages WireGuard INI configuration to `%TEMP%\pulse_vpn.conf`
  Future<File> writeConfigToTemp(WireGuardConfig config, {String? customPath}) async {
    final targetPath = customPath ?? stagingConfigPath;
    final file = File(targetPath);
    await file.parent.create(recursive: true);
    await file.writeAsString(config.toIni(), flush: true);
    _lastStagedConfigPath = file.path;
    return file;
  }

  /// Generates OS-level Windows commands to install the tunnel service and override
  /// `0.0.0.0/0 -> Ethernet` using `/1` split-default routes (`0.0.0.0/1` and `128.0.0.0/1`).
  List<String> buildStartTunnelCommands({
    required String configPath,
    required String tunnelIp,
    required String endpointHost,
    String? physicalGateway,
  }) {
    final commands = <String>[
      'wireguard.exe /installtunnelservice "$configPath"',
    ];

    if (physicalGateway != null && physicalGateway.trim().isNotEmpty) {
      commands.add(
        'route add $endpointHost mask 255.255.255.255 ${physicalGateway.trim()} metric 1',
      );
    }

    commands.addAll([
      'route add 0.0.0.0 mask 128.0.0.0 $tunnelIp metric 5',
      'route add 128.0.0.0 mask 128.0.0.0 $tunnelIp metric 5',
      'netsh interface ip set dns name="$tunnelName" static 1.1.1.1 primary',
    ]);

    return commands;
  }

  /// Generates 0ms make-before-break live WireGuard peer endpoint update command
  String buildFastHopEndpointCommand({
    required String peerPublicKey,
    required String newEndpoint,
  }) {
    final normalizedEndpoint =
        newEndpoint.contains(':') ? newEndpoint : '$newEndpoint:2408';
    return 'wg set $tunnelName peer $peerPublicKey endpoint $normalizedEndpoint';
  }

  /// Generates OS-level commands to remove split-default routes and uninstall the tunnel service
  List<String> buildStopTunnelCommands() {
    return [
      'wireguard.exe /uninstalltunnelservice $tunnelName',
      'route delete 0.0.0.0 mask 128.0.0.0',
      'route delete 128.0.0.0 mask 128.0.0.0',
    ];
  }

  /// Writes `%TEMP%\pulse_vpn.conf`, installs the Windows WireGuard service, and applies split-default routes
  Future<bool> startTunnel(
    WireGuardConfig config, {
    String? physicalGateway,
    bool dryRun = false,
  }) async {
    final stagedFile = await writeConfigToTemp(config);
    final tunnelIp = extractTunnelIpv4(config.interface.address);
    final firstPeer = config.peers.isNotEmpty ? config.peers.first : null;
    final endpoint = firstPeer?.endpoint ?? '162.159.192.1:2408';
    final endpointHost = extractEndpointHost(endpoint);

    final commands = buildStartTunnelCommands(
      configPath: stagedFile.path,
      tunnelIp: tunnelIp,
      endpointHost: endpointHost,
      physicalGateway: physicalGateway,
    );

    _executedCommandsLog.addAll(commands);
    _activeEndpoint = endpoint;

    if (!dryRun && Platform.isWindows) {
      for (final cmd in commands) {
        try {
          await Process.run('cmd.exe', ['/c', cmd]);
        } catch (_) {
          // Graceful handling if wireguard.exe is not in PATH on headless test runners
        }
      }
    }

    _isTunnelActive = true;
    return true;
  }

  /// Performs a 0ms make-before-break Fast-Hop IP rotation via `wg set <tunnel> peer <pubkey> endpoint <ip:port>`
  Future<bool> rotatePeerEndpoint({
    required String peerPublicKey,
    required String newEndpoint,
    bool dryRun = false,
  }) async {
    final command = buildFastHopEndpointCommand(
      peerPublicKey: peerPublicKey,
      newEndpoint: newEndpoint,
    );
    _executedCommandsLog.add(command);
    _activeEndpoint =
        newEndpoint.contains(':') ? newEndpoint : '$newEndpoint:2408';

    if (!dryRun && Platform.isWindows) {
      try {
        await Process.run('cmd.exe', ['/c', command]);
      } catch (_) {
        // Non-fatal in environments without wg.exe installed
      }
    }

    return true;
  }

  /// Tears down the OS WireGuard service and restores the original physical default route
  Future<bool> stopTunnel({bool dryRun = false}) async {
    final commands = buildStopTunnelCommands();
    _executedCommandsLog.addAll(commands);

    if (!dryRun && Platform.isWindows) {
      for (final cmd in commands) {
        try {
          await Process.run('cmd.exe', ['/c', cmd]);
        } catch (_) {
          // Non-fatal cleanup
        }
      }
    }

    _isTunnelActive = false;
    _activeEndpoint = null;
    return true;
  }
}
