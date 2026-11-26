// Pulse VPN - Core WireGuard Configuration Parser & Generator
// lib/core/wireguard_config.dart

class WireGuardInterface {
  final String privateKey;
  final String address;
  final String? dns;
  final int listenPort;
  final int mtu;

  WireGuardInterface({
    required this.privateKey,
    required this.address,
    this.dns,
    this.listenPort = 0,
    int mtu = 1420,
  }) : mtu = clampMtu(mtu);

  /// Clamps MTU to standard safe WireGuard MTU (1420 bytes) to avoid packet fragmentation
  static int clampMtu(int value) {
    if (value <= 0 || value > 1420) {
      return 1420;
    }
    return value;
  }
}

class WireGuardPeer {
  final String publicKey;
  final String? presharedKey;
  final String endpoint;
  final List<String> allowedIPs;
  final int persistentKeepalive;

  WireGuardPeer({
    required this.publicKey,
    this.presharedKey,
    required this.endpoint,
    this.allowedIPs = const ['0.0.0.0/0', '::/0'],
    this.persistentKeepalive = 25,
  });
}

class WireGuardConfig {
  final WireGuardInterface interface;
  final List<WireGuardPeer> peers;

  WireGuardConfig({
    required this.interface,
    required this.peers,
  });

  /// Parse standard WireGuard .conf INI string into structured configuration
  static WireGuardConfig parse(String iniContent) {
    String currentSection = '';
    Map<String, String> ifaceMap = {};
    List<Map<String, String>> peersList = [];
    Map<String, String> currentPeer = {};

    final lines = iniContent.split(RegExp(r'\r?\n'));
    for (var line in lines) {
      final trimmed = line.trim();
      if (trimmed.isEmpty || trimmed.startsWith('#')) {
        continue;
      }

      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        currentSection = trimmed.substring(1, trimmed.length - 1).toLowerCase();
        if (currentSection == 'peer') {
          currentPeer = {};
          peersList.add(currentPeer);
        }
        continue;
      }

      final eqIdx = trimmed.indexOf('=');
      if (eqIdx == -1) continue;

      final key = trimmed.substring(0, eqIdx).trim().toLowerCase();
      final val = trimmed.substring(eqIdx + 1).trim();

      if (currentSection == 'interface') {
        ifaceMap[key] = val;
      } else if (currentSection == 'peer') {
        currentPeer[key] = val;
      }
    }

    final privateKey = ifaceMap['privatekey'] ?? '';
    final address = ifaceMap['address'] ?? '';
    final dns = ifaceMap['dns'];
    final listenPort = int.tryParse(ifaceMap['listenport'] ?? '0') ?? 0;
    final parsedMtu = int.tryParse(ifaceMap['mtu'] ?? '1420') ?? 1420;

    final iface = WireGuardInterface(
      privateKey: privateKey,
      address: address,
      dns: dns,
      listenPort: listenPort,
      mtu: parsedMtu,
    );

    final peers = peersList.map((p) {
      final pubKey = p['publickey'] ?? '';
      final psk = p['presharedkey'];
      final endpoint = p['endpoint'] ?? '';
      final keepalive = int.tryParse(p['persistentkeepalive'] ?? '25') ?? 25;
      final allowedStr = p['allowedips'] ?? '0.0.0.0/0, ::/0';
      final allowedIPs = allowedStr
          .split(',')
          .map((ip) => ip.trim())
          .where((ip) => ip.isNotEmpty)
          .toList();

      return WireGuardPeer(
        publicKey: pubKey,
        presharedKey: psk,
        endpoint: endpoint,
        allowedIPs: allowedIPs,
        persistentKeepalive: keepalive,
      );
    }).toList();

    return WireGuardConfig(interface: iface, peers: peers);
  }

  /// Serialize structured configuration into standard WireGuard .conf format
  String toIni() {
    final buffer = StringBuffer();
    buffer.writeln('[Interface]');
    buffer.writeln('PrivateKey = ${interface.privateKey}');
    buffer.writeln('Address = ${interface.address}');
    if (interface.dns != null && interface.dns!.isNotEmpty) {
      buffer.writeln('DNS = ${interface.dns}');
    }
    if (interface.listenPort > 0) {
      buffer.writeln('ListenPort = ${interface.listenPort}');
    }
    buffer.writeln('MTU = ${interface.mtu}');

    for (var peer in peers) {
      buffer.writeln('\n[Peer]');
      buffer.writeln('PublicKey = ${peer.publicKey}');
      if (peer.presharedKey != null && peer.presharedKey!.isNotEmpty) {
        buffer.writeln('PresharedKey = ${peer.presharedKey}');
      }
      buffer.writeln('Endpoint = ${peer.endpoint}');
      buffer.writeln('AllowedIPs = ${peer.allowedIPs.join(', ')}');
      if (peer.persistentKeepalive > 0) {
        buffer.writeln('PersistentKeepalive = ${peer.persistentKeepalive}');
      }
    }

    return buffer.toString();
  }
}
