// Pulse VPN - Relay Discovery & Latency Engine
// lib/core/relay_discovery.dart

class RelayNode {
  final String hostname;
  final String ip;
  final int score;
  final int pingLatencyMs;
  final int jitterMs;
  final int speedBps;
  final String countryLong;
  final String countryShort;
  final String flagEmoji;
  final String configBase64;

  RelayNode({
    required this.hostname,
    required this.ip,
    required this.score,
    required this.pingLatencyMs,
    required this.jitterMs,
    required this.speedBps,
    required this.countryLong,
    required this.countryShort,
    required this.flagEmoji,
    required this.configBase64,
  });
}

/// Converts a 2-letter ISO country code into Unicode Regional Indicator flag emoji
String countryCodeToFlag(String code) {
  if (code.length != 2) return '🌐';
  final upper = code.toUpperCase();
  final first = upper.codeUnitAt(0) - 0x41 + 0x1F1E6;
  final second = upper.codeUnitAt(1) - 0x41 + 0x1F1E6;
  if (first < 0x1F1E6 || first > 0x1F1FF || second < 0x1F1E6 || second > 0x1F1FF) {
    return '🌐';
  }
  return String.fromCharCode(first) + String.fromCharCode(second);
}

/// Calculates relay quality score favoring low latency, low jitter, and high bandwidth
int calculateRelayScore(int latencyMs, int jitterMs, int speedBps) {
  final speedMbps = speedBps / 1000000.0;
  final penalty = (latencyMs * 2.0) + (jitterMs * 3.5);
  final score = (speedMbps * 50.0) - penalty;
  return score > 0 ? score.toInt() : 1;
}

/// Parses public VPN Gate format CSV data into structured RelayNode list
List<RelayNode> parseVpnGateCsv(String csvData) {
  final List<RelayNode> relays = [];
  final lines = csvData.split(RegExp(r'\r?\n'));

  for (var line in lines) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('*') || trimmed.startsWith('#')) {
      continue;
    }

    final cols = trimmed.split(',');
    if (cols.length < 15) continue;

    final hostname = cols[0].trim();
    final ip = cols[1].trim();
    final score = int.tryParse(cols[2].trim()) ?? 0;
    final ping = int.tryParse(cols[3].trim()) ?? 999;
    final speed = int.tryParse(cols[4].trim()) ?? 0;
    final countryLong = cols[5].trim();
    final countryShort = cols[6].trim();
    final configBase64 = cols[14].trim();

    // Estimate jitter proportional to ping variance (or baseline 5-15% of ping)
    final estimatedJitter = (ping * 0.12).toInt().clamp(1, 100);

    relays.add(RelayNode(
      hostname: hostname,
      ip: ip,
      score: score > 0 ? score : calculateRelayScore(ping, estimatedJitter, speed),
      pingLatencyMs: ping,
      jitterMs: estimatedJitter,
      speedBps: speed,
      countryLong: countryLong,
      countryShort: countryShort,
      flagEmoji: countryCodeToFlag(countryShort),
      configBase64: configBase64,
    ));
  }

  return relays;
}

/// Sorts relays by lowest jitter and lowest latency
List<RelayNode> sortRelaysByJitter(List<RelayNode> relays) {
  final sorted = List<RelayNode>.from(relays);
  sorted.sort((a, b) {
    final jitterCmp = a.jitterMs.compareTo(b.jitterMs);
    if (jitterCmp != 0) return jitterCmp;
    return a.pingLatencyMs.compareTo(b.pingLatencyMs);
  });
  return sorted;
}

/// Sorts relays by highest calculated quality score
List<RelayNode> sortRelaysByScore(List<RelayNode> relays) {
  final sorted = List<RelayNode>.from(relays);
  sorted.sort((a, b) => b.score.compareTo(a.score));
  return sorted;
}
