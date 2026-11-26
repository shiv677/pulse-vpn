// Pulse VPN - Bandwidth Telemetry & Connection State Machine
// lib/core/telemetry.dart

enum VpnConnectionState {
  disconnected,
  connecting,
  connected,
  reconnecting,
  error,
}

/// Strict connection state machine
class VpnStateMachine {
  VpnConnectionState _currentState = VpnConnectionState.disconnected;
  String? _lastError;

  VpnConnectionState get currentState => _currentState;
  String? get lastError => _lastError;

  static const Map<VpnConnectionState, Set<VpnConnectionState>> _allowedTransitions = {
    VpnConnectionState.disconnected: {
      VpnConnectionState.connecting,
    },
    VpnConnectionState.connecting: {
      VpnConnectionState.connected,
      VpnConnectionState.error,
      VpnConnectionState.disconnected,
    },
    VpnConnectionState.connected: {
      VpnConnectionState.reconnecting,
      VpnConnectionState.disconnected,
    },
    VpnConnectionState.reconnecting: {
      VpnConnectionState.connected,
      VpnConnectionState.error,
      VpnConnectionState.disconnected,
    },
    VpnConnectionState.error: {
      VpnConnectionState.connecting,
      VpnConnectionState.disconnected,
    },
  };

  /// Attempts to transition to a new state. Returns true if successful, false otherwise.
  bool transition(VpnConnectionState newState, {String? errorMessage}) {
    final validTargets = _allowedTransitions[_currentState];
    if (validTargets == null || !validTargets.contains(newState)) {
      return false;
    }

    _currentState = newState;
    if (newState == VpnConnectionState.error) {
      _lastError = errorMessage ?? 'Unknown VPN connection error';
    } else if (newState == VpnConnectionState.connected) {
      _lastError = null;
    }
    return true;
  }

  void reset() {
    _currentState = VpnConnectionState.disconnected;
    _lastError = null;
  }
}

/// Real-time bandwidth and session telemetry
class BandwidthTelemetry {
  int rxBytes = 0;
  int txBytes = 0;
  double rxSpeedMbps = 0.0;
  double txSpeedMbps = 0.0;
  double packetLossPercent = 0.0;
  Duration sessionDuration = Duration.zero;

  void update({
    required int totalRxBytes,
    required int totalTxBytes,
    required double deltaSeconds,
    int packetsSent = 0,
    int packetsLost = 0,
    Duration? duration,
  }) {
    if (deltaSeconds > 0) {
      final deltaRx = (totalRxBytes - rxBytes).clamp(0, 1000000000);
      final deltaTx = (totalTxBytes - txBytes).clamp(0, 1000000000);

      // (Bytes * 8) / (seconds * 1,000,000) = Mbps
      rxSpeedMbps = (deltaRx * 8.0) / (deltaSeconds * 1000000.0);
      txSpeedMbps = (deltaTx * 8.0) / (deltaSeconds * 1000000.0);
    }

    rxBytes = totalRxBytes;
    txBytes = totalTxBytes;

    if (packetsSent > 0) {
      packetLossPercent = ((packetsLost / packetsSent) * 100.0).clamp(0.0, 100.0);
    } else {
      packetLossPercent = 0.0;
    }

    if (duration != null) {
      sessionDuration = duration;
    }
  }

  String formatDuration() {
    final hours = sessionDuration.inHours.toString().padLeft(2, '0');
    final minutes = (sessionDuration.inMinutes % 60).toString().padLeft(2, '0');
    final seconds = (sessionDuration.inSeconds % 60).toString().padLeft(2, '0');
    return '$hours:$minutes:$seconds';
  }
}
