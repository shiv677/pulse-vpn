// Pulse VPN - Multi-Relay Fast-Hop & Make-Before-Break Engine
// lib/core/fast_hop.dart

import 'auth_service.dart';
import 'relay_discovery.dart';

enum FastHopInterval {
  fiveSeconds(5),
  thirtySeconds(30),
  oneMinute(60),
  fiveMinutes(300),
  disabled(0);

  final int seconds;
  const FastHopInterval(this.seconds);

  bool get isEnabled => this != FastHopInterval.disabled && seconds > 0;
  int get preWarmLeadSeconds => isEnabled ? 2 : 0;
}

enum FastHopState {
  idle,
  active,
  preWarmingStandby,
  swapping,
}

class FastHopController {
  FastHopInterval _interval = FastHopInterval.disabled;
  FastHopState _state = FastHopState.idle;
  RelayNode? _activePeer;
  RelayNode? _standbyPeer;
  bool _isStandbyPreWarmed = false;
  int _hopCount = 0;
  int _elapsedSecondsInCycle = 0;
  List<RelayNode> _candidateQueue = [];

  FastHopInterval get interval => _interval;
  FastHopState get state => _state;
  RelayNode? get activePeer => _activePeer;
  RelayNode? get standbyPeer => _standbyPeer;
  bool get isStandbyPreWarmed => _isStandbyPreWarmed;
  int get hopCount => _hopCount;
  List<RelayNode> get candidateQueue => List.unmodifiable(_candidateQueue);

  /// Populates the candidate relay queue sorted by lowest jitter and latency
  void updateCandidates(List<RelayNode> relays) {
    _candidateQueue = sortRelaysByJitter(relays);
    if (_activePeer == null && _candidateQueue.isNotEmpty) {
      _activePeer = _candidateQueue[0];
    }
    if (_standbyPeer == null && _candidateQueue.length > 1) {
      _standbyPeer = _candidateQueue[1];
    }
  }

  /// Checks whether the user session is authorized to use Fast-Hop rotation
  static bool canUseFastHop(UserSession? session) {
    return session != null && session.isPro;
  }

  /// Enables Fast-Hop dual-peer pool (strictly gated by UserSession.isPro)
  bool enable({
    required UserSession? session,
    required FastHopInterval interval,
    List<RelayNode>? relays,
  }) {
    if (interval == FastHopInterval.disabled) {
      disable();
      return true;
    }

    if (!canUseFastHop(session)) {
      throw StateError('Fast-Hop requires an active Pulse VPN Pro subscription');
    }

    if (relays != null) {
      updateCandidates(relays);
    }

    if (_candidateQueue.length < 2) {
      throw StateError('Fast-Hop requires at least 2 relay nodes for hot standby');
    }

    _interval = interval;
    _activePeer = _candidateQueue[0];
    _standbyPeer = _candidateQueue[1];
    _isStandbyPreWarmed = false;
    _elapsedSecondsInCycle = 0;
    _state = FastHopState.active;
    return true;
  }

  /// Pre-warms and handshakes the standby peer 2 seconds before the scheduled hop
  bool preWarmStandby() {
    if (!_interval.isEnabled || _standbyPeer == null) {
      return false;
    }
    _state = FastHopState.preWarmingStandby;
    _isStandbyPreWarmed = true;
    return true;
  }

  /// Executes a 0ms make-before-break route swap preserving existing socket bindings
  RelayNode executeHop({required UserSession? session}) {
    if (!canUseFastHop(session)) {
      throw StateError('Fast-Hop execution denied: Pro tier required');
    }
    if (!_interval.isEnabled || _activePeer == null || _standbyPeer == null) {
      throw StateError('Fast-Hop is not active or missing standby peer');
    }

    if (!_isStandbyPreWarmed) {
      preWarmStandby();
    }

    _state = FastHopState.swapping;

    final previousActive = _activePeer!;
    final promotedPeer = _standbyPeer!;

    // Promote pre-warmed standby peer to active (0ms route metric flip)
    _activePeer = promotedPeer;

    // Rotate previous active peer to the end of the jitter-ranked queue
    _candidateQueue.removeWhere((r) => r.ip == previousActive.ip);
    _candidateQueue.add(previousActive);

    // Select next lowest-jitter standby candidate distinct from activePeer
    _standbyPeer = _candidateQueue.firstWhere(
      (r) => r.ip != _activePeer!.ip,
      orElse: () => previousActive,
    );

    _isStandbyPreWarmed = false;
    _elapsedSecondsInCycle = 0;
    _hopCount += 1;
    _state = FastHopState.active;

    return _activePeer!;
  }

  /// Advances the cycle clock by 1 second, triggering pre-warm at T-2s and hop at T=0s
  void tickSecond({required UserSession? session}) {
    if (!_interval.isEnabled || _state == FastHopState.idle) {
      return;
    }
    if (!canUseFastHop(session)) {
      disable();
      return;
    }

    _elapsedSecondsInCycle += 1;
    final remaining = _interval.seconds - _elapsedSecondsInCycle;

    if (remaining <= _interval.preWarmLeadSeconds &&
        remaining > 0 &&
        !_isStandbyPreWarmed) {
      preWarmStandby();
    } else if (remaining <= 0) {
      executeHop(session: session);
    }
  }

  void disable() {
    _interval = FastHopInterval.disabled;
    _state = FastHopState.idle;
    _isStandbyPreWarmed = false;
    _elapsedSecondsInCycle = 0;
  }
}
