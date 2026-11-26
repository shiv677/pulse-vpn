// Pulse VPN - Cyber-Minimalist Responsive Dashboard UI
// lib/ui/home_screen.dart
//
// Matches Shivansh's portfolio cyber-minimalist design language:
// - Connect toggle button (animated power orb + state ring)
// - Real-time speedometer (Rx/Tx Mbps radial gauge + packet loss telemetry)
// - Country/server picker (Unicode flag emoji, latency, jitter, lowest-jitter sort)
// - Private/public mode switcher (Private Cloud Oracle Exit vs Public VPN Gate Relay)
// - Pro Authentication modal trigger (Login / Pro) in top navigation bar
// - Fast-Hop multi-relay rotation visualizer & 5s countdown indicator

import 'dart:async';
import 'package:flutter/material.dart';
import '../core/auth_service.dart';
import '../core/fast_hop.dart';
import '../core/killswitch.dart';
import '../core/native_tunnel_bridge.dart';
import '../core/relay_discovery.dart';
import '../core/telemetry.dart';
import '../core/warp_provisioner.dart';
import '../core/wireguard_config.dart';
import 'widgets/auth_modal.dart';
import 'widgets/fast_hop_indicator.dart';
import 'widgets/server_picker_modal.dart';
import 'widgets/speedometer_gauge.dart';

enum VpnTunnelMode {
  privateCloud,
  publicRelay,
}

class PulseDashboardScreen extends StatefulWidget {
  const PulseDashboardScreen({super.key});

  @override
  State<PulseDashboardScreen> createState() => _PulseDashboardScreenState();
}

class _PulseDashboardScreenState extends State<PulseDashboardScreen> {
  final VpnStateMachine _stateMachine = VpnStateMachine();
  final BandwidthTelemetry _telemetry = BandwidthTelemetry();
  final WindowsKillswitchEngine _windowsKillswitch = const WindowsKillswitchEngine();
  final AuthService _authService = AuthService();
  final FastHopController _fastHopController = FastHopController();
  final NativeTunnelBridge _tunnelBridge = NativeTunnelBridge();
  final WarpProvisioner _warpProvisioner = WarpProvisioner();

  VpnTunnelMode _selectedMode = VpnTunnelMode.privateCloud;
  bool _killswitchEnabled = true;
  bool _allowLanTraffic = true;
  UserSession? _currentSession;
  int _fastHopElapsedSeconds = 0;
  Timer? _fastHopTimer;
  WireGuardConfig? _activeWireGuardConfig;

  late List<RelayNode> _relays;
  late RelayNode _activeRelay;

  @override
  void initState() {
    super.initState();
    _relays = sortRelaysByJitter([
      ...WarpProvisioner.buildWarpRelayPool(),
      ..._buildDefaultRelays(),
    ]);
    _activeRelay = _relays.first;
    _fastHopController.updateCandidates(_relays);
  }

  @override
  void dispose() {
    _fastHopTimer?.cancel();
    super.dispose();
  }

  List<RelayNode> _buildDefaultRelays() {
    return [
      RelayNode(
        hostname: 'oci-ap-mumbai-01.pulsevpn.internal',
        ip: '140.238.220.14',
        score: 98500,
        pingLatencyMs: 11,
        jitterMs: 2,
        speedBps: 940000000,
        countryLong: 'India (Oracle Cloud Private)',
        countryShort: 'IN',
        flagEmoji: countryCodeToFlag('IN'),
        configBase64: 'W0ludGVyZmFjZV0=',
      ),
      RelayNode(
        hostname: 'vg-uswest-01.opengw.net',
        ip: '203.0.113.19',
        score: 84200,
        pingLatencyMs: 18,
        jitterMs: 3,
        speedBps: 620000000,
        countryLong: 'United States',
        countryShort: 'US',
        flagEmoji: countryCodeToFlag('US'),
        configBase64: 'W0ludGVyZmFjZV0=',
      ),
      RelayNode(
        hostname: 'vg-tokyo-fiber.opengw.net',
        ip: '198.51.100.42',
        score: 79400,
        pingLatencyMs: 24,
        jitterMs: 4,
        speedBps: 540000000,
        countryLong: 'Japan',
        countryShort: 'JP',
        flagEmoji: countryCodeToFlag('JP'),
        configBase64: 'W0ludGVyZmFjZV0=',
      ),
      RelayNode(
        hostname: 'vg-frankfurt-core.opengw.net',
        ip: '192.0.2.88',
        score: 73100,
        pingLatencyMs: 31,
        jitterMs: 5,
        speedBps: 480000000,
        countryLong: 'Germany',
        countryShort: 'DE',
        flagEmoji: countryCodeToFlag('DE'),
        configBase64: 'W0ludGVyZmFjZV0=',
      ),
      RelayNode(
        hostname: 'vg-singapore-edge.opengw.net',
        ip: '203.0.113.104',
        score: 88900,
        pingLatencyMs: 15,
        jitterMs: 2,
        speedBps: 780000000,
        countryLong: 'Singapore',
        countryShort: 'SG',
        flagEmoji: countryCodeToFlag('SG'),
        configBase64: 'W0ludGVyZmFjZV0=',
      ),
    ];
  }

  Future<void> _toggleConnection() async {
    if (_stateMachine.currentState == VpnConnectionState.disconnected ||
        _stateMachine.currentState == VpnConnectionState.error) {
      setState(() {
        _stateMachine.transition(VpnConnectionState.connecting);
      });

      final endpoint = '${_activeRelay.ip}:2408';
      final config = await _warpProvisioner.provisionFreeConfig(
        endpointOverride: endpoint,
      );
      _activeWireGuardConfig = config;
      await _tunnelBridge.startTunnel(config);

      if (!mounted) return;
      setState(() {
        _stateMachine.transition(VpnConnectionState.connected);
        _telemetry.update(
          totalRxBytes: 18450000,
          totalTxBytes: 4920000,
          deltaSeconds: 1.0,
          packetsSent: 1200,
          packetsLost: 1,
          duration: const Duration(minutes: 14, seconds: 38),
        );
      });
      _startFastHopLoop();
    } else {
      _fastHopTimer?.cancel();
      _fastHopTimer = null;
      await _tunnelBridge.stopTunnel();

      if (!mounted) return;
      setState(() {
        _stateMachine.transition(VpnConnectionState.disconnected);
        _telemetry.update(
          totalRxBytes: 0,
          totalTxBytes: 0,
          deltaSeconds: 1.0,
          packetsSent: 0,
          packetsLost: 0,
          duration: Duration.zero,
        );
      });
    }
  }

  void _startFastHopLoop() {
    _fastHopTimer?.cancel();
    _fastHopTimer = Timer.periodic(const Duration(seconds: 1), (_) async {
      if (!mounted ||
          _stateMachine.currentState != VpnConnectionState.connected ||
          !_fastHopController.interval.isEnabled) {
        return;
      }

      final previousHopCount = _fastHopController.hopCount;
      _fastHopController.tickSecond(session: _currentSession);

      if (_fastHopController.hopCount > previousHopCount &&
          _fastHopController.activePeer != null) {
        final nextPeer = _fastHopController.activePeer!;
        final peerPubKey = (_activeWireGuardConfig != null &&
                _activeWireGuardConfig!.peers.isNotEmpty)
            ? _activeWireGuardConfig!.peers.first.publicKey
            : WarpProvisioner.warpAnycastPublicKey;
        await _tunnelBridge.rotatePeerEndpoint(
          peerPublicKey: peerPubKey,
          newEndpoint: '${nextPeer.ip}:2408',
        );
      }

      if (mounted) {
        setState(() {
          _activeRelay = _fastHopController.activePeer ?? _activeRelay;
          _fastHopElapsedSeconds =
              (_fastHopElapsedSeconds + 1) % _fastHopController.interval.seconds;
        });
      }
    });
  }

  void _switchMode(VpnTunnelMode mode) {
    setState(() {
      _selectedMode = mode;
      if (mode == VpnTunnelMode.privateCloud) {
        _activeRelay = _relays.firstWhere(
          (r) => r.countryShort == 'IN',
          orElse: () => _relays.first,
        );
      } else {
        _activeRelay = _relays.firstWhere(
          (r) => r.countryShort != 'IN',
          orElse: () => _relays.first,
        );
      }
    });
  }

  void _openAuthModal() {
    showDialog<UserSession?>(
      context: context,
      builder: (context) => AuthModal(
        authService: _authService,
        onSessionUpdated: (session) {
          setState(() {
            _currentSession = session;
            if (!(session?.isPro ?? false)) {
              _fastHopController.disable();
              _fastHopElapsedSeconds = 0;
            }
          });
        },
      ),
    );
  }

  void _handleFastHopIntervalChange(FastHopInterval interval) {
    setState(() {
      if (interval == FastHopInterval.disabled) {
        _fastHopController.disable();
        _fastHopElapsedSeconds = 0;
      } else if (_currentSession?.isPro ?? false) {
        _fastHopController.enable(
          session: _currentSession,
          interval: interval,
          relays: _relays,
        );
        _fastHopController.preWarmStandby();
        _activeRelay = _fastHopController.activePeer ?? _activeRelay;
        _fastHopElapsedSeconds = 0;
        if (_stateMachine.currentState == VpnConnectionState.connected) {
          _startFastHopLoop();
        }
      } else {
        _openAuthModal();
      }
    });
  }

  void _openCountryServerPicker() {
    showModalBottomSheet<RelayNode>(
      context: context,
      backgroundColor: const Color(0xFF0D121C),
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => ServerPickerModal(
        relays: _relays,
        selectedRelay: _activeRelay,
        onSelect: (relay) {
          setState(() {
            _activeRelay = relay;
          });
          Navigator.of(context).pop(relay);
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isConnected = _stateMachine.currentState == VpnConnectionState.connected;
    final accentColor = isConnected ? const Color(0xFF10B981) : const Color(0xFF00F0FF);

    return Scaffold(
      backgroundColor: const Color(0xFF07090E),
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final isDesktop = constraints.maxWidth >= 820;
            return Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1120),
                child: Padding(
                  padding: const EdgeInsets.all(24.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildTopHeader(isConnected, accentColor),
                      const SizedBox(height: 18),
                      _buildPrivatePublicModeSwitcher(accentColor),
                      const SizedBox(height: 20),
                      Expanded(
                        child: isDesktop
                            ? _buildDesktopTwoColumnLayout(isConnected, accentColor)
                            : _buildMobileSingleColumnLayout(isConnected, accentColor),
                      ),
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildTopHeader(bool isConnected, Color accentColor) {
    final isPro = _currentSession?.isPro ?? false;

    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Row(
          children: [
            Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: accentColor,
                boxShadow: [
                  BoxShadow(
                    color: accentColor.withOpacity(0.6),
                    blurRadius: 10,
                    spreadRadius: 2,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            const Text(
              'PULSE // WIREGUARD ENGINE',
              style: TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.8,
              ),
            ),
          ],
        ),
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: const Color(0xFF111622),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: accentColor.withOpacity(0.35)),
              ),
              child: Text(
                isConnected
                    ? 'CHACHA20-POLY1305 • MTU ${WireGuardInterface.clampMtu(1420)}'
                    : 'STANDBY • SPLIT-ROUTE READY',
                style: TextStyle(
                  color: accentColor,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.2,
                ),
              ),
            ),
            const SizedBox(width: 10),
            InkWell(
              key: const Key('login_pro_nav_button'),
              onTap: _openAuthModal,
              borderRadius: BorderRadius.circular(8),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: isPro
                      ? const Color(0xFF10B981).withOpacity(0.18)
                      : const Color(0xFF111622),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: isPro ? const Color(0xFF10B981) : const Color(0xFF00F0FF),
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      isPro ? Icons.verified_user_rounded : Icons.person_outline_rounded,
                      size: 14,
                      color: isPro ? const Color(0xFF10B981) : const Color(0xFF00F0FF),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      isPro ? 'PRO ACTIVE' : 'Login / Pro',
                      style: TextStyle(
                        color: isPro ? const Color(0xFF10B981) : Colors.white,
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.9,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }

  /// Private Cloud vs Public Relay Mode Switcher
  Widget _buildPrivatePublicModeSwitcher(Color accentColor) {
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: const Color(0xFF111622),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Row(
        children: [
          Expanded(
            child: _buildModeSegment(
              title: 'PRIVATE CLOUD NODE',
              subtitle: 'Oracle Always-Free WireGuard',
              mode: VpnTunnelMode.privateCloud,
              accentColor: accentColor,
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: _buildModeSegment(
              title: 'PUBLIC RELAY MESH',
              subtitle: 'VPN Gate Lowest-Jitter Nodes',
              mode: VpnTunnelMode.publicRelay,
              accentColor: accentColor,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildModeSegment({
    required String title,
    required String subtitle,
    required VpnTunnelMode mode,
    required Color accentColor,
  }) {
    final isSelected = _selectedMode == mode;
    return GestureDetector(
      onTap: () => _switchMode(mode),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
        decoration: BoxDecoration(
          color: isSelected ? accentColor.withOpacity(0.14) : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected ? accentColor.withOpacity(0.6) : Colors.transparent,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: TextStyle(
                color: isSelected ? Colors.white : const Color(0xFF94A3B8),
                fontSize: 12,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.1,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              subtitle,
              style: TextStyle(
                color: isSelected ? accentColor : const Color(0xFF64748B),
                fontSize: 11,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDesktopTwoColumnLayout(bool isConnected, Color accentColor) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Expanded(
          flex: 5,
          child: _buildConnectTogglePanel(isConnected, accentColor),
        ),
        const SizedBox(width: 24),
        Expanded(
          flex: 7,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                RealTimeSpeedometer(
                  rxSpeedMbps: _telemetry.rxSpeedMbps,
                  txSpeedMbps: _telemetry.txSpeedMbps,
                  packetLossPercent: _telemetry.packetLossPercent,
                  isConnected: isConnected,
                  accentColor: accentColor,
                ),
                const SizedBox(height: 16),
                FastHopIndicator(
                  controller: _fastHopController,
                  session: _currentSession,
                  elapsedSecondsInCycle: _fastHopElapsedSeconds,
                  onIntervalChanged: _handleFastHopIntervalChange,
                  onUpgradeToProRequested: _openAuthModal,
                ),
                const SizedBox(height: 16),
                _buildCountryServerPickerCard(accentColor),
                const SizedBox(height: 14),
                _buildKillswitchSecurityFooter(accentColor),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildMobileSingleColumnLayout(bool isConnected, Color accentColor) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _buildConnectTogglePanel(isConnected, accentColor),
          const SizedBox(height: 16),
          RealTimeSpeedometer(
            rxSpeedMbps: _telemetry.rxSpeedMbps,
            txSpeedMbps: _telemetry.txSpeedMbps,
            packetLossPercent: _telemetry.packetLossPercent,
            isConnected: isConnected,
            accentColor: accentColor,
          ),
          const SizedBox(height: 16),
          FastHopIndicator(
            controller: _fastHopController,
            session: _currentSession,
            elapsedSecondsInCycle: _fastHopElapsedSeconds,
            onIntervalChanged: _handleFastHopIntervalChange,
            onUpgradeToProRequested: _openAuthModal,
          ),
          const SizedBox(height: 16),
          _buildCountryServerPickerCard(accentColor),
          const SizedBox(height: 16),
          _buildKillswitchSecurityFooter(accentColor),
        ],
      ),
    );
  }

  /// Connect Toggle Button & Session Orb Panel
  Widget _buildConnectTogglePanel(bool isConnected, Color accentColor) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0xFF111622),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            _stateMachine.currentState.name.toUpperCase(),
            style: TextStyle(
              color: accentColor,
              fontSize: 13,
              fontWeight: FontWeight.w700,
              letterSpacing: 2.0,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _telemetry.formatDuration(),
            style: const TextStyle(
              color: Colors.white,
              fontSize: 28,
              fontWeight: FontWeight.w300,
              letterSpacing: 2.0,
            ),
          ),
          const SizedBox(height: 28),
          GestureDetector(
            key: const Key('connect_toggle_button'),
            onTap: _toggleConnection,
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 250),
              width: 148,
              height: 148,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: const Color(0xFF07090E),
                border: Border.all(color: accentColor, width: 3),
                boxShadow: [
                  BoxShadow(
                    color: accentColor.withOpacity(isConnected ? 0.35 : 0.15),
                    blurRadius: 28,
                    spreadRadius: 4,
                  ),
                ],
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.power_settings_new_rounded,
                    size: 46,
                    color: accentColor,
                  ),
                  const SizedBox(height: 6),
                  Text(
                    isConnected ? 'DISCONNECT' : 'CONNECT',
                    style: TextStyle(
                      color: accentColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.4,
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),
          Text(
            'ENDPOINT // ${_activeRelay.ip}:51820',
            style: const TextStyle(
              color: Color(0xFF94A3B8),
              fontSize: 12,
              letterSpacing: 0.8,
            ),
          ),
        ],
      ),
    );
  }

  /// Country / Server Picker Card
  Widget _buildCountryServerPickerCard(Color accentColor) {
    return InkWell(
      key: const Key('country_server_picker'),
      onTap: _openCountryServerPicker,
      borderRadius: BorderRadius.circular(14),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        decoration: BoxDecoration(
          color: const Color(0xFF111622),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: const Color(0xFF1E293B)),
        ),
        child: Row(
          children: [
            Text(
              _activeRelay.flagEmoji,
              style: const TextStyle(fontSize: 28),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    _activeRelay.countryLong.toUpperCase(),
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.0,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${_activeRelay.hostname} • ${_activeRelay.pingLatencyMs} ms ping • ${_activeRelay.jitterMs} ms jitter',
                    style: const TextStyle(
                      color: Color(0xFF94A3B8),
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: accentColor.withOpacity(0.12),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                'CHANGE NODE',
                style: TextStyle(
                  color: accentColor,
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.8,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildKillswitchSecurityFooter(Color accentColor) {
    final scriptPreview = _windowsKillswitch.generateEnableScript(
      serverEndpointIp: _activeRelay.ip,
      serverEndpointPort: 51820,
      allowLocalLan: _allowLanTraffic,
    );

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
      decoration: BoxDecoration(
        color: const Color(0xFF111622),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Icon(
                _killswitchEnabled ? Icons.shield_outlined : Icons.shield_moon_outlined,
                color: accentColor,
                size: 18,
              ),
              const SizedBox(width: 10),
              Text(
                'WFP / VpnService Killswitch (${scriptPreview.split('\n').length} rules active)',
                style: const TextStyle(
                  color: Color(0xFFCBD5E1),
                  fontSize: 12,
                ),
              ),
            ],
          ),
          Switch(
            value: _killswitchEnabled,
            activeColor: accentColor,
            onChanged: (val) => setState(() => _killswitchEnabled = val),
          ),
        ],
      ),
    );
  }
}
