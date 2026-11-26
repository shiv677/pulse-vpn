// Pulse VPN - Fast-Hop Multi-Relay Visualizer & Interval Selector
// lib/ui/widgets/fast_hop_indicator.dart

import 'package:flutter/material.dart';
import '../../core/auth_service.dart';
import '../../core/fast_hop.dart';
import '../../core/relay_discovery.dart';

class FastHopIndicator extends StatelessWidget {
  final FastHopController controller;
  final UserSession? session;
  final int elapsedSecondsInCycle;
  final ValueChanged<FastHopInterval> onIntervalChanged;
  final VoidCallback onUpgradeToProRequested;

  const FastHopIndicator({
    super.key,
    required this.controller,
    required this.session,
    required this.elapsedSecondsInCycle,
    required this.onIntervalChanged,
    required this.onUpgradeToProRequested,
  });

  static const Map<FastHopInterval, String> intervalLabels = {
    FastHopInterval.fiveSeconds: '5s (Extreme Privacy)',
    FastHopInterval.thirtySeconds: '30s',
    FastHopInterval.oneMinute: '1m',
    FastHopInterval.fiveMinutes: '5m',
    FastHopInterval.disabled: 'Off',
  };

  @override
  Widget build(BuildContext context) {
    final isPro = session?.isPro ?? false;
    final activeInterval = controller.interval;
    final activeRelay = controller.activePeer;
    final standbyRelay = controller.standbyPeer;

    final totalSeconds = activeInterval.seconds > 0 ? activeInterval.seconds : 5;
    final progress = activeInterval.isEnabled
        ? ((totalSeconds - elapsedSecondsInCycle) / totalSeconds).clamp(0.0, 1.0)
        : 0.0;

    return Container(
      key: const Key('fast_hop_indicator'),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF111622),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: activeInterval.isEnabled
              ? const Color(0xFF10B981).withOpacity(0.55)
              : const Color(0xFF1E293B),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  const Icon(
                    Icons.auto_mode_rounded,
                    color: Color(0xFF00F0FF),
                    size: 16,
                  ),
                  const SizedBox(width: 8),
                  const Text(
                    'FAST-HOP // MAKE-BEFORE-BREAK ROTATION',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.3,
                    ),
                  ),
                ],
              ),
              if (!isPro)
                GestureDetector(
                  key: const Key('upgrade_to_pro_pill'),
                  onTap: onUpgradeToProRequested,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF59E0B).withOpacity(0.16),
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(color: const Color(0xFFF59E0B)),
                    ),
                    child: const Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.lock_outline, color: Color(0xFFF59E0B), size: 12),
                        SizedBox(width: 4),
                        Text(
                          'Upgrade to Pro',
                          style: TextStyle(
                            color: Color(0xFFFBBF24),
                            fontSize: 10,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ],
                    ),
                  ),
                )
              else
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: const Color(0xFF10B981).withOpacity(0.16),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    'HOPS: ${controller.hopCount}',
                    style: const TextStyle(
                      color: Color(0xFF10B981),
                      fontSize: 10,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: FastHopInterval.values.map((interval) {
              final label = intervalLabels[interval] ?? interval.name;
              final isSelected = activeInterval == interval;
              final isLocked = !isPro && interval != FastHopInterval.disabled;

              return GestureDetector(
                onTap: () {
                  if (isLocked) {
                    onUpgradeToProRequested();
                  } else {
                    onIntervalChanged(interval);
                  }
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: isSelected
                        ? const Color(0xFF10B981).withOpacity(0.2)
                        : const Color(0xFF07090E),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: isSelected
                          ? const Color(0xFF10B981)
                          : const Color(0xFF1E293B),
                    ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (isLocked) ...[
                        const Icon(
                          Icons.lock_outline,
                          size: 11,
                          color: Color(0xFFF59E0B),
                        ),
                        const SizedBox(width: 4),
                      ],
                      Text(
                        label,
                        style: TextStyle(
                          color: isSelected
                              ? Colors.white
                              : const Color(0xFF94A3B8),
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              );
            }).toList(),
          ),
          const SizedBox(height: 14),
          _buildLiveRelayHopVisualizer(
            activeRelay: activeRelay,
            standbyRelay: standbyRelay,
            progress: progress,
            remainingSeconds: (totalSeconds - elapsedSecondsInCycle).clamp(0, totalSeconds),
            isPreWarmed: controller.isStandbyPreWarmed,
            isEnabled: activeInterval.isEnabled,
          ),
        ],
      ),
    );
  }

  Widget _buildLiveRelayHopVisualizer({
    required RelayNode? activeRelay,
    required RelayNode? standbyRelay,
    required double progress,
    required int remainingSeconds,
    required bool isPreWarmed,
    required bool isEnabled,
  }) {
    final activeFlag = activeRelay?.flagEmoji ?? '🇮🇳';
    final activeIp = activeRelay?.ip ?? '140.238.220.14';
    final activePing = activeRelay?.pingLatencyMs ?? 11;
    final standbyFlag = standbyRelay?.flagEmoji ?? '🇸🇬';
    final standbyCountry = standbyRelay?.countryShort ?? 'SG';

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF07090E),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Text(activeFlag, style: const TextStyle(fontSize: 18)),
                  const SizedBox(width: 8),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Active Relay',
                        style: TextStyle(
                          color: Color(0xFF64748B),
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Text(
                        '$activeIp • ${activePing}ms',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const Icon(
                Icons.swap_horiz_rounded,
                color: Color(0xFF00F0FF),
                size: 18,
              ),
              Row(
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      Text(
                        isPreWarmed
                            ? 'Standby Relay (Pre-warmed)'
                            : 'Standby Relay (Pre-warmed: ${isEnabled ? "T-2s" : "Off"})',
                        style: TextStyle(
                          color: isPreWarmed
                              ? const Color(0xFF10B981)
                              : const Color(0xFF64748B),
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Text(
                        isEnabled ? 'Next hop in ${remainingSeconds}s ($standbyCountry)' : 'Rotation Off',
                        style: const TextStyle(
                          color: Color(0xFFCBD5E1),
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(width: 8),
                  Text(standbyFlag, style: const TextStyle(fontSize: 18)),
                ],
              ),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: isEnabled ? progress : 0.0,
              minHeight: 5,
              backgroundColor: const Color(0xFF1E293B),
              valueColor: AlwaysStoppedAnimation<Color>(
                isPreWarmed ? const Color(0xFF10B981) : const Color(0xFF00F0FF),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
