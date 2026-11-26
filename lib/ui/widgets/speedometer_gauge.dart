// Pulse VPN - Real-Time Speedometer & Bandwidth Telemetry Gauge
// lib/ui/widgets/speedometer_gauge.dart

import 'dart:math' as math;
import 'package:flutter/material.dart';

class RealTimeSpeedometer extends StatelessWidget {
  final double rxSpeedMbps;
  final double txSpeedMbps;
  final double packetLossPercent;
  final bool isConnected;
  final Color accentColor;

  const RealTimeSpeedometer({
    super.key,
    required this.rxSpeedMbps,
    required this.txSpeedMbps,
    required this.packetLossPercent,
    required this.isConnected,
    required this.accentColor,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF111622),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'REAL-TIME THROUGHPUT TELEMETRY',
                style: TextStyle(
                  color: Color(0xFF94A3B8),
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.5,
                ),
              ),
              Text(
                'LOSS: ${packetLossPercent.toStringAsFixed(2)}%',
                style: TextStyle(
                  color: accentColor,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          SizedBox(
            height: 130,
            child: CustomPaint(
              painter: SpeedometerArcPainter(
                normalizedValue: (rxSpeedMbps / 500.0).clamp(0.0, 1.0),
                accentColor: accentColor,
              ),
              child: Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      rxSpeedMbps.toStringAsFixed(1),
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 34,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    Text(
                      'DOWNLINK Mbps',
                      style: TextStyle(
                        color: accentColor,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.4,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: _buildMetricTile(
                  label: 'DOWNLOAD (RX)',
                  value: '${rxSpeedMbps.toStringAsFixed(1)} Mbps',
                  accentColor: accentColor,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildMetricTile(
                  label: 'UPLOAD (TX)',
                  value: '${txSpeedMbps.toStringAsFixed(1)} Mbps',
                  accentColor: const Color(0xFF38BDF8),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildMetricTile({
    required String label,
    required String value,
    required Color accentColor,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 14),
      decoration: BoxDecoration(
        color: const Color(0xFF07090E),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: const TextStyle(
              color: Color(0xFF64748B),
              fontSize: 10,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.1,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            style: TextStyle(
              color: accentColor,
              fontSize: 15,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class SpeedometerArcPainter extends CustomPainter {
  final double normalizedValue;
  final Color accentColor;

  SpeedometerArcPainter({
    required this.normalizedValue,
    required this.accentColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height * 0.78);
    final radius = math.min(size.width * 0.36, size.height * 0.72);

    final trackPaint = Paint()
      ..color = const Color(0xFF1E293B)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10
      ..strokeCap = StrokeCap.round;

    final activePaint = Paint()
      ..color = accentColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10
      ..strokeCap = StrokeCap.round;

    const startAngle = math.pi * 1.05;
    const sweepAngle = math.pi * 0.9;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepAngle,
      false,
      trackPaint,
    );

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepAngle * normalizedValue,
      false,
      activePaint,
    );
  }

  @override
  bool shouldRepaint(covariant SpeedometerArcPainter oldDelegate) {
    return oldDelegate.normalizedValue != normalizedValue ||
        oldDelegate.accentColor != accentColor;
  }
}
