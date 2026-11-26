// Pulse VPN - Country / Server Relay Picker Modal
// lib/ui/widgets/server_picker_modal.dart

import 'package:flutter/material.dart';
import '../../core/relay_discovery.dart';

class ServerPickerModal extends StatefulWidget {
  final List<RelayNode> relays;
  final RelayNode selectedRelay;
  final ValueChanged<RelayNode> onSelect;

  const ServerPickerModal({
    super.key,
    required this.relays,
    required this.selectedRelay,
    required this.onSelect,
  });

  @override
  State<ServerPickerModal> createState() => _ServerPickerModalState();
}

class _ServerPickerModalState extends State<ServerPickerModal> {
  String _searchQuery = '';
  bool _sortByLowestJitter = true;

  @override
  Widget build(BuildContext context) {
    final sorted = _sortByLowestJitter
        ? sortRelaysByJitter(widget.relays)
        : sortRelaysByScore(widget.relays);

    final filtered = sorted.where((node) {
      if (_searchQuery.isEmpty) return true;
      final q = _searchQuery.toLowerCase();
      return node.countryLong.toLowerCase().contains(q) ||
          node.countryShort.toLowerCase().contains(q) ||
          node.hostname.toLowerCase().contains(q) ||
          node.ip.contains(q);
    }).toList();

    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'SELECT EXIT NODE // RELAY DISCOVERY',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 13,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.4,
                ),
              ),
              TextButton(
                onPressed: () => setState(() => _sortByLowestJitter = !_sortByLowestJitter),
                child: Text(
                  _sortByLowestJitter ? 'SORT: LOWEST JITTER' : 'SORT: QUALITY SCORE',
                  style: const TextStyle(
                    color: Color(0xFF00F0FF),
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          TextField(
            onChanged: (value) => setState(() => _searchQuery = value),
            style: const TextStyle(color: Colors.white, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Filter by country, hostname, or IP...',
              hintStyle: const TextStyle(color: Color(0xFF64748B)),
              prefixIcon: const Icon(Icons.search, color: Color(0xFF64748B), size: 18),
              filled: true,
              fillColor: const Color(0xFF111622),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: Color(0xFF1E293B)),
              ),
            ),
          ),
          const SizedBox(height: 14),
          Flexible(
            child: ListView.separated(
              shrinkWrap: true,
              itemCount: filtered.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, index) {
                final node = filtered[index];
                final isSelected = node.ip == widget.selectedRelay.ip;
                return ListTile(
                  onTap: () => widget.onSelect(node),
                  tileColor: const Color(0xFF111622),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                    side: BorderSide(
                      color: isSelected ? const Color(0xFF00F0FF) : const Color(0xFF1E293B),
                    ),
                  ),
                  leading: Text(node.flagEmoji, style: const TextStyle(fontSize: 24)),
                  title: Text(
                    node.countryLong,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  subtitle: Text(
                    '${node.hostname} (${node.ip})',
                    style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
                  ),
                  trailing: Text(
                    '${node.pingLatencyMs} ms • ±${node.jitterMs} ms',
                    style: const TextStyle(
                      color: Color(0xFF10B981),
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
