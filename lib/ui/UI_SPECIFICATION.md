# Pulse VPN — Cyber-Minimalist Dashboard UI Specification

## 1. Design Language & Visual Identity
Aligned with Shivansh Dimri's systems-engineering portfolio aesthetic:
- **Primary Canvas (`obsidianBg`)**: `#07090E` (Deep Obsidian)
- **Glass Surface (`surfaceCard`)**: `#111622` with `1px solid #1E293B` border
- **Standby Accent (`cyberCyan`)**: `#00F0FF` (High-contrast telemetry cyan)
- **Connected Accent (`emeraldPulse`)**: `#10B981` (Verified tunnel lock emerald)
- **Typography**: Monospaced telemetry labels with wide tracking (`1.2px–2.0px`), high-contrast tabular numbers for live throughput counters and duration timers.

## 2. Core Interactive Components

### A. Connect Toggle Button (`lib/ui/home_screen.dart`)
- **Component Key**: `connect_toggle_button`
- **Behavior**: Drives `VpnStateMachine` transitions (`disconnected` -> `connecting` -> `connected` -> `disconnected`).
- **Visual Feedback**: 148x148px circular power orb with radial glow, active session duration clock (`HH:MM:SS`), and active encryption header (`CHACHA20-POLY1305 • MTU 1420`).

### B. Real-Time Speedometer (`lib/ui/widgets/speedometer_gauge.dart`)
- **Component**: `RealTimeSpeedometer` & `SpeedometerArcPainter`
- **Metrics Displayed**:
  - Live radial arc gauge normalized to link capacity
  - Downlink throughput (`RX Mbps`)
  - Uplink throughput (`TX Mbps`)
  - Real-time packet loss percentage (`LOSS %`)

### C. Country / Server Picker (`lib/ui/widgets/server_picker_modal.dart`)
- **Component Key**: `country_server_picker`
- **Features**:
  - Unicode country flag emoji rendering via `countryCodeToFlag(countryShort)`
  - Instant search filter by country name, ISO code, hostname, or IP
  - One-click sort toggle between **Lowest Jitter** (`sortRelaysByJitter`) and **Quality Score** (`sortRelaysByScore`)

### D. Private / Public Mode Switcher (`lib/ui/home_screen.dart`)
- **Modes**:
  1. `VpnTunnelMode.privateCloud`: Connects to self-hosted Oracle Cloud Always-Free WireGuard exit node (`server/setup-server.sh`).
  2. `VpnTunnelMode.publicRelay`: Connects to zero-configuration community relays discovered via the VPN Gate CSV parser (`parseVpnGateCsv`).

## 3. Responsive Breakpoints
- **Desktop (`width >= 820px`)**: Dual-column command center layout (5:7 split between Connect Orb panel and Telemetry + Server Picker stack).
- **Mobile (`width < 820px`)**: Single-column scrollable stack optimized for one-handed Android operation and Quick Settings tile (`PulseTileService`) handoff.
