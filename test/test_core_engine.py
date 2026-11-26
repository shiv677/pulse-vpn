#!/usr/bin/env python3
"""Pulse VPN - Core Engine Test Suite

Tests WireGuard INI parsing/generation, MTU clamping, IP routing calculations,
VPN Gate relay discovery parsing, killswitch rules, and telemetry state machine.
Zero external dependencies (uses standard library unittest).
"""

import ipaddress
import os
import re
import unittest

# ----------------------------------------------------------------------
# 1. WireGuard Config Parser / Generator Reference Implementation
# ----------------------------------------------------------------------

def clamp_mtu(value: int) -> int:
    if value <= 0 or value > 1420:
        return 1420
    return value


class WireGuardConfigEngine:
    @staticmethod
    def parse_ini(ini_text: str):
        interface = {}
        peers = []
        current_section = None
        current_peer = {}

        for raw_line in ini_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip().lower()
                if current_section == "peer":
                    current_peer = {}
                    peers.append(current_peer)
                continue

            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip().lower()
                val = val.strip()

                if current_section == "interface":
                    interface[key] = val
                elif current_section == "peer":
                    current_peer[key] = val

        mtu_raw = int(interface.get("mtu", 1420))
        interface["mtu"] = clamp_mtu(mtu_raw)
        return {"interface": interface, "peers": peers}

    @staticmethod
    def to_ini(config: dict) -> str:
        lines = ["[Interface]"]
        iface = config.get("interface", {})
        for key in ["privatekey", "address", "dns", "listenport", "mtu"]:
            if key in iface and iface[key] is not None and iface[key] != "":
                cap_key = {
                    "privatekey": "PrivateKey",
                    "address": "Address",
                    "dns": "DNS",
                    "listenport": "ListenPort",
                    "mtu": "MTU",
                }.get(key, key)
                lines.append(f"{cap_key} = {iface[key]}")

        for peer in config.get("peers", []):
            lines.append("\n[Peer]")
            for key in ["publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"]:
                if key in peer and peer[key] is not None and peer[key] != "":
                    cap_key = {
                        "publickey": "PublicKey",
                        "presharedkey": "PresharedKey",
                        "endpoint": "Endpoint",
                        "allowedips": "AllowedIPs",
                        "persistentkeepalive": "PersistentKeepalive",
                    }.get(key, key)
                    lines.append(f"{cap_key} = {peer[key]}")

        return "\n".join(lines)


# ----------------------------------------------------------------------
# 2. IP Routing Calculations
# ----------------------------------------------------------------------

def split_default_route():
    """Split 0.0.0.0/0 into two /1 subnets (0.0.0.0/1 and 128.0.0.0/1).
    This overrides the default gateway without deleting or clobbering it.
    """
    return ["0.0.0.0/1", "128.0.0.0/1"]


def is_ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    net = ipaddress.ip_network(subnet_str, strict=False)
    return ip in net


def calculate_excluded_lan_routes():
    """Private RFC 1918 + loopback + link-local subnets to bypass when LAN access enabled."""
    return [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    ]


# ----------------------------------------------------------------------
# 3. Relay Discovery & Latency Engine
# ----------------------------------------------------------------------

def country_code_to_flag(code: str) -> str:
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    code = code.upper()
    first = ord(code[0]) - ord("A") + 0x1F1E6
    second = ord(code[1]) - ord("A") + 0x1F1E6
    return chr(first) + chr(second)


def calculate_relay_score(latency_ms: int, jitter_ms: int, speed_bps: int) -> int:
    speed_mbps = speed_bps / 1_000_000.0
    penalty = (latency_ms * 2.0) + (jitter_ms * 3.5)
    score = int((speed_mbps * 50.0) - penalty)
    return max(score, 1)


def parse_vpngate_csv(csv_content: str):
    relays = []
    for line in csv_content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("*") or trimmed.startswith("#"):
            continue
        cols = trimmed.split(",")
        if len(cols) < 15:
            continue
        hostname = cols[0].strip()
        ip = cols[1].strip()
        score = int(cols[2].strip()) if cols[2].strip().isdigit() else 0
        ping = int(cols[3].strip()) if cols[3].strip().isdigit() else 999
        speed = int(cols[4].strip()) if cols[4].strip().isdigit() else 0
        country_long = cols[5].strip()
        country_short = cols[6].strip()
        config_b64 = cols[14].strip()

        jitter = max(1, min(100, int(ping * 0.12)))
        calculated_score = score if score > 0 else calculate_relay_score(ping, jitter, speed)

        relays.append({
            "hostname": hostname,
            "ip": ip,
            "score": calculated_score,
            "ping": ping,
            "jitter": jitter,
            "speed": speed,
            "country_long": country_long,
            "country_short": country_short,
            "flag": country_code_to_flag(country_short),
            "config_b64": config_b64,
        })
    return relays


def sort_relays_by_jitter(relays: list):
    return sorted(relays, key=lambda r: (r["jitter"], r["ping"]))


# ----------------------------------------------------------------------
# 4. Killswitch Engine
# ----------------------------------------------------------------------

class WindowsKillswitchGenerator:
    def __init__(self, prefix="PulseVPN_Killswitch"):
        self.prefix = prefix

    def generate_enable_script(self, server_ip: str, server_port: int, interface_alias="PulseVPN", allow_lan=True):
        lines = [
            'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound',
            f'New-NetFirewallRule -DisplayName "{self.prefix}_Allow_Loopback" -Direction Outbound -Action Allow -RemoteAddress "127.0.0.1/8","::1" -Profile Any',
            f'New-NetFirewallRule -DisplayName "{self.prefix}_Allow_Tunnel" -Direction Outbound -Action Allow -InterfaceAlias "{interface_alias}" -Profile Any',
            f'New-NetFirewallRule -DisplayName "{self.prefix}_Allow_Handshake" -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress "{server_ip}" -RemotePort {server_port} -Profile Any',
        ]
        if allow_lan:
            lines.append(
                f'New-NetFirewallRule -DisplayName "{self.prefix}_Allow_LAN" -Direction Outbound -Action Allow -RemoteAddress "192.168.0.0/16","10.0.0.0/8","172.16.0.0/12","169.254.0.0/16" -Profile Any'
            )
        lines.append(
            f'New-NetFirewallRule -DisplayName "{self.prefix}_Allow_DHCP" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any'
        )
        return "\n".join(lines)

    def generate_disable_script(self):
        return "\n".join([
            f'Get-NetFirewallRule -DisplayName "{self.prefix}_*" | Remove-NetFirewallRule',
            'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound',
        ])


class AndroidVpnBlockingValidator:
    @staticmethod
    def validate(allowed_apps: list, disallowed_apps: list) -> bool:
        if allowed_apps and disallowed_apps:
            return False
        return True


# ----------------------------------------------------------------------
# 5. Telemetry & State Machine
# ----------------------------------------------------------------------

ALLOWED_TRANSITIONS = {
    "disconnected": {"connecting"},
    "connecting": {"connected", "error", "disconnected"},
    "connected": {"reconnecting", "disconnected"},
    "reconnecting": {"connected", "error", "disconnected"},
    "error": {"connecting", "disconnected"},
}


class VpnStateMachineTestable:
    def __init__(self):
        self.state = "disconnected"
        self.last_error = None

    def transition(self, target_state: str, error_msg: str = None) -> bool:
        valid_targets = ALLOWED_TRANSITIONS.get(self.state, set())
        if target_state not in valid_targets:
            return False
        self.state = target_state
        if target_state == "error":
            self.last_error = error_msg or "Unknown error"
        elif target_state == "connected":
            self.last_error = None
        return True


class BandwidthTelemetryCalculator:
    @staticmethod
    def calculate_speed_mbps(delta_bytes: int, delta_seconds: float) -> float:
        if delta_seconds <= 0:
            return 0.0
        return (delta_bytes * 8.0) / (delta_seconds * 1_000_000.0)

    @staticmethod
    def calculate_packet_loss(packets_sent: int, packets_lost: int) -> float:
        if packets_sent <= 0:
            return 0.0
        return min(100.0, max(0.0, (packets_lost / packets_sent) * 100.0))

    @staticmethod
    def format_duration(seconds: int) -> str:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


# ======================================================================
# Unit Tests
# ======================================================================

class TestPulseVpnCoreEngine(unittest.TestCase):

    # 1. WireGuard Config Parser & MTU Clamping
    def test_wireguard_ini_parsing(self):
        ini_content = """
        # Pulse VPN WireGuard Configuration Sample
        [Interface]
        PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
        Address = 10.0.0.2/32, fd00::2/128
        DNS = 1.1.1.1, 1.0.0.1
        MTU = 1500

        [Peer]
        PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
        PresharedKey = ccccccccccccccccccccccccccccccccccccccccccc=
        Endpoint = 198.51.100.1:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """
        cfg = WireGuardConfigEngine.parse_ini(ini_content)
        self.assertEqual(cfg["interface"]["privatekey"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")
        self.assertEqual(cfg["interface"]["address"], "10.0.0.2/32, fd00::2/128")
        self.assertEqual(cfg["interface"]["dns"], "1.1.1.1, 1.0.0.1")
        # MTU must be clamped from 1500 to 1420
        self.assertEqual(cfg["interface"]["mtu"], 1420)

        self.assertEqual(len(cfg["peers"]), 1)
        peer = cfg["peers"][0]
        self.assertEqual(peer["publickey"], "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=")
        self.assertEqual(peer["endpoint"], "198.51.100.1:51820")
        self.assertEqual(peer["persistentkeepalive"], "25")

    def test_mtu_clamping_rules(self):
        self.assertEqual(clamp_mtu(1500), 1420)
        self.assertEqual(clamp_mtu(9000), 1420)
        self.assertEqual(clamp_mtu(0), 1420)
        self.assertEqual(clamp_mtu(-10), 1420)
        self.assertEqual(clamp_mtu(1420), 1420)
        self.assertEqual(clamp_mtu(1360), 1360)
        self.assertEqual(clamp_mtu(1280), 1280)

    def test_wireguard_ini_generator(self):
        config_data = {
            "interface": {
                "privatekey": "privkey123=",
                "address": "10.8.0.2/24",
                "dns": "1.1.1.1",
                "listenport": "51820",
                "mtu": 1420,
            },
            "peers": [
                {
                    "publickey": "pubkey456=",
                    "endpoint": "203.0.113.5:51820",
                    "allowedips": "0.0.0.0/0",
                    "persistentkeepalive": 25,
                }
            ],
        }
        ini_out = WireGuardConfigEngine.to_ini(config_data)
        self.assertIn("[Interface]", ini_out)
        self.assertIn("PrivateKey = privkey123=", ini_out)
        self.assertIn("MTU = 1420", ini_out)
        self.assertIn("[Peer]", ini_out)
        self.assertIn("PublicKey = pubkey456=", ini_out)
        self.assertIn("Endpoint = 203.0.113.5:51820", ini_out)

    # 2. IP Routing Calculations
    def test_default_route_splitting(self):
        routes = split_default_route()
        self.assertEqual(routes, ["0.0.0.0/1", "128.0.0.0/1"])

        # Check coverage of all IPv4
        ip1 = ipaddress.ip_address("1.2.3.4")
        ip2 = ipaddress.ip_address("200.50.25.1")
        net1 = ipaddress.ip_network(routes[0])
        net2 = ipaddress.ip_network(routes[1])
        self.assertTrue(ip1 in net1 or ip1 in net2)
        self.assertTrue(ip2 in net1 or ip2 in net2)

    def test_subnet_containment_and_lan_bypass(self):
        lan_subnets = calculate_excluded_lan_routes()
        self.assertTrue(any(is_ip_in_subnet("192.168.1.105", net) for net in lan_subnets))
        self.assertTrue(any(is_ip_in_subnet("10.0.0.15", net) for net in lan_subnets))
        self.assertTrue(any(is_ip_in_subnet("172.20.5.1", net) for net in lan_subnets))
        self.assertTrue(any(is_ip_in_subnet("127.0.0.1", net) for net in lan_subnets))
        # Public IP must not be in LAN subnets
        self.assertFalse(any(is_ip_in_subnet("8.8.8.8", net) for net in lan_subnets))
        self.assertFalse(any(is_ip_in_subnet("1.1.1.1", net) for net in lan_subnets))

    # 3. Relay Discovery & Parsing
    def test_country_code_to_flag(self):
        self.assertEqual(country_code_to_flag("US"), "🇺🇸")
        self.assertEqual(country_code_to_flag("JP"), "🇯🇵")
        self.assertEqual(country_code_to_flag("DE"), "🇩🇪")
        self.assertEqual(country_code_to_flag("GB"), "🇬🇧")
        self.assertEqual(country_code_to_flag("SG"), "🇸🇬")
        self.assertEqual(country_code_to_flag("XX"), "🇽🇽")
        self.assertEqual(country_code_to_flag(""), "🌐")
        self.assertEqual(country_code_to_flag("INVALID"), "🌐")

    def test_vpngate_csv_parser_and_jitter_sort(self):
        csv_sample = """#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
vg-tokyo.opengw.net,192.0.2.1,50000,15,85000000,Japan,JP,10,12345,100,5000,2,Admin,Msg,Y29uZmlnMQ==
vg-frankfurt.opengw.net,198.51.100.2,40000,45,45000000,Germany,DE,5,67890,50,2500,2,Admin,Msg,Y29uZmlnMg==
vg-uswest.opengw.net,203.0.113.3,30000,8,120000000,United States,US,20,54321,200,9000,2,Admin,Msg,Y29uZmlnMw==
"""
        relays = parse_vpngate_csv(csv_sample)
        self.assertEqual(len(relays), 3)

        us_relay = next(r for r in relays if r["country_short"] == "US")
        self.assertEqual(us_relay["flag"], "🇺🇸")
        self.assertEqual(us_relay["ping"], 8)

        # Sort by jitter/ping
        sorted_relays = sort_relays_by_jitter(relays)
        self.assertEqual(sorted_relays[0]["country_short"], "US")
        self.assertEqual(sorted_relays[1]["country_short"], "JP")
        self.assertEqual(sorted_relays[2]["country_short"], "DE")

    # 4. Killswitch Rules Engine
    def test_windows_wfp_firewall_rule_generation(self):
        engine = WindowsKillswitchGenerator("PulseVPN_Killswitch")
        enable_script = engine.generate_enable_script("198.51.100.5", 51820)
        self.assertIn("blockinbound,blockoutbound", enable_script)
        self.assertIn("PulseVPN_Killswitch_Allow_Loopback", enable_script)
        self.assertIn("PulseVPN_Killswitch_Allow_Tunnel", enable_script)
        self.assertIn("PulseVPN_Killswitch_Allow_Handshake", enable_script)
        self.assertIn("-RemoteAddress \"198.51.100.5\"", enable_script)
        self.assertIn("-RemotePort 51820", enable_script)
        self.assertIn("PulseVPN_Killswitch_Allow_LAN", enable_script)

        disable_script = engine.generate_disable_script()
        self.assertIn("Remove-NetFirewallRule", disable_script)
        self.assertIn("blockinbound,allowoutbound", disable_script)

    def test_android_vpn_split_tunneling_validation(self):
        # Disallow both allowed and disallowed at the same time
        self.assertTrue(AndroidVpnBlockingValidator.validate(["com.example.app"], []))
        self.assertTrue(AndroidVpnBlockingValidator.validate([], ["com.bad.app"]))
        self.assertTrue(AndroidVpnBlockingValidator.validate([], []))
        self.assertFalse(AndroidVpnBlockingValidator.validate(["com.app1"], ["com.app2"]))

    # 5. Telemetry & State Machine Transitions
    def test_state_machine_valid_transitions(self):
        sm = VpnStateMachineTestable()
        self.assertEqual(sm.state, "disconnected")

        # disconnected -> connecting
        self.assertTrue(sm.transition("connecting"))
        self.assertEqual(sm.state, "connecting")

        # connecting -> connected
        self.assertTrue(sm.transition("connected"))
        self.assertEqual(sm.state, "connected")

        # connected -> reconnecting
        self.assertTrue(sm.transition("reconnecting"))
        self.assertEqual(sm.state, "reconnecting")

        # reconnecting -> error
        self.assertTrue(sm.transition("error", "Handshake timeout"))
        self.assertEqual(sm.state, "error")
        self.assertEqual(sm.last_error, "Handshake timeout")

        # error -> connecting
        self.assertTrue(sm.transition("connecting"))
        self.assertEqual(sm.state, "connecting")

        # connecting -> disconnected
        self.assertTrue(sm.transition("disconnected"))
        self.assertEqual(sm.state, "disconnected")

    def test_state_machine_invalid_transitions(self):
        sm = VpnStateMachineTestable()
        # Cannot jump from disconnected to connected directly
        self.assertFalse(sm.transition("connected"))
        self.assertEqual(sm.state, "disconnected")

        # Cannot jump from disconnected to reconnecting
        self.assertFalse(sm.transition("reconnecting"))
        self.assertEqual(sm.state, "disconnected")

    def test_telemetry_calculations(self):
        # 12.5 MB in 1 second = 100 Mbps
        speed = BandwidthTelemetryCalculator.calculate_speed_mbps(12_500_000, 1.0)
        self.assertAlmostEqual(speed, 100.0, places=1)

        # Packet loss: 5 out of 100 = 5.0%
        loss = BandwidthTelemetryCalculator.calculate_packet_loss(100, 5)
        self.assertEqual(loss, 5.0)

        # Duration format: 3665s = 01:01:05
        formatted = BandwidthTelemetryCalculator.format_duration(3665)
        self.assertEqual(formatted, "01:01:05")

    # 6. Verify Dart Source Files Presence and Signatures
    def test_dart_source_files_exist_and_valid(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        lib_core = os.path.join(base_dir, "lib", "core")

        dart_files = [
            "wireguard_config.dart",
            "relay_discovery.dart",
            "killswitch.dart",
            "telemetry.dart",
        ]

        for fname in dart_files:
            fpath = os.path.join(lib_core, fname)
            self.assertTrue(os.path.exists(fpath), f"Missing Dart file: {fname}")
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertGreater(len(content), 100, f"{fname} is unexpectedly small")

        # Verify wireguard_config.dart has clampMtu & parse
        with open(os.path.join(lib_core, "wireguard_config.dart"), "r", encoding="utf-8") as f:
            c = f.read()
            self.assertIn("class WireGuardConfig", c)
            self.assertIn("clampMtu", c)
            self.assertIn("1420", c)

        # Verify relay_discovery.dart has countryCodeToFlag
        with open(os.path.join(lib_core, "relay_discovery.dart"), "r", encoding="utf-8") as f:
            c = f.read()
            self.assertIn("countryCodeToFlag", c)
            self.assertIn("parseVpnGateCsv", c)
            self.assertIn("sortRelaysByJitter", c)

        # Verify killswitch.dart has Windows and Android engines
        with open(os.path.join(lib_core, "killswitch.dart"), "r", encoding="utf-8") as f:
            c = f.read()
            self.assertIn("WindowsKillswitchEngine", c)
            self.assertIn("AndroidVpnBlockingState", c)
            self.assertIn("blockinbound,blockoutbound", c)

        # Verify telemetry.dart has VpnConnectionState & VpnStateMachine
        with open(os.path.join(lib_core, "telemetry.dart"), "r", encoding="utf-8") as f:
            c = f.read()
            self.assertIn("enum VpnConnectionState", c)
            self.assertIn("class VpnStateMachine", c)
            self.assertIn("class BandwidthTelemetry", c)


if __name__ == "__main__":
    unittest.main(verbosity=2)
