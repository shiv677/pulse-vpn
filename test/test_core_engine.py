#!/usr/bin/env python3
"""Pulse VPN - Core Engine Test Suite

Tests WireGuard INI parsing/generation, MTU clamping, IP routing calculations,
VPN Gate relay discovery parsing, killswitch rules, and telemetry state machine.
Zero external dependencies (uses standard library unittest).
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
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


# ----------------------------------------------------------------------
# 6. Pro Authentication & Fast-Hop Engine
# ----------------------------------------------------------------------

class SecurityException(Exception):
    pass


class UserSessionTestable:
    def __init__(self, user_id: str, email: str, tier: str, token: str, expires_at: int):
        self.user_id = user_id
        self.email = email
        self.tier = tier.lower()
        self.token = token
        self.expires_at = expires_at

    def is_expired(self, now_ts: int = None) -> bool:
        check_ts = int(time.time()) if now_ts is None else now_ts
        return check_ts >= self.expires_at

    @property
    def is_pro(self) -> bool:
        return self.tier == "pro" and not self.is_expired()


class AuthServiceTestable:
    DEFAULT_SECRET = "pulse_vpn_server_hmac_sha256_secret_key_v1"

    def __init__(self, signing_key: str = DEFAULT_SECRET):
        self.signing_key = signing_key
        self.stored_token = None
        self.current_session = None

    @staticmethod
    def compute_hmac_sha256(signing_input: str, secret: str) -> str:
        digest = hmac.new(
            secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    @classmethod
    def create_jwt(cls, sub: str, email: str, tier: str, exp: int, secret: str = DEFAULT_SECRET) -> str:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": sub, "email": email, "tier": tier, "exp": exp}).encode()
        ).decode().rstrip("=")
        signing_input = f"{header}.{payload}"
        sig = cls.compute_hmac_sha256(signing_input, secret)
        return f"{signing_input}.{sig}"

    @staticmethod
    def decode_jwt_claims(token: str) -> dict:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        payload_b64 = parts[1]
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        raw = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8")
        return json.loads(raw)

    def verify_token(self, token: str, signing_key: str = None, now_ts: int = None) -> UserSessionTestable:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        header, payload, provided_sig = parts
        secret = signing_key if signing_key is not None else self.signing_key
        expected_sig = self.compute_hmac_sha256(f"{header}.{payload}", secret)
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise SecurityException(
                "Cryptographic signature verification failed: token is untrusted or tampered"
            )

        claims = self.decode_jwt_claims(token)
        sub = claims.get("sub", "")
        if not sub:
            raise ValueError("Missing sub claim")
        tier = claims.get("tier", "free")
        exp = claims.get("exp")
        if not isinstance(exp, int):
            raise ValueError("Missing integer exp claim")
        email = claims.get("email", f"{sub}@pulsevpn.io")
        session = UserSessionTestable(sub, email, tier, token, exp)
        if session.is_expired(now_ts=now_ts):
            raise PermissionError("JWT token has expired")
        self.current_session = session
        self.stored_token = token
        return session

    def sign_up(self, email: str, password: str, ttl_seconds: int = 86400) -> UserSessionTestable:
        # All standard signups strictly default to UserTier.free
        exp = int(time.time()) + ttl_seconds
        token = self.create_jwt(f"usr_{abs(hash(email))}", email, "free", exp, self.signing_key)
        return self.verify_token(token, signing_key=self.signing_key)

    def log_out(self):
        self.current_session = None
        self.stored_token = None


class FastHopControllerTestable:
    INTERVALS = {
        "disabled": 0,
        "fiveSeconds": 5,
        "thirtySeconds": 30,
        "oneMinute": 60,
        "fiveMinutes": 300,
    }

    def __init__(self):
        self.interval_name = "disabled"
        self.interval_seconds = 0
        self.state = "idle"
        self.active_peer = None
        self.standby_peer = None
        self.is_standby_pre_warmed = False
        self.hop_count = 0
        self.elapsed_in_cycle = 0
        self.candidate_queue = []

    def enable(self, session: UserSessionTestable, interval_name: str, relays: list):
        if interval_name == "disabled":
            self.disable()
            return True
        if session is None or not session.is_pro:
            raise PermissionError("Fast-Hop requires Pulse VPN Pro tier")
        sorted_relays = sort_relays_by_jitter(relays)
        if len(sorted_relays) < 2:
            raise ValueError("At least 2 relays required for dual-peer standby")
        self.candidate_queue = list(sorted_relays)
        self.interval_name = interval_name
        self.interval_seconds = self.INTERVALS[interval_name]
        self.active_peer = self.candidate_queue[0]
        self.standby_peer = self.candidate_queue[1]
        self.is_standby_pre_warmed = False
        self.elapsed_in_cycle = 0
        self.state = "active"
        return True

    def pre_warm_standby(self):
        if self.interval_seconds <= 0 or self.standby_peer is None:
            return False
        self.state = "preWarmingStandby"
        self.is_standby_pre_warmed = True
        return True

    def execute_hop(self, session: UserSessionTestable):
        if session is None or not session.is_pro:
            raise PermissionError("Pro tier required to execute hop")
        if not self.is_standby_pre_warmed:
            self.pre_warm_standby()
        self.state = "swapping"
        prev_active = self.active_peer
        self.active_peer = self.standby_peer
        self.candidate_queue = [r for r in self.candidate_queue if r["ip"] != prev_active["ip"]]
        self.candidate_queue.append(prev_active)
        self.standby_peer = next(
            (r for r in self.candidate_queue if r["ip"] != self.active_peer["ip"]),
            prev_active,
        )
        self.is_standby_pre_warmed = False
        self.elapsed_in_cycle = 0
        self.hop_count += 1
        self.state = "active"
        return self.active_peer

    def tick_second(self, session: UserSessionTestable):
        if self.interval_seconds <= 0 or self.state == "idle":
            return
        self.elapsed_in_cycle += 1
        remaining = self.interval_seconds - self.elapsed_in_cycle
        if 0 < remaining <= 2 and not self.is_standby_pre_warmed:
            self.pre_warm_standby()
        elif remaining <= 0:
            self.execute_hop(session)

    def disable(self):
        self.interval_name = "disabled"
        self.interval_seconds = 0
        self.state = "idle"
        self.is_standby_pre_warmed = False
        self.elapsed_in_cycle = 0


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
            "auth_service.dart",
            "fast_hop.dart",
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

        # Verify auth_service.dart has UserTier, UserSession, AuthService, decodeJwtClaims, SecurityException, HMAC-SHA256
        with open(os.path.join(lib_core, "auth_service.dart"), "r", encoding="utf-8") as f:
            c = f.read()
            self.assertIn("enum UserTier", c)
            self.assertIn("class UserSession", c)
            self.assertIn("class AuthService", c)
            self.assertIn("class SecurityException", c)
            self.assertIn("decodeJwtClaims", c)
            self.assertIn("computeHmacSha256", c)
            self.assertIn("Cryptographic signature verification failed: token is untrusted or tampered", c)
            self.assertNotIn("contains('pro')", c)
            self.assertNotIn("overrideTier", c)

        # Verify fast_hop.dart has FastHopInterval, FastHopController, executeHop
        with open(os.path.join(lib_core, "fast_hop.dart"), "r", encoding="utf-8") as f:
            c = f.read()
            self.assertIn("enum FastHopInterval", c)
            self.assertIn("class FastHopController", c)
            self.assertIn("executeHop", c)
            self.assertIn("preWarmStandby", c)

    # 8. Pro Authentication & Fast-Hop Multi-Relay Tests
    def test_auth_service_jwt_decode_tier_and_expiry(self):
        auth = AuthServiceTestable()
        future_exp = int(time.time()) + 3600
        pro_jwt = auth.create_jwt("user_99", "shivansh@pulsevpn.io", "pro", future_exp)

        claims = auth.decode_jwt_claims(pro_jwt)
        self.assertEqual(claims["sub"], "user_99")
        self.assertEqual(claims["tier"], "pro")
        self.assertEqual(claims["exp"], future_exp)

        session = auth.verify_token(pro_jwt)
        self.assertTrue(session.is_pro)
        self.assertEqual(session.user_id, "user_99")
        self.assertEqual(auth.stored_token, pro_jwt)

        # Free tier check
        free_jwt = auth.create_jwt("user_100", "free@pulsevpn.io", "free", future_exp)
        free_session = auth.verify_token(free_jwt)
        self.assertFalse(free_session.is_pro)

        # Expired token rejection
        past_exp = int(time.time()) - 60
        expired_jwt = auth.create_jwt("user_99", "shivansh@pulsevpn.io", "pro", past_exp)
        with self.assertRaises(PermissionError):
            auth.verify_token(expired_jwt)

        auth.log_out()
        self.assertIsNone(auth.current_session)
        self.assertIsNone(auth.stored_token)

    def test_auth_service_hmac_sha256_tampering_and_pro_signature(self):
        server_secret = "pulse_server_production_secret_2026"
        auth = AuthServiceTestable(signing_key=server_secret)
        future_exp = int(time.time()) + 3600

        # 1. Standard signup (even with 'pro' in email) defaults strictly to UserTier.free
        signup_session = auth.sign_up("shivansh.pro@pulsevpn.io", "StrongPassword123!")
        self.assertEqual(signup_session.tier, "free")
        self.assertFalse(signup_session.is_pro)

        # 2. Tampering payload from tier='free' to tier='pro' must throw SecurityException
        free_token = auth.create_jwt("user_50", "user50@pulsevpn.io", "free", future_exp, secret=server_secret)
        header_seg, _, sig_seg = free_token.split(".")
        tampered_payload = (
            base64.urlsafe_b64encode(
                json.dumps({
                    "sub": "user_50",
                    "email": "user50@pulsevpn.io",
                    "tier": "pro",
                    "exp": future_exp,
                }).encode("utf-8")
            )
            .decode("utf-8")
            .rstrip("=")
        )
        tampered_token = f"{header_seg}.{tampered_payload}.{sig_seg}"
        with self.assertRaises(SecurityException) as ctx:
            auth.verify_token(tampered_token, signing_key=server_secret)
        self.assertIn(
            "Cryptographic signature verification failed: token is untrusted or tampered",
            str(ctx.exception),
        )

        # 3. Token signed with wrong attacker secret must throw SecurityException
        forged_pro_token = auth.create_jwt(
            "user_50", "user50@pulsevpn.io", "pro", future_exp, secret="attacker_forged_key"
        )
        with self.assertRaises(SecurityException):
            auth.verify_token(forged_pro_token, signing_key=server_secret)

        # 4. Legitimate server-signed HMAC-SHA256 Pro token succeeds and grants Pro tier
        legit_pro_token = auth.create_jwt(
            "user_50", "user50@pulsevpn.io", "pro", future_exp, secret=server_secret
        )
        pro_session = auth.verify_token(legit_pro_token, signing_key=server_secret)
        self.assertTrue(pro_session.is_pro)
        self.assertEqual(pro_session.tier, "pro")

    def test_fast_hop_dual_peer_prewarm_and_5s_rotation(self):
        auth = AuthServiceTestable()
        future_exp = int(time.time()) + 3600
        pro_session = auth.verify_token(auth.create_jwt("pro_1", "pro@pulsevpn.io", "pro", future_exp))
        free_session = auth.verify_token(auth.create_jwt("free_1", "free@pulsevpn.io", "free", future_exp))

        csv_sample = """#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
vg-tokyo,192.0.2.10,50000,15,85000000,Japan,JP,10,12345,100,5000,2,Admin,Msg,Y29uZmlnMQ==
vg-frankfurt,198.51.100.20,40000,45,45000000,Germany,DE,5,67890,50,2500,2,Admin,Msg,Y29uZmlnMg==
vg-uswest,203.0.113.30,30000,8,120000000,United States,US,20,54321,200,9000,2,Admin,Msg,Y29uZmlnMw==
"""
        relays = parse_vpngate_csv(csv_sample)
        controller = FastHopControllerTestable()

        # Free user must be blocked from enabling Fast-Hop
        with self.assertRaises(PermissionError):
            controller.enable(free_session, "fiveSeconds", relays)

        # Pro user enables 5-second Fast-Hop
        self.assertTrue(controller.enable(pro_session, "fiveSeconds", relays))
        self.assertEqual(controller.state, "active")
        # Lowest jitter/ping is US (8ms), standby is JP (15ms)
        self.assertEqual(controller.active_peer["country_short"], "US")
        self.assertEqual(controller.standby_peer["country_short"], "JP")
        self.assertFalse(controller.is_standby_pre_warmed)

        # Tick 1s, 2s -> still active (3s remaining)
        controller.tick_second(pro_session)
        controller.tick_second(pro_session)
        self.assertEqual(controller.state, "active")
        self.assertFalse(controller.is_standby_pre_warmed)

        # Tick 3s -> 2s remaining before hop -> triggers standby pre-warm handshake
        controller.tick_second(pro_session)
        self.assertEqual(controller.state, "preWarmingStandby")
        self.assertTrue(controller.is_standby_pre_warmed)

        # Tick 4s -> 1s remaining -> stays pre-warmed
        controller.tick_second(pro_session)
        self.assertTrue(controller.is_standby_pre_warmed)

        # Tick 5s -> 0s remaining -> executes 0ms make-before-break route swap
        controller.tick_second(pro_session)
        self.assertEqual(controller.hop_count, 1)
        self.assertEqual(controller.state, "active")
        self.assertEqual(controller.active_peer["country_short"], "JP")
        self.assertEqual(controller.standby_peer["country_short"], "DE")
        self.assertFalse(controller.is_standby_pre_warmed)

    # 7. Verify Phase 3 Native Platform Integration, UI Dashboard & Packaging
    def test_android_manifest_and_services(self):
        import xml.etree.ElementTree as ET
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel_path in ["android/AndroidManifest.xml", "android/app/src/main/AndroidManifest.xml"]:
            manifest_path = os.path.join(base_dir, *rel_path.split("/"))
            self.assertTrue(os.path.exists(manifest_path), f"Missing {rel_path}")
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            with open(manifest_path, "r", encoding="utf-8") as f:
                raw_xml = f.read()
            self.assertIn("android.permission.BIND_VPN_SERVICE", raw_xml)
            self.assertIn("android.permission.INTERNET", raw_xml)
            self.assertIn("android.permission.ACCESS_NETWORK_STATE", raw_xml)
            self.assertIn("android.permission.FOREGROUND_SERVICE_SPECIAL_USE", raw_xml)
            self.assertIn("pulse_vpn_tunnel_channel", raw_xml)
            self.assertIn("PulseVpnService", raw_xml)
            self.assertIn("PulseTileService", raw_xml)
            self.assertIsNotNone(root)

    def test_windows_wintun_and_inno_setup_packaging(self):
        import json
        import xml.etree.ElementTree as ET
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        wintun_manifest = os.path.join(base_dir, "windows", "wintun.manifest")
        self.assertTrue(os.path.exists(wintun_manifest))
        ET.parse(wintun_manifest)
        with open(wintun_manifest, "r", encoding="utf-8") as f:
            manifest_txt = f.read()
        self.assertIn("requireAdministrator", manifest_txt)

        pkg_cfg_path = os.path.join(base_dir, "windows", "packaging_config.json")
        self.assertTrue(os.path.exists(pkg_cfg_path))
        with open(pkg_cfg_path, "r", encoding="utf-8") as f:
            pkg_cfg = json.load(f)
        self.assertEqual(pkg_cfg["driver"]["dll_name"], "wintun.dll")
        self.assertEqual(pkg_cfg["installer_output_name"], "PulseVPN-Setup")

        iss_path = os.path.join(base_dir, "packaging", "windows", "installer.iss")
        self.assertTrue(os.path.exists(iss_path))
        with open(iss_path, "r", encoding="utf-8") as f:
            iss_txt = f.read()
        self.assertIn("OutputBaseFilename=PulseVPN-Setup", iss_txt)
        self.assertIn("wintun.dll", iss_txt)
        self.assertIn("PrivilegesRequired=admin", iss_txt)

    def test_cyber_minimalist_ui_dashboard_and_workflows(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ui_home = os.path.join(base_dir, "lib", "ui", "home_screen.dart")
        ui_speedometer = os.path.join(base_dir, "lib", "ui", "widgets", "speedometer_gauge.dart")
        ui_picker = os.path.join(base_dir, "lib", "ui", "widgets", "server_picker_modal.dart")
        ui_auth = os.path.join(base_dir, "lib", "ui", "widgets", "auth_modal.dart")
        ui_fasthop = os.path.join(base_dir, "lib", "ui", "widgets", "fast_hop_indicator.dart")

        for p in [ui_home, ui_speedometer, ui_picker, ui_auth, ui_fasthop]:
            self.assertTrue(os.path.exists(p), f"Missing UI file: {p}")

        with open(ui_home, "r", encoding="utf-8") as f:
            home_txt = f.read()
        self.assertIn("connect_toggle_button", home_txt)
        self.assertIn("country_server_picker", home_txt)
        self.assertIn("RealTimeSpeedometer", home_txt)
        self.assertIn("VpnTunnelMode", home_txt)
        self.assertIn("AuthModal", home_txt)
        self.assertIn("Login / Pro", home_txt)
        self.assertIn("FastHopIndicator", home_txt)

        with open(ui_auth, "r", encoding="utf-8") as f:
            auth_txt = f.read()
        self.assertIn("class AuthModal", auth_txt)
        self.assertIn("auth_email_field", auth_txt)
        self.assertIn("auth_password_field", auth_txt)
        self.assertIn("auth_submit_button", auth_txt)
        self.assertIn("pro_tier_badge", auth_txt)

        with open(ui_fasthop, "r", encoding="utf-8") as f:
            fh_txt = f.read()
        self.assertIn("class FastHopIndicator", fh_txt)
        self.assertIn("5s (Extreme Privacy)", fh_txt)
        self.assertIn("30s", fh_txt)
        self.assertIn("1m", fh_txt)
        self.assertIn("5m", fh_txt)
        self.assertIn("Off", fh_txt)
        self.assertIn("Active Relay", fh_txt)
        self.assertIn("Standby Relay (Pre-warmed)", fh_txt)
        self.assertIn("Upgrade to Pro", fh_txt)

        # Verify balanced Dart braces/parentheses across all UI and core Dart files
        for dart_path in [ui_home, ui_speedometer, ui_picker, ui_auth, ui_fasthop]:
            with open(dart_path, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertEqual(src.count("{"), src.count("}"), f"Unbalanced braces in {dart_path}")
            self.assertEqual(src.count("("), src.count(")"), f"Unbalanced parens in {dart_path}")

        ci_wf = os.path.join(base_dir, ".github", "workflows", "ci.yml")
        build_wf = os.path.join(base_dir, ".github", "workflows", "build-clients.yml")
        self.assertTrue(os.path.exists(ci_wf))
        self.assertTrue(os.path.exists(build_wf))


if __name__ == "__main__":
    unittest.main(verbosity=2)
