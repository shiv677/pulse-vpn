#!/usr/bin/env bash
# Pulse VPN - Zero-Configuration WireGuard Server Bootstrap
# Target: Ubuntu / Debian on Oracle Cloud Always-Free (ARM64 Ampere / AMD64)

set -euo pipefail

WG_INTERFACE="wg0"
WG_PORT="${WG_PORT:-51820}"
WG_SUBNET="10.66.66.0/24"
WG_SERVER_IP="10.66.66.1/24"
WG_DNS="${WG_DNS:-1.1.1.1, 1.0.0.1}"
WG_DIR="/etc/wireguard"
CLIENT_DIR="${WG_DIR}/clients"
CLIENT_NAME="${1:-pulse-client1}"
CLIENT_IP="10.66.66.2/32"

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Please run this script as root (sudo ./setup-server.sh)"
  exit 1
fi

echo "==> [1/6] Installing WireGuard kernel tools, qrencode, and firewall utilities (iptables / nftables)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard wireguard-tools qrencode iptables nftables curl iproute2
modprobe wireguard || true

echo "==> [2/6] Enabling Linux kernel IPv4 and IPv6 packet forwarding..."
cat >/etc/sysctl.d/99-pulse-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl --system

PRIMARY_IFACE="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
PUBLIC_IP="$(curl -4 -fsSL https://api.ipify.org || curl -4 -fsSL https://ifconfig.me || hostname -I | awk '{print $1}')"

echo "==> Detected outbound interface: ${PRIMARY_IFACE} | Public Endpoint: ${PUBLIC_IP}:${WG_PORT}"

echo "==> [3/6] Generating server and client Curve25519 keys..."
mkdir -p "${CLIENT_DIR}"
chmod 700 "${WG_DIR}" "${CLIENT_DIR}"

if [[ ! -f "${WG_DIR}/server_private.key" ]]; then
  wg genkey | tee "${WG_DIR}/server_private.key" | wg pubkey > "${WG_DIR}/server_public.key"
  chmod 600 "${WG_DIR}/server_private.key"
fi

SERVER_PRIV_KEY="$(cat "${WG_DIR}/server_private.key")"
SERVER_PUB_KEY="$(cat "${WG_DIR}/server_public.key")"

wg genkey | tee "${CLIENT_DIR}/${CLIENT_NAME}.key" | wg pubkey > "${CLIENT_DIR}/${CLIENT_NAME}.pub"
wg genpsk > "${CLIENT_DIR}/${CLIENT_NAME}.psk"
chmod 600 "${CLIENT_DIR}/${CLIENT_NAME}.key" "${CLIENT_DIR}/${CLIENT_NAME}.psk"

CLIENT_PRIV_KEY="$(cat "${CLIENT_DIR}/${CLIENT_NAME}.key")"
CLIENT_PUB_KEY="$(cat "${CLIENT_DIR}/${CLIENT_NAME}.pub")"
CLIENT_PSK="$(cat "${CLIENT_DIR}/${CLIENT_NAME}.psk")"

echo "==> [4/6] Writing WireGuard server config (${WG_DIR}/${WG_INTERFACE}.conf)..."
cat >"${WG_DIR}/${WG_INTERFACE}.conf" <<EOF
[Interface]
Address = ${WG_SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
MTU = 1420
PostUp = iptables -I INPUT -p udp --dport ${WG_PORT} -j ACCEPT; iptables -I FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -I FORWARD -o ${WG_INTERFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o ${PRIMARY_IFACE} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${WG_PORT} -j ACCEPT; iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_INTERFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o ${PRIMARY_IFACE} -j MASQUERADE

[Peer]
# ${CLIENT_NAME}
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}
EOF
chmod 600 "${WG_DIR}/${WG_INTERFACE}.conf"

echo "==> [5/6] Generating client configuration (${CLIENT_DIR}/${CLIENT_NAME}.conf)..."
cat >"${CLIENT_DIR}/${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = 10.66.66.2/24
DNS = ${WG_DNS}
MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PSK}
Endpoint = ${PUBLIC_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
chmod 600 "${CLIENT_DIR}/${CLIENT_NAME}.conf"

echo "==> [6/6] Starting and enabling wg-quick@${WG_INTERFACE} service..."
systemctl enable "wg-quick@${WG_INTERFACE}"
systemctl restart "wg-quick@${WG_INTERFACE}"

echo ""
echo "================================================================="
echo " Pulse VPN WireGuard Server Ready!"
echo " Endpoint    : ${PUBLIC_IP}:${WG_PORT}"
echo " Client Conf : ${CLIENT_DIR}/${CLIENT_NAME}.conf"
echo "================================================================="
echo "Scan the QR code below inside the Pulse VPN Android/Desktop App:"
echo ""
qrencode -t ansiutf8 < "${CLIENT_DIR}/${CLIENT_NAME}.conf"
echo ""
echo "----- BEGIN CLIENT CONFIG -----"
cat "${CLIENT_DIR}/${CLIENT_NAME}.conf"
echo "----- END CLIENT CONFIG -----"
