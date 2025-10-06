#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "${HERE}/_lib_cli.sh"

# ---------- Run & Report ----------
RUN="${RUN:-$(date +%s)}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${HERE}/artifacts}"
mkdir -p "${ARTIFACTS_DIR}"
REPORT="${REPORT:-${ARTIFACTS_DIR}/e2e_report_${RUN}.md}"
LATEST_LINK="${ARTIFACTS_DIR}/e2e_report_latest.md"

report_init() {
  cat >"$REPORT" <<EOF
# LinkGuard E2E Report — RUN $RUN

**Server:** ${SERVER_IP}:${SERVER_PORT}  
**Fecha:** $(date -Iseconds)

---
EOF
  ln -sf "$(basename "$REPORT")" "$LATEST_LINK" || true
}
rlog()     { printf "%s\n" "$*" >> "$REPORT"; }
rsection() { printf "\n## %s\n\n" "$*" >> "$REPORT"; }
rcode()    { printf "\n\`\`\`\n%s\n\`\`\`\n" "$*" >> "$REPORT"; }

# ---------- Datos de prueba ----------
USERA="user_${RUN}_A"; EMAILA="u${RUN}_A@example.com"; PASSA="S3cret_${RUN}_A"
USERB="user_${RUN}_B"; EMAILB="u${RUN}_B@example.com"; PASSB="S3cret_${RUN}_B"

VPN_NAME="vg_${RUN}"
VPN_SEGMENT_A="${VPN_SEGMENT_A:-10.$((RANDOM%200+20)).$((RANDOM%200)).0}"
VPN_MASK_A="${VPN_MASK_A:-24}"

ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"
ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"
WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

NET_ID=""; WG_A_IP=""; WG_B_IP=""
A_PUB="";  B_PUB=""

# ---------- Firewall backend (iptables/nft) ----------
fw_backend() {
  rin "$1" 'command -v iptables >/dev/null && echo iptables || (command -v nft >/dev/null && echo nft || echo none)'
}

chain_setup() {
  local svc="$1" b; b="$(fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" '
        iptables -N E2E_BLOCK 2>/dev/null || true
        iptables -D INPUT  -j E2E_BLOCK 2>/dev/null || true
        iptables -D OUTPUT -j E2E_BLOCK 2>/dev/null || true
        iptables -I INPUT  1 -j E2E_BLOCK
        iptables -I OUTPUT 1 -j E2E_BLOCK
        iptables -F E2E_BLOCK
      ' ;;
    nft)
      rin "$svc" '
        nft list table inet e2e >/dev/null 2>&1 || nft add table inet e2e
        nft list chain inet e2e in  >/dev/null 2>&1 || nft add chain inet e2e in  { type filter hook input  priority 0; policy accept; }
        nft list chain inet e2e out >/dev/null 2>&1 || nft add chain inet e2e out { type filter hook output priority 0; policy accept; }
        nft flush chain inet e2e in
        nft flush chain inet e2e out
      ' ;;
    *) err "No hay iptables ni nft en $svc"; exit 127 ;;
  esac
}
chain_clear() {
  local svc="$1" b; b="$(fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" 'iptables -F E2E_BLOCK 2>/dev/null || true; iptables -D INPUT -j E2E_BLOCK 2>/dev/null || true; iptables -D OUTPUT -j E2E_BLOCK 2>/dev/null || true' ;;
    nft)      rin "$svc" 'nft flush chain inet e2e in 2>/dev/null || true; nft flush chain inet e2e out 2>/dev/null || true' ;;
  esac
}
block_pair() {
  local svc="$1" ip="$2" b; b="$(fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" "iptables -A E2E_BLOCK -d $ip -j REJECT; iptables -A E2E_BLOCK -s $ip -j REJECT" ;;
    nft)      rin "$svc" "nft add rule inet e2e in  ip saddr $ip reject; nft add rule inet e2e out ip daddr $ip reject" ;;
  esac
}
block_inbound_from() {
  local svc="$1" ip="$2" b; b="$(fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" "iptables -A E2E_BLOCK -s $ip -j REJECT" ;;
    nft)      rin "$svc" "nft add rule inet e2e in ip saddr $ip reject" ;;
  esac
}

# ---------- WireGuard helpers ----------
gen_wg_keys() {
  local svc="$1" prefix="$2"
  rin "$svc" "umask 077; wg genkey | tee /tmp/${prefix}_priv.key | wg pubkey > /tmp/${prefix}_pub.key"
  local pub priv
  pub="$(rin "$svc" "cat /tmp/${prefix}_pub.key" | tail -n1)"
  priv="$(rin "$svc" "cat /tmp/${prefix}_priv.key" | tail -n1)"
  echo "${pub}|${priv}"
}
wg_addr_ipv4() { rin "$1" "ip -4 -o addr show dev wg0 2>/dev/null | awk '{print \$4}' | head -n1 | cut -d/ -f1" | tail -n1; }
has_peer_pub() { rin "$1" "wg show wg0 2>/dev/null | grep -q \"$2\"" && echo yes || echo no; }
latest_handshake() { rin "$1" "wg show wg0 2>/dev/null | awk -F': ' '/latest handshake/ {print \$2; exit}'" | tail -n1; }

# ---------- CLI shortcuts ----------
cli_a2() { run_cli "$ALMA2_NAME" "$*"; }
cli_a3() { run_cli "$ALMA3_NAME" "$*"; }

# ---------- Sesiones (¡una a la vez!) ----------
server_login()  { run_cli "$1" "identificar_usuario $2 $3"; run_cli "$1" "whoami"; }
server_logout() { run_cli "$1" "cerrar_sesion" || true; }
with_session()  { local svc="$1" email="$2" pass="$3"; shift 3; server_login "$svc" "$email" "$pass"; run_cli "$svc" "$*"; server_logout "$svc"; }

# ---------- Asserts duros ----------
assert_server_listening() { rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>'"; }
assert_iface_up()         { rin "$1" "ip link show dev wg0 2>/dev/null | grep -q 'state UP'"; }
assert_peer_present()     { rin "$1" "wg show wg0 2>/dev/null | grep -q \"$2\""; }

# ---------- Checks suaves ----------
check_ping() {
  local svc="$1" dst="$2" label="$3"
  local out; out="$(rin "$svc" "ping -c1 -W1 $dst" || true)"
  rlog "- $label: $(echo "$out" | awk -F'[ ,]+' '/transmitted/ {print $1\"tx/\"$4\"rx\"}' | head -n1)"
  rcode "$out"
}
check_wg_show() { rlog "- $2: \`wg show\`"; rcode "$(rin "$1" "wg show 2>/dev/null || true")"; }

# ---------- Smoke ----------
smoke() {
  rsection "Smoke"
  ensure_tools "$ALMA1_NAME"; ensure_tools "$ALMA2_NAME"; ensure_tools "$ALMA3_NAME"
  assert_server_listening
  ok "Server escucha en ${SERVER_PORT}"
  rlog "- Server escucha en ${SERVER_PORT}: **OK**"
  rlog "- nc alma2→server:"; rcode "$(rin "$ALMA2_NAME" "nc -vz ${SERVER_IP} ${SERVER_PORT} || true")"
  rlog "- nc alma3→server:"; rcode "$(rin "$ALMA3_NAME" "nc -vz ${SERVER_IP} ${SERVER_PORT} || true")"
}

# ---------- Core: VPC única + sesiones serializadas ----------
workflow_core() {
  rsection "Core (1 sesión a la vez, 1 VPC activa)"

  # Cierra sesiones viejas por si acaso
  server_logout "$ALMA2_NAME" || true
  server_logout "$ALMA3_NAME" || true

  # 0) A y B se registran (cada uno en su sesión)
  with_session "$ALMA2_NAME" "$EMAILA" "$PASSA" "registrar_usuario ${USERA} ${EMAILA} ${PASSA}" || true
  with_session "$ALMA3_NAME" "$EMAILB" "$PASSB" "registrar_usuario ${USERB} ${EMAILB} ${PASSB}" || true

  # 1) A crea la VPC (su sesión)
  server_login "$ALMA2_NAME" "$EMAILA" "$PASSA"
  NET_ID="$(run_cli "$ALMA2_NAME" "crear_red_privada ${VPN_NAME} ${VPN_SEGMENT_A}" | extract_uuid_like || true)"
  if [[ -z "${NET_ID:-}" ]]; then
    NET_ID="$(run_cli "$ALMA2_NAME" "crear_red_privada ${VPN_NAME}" | extract_uuid_like || true)"
  fi
  [[ -n "${NET_ID:-}" ]] || { err "No pude obtener NET_ID"; server_logout "$ALMA2_NAME"; exit 2; }
  rlog "- NET_ID: \`${NET_ID}\`"
  server_logout "$ALMA2_NAME"

  # 2) A registra su peer e inicializa WG (sesión A)
  A_KEYS="$(gen_wg_keys "$ALMA2_NAME" "a2")"; A_PUB="${A_KEYS%%|*}"
  server_login "$ALMA2_NAME" "$EMAILA" "$PASSA"
  run_cli "$ALMA2_NAME" "registrar_como_peer peer_alma2 ${NET_ID} ${ALMA2_IP_C} ${WG_PORT_A}"
  run_cli "$ALMA2_NAME" "init_wireguard_interfaz ${ALMA2_IP_C}"
  run_cli "$ALMA2_NAME" "crear_peer ${A_PUB} ${VPN_SEGMENT_A}/${VPN_MASK_A} ${ALMA2_IP_C} ${WG_PORT_A}"
  server_logout "$ALMA2_NAME"

  # 3) B registra su peer e inicializa WG (sesión B)
  B_KEYS="$(gen_wg_keys "$ALMA3_NAME" "a3")"; B_PUB="${B_KEYS%%|*}"
  server_login "$ALMA3_NAME" "$EMAILB" "$PASSB"
  run_cli "$ALMA3_NAME" "registrar_como_peer peer_alma3 ${NET_ID} ${ALMA3_IP_C} ${WG_PORT_B}"
  run_cli "$ALMA3_NAME" "init_wireguard_interfaz ${ALMA3_IP_C}"
  run_cli "$ALMA3_NAME" "crear_peer ${B_PUB} ${VPN_SEGMENT_A}/${VPN_MASK_A} ${ALMA3_IP_C} ${WG_PORT_B}"
  server_logout "$ALMA3_NAME"

  # 4) Asserts locales (sin sesión)
  assert_iface_up "$ALMA2_NAME"
  assert_iface_up "$ALMA3_NAME"
  assert_peer_present "$ALMA2_NAME" "$A_PUB"
  assert_peer_present "$ALMA3_NAME" "$B_PUB"
  WG_A_IP="$(wg_addr_ipv4 "$ALMA2_NAME")"
  WG_B_IP="$(wg_addr_ipv4 "$ALMA3_NAME")"
  rlog "- wg0 alma2: ${WG_A_IP:-<sin ip>}"
  rlog "- wg0 alma3: ${WG_B_IP:-<sin ip>}"
  check_wg_show "$ALMA2_NAME" "alma2"
  check_wg_show "$ALMA3_NAME" "alma3"

  ok "Core OK (VPC: ${NET_ID})"
}

chain_flush() {
  local svc="$1" b; b="$(fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" 'iptables -F E2E_BLOCK 2>/dev/null || true' ;;
    nft)      rin "$svc" 'nft flush chain inet e2e in 2>/dev/null || true; nft flush chain inet e2e out 2>/dev/null || true' ;;
  esac
}

ensure_hook() {
  local svc="$1" b; b="$(fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" 'iptables -C INPUT -j E2E_BLOCK 2>/dev/null || iptables -I INPUT 1 -j E2E_BLOCK'
      ;;
    nft)
      # en nft ya creamos una chain base con hook input en chain_setup
      :
      ;;
  esac
}
