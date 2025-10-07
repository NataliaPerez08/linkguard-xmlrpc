#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
source "${HERE}/_lib_cli.sh"   # requiere: rin, ensure_tools, log, ok, err, CLI_DIR, CLI_BIN

# ────────────────────────────────────────────────────────────────────────────────
# Fallbacks & wrappers
# ────────────────────────────────────────────────────────────────────────────────

# Si _lib_cli.sh no define warn, créala aquí.
type warn >/dev/null 2>&1 || warn(){ echo "⚠️  $*" >&2; }

# Wrapper argv-seguro y robusto (evita 'unbound variable' si falta servicio).
run_cli_q() {
  local svc="${1:-}"
  if [[ -z "$svc" ]]; then
    err "run_cli_q: falta servicio (alma2/alma3/alma4)"
    return 22
  fi
  shift || true

  local -a args=("$@")
  local q="" x
  for x in "${args[@]}"; do q+=$(printf "%q " "$x"); done

  log "[$svc] CLI(argv): ${CLI_BIN} ${q}"
  rin "$svc" "cd '${CLI_DIR:-/shared/Cliente}' && ${CLI_BIN} ${q}"
}

# ────────────────────────────────────────────────────────────────────────────────
# Helpers de red/WG
# ────────────────────────────────────────────────────────────────────────────────

wait_wg_ip() {
  local svc="$1" tries=60
  for _ in $(seq 1 "${tries}"); do
    if rin "$svc" "ip -o -4 addr show dev wg0 2>/dev/null | grep -q ' inet '"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wg_addr_ipv4() {
  rin "$1" "ip -4 -o addr show dev wg0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -n1" | tail -n1
}

assert_ping() {
  local svc="$1" dst="$2" label="$3"
  rin "$svc" "ping -c1 -W2 ${dst} >/dev/null"
  log "✅ ${label}: OK"
}

assert_ping_fail() {
  local svc="$1" dst="$2" label="$3"
  if rin "$svc" "ping -c1 -W1 ${dst} >/dev/null"; then
    err "❌ ${label}: NO debía responder"
    exit 30
  else
    log "✅ ${label}: BLOQUEADO"
  fi
}

assert_nc_udp_fail() {
  local svc="$1" host="$2" port="$3" label="$4"
  if rin "$svc" "PATH=/usr/sbin:/sbin:\$PATH command -v ncat >/dev/null 2>&1"; then
    rin "$svc" "PATH=/usr/sbin:/sbin:\$PATH ncat -z -u -w1 ${host} ${port}" \
      && { err "❌ ${label}: NO debía conectar"; exit 31; } \
      || log "✅ ${label}: BLOQUEADO (UDP)"
  else
    rin "$svc" "PATH=/usr/sbin:/sbin:\$PATH nc -u -z -w1 ${host} ${port}" \
      && { err "❌ ${label}: NO debía conectar"; exit 31; } \
      || log "✅ ${label}: BLOQUEADO (UDP)"
  fi
}

extract_id() {
  grep -oE '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|id_[A-Za-z0-9._-]+|[A-Za-z0-9._-]{12,})' | head -n1
}

# ────────────────────────────────────────────────────────────────────────────────
# Firewall helpers (iptables/nft)
# ────────────────────────────────────────────────────────────────────────────────

_fw_backend() {
  rin "$1" 'PATH=/usr/sbin:/sbin:$PATH command -v iptables >/dev/null && echo iptables || (command -v nft >/dev/null && echo nft || echo none)'
}

ensure_fw_tools() {
  local svc="$1"

  rin "$svc" '
    PATH=/usr/sbin:/sbin:$PATH

    # iptables/nft
    if ! command -v iptables >/dev/null && ! command -v nft >/dev/null; then
      if command -v dnf >/dev/null; then
        dnf -y install iptables nftables conntrack-tools >/dev/null 2>&1 || true
      elif command -v yum >/dev/null; then
        yum -y install iptables nftables conntrack-tools >/dev/null 2>&1 || true
      fi
    fi

    # ncat/nc
    command -v ncat >/dev/null || command -v nc >/dev/null || {
      if command -v dnf >/dev/null; then
        dnf -y install nmap-ncat >/dev/null 2>&1 || true
      elif command -v yum >/dev/null; then
        yum -y install nmap-ncat >/dev/null 2>&1 || true
      fi
    }
  '

  local b; b="$(_fw_backend "$svc")"
  if [[ "$b" == "none" ]]; then
    err "Sin iptables/nft en ${svc} (instálalos en la imagen o deja que ensure_fw_tools lo haga)."
    exit 127
  fi
}

chain_setup() {
  local svc="${1:-}"
  [[ -n "$svc" ]] || { err "chain_setup: falta servicio"; exit 22; }

  local b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" '
        PATH=/usr/sbin:/sbin:$PATH
        iptables -N E2E_BLOCK 2>/dev/null || true
        iptables -C INPUT  -j E2E_BLOCK 2>/dev/null || iptables -I INPUT  1 -j E2E_BLOCK
        iptables -C OUTPUT -j E2E_BLOCK 2>/dev/null || iptables -I OUTPUT 1 -j E2E_BLOCK
      '
      ;;
    nft)
      rin "$svc" '
        PATH=/usr/sbin:/sbin:$PATH
        nft list table inet e2e >/dev/null 2>&1 || nft add table inet e2e
        nft list chain inet e2e in  >/dev/null 2>&1 || nft add chain inet e2e in  { type filter hook input  priority 0; policy accept; }
        nft list chain inet e2e out >/dev/null 2>&1 || nft add chain inet e2e out { type filter hook output priority 0; policy accept; }
      '
      ;;
    *)
      err "Sin iptables/nft en $svc"
      exit 127
      ;;
  esac
}

chain_flush() {
  local svc="${1:-}"
  [[ -n "$svc" ]] || { err "chain_flush: falta servicio"; exit 22; }

  local b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH iptables -F E2E_BLOCK 2>/dev/null || true' ;;
    nft)      rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH nft flush chain inet e2e in 2>/dev/null || true; nft flush chain inet e2e out 2>/dev/null || true' ;;
  esac
}

# Bloquea NEW entre un par (simétrico in/out) — solo orquestador habilitado.
block_pair() {
  local svc="${1:-}" other="${2:-}"
  [[ -n "$svc" && -n "$other" ]] || { err "block_pair: faltan args (svc, other)"; exit 22; }

  local b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" "
        PATH=/usr/sbin:/sbin:\$PATH
        iptables -A E2E_BLOCK -s ${other} -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
        iptables -A E2E_BLOCK -d ${other} -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
      "
      ;;
    nft)
      rin "$svc" "
        PATH=/usr/sbin:/sbin:\$PATH
        nft add rule inet e2e in  ip saddr ${other} ct state new reject
        nft add rule inet e2e out ip daddr ${other} ct state new reject
      "
      ;;
  esac
}

# ────────────────────────────────────────────────────────────────────────────────
# Parámetros (override por env si quieres)
# ────────────────────────────────────────────────────────────────────────────────

USR_NAME="${USR_NAME:-n3_3p}"
USR_EMAIL="${USR_EMAIL:-n3_3p}"
USR_PASS="${USR_PASS:-pas3}"

VPN_NAME="${VPN_NAME:-vpn3_3p}"
NET_ID="${NET_ID:-0}"     # contrato actual del server: una VPC/sesión → id 0

ALMA2_NAME="${ALMA2_NAME:-alma2}"
ALMA3_NAME="${ALMA3_NAME:-alma3}"
ALMA4_NAME="${ALMA4_NAME:-alma4}"

ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"
ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"
ALMA4_IP_C="${ALMA4_IP_C:-172.20.0.13}"

WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"
WG_PORT_C="${WG_PORT_C:-51822}"

# ────────────────────────────────────────────────────────────────────────────────
# Prechecks
# ────────────────────────────────────────────────────────────────────────────────

ensure_tools "$ALMA1_NAME"
ensure_tools "$ALMA2_NAME"
ensure_tools "$ALMA3_NAME"
ensure_tools "$ALMA4_NAME"

# Asegura backends de firewall y herramientas de red en los peers
ensure_fw_tools "$ALMA2_NAME"
ensure_fw_tools "$ALMA3_NAME"
ensure_fw_tools "$ALMA4_NAME"

# Server escuchando
rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>'" \
  || { err "server NO escucha en ${SERVER_PORT}"; exit 2; }

log "[S3-3P] Solo orquestador: bloquear directo entre todos → endpoints → esperar wg0 → ping wg (malla)"

# ────────────────────────────────────────────────────────────────────────────────
# 0) Bloqueo simétrico NEW entre todos los pares (solo orquestador queda útil)
# ────────────────────────────────────────────────────────────────────────────────

chain_setup "$ALMA2_NAME"; chain_flush "$ALMA2_NAME"
chain_setup "$ALMA3_NAME"; chain_flush "$ALMA3_NAME"
chain_setup "$ALMA4_NAME"; chain_flush "$ALMA4_NAME"

block_pair "$ALMA2_NAME" "$ALMA3_IP_C"
block_pair "$ALMA2_NAME" "$ALMA4_IP_C"
block_pair "$ALMA3_NAME" "$ALMA2_IP_C"
block_pair "$ALMA3_NAME" "$ALMA4_IP_C"
block_pair "$ALMA4_NAME" "$ALMA2_IP_C"
block_pair "$ALMA4_NAME" "$ALMA3_IP_C"

# ────────────────────────────────────────────────────────────────────────────────
# 1) Usuario y red (una sesión/VPC activa)
# ────────────────────────────────────────────────────────────────────────────────

run_cli_q "$ALMA2_NAME" registrar_usuario "$USR_NAME" "$USR_EMAIL" "$USR_PASS" || true
run_cli_q "$ALMA2_NAME" crear_red_privada "$VPN_NAME"

# ────────────────────────────────────────────────────────────────────────────────
# 2) Registrar 3 peers (firma exacta)
# ────────────────────────────────────────────────────────────────────────────────

run_cli_q "$ALMA2_NAME" registrar_como_peer "e1" "$NET_ID" "$ALMA2_IP_C" "$WG_PORT_A"
run_cli_q "$ALMA3_NAME" registrar_como_peer "e2" "$NET_ID" "$ALMA3_IP_C" "$WG_PORT_B"
run_cli_q "$ALMA4_NAME" registrar_como_peer "e3" "$NET_ID" "$ALMA4_IP_C" "$WG_PORT_C"

# ────────────────────────────────────────────────────────────────────────────────
# 3) Verificar que NO hay directo entre pares (ICMP y UDP)
# ────────────────────────────────────────────────────────────────────────────────

assert_ping_fail   "$ALMA2_NAME" "$ALMA3_IP_C" "ping A→B bloqueado"
assert_nc_udp_fail "$ALMA2_NAME" "$ALMA3_IP_C" "$WG_PORT_B" "UDP A→B"

assert_ping_fail   "$ALMA3_NAME" "$ALMA4_IP_C" "ping B→C bloqueado"
assert_nc_udp_fail "$ALMA3_NAME" "$ALMA4_IP_C" "$WG_PORT_C" "UDP B→C"

assert_ping_fail   "$ALMA4_NAME" "$ALMA2_IP_C" "ping C→A bloqueado"
assert_nc_udp_fail "$ALMA4_NAME" "$ALMA2_IP_C" "$WG_PORT_A" "UDP C→A"

# ────────────────────────────────────────────────────────────────────────────────
# 5) Esperar wg0 con IP en los tres
# ────────────────────────────────────────────────────────────────────────────────

wait_wg_ip "$ALMA2_NAME" || { err "alma2: wg0 sin IP"; exit 4; }
wait_wg_ip "$ALMA3_NAME" || { err "alma3: wg0 sin IP"; exit 4; }
wait_wg_ip "$ALMA4_NAME" || { err "alma4: wg0 sin IP"; exit 4; }

WG_A="$(wg_addr_ipv4 "$ALMA2_NAME")"
WG_B="$(wg_addr_ipv4 "$ALMA3_NAME")"
WG_C="$(wg_addr_ipv4 "$ALMA4_NAME")"

for ip in "$WG_A" "$WG_B" "$WG_C"; do
  case "$ip" in
    172.20.*) err "wg0 no debe ser 172.20.* (VPN mal asignada): ${ip}"; exit 5;;
  esac
done

log "[S3-3P] wg0: A=${WG_A}  B=${WG_B}  C=${WG_C}"

# ────────────────────────────────────────────────────────────────────────────────
# 6) Pings wg en malla
# ────────────────────────────────────────────────────────────────────────────────

assert_ping "$ALMA2_NAME" "$WG_B" "A→B (wg)"
assert_ping "$ALMA3_NAME" "$WG_A" "B→A (wg)"

assert_ping "$ALMA3_NAME" "$WG_C" "B→C (wg)"
assert_ping "$ALMA4_NAME" "$WG_B" "C→B (wg)"

assert_ping "$ALMA4_NAME" "$WG_A" "C→A (wg)"
assert_ping "$ALMA2_NAME" "$WG_C" "A→C (wg)"

ok "[S3-3P] OK — sin directo entre pares; orquestador conectó; malla wg operativa"
