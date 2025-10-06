#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "${HERE}/_lib_cli.sh"     # usa rin/ensure_tools/vars
# NOTA: _lib_cli.sh debe tener CLI_DIR=/shared/Cliente y CLI_BIN="python3 main.py"

# --- wrapper argv-seguro (por si no existe ya en _lib_cli.sh) ---
run_cli_q() {
  local svc="$1"; shift
  local -a args=("$@")
  local q="" a
  for a in "${args[@]}"; do q+=$(printf "%q " "$a"); done
  log "[$svc] CLI(argv): ${CLI_BIN} ${q}"
  rin "$svc" "cd '${CLI_DIR:-/shared/Cliente}' && ${CLI_BIN} ${q}"
}

# --- helpers del caso ---
wait_wg_ip() {
  local svc="$1" tries=60
  for _ in $(seq 1 $tries); do
    if rin "$svc" "ip -o -4 addr show dev wg0 2>/dev/null | grep -q ' inet '" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}
wg_addr_ipv4() { rin "$1" "ip -4 -o addr show dev wg0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -n1" | tail -n1; }
assert_ping()      { local svc="$1" dst="$2" label="$3"; rin "$svc" "ping -c1 -W2 ${dst} >/dev/null"; log "✅ ${label}: OK"; }
assert_ping_fail() { local svc="$1" dst="$2" label="$3"; if rin "$svc" "ping -c1 -W1 ${dst} >/dev/null"; then err "❌ ${label}: NO debía responder"; exit 20; else log "✅ ${label}: BLOQUEADO"; fi; }
assert_nc_udp_fail() {
  local svc="$1" host="$2" port="$3" label="$4"
  if rin "$svc" "PATH=/usr/sbin:/sbin:$PATH command -v ncat >/dev/null 2>&1"; then
    rin "$svc" "PATH=/usr/sbin:/sbin:$PATH ncat -z -u -w1 ${host} ${port}" && { err "❌ ${label}: NO debía conectar"; exit 21; } || log "✅ ${label}: BLOQUEADO (UDP)"
  else
    rin "$svc" "PATH=/usr/sbin:/sbin:$PATH nc -u -z -w1 ${host} ${port}"   && { err "❌ ${label}: NO debía conectar"; exit 21; } || log "✅ ${label}: BLOQUEADO (UDP)"
  fi
}
extract_id() { grep -oE '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|id_[A-Za-z0-9._-]+|[A-Za-z0-9._-]{12,})' | head -n1; }

# --- firewall helpers (iptables/nft) ---
_fw_backend() { rin "$1" 'PATH=/usr/sbin:/sbin:$PATH command -v iptables >/dev/null && echo iptables || (command -v nft >/dev/null && echo nft || echo none)'; }

chain_setup() {
  local svc="$1" b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" '
        PATH=/usr/sbin:/sbin:$PATH
        iptables -N E2E_BLOCK 2>/dev/null || true
        iptables -C INPUT  -j E2E_BLOCK 2>/dev/null || iptables -I INPUT  1 -j E2E_BLOCK
        iptables -C OUTPUT -j E2E_BLOCK 2>/dev/null || iptables -I OUTPUT 1 -j E2E_BLOCK
      ' ;;
    nft)
      rin "$svc" '
        PATH=/usr/sbin:/sbin:$PATH
        nft list table inet e2e >/dev/null 2>&1 || nft add table inet e2e
        nft list chain inet e2e in  >/dev/null 2>&1 || nft add chain inet e2e in  { type filter hook input  priority 0; policy accept; }
        nft list chain inet e2e out >/dev/null 2>&1 || nft add chain inet e2e out { type filter hook output priority 0; policy accept; }
      ' ;;
    *) err "No hay iptables ni nft en $svc"; exit 127 ;;
  esac
}
chain_flush() {
  local svc="$1" b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH iptables -F E2E_BLOCK 2>/dev/null || true' ;;
    nft)      rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH nft flush chain inet e2e in 2>/dev/null || true; nft flush chain inet e2e out 2>/dev/null || true' ;;
  esac
}
ensure_hook() {
  local svc="$1" b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH iptables -C INPUT -j E2E_BLOCK 2>/dev/null || iptables -I INPUT 1 -j E2E_BLOCK' ;;
    nft) : ;;
  esac
}

# 💡 NAT stateful: permite ESTABLISHED/RELATED, y bloquea solo NEW desde alma2
allow_established() {
  local svc="$1" b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH iptables -C E2E_BLOCK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I E2E_BLOCK 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
      rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH iptables -C E2E_BLOCK -m conntrack --ctstate INVALID -j DROP 2>/dev/null || iptables -I E2E_BLOCK 2 -m conntrack --ctstate INVALID -j DROP'
      ;;
    nft)
      rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH nft add rule inet e2e in  ct state established,related accept 2>/dev/null || true'
      rin "$svc" 'PATH=/usr/sbin:/sbin:$PATH nft add rule inet e2e in  ct state invalid drop 2>/dev/null || true'
      ;;
  esac
}
block_inbound_new_from() {
  local svc="$1" ip="$2" b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables) rin "$svc" "PATH=/usr/sbin:/sbin:$PATH iptables -A E2E_BLOCK -s $ip -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable" ;;
    nft)      rin "$svc" "PATH=/usr/sbin:/sbin:$PATH nft add rule inet e2e in ip saddr $ip ct state new reject" ;;
  esac
}

# --- parámetros del caso ---
USR_NAME="${USR_NAME:-n2}"
USR_EMAIL="${USR_EMAIL:-n2}"
USR_PASS="${USR_PASS:-pas2}"
VPN_NAME="${VPN_NAME:-vpn2}"
NET_ID="${NET_ID:-0}"                 # '0' por contrato actual

ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"
ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"
WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

# --- prechecks básicos ---
ensure_tools "$ALMA1_NAME"
ensure_tools "$ALMA2_NAME"
ensure_tools "$ALMA3_NAME"
rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>'" || { err "server NO escucha en ${SERVER_PORT}"; exit 2; }

log "[S2] Flujo: registrar_usuario → crear_red_privada → registrar_como_peer(A,B) → pruebas no-público → conectar_endpoint(A,B) → esperar wg0 → ping wg↔wg"

# 0) Simular NAT stateful en alma3: hook + limpiar + permitir ESTABLISHED + bloquear NEW desde alma2
chain_setup "$ALMA2_NAME"; chain_flush "$ALMA2_NAME"; ensure_hook "$ALMA2_NAME"
chain_setup "$ALMA3_NAME"; chain_flush "$ALMA3_NAME"; ensure_hook "$ALMA3_NAME"
allow_established "$ALMA3_NAME"
block_inbound_new_from "$ALMA3_NAME" "$ALMA2_IP_C"

# 1) registrar_usuario (desde alma2)
run_cli_q "$ALMA2_NAME" registrar_usuario "$USR_NAME" "$USR_EMAIL" "$USR_PASS" || true

# 2) crear_red_privada
run_cli_q "$ALMA2_NAME" crear_red_privada "$VPN_NAME"

# 3) registrar_como_peer en alma2 y alma3 (ORDEN EXACTO)
run_cli_q "$ALMA2_NAME" registrar_como_peer "e2a" "$NET_ID" "$ALMA2_IP_C" "$WG_PORT_A"
run_cli_q "$ALMA3_NAME" registrar_como_peer "e2b" "$NET_ID" "$ALMA3_IP_C" "$WG_PORT_B"

# --- PRUEBAS de NO-PÚBLICO (antes de conectar por orquestador) ---
log "[S2] Verificando que alma3 NO es público desde alma2 (pero SÍ permite replies a tráfico saliente):"
assert_ping_fail "$ALMA2_NAME" "$ALMA3_IP_C" "ping directo alma2→alma3 BLOQUEADO (NEW)"
rin "$ALMA3_NAME" "PATH=/usr/sbin:/sbin:$PATH ss -lun | grep -q ':${WG_PORT_B}\\>'" && log "ℹ️ alma3 escucha UDP:${WG_PORT_B}" || warn "⚠️ alma3 aún no muestra UDP:${WG_PORT_B}"
assert_nc_udp_fail "$ALMA2_NAME" "$ALMA3_IP_C" "$WG_PORT_B" "UDP alma2→alma3:${WG_PORT_B} BLOQUEADO"
# Ahora, gracias a ESTABLISHED/RELATED permitido, este ping debe PASAR:
assert_ping "$ALMA3_NAME" "$ALMA2_IP_C" "ping directo alma3→alma2 PERMITIDO (replies entran)"

# 4) Conexión mediada por orquestador: obtener IDs y conectar
EP_A="$(run_cli_q "$ALMA2_NAME" ver_endpoints "$NET_ID" | extract_id || true)"
EP_B="$(run_cli_q "$ALMA3_NAME" ver_endpoints "$NET_ID" | extract_id || true)"
[[ -n "$EP_A" ]] || { err "No encontré endpoint de A en red ${NET_ID}"; exit 3; }
[[ -n "$EP_B" ]] || { err "No encontré endpoint de B en red ${NET_ID}"; exit 3; }

#run_cli_q "$ALMA2_NAME" conectar_endpoint "$EP_A" "$NET_ID"
#run_cli_q "$ALMA3_NAME" conectar_endpoint "$EP_B" "$NET_ID"

# 5) Esperar wg0 con IP
log "[S2] Esperando wg0 con IP en ambos clientes…"
wait_wg_ip "$ALMA2_NAME" || { err "alma2: wg0 sin IP tras timeout"; exit 4; }
wait_wg_ip "$ALMA3_NAME" || { err "alma3: wg0 sin IP tras timeout"; exit 4; }

WG_A_IP="$(wg_addr_ipv4 "$ALMA2_NAME")"
WG_B_IP="$(wg_addr_ipv4 "$ALMA3_NAME")"
log "[S2] wg0 alma2 = ${WG_A_IP} ; wg0 alma3 = ${WG_B_IP}"

case "$WG_A_IP" in 172.20.*) err "wg0 alma2 no debe ser 172.20.* (VPN mal asignada)"; exit 5;; esac
case "$WG_B_IP" in 172.20.*) err "wg0 alma3 no debe ser 172.20.* (VPN mal asignada)"; exit 5;; esac

# 6) ping wg↔wg obligatorio
assert_ping "$ALMA2_NAME" "$WG_B_IP" "ping alma2→alma3 (wg, mediado)"
assert_ping "$ALMA3_NAME" "$WG_A_IP" "ping alma3→alma2 (wg, mediado)"

ok "[S2] COMPLETO: no-público verificado (stateful), conexión mediada por orquestador, wg0 con IP y ping wg↔wg OK"
