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
wg_addr_ipv4()      { rin "$1" "ip -4 -o addr show dev wg0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -n1" | tail -n1; }
assert_ping()       { local svc="$1" dst="$2" label="$3"; rin "$svc" "ping -c1 -W2 ${dst} >/dev/null"; log "✅ ${label}: OK"; }
assert_ping_fail()  { local svc="$1" dst="$2" label="$3"; if rin "$svc" "ping -c1 -W1 ${dst} >/dev/null"; then err "❌ ${label}: NO debía responder"; exit 30; else log "✅ ${label}: BLOQUEADO"; fi; }
assert_nc_udp_fail(){
  local svc="$1" host="$2" port="$3" label="$4"
  if rin "$svc" "PATH=/usr/sbin:/sbin:$PATH command -v ncat >/dev/null 2>&1"; then
    rin "$svc" "PATH=/usr/sbin:/sbin:$PATH ncat -z -u -w1 ${host} ${port}" && { err "❌ ${label}: NO debía conectar"; exit 31; } || log "✅ ${label}: BLOQUEADO (UDP)"
  else
    rin "$svc" "PATH=/usr/sbin:/sbin:$PATH nc -u -z -w1 ${host} ${port}"   && { err "❌ ${label}: NO debía conectar"; exit 31; } || log "✅ ${label}: BLOQUEADO (UDP)"
  fi
}
extract_id()        { grep -oE '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|id_[A-Za-z0-9._-]+|[A-Za-z0-9._-]{12,})' | head -n1; }

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
# Bloquea cualquier NEW de/para el otro peer (sin afectar tráfico con el orquestador)
block_no_direct_pair() {
  local svc="$1" other="$2" b; b="$(_fw_backend "$svc")"
  case "$b" in
    iptables)
      rin "$svc" "
        PATH=/usr/sbin:/sbin:$PATH
        iptables -A E2E_BLOCK -s ${other} -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
        iptables -A E2E_BLOCK -d ${other} -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
      "
      ;;
    nft)
      rin "$svc" "
        PATH=/usr/sbin:/sbin:$PATH
        nft add rule inet e2e in  ip saddr ${other} ct state new reject
        nft add rule inet e2e out ip daddr ${other} ct state new reject
      "
      ;;
  esac
}

# --- parámetros del caso ---
USR_NAME="${USR_NAME:-n3}"
USR_EMAIL="${USR_EMAIL:-n3}"
USR_PASS="${USR_PASS:-pas3}"
VPN_NAME="${VPN_NAME:-vpn3}"
NET_ID="${NET_ID:-0}"                 # por contrato actual: '0' (o el real si tu server ya lo devuelve)

ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"
ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"
WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

# --- prechecks básicos ---
ensure_tools "$ALMA1_NAME"
ensure_tools "$ALMA2_NAME"
ensure_tools "$ALMA3_NAME"
rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>'" || { err "server NO escucha en ${SERVER_PORT}"; exit 2; }

log "[S3] Flujo: registrar_usuario → crear_red_privada → registrar_como_peer(A,B) → probar NO-directo en ambos sentidos → conectar_endpoint(A,B) → esperar wg0 → ping wg↔wg"

# 0) “Solo orquestador”: impedir cualquier tráfico directo entre alma2 y alma3 (en ambos sentidos)
chain_setup "$ALMA2_NAME"; chain_flush "$ALMA2_NAME"
chain_setup "$ALMA3_NAME"; chain_flush "$ALMA3_NAME"
block_no_direct_pair "$ALMA2_NAME" "$ALMA3_IP_C"
block_no_direct_pair "$ALMA3_NAME" "$ALMA2_IP_C"

# 1) registrar_usuario (desde alma2, referencia)
run_cli_q "$ALMA2_NAME" registrar_usuario "$USR_NAME" "$USR_EMAIL" "$USR_PASS" || true

# 2) crear_red_privada
run_cli_q "$ALMA2_NAME" crear_red_privada "$VPN_NAME"

# 3) registrar_como_peer en alma2 y alma3 (ORDEN EXACTO)
#    python3 main.py registrar_como_peer <nombre> <id_red_privada> <ip_cliente> <puerto_cliente>
run_cli_q "$ALMA2_NAME" registrar_como_peer "e3a" "$NET_ID" "$ALMA2_IP_C" "$WG_PORT_A"
run_cli_q "$ALMA3_NAME" registrar_como_peer "e3b" "$NET_ID" "$ALMA3_IP_C" "$WG_PORT_B"

# --- PRUEBAS: ninguno es “público” respecto del otro (ambas direcciones fallan) ---
log "[S3] Verificando que NO hay conectividad directa entre alma2 y alma3 (en ningún sentido):"
assert_ping_fail   "$ALMA2_NAME" "$ALMA3_IP_C" "ping directo alma2→alma3 BLOQUEADO"
assert_nc_udp_fail "$ALMA2_NAME" "$ALMA3_IP_C" "$WG_PORT_B" "UDP alma2→alma3:${WG_PORT_B} BLOQUEADO"
assert_ping_fail   "$ALMA3_NAME" "$ALMA2_IP_C" "ping directo alma3→alma2 BLOQUEADO"
assert_nc_udp_fail "$ALMA3_NAME" "$ALMA2_IP_C" "$WG_PORT_A" "UDP alma3→alma2:${WG_PORT_A} BLOQUEADO"

# 4) Conexión mediada por orquestador: obtener IDs y conectar
EP_A="$(run_cli_q "$ALMA2_NAME" ver_endpoints "$NET_ID" | extract_id || true)"
EP_B="$(run_cli_q "$ALMA3_NAME" ver_endpoints "$NET_ID" | extract_id || true)"
[[ -n "$EP_A" ]] || { err "No encontré endpoint de A en red ${NET_ID}"; exit 3; }
[[ -n "$EP_B" ]] || { err "No encontré endpoint de B en red ${NET_ID}"; exit 3; }

#run_cli_q "$ALMA2_NAME" conectar_endpoint "$EP_A" "$NET_ID"
#run_cli_q "$ALMA3_NAME" conectar_endpoint "$EP_B" "$NET_ID"

# 5) Esperar wg0 con IP (push del orquestador/relay)
log "[S3] Esperando wg0 con IP en ambos clientes…"
wait_wg_ip "$ALMA2_NAME" || { err "alma2: wg0 sin IP tras timeout"; exit 4; }
wait_wg_ip "$ALMA3_NAME" || { err "alma3: wg0 sin IP tras timeout"; exit 4; }

WG_A_IP="$(wg_addr_ipv4 "$ALMA2_NAME")"
WG_B_IP="$(wg_addr_ipv4 "$ALMA3_NAME")"
log "[S3] wg0 alma2 = ${WG_A_IP} ; wg0 alma3 = ${WG_B_IP}"

# sanity: que NO sea 172.20.* (eso es transporte Docker, no la VPN)
case "$WG_A_IP" in 172.20.*) err "wg0 alma2 no debe ser 172.20.* (VPN mal asignada)"; exit 5;; esac
case "$WG_B_IP" in 172.20.*) err "wg0 alma3 no debe ser 172.20.* (VPN mal asignada)"; exit 5;; esac

# 6) ping wg↔wg obligatorio (debe funcionar mediado por el orquestador)
assert_ping "$ALMA2_NAME" "$WG_B_IP" "ping alma2→alma3 (wg, mediado por orquestador)"
assert_ping "$ALMA3_NAME" "$WG_A_IP" "ping alma3→alma2 (wg, mediado por orquestador)"

ok "[S3] COMPLETO: sin conectividad directa en ningún sentido, conexión mediada por orquestador, wg0 con IP y ping wg↔wg OK"

