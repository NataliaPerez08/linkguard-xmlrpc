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
assert_ping()  { local svc="$1" dst="$2" label="$3"; rin "$svc" "ping -c1 -W2 ${dst} >/dev/null"; log "✅ ${label}: OK"; }

# --- parámetros del caso (puedes sobreescribir por env si quieres) ---
USR_NAME="${USR_NAME:-n1}"
USR_EMAIL="${USR_EMAIL:-n1}"
USR_PASS="${USR_PASS:-pas}"
VPN_NAME="${VPN_NAME:-vpn1}"
NET_ID="0"                         # lo pides literal 0
ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"
ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"

WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

# --- prechecks básicos ---
ensure_tools "$ALMA1_NAME"
ensure_tools "$ALMA2_NAME"
ensure_tools "$ALMA3_NAME"
rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>'" || { err "server NO escucha en ${SERVER_PORT}"; exit 2; }

log "[S1] Flujo exacto requerido: registrar_usuario → crear_red_privada → registrar_como_peer(A) → registrar_como_peer(B) → ping"

# 1) registrar_usuario (desde alma2, como referencia)
run_cli_q "$ALMA2_NAME" registrar_usuario "$USR_NAME" "$USR_EMAIL" "$USR_PASS" || true

# 2) crear_red_privada vpn1 (desde alma2)
run_cli_q "$ALMA2_NAME" crear_red_privada "$VPN_NAME"

# 3) registrar_como_peer en alma2 y alma3 (USANDO EL ORDEN EXACTO)
#    python3 main.py registrar_como_peer <nombre> <id_red_privada> <ip_cliente> <puerto_cliente>
run_cli_q "$ALMA2_NAME" registrar_como_peer "e1" "$NET_ID" "$ALMA2_IP_C" "$WG_PORT_A"
run_cli_q "$ALMA3_NAME" registrar_como_peer "e1" "$NET_ID" "$ALMA3_IP_C" "$WG_PORT_B"

# 4) esperar a que el orquestador empuje config y aparezca wg0 con IP
log "[S1] Esperando wg0 con IP en ambos clientes…"
wait_wg_ip "$ALMA2_NAME" || { err "alma2: wg0 sin IP tras timeout"; exit 3; }
wait_wg_ip "$ALMA3_NAME" || { err "alma3: wg0 sin IP tras timeout"; exit 3; }

WG_A_IP="$(wg_addr_ipv4 "$ALMA2_NAME")"
WG_B_IP="$(wg_addr_ipv4 "$ALMA3_NAME")"
log "[S1] wg0 alma2 = ${WG_A_IP} ; wg0 alma3 = ${WG_B_IP}"

# 5) prueba de conectividad (ping entre interfaces wg0) — obligatorio
assert_ping "$ALMA2_NAME" "$WG_B_IP" "ping alma2→alma3 (wg)"
assert_ping "$ALMA3_NAME" "$WG_A_IP" "ping alma3→alma2 (wg)"

ok "[S1] COMPLETO: usuario creado, vpn creada, endpoints registrados, wg0 con IP en ambos y ping ok"
