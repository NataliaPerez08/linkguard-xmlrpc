#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "${HERE}/_lib_cli.sh"

# --- wrapper argv-seguro ---
run_cli_q() { local svc="$1"; shift; local -a a=("$@"); local q=""; for x in "${a[@]}"; do q+=$(printf "%q " "$x"); done; log "[$svc] CLI(argv): ${CLI_BIN} ${q}"; rin "$svc" "cd '${CLI_DIR:-/shared/Cliente}' && ${CLI_BIN} ${q}"; }

# --- helpers ---
wait_wg_ip(){ local svc="$1" t=60; for _ in $(seq 1 $t); do rin "$svc" "ip -o -4 a s dev wg0 2>/dev/null|grep -q ' inet '" && return 0 || sleep 1; done; return 1; }
wg_addr_ipv4(){ rin "$1" "ip -4 -o a s dev wg0 2>/dev/null|awk '{print \$4}'|cut -d/ -f1|head -n1"|tail -n1; }
assert_ping(){ local s="$1" d="$2" l="$3"; rin "$s" "ping -c1 -W2 $d >/dev/null"; log "✅ $l: OK"; }

# --- params (overridable por env) ---
USR_NAME="${USR_NAME:-n1_3p}"; USR_EMAIL="${USR_EMAIL:-n1_3p}"; USR_PASS="${USR_PASS:-pas}"
VPN_NAME="${VPN_NAME:-vpn1_3p}"; NET_ID="${NET_ID:-0}"

ALMA2_NAME="${ALMA2_NAME:-alma2}"; ALMA3_NAME="${ALMA3_NAME:-alma3}"; ALMA4_NAME="${ALMA4_NAME:-alma4}"
ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"; ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"; ALMA4_IP_C="${ALMA4_IP_C:-172.20.0.13}"
WG_PORT_A="${WG_PORT_A:-51820}"; WG_PORT_B="${WG_PORT_B:-51821}"; WG_PORT_C="${WG_PORT_C:-51822}"

# --- prechecks ---
ensure_tools "$ALMA1_NAME"; ensure_tools "$ALMA2_NAME"; ensure_tools "$ALMA3_NAME"; ensure_tools "$ALMA4_NAME"
rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>'" || { err "server NO escucha en ${SERVER_PORT}"; exit 2; }

log "[S1-3P] registrar_usuario → crear_red_privada → registrar 3 peers → esperar wg0 → ping wg (malla)"

# 1) usuario y red
run_cli_q "$ALMA2_NAME" registrar_usuario "$USR_NAME" "$USR_EMAIL" "$USR_PASS" || true
run_cli_q "$ALMA2_NAME" crear_red_privada "$VPN_NAME"

# 2) registrar 3 peers (firma exacta)
run_cli_q "$ALMA2_NAME" registrar_como_peer "e1" "$NET_ID" "$ALMA2_IP_C" "$WG_PORT_A"
run_cli_q "$ALMA3_NAME" registrar_como_peer "e2" "$NET_ID" "$ALMA3_IP_C" "$WG_PORT_B"
run_cli_q "$ALMA4_NAME" registrar_como_peer "e3" "$NET_ID" "$ALMA4_IP_C" "$WG_PORT_C"

# 3) esperar wg0 en los tres
wait_wg_ip "$ALMA2_NAME" || { err "alma2: wg0 sin IP"; exit 3; }
wait_wg_ip "$ALMA3_NAME" || { err "alma3: wg0 sin IP"; exit 3; }
wait_wg_ip "$ALMA4_NAME" || { err "alma4: wg0 sin IP"; exit 3; }

WG_A="$(wg_addr_ipv4 "$ALMA2_NAME")"; WG_B="$(wg_addr_ipv4 "$ALMA3_NAME")"; WG_C="$(wg_addr_ipv4 "$ALMA4_NAME")"
for ip in "$WG_A" "$WG_B" "$WG_C"; do case "$ip" in 172.20.*) err "wg0 no debe ser 172.20.* (VPN mal asignada): $ip"; exit 5;; esac; done
log "[S1-3P] wg0: A=$WG_A B=$WG_B C=$WG_C"

# 4) malla de pings wg (A↔B, B↔C, C↔A)
assert_ping "$ALMA2_NAME" "$WG_B" "A→B (wg)"; assert_ping "$ALMA3_NAME" "$WG_A" "B→A (wg)"
assert_ping "$ALMA3_NAME" "$WG_C" "B→C (wg)"; assert_ping "$ALMA4_NAME" "$WG_B" "C→B (wg)"
assert_ping "$ALMA4_NAME" "$WG_A" "C→A (wg)"; assert_ping "$ALMA2_NAME" "$WG_C" "A→C (wg)"

ok "[S1-3P] OK — 3 peers en malla con pings wg en ambas direcciones"
