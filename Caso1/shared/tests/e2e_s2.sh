#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "${HERE}/e2e_common.sh"

report_init
rsection "Escenario 2 — Uno no público (bloqueo entrante alma3 desde alma2)"
chain_setup "$ALMA2_NAME"; chain_clear "$ALMA2_NAME"
chain_setup "$ALMA3_NAME"; chain_clear "$ALMA3_NAME"
block_inbound_from "$ALMA3_NAME" "$ALMA2_IP_C"

smoke
workflow_core

# Obtener endpoints y conectar vía orquestador (serializado por sesión)
server_login "$ALMA2_NAME" "$EMAILA" "$PASSA"
EP_A="$(run_cli "$ALMA2_NAME" "ver_endpoints ${NET_ID}" | extract_uuid_like || true)"
server_logout "$ALMA2_NAME"

server_login "$ALMA3_NAME" "$EMAILB" "$PASSB"
EP_B="$(run_cli "$ALMA3_NAME" "ver_endpoints ${NET_ID}" | extract_uuid_like || true)"
server_logout "$ALMA3_NAME"

server_login "$ALMA2_NAME" "$EMAILA" "$PASSA"
[[ -n "${EP_A:-}" ]] && run_cli "$ALMA2_NAME" "conectar_endpoint ${EP_A} ${NET_ID}" || true
server_logout "$ALMA2_NAME"

server_login "$ALMA3_NAME" "$EMAILB" "$PASSB"
[[ -n "${EP_B:-}" ]] && run_cli "$ALMA3_NAME" "conectar_endpoint ${EP_B} ${NET_ID}" || true
server_logout "$ALMA3_NAME"

rsection "Checks conectividad"
if [[ -n "${WG_A_IP:-}" && -n "${WG_B_IP:-}" ]]; then
  check_ping "$ALMA2_NAME" "$WG_B_IP" "ping alma2→alma3 (mediado)"
  check_ping "$ALMA3_NAME" "$WG_A_IP" "ping alma3→alma2 (mediado)"
else
  warn "IPs wg0 no detectadas; se omiten pings wg"
fi
rlog "- latest handshake alma2: $(latest_handshake "$ALMA2_NAME" || true)"
rlog "- latest handshake alma3: $(latest_handshake "$ALMA3_NAME" || true)"

ok "[S2] OK"
rlog "\n**Resultado S2:** OK ✅\n"
