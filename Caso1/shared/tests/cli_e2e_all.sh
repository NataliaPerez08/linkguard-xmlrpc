#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Carga lib host→docker
# Asegúrate de llamarlo desde el host: bash ./shared/tests/cli_e2e_all.sh
source "${HERE}/_lib_cli.sh"

RUN="$(date +%s)"
USERA="user_${RUN}_A"
EMAILA="u${RUN}_A@example.com"
PASSA="S3cret_${RUN}_A"

USERB="user_${RUN}_B"
EMAILB="u${RUN}_B@example.com"
PASSB="S3cret_${RUN}_B"

VPN_NAME="vg_${RUN}"
VPN_SEGMENT_A="${VPN_SEGMENT_A:-10.$((RANDOM%200+20)).$((RANDOM%200)).0}"
VPN_MASK_A="${VPN_MASK_A:-24}"

WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

ALMA2_IP_C="${ALMA2_IP_C:-172.20.0.11}"
ALMA3_IP_C="${ALMA3_IP_C:-172.20.0.12}"

trap 'echo "[E2E] FAIL (trap)"; exit 1' ERR

# --- Helpers de red (simulan NAT/bloqueo peer-to-peer) ---

chain_setup() {
  local svc="$1"
  rin "$svc" '
    iptables -N E2E_BLOCK 2>/dev/null || true
    iptables -D INPUT  -j E2E_BLOCK 2>/dev/null || true
    iptables -D OUTPUT -j E2E_BLOCK 2>/dev/null || true
    iptables -I INPUT  1 -j E2E_BLOCK
    iptables -I OUTPUT 1 -j E2E_BLOCK
    iptables -F E2E_BLOCK
  '
}

chain_clear() {
  local svc="$1"
  rin "$svc" '
    iptables -F E2E_BLOCK 2>/dev/null || true
    iptables -D INPUT  -j E2E_BLOCK 2>/dev/null || true
    iptables -D OUTPUT -j E2E_BLOCK 2>/dev/null || true
  '
}

# Bloquea tráfico directo entre dos IPs (ambas direcciones)
block_pair() {
  local svc="$1" other_ip="$2"
  rin "$svc" "iptables -A E2E_BLOCK -d ${other_ip} -j REJECT; iptables -A E2E_BLOCK -s ${other_ip} -j REJECT"
}

# Bloquea SOLO entradas desde una IP (simula “no tengo IP pública”)
block_inbound_from() {
  local svc="$1" other_ip="$2"
  rin "$svc" "iptables -A E2E_BLOCK -s ${other_ip} -j REJECT"
}

# --- Generación de llaves WireGuard dentro de cada peer ---
gen_wg_keys() {
  local svc="$1" prefix="$2"
  rin "$svc" "umask 077; wg genkey | tee /tmp/${prefix}_priv.key | wg pubkey > /tmp/${prefix}_pub.key"
  local pub priv
  pub="$(rin "$svc" "cat /tmp/${prefix}_pub.key" | tail -n1)"
  priv="$(rin "$svc" "cat /tmp/${prefix}_priv.key" | tail -n1)"
  echo "${pub}|${priv}"
}

# --- Invocadores CLI (encapsulan tu main.py) ---
cli_a2() { run_cli "$ALMA2_NAME" "${CLI_BIN} $*"; }
cli_a3() { run_cli "$ALMA3_NAME" "${CLI_BIN} $*"; }

# --- Checks básicos ---
smoke() {
  ensure_tools "$ALMA1_NAME"
  ensure_tools "$ALMA2_NAME"
  ensure_tools "$ALMA3_NAME"
  rin "$ALMA1_NAME" "ss -tlpn | grep -q ':${SERVER_PORT}\\>' && echo 'server escucha ${SERVER_PORT}' || (echo 'server NO escucha' && exit 1)"
  rin "$ALMA2_NAME" "nc -vz ${SERVER_IP} ${SERVER_PORT} || true"
  rin "$ALMA3_NAME" "nc -vz ${SERVER_IP} ${SERVER_PORT} || true"
}

# --- Flujo de negocio base: registrar → login → crear red → registrar peers → init WG → conectar ---
workflow_core() {
  log "[SCN] Registrar usuarios y login"
  cli_a2 "registrar_usuario ${USERA} ${EMAILA} ${PASSA}" || true
  cli_a2 "identificar_usuario ${EMAILA} ${PASSA}"
  cli_a2 "whoami"

  cli_a3 "registrar_usuario ${USERB} ${EMAILB} ${PASSB}" || true
  cli_a3 "identificar_usuario ${EMAILB} ${PASSB}"
  cli_a3 "whoami"

  log "[SCN] Crear red privada (con segmento)"
  NET_ID="$(cli_a2 "crear_red_privada ${VPN_NAME} ${VPN_SEGMENT_A}" | extract_uuid_like || true)"
  if [[ -z "${NET_ID:-}" ]]; then
    # fallback si no acepta segmento
    NET_ID="$(cli_a2 "crear_red_privada ${VPN_NAME}" | extract_uuid_like || true)"
  fi
  [[ -n "${NET_ID:-}" ]] || { err "No pude obtener NET_ID"; exit 2; }
  log "NET_ID=${NET_ID}"

  log "[SCN] Ver redes/endpoints"
  cli_a2 "ver_redes_privadas"
  cli_a3 "ver_redes_privadas"
  EP_LST="$(cli_a2 "ver_endpoints ${NET_ID}" || true)"
  echo "$EP_LST" | sed -n '1,120p' | tee -a "${ARTIFACTS_DIR}/endpoints_${RUN}.log"

  log "[SCN] Registrar peers y preparar WireGuard"
  # Generar llaves WG en cada peer
  A_KEYS="$(gen_wg_keys "$ALMA2_NAME" "a2")"; A_PUB="${A_KEYS%%|*}"; A_PRIV="${A_KEYS##*|}"
  B_KEYS="$(gen_wg_keys "$ALMA3_NAME" "a3")"; B_PUB="${B_KEYS%%|*}"; B_PRIV="${B_KEYS##*|}"

  # Registrar como peer ante el orquestador
  # python3 main.py registrar_como_peer <nombre> <id_red_privada> <ip_cliente> <puerto_cliente> 
  #cli_a2 "registrar_como_peer peer_alma2 ${NET_ID} ${ALMA2_IP_C} ${WG_PORT_A}"
  cli_a2 "registrar_como_peer peer_alma2 0 ${ALMA2_IP_C} ${WG_PORT_A}"
  cli_a3 "registrar_como_peer peer_alma3 ${NET_ID} ${ALMA3_IP_C} ${WG_PORT_B}"

  # Inicializar interfaces (suponiendo que tu CLI crea wg0 con esa IP)
  #cli_a2 "init_wireguard_interfaz ${ALMA2_IP_C}"
  #cli_a3 "init_wireguard_interfaz ${ALMA3_IP_C}"

  # Crear peer con llaves/allowed-ips (cada lado)
  cli_a2 "crear_peer ${A_PUB} ${VPN_SEGMENT_A}/$VPN_MASK_A ${ALMA2_IP_C} ${WG_PORT_A}"
  cli_a3 "crear_peer ${B_PUB} ${VPN_SEGMENT_A}/$VPN_MASK_A ${ALMA3_IP_C} ${WG_PORT_B}"

  ok "Core listo (NET_ID=${NET_ID})"
}

# --- Acciones por escenario ---
escenario_1_todos_alcanzables() {
  log "[ESCENARIO 1] Todos alcanzables (limpiando filtros)"
  chain_setup "$ALMA2_NAME"; chain_clear "$ALMA2_NAME"
  chain_setup "$ALMA3_NAME"; chain_clear "$ALMA3_NAME"

  workflow_core

  log "[S1] Conectar directo por IP/puerto (p2p)"
  cli_a2 "conectar_endpoint_directo ${ALMA3_IP_C} ${WG_PORT_B}" || true
  cli_a3 "conectar_endpoint_directo ${ALMA2_IP_C} ${WG_PORT_A}" || true
}

escenario_2_uno_no_publico() {
  log "[ESCENARIO 2] Uno sin IP pública (bloquear entrante a alma3 desde alma2)"
  chain_setup "$ALMA2_NAME"; chain_clear "$ALMA2_NAME"
  chain_setup "$ALMA3_NAME"; chain_clear "$ALMA3_NAME"
  # alma3 no acepta tráfico entrante desde alma2 (simula NAT entrante)
  block_inbound_from "$ALMA3_NAME" "$ALMA2_IP_C"

  workflow_core

  log "[S2] Conexión mediada por Orquestador (IDs)"
  # Si necesitas ID de endpoint, intenta inferir del listado:
  EP_A="$(cli_a2 "ver_endpoints ${NET_ID}" | extract_uuid_like || true)"
  EP_B="$(cli_a3 "ver_endpoints ${NET_ID}" | extract_uuid_like || true)"
  [[ -n "${EP_A:-}" ]] && cli_a2 "conectar_endpoint ${EP_A} ${NET_ID}" || true
  [[ -n "${EP_B:-}" ]] && cli_a3 "conectar_endpoint ${EP_B} ${NET_ID}" || true
}

escenario_3_solo_orquestador() {
  log "[ESCENARIO 3] Solo Orquestador alcanzable (bloqueo total p2p)"
  chain_setup "$ALMA2_NAME"; chain_clear "$ALMA2_NAME"; block_pair "$ALMA2_NAME" "$ALMA3_IP_C"
  chain_setup "$ALMA3_NAME"; chain_clear "$ALMA3_NAME"; block_pair "$ALMA3_NAME" "$ALMA2_IP_C"

  workflow_core

  log "[S3] Forzar conexión via Orquestador (sin p2p)"
  EP_A="$(cli_a2 "ver_endpoints ${NET_ID}" | extract_uuid_like || true)"
  EP_B="$(cli_a3 "ver_endpoints ${NET_ID}" | extract_uuid_like || true)"
  [[ -n "${EP_A:-}" ]] && cli_a2 "conectar_endpoint ${EP_A} ${NET_ID}" || true
  [[ -n "${EP_B:-}" ]] && cli_a3 "conectar_endpoint ${EP_B} ${NET_ID}" || true
}

# --- Casos extra: editar / borrar ---
editar_y_borrar() {
  log "[EXTRA] Editar red (segmento/nombre/allowed_ips) y borrar peer/red"
  cli_a2 "editar_red_privada ${NET_ID} ${VPN_SEGMENT_A} ${VPN_MASK_A}" || true
  cli_a2 "editar_nombre_red_privada ${NET_ID} ${VPN_NAME}_renamed" || true
  cli_a2 "edit_allow_ips ${NET_ID} ${VPN_SEGMENT_A}/${VPN_MASK_A}" || true

  # Intento de edición de endpoint (si tu CLI lo soporta)
  cli_a2 "editar_red_peer ${NET_ID} endpoint_alma2" || true
  cli_a2 "edit_endpoint_port ${NET_ID} endpoint_alma2 ${WG_PORT_A}" || true

  # Limpieza
  cli_a2 "borrar_red_privada ${NET_ID}" || true
}

# --- MAIN ---
log "[E2E] Smoke inicial"
smoke

log "[E2E] ESCENARIO 1"
escenario_1_todos_alcanzables

log "[E2E] ESCENARIO 2"
escenario_2_uno_no_publico

log "[E2E] ESCENARIO 3"
escenario_3_solo_orquestador

log "[E2E] Editar/Borrar"
editar_y_borrar

ok "[E2E] COMPLETO (RUN=${RUN})"
