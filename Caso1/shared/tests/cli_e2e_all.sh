#!/usr/bin/env bash
set -euo pipefail
source /shared/tests/_lib_cli.sh

RUN="$(date +%s)"
LOG_FILE="${ARTIFACTS_DIR}/cli_e2e_${RUN}.log"
VARS_FILE="${ARTIFACTS_DIR}/cli_e2e_${RUN}.env"
: >"${VARS_FILE}"

save_var(){ echo "export $1=\"$2\"" >> "${VARS_FILE}"; log "SET $1=$2"; }

# Datos de prueba
USER1="user_${RUN}_1"; EMAIL1="u${RUN}_1@example.com"; PASS1="S3cret_${RUN}_1"
USER2="user_${RUN}_2"; EMAIL2="u${RUN}_2@example.com"; PASS2="S3cret_${RUN}_2"

VPN_NAME="vg_${RUN}"
VPN_SEGMENT_A="10.200.$((RANDOM%200)).0" ; VPN_MASK_A="24"

# Puertos clientes (diferentes para que no choquen)
ALMA2_PORT="${ALMA2_PORT:-51820}"
ALMA3_PORT="${ALMA3_PORT:-51821}"

# Claves/allowed (dummy)
PUBKEY1="PUB_${RUN}_1"
PUBKEY2="PUB_${RUN}_2"
ALLOWED1="10.10.$((RANDOM%200)).0/24,10.11.$((RANDOM%200)).0/24"
ALLOWED2="10.12.$((RANDOM%200)).0/24,10.13.$((RANDOM%200)).0/24"

clients=( "alma2:${ALMA2_IP}:${ALMA2_PORT}:${USER1}:${EMAIL1}:${PASS1}" \
          "alma3:${ALMA3_IP}:${ALMA3_PORT}:${USER2}:${EMAIL2}:${PASS2}" )

log "=== CLI E2E START (RUN=${RUN}) ==="

# Asegura herramientas mínimas
ensure_tools "alma2"
ensure_tools "alma3"

# 0) Pre-chequeo rápido: reachability al server
for c in "${clients[@]}"; do
  IFS=':' read -r svc cip cport uname email pass <<< "$c"
  log "--- precheck $svc ---"
  rin "$svc" "ip route | sed -n '1,80p' " | tee -a "${LOG_FILE}"
  if ! rin "$svc" "nc -vz ${SERVER_IP} ${SERVER_PORT} </dev/null"; then
    err "$svc no alcanza ${SERVER_IP}:${SERVER_PORT} — revisa red/compose/healthcheck"
  fi
done

# 1) Registrar usuarios en cada cliente; login; whoami
for c in "${clients[@]}"; do
  IFS=':' read -r svc cip cport uname email pass <<< "$c"
  out="$(run_cli "$svc" "$CLI_BIN registrar_usuario $uname $email $pass")" || true
  UID="$(echo "$out" | extract_uuid_like || true)"; [[ -n "${UID:-}" ]] && save_var "${svc}_USER_ID" "$UID"
  run_cli "$svc" "$CLI_BIN identificar_usuario $email $pass"
  run_cli "$svc" "$CLI_BIN whoami"
done

# 2) Crear red SIN segmento (desde alma2) y CON segmento (desde alma2)
out="$(run_cli alma2 "$CLI_BIN crear_red_privada ${VPN_NAME}")" || true
RED_ID="$(echo "$out" | extract_uuid_like || true)"; [[ -n "${RED_ID:-}" ]] && save_var RED_ID "$RED_ID"

out="$(run_cli alma2 "$CLI_BIN crear_red_privada ${VPN_NAME}_seg ${VPN_SEGMENT_A}/${VPN_MASK_A}")" || true
RED_SEG_ID="$(echo "$out" | extract_uuid_like || true)"; [[ -n "${RED_SEG_ID:-}" ]] && save_var RED_SEG_ID "$RED_SEG_ID"

run_cli alma2 "$CLI_BIN ver_redes_privadas"
[[ -n "${RED_ID:-}" ]] && run_cli alma2 "$CLI_BIN ver_endpoints ${RED_ID}"

# 3) Registrar ambos clientes como peer en RED_ID y conectar
for c in "${clients[@]}"; do
  IFS=':' read -r svc cip cport uname email pass <<< "$c"
  out="$(run_cli "$svc" "$CLI_BIN registrar_como_peer ${uname}_peer ${RED_ID} ${cip} ${cport}")" || true
  EP_ID="$(echo "$out" | extract_uuid_like || true)"
  [[ -n "${EP_ID:-}" ]] && save_var "${svc}_EP_ID" "$EP_ID"
  [[ -n "${EP_ID:-}" ]] && run_cli "$svc" "$CLI_BIN conectar_endpoint ${EP_ID} ${RED_ID}"
done

# 4) Conexión directa al server (handshake inicial)
run_cli alma2 "$CLI_BIN conectar_endpoint_directo ${SERVER_IP} 51820" || true
run_cli alma3 "$CLI_BIN conectar_endpoint_directo ${SERVER_IP} 51820" || true

# 5) Consultar IP pública, init WG, crear peer manual (uno por cliente)
run_cli alma2 "$CLI_BIN consultar_ip_publica_cliente"
run_cli alma3 "$CLI_BIN consultar_ip_publica_cliente"

run_cli alma2 "$CLI_BIN init_wireguard_interfaz ${ALMA2_IP}"
run_cli alma3 "$CLI_BIN init_wireguard_interfaz ${ALMA3_IP}"

run_cli alma2 "$CLI_BIN crear_peer ${PUBKEY1} ${ALLOWED1} ${ALMA2_IP} 51920"
run_cli alma3 "$CLI_BIN crear_peer ${PUBKEY2} ${ALLOWED2} ${ALMA3_IP} 51921"

# 6) Ediciones de red (segmento/máscara, nombre, allowed_ips)
if [[ -n "${RED_ID:-}" ]]; then
  run_cli alma2 "$CLI_BIN editar_red_privada ${RED_ID} ${VPN_SEGMENT_A} 23"     # cambia segmento/máscara
  run_cli alma2 "$CLI_BIN editar_nombre_red_privada ${RED_ID} ${VPN_NAME}_EDIT" # cambia nombre
  run_cli alma2 "$CLI_BIN edit_allow_ips ${RED_ID} 10.250.0.0/16,10.251.0.0/16" # allowed list
fi

# 7) Ediciones de endpoint (IP, puerto, nombre) para cada cliente si tenemos EP_ID
for c in "${clients[@]}"; do
  IFS=':' read -r svc cip cport uname email pass <<< "$c"
  EP_VAR="${svc}_EP_ID"
  EP_ID="$(grep -oP "(?<=^export ${EP_VAR}=\").*(?=\"$)" "${VARS_FILE}" || true)"
  if [[ -n "${EP_ID:-}" && -n "${RED_ID:-}" ]]; then
    run_cli "$svc" "$CLI_BIN editar_red_peer ${RED_ID} ${EP_ID}"
    run_cli "$svc" "$CLI_BIN edit_endpoint ${RED_ID} ${EP_ID} 8.8.8.8"
    run_cli "$svc" "$CLI_BIN edit_endpoint_port ${RED_ID} ${EP_ID} $((cport+100))"
    run_cli "$svc" "$CLI_BIN editar_endpoint_name ${RED_ID} ${EP_ID} ep_${svc}_${RUN}"
  fi
done

# 8) Borrados (peer y red secundaria con segmento)
for c in "${clients[@]}"; do
  IFS=':' read -r svc cip cport uname email pass <<< "$c"
  EP_VAR="${svc}_EP_ID"
  EP_ID="$(grep -oP "(?<=^export ${EP_VAR}=\").*(?=\"$)" "${VARS_FILE}" || true)"
  if [[ -n "${EP_ID:-}" && -n "${RED_ID:-}" ]]; then
    run_cli "$svc" "$CLI_BIN borrar_red_peer ${RED_ID} ${EP_ID}" || true
  fi
done

[[ -n "${RED_SEG_ID:-}" ]] && run_cli alma2 "$CLI_BIN borrar_red_privada ${RED_SEG_ID}" || true

# 9) Cerrar sesión en ambos clientes
for c in "${clients[@]}"; do
  IFS=':' read -r svc _ _ _ email pass <<< "$c"
  run_cli "$svc" "$CLI_BIN cerrar_sesion"
done

ok "CLI E2E FIN. Artifacts:"
ok "  - ${LOG_FILE}"
ok "  - ${VARS_FILE}"
