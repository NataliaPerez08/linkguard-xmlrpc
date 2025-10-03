#!/usr/bin/env bash
set -euo pipefail

SERVER_IP="${SERVER_IP:-172.20.0.10}"
#SERVER_PORT="${SERVER_PORT:-8000}"

CLIENTS=("alma2" "alma3")

pass_cnt=0
fail_cnt=0
log()  { echo "[$(date +'%F %T')] $*"; }
ok()   { echo "$*"; ((pass_cnt++)) || true; }
err()  { echo "$*"; ((fail_cnt++)) || true; }

# Ejecuta dentro de un contenedor
run() {
  local svc="$1"; shift
  docker compose exec -T "$svc" bash -lc "$*" 2>&1
}

# Asegurar herramientas mínimas en cliente
ensure_tools() {
  local svc="$1"
  run "$svc" "command -v nc >/dev/null 2>&1 || (apt-get update && apt-get install -y netcat-openbsd >/dev/null 2>&1 || yum install -y nmap-ncat >/dev/null 2>&1 || true)"
  run "$svc" "command -v arping >/dev/null 2>&1 || (apt-get update && apt-get install -y iputils-arping >/dev/null 2>&1 || yum install -y arping >/dev/null 2>&1 || true)"
}

check_arp() {
  local svc="$1"
  if run "$svc" "ip neigh flush ${SERVER_IP} >/dev/null 2>&1; arping -c2 -I eth0 ${SERVER_IP}" | grep -qi "Received 0 response"; then
    err "$svc: ARP a ${SERVER_IP} SIN respuesta"
  else
    ok "$svc: ARP a ${SERVER_IP} OK"
  fi
}

check_ping() {
  local svc="$1"
  if run "$svc" "ping -c1 -W2 ${SERVER_IP} >/dev/null"; then
    ok "$svc: ping a ${SERVER_IP} OK"
  else
    err "$svc: ping a ${SERVER_IP} FALLÓ"
  fi
}

check_tcp() {
  local svc="$1"
  if run "$svc" "nc -vz ${SERVER_IP} ${SERVER_PORT} </dev/null"; then
    ok "$svc: TCP ${SERVER_IP}:${SERVER_PORT} OK"
  else
    err "$svc: TCP ${SERVER_IP}:${SERVER_PORT} NO accesible"
  fi
}

check_routes() {
  local svc="$1"
  local out
  out="$(run "$svc" "ip route show table main")" || true
  echo "$out" | grep -qE "^${SERVER_IP}/32|dev eth0|^172\.20\.0\.0/24" && ok "$svc: rutas locales visibles" || err "$svc: revisar rutas locales (tabla main)"
}

check_wg() {
  local svc="$1"
  # No fallar si no está instalado; es solo informativo
  if run "$svc" "command -v wg >/dev/null 2>&1"; then
    run "$svc" "wg show" || true
    if run "$svc" "ip -br link show | grep -E '^wg[0-9]';"; then
      ok "$svc: interfaz WireGuard presente"
    else
      log "$svc: wg no visible (aún) — informativo"
    fi
  else
    log "$svc: comando 'wg' no instalado — omitiendo chequeo WG"
  fi
}

log "=== SANITY START (server=${SERVER_IP}:${SERVER_PORT}) ==="

for c in "${CLIENTS[@]}"; do
  log "--- Preparando ${c} ---"
  ensure_tools "$c"

  log "--- ${c}: chequeos de conectividad ---"
  check_arp  "$c"
  check_ping "$c"
  check_tcp  "$c"
  check_routes "$c"
  check_wg "$c"
done

log "=== SANITY SUMMARY: PASS=${pass_cnt} FAIL=${fail_cnt} ==="
[[ $fail_cnt -eq 0 ]] || exit 1