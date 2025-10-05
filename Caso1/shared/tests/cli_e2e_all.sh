#!/usr/bin/env bash
set -euxo pipefail

# === Contexto: dentro de alma2 ===
: "${SERVER_IP:=172.20.0.10}"
: "${SERVER_PORT:=8000}"
: "${ARTIFACTS_DIR:=/shared/tests/artifacts}"
mkdir -p "$ARTIFACTS_DIR"

timestamp() { date +'%F %T'; }
log()  { echo "[$(timestamp)] $*"; }
ok()   { echo "✅ $*"; }
err()  { echo "❌ $*" >&2; }

# IMPORTANTÍSIMO: NADA DE DOCKER AQUÍ DENTRO.
rin() {  # ejecuta local, sin docker
  bash -lc "$*" 2>&1
}

# Esperar a que el server esté escuchando (máx 30s)
wait_for_port() {
  local host="$1" port="$2" tries=30
  for i in $(seq 1 $tries); do
    if (command -v nc >/dev/null 2>&1 && nc -z "$host" "$port") || ss -tlpn | grep -q ":$port\\>"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

echo "[E2E] start en $(hostname) $(date)"
echo "[E2E] SERVER_IP=$SERVER_IP SERVER_PORT=$SERVER_PORT"

# Sanity de red
nc -vz "$SERVER_IP" "$SERVER_PORT" || true
wait_for_port "$SERVER_IP" "$SERVER_PORT" || { err "server no disponible en $SERVER_IP:$SERVER_PORT"; exit 2; }

# === TU SUITE AQUÍ ===
# Ejemplos:
# 1) Probar CLI cliente local (si aplica)
rin 'python3 /shared/Cliente/main.py whoami || true'


ok "[E2E] fin OK"
