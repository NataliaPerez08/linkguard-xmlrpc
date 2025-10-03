#!/usr/bin/env bash
set -euo pipefail

# ===== Config por defecto (puedes overridear al invocar el script principal) =====
SERVER_IP="${SERVER_IP:-172.20.0.10}"
SERVER_PORT="${SERVER_PORT:-8080}"

ALMA2_IP="${ALMA2_IP:-172.20.0.11}"
ALMA3_IP="${ALMA3_IP:-172.20.0.12}"

CLI_BIN="${CLI_BIN:-python3 /shared/WG/Cliente/main.py}"   # <-- tu CLI

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/shared/tests/artifacts}"
mkdir -p "${ARTIFACTS_DIR}"

timestamp() { date +'%F %T'; }
log()  { echo "[$(timestamp)] $*" | tee -a "${LOG_FILE}"; }
ok()   { echo "✅ $*" | tee -a "${LOG_FILE}"; }
err()  { echo "❌ $*" | tee -a "${LOG_FILE}"; }

# Ejecuta dentro de un servicio (alma2 o alma3) en shell no interactivo
rin() {
  local svc="$1"; shift
  docker compose exec -T "$svc" bash -lc "$*" 2>&1
}

# Ejecuta comando del CLI dentro de un servicio
run_cli() {
  local svc="$1"; shift
  local cmd="$*"
  log "[$svc] CLI: $cmd"
  rin "$svc" "$cmd"
}

# Parsers simples de IDs desde stdout (si no tienes --json)
extract_uuid_like() {
  # uuid, id_*, o token >= 12 chars (mejorable si más info)
  grep -oE '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|id_[A-Za-z0-9._-]+|[A-Za-z0-9._-]{12,})' | head -n1
}

# Prepara herram. básicas en el contenedor
ensure_tools() {
  local svc="$1"
  rin "$svc" "command -v nc >/dev/null 2>&1 || (apt-get update && apt-get install -y netcat-openbsd >/dev/null 2>&1 || yum install -y nmap-ncat >/dev/null 2>&1 || true)"
  rin "$svc" "command -v arping >/dev/null 2>&1 || (apt-get update && apt-get install -y iputils-arping >/dev/null 2>&1 || yum install -y arping >/dev/null 2>&1 || true)"
}
