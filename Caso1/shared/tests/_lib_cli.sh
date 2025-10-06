#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVER_IP="${SERVER_IP:-172.20.0.10}"
SERVER_PORT="${SERVER_PORT:-8000}"

ALMA1_NAME="${ALMA1_NAME:-alma1}"
ALMA2_NAME="${ALMA2_NAME:-alma2}"
ALMA3_NAME="${ALMA3_NAME:-alma3}"

CLI_BIN="${CLI_BIN:-python3 /shared/Cliente/main.py}"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-${ROOT_DIR}/artifacts}"
mkdir -p "${ARTIFACTS_DIR}"

LOG_FILE="${LOG_FILE:-${ARTIFACTS_DIR}/cli_test_$(date +%s).log}"

timestamp() { date +'%F %T'; }
log()  { echo "[$(timestamp)] $*" | tee -a "${LOG_FILE}"; }
ok()   { echo "✅ $*" | tee -a "${LOG_FILE}"; }
warn() { echo "⚠️  $*" | tee -a "${LOG_FILE}"; }
err()  { echo "❌ $*" | tee -a "${LOG_FILE}"; }

compose_exec() {
  local svc="$1"; shift
  if docker compose version >/dev/null 2>&1; then
    docker compose exec -T "$svc" bash -lc "$*" 2>&1
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose exec -T "$svc" bash -lc "$*" 2>&1
  else
    err "No encuentro 'docker compose' ni 'docker-compose' en el HOST."
    exit 127
  fi
}

rin() {
  local svc="$1"; shift
  local cmd="$*"
  if docker exec -T "$svc" bash -lc "true" >/dev/null 2>&1; then
    docker exec -T "$svc" bash -lc "$cmd" 2>&1
  else
    compose_exec "$svc" "$cmd"
  fi
}

run_cli() { local svc="$1"; shift; log "[$svc] CLI: $*"; rin "$svc" "${CLI_BIN} $*"; }

extract_uuid_like() {
  grep -oE '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|id_[A-Za-z0-9._-]+|[A-Za-z0-9._-]{12,})' | head -n1
}

ensure_tools() {
  local svc="$1"
  rin "$svc" 'command -v ncat >/dev/null 2>&1 || command -v nc >/dev/null 2>&1 || \
    ( { command -v dnf >/dev/null 2>&1 && dnf -y install nmap-ncat >/dev/null 2>&1; } || \
      { command -v yum >/dev/null 2>&1 && yum -y install nmap-ncat   >/dev/null 2>&1; } || true )'
  rin "$svc" 'command -v ss >/dev/null 2>&1 || ( { command -v dnf >/dev/null 2>&1 && dnf -y install iproute >/dev/null 2>&1; } || true )'
  rin "$svc" 'command -v iptables >/dev/null 2>&1 || ( { command -v dnf >/dev/null 2>&1 && dnf -y install iptables >/dev/null 2>&1; } || true )'
  rin "$svc" 'command -v wg >/dev/null 2>&1 || ( { command -v dnf >/dev/null 2>&1 && dnf -y install wireguard-tools >/dev/null 2>&1; } || true )'
}
