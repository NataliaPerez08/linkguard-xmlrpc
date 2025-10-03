mkdir -p shared/tests
cat > shared/tests/run_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Variables del server (puedes overridearlas al invocar)
SERVER_IP="${SERVER_IP:-172.20.0.10}"
SERVER_PORT="${SERVER_PORT:-8080}"

echo "==[1/2] SANITY=="
SERVER_IP="$SERVER_IP" SERVER_PORT="$SERVER_PORT" bash shared/tests/sanity.sh

echo "==[2/2] E2E (dual)=="
docker compose exec -T alma2 bash -lc "bash /shared/tests/e2e_cli_dual.sh"
EOF

chmod +x shared/tests/run_all.sh
