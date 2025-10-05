SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

SERVER_IP    ?= 172.20.0.10
SERVER_PORT  ?= 8080
ARTIFACTS_DIR ?= ./shared/tests/artifacts
SANITY_SCRIPT ?= ./sanity.sh
E2E_SCRIPT    ?= /shared/tests/cli_e2e_all.sh

S ?= alma2
CMD ?= "bash"

ALMA1 ?= alma1
ALMA2 ?= alma2
ALMA3 ?= alma3

.PHONY: up down logs ps restart sanity e2e test sh1 sh2 sh3 exec copy wait clean build rebuild pull help

# ---------- Ciclo de vida ----------
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v

build:
	$(COMPOSE) build

rebuild:
	$(COMPOSE) build --no-cache

pull:
	$(COMPOSE) pull

ps:
	$(COMPOSE) ps

restart:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f --tail=200

# ---------- Helpers ----------
wait:
	@echo "Esperando a que $(S) esté RUNNING..."
	@for i in {1..50}; do \
		state="$$( $(COMPOSE) ps --status running --services | grep -x '$(S)' || true )"; \
		if [[ -n "$$state" ]]; then echo "OK: $(S) RUNNING"; exit 0; fi; \
		sleep 1; \
	done; \
	echo "FALLO: $(S) no llegó a RUNNING a tiempo" >&2; \
	exit 1

exec:
	@if docker exec -T $(S) bash -lc "true" >/dev/null 2>&1; then \
		docker exec -T $(S) bash -lc $(CMD); \
	else \
		$(COMPOSE) exec -T $(S) bash -lc $(CMD); \
	fi

SRC ?=
DST ?=
copy:
	@if [ -z "$(SRC)" ] || [ -z "$(DST)" ]; then \
		echo "Usa: make copy S=alma2 SRC=./local DST=/remote/path"; exit 2; \
	fi
	@cid="$$(docker ps --format '{{.Names}}' | grep -x '$(S)' || true)"; \
	if [[ -n "$$cid" ]]; then \
		docker cp $(SRC) $(S):$(DST); \
	else \
		cid="$$( $(COMPOSE) ps -q $(S) )"; \
		if [[ -z "$$cid" ]]; then echo "No encuentro $(S)"; exit 2; fi; \
		docker cp $(SRC) $$cid:$(DST); \
	fi

# ---------- Pruebas ----------
sanity:
	@mkdir -p $(ARTIFACTS_DIR)
	@echo "== SANITY =="
	SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) bash $(SANITY_SCRIPT)

e2e: wait
	@echo "== E2E en $(S) =="
	$(COMPOSE) exec -T $(S) bash -lc 'set -euxo pipefail; timeout 180s bash /shared/tests/cli_e2e_all.sh'


test: sanity
	@echo "== TEST (E2E) en alma2 =="
	$(COMPOSE) exec -T $(ALMA2) bash -lc "bash $(E2E_SCRIPT)"

# ---------- Shells ----------
sh1:
	$(COMPOSE) exec $(ALMA1) bash
sh2:
	$(COMPOSE) exec $(ALMA2) bash
sh3:
	$(COMPOSE) exec $(ALMA3) bash

# ---------- Limpieza ----------
clean: down
	rm -rf $(ARTIFACTS_DIR) || true

# ---------- Ayuda ----------
help:
	@echo "Targets comunes:"
	@echo "  make up / down / logs / ps / restart"
	@echo "  make build / rebuild / pull"
	@echo "  make sanity            # corre sanity.sh con SERVER_IP/PORT=8080"
	@echo "  make e2e S=alma3       # corre E2E en el servicio indicado"
	@echo "  make test              # sanity -> E2E (default alma2)"
	@echo "  make exec S=alma2 CMD='ip addr'"
	@echo "  make copy S=alma2 SRC=./file DST=/tmp/"
	@echo "  make wait S=alma3      # espera a RUNNING"
	@echo "  make sh1|sh2|sh3       # shells"


# make up            # levanta alma1, alma2, alma3
# make test          # (Sanity -> E2E) o usa 'make e2e' para solo la suite CLI
# make logs          # revisar logs si algo falla