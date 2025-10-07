SHELL := /usr/bin/env bash
COMPOSE ?= docker compose

SERVER_IP    ?= 172.20.0.10
SERVER_PORT  ?= 8080
TESTS_DIR    ?= shared/tests
ARTIFACTS    ?= $(TESTS_DIR)/artifacts

# -------- util --------
define wait_running
	@echo "Esperando a que $(1) esté RUNNING..."
	@for i in $$(seq 1 60); do \
	  s="$$( $(COMPOSE) ps --status=running -q $(1) )"; \
	  if [ -n "$$s" ]; then echo "OK: $(1) RUNNING"; exit 0; fi; \
	  sleep 1; \
	done; \
	echo "FALLO: $(1) no RUNNING"; exit 2
endef

.PHONY: up up3 down logs sh1 sh2 sh3 sh4 prune clean \
        sanity e2e-s1 e2e-s2 e2e-s3 \
        e2e-s1-3p e2e-s2-3p e2e-s3-3p

# ---------- infra ----------
up:     ## 2 peers (alma1, alma2, alma3)
	$(COMPOSE) up -d --build
	$(call wait_running,alma1)
	$(call wait_running,alma2)
	$(call wait_running,alma3)

up3:    ## 3 peers (activa perfil 'three' para alma4)
	$(COMPOSE) --profile three up -d --build
	$(call wait_running,alma1)
	$(call wait_running,alma2)
	$(call wait_running,alma3)
	$(call wait_running,alma4)

down:
	COMPOSE_PROFILES=three $(COMPOSE) down -v --remove-orphans

logs:
	$(COMPOSE) logs -f --tail=200

sh1: ; $(COMPOSE) exec alma1 bash
sh2: ; $(COMPOSE) exec alma2 bash
sh3: ; $(COMPOSE) exec alma3 bash
sh4: ; $(COMPOSE) --profile three exec alma4 bash

prune:  ## limpia Docker agresivo (cuidado)
	docker system prune -af --volumes || true

clean: down
	rm -rf $(ARTIFACTS) || true
	mkdir -p $(ARTIFACTS)

# ---------- sanity ----------
sanity:
	mkdir -p $(ARTIFACTS)
	SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) bash ./sanity.sh

# ---------- E2E (2 peers) ----------
e2e-s1:
	@SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) bash ./e2e_s1.sh
e2e-s2:
	@SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) bash ./e2e_s2.sh
e2e-s3:
	@SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) bash ./e2e_s3.sh

# ---------- E2E (3 peers) ----------
e2e-s1-3p:
	@SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) ./e2e_s1_3p.sh
e2e-s2-3p:
	@SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) ./e2e_s2_3p.sh
e2e-s3-3p:
	@SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) ./e2e_s3_3p.sh
