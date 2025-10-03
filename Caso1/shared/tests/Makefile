.PHONY: up down logs sanity e2e test sh1 sh2 sh3 clean

up:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=200

# (Opcional) Sanity previo si ya lo tienes creado como shared/tests/sanity.sh
sanity:
	SERVER_IP=172.20.0.10 SERVER_PORT=8000 bash ./sanity.sh

# Solo las pruebas de CLI (desde alma2 y alma3)
e2e:
	docker compose exec -T alma2 bash -lc "bash /shared/tests/cli_e2e_all.sh"

# Pipeline completo: Sanity -> E2E (fail-fast si sanity falla)
test:
	SERVER_IP=172.20.0.10 SERVER_PORT=8080 bash /shared/tests/sanity.sh
	docker compose exec -T alma2 bash -lc "bash /shared/tests/cli_e2e_all.sh"

sh1:
	docker compose exec alma1 bash
sh2:
	docker compose exec alma2 bash
sh3:
	docker compose exec alma3 bash

clean: down
	rm -rf shared/tests/artifacts || true


# make up            # levanta alma1, alma2, alma3
# make test          # (Sanity -> E2E) o usa 'make e2e' para solo la suite CLI
# make logs          # revisar logs si algo falla