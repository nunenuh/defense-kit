.PHONY: build docker-build docker-up docker-scan

build:
	cd defense-kit-cli && make build

docker-build: build
	cd docker && docker compose build

docker-up:
	cd docker && TARGET_PATH=$(TARGET_PATH) docker compose up -d

docker-scan:
	cd docker && docker compose exec defense-kit defense-kit scan

docker-down:
	cd docker && docker compose down
