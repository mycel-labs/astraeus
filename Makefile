.PHONY: devnet-up
devnet-up:
	@docker compose --file ./compose.yaml up --detach

.PHONY: devnet-down
devnet-down:
	@docker compose --file ./compose.yaml down

.PHONY: run-go
run-go:
	@go run ./src/go/*
