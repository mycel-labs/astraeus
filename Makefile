.PHONY: devnet-up
devnet-up:
	@docker compose --file ./compose.yaml up --detach

.PHONY: devnet-down
devnet-down:
	@docker compose --file ./compose.yaml down

.PHONY: run-go
run-go:
	@cd src/go && go run main.go && cd ../../

.PHONY: run-proto
run-proto:
	@protoc -I./src/proto \
  --go_out=src/go/pb --go_opt=paths=source_relative \
  --go-grpc_out=src/go/pb --go-grpc_opt=paths=source_relative \
  --grpc-gateway_out=src/go/pb --grpc-gateway_opt=paths=source_relative \
  src/proto/transferable_account.proto
