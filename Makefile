# suave-geth
.PHONY: devnet-up devnet-down 
devnet-up:
	@docker compose --file ./compose.yaml up --detach

.PHONY: devnet-down
devnet-down:
	@docker compose --file ./compose.yaml down



# Solidity
build-solidity:
	forge build

test-solidity:
	forge test --ffi

lint-solidity:
	solhint 'src/**/*.sol'

fmt-solidity:
	forge fmt

check-fmt-solidity:
	forge fmt --check

# Golang
.PHONY: run-go
run-go:
	@cd src/go && go run main.go && cd ../../

build-go:
	go build ./src/go

test-go:
	go test ./src/go/... ./test/...

lint-go:
	golangci-lint run

fmt-go:
	go fmt ./src/go/... ./test/...

check-fmt-go:
	gofmt -d .

# Protobuf
.PHONY: run-proto
run-proto:
	@protoc -I./src/proto \
  --go_out=src/go/pb --go_opt=paths=source_relative \
  --go-grpc_out=src/go/pb --go-grpc_opt=paths=source_relative \
  --grpc-gateway_out=src/go/pb --grpc-gateway_opt=paths=source_relative \
  src/proto/transferable_account.proto

compile-proto:
	@make run-proto

# lint-proto:
# 	buf lint

fmt-proto:
	buf format

check-fmt-proto:
	buf format -d

# General
.PHONY: build test lint fmt check-fmt
build: build-solidity build-go compile-proto

test: test-solidity test-go

lint: lint-solidity lint-go 

fmt: fmt-solidity fmt-go fmt-proto

check-fmt: check-fmt-solidity check-fmt-go check-fmt-proto

# CI
ci: build test lint check-fmt
