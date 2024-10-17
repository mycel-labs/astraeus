PROTOBUF_DOCKER_IMAGE := custom-protobuf-image
PROTOBUF_DOCKERFILE := docker/protobuf.Dockerfile

# suave-geth
.PHONY: devnet-up devnet-down 
devnet-up:
	@docker compose --file ./compose.geth.yaml up --detach

.PHONY: devnet-down
devnet-down:
	@docker compose --file ./compose.geth.yaml down

# Solidity
build-solidity:
	forge build --via-ir

build-solidity-extra:
	forge build --extra-output-files abi bin --via-ir

gen-solidity-go-bindings:
	./scripts/utils/gen-solidity-go-bindings.sh

test-solidity:
	forge test --ffi --via-ir test/**/*.t.sol

lint-solidity:
	solhint 'src/**/*.sol'

fmt-solidity:
	forge fmt src/solidit

check-fmt-solidity:
	forge fmt --check src/solidity

# Golang
.PHONY: run-go
run-go:
	@go run ./src/go/...

build-go:
	go build ./src/go

test-go:
	go test ./src/go/... ./test/...

lint-go:
	golangci-lint run

fmt-go:
	go fmt ./src/go/... ./test/...

check-fmt-go:
	gofmt -d ./src/go ./test

# Protobuf
.PHONY: run-proto
run-proto:
	@docker build -t $(PROTOBUF_DOCKER_IMAGE) -f $(PROTOBUF_DOCKERFILE) .
	@rm -f docs/api.md
	@docker run --rm -v $(PWD):/workspace \
		$(PROTOBUF_DOCKER_IMAGE) \
		generate

compile-proto:
	@make run-proto

lint-proto:
	buf lint

fmt-proto:
	buf format src/proto

check-fmt-proto:
	buf format -d src/proto

# General
.PHONY: build test lint fmt check-fmt
build: build-solidity build-go compile-proto

test: test-solidity test-go

lint: lint-solidity 

fmt: fmt-solidity fmt-go fmt-proto

check-fmt: check-fmt-solidity check-fmt-go check-fmt-proto

# CI
ci: build test lint check-fmt

# Run e2e tests using docker compose
test-e2e-docker:
	@echo "----- Running e2e tests on docker compose -----"
	@docker compose -f compose.local.yaml up

# Start API Server using Docker
run-api-server-docker:
	@echo "----- Starging Astraeus API Server... -----"
	@docker compose -f compose.yaml up
	