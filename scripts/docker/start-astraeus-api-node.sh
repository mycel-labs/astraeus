#!/bin/sh

export TA_STORE_CONTRACT_ADDRESS=${TA_STORE_CONTRACT_ADDRESS}
export PRIVATE_KEY=${PRIVATE_KEY}
export RPC_URL=${RPC_URL:-http://host.docker.internal:8545}

echo "Starting astraeus-api--node with arguments: $1"

forge install
forge build --via-ir
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY src/solidity/TransferableAccountStore.sol:TransferableAccountStore

make run-go 


