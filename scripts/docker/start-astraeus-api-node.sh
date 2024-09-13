#!/bin/sh

export PRIVATE_KEY=${PRIVATE_KEY}
export RPC_URL=${RPC_URL:-http://host.docker.internal:8545}

echo "Starting astraeus-api--node with arguments: $1"

forge install
forge build --via-ir
output=$(forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY src/solidity/TransferableAccountStore.sol:TransferableAccountStore)
contract_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')
export TA_STORE_CONTRACT_ADDRESS=$contract_address
echo "Deployed to ${TA_STORE_CONTRACT_ADDRESS}"

make run-go &


