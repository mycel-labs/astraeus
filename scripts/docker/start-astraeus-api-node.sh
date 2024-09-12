#!/bin/sh

export TA_STORE_CONTRACT_ADDRESS=${TA_STORE_CONTRACT_ADDRESS}
export PRIVATE_KEY=${PRIVATE_KEY}
export RPC_URL=${RPC_URL:-http://host.docker.internal:8545}

echo "Starting astraeus-api--node with arguments: $1"

make run-go 



