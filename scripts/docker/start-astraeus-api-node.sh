#!/bin/sh

export PRIVATE_KEY=${PRIVATE_KEY}
export RPC_URL=${RPC_URL:-http://host.docker.internal:8545}

export ALICE_PRIVATE_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

echo "Starting astraeus-api--node with arguments: $1"

forge install
forge build --via-ir
output=$(forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY src/solidity/TransferableAccountStore.sol:TransferableAccountStore)
contract_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')
export TA_STORE_CONTRACT_ADDRESS=$contract_address
echo "Deployed to ${TA_STORE_CONTRACT_ADDRESS}"

make run-go &


sleep 120

# Run the generating TimedSignature scripts and capture its output
go_output=$(go run scripts/utils/generate_timed_signature/main.go 2000000000 $ALICE_PRIVATE_KEY)

# Extract the necessary information from the Go script output
address=$(echo "$go_output" | grep "Address:" | awk '{print $2}')
message_hash=$(echo "$go_output" | grep "Message Hash:" | awk '{print $3}')
signature=$(echo "$go_output" | grep "Signature:" | awk '{print $2}')

# Send a POST request about creating a account to the API server
create_account_response=$(curl -s -X POST http://localhost:8080/v1/accounts -d '{
  "proof": {
    "validFor": 2000000000,
    "messageHash": "'"$message_hash"'",
    "signature": "'"$signature"'",
    "signer": "'"$address"'"
  }
}')

create_account_tx_hash=$(echo "$create_account_response" | jq -r '.txHash')
create_account_account_id=$(echo "$create_account_response" | jq -r '.accountId')

if [ "$create_account_tx_hash" != "" ] && [ "$create_account_account_id" != "" ]; then
  echo "Create account succeeded: txHash=$create_account_tx_hash, accountId=$create_account_account_id"
else
  echo "Create account failed: $create_account_response"
fi