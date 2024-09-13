#!/bin/sh

export PRIVATE_KEY=${PRIVATE_KEY}
export RPC_URL=${RPC_URL:-http://host.docker.internal:8545}

export ALICE_PRIVATE_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export BOB_PRIVATE_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

echo "Starting astraeus-api--node with arguments: $1"

forge install
forge build --via-ir
output=$(forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY src/solidity/TransferableAccountStore.sol:TransferableAccountStore)
contract_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')
export TA_STORE_CONTRACT_ADDRESS=$contract_address
echo "Deployed to ${TA_STORE_CONTRACT_ADDRESS}"

make run-go &

# waiting for starting the API server.
sleep 120

# Run the generating TimedSignature scripts and capture its output
future_unix_time=$(( $(date +%s) + 86400 ))

alice_timedsignature_output=$(go run scripts/utils/generate_timed_signature/main.go $future_unix_time $ALICE_PRIVATE_KEY)
alice_address=$(echo "$alice_timedsignature_output" | grep "Address:" | awk '{print $2}')
alice_message_hash=$(echo "$alice_timedsignature_output" | grep "Message Hash:" | awk '{print $3}')
alice_signature=$(echo "$alice_timedsignature_output" | grep "Signature:" | awk '{print $2}')

bob_timedsignature_output=$(go run scripts/utils/generate_timed_signature/main.go $future_unix_time $BOB_PRIVATE_KEY)
bob_address=$(echo "$bob_timedsignature_output" | grep "Address:" | awk '{print $2}')
bob_message_hash=$(echo "$bob_timedsignature_output" | grep "Message Hash:" | awk '{print $3}')
bob_signature=$(echo "$bob_timedsignature_output" | grep "Signature:" | awk '{print $2}')

echo "--------------- Create Acccount -------------------"
create_account_response=$(curl -s -X POST http://localhost:8080/v1/accounts -d '{
  "proof": {
    "validFor": "'"$future_unix_time"'",
    "messageHash": "'"$alice_message_hash"'",
    "signature": "'"$alice_signature"'",
    "signer": "'"$alice_address"'"
  }
}')

create_account_tx_hash=$(echo "$create_account_response" | jq -r '.txHash')
create_account_account_id=$(echo "$create_account_response" | jq -r '.accountId')

if [ "$create_account_tx_hash" != "" ] && [ "$create_account_account_id" != "" ]; then
  echo "Create account succeeded: txHash=$create_account_tx_hash, accountId=$create_account_account_id"
else
  echo "Create account failed: $create_account_response"
fi

echo "--------------- Approve Address -------------------"
curl -s -X POST http://localhost:8080/v1/accounts/$create_account_account_id/approve -d '{
  "base": {
    "account_id": "'"$create_account_account_id"'",
    "proof": {
      "validFor": "'"$future_unix_time"'",
      "messageHash": "'"$alice_message_hash"'",
      "signature": "'"$alice_signature"'",
      "signer": "'"$alice_address"'"
    }
  },
  "address": "'"$bob_address"'"
}'

echo "--------------- Transfer Account -------------------"
curl -s -X POST http://localhost:8080/v1/accounts/$create_account_account_id/transfer -d '{
  "base": {
    "account_id": "'"$create_account_account_id"'",
    "proof": {
      "validFor": "'"$future_unix_time"'",
      "messageHash": "'"$bob_message_hash"'",
      "signature": "'"$bob_signature"'",
      "signer": "'"$bob_address"'"
    }
  },
  "address": "'"$bob_address"'"
}'