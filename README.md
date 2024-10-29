# Astraeus

This project implements a transferable account system using smart contracts.

## Features

- Account creation and management
- Secure ownership transfer

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/mycel-labs/astraeus.git
   cd astraeus
   ```

2. Install dependencies:
   ```
   forge install
   ```

3. Compile the contracts:
   ```
   forge build
   ```

## Getting Started

This guide will help you set up the Astraeus API server on the Suave Toliman Testnet to easily use Transferable Accounts (TA). You will learn how to create, approve, and transfer TAs using the API server. Additionally, you will learn how to sign transactions on external chains using TAs.

### Prerequisites

- An environment capable of running Docker
- Two accounts on the Toliman Testnet with access to their private keys and TEETH tokens
- Two accounts on the Sepolia Testnet with access to their private keys and SepoliaETH tokens

If you do not have these tokens, you can obtain them from the [Toliman Testnet Faucet](https://faucet.toliman.suave.flashbots.net/) and [Sepolia Testne Faucet](https://www.alchemy.com/faucets/ethereum-sepolia)

### Steps

1. **Copy the example environment file to create your own `.env` file:**
   ```
   cp .env.example .env
   ```

2. **Edit the `.env` file and set the `PRIVATE_KEY` to the private key of an account that holds tokens on the Suave network.**

3. **Start the API server using Docker:**
   ```
   make run-api-server-docker
   ```

   At this point, the API server should be running locally via Docker.

4. **Generate the Timed Signature required for API requests. Replace `your_private_key` with the private key of your account on Suave and `targetFunction` with "CreateAccount":**

   To execute a request against the API, you need to prepare a signature each time that indicates from which account and for which function the request is being made.

   ```
   go run scripts/utils/generate_timed_signature/main.go <your_private_key> CreateAccount
   ```
   
   First, we are creating a signature for "CreateAccount"

   input example:
   ```
    go run scripts/utils/generate_timed_signature/main.go 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94 CreateAccount
   ```
   
   output example:
   ```
   "proof": {
      "validFor": 1730260787,
      "messageHash": "7fe8d937495fbdf3324310fddedebd0ea6a14fd9451d42b692435f4db53fbdee",
      "signature": "9cc6629cbf04e3f75f2ecb2fd9b780b886975938c8b1326ad2e92ef5a705e6305c4c28b92a270950a7153f91a5607da04c0a77937dd6f4c5128864cd34a33ba21c",
      "signer": "0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3",
      "nonce": 3,
      "target_function_hash": "030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f"
   }
   ```

5. **Create Account Request to API Server**

   Execute the request to create a TA. Use the output from step 4 in the `proof` section:

   ```
   curl -X POST http://localhost:8080/v1/accounts -d '{
      "proof": {
         "validFor": <validFor>,
         "messageHash": "<messageHash>",
         "signature": "<signature>",
         "signer": "<signer>",
         "nonce": <nonce>,
         "target_function_hash": "<target_function_hash>"
      }
   }'
   ```

   input example:
   ```
   curl -X POST http://localhost:8080/v1/accounts -d '{
      "proof": {
         "validFor": 1730260787,
         "messageHash": "7fe8d937495fbdf3324310fddedebd0ea6a14fd9451d42b692435f4db53fbdee",
         "signature": "9cc6629cbf04e3f75f2ecb2fd9b780b886975938c8b1326ad2e92ef5a705e6305c4c28b92a270950a7153f91a5607da04c0a77937dd6f4c5128864cd34a33ba21c",
         "signer": "0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3",
         "nonce": 3,
         "target_function_hash": "030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f"
      }
   }'
   ```
   
   output example:
   ```
   {"txHash":"0x98f3367e503d32d6e817ca251bc7cfefdd6d11c970fbac1bc74ad06efe7f8d49","accountId":"0x5f927be8e73951a99a84fa7b21e1d5c4","ethereumAddress":"0x6b972Cc0A1CdF473a48C27831B0A3b64CBD8E549"}
   ```

   Once the `txHash` is displayed, the account creation is complete. The displayed `accountId` and `ethereumAddress` are the ID of the account and The account's address on EVM

6. **Approve Address Request to API Server**

   Approve the transfer of TA ownership from the current account to another account.

   You need to create a signature to execute the ApproveAddress Function. (As with the previous step)

   ```
   go run scripts/utils/generate_timed_signature/main.go <your_private_key> ApproveAddress
   ```

   input example:
   ```
    go run scripts/utils/generate_timed_signature/main.go 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94 ApproveAddress
   ```
   
   output example:
   ```
   "proof": {
      "validFor": 1730262911,
      "messageHash": "9978c1ecc11cd29ea7aa2d1571ef6fdba80b0501a0938d5c17ead3baa4b5dfb0",
      "signature": "a1c818ebef4d29ae7d8fff29648d6aa3936d5657a03324ffa758f792a79fbca44087ce49ab485fd81c30d8da29f1b292ed744aff2071f0207385f8f44635af311b",
      "signer": "0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3",
      "nonce": 4,
      "target_function_hash": "16d1dabab53b460506870428d7a255f9bff53294080a73797c114f4e25b5e76f"
   }
   ```

   Once the signature is created, try executing the API using the signature information. 
   The PATH of the URL for executing the API must include the accountId of the TA you created.

   ```
   curl -s -X POST http://localhost:8080/v1/accounts/<your TA's accountId>/approve -d '{
     "base": {
      "account_id": "<your TA's accountId>",
      "proof": {
         "validFor": <validFor>,
         "messageHash": "<messageHash>",
         "signature": "<signature>",
         "signer": "<signer>",
         "nonce": <nonce>,
         "target_function_hash": "<target_function_hash>"
      }
     },
     "address": "<another suave account address>"
   }'
   ```

   input example:
   ```
   curl -s -X POST http://localhost:8080/v1/accounts/0x5f927be8e73951a99a84fa7b21e1d5c4/approve -d '{
     "base": {
      "account_id": "0x5f927be8e73951a99a84fa7b21e1d5c4",
      "proof": {
         "validFor": 1730262911,
         "messageHash": "9978c1ecc11cd29ea7aa2d1571ef6fdba80b0501a0938d5c17ead3baa4b5dfb0",
         "signature": "a1c818ebef4d29ae7d8fff29648d6aa3936d5657a03324ffa758f792a79fbca44087ce49ab485fd81c30d8da29f1b292ed744aff2071f0207385f8f44635af311b",
         "signer": "0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3",
         "nonce": 4,
         "target_function_hash": "16d1dabab53b460506870428d7a255f9bff53294080a73797c114f4e25b5e76f"
      }
     },
     "address": "0x696600D88559ac1C0E84de6208F3C568Af9e6a48"
   }'
   ```
   
   output example:
   ```
   {"txHash":"0x19eb20300738d3d2ffa63fe35cb3cf9fe1737e4d19cd65fb693b784b0abd51f5"}
   ```

   Once the `txHash` is displayed, the account approval is complete.

8. **Transfer Account Request to API Server**

   Execute the transfer of TA ownership. This can be done by either the current TA owner or the approved account.
   In this example, the transfer is executed with the signature of the TA creator, but you can also create and execute the request with the signature of the recipient.

   ```
   curl -s -X POST http://localhost:8080/v1/accounts/$create_account_account_id/transfer -d '{
     "base": {
       "account_id": "0xb06e9fd4baf654208e7886284cdcdab2",
       "proof": {
         "validFor": "1726946480",
         "messageHash": "32948247c695a2545f9b35c040a293f1c6cd300062e9d7abdf0b3ed2a7b596d1",
         "signature": "50346a31ad859f211294496e01083dcb85803bb27923b8d256756c71bdbfe36e1e89741215f58fd4bb8db42f04775303e60748b99f10c64e189d1f585d6b77531c",
         "signer": "1b1374742cb5f84b1ef167db57236350380084e1"
       }
     },
     "address": "your_another_account_address"
   }'
   ```

   Once these steps are completed, the ownership of the TA will be transferred.

   For more details on API requests, refer to the documentation at:
   [API Documentation](https://github.com/mycel-labs/astraeus/blob/main/docs/api.md)

9. **Sign from Transferable Account Request to API Server**

   If you own a TA and hold assets on an external chain with that TA, you can create a Tx to send assets from the TA account and broadcast it to the external chain.

   Before executing the command, make sure to set the RPC of the chain to broadcast the Tx as `WITHDRAW_TESTNET_RPC` in your `.env` file.

   Specify the arguments in the following order: the accountID of the TA you are using, the ChainID to execute the Tx, the address to which you want to send the ETH, and the amount of ETH to send.

   Example:
   ```
   $ go run scripts/utils/execute_withdraw_tx/main.go 0x439376239c54540980f027ac33e1c11a 11155111 0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3 0.0001
   ```

   Once the transfer is successful, the `txHash` will be displayed.



## Testing

Run the test suite using Foundry:

```
make build-solidity && make test-solidity
```

Run the e2e tests on docker compose:

```
make test-e2e-docker
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
