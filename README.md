# Transferable Account

This project implements a transferable account system using smart contracts.

## Features

- Account creation and management
- Secure ownership transfer

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/mycel-labs/transferable-account.git
   cd transferable-account
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

This guide will help you set up the Astraeus API server on the Suave Toliman Testnet to easily use Transferable Accounts (TA). You will learn how to create, approve, and transfer TAs using the API server.

### Prerequisites

- An environment capable of running Docker
- Two accounts on the Toliman Testnet with access to their private keys and TEETH tokens

If you do not have TEETH tokens, you can obtain them from the [Toliman Testnet Faucet](https://faucet.toliman.suave.flashbots.net/).

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

4. **Generate the Timed Signature required for API requests. Replace `validFor` with the UnixTime until which the signature is valid, and `your_private_key` with the private key of your account:**

   Generate signatures for both of your accounts.
   ```
   go run scripts/utils/generate_timed_signature/main.go 1726946480(validFor) 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94(your_private_key)
   Address: 1b1374742cb5f84b1ef167db57236350380084e1
   Message Hash: 32948247c695a2545f9b35c040a293f1c6cd300062e9d7abdf0b3ed2a7b596d1
   Signature: 50346a31ad859f211294496e01083dcb85803bb27923b8d256756c71bdbfe36e1e89741215f58fd4bb8db42f04775303e60748b99f10c64e189d1f585d6b77531c
   ```

5. **Create Account Request to API Server**

   Execute the request to create a TA. Use the output from step 4 in the `proof` section:
   ```
   curl -X POST http://localhost:8080/v1/accounts -d '{
     "proof": {
       "validFor": 1726946480,
       "messageHash": "32948247c695a2545f9b35c040a293f1c6cd300062e9d7abdf0b3ed2a7b596d1",
       "signature": "50346a31ad859f211294496e01083dcb85803bb27923b8d256756c71bdbfe36e1e89741215f58fd4bb8db42f04775303e60748b99f10c64e189d1f585d6b77531c",
       "signer": "1b1374742cb5f84b1ef167db57236350380084e1"
     }
   }'
   {"txHash":"0x554f24eeeb38bd54b64551863c6ab1878b559d390ac14ad26a4b1f3e07beaf5d", "accountId":"0xb06e9fd4baf654208e7886284cdcdab2"}
   ```

   Once the `txHash` is displayed, the account creation is complete. The displayed `accountId` is the ID of the account you created.

6. **Approve Address Request to API Server**

   Approve the transfer of TA ownership from the current account to another account.

   Specify the `account_id` of the created account. Use the same values as before, and input the address of the other account in the `address` field.
   ```
   curl -s -X POST http://localhost:8080/v1/accounts/$create_account_account_id/approve -d '{
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

   Once the `txHash` is displayed, the account approval is complete.

7. **Transfer Account Request to API Server**

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
