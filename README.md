# Astraeus

This project implements a transferable account system using smart contracts.

## Features

- Account creation and management
- Secure ownership transfer

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Docker 

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/mycel-labs/astraeus.git
   cd astraeus
   ```

2. Install dependencies:
   ```
   make install
   ```

3. Compile the contracts:
   ```
   make build
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

6. **Create Account Request to API Server**

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

6. **Deposit SepoliaETH to TA's Address**

   Once the TA is created, try sending ETH on Sepolia to the ethereumAddress held by the TA.
   You can refer to the ethereumAddress held by the created TA from the result of the CreateAccount execution.

   This operation will be conducted on the Sepolia Testnet, not on the Suave Toliman Testnet, so please be careful.

7. **Approve Address Request to API Server**

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
     "address": "0x755201605CB3bBeE61320cc3d5Af2Bb5Ed15DE0F"
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

   You need to create a signature to execute the TransferAccount Function. (As with the previous step)

   ```
   go run scripts/utils/generate_timed_signature/main.go <your_private_key> TransferAccount
   ```

   input example:
   ```
   go run scripts/utils/generate_timed_signature/main.go 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94 TransferAccount
   ```
   
   output example:
   ```
   "proof": {
      "validFor": 1730273730,
      "messageHash": "8137a1f78f956ec8663e23bcb1f07d4739effa0254a229d3eebf3d19bb95e9e3",
      "signature": "3171639eb953784b663356b60d7231cc2639d549a53b30997171f3b77f58f2271c71ff898d1993295c62775710d2c17d7fc1f135aee06be2706dcd84cacc081b1b",
      "signer": "0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3",
      "nonce": 5,
      "target_function_hash": "29535a955f68dc291a88a89b6112c958d2edce1684117ccd6b54ca173656f65f"
   }
   ```

   Once the signature is created, try executing the API using the signature information. 
   The PATH of the URL for executing the API must include the accountId of the TA you created.

   ```
   curl -s -X POST http://localhost:8080/v1/accounts/<your TA's accountId>/transfer -d '{
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
   curl -s -X POST http://localhost:8080/v1/accounts/0x5f927be8e73951a99a84fa7b21e1d5c4/transfer -d '{
     "base": {
      "account_id": "0x5f927be8e73951a99a84fa7b21e1d5c4",
      "proof": {
         "validFor": 1730273730,
         "messageHash": "8137a1f78f956ec8663e23bcb1f07d4739effa0254a229d3eebf3d19bb95e9e3",
         "signature": "3171639eb953784b663356b60d7231cc2639d549a53b30997171f3b77f58f2271c71ff898d1993295c62775710d2c17d7fc1f135aee06be2706dcd84cacc081b1b",
         "signer": "0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3",
         "nonce": 5,
         "target_function_hash": "29535a955f68dc291a88a89b6112c958d2edce1684117ccd6b54ca173656f65f"
      }
     },
     "address": "0x755201605CB3bBeE61320cc3d5Af2Bb5Ed15DE0F"
   }'
   ```
   
   output example:
   ```
   {"txHash":"0x26ad303c786550433848519411438b3f1531f568be25563d29645d1f6275341c"}
   ```

   Once these steps are completed, the ownership of the TA will be transferred.

   You can check the TA's owner address using the following command
   ```
   curl -X GET http://localhost:8080/v1/accounts/<your TA's accountId>
   ```

   example
   ```
   curl -X GET http://localhost:8080/v1/accounts/0x436d02ef904e536a870d12949e429819
   {"account":{"accountId":"0x436d02ef904e536a870d12949e429819","owner":"0x755201605CB3bBeE61320cc3d5Af2Bb5Ed15DE0F","publicKeyX":"a91cd998338946de2b6a1bc36dc109b5bcc8a826143174d7820eb0e26f05e042","publicKeyY":"90bf93a068d2dc9aa497cb25e006f14e1abfc754935d1d98c8e5a8b8d0812e64","signatureAlgorithm":"SignatureAlgorithm_ECDSA","isLocked":false}}
   ```

9. **Unlock the Transferable Account**

   After the transfer of the TA is complete, let's perform the unlock operation from the account that received the TA.
   By unlocking the TA, you will be able to withdraw assets from addresses on different chains associated with the TA.

   You need to create a signature to execute the TransferAccount Function. (As with the previous step)
   Please note that the private key of the account that received the TA on the Toliman Testnet will be required.

   ```
   go run scripts/utils/generate_timed_signature/main.go <your_private_key> UnlockAccount
   ```

   input example:
   ```
   go run scripts/utils/generate_timed_signature/main.go 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94 UnlockAccount
   ```
   
   output example:
   ```
   "proof": {
      "validFor": 1730276042,
      "messageHash": "4dc2219469c3081b806b29d942e94c09aa949726d6a043c459e091a47fac5d09",
      "signature": "b23824ac0edf74ba1b5771531d20ce3b549eba74976f955cb41484b88965fe432a3da3a37a22cc38c850e38819f52a38b24ee292fc32c62fb301fe96f48d668d1c",
      "signer": "0x755201605CB3bBeE61320cc3d5Af2Bb5Ed15DE0F",
      "nonce": 0,
      "target_function_hash": "062e71868bb32b076e90fa8fa0fa661f47d2f38ee0e9db39a5ab5569589f6332"
   }
   ```

   Once the signature is created, try executing the API using the signature information. 
   The PATH of the URL for executing the API must include the accountId of the TA you created.

   ```
   curl -s -X POST http://localhost:8080/v1/accounts/<your TA's accountId>/unlock -d '{
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
     }
   }'
   ```

   input example:
   ```
   curl -s -X POST http://localhost:8080/v1/accounts/0x5f927be8e73951a99a84fa7b21e1d5c4/unlock -d '{
     "base": {
      "account_id": "0x5f927be8e73951a99a84fa7b21e1d5c4",
      "proof": {
         "validFor": 1730276042,
         "messageHash": "4dc2219469c3081b806b29d942e94c09aa949726d6a043c459e091a47fac5d09",
         "signature": "b23824ac0edf74ba1b5771531d20ce3b549eba74976f955cb41484b88965fe432a3da3a37a22cc38c850e38819f52a38b24ee292fc32c62fb301fe96f48d668d1c",
         "signer": "0x755201605CB3bBeE61320cc3d5Af2Bb5Ed15DE0F",
         "nonce": 0,
         "target_function_hash": "062e71868bb32b076e90fa8fa0fa661f47d2f38ee0e9db39a5ab5569589f6332"
      }
     }
   }'
   ```
   
   output example:
   ```
   {"txHash":"0x26ad303c786550433848519411438b3f1531f568be25563d29645d1f6275341c"}
   ```

   You can check the TA's lock status using the following command

   ```
   curl -X GET http://localhost:8080/v1/accounts/<your TA's accountId>/locked
   ```

   example
   ```
   curl -X GET http://localhost:8080/v1/accounts/0x436d02ef904e536a870d12949e429819/locked
   {"result":false}
   ```


10. **Sign from Transferable Account**

    If you own a TA and hold assets on an external chain with that TA, you can create a Tx to send assets from the TA account and broadcast it to the external chain.

    Before executing the command, make sure to set the RPC of the chain to broadcast the Tx as `WITHDRAW_TESTNET_RPC` in your `.env` file.

    Specify the arguments in the following order: the accountID of the TA you are using, the ChainID to execute the Tx, the address to which you want to send the ETH, and the amount of ETH to send.

    Please note that the private key of the account that received the TA on the Toliman Testnet will be required.

    ```
    $ go run scripts/utils/execute_withdraw_tx/main.go <your_private_key> <your TA's accountId> <external chainId> <recipient address on external chain> <transfer amount of ETH on external chain>
    ```

    When the transaction is ready, you will be prompted to confirm whether to proceed, as shown in the example below. If everything looks good, type ‘y’ and press Enter.

    input example:
    ```
    $ go run scripts/utils/execute_withdraw_tx/main.go 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94 0x439376239c54540980f027ac33e1c11a 11155111 0x0A772258e2f36999C6aA57B2Ba09B78caF7EbAd3 0.0001
    2024/10/31 15:12:11 Using PRIVATE_KEY: 10c62a6364b1730ec101460c871952403631adb66fe7e043914c7d0056ca8e94
    2024/10/31 15:12:11 Using RPC_URL: https://rpc.toliman.suave.flashbots.net
    2024/10/31 15:12:11 Using TA_STORE_CONTRACT_ADDRESS: 0xEa8a6ce7098B79Bd8B4920120734a5081046C44F
    2024/10/31 15:12:12 Get Account Response:  account:{account_id:"0x436d02ef904e536a870d12949e429819"
    owner:"0x755201605CB3bBeE61320cc3d5Af2Bb5Ed15DE0F"
    public_key_x:"a91cd998338946de2b6a1bc36dc109b5bcc8a826143174d7820eb0e26f05e042"
    public_key_y:"90bf93a068d2dc9aa497cb25e006f14e1abfc754935d1d98c8e5a8b8d0812e64" signature_algorithm:SignatureAlgorithm_ECDSA}
    2024/10/31 15:12:12 TA's Ethereum Address:  0x6a06c9e34f0e167c2aD2Ba3d97D588BaA9A0C37c
    2024/10/31 15:12:13 Suggested Gas Price: 4297882348
    2024/10/31 15:12:13 Suggested Gas Tip Cap: 305482713
    2024/10/31 15:12:13 Transaction Hash: c3f2f2779693bb9687ea25f1d8585f7907031fbbbfc57492296c94d3cf246f33
    2024/10/31 15:12:17 Sign Response:  tx_hash:"0x74322f8c27019b1ce5c475cf76af225c47cc7a97ef4afb73cba4f68526dab132" signature:"323ab432a41b47a8e02383a0648262248850b84c9d5530394252de87e0869baa7944c6db4b50c2eacc6562bc85ec824eb0451ac6a6adac19b1ec42bcfe84bcd101"
    2024/10/31 15:12:17 Sender Address:  0x6a06c9e34f0e167c2aD2Ba3d97D588BaA9A0C37c
    You need to depoist send value & gas ETH to 0x6a06c9e34f0e167c2aD2Ba3d97D588BaA9A0C37c (y/n):
    ```

    Once the transfer is successful, the `txHash` will be displayed.

    output example
    ```
    2024/10/31 15:12:19 Transaction sent successfully! Tx Hash:  0xf833ec2ea7202e929cf440b935702df8b56e24a2b4cea03d776f2d9357d2d7f8
    ```

    Let’s check the outputted Tx Hash on each chain’s explorer.
    
    - [Sepoilia Testnet Etherscan](https://sepolia.etherscan.io/)

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
