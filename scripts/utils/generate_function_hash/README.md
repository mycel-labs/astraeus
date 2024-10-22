# Function Hash Generator

This utility generates Keccak256 hashes for Solidity function signatures. These hashes are used in the smart contract to identify specific functions.

## Usage

To generate a function hash, use the following command:

```
go run generate_function_hash.go "FunctionName(type1 param1,type2 param2,...)"
```

Replace `FunctionName` with the actual function name and provide the parameter types and names as they appear in the Solidity function signature.

## Examples

Here are some examples based on the function hashes used in our project:

1. Approve Address:
   ```
   go run generate_function_hash.go "ApproveAddress(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)"
   ```
   Expected output: 0x16d1dabab53b460506870428d7a255f9bff53294080a73797c114f4e25b5e76f

2. Create Account:
   ```
   go run generate_function_hash.go "CreateAccount(SignatureVerifier.TimedSignature timedSignature)"
   ```
   Expected output: 0x030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f

3. Sign:
   ```
   go run generate_function_hash.go "Sign(SignatureVerifier.TimedSignature timedSignature,string accountId,bytes data)"
   ```
   Expected output: 0xd34780a58dd276dd414ea2abde077f3492ca5422926cdcadf8def7a93f12e993

## Verification

You can verify the generated hashes against the constants defined in the `constants.go` file:
