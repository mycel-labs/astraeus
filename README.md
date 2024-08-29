# Transferable Account

This project implements a transferable account system using smart contracts.

## Features

- Account creation and management
- Secure ownership transfer

## Getting Started

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

## Usage

WIP

## Testing

Run the test suite using Foundry:

```
forge test
```
### Test Overview

These tests are designed to verify the functionality of the TransferableAccountStore contract, which is part of a system using the Suave protocol for confidential computations. The tests cover various operations such as account creation, approval, transfer, and deletion.

Throughout these tests, you'll notice a pattern of encoding and decoding data:

#### 1. Encoding

Many functions in TransferableAccountStore return encoded data. This is because these functions are designed to be called in a confidential compute environment, where the actual operations happen off-chain, and only the encoded results are returned on-chain. The encoded data typically includes both a function selector for the callback and the operation-specific details.

#### 2. Decoding

To verify the results, we need to decode this data. The `decodeEncodedData()` helper function removes the first 4 bytes (function selector) and returns the rest of the data, which contains the encoded operation details.

#### 3. ABI Decoding

After removing the function selector, we use `abi.decode` to convert the raw bytes into structured objects (like `Account`) that we can work with in our tests.

#### Importance of the Encode-Decode Pattern

This encode-decode pattern is crucial because:
- It simulates the full process that would occur in a real transaction on the Suave network.
- It allows the contract to maintain confidentiality while still enabling us to verify the correctness of various operations in our tests.
- It ensures our tests accurately reflect the contract's behavior in its intended environment.

#### Test Structure

Each test function focuses on a specific operation (create, approve, transfer, etc.), but they all follow this general pattern of calling a function, decoding its result, and then asserting that the operation produced the expected outcome.

By structuring our tests this way, we can comprehensively verify that the TransferableAccountStore contract correctly handles all its operations while respecting the confidentiality requirements of the Suave protocol.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
