// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";

contract SignatureVerifier is ISignatureVerifier {
    function hashMessage(uint256 validFor, address sender) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(validFor, sender));
    }

    function verifyTimedSignature(uint256 validFor, bytes32 messageHash, bytes memory signature)
        external
        view
        returns (bool)
    {
        require(block.timestamp <= validFor, "Signature has expired");

        // Recalculate the message hash
        bytes32 calculatedHash = hashMessage(validFor, msg.sender);
        require(messageHash == calculatedHash, "Invalid message hash");

        // Verify the signature
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        address recoveredSigner = ecrecover(ethSignedMessageHash, v, r, s);

        return recoveredSigner == msg.sender;
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");
    }
}
