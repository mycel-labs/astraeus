// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library SignatureVerifier {
    struct TimedSignature {
        uint256 validFor;
        bytes32 messageHash;
        bytes signature;
        address signer;
    }

    event SignatureFailed(bytes32 messageHash, address signer, uint256 validFor);
    event SignatureVerified(bytes32 messageHash, address signer, uint256 validFor);

    function hashMessage(uint256 validFor, address sender) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(validFor, sender));
    }

    function verifyTimedSignature(uint256 validFor, bytes32 messageHash, bytes memory signature, address signer)
        internal
        view
        returns (bool)
    {
        require(block.timestamp <= validFor, "Signature has expired");

        // Recalculate the message hash
        bytes32 calculatedHash = hashMessage(validFor, signer);
        require(messageHash == calculatedHash, "Invalid message hash");

        // Verify the signature
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        address recoveredSigner = ecrecover(ethSignedMessageHash, v, r, s);

        return recoveredSigner == signer;
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
