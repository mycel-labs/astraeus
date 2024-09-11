// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library SignatureVerifier {
    struct TimedSignature {
        uint64 validFor;
        bytes32 messageHash;
        bytes signature;
        address signer;
        uint256 nonce;
    }

    event SignatureFailed(bytes32 messageHash, address signer, uint64 validFor);
    event SignatureVerified(bytes32 messageHash, address signer, uint64 validFor);

    function hashMessage(uint64 validFor, address sender, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(validFor, sender, nonce));
    }

    function verifyTimedSignature(
        uint64 validFor,
        bytes32 messageHash,
        bytes memory signature,
        address signer,
        uint256 nonce
    ) internal view returns (bool) {
        if (block.timestamp > validFor) {
            return false;
        }

        // Recalculate the message hash
        if (messageHash != hashMessage(validFor, signer, nonce)) {
            return false;
        }

        // Verify the signature
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Mycel Signed Message:\n32", messageHash));
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
