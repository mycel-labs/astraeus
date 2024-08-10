// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

interface ISignatureVerifier {
    struct TimedSignature {
        uint256 validFor;
        bytes32 messageHash;
        bytes signature;
    }

    event SignatureFailed(bytes32 messageHash, address signer, uint256 validFor);
    event SignatureVerified(bytes32 messageHash, address signer, uint256 validFor);

    function verifyTimedSignature(TimedSignature memory signature) external view returns (bool);
}
