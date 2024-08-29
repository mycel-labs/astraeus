// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "suave-std/suavelib/Suave.sol";
import "../lib/SignatureVerifier.sol";

interface ITransferableAccountStore {
    struct Account {
        Suave.DataId accountId;
        address owner;
        uint256 publicKeyX;
        uint256 publicKeyY;
        Curve curve;
    }

    enum Curve {
        CURVE_UNKNOWN,
        ECDSA,
        EDDSA
    }

    struct TimeLock {
        uint256 lockUntil;
        address lockedBy;
    }

    // Events
    event AccountCreated(string accountId, Account account);
    event AccountTransferred(string accountId, Account account);
    event AddressApproved(string accountId, address approvedAddress);
    event ApprovalRevoked(string accountId, address revokedAddress);
    event AccountLocked(string accountId, uint256 duration);
    event AccountUnlocked(string accountId);
    event AccountDeleted(string accountId);
    event Signature(string accountId, bytes signature);

    // Getters
    function getAccount(string memory accountId) external view returns (Account memory);
    function isApproved(string memory accountId, address _address) external view returns (bool);
    function isOwner(string memory accountId, address _address) external view returns (bool);
    function isLocked(string memory accountId) external view returns (bool);
    function getLock(string memory accountId) external view returns (TimeLock memory);

    // Actions
    function createAccount(SignatureVerifier.TimedSignature calldata signature) external returns (bytes memory);
    function transferAccount(SignatureVerifier.TimedSignature calldata signature, address to, string memory accountId)
        external
        returns (bytes memory);
    function deleteAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId)
        external
        returns (bytes memory);
    function lockAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId, uint256 duration)
        external
        returns (bytes memory);
    function unlockAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId)
        external
        returns (bytes memory);

    function approveAddress(
        SignatureVerifier.TimedSignature calldata signature,
        string memory accountId,
        address _address
    ) external returns (bytes memory);

    function revokeApproval(
        SignatureVerifier.TimedSignature calldata signature,
        string memory accountId,
        address _address
    ) external view returns (bytes memory);

    function sign(Suave.DataId accountId, bytes memory data) external returns (bytes memory);

    function verifyTimedSignature(SignatureVerifier.TimedSignature calldata signature) external view returns (bool);
}
