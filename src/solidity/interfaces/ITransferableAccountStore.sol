// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "suave-std/suavelib/Suave.sol";

interface ITransferableAccountStore {
    struct Account {
        Suave.DataId accountId;
        address owner;
        uint256 publicKeyX;
        uint256 publicKeyY;
        string key;
    }

    struct TimeLock {
        uint256 expiresAt;
        address lockedBy;
        address unlockTo;
    }

    // Events
    event AccountCreated(string accountId, Account account);
    event AccountTransferred(string accountId, Account account);
    event AddressApproved(string accountId, address approvedAddress);
    event ApprovalRevoked(string accountId, address revokedAddress);
    event AccountLocked(string accountId);
    event AccountUnlocked(string accountId);
    event Signature(string accountId, bytes signature);

    // Getters
    function getAccount(string memory accountId) external view returns (Account memory);
    function isApproved(string memory accountId, address _address) external view returns (bool);
    function isOwner(string memory accountId, address _address) external view returns (bool);
    function isLocked(string memory accountId) external view returns (bool);
    function getLock(string memory accountId) external view returns (TimeLock memory);

    // Actions
    function createAccount() external returns (bytes memory);
    function transferAccount(address to, string memory accountId) external pure returns (bytes memory);
    function deleteAccount(string memory accountId) external returns (bytes memory);
    function lockAccount(string memory accountId) external returns (bytes memory);
    function unlockAccount(string memory accountId) external returns (bytes memory);

    function approveAddress(string memory accountId, address _address) external view returns (bytes memory);
    function revokeApproval(string memory accountId, address _address) external;

    function sign(Suave.DataId accountId, bytes memory data) external returns (bytes memory);
}
