// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "suave-std/suavelib/Suave.sol";

interface ITransferableAccountStore {
    struct Account {
        Suave.DataId accountId;
        address creator;
        address owner;
        uint256 publicKeyX;
        uint256 publicKeyY;
        address[] approvedAddresses;
        string key;
    }

    // Events
    event AccountCreated(string accountId, Account account);
    event AccountTransferred(string accountId, Account account);
    event AddressApproved(string accountId, address approvedAddress);
    event AddressRevoked(string accountId, address revokedAddress);
    event Signature(string accountId, bytes signature);

    // Getters
    function getAccount(string memory accountId) external view returns (Account memory);
    function isApproved(string memory accountId, address _address) external view returns (bool);
    function isOwner(string memory accountId, address _address) external view returns (bool);

    // Actions
    function createAccount() external returns (bytes memory);
    function transferAccount(address to, string memory accountId) external pure returns (bytes memory);

    function approveAddress(string memory accountId, address _address) external view returns (bytes memory);
    function revokeAddress(string memory accountId, address _address) external;

    function sign(Suave.DataId accountId, bytes memory data) external returns (bytes memory);
}
