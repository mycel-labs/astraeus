// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "suave-std/suavelib/Suave.sol";
import "suave-std/Transactions.sol";
import "../lib/SignatureVerifier.sol";

interface ITransferableAccountStore {
    struct Account {
        Suave.DataId accountId;
        address owner;
        uint256 publicKeyX;
        uint256 publicKeyY;
        Curve curve;
        bool isLocked;
    }

    enum Curve {
        CURVE_UNKNOWN,
        ECDSA,
        EDDSA
    }

    // Events
    event AccountCreated(string accountId, Account account);
    event AccountTransferred(string accountId, Account account);
    event AddressApproved(string accountId, address approvedAddress);
    event ApprovalRevoked(string accountId, address revokedAddress);
    event AccountLocked(string accountId, uint256 duration);
    event AccountUnlocked(string accountId);
    event AccountDeleted(string accountId);
    event Signature(bytes signature);
    event RLPTransaction(bytes rlptxn);
    event RLPTransactionHashed(bytes rlpTxnHash);
    event Transaction1559(Transactions.EIP1559 signedTx);
    event Transaction1559bytes(bytes signedTx);
    event Transaction155(Transactions.EIP155 signedTx);
    event Privatekey(bytes signingKey);
    event PrivatekeyString(string signingKey);
    event SignerAddress(address signer);

    // Getters
    function getAccount(string memory accountId) external view returns (Account memory);
    function isApproved(string memory accountId, address _address) external view returns (bool);
    function isOwner(string memory accountId, address _address) external view returns (bool);
    function isAccountLocked(string memory accountId) external view returns (bool);

    // Actions
    function createAccount(SignatureVerifier.TimedSignature calldata signature) external returns (bytes memory);
    function transferAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId, address to)
        external
        returns (bytes memory);
    function deleteAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId)
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
    ) external returns (bytes memory);

    function sign(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId, bytes memory data)
        external
        returns (bytes memory);

    function sign1559(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        bytes memory rlpTxnHash
    ) external returns (bytes memory);
    function sign155(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        Transactions.EIP155Request calldata transaction
    ) external returns (bytes memory);

    function verifyTimedSignature(SignatureVerifier.TimedSignature calldata signature) external view returns (bool);
}
