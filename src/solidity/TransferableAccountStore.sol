// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "suave-std/Suapp.sol";
import "suave-std/suavelib/Suave.sol";
import "suave-std/Context.sol";
import "suave-std/Transactions.sol";
import "suave-std/suavelib/Suave.sol";

import "./interfaces/ITransferableAccountStore.sol";
import "./lib/EllipticCurve.sol";
import "./lib/Utils.sol";
import "./lib/SignatureVerifier.sol";

contract TransferableAccountStore is Suapp, ITransferableAccountStore {
    using SignatureVerifier for SignatureVerifier.TimedSignature;

    /**
     * Constants
     */
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    string public KEY_FA = "KEY";

    mapping(string => Account) public accountsStore;
    mapping(Suave.DataId => address) public accountApprovals;
    mapping(string => TimeLock) private accountTimeLocks;

    /**
     * Modifiers
     */
    modifier onlyApproved(string memory accountId) {
        require(isApproved(accountId, msg.sender), "Address not approved");
        _;
    }

    /**
     * Functions
     */

    /**
     * @dev Check if an address is approved for a given account
     * @param accountId The account ID
     * @param _address The address to check
     * @return bool Whether the address is approved
     */
    function isApproved(string memory accountId, address _address) public view returns (bool) {
        Account storage account = accountsStore[accountId];
        return accountApprovals[account.accountId] == _address;
    }

    /**
     * @dev Check if an address is the owner of a given account
     * @param accountId The account ID
     * @param _address The address to check
     * @return bool Whether the address is the owner
     */
    function isOwner(string memory accountId, address _address) public view returns (bool) {
        Account storage account = accountsStore[accountId];
        if (account.owner == _address) {
            return true;
        }

        return false;
    }

    /**
     * @dev Check if an account is locked
     * @param accountId The account ID
     * @return bool Whether the account is locked
     */
    function isLocked(string memory accountId) public view returns (bool) {
        TimeLock memory lock = accountTimeLocks[accountId];
        return (lock.lockUntil > block.timestamp);
    }

    /**
     * @dev Get the lock for an account
     * @param accountId The account ID
     * @return TimeLock The lock
     */
    function getLock(string memory accountId) public view returns (TimeLock memory) {
        return accountTimeLocks[accountId];
    }

    /**
     * @dev Get an account by its ID
     * @param accountId The account ID
     * @return Account The account
     */
    function getAccount(string memory accountId) public view returns (Account memory) {
        return accountsStore[accountId];
    }

    /**
     * @dev Approve an address for a given account
     * @param accountId The account ID
     * @param _address The address to approve
     */
    function approveAddressCallback(Suave.DataId accountId, address _address) public emitOffchainLogs {
        accountApprovals[accountId] = _address;
        emit AddressApproved(Utils.iToHex(abi.encodePacked(accountId)), _address);
    }

    /**
     * @dev Approve an address for a given account
     * @param accountId The account ID
     * @param _address The address to approve
     * @return bytes The encoded callback data
     */
    function approveAddress(
        SignatureVerifier.TimedSignature calldata signature,
        string memory accountId,
        address _address
    ) external returns (bytes memory) {
        Account storage account = accountsStore[accountId];
        require(account.owner == msg.sender, "Only owner can approve addresses");
        return abi.encodePacked(this.approveAddressCallback.selector, abi.encode(account.accountId, _address));
    }

    /**
     * @dev Revoke an address for a given account
     * @param accountId The account ID
     * @param _address The address to revoke
     */
    function revokeApproval(
        SignatureVerifier.TimedSignature calldata signature,
        string memory accountId,
        address _address
    ) public {
        Account storage account = accountsStore[accountId];
        require(account.owner == msg.sender, "Only owner can revoke addresses");
        delete accountApprovals[account.accountId];
        emit ApprovalRevoked(accountId, _address);
    }

    /**
     * @dev Store an account in the store
     * @param account The account to store
     * @return string The account ID
     */
    function storeAccount(Account memory account) internal returns (string memory) {
        string memory accountId = Utils.iToHex(abi.encodePacked(account.accountId));
        accountsStore[accountId] = account;
        emit AccountCreated(accountId, account);
        return accountId;
    }

    /**
     * @dev Create an account
     * @param account The account to create
     * @return string The account ID
     */
    function createAccountCallback(Account memory account) public emitOffchainLogs returns (string memory) {
        string memory accountId = storeAccount(account);
        return accountId;
    }

    /**
     * @dev Create an account
     * @return bytes The encoded callback data
     */
    function createAccount(SignatureVerifier.TimedSignature calldata signature) public returns (bytes memory) {
        string memory keyData = Suave.privateKeyGen(Suave.CryptoSignature.SECP256);

        address[] memory peekers = new address[](1);
        peekers[0] = address(this);

        Suave.DataRecord memory record = Suave.newDataRecord(10, peekers, peekers, "private_key");
        Suave.confidentialStore(record.id, KEY_FA, abi.encodePacked(keyData));
        (uint256 x, uint256 y) = generatePublicKey(Utils.hexStringToUint256(keyData));
        address[] memory approvedAddresses = new address[](1);
        approvedAddresses[0] = msg.sender;

        Account memory account =
            Account({accountId: record.id, owner: msg.sender, publicKeyX: x, publicKeyY: y, curve: Curve.ECDSA});

        return abi.encodePacked(this.createAccountCallback.selector, abi.encode(account));
    }

    /**
     * @dev Transfer an account to another address
     * @param to The address to transfer the account to
     * @param accountId The account ID
     */
    function transferAccountCallback(address to, string memory accountId) public {
        Account storage account = accountsStore[accountId];
        account.owner = to;

        // Reset approved addresses
        delete accountApprovals[account.accountId];

        emit AccountTransferred(accountId, account);
    }

    /**
     * @dev Transfer an account to another address
     * @param to The address to transfer the account to
     * @param accountId The account ID
     * @return bytes The encoded callback data
     */
    function transferAccount(SignatureVerifier.TimedSignature calldata signature, address to, string memory accountId)
        public
        returns (bytes memory)
    {
        // TODO: verify signature
        require(isOwner(accountId, signature.signer), "Only owner can transfer accounts");
        return abi.encodePacked(this.transferAccountCallback.selector, abi.encode(to, accountId));
    }

    /**
     * @dev Delete an account
     * @param accountId The account ID
     */
    function deleteAccountCallback(string memory accountId) public onlyApproved(accountId) {
        delete accountsStore[accountId];
        emit AccountDeleted(accountId);
    }

    /**
     * @dev Delete an account
     * @param accountId The account ID
     * @return bytes The encoded callback data
     */
    function deleteAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId)
        public
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(this.deleteAccountCallback.selector, abi.encode(accountId));
    }

    /**
     * @dev Lock an account
     * @param accountId The account ID
     * @param duration The duration to lock the account for
     */
    function lockAccountCallback(string memory accountId, uint256 duration) public onlyApproved(accountId) {
        require(!isLocked(accountId), "Account is already locked");
        accountTimeLocks[accountId] = TimeLock({lockUntil: block.timestamp + duration, lockedBy: msg.sender});
        emit AccountLocked(accountId, duration);
    }

    /**
     * @dev Lock an account
     * @param accountId The account ID
     * @return bytes The encoded callback data
     */
    function lockAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId, uint256 duration)
        public
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(this.lockAccountCallback.selector, abi.encode(accountId));
    }

    /**
     * @dev Unlock an account
     * @param accountId The account ID
     */
    function unlockAccountCallback(string memory accountId) public onlyApproved(accountId) {
        require(isLocked(accountId), "Account is not locked");
        delete accountTimeLocks[accountId];
        emit AccountUnlocked(accountId);
    }

    /**
     * @dev Unlock an account
     * @param accountId The account ID
     * @return bytes The encoded callback data
     */
    function unlockAccount(SignatureVerifier.TimedSignature calldata signature, string memory accountId)
        public
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(this.unlockAccountCallback.selector, abi.encode(accountId));
    }

    function signCallback() public emitOffchainLogs {}

    /**
     * @dev Sign data
     * @param accountId The account ID
     * @param data The data to sign
     * @return bytes The encoded callback data
     */
    function sign(Suave.DataId accountId, bytes memory data) public returns (bytes memory) {
        bytes memory signingKey = Suave.confidentialRetrieve(accountId, KEY_FA);
        bytes memory signature = signData(data, string(signingKey));
        string memory accountIdString = Utils.iToHex(abi.encodePacked(accountId));
        emit Signature(accountIdString, signature);
        return abi.encodePacked(this.signCallback.selector);
    }

    /**
     * @dev Sign data
     * @param data The data to sign
     * @param privateKeyString The private key to sign the data with
     * @return bytes The signature
     */
    function signData(bytes memory data, string memory privateKeyString) private returns (bytes memory) {
        bytes memory signature = Suave.signMessage(data, Suave.CryptoSignature.SECP256, privateKeyString);
        return signature;
    }

    /**
     * @dev Generate a public key from a private key
     * @param privKey The private key
     * @return uint256 The x coordinate of the public key
     * @return uint256 The y coordinate of the public key
     */
    function generatePublicKey(uint256 privKey) private pure returns (uint256, uint256) {
        return EllipticCurve.ecMul(privKey, GX, GY, AA, PP);
    }
}
