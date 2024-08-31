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

    /**
     * Modifiers
     */
    modifier onlyLocked(string memory accountId) {
        require(isAccountLocked(accountId), "Account must be locked to perform this action");
        _;
    }

    modifier onlyUnlocked(string memory accountId) {
        require(!isAccountLocked(accountId), "Account must be unlocked to perform this action");
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
    function isAccountLocked(string memory accountId) public view returns (bool) {
        Account storage account = accountsStore[accountId];
        return account.isLocked;
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
    function approveAddressCallback(
        SignatureVerifier.TimedSignature calldata timedSignature,
        Suave.DataId accountId,
        address _address
    ) public emitOffchainLogs onlyLocked(Utils.iToHex(abi.encodePacked(accountId))) {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(
            isOwner(Utils.iToHex(abi.encodePacked(accountId)), timedSignature.signer),
            "The signer is not the owner of the account."
        );
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
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        address _address
    ) external view onlyLocked(accountId) returns (bytes memory) {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");

        Account storage account = accountsStore[accountId];
        require(account.owner == timedSignature.signer, "Only owner can approve addresses");
        return abi.encodePacked(
            this.approveAddressCallback.selector, abi.encode(timedSignature, account.accountId, _address)
        );
    }

    /**
     * @dev Revoke an address for a given account
     * @param accountId The account ID
     * @param _address The address to revoke
     */
    function revokeApproval(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        address _address
    ) public onlyLocked(accountId) {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");

        Account storage account = accountsStore[accountId];
        require(account.owner == timedSignature.signer, "Only owner can revoke addresses");
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
    function createAccountCallback(SignatureVerifier.TimedSignature calldata timedSignature, Account memory account)
        public
        emitOffchainLogs
        returns (string memory)
    {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(timedSignature.signer == account.owner, "The signer is not the owner of the account.");
        require(account.isLocked == true, "The account should be locked by default");
        string memory accountId = storeAccount(account);
        return accountId;
    }

    /**
     * @dev Create an account
     * @return bytes The encoded callback data
     */
    function createAccount(SignatureVerifier.TimedSignature calldata timedSignature) public returns (bytes memory) {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");

        string memory keyData = Suave.privateKeyGen(Suave.CryptoSignature.SECP256);

        address[] memory peekers = new address[](1);
        peekers[0] = address(this);

        Suave.DataRecord memory record = Suave.newDataRecord(10, peekers, peekers, "private_key");
        Suave.confidentialStore(record.id, KEY_FA, abi.encodePacked(keyData));
        (uint256 x, uint256 y) = generatePublicKey(Utils.hexStringToUint256(keyData));
        address[] memory approvedAddresses = new address[](1);
        approvedAddresses[0] = timedSignature.signer;

        Account memory account = Account({
            accountId: record.id,
            owner: timedSignature.signer,
            publicKeyX: x,
            publicKeyY: y,
            curve: Curve.ECDSA,
            isLocked: true
        });

        return abi.encodePacked(this.createAccountCallback.selector, abi.encode(timedSignature, account));
    }

    /**
     * @dev Transfer an account to another address
     * @param to The address to transfer the account to
     * @param accountId The account ID
     */
    function transferAccountCallback(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        address to
    ) public onlyLocked(accountId) {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(isApproved(accountId, timedSignature.signer), "the signer is not approved");
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
    function transferAccount(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        address to
    ) public view onlyLocked(accountId) returns (bytes memory) {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(isApproved(accountId, timedSignature.signer), "the signer is not approved");
        return abi.encodePacked(this.transferAccountCallback.selector, abi.encode(timedSignature, accountId, to));
    }

    /**
     * @dev Delete an account
     * @param accountId The account ID
     */
    function deleteAccountCallback(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId)
        public
    {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(isOwner(accountId, timedSignature.signer), "The signer is not the owner of the account.");
        delete accountsStore[accountId];
        emit AccountDeleted(accountId);
    }

    /**
     * @dev Delete an account
     * @param accountId The account ID
     * @return bytes The encoded callback data
     */
    function deleteAccount(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId)
        public
        view
        returns (bytes memory)
    {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(isOwner(accountId, timedSignature.signer), "The signer is not the owner of the account.");
        return abi.encodePacked(this.deleteAccountCallback.selector, abi.encode(timedSignature, accountId));
    }

    /**
     * @dev Unlock an account
     * @param accountId The account ID
     */
    function unlockAccountCallback(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId)
        public
        onlyLocked(accountId)
    {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        require(isOwner(accountId, timedSignature.signer), "The signer is not the owner of the account.");
        Account storage account = accountsStore[accountId];
        account.isLocked = false;
        emit AccountUnlocked(accountId);
    }

    /**
     * @dev Unlock an account
     * @param accountId The account ID
     * @return bytes The encoded callback data
     */
    function unlockAccount(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId)
        public
        view
        onlyLocked(accountId)
        returns (bytes memory)
    {
        require(_verifyTimedSignature(timedSignature), "Invalid timedSignature");
        return abi.encodePacked(this.unlockAccountCallback.selector, abi.encode(timedSignature, accountId));
    }

    function signCallback() public emitOffchainLogs {}

    /**
     * @dev Sign data
     * @param accountId The account ID
     * @param data The data to sign
     * @return bytes The encoded callback data
     */
    function sign(Suave.DataId accountId, bytes memory data)
        public
        onlyUnlocked(Utils.iToHex(abi.encodePacked(accountId)))
        returns (bytes memory)
    {
        bytes memory signingKey = Suave.confidentialRetrieve(accountId, KEY_FA);
        bytes memory signature = signData(data, string(signingKey));
        string memory accountIdString = Utils.iToHex(abi.encodePacked(accountId));
        emit Signature(accountIdString, signature);
        return abi.encodePacked(this.signCallback.selector);
    }

    /**
     * @dev Verify a timed signature
     * @param timedSignature The timedSignature to verify
     * @return bool Whether the timedSignature is valid
     */
    function verifyTimedSignature(SignatureVerifier.TimedSignature calldata timedSignature)
        public
        view
        returns (bool)
    {
        return _verifyTimedSignature(timedSignature);
    }

    /**
     * @dev Verify a timed signature
     * @param timedSignature The timedSignature to verify
     * @return bool Whether the timedSignature is valid
     */
    function _verifyTimedSignature(SignatureVerifier.TimedSignature calldata timedSignature)
        private
        view
        returns (bool)
    {
        return SignatureVerifier.verifyTimedSignature(
            timedSignature.validFor, timedSignature.messageHash, timedSignature.signature, timedSignature.signer
        );
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
