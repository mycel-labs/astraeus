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
    mapping(address => uint64) public nonces;

    /**
     * Modifiers
     */
    modifier onlyLocked(string memory accountId) {
        require(isAccountLocked(accountId), "Account must be locked to perform this action");
        _;
    }

    /**
     * Errors
     */
    error InvalidTimedSignature();
    error OnlyOwnerCanApproveAddresses();
    error OnlyOwnerCanRevokeApproval();
    error OnlyOwnerCanDeleteAccount();
    error OnlyOwnerCanUnlockAccount();
    error OnlyApprovedAccount();
    error OnlyUnlockAccount();

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
        if (account.owner == _address) {
            return true;
        }
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
    function approveAddress(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        address _address
    ) external onlyLocked(accountId) {
        // keccak256("ApproveAddress(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)");
        bytes32 APPROVE_ADDRESS_FUNCTION_HASH = 0x16d1dabab53b460506870428d7a255f9bff53294080a73797c114f4e25b5e76f;
        if (!consumeNonce(timedSignature, APPROVE_ADDRESS_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        Account storage account = accountsStore[accountId];
        if (!isOwner(accountId, timedSignature.signer)) {
            revert OnlyOwnerCanApproveAddresses();
        }
        accountApprovals[account.accountId] = _address;
        emit AddressApproved(Utils.iToHex(abi.encodePacked(accountId)), _address);
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
        // keccak256("RevokeApproval(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)");
        bytes32 REVOKE_APPROVAL_FUNCTION_HASH = 0xdb4c3d2d6140b1cf852cff55c9c9a3d0c16d15c9da5e35f87fdc664b1bbf1c32;
        if (!consumeNonce(timedSignature, REVOKE_APPROVAL_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        if (!isOwner(accountId, timedSignature.signer)) {
            revert OnlyOwnerCanRevokeApproval();
        }

        Account storage account = accountsStore[accountId];
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
        // keccak256("CreateAccount(SignatureVerifier.TimedSignature timedSignature)");
        bytes32 CREATE_ACCOUNT_FUNCTION_HASH = 0x030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f;
        if (!consumeNonce(timedSignature, CREATE_ACCOUNT_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        require(timedSignature.signer == account.owner, "The signer is not the owner of the account.");
        require(account.isLocked == true, "The account should be locked by default");
        string memory accountId = storeAccount(account);
        return accountId;
    }

    /**
     * @dev Create an account
     * @return bytes The encoded callback data
     */
    function createAccount(SignatureVerifier.TimedSignature calldata timedSignature)
        public
        confidential
        returns (bytes memory)
    {
        // keccak256("CreateAccount(SignatureVerifier.TimedSignature timedSignature)");
        bytes32 CREATE_ACCOUNT_FUNCTION_HASH = 0x030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f;
        if (!verifyTimedSignature(timedSignature, CREATE_ACCOUNT_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }

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
    function transferAccount(
        SignatureVerifier.TimedSignature calldata timedSignature,
        string memory accountId,
        address to
    ) public onlyLocked(accountId) {
        // keccak256("TransferAccount(SignatureVerifier.TimedSignature timedSignature,string accountId,address to)");
        bytes32 TRANSFER_ACCOUNT_FUNCTION_HASH = 0x29535a955f68dc291a88a89b6112c958d2edce1684117ccd6b54ca173656f65f;
        if (!consumeNonce(timedSignature, TRANSFER_ACCOUNT_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        if (!isApproved(accountId, timedSignature.signer)) {
            revert OnlyApprovedAccount();
        }
        Account storage account = accountsStore[accountId];
        account.owner = to;

        // Reset approved addresses
        delete accountApprovals[account.accountId];
        emit AccountTransferred(accountId, account);
    }

    /**
     * @dev Delete an account
     * @param accountId The account ID
     */
    function deleteAccount(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId) public {
        // keccak256("DeleteAccount(SignatureVerifier.TimedSignature timedSignature,string accountId)");
        bytes32 DELETE_ACCOUNT_FUNCTION_HASH = 0x31819315e31d5175ae85114dd27816114c585abc7f9d53ef5ca9bf3c4f2db038;
        if (!consumeNonce(timedSignature, DELETE_ACCOUNT_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        if (!isOwner(accountId, timedSignature.signer)) {
            revert OnlyOwnerCanDeleteAccount();
        }
        delete accountsStore[accountId];
        emit AccountDeleted(accountId);
    }

    /**
     * @dev Unlock an account
     * @param accountId The account ID
     */
    function unlockAccount(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId)
        public
        onlyLocked(accountId)
    {
        // keccak256("UnlockAccount(SignatureVerifier.TimedSignature timedSignature,string accountId)");
        bytes32 UNLOCK_ACCOUNT_FUNCTION_HASH = 0x062e71868bb32b076e90fa8fa0fa661f47d2f38ee0e9db39a5ab5569589f6332;
        if (!consumeNonce(timedSignature, UNLOCK_ACCOUNT_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        if (!isOwner(accountId, timedSignature.signer)) {
            revert OnlyOwnerCanUnlockAccount();
        }
        Account storage account = accountsStore[accountId];
        account.isLocked = false;
        emit AccountUnlocked(accountId);
    }

    function signCallback() public emitOffchainLogs {}

    /**
     * @dev Sign data
     * @param accountId The account ID
     * @param data The data to sign
     * @return bytes The encoded callback data
     */
    function sign(SignatureVerifier.TimedSignature calldata timedSignature, string memory accountId, bytes memory data)
        public
        confidential
        returns (bytes memory)
    {
        // keccak256("Sign(SignatureVerifier.TimedSignature timedSignature,string accountId,bytes data)");
        bytes32 SIGN_FUNCTION_HASH = 0xd34780a58dd276dd414ea2abde077f3492ca5422926cdcadf8def7a93f12e993;
        if (!verifyTimedSignature(timedSignature, SIGN_FUNCTION_HASH)) {
            revert InvalidTimedSignature();
        }
        if (!isApproved(accountId, timedSignature.signer)) {
            revert OnlyApprovedAccount();
        }
        if (isAccountLocked(accountId)) {
            revert OnlyUnlockAccount();
        }

        Account storage account = accountsStore[accountId];
        require(account.owner != address(0), "Account does not exist");

        bytes memory signingKey = Suave.confidentialRetrieve(account.accountId, KEY_FA);
        require(signingKey.length > 0, "Signing key not found");

        bytes memory signature = Suave.signMessage(data, Suave.CryptoSignature.SECP256, string(signingKey));
        emit Signature(signature);

        return abi.encodePacked(this.signCallback.selector);
    }

    /**
     * @dev Verify a timed signature
     * @param timedSignature The timedSignature to verify
     * @return bool Whether the timedSignature is valid
     */
    function consumeNonce(SignatureVerifier.TimedSignature calldata timedSignature, bytes32 targetFunctionHash)
        public
        returns (bool)
    {
        require(timedSignature.nonce == nonces[timedSignature.signer], "Invalid nonce");
        bool isValid = verifyTimedSignature(timedSignature, targetFunctionHash);
        if (isValid) {
            nonces[timedSignature.signer]++;
        }
        return isValid;
    }

    /**
     * @dev Verify a timed signature
     * @param timedSignature The timedSignature to verify
     * @return bool Whether the timedSignature is valid
     */
    function verifyTimedSignature(SignatureVerifier.TimedSignature calldata timedSignature, bytes32 targetFunctionHash)
        public
        view
        returns (bool)
    {
        require(timedSignature.targetFunctionHash == targetFunctionHash, "Invalid targetFunctionHash");
        return SignatureVerifier.verifyTimedSignature(
            timedSignature.validFor,
            timedSignature.messageHash,
            timedSignature.signature,
            timedSignature.signer,
            nonces[timedSignature.signer],
            targetFunctionHash
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

    /**
     * @dev Get the nonce for a given address
     * @param _address The address to get the nonce for
     * @return uint64 The nonce associated with the address
     */
    function getNonce(address _address) public view returns (uint64) {
        return nonces[_address];
    }
}
