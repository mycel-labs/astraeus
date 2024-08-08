// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "suave-std/Suapp.sol";
import "suave-std/suavelib/Suave.sol";
import "suave-std/Context.sol";
import "suave-std/Transactions.sol";
import "suave-std/suavelib/Suave.sol";

import "./lib/EllipticCurve.sol";
import "./lib/Utils.sol";

contract TransferableAccountStore is Suapp {
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    string public KEY_FA = "KEY";

    struct Account {
        Suave.DataId accountId;
        address creator;
        address owner;
        address ethereumAddress;
        uint256 publicKeyX;
        uint256 publicKeyY;
        address[] approvedAddresses;
        // for debug
        string key;
    }

    struct Approval {
        mapping(address => bool) approvedAddresses;
    }

    mapping(string => Account) public accountsStore;
    mapping(string => Suave.DataId) public accountIdStore;
    mapping(string => Approval) internal approvals;

    event AccountCreated(string accountId, Account account);
    event AccountTransferred(string accountId, Account account);
    event Signature(string accountId, bytes signature);
    event AddressApproved(string accountId, address approvedAddress);
    event AddressRevoked(string accountId, address revokedAddress);

    modifier onlyApproved(string memory accountId) {
        require(isApproved(accountId, msg.sender), "Address not approved");
        _;
    }

    function isApproved(string memory accountId, address _address) public view returns (bool) {
        Account storage account = accountsStore[accountId];
        for (uint256 i = 0; i < account.approvedAddresses.length; i++) {
            if (account.approvedAddresses[i] == _address) {
                return true;
            }
        }
        return false;
    }

    function isOwner(string memory accountId, address _address) public view returns (bool) {
        Account storage account = accountsStore[accountId];
        if (account.owner == _address) {
            return true;
        }

        return false;
    }

    function getAccount(string memory accountId) public view returns (Account memory) {
        return accountsStore[accountId];
    }

    function getEthereumAddress(string memory accountId) public view returns (address) {
        Account storage account = accountsStore[accountId];
        return account.ethereumAddress;
    }

    function approveAddressCallback(string memory accountId, address _address) public emitOffchainLogs {
        Account storage account = accountsStore[accountId];
        account.approvedAddresses.push(_address);
        emit AddressApproved(accountId, _address);
    }

    function approveAddress(string memory accountId, address _address) public view returns (bytes memory) {
        Account storage account = accountsStore[accountId];
        require(account.owner == msg.sender, "Only owner can approve addresses");
        return abi.encodePacked(this.approveAddressCallback.selector, abi.encode(accountId, _address));
    }

    function revokeAddress(string memory accountId, address _address) public {
        Account storage account = accountsStore[accountId];
        require(account.owner == msg.sender, "Only owner can revoke addresses");

        // Remove address from approvedAddresses
        uint256 length = account.approvedAddresses.length;
        for (uint256 i = 0; i < length; i++) {
            if (account.approvedAddresses[i] == _address) {
                account.approvedAddresses[i] = account.approvedAddresses[length - 1];
                account.approvedAddresses.pop();
                emit AddressRevoked(accountId, _address);
                break;
            }
        }
    }

    function storeAccount(Account memory account) public returns (string memory) {
        string memory accountId = Utils.iToHex(abi.encodePacked(account.accountId));
        accountsStore[accountId] = account;
        accountIdStore[accountId] = account.accountId;
        emit AccountCreated(accountId, account);
        return accountId;
    }

    function createAccountCallback(Account memory account) public emitOffchainLogs returns (string memory) {
        string memory accountId = storeAccount(account);
        return accountId;
    }

    function createAccount() public returns (bytes memory) {
        string memory keyData = Suave.privateKeyGen(Suave.CryptoSignature.SECP256);

        address[] memory peekers = new address[](1);
        peekers[0] = address(this);

        Suave.DataRecord memory record = Suave.newDataRecord(10, peekers, peekers, "private_key");
        Suave.confidentialStore(record.id, KEY_FA, abi.encodePacked(keyData));
        (uint256 x, uint256 y) = generatePublicKey(Utils.hexStringToUint256(keyData));
        address[] memory approvedAddresses = new address[](1);
        approvedAddresses[0] = msg.sender;

        Account memory account = Account({
            accountId: record.id,
            creator: msg.sender,
            owner: msg.sender,
            ethereumAddress: generateEthereumAddress(Utils.hexStringToUint256(keyData)),
            publicKeyX: x,
            publicKeyY: y,
            approvedAddresses: approvedAddresses,
            key: keyData
        });

        return abi.encodePacked(this.createAccountCallback.selector, abi.encode(account));
    }

    function transferAccountCallback(address to, string memory accountId) public onlyApproved(accountId) {
        Account storage account = accountsStore[accountId];
        require(account.creator != address(0), "Account not found");
        require(account.owner == account.creator, "Account already transferred");
        account.owner = to;

        // Reset approved addresses
        delete account.approvedAddresses;
        account.approvedAddresses.push(to);

        emit AccountTransferred(accountId, account);
    }

    function transferAccount(address to, string memory accountId) public pure returns (bytes memory) {
        return abi.encodePacked(this.transferAccountCallback.selector, abi.encode(to, accountId));
    }

    function signCallback() public emitOffchainLogs {}

    function sign(Suave.DataId accountId, bytes memory data) public returns (bytes memory) {
        bytes memory signingKey = Suave.confidentialRetrieve(accountId, KEY_FA);
        bytes memory signature = signData(data, string(signingKey));
        string memory accountIdString = Utils.iToHex(abi.encodePacked(accountId));
        emit Signature(accountIdString, signature);
        return abi.encodePacked(this.signCallback.selector);
    }

    function signData(bytes memory data, string memory privateKeyString) private returns (bytes memory) {
        bytes memory signature = Suave.signMessage(data, Suave.CryptoSignature.SECP256, privateKeyString);
        return signature;
    }

    function generatePublicKey(uint256 privKey) public pure returns (uint256, uint256) {
        return EllipticCurve.ecMul(privKey, GX, GY, AA, PP);
    }

    function generateEthereumAddress(uint256 privKey) public pure returns (address) {
        (uint256 x, uint256 y) = generatePublicKey(privKey);
        bytes memory publicKey = abi.encodePacked(x, y);

        // Perform Keccak-256 hashing
        bytes32 hashedKey = keccak256(publicKey);

        // Take the last 20 bytes of the hashed key as the Ethereum address
        return address(uint160(uint256(hashedKey)));
    }
}
