// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "suave-std/Test.sol";
import "suave-std/suavelib/Suave.sol";
import "../src/solidity/TransferableAccountStore.sol";
import "../src/solidity/interfaces/ITransferableAccountStore.sol";

contract TransferableAccountStoreTest is Test, SuaveEnabled {
    address public admin = address(this);
    address public user1 = address(0x1);

    // Helper function to decode encoded data
    function decodeEncodedData(bytes memory encodedData) internal pure returns (bytes memory) {
        bytes memory decodedData = new bytes(encodedData.length - 4);
        for (uint256 i = 4; i < encodedData.length; i++) {
            decodedData[i - 4] = encodedData[i];
        }
        return decodedData;
    }

    function testCreateAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        assertEq(account.owner, address(this), "Owner should be the test contract");
        assertTrue(account.isLocked, "Account should be locked");
    }

    function testCreateAccountCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        (
            Suave.DataId storedAccountId,
            address storedOwner,
            uint256 storedPublicKeyX,
            uint256 storedPublicKeyY,
            ITransferableAccountStore.Curve storedCurve,
            bool isLocked
        ) = tas.accountsStore(accountId);
        bytes16 storedAccountIdBytes = Suave.DataId.unwrap(storedAccountId);
        string memory storedAccountIdToString = StringUtils.bytes16ToString(storedAccountIdBytes);
        assertEq(storedAccountIdToString, accountId, "Stored account ID should match");
        assertEq(storedOwner, account.owner, "Stored account owner should match");
        assertEq(storedPublicKeyX, account.publicKeyX, "Stored account public key X should match");
        assertEq(storedPublicKeyY, account.publicKeyY, "Stored account public key Y should match");
        assertEq(uint256(storedCurve), uint256(account.curve), "Stored account curve should match");
        assertTrue(isLocked, "Stored account should be locked");
    }

    function testApproveAddress() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);
        bytes memory approveData = decodeEncodedData(encodedApproveAddressData);

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveData, (bytes16, address));
        assertEq(StringUtils.bytes16ToString(decodedAccountId), accountId, "Approved account ID should match");
        assertEq(decodedAddress, user1, "Approved account address should match");
    }

    function testApproveAddressCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveAddressData, (bytes16, address));

        tas.approveAddressCallback(Suave.DataId.wrap(decodedAccountId), decodedAddress);

        address approvedAddress = tas.accountApprovals(Suave.DataId.wrap(decodedAccountId));
        assertEq(approvedAddress, decodedAddress, "Approved account address should match");
    }

    function testTransferAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveAddressData, (bytes16, address));
        tas.approveAddressCallback(Suave.DataId.wrap(decodedAccountId), decodedAddress);

        bytes memory encodedTransferAccountData = tas.transferAccount(accountId, user1);
        bytes memory transferAccountData = decodeEncodedData(encodedTransferAccountData);

        (string memory decodedTransferdAccountId, address decodedToAddress) =
            abi.decode(transferAccountData, (string, address));
        assertEq(decodedTransferdAccountId, accountId, "Approved account ID should match");
        assertEq(decodedToAddress, user1, "Approved account address should match");
    }

    function testTransferAccountCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveAddressData, (bytes16, address));
        tas.approveAddressCallback(Suave.DataId.wrap(decodedAccountId), decodedAddress);

        bytes memory encodedTransferAccountData = tas.transferAccount(accountId, user1);
        bytes memory transferAccountData = decodeEncodedData(encodedTransferAccountData);

        (string memory decodedTransferdAccountId, address decodedToAddress) =
            abi.decode(transferAccountData, (string, address));

        vm.prank(user1);
        tas.transferAccountCallback(decodedTransferdAccountId, decodedToAddress);

        (, address newOwner,,,, bool isAccountLocked) = tas.accountsStore(decodedTransferdAccountId);
        assertEq(newOwner, user1, "Stored account owner should match");

        assertTrue(isAccountLocked, "Transfered account should be locked");
    }

    function testIsApproved() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveAddressData, (bytes16, address));
        tas.approveAddressCallback(Suave.DataId.wrap(decodedAccountId), decodedAddress);

        bool isApproved = tas.isApproved(accountId, user1);
        assertTrue(isApproved, "Address should be approved");

        tas.revokeApproval(accountId, user1);
        isApproved = tas.isApproved(accountId, user1);
        assertFalse(isApproved, "Address should not be approved after revocation");
    }

    function testIsOwner() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);

        bool isOwner = tas.isOwner(accountId, address(this));
        assertTrue(isOwner, "Address should be the owner");

        isOwner = tas.isOwner(accountId, user1);
        assertFalse(isOwner, "Address should not be the owner");
    }

    function testGetAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);

        ITransferableAccountStore.Account memory retrievedAccount = tas.getAccount(accountId);
        bytes16 retrievedAccountIdBytes = Suave.DataId.unwrap(retrievedAccount.accountId);

        assertEq(StringUtils.bytes16ToString(retrievedAccountIdBytes), accountId, "Account ID should match");
        assertEq(retrievedAccount.owner, account.owner, "Owner should match");
        assertEq(retrievedAccount.publicKeyX, account.publicKeyX, "Public Key X should match");
        assertEq(retrievedAccount.publicKeyY, account.publicKeyY, "Public Key Y should match");
        assertEq(uint256(retrievedAccount.curve), uint256(account.curve), "Curve should match");
    }

    function testRevokeApproval() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        tas.approveAddress(accountId, user1);
        tas.approveAddressCallback(account.accountId, user1);

        bool isApproved = tas.isApproved(accountId, user1);
        assertTrue(isApproved, "Address should be approved");

        tas.revokeApproval(accountId, user1);
        isApproved = tas.isApproved(accountId, user1);
        assertFalse(isApproved, "Address should not be approved after revocation");
    }

    function testDeleteAccountCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(account);

        ITransferableAccountStore.Account memory retrievedAccount = tas.getAccount(accountId);
        assertEq(retrievedAccount.owner, account.owner, "Owner should match before deletion");

        bytes memory encodedDeleteAccountData = tas.deleteAccount(accountId);
        bytes memory deleteAccountData = decodeEncodedData(encodedDeleteAccountData);

        (string memory decodedAccountId) = abi.decode(deleteAccountData, (string));
        tas.deleteAccountCallback(decodedAccountId);

        retrievedAccount = tas.getAccount(decodedAccountId);
        assertEq(retrievedAccount.owner, address(0), "Owner should be zero address after deletion");
    }

    function testUnlockAccountCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(account);

        bool isAccountLocked = tas.isAccountLocked(accountId);
        assertTrue(isAccountLocked, "Account should be locked immediately after creation");

        tas.unlockAccountCallback(accountId);

        isAccountLocked = tas.isAccountLocked(accountId);
        assertFalse(isAccountLocked, "Account should be unlocked");
    }
}

library StringUtils {
    function bytes16ToString(bytes16 data) internal pure returns (string memory) {
        bytes memory bytesArray = new bytes(34); // 0x + 32 characters
        bytesArray[0] = "0";
        bytesArray[1] = "x";
        for (uint256 i = 0; i < 16; i++) {
            bytesArray[2 + i * 2] = _byteToHexChar(uint8(data[i]) / 16);
            bytesArray[2 + i * 2 + 1] = _byteToHexChar(uint8(data[i]) % 16);
        }
        return string(bytesArray);
    }

    function _byteToHexChar(uint8 b) private pure returns (bytes1) {
        if (b < 10) {
            return bytes1(b + 0x30); // 0-9 -> '0'-'9'
        } else {
            return bytes1(b + 0x57); // 10-15 -> 'a'-'f'
        }
    }
}
