// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "suave-std/Test.sol";
import "suave-std/suavelib/Suave.sol";
import "../src/solidity/TransferableAccountStore.sol";
import "../src/solidity/interfaces/ITransferableAccountStore.sol";

contract TransferableAccountStoreTest is Test, SuaveEnabled {
    address public owner;
    address public user1 = address(0x1);

    function testCreateAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedData = tas.createAccount();

        bytes4 selector;
        bytes memory accountData;

        assembly {
            selector := mload(add(encodedData, 32))
        }

        accountData = new bytes(encodedData.length - 4);
        for (uint256 i = 4; i < encodedData.length; i++) {
            accountData[i - 4] = encodedData[i];
        }

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));
        console.log("Owner:", account.owner);
        console.log("Public Key X:", account.publicKeyX);
        console.log("Public Key Y:", account.publicKeyY);

        assertEq(account.owner, address(this), "Owner should be the test contract");
    }

    function testCreateAccountCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedData = tas.createAccount();

        bytes4 selector;
        bytes memory accountData;

        assembly {
            selector := mload(add(encodedData, 32))
        }

        accountData = new bytes(encodedData.length - 4);
        for (uint256 i = 4; i < encodedData.length; i++) {
            accountData[i - 4] = encodedData[i];
        }

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        (
            Suave.DataId storedAccountId,
            address storedOwner,
            uint256 storedPublicKeyX,
            uint256 storedPublicKeyY,
            ITransferableAccountStore.Curve storedCurve
        ) = tas.accountsStore(accountId);
        bytes16 storedAccountIdBytes = Suave.DataId.unwrap(storedAccountId);
        string memory storedAccountIdToString = bytes16ToString(storedAccountIdBytes);
        assertEq(storedAccountIdToString, accountId, "Stored account ID should match");
        assertEq(storedOwner, account.owner, "Stored account owner should match");
        assertEq(storedPublicKeyX, account.publicKeyX, "Stored account public key X should match");
        assertEq(storedPublicKeyY, account.publicKeyY, "Stored account public key Y should match");
        assertEq(uint256(storedCurve), uint256(account.curve), "Stored account curve should match");
    }

    function testApproveAddress() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData;
        accountData = new bytes(encodedCreateAccountData.length - 4);
        for (uint256 i = 4; i < encodedCreateAccountData.length; i++) {
            accountData[i - 4] = encodedCreateAccountData[i];
        }

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);

        bytes4 selector;
        bytes memory approveData;

        assembly {
            selector := mload(add(encodedApproveAddressData, 32))
        }

        approveData = new bytes(encodedApproveAddressData.length - 4);
        for (uint256 i = 4; i < encodedApproveAddressData.length; i++) {
            approveData[i - 4] = encodedApproveAddressData[i];
        }

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveData, (bytes16, address));
        console.logBytes16(decodedAccountId);
        console.logAddress(decodedAddress);
        assertEq(bytes16ToString(decodedAccountId), accountId, "Approved account ID should match");
        assertEq(decodedAddress, user1, "Approved account address should match");
    }

    function testApproveAddressCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes memory encodedCreateAccountData = tas.createAccount();
        bytes memory accountData;
        accountData = new bytes(encodedCreateAccountData.length - 4);
        for (uint256 i = 4; i < encodedCreateAccountData.length; i++) {
            accountData[i - 4] = encodedCreateAccountData[i];
        }

        (ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(account);
        bytes memory encodedApproveAddressData = tas.approveAddress(accountId, user1);

        bytes4 selector;
        bytes memory approveAddressData;

        assembly {
            selector := mload(add(encodedApproveAddressData, 32))
        }

        approveAddressData = new bytes(encodedApproveAddressData.length - 4);
        for (uint256 i = 4; i < encodedApproveAddressData.length; i++) {
            approveAddressData[i - 4] = encodedApproveAddressData[i];
        }

        (bytes16 decodedAccountId, address decodedAddress) = abi.decode(approveAddressData, (bytes16, address));

        tas.approveAddressCallback(Suave.DataId.wrap(decodedAccountId), decodedAddress);

        address approvedAddress = tas.accountApprovals(Suave.DataId.wrap(decodedAccountId));
        assertEq(approvedAddress, decodedAddress, "Approved account address should match");
    }

    function bytes16ToString(bytes16 data) public pure returns (string memory) {
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
