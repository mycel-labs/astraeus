// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "suave-std/Test.sol";
import "suave-std/suavelib/Suave.sol";
import "../src/solidity/TransferableAccountStore.sol";
import "../src/solidity/interfaces/ITransferableAccountStore.sol";
import "../src/solidity/lib/SignatureVerifier.sol";

contract TransferableAccountStoreTest is Test, SuaveEnabled {
    address public admin = address(this);
    uint256 alicePrivateKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    uint256 bobPrivateKey = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

    address public alice = vm.addr(alicePrivateKey);
    address public bob = vm.addr(bobPrivateKey);

    function generateTimedSignature(uint64 validFor, address signer, uint256 privateKey)
        internal
        pure
        returns (SignatureVerifier.TimedSignature memory)
    {
        bytes32 messageHash = SignatureVerifier.hashMessage(validFor, signer);
        bytes32 mycelSignedMessageHash = keccak256(abi.encodePacked("\x19Mycel Signed Message:\n32", messageHash));
        bytes memory signature = signMessage(mycelSignedMessageHash, privateKey);

        return SignatureVerifier.TimedSignature({
            validFor: validFor,
            messageHash: messageHash,
            signature: signature,
            signer: signer
        });
    }

    function signMessage(bytes32 messageHash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function setupTransferableAccountStore(uint64 validFor, address user, uint256 privateKey)
        internal
        returns (TransferableAccountStore, SignatureVerifier.TimedSignature memory)
    {
        vm.prank(user);
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig = generateTimedSignature(validFor, user, privateKey);
        return (tas, sig);
    }

    function testVerifyTimedSignature() public {
        vm.warp(1000);
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);

        bool isValid = tas.verifyTimedSignature(sig);
        assertTrue(isValid, "Valid signature should be accepted");

        vm.warp(uint64(block.timestamp + 86401));
        isValid = tas.verifyTimedSignature(sig);
        assertFalse(isValid, "Expired signature should be rejected");

        sig.signature[0] ^= 0xFF;
        isValid = tas.verifyTimedSignature(sig);
        assertFalse(isValid, "Invalid signature should be rejected");
    }

    // Helper function to decode encoded data
    function decodeEncodedData(bytes memory encodedData) internal pure returns (bytes memory) {
        bytes memory decodedData = new bytes(encodedData.length - 4);
        for (uint256 i = 4; i < encodedData.length; i++) {
            decodedData[i - 4] = encodedData[i];
        }
        return decodedData;
    }

    function testCreateAccount() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        assertEq(decodedTimedSignature.signature, sig.signature, "Signature should be same");
        assertEq(decodedAccount.owner, sig.signer, "Owner should be alice");
        assertTrue(decodedAccount.isLocked, "Account should be locked");
    }

    function testCreateAccountCallback() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);
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
        assertEq(storedOwner, decodedAccount.owner, "Stored account owner should match");
        assertEq(storedPublicKeyX, decodedAccount.publicKeyX, "Stored account public key X should match");
        assertEq(storedPublicKeyY, decodedAccount.publicKeyY, "Stored account public key Y should match");
        assertEq(uint256(storedCurve), uint256(decodedAccount.curve), "Stored account curve should match");
        assertTrue(isLocked, "Stored account shouold be locked");
    }

    function testApproveAddress() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory decodedAccount) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(sig, decodedAccount);
        bytes memory encodedApproveAddressData = tas.approveAddress(sig, accountId, bob);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            bytes16 decodedAccountId,
            address decodedAddress
        ) = abi.decode(approveAddressData, (SignatureVerifier.TimedSignature, bytes16, address));

        assertEq(decodedTimedSignature.signature, sig.signature, "Signature should be same");
        assertEq(StringUtils.bytes16ToString(decodedAccountId), accountId, "Approved account ID should match");
        assertEq(decodedAddress, bob, "Approved account address should match");
    }

    function testApproveAddressCallback() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory decodedAccount) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(sig, decodedAccount);
        bytes memory encodedApproveAddressData = tas.approveAddress(sig, accountId, bob);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            bytes16 decodedAccountId,
            address decodedAddress
        ) = abi.decode(approveAddressData, (SignatureVerifier.TimedSignature, bytes16, address));
        tas.approveAddressCallback(decodedTimedSignature, Suave.DataId.wrap(decodedAccountId), decodedAddress);

        assertEq(decodedAddress, bob, "Approved account address should match");

        address approvedAddress = tas.accountApprovals(Suave.DataId.wrap(decodedAccountId));
        assertEq(approvedAddress, decodedAddress, "Approved account address should match");
    }

    function testTransferAccount() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory aliceSig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(aliceSig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(aliceSig, account);
        bytes memory encodedApproveAddressData = tas.approveAddress(aliceSig, accountId, bob);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (, bytes16 decodedAccountId, address decodedAddress) =
            abi.decode(approveAddressData, (SignatureVerifier.TimedSignature, bytes16, address));
        tas.approveAddressCallback(aliceSig, Suave.DataId.wrap(decodedAccountId), decodedAddress);

        SignatureVerifier.TimedSignature memory bobSig =
            generateTimedSignature(uint64(block.timestamp + 86400), bob, bobPrivateKey);

        bytes memory encodedTransferAccountData = tas.transferAccount(bobSig, accountId, bob);
        bytes memory transferAccountData = decodeEncodedData(encodedTransferAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            string memory decodedTransferdAccountId,
            address decodedToAddress
        ) = abi.decode(transferAccountData, (SignatureVerifier.TimedSignature, string, address));

        assertEq(decodedTimedSignature.signature, bobSig.signature, "Signature should be same");
        assertEq(decodedTransferdAccountId, accountId, "Approved account ID should match");
        assertEq(decodedToAddress, bob, "Approved account address should match");
    }

    function testTransferAccountCallback() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory aliceSig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(aliceSig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(aliceSig, account);
        bytes memory encodedApproveAddressData = tas.approveAddress(aliceSig, accountId, bob);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (, bytes16 decodedAccountId, address decodedAddress) =
            abi.decode(approveAddressData, (SignatureVerifier.TimedSignature, bytes16, address));
        tas.approveAddressCallback(aliceSig, Suave.DataId.wrap(decodedAccountId), decodedAddress);

        SignatureVerifier.TimedSignature memory bobSig =
            generateTimedSignature(uint64(block.timestamp + 86400), bob, bobPrivateKey);

        bytes memory encodedTransferAccountData = tas.transferAccount(bobSig, accountId, bob);
        bytes memory transferAccountData = decodeEncodedData(encodedTransferAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            string memory decodedTransferdAccountId,
            address decodedToAddress
        ) = abi.decode(transferAccountData, (SignatureVerifier.TimedSignature, string, address));

        tas.transferAccountCallback(decodedTimedSignature, decodedTransferdAccountId, decodedToAddress);

        (, address newOwner,,,, bool isAccountLocked) = tas.accountsStore(decodedTransferdAccountId);

        assertEq(newOwner, bob, "Stored account owner should match");
        assertTrue(isAccountLocked, "Transfered account should be locked");
    }

    function testIsApproved() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        string memory accountId = tas.createAccountCallback(sig, account);
        bytes memory encodedApproveAddressData = tas.approveAddress(sig, accountId, bob);
        bytes memory approveAddressData = decodeEncodedData(encodedApproveAddressData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            bytes16 decodedAccountId,
            address decodedAddress
        ) = abi.decode(approveAddressData, (SignatureVerifier.TimedSignature, bytes16, address));
        tas.approveAddressCallback(decodedTimedSignature, Suave.DataId.wrap(decodedAccountId), decodedAddress);

        bool isApproved = tas.isApproved(accountId, bob);
        assertTrue(isApproved, "Address should be approved");

        tas.revokeApprovalCallback(sig, accountId, bob);
        isApproved = tas.isApproved(accountId, bob);
        assertFalse(isApproved, "Address should not be approved after revocation");
    }

    function testIsOwner() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(sig, account);

        bool isOwner = tas.isOwner(accountId, alice);
        assertTrue(isOwner, "Address should be the owner");

        isOwner = tas.isOwner(accountId, bob);
        assertFalse(isOwner, "Address should not be the owner");
    }

    function testGetAccount() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(sig, account);

        ITransferableAccountStore.Account memory retrievedAccount = tas.getAccount(accountId);
        bytes16 retrievedAccountIdBytes = Suave.DataId.unwrap(retrievedAccount.accountId);

        assertEq(StringUtils.bytes16ToString(retrievedAccountIdBytes), accountId, "Account ID should match");
        assertEq(retrievedAccount.owner, account.owner, "Owner should match");
        assertEq(retrievedAccount.publicKeyX, account.publicKeyX, "Public Key X should match");
        assertEq(retrievedAccount.publicKeyY, account.publicKeyY, "Public Key Y should match");
        assertEq(uint256(retrievedAccount.curve), uint256(account.curve), "Curve should match");
    }

    function testRevokeApproval() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(sig, account);

        tas.approveAddress(sig, accountId, bob);
        tas.approveAddressCallback(sig, account.accountId, bob);

        bool isApproved = tas.isApproved(accountId, bob);
        assertTrue(isApproved, "Address should be approved");

        tas.revokeApproval(sig, accountId, bob);
        isApproved = tas.isApproved(accountId, bob);
        assertFalse(isApproved, "Address should not be approved after revocation");
    }

    function testDeleteAccountCallback() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(sig, account);

        ITransferableAccountStore.Account memory retrievedAccount = tas.getAccount(accountId);
        assertEq(retrievedAccount.owner, account.owner, "Owner should match before deletion");

        bytes memory encodedDeleteAccountData = tas.deleteAccount(sig, accountId);
        bytes memory deleteAccountData = decodeEncodedData(encodedDeleteAccountData);

        (SignatureVerifier.TimedSignature memory decodedTimedSignature, string memory decodedAccountId) =
            abi.decode(deleteAccountData, (SignatureVerifier.TimedSignature, string));
        tas.deleteAccountCallback(decodedTimedSignature, decodedAccountId);

        retrievedAccount = tas.getAccount(decodedAccountId);
        assertEq(retrievedAccount.owner, address(0), "Owner should be zero address after deletion");
    }

    function testUnlockAccountCallback() public {
        (TransferableAccountStore tas, SignatureVerifier.TimedSignature memory sig) =
            setupTransferableAccountStore(uint64(block.timestamp + 86400), alice, alicePrivateKey);
        bytes memory encodedCreateAccountData = tas.createAccount(sig);
        bytes memory createdAccountData = decodeEncodedData(encodedCreateAccountData);

        (, ITransferableAccountStore.Account memory account) =
            abi.decode(createdAccountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(sig, account);

        bool isAccountLocked = tas.isAccountLocked(accountId);
        assertTrue(isAccountLocked, "Account should be locked immediately after creation");

        bytes memory encodedUnlockAccountData = tas.unlockAccount(sig, accountId);
        bytes memory unlockAccountData = decodeEncodedData(encodedUnlockAccountData);

        (SignatureVerifier.TimedSignature memory decodedTimedSignature, string memory decodedAccountId) =
            abi.decode(unlockAccountData, (SignatureVerifier.TimedSignature, string));
        tas.unlockAccountCallback(decodedTimedSignature, decodedAccountId);

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
