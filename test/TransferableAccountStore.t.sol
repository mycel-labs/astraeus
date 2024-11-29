// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "suave-std/Test.sol";
import "suave-std/suavelib/Suave.sol";
import "../src/solidity/TransferableAccountStore.sol";
import "../src/solidity/interfaces/ITransferableAccountStore.sol";
import "../src/solidity/lib/SignatureVerifier.sol";

contract TransferableAccountStoreTest is Test, SuaveEnabled {
    address public admin = address(this);
    uint256 public constant ALICE_PRIVATE_KEY = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    uint256 public constant BOB_PRIVATE_KEY = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

    address public alice = vm.addr(ALICE_PRIVATE_KEY);
    address public bob = vm.addr(BOB_PRIVATE_KEY);

    bytes32 public constant CREATE_ACCOUNT_FUNCTION_HASH =
        keccak256("CreateAccount(SignatureVerifier.TimedSignature timedSignature)");
    bytes32 public constant APPROVE_ADDRESS_FUNCTION_HASH =
        keccak256("ApproveAddress(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)");
    bytes32 public constant TRANSFER_ACCOUNT_FUNCTION_HASH =
        keccak256("TransferAccount(SignatureVerifier.TimedSignature timedSignature,string accountId,address to)");
    bytes32 public constant REVOKE_APPROVAL_FUNCTION_HASH =
        keccak256("RevokeApproval(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)");
    bytes32 public constant DELETE_ACCOUNT_FUNCTION_HASH =
        keccak256("DeleteAccount(SignatureVerifier.TimedSignature timedSignature,string accountId)");
    bytes32 public constant UNLOCK_ACCOUNT_FUNCTION_HASH =
        keccak256("UnlockAccount(SignatureVerifier.TimedSignature timedSignature,string accountId)");
    bytes32 public constant SIGN_FUNCTION_HASH =
        keccak256("Sign(SignatureVerifier.TimedSignature timedSignature,string accountId,bytes data)");

    error AccountLocked();
    error AccountLockedError();

    function generateTimedSignature(
        uint64 validFor,
        address signer,
        uint256 privateKey,
        uint64 nonce,
        bytes32 targetFunctionHash
    ) internal pure returns (SignatureVerifier.TimedSignature memory) {
        bytes32 messageHash = SignatureVerifier.hashMessage(validFor, signer, nonce, targetFunctionHash);
        bytes32 mycelSignedMessageHash = keccak256(abi.encodePacked("\x19Mycel Signed Message:\n32", messageHash));
        bytes memory signature = signMessage(mycelSignedMessageHash, privateKey);

        return SignatureVerifier.TimedSignature({
            validFor: validFor,
            messageHash: messageHash,
            signature: signature,
            signer: signer,
            nonce: nonce,
            targetFunctionHash: targetFunctionHash
        });
    }

    function signMessage(bytes32 messageHash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function testVerifyTimedSignature() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        bytes32 targetFunctionHashDemo = keccak256("test timedSignature");
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), targetFunctionHashDemo
        );

        vm.warp(1000);
        bool isValid = tas.verifyTimedSignature(sig0, targetFunctionHashDemo);
        assertTrue(isValid, "Valid signature should be accepted");

        vm.warp(uint64(block.timestamp + 86401));
        isValid = tas.verifyTimedSignature(sig0, targetFunctionHashDemo);
        assertFalse(isValid, "Expired signature should be rejected");

        sig0.signature[0] ^= 0xFF;
        isValid = tas.verifyTimedSignature(sig0, targetFunctionHashDemo);
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
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );

        bytes memory encodedData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));

        assertEq(decodedTimedSignature.signature, sig0.signature, "Signature should be same");
        assertEq(decodedAccount.owner, sig0.signer, "Owner should be alice");
        assertTrue(decodedAccount.isLocked, "Account should be locked");
    }

    function testCreateAccountCallback() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedData = tas.createAccount(sig0);
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
            ITransferableAccountStore.SignatureAlgorithm signatureAlgorithm,
            bool isLocked
        ) = tas.accountsStore(accountId);
        bytes16 storedAccountIdBytes = Suave.DataId.unwrap(storedAccountId);
        string memory storedAccountIdToString = StringUtils.bytes16ToString(storedAccountIdBytes);

        assertEq(storedAccountIdToString, accountId, "Stored account ID should match");
        assertEq(storedOwner, decodedAccount.owner, "Stored account owner should match");
        assertEq(storedPublicKeyX, decodedAccount.publicKeyX, "Stored account public key X should match");
        assertEq(storedPublicKeyY, decodedAccount.publicKeyY, "Stored account public key Y should match");
        assertEq(
            uint256(signatureAlgorithm), uint256(decodedAccount.signatureAlgorithm), "Stored account curve should match"
        );
        assertTrue(isLocked, "Stored account shouold be locked");
    }

    function testApproveAddress() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            APPROVE_ADDRESS_FUNCTION_HASH
        );
        tas.approveAddress(sig1, accountId, bob);

        address approvedAddress = tas.accountApprovals(decodedAccount.accountId);
        assertEq(bob, approvedAddress, "Approved account address should match");
    }

    function testTransferAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory aliceSig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(aliceSig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        SignatureVerifier.TimedSignature memory aliceSig1 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            APPROVE_ADDRESS_FUNCTION_HASH
        );
        tas.approveAddress(aliceSig1, accountId, bob);

        SignatureVerifier.TimedSignature memory bobSig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), bob, BOB_PRIVATE_KEY, tas.getNonce(bob), TRANSFER_ACCOUNT_FUNCTION_HASH
        );

        tas.transferAccount(bobSig0, accountId, bob);

        (, address newOwner,,,, bool isAccountLocked) = tas.accountsStore(accountId);

        assertEq(newOwner, bob, "Stored account owner should match");
        assertTrue(isAccountLocked, "Transfered account should be locked");
    }

    function testIsApproved() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            APPROVE_ADDRESS_FUNCTION_HASH
        );
        tas.approveAddress(sig1, accountId, bob);

        bool isApproved = tas.isApproved(accountId, bob);
        assertTrue(isApproved, "Address should be approved");

        SignatureVerifier.TimedSignature memory sig2 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            REVOKE_APPROVAL_FUNCTION_HASH
        );
        tas.revokeApproval(sig2, accountId, bob);
        isApproved = tas.isApproved(accountId, bob);
        assertFalse(isApproved, "Address should not be approved after revocation");
    }

    function testIsOwner() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        bool isOwner = tas.isOwner(accountId, alice);
        assertTrue(isOwner, "Address should be the owner");

        isOwner = tas.isOwner(accountId, bob);
        assertFalse(isOwner, "Address should not be the owner");
    }

    function testGetAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        ITransferableAccountStore.Account memory retrievedAccount = tas.getAccount(accountId);
        bytes16 retrievedAccountIdBytes = Suave.DataId.unwrap(retrievedAccount.accountId);

        assertEq(StringUtils.bytes16ToString(retrievedAccountIdBytes), accountId, "Account ID should match");
        assertEq(retrievedAccount.owner, decodedAccount.owner, "Owner should match");
        assertEq(retrievedAccount.publicKeyX, decodedAccount.publicKeyX, "Public Key X should match");
        assertEq(retrievedAccount.publicKeyY, decodedAccount.publicKeyY, "Public Key Y should match");
        assertEq(
            uint256(retrievedAccount.signatureAlgorithm),
            uint256(decodedAccount.signatureAlgorithm),
            "signatureAlgorithm should match"
        );
    }

    function testRevokeApproval() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            APPROVE_ADDRESS_FUNCTION_HASH
        );
        tas.approveAddress(sig1, accountId, bob);

        bool isApproved = tas.isApproved(accountId, bob);
        assertTrue(isApproved, "Address should be approved");

        SignatureVerifier.TimedSignature memory sig2 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            REVOKE_APPROVAL_FUNCTION_HASH
        );
        tas.revokeApproval(sig2, accountId, bob);

        isApproved = tas.isApproved(accountId, bob);
        assertFalse(isApproved, "Address should not be approved after revocation");
    }

    function testDeleteAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        ITransferableAccountStore.Account memory retrievedAccount = tas.getAccount(accountId);
        assertEq(retrievedAccount.owner, decodedAccount.owner, "Owner should match before deletion");

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), DELETE_ACCOUNT_FUNCTION_HASH
        );
        tas.deleteAccount(sig1, accountId);

        retrievedAccount = tas.getAccount(accountId);
        assertEq(retrievedAccount.owner, address(0), "Owner should be zero address after deletion");
    }

    function testUnlockAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        bool isAccountLocked = tas.isAccountLocked(accountId);
        assertTrue(isAccountLocked, "Account should be locked immediately after creation");

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), UNLOCK_ACCOUNT_FUNCTION_HASH
        );
        tas.unlockAccount(sig1, accountId);

        isAccountLocked = tas.isAccountLocked(accountId);
        assertFalse(isAccountLocked, "Account should be unlocked");
    }

    function testSign() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        bool isAccountLocked = tas.isAccountLocked(accountId);
        assertTrue(isAccountLocked, "Account should be locked immediately after creation");

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), UNLOCK_ACCOUNT_FUNCTION_HASH
        );
        tas.unlockAccount(sig1, accountId);

        isAccountLocked = tas.isAccountLocked(accountId);

        bytes memory dummyData = abi.encodePacked("dummy data");
        bytes32 hashedDummyData = keccak256(dummyData);

        if (isAccountLocked) {
            revert AccountLocked();
        }

        SignatureVerifier.TimedSignature memory sig2 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), SIGN_FUNCTION_HASH
        );
        bytes memory encodedSignData = tas.sign(sig2, accountId, abi.encodePacked(hashedDummyData));
        bytes4 selector;
        assembly {
            selector := mload(add(encodedSignData, 32))
        }

        assertEq(selector, tas.signCallback.selector, "Sign callback selector mismatch");
    }

    function testSignAfterTransfer() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory aliceSig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(aliceSig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        SignatureVerifier.TimedSignature memory aliceSig1 = generateTimedSignature(
            uint64(block.timestamp + 86400),
            alice,
            ALICE_PRIVATE_KEY,
            tas.getNonce(alice),
            APPROVE_ADDRESS_FUNCTION_HASH
        );
        tas.approveAddress(aliceSig1, accountId, bob);

        SignatureVerifier.TimedSignature memory bobSig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), bob, BOB_PRIVATE_KEY, tas.getNonce(bob), TRANSFER_ACCOUNT_FUNCTION_HASH
        );
        tas.transferAccount(bobSig0, accountId, bob);

        SignatureVerifier.TimedSignature memory bobSig1 = generateTimedSignature(
            uint64(block.timestamp + 86400), bob, BOB_PRIVATE_KEY, tas.getNonce(bob), UNLOCK_ACCOUNT_FUNCTION_HASH
        );
        tas.unlockAccount(bobSig1, accountId);

        bytes memory dummyData = abi.encodePacked("dummy data");
        bytes32 hashedDummyData = keccak256(dummyData);

        SignatureVerifier.TimedSignature memory bobSig2 = generateTimedSignature(
            uint64(block.timestamp + 86400), bob, BOB_PRIVATE_KEY, tas.getNonce(bob), SIGN_FUNCTION_HASH
        );
        bytes memory encodedSignData = tas.sign(bobSig2, accountId, abi.encodePacked(hashedDummyData));
        bytes4 selector;
        assembly {
            selector := mload(add(encodedSignData, 32))
        }

        assertEq(selector, tas.signCallback.selector, "Sign callback selector mismatch");
    }

    function testSignWhenAccountIsLocked() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        SignatureVerifier.TimedSignature memory sig0 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), CREATE_ACCOUNT_FUNCTION_HASH
        );
        bytes memory encodedCreateAccountData = tas.createAccount(sig0);
        bytes memory accountData = decodeEncodedData(encodedCreateAccountData);

        (
            SignatureVerifier.TimedSignature memory decodedTimedSignature,
            ITransferableAccountStore.Account memory decodedAccount
        ) = abi.decode(accountData, (SignatureVerifier.TimedSignature, ITransferableAccountStore.Account));
        string memory accountId = tas.createAccountCallback(decodedTimedSignature, decodedAccount);

        bool isAccountLocked = tas.isAccountLocked(accountId);
        assertTrue(isAccountLocked, "Account should be locked immediately after creation");

        bytes memory dummyData = abi.encodePacked("dummy data");
        bytes32 hashedDummyData = keccak256(dummyData);

        SignatureVerifier.TimedSignature memory sig1 = generateTimedSignature(
            uint64(block.timestamp + 86400), alice, ALICE_PRIVATE_KEY, tas.getNonce(alice), SIGN_FUNCTION_HASH
        );
        vm.expectRevert();
        tas.sign(sig1, accountId, abi.encodePacked(hashedDummyData));
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
