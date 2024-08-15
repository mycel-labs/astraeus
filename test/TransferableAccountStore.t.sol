// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/solidity/TransferableAccountStore.sol";

contract TransferableAccountStoreTest is Test {
    TransferableAccountStore public store;
    address public owner;
    address public user1;
    address public user2;

    function setUp() public {
        store = new TransferableAccountStore();
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
    }

    function testCreateAccount() public {
        bytes memory callbackData = store.createAccount();
        (bytes4 selector, Account memory account) = abi.decode(callbackData[4:], (bytes4, Account));

        assertEq(selector, store.createAccountCallback.selector);
        assertEq(account.owner, owner);
        assertTrue(account.publicKeyX != 0);
        assertTrue(account.publicKeyY != 0);
    }

    function testApproveAddress() public {
        // アカウントを作成
        bytes memory createCallbackData = store.createAccount();
        (, Account memory account) = abi.decode(createCallbackData[4:], (bytes4, Account));
        string memory accountId = store.createAccountCallback(account);

        // アドレスを承認
        bytes memory approveCallbackData = store.approveAddress(accountId, user1);
        (bytes4 approveSelector, Suave.DataId approveAccountId, address approveAddress) =
            abi.decode(approveCallbackData[4:], (bytes4, Suave.DataId, address));

        assertEq(approveSelector, store.approveAddressCallback.selector);
        assertEq(approveAccountId, account.accountId);
        assertEq(approveAddress, user1);

        // 承認を確認
        store.approveAddressCallback(account.accountId, user1);
        assertTrue(store.isApproved(accountId, user1));
    }

    function testTransferAccount() public {
        // アカウントを作成
        bytes memory createCallbackData = store.createAccount();
        (, Account memory account) = abi.decode(createCallbackData[4:], (bytes4, Account));
        string memory accountId = store.createAccountCallback(account);

        // アカウントを転送
        bytes memory transferCallbackData = store.transferAccount(user1, accountId);
        (bytes4 transferSelector, address transferTo, string memory transferAccountId) =
            abi.decode(transferCallbackData[4:], (bytes4, address, string));

        assertEq(transferSelector, store.transferAccountCallback.selector);
        assertEq(transferTo, user1);
        assertEq(transferAccountId, accountId);

        // 転送を実行
        vm.prank(owner);
        store.transferAccountCallback(user1, accountId);

        // 新しい所有者を確認
        Account memory updatedAccount = store.getAccount(accountId);
        assertEq(updatedAccount.owner, user1);
    }

    function testLockAndUnlockAccount() public {
        // アカウントを作成
        bytes memory createCallbackData = store.createAccount();
        (, Account memory account) = abi.decode(createCallbackData[4:], (bytes4, Account));
        string memory accountId = store.createAccountCallback(account);

        // アカウントをロック
        bytes memory lockCallbackData = store.lockAccount(accountId);
        (bytes4 lockSelector, string memory lockAccountId) = abi.decode(lockCallbackData[4:], (bytes4, string));

        assertEq(lockSelector, store.lockAccountCallback.selector);
        assertEq(lockAccountId, accountId);

        // ロックを実行
        vm.prank(owner);
        store.lockAccountCallback(accountId, 3600); // 1時間ロック

        // ロック状態を確認
        assertTrue(store.isLocked(accountId));

        // アカウントをアンロック
        bytes memory unlockCallbackData = store.unlockAccount(accountId);
        (bytes4 unlockSelector, string memory unlockAccountId) = abi.decode(unlockCallbackData[4:], (bytes4, string));

        assertEq(unlockSelector, store.unlockAccountCallback.selector);
        assertEq(unlockAccountId, accountId);

        // アンロックを実行
        vm.prank(owner);
        store.unlockAccountCallback(accountId);

        // アンロック状態を確認
        assertFalse(store.isLocked(accountId));
    }
}
