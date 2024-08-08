// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.2 <0.9.0;

import "forge-std/Test.sol";
import "../src/solidity/Storage.sol";

contract StorageTest is Test {
    Storage public storageContract;

    function setUp() public {
        storageContract = new Storage();
    }

    function testStore() public {
        uint256 testValue = 42;
        storageContract.store(testValue);
        assertEq(storageContract.retrieve(), testValue, "The value is not stored correctly");
    }

    function testRetrieve() public {
        uint256 initialValue = storageContract.retrieve();
        assertEq(initialValue, 0, "The initial value is not 0");

        uint256 newValue = 100;
        storageContract.store(newValue);
        uint256 retrievedValue = storageContract.retrieve();
        assertEq(retrievedValue, newValue, "The value is not retrieved correctly");
    }
}
