// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/solidity/TransferableAccountStore.sol";

contract TestContract is Test {
    TransferableAccountStore c;
    uint256 privateKey = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;

    function setUp() public {
        c = new TransferableAccountStore();
    }

    function assertBytesEq(bytes memory a, bytes memory b) internal pure {
        assertEq(a.length, b.length, "Bytes length mismatch");
        for (uint256 i = 0; i < a.length; i++) {
            assertEq(uint8(a[i]), uint8(b[i]), "Byte mismatch at index");
        }
    }

    function testGeneratePublicKey() public view {
        (uint256 x, uint256 y) = c.generatePublicKey(privateKey);
        bytes memory publicKey = abi.encodePacked(x, y);

        bytes memory expectedPublicKey =
            hex"a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235";
        assertBytesEq(publicKey, expectedPublicKey);
    }
}
