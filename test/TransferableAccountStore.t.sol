// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "suave-std/Test.sol";
import "suave-std/suavelib/Suave.sol";
import "../src/solidity/TransferableAccountStore.sol";
import "../src/solidity/interfaces/ITransferableAccountStore.sol";

contract TransferableAccountStoreTest is Test, SuaveEnabled {
    function testCreateAccount() public {
        TransferableAccountStore tas = new TransferableAccountStore();
        address tasAddress = address(tas);
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

    }

    function testGeneratePublicKey() public view {
        (uint256 x, uint256 y) = c.generatePublicKey(privateKey);
        bytes memory publicKey = abi.encodePacked(x, y);

        bytes memory expectedPublicKey =
            hex"a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235";
        assertBytesEq(publicKey, expectedPublicKey);
    }
}
