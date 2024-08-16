// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "suave-std/Test.sol";
import "suave-std/suavelib/Suave.sol";
import "../src/solidity/TransferableAccountStore.sol";

contract TransferableAccountStoreTest is Test, SuaveEnabled {
    TransferableAccountStore public store;
    address public owner;
    address public user1;
    address public user2;
}
