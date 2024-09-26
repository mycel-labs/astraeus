// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

library Utils {
    function hexStringToUint256(string memory s) internal pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 16 + (c - 48);
            }
            if (c >= 65 && c <= 70) {
                result = result * 16 + (c - 55);
            }
            if (c >= 97 && c <= 102) {
                result = result * 16 + (c - 87);
            }
        }
        return result;
    }

    function iToHex(bytes memory buffer) internal pure returns (string memory) {
        // Fixed buffer size for hexadecimal convertion
        bytes memory converted = new bytes(buffer.length * 2);

        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }

    function hexStringToBytes(string memory s) internal pure returns (bytes memory) {
        bytes memory ss = bytes(s);
        require(ss.length % 2 == 0, "Hex string has odd length");

        bytes memory result = new bytes(ss.length / 2);
        for (uint256 i = 0; i < ss.length / 2; ++i) {
            result[i] = bytes1(byteFromHexChar(uint8(ss[2 * i])) << 4 | byteFromHexChar(uint8(ss[2 * i + 1])));
        }
        return result;
    }

    function byteFromHexChar(uint8 c) private pure returns (uint8) {
        if (bytes1(c) >= "0" && bytes1(c) <= "9") {
            return c - uint8(bytes1("0"));
        }
        if (bytes1(c) >= "a" && bytes1(c) <= "f") {
            return 10 + c - uint8(bytes1("a"));
        }
        if (bytes1(c) >= "A" && bytes1(c) <= "F") {
            return 10 + c - uint8(bytes1("A"));
        }
        revert("Invalid hex character");
    }

    function isValidHexString(bytes memory str) internal pure returns (bool) {
        for (uint256 i = 0; i < str.length; i++) {
            bytes1 char = str[i];
            if (
                !(char >= 0x30 && char <= 0x39) // 0-9
                    && !(char >= 0x41 && char <= 0x46) // A-F
                    && !(char >= 0x61 && char <= 0x66)
            ) {
                // a-f
                return false;
            }
        }
        return true;
    }

    function decodeSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
    }

    function uintToString(uint256 v) internal pure returns (string memory) {
        if (v == 0) {
            return "0";
        }
        uint256 j = v;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len - 1;
        while (v != 0) {
            bstr[k--] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
        return string(bstr);
    }
}
