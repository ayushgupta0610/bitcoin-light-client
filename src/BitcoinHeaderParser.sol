// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Convert this to lib
contract BitcoinHeaderParser {
    struct BlockHeader {
        uint256 version; // Block version
        bytes32 prevBlock; // Previous block hash
        bytes32 merkleRoot; // Merkle tree root hash
        uint256 timestamp; // Block timestamp
        uint256 difficultyBits; // Compressed difficulty target
        uint256 nonce; // Nonce used for mining
        uint256 height; // Block height
    }

    /// @notice Parses raw Bitcoin block header bytes into a structured format
    /// @param rawHeader The 80-byte Bitcoin block header
    /// @return header The parsed BlockHeader struct
    function parseBlockHeader(bytes calldata rawHeader) public pure returns (BlockHeader memory header) {
        require(rawHeader.length == 80, "Invalid header length");

        // Version (4 bytes) - Convert from LE to BE
        header.version = bytesToUint256(reverseBytes(rawHeader[0:4]));

        // Previous block hash (32 bytes) - Reverse byte order
        header.prevBlock = bytes32(reverseBytes(rawHeader[4:36]));

        // Merkle root (32 bytes) - Reverse byte order
        header.merkleRoot = bytes32(reverseBytes(rawHeader[36:68]));

        // Timestamp (4 bytes) - Convert from LE to BE
        header.timestamp = bytesToUint256(reverseBytes(rawHeader[68:72]));

        // Difficulty bits (4 bytes) - Convert from LE to BE
        header.difficultyBits = bytesToUint256(reverseBytes(rawHeader[72:76]));

        // Nonce (4 bytes) - Convert from LE to BE
        header.nonce = bytesToUint256(reverseBytes(rawHeader[76:80]));
    }

    /// @notice Converts bytes to uint256
    /// @param b The bytes to convert
    /// @return The resulting uint256
    function bytesToUint256(bytes memory b) internal pure returns (uint256) {
        uint256 number;
        for (uint256 i = 0; i < b.length; i++) {
            number = number + uint256(uint8(b[i])) * (2 ** (8 * (b.length - 1 - i)));
        }
        return number;
    }

    /// @notice Reverses the order of bytes in a byte array
    /// @param input The input bytes to reverse
    /// @return The reversed bytes
    function reverseBytes(bytes calldata input) internal pure returns (bytes memory) {
        bytes memory output = new bytes(input.length);

        for (uint256 i = 0; i < input.length; i++) {
            output[i] = input[input.length - 1 - i];
        }

        return output;
    }

    /// @notice Decode a hex string into bytes
    /// @param hexStr The hex string (without 0x prefix)
    /// @return The decoded bytes
    function hexToBytes(string memory hexStr) internal pure returns (bytes memory) {
        bytes memory hexBytes = bytes(hexStr);
        require(hexBytes.length % 2 == 0, "Invalid hex string length");

        bytes memory result = new bytes(hexBytes.length / 2);

        for (uint256 i = 0; i < hexBytes.length; i += 2) {
            uint8 hi = uint8(hexDigitToVal(hexBytes[i]));
            uint8 lo = uint8(hexDigitToVal(hexBytes[i + 1]));
            result[i / 2] = bytes1(hi << 4 | lo);
        }

        return result;
    }

    /// @notice Convert a hex character to its decimal value
    function hexDigitToVal(bytes1 c) internal pure returns (uint8) {
        if (bytes1("0") <= c && c <= bytes1("9")) {
            return uint8(c) - uint8(bytes1("0"));
        }
        if (bytes1("a") <= c && c <= bytes1("f")) {
            return 10 + uint8(c) - uint8(bytes1("a"));
        }
        if (bytes1("A") <= c && c <= bytes1("F")) {
            return 10 + uint8(c) - uint8(bytes1("A"));
        }
        revert("Invalid hex character");
    }
}
