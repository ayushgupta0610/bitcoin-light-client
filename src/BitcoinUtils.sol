// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library BitcoinUtils {
    error SHA256_FAILED();
    error EXPONENT_TOO_LARGE();
    error INVALID_LENGTH();
    error INVALID_HEX_CHARACTER();

    struct BlockHeader {
        uint32 version; // 4 bytes
        uint32 timestamp; // 4 bytes
        uint32 difficultyBits; // 4 bytes
        uint32 nonce; // 4 bytes
        uint32 height; // 4 bytes
        bytes32 prevBlock; // 32 bytes
        bytes32 merkleRoot; // 32 bytes
    }

    /// @notice Creates bitcoin sha256 double hash
    /// @param bytesData bytes data to be double hashed
    /// @return bytes32 sha256 double hashed
    function sha256DoubleHash(bytes memory bytesData) internal view returns (bytes32) {
        // First SHA256
        (bool success1, bytes memory result1) = address(0x2).staticcall(abi.encodePacked(bytesData));
        require(success1, SHA256_FAILED());

        // Second SHA256
        (bool success2, bytes memory result2) = address(0x2).staticcall(result1);
        require(success2, SHA256_FAILED());

        return bytes32(result2);
    }

    /// @notice Parses raw Bitcoin block header bytes into a structured format
    /// @param rawHeader The 80-byte Bitcoin block header
    /// @return header The parsed BlockHeader struct
    function parseBlockHeader(bytes calldata rawHeader) internal pure returns (BlockHeader memory header) {
        require(rawHeader.length == 80, INVALID_LENGTH());

        // Version (4 bytes) - Convert from LE to BE
        header.version = uint32(bytesToUint256(reverseBytes(rawHeader[0:4])));

        // Previous block hash (32 bytes) - Reverse byte order
        header.prevBlock = bytes32(reverseBytes(rawHeader[4:36]));

        // Merkle root (32 bytes) - Reverse byte order
        header.merkleRoot = bytes32(reverseBytes(rawHeader[36:68]));

        // Timestamp (4 bytes) - Convert from LE to BE and cast to uint32
        header.timestamp = uint32(bytesToUint256(reverseBytes(rawHeader[68:72])));

        // Difficulty bits (4 bytes) - Convert from LE to BE and cast to uint32
        header.difficultyBits = uint32(bytesToUint256(reverseBytes(rawHeader[72:76])));

        // Nonce (4 bytes) - Convert from LE to BE and cast to uint32
        header.nonce = uint32(bytesToUint256(reverseBytes(rawHeader[76:80])));
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
    function reverseBytes(bytes memory input) internal pure returns (bytes memory) {
        bytes memory output = new bytes(input.length);

        for (uint256 i = 0; i < input.length; i++) {
            output[i] = input[input.length - 1 - i];
        }

        return output;
    }

    /// @notice Reverses bytes32
    /// @param input The input bytes32 to reverse
    /// @return The reversed bytes32
    function reverseBytes32(bytes32 input) internal pure returns (bytes32) {
        // Convert the bytes32 to bytes memory for easier manipulation
        bytes memory temp = new bytes(32);

        // Copy the bytes32 into our temporary array
        assembly {
            mstore(add(temp, 32), input)
        }

        // Create new bytes for the reversed result
        bytes memory reversed = new bytes(32);

        // Reverse the bytes
        for (uint256 i = 0; i < 32; i++) {
            reversed[i] = temp[31 - i];
        }

        // Convert back to bytes32
        bytes32 result;
        assembly {
            result := mload(add(reversed, 32))
        }

        return result;
    }

    /// @notice Reverses bytes32 array
    /// @param input The input bytes32 array to reverse
    /// @return The reversed bytes32 array
    function reverseBytes32Array(bytes32[] memory input) internal pure returns (bytes32[] memory) {
        uint256 length = input.length;
        bytes32[] memory output = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            output[i] = reverseBytes32(input[i]);
        }
        return output;
    }

    /// @notice Decode a hex string into bytes
    /// @param hexStr The hex string (without 0x prefix)
    /// @return The decoded bytes
    function hexToBytes(string memory hexStr) internal pure returns (bytes memory) {
        bytes memory hexBytes = bytes(hexStr);
        require(hexBytes.length % 2 == 0, INVALID_LENGTH());

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
        revert INVALID_HEX_CHARACTER();
    }

    /// @notice Generate a sha256 double hash for a pair of bytes32 values
    /// @param a bytes32 value
    /// @param b bytes32 value
    /// @return bytes32 sha256 double hash
    function hashPair(bytes32 a, bytes32 b) internal view returns (bytes32) {
        return BitcoinUtils.sha256DoubleHash(abi.encodePacked(a, b));
    }

    /// @notice Serializes a BlockHeader struct into raw Bitcoin block header bytes
    /// @param version Block version
    /// @param blockTimestamp  Block timestamp
    /// @param difficultyBits Compressed difficulty target
    /// @param nonce used for mining
    /// @param prevBlock Previous block hash
    /// @param merkleRoot Merkle tree root hash
    /// @return The 80-byte Bitcoin block header
    function serializeBlockHeader(
        uint32 version,
        uint32 blockTimestamp,
        uint32 difficultyBits,
        uint32 nonce,
        bytes32 prevBlock,
        bytes32 merkleRoot
    ) internal pure returns (bytes memory) {
        bytes memory rawHeader = new bytes(80);

        // Version (4 bytes) - Convert to LE
        bytes memory versionBytes = reverseBytes(abi.encodePacked(version));
        for (uint256 i = 0; i < 4; i++) {
            rawHeader[i] = versionBytes[i];
        }

        // Previous block hash (32 bytes) - Reverse byte order
        bytes memory prevBlockBytes = reverseBytes(abi.encodePacked(prevBlock));
        for (uint256 i = 0; i < 32; i++) {
            rawHeader[i + 4] = prevBlockBytes[i];
        }

        // Merkle root (32 bytes) - Reverse byte order
        bytes memory merkleRootBytes = reverseBytes(abi.encodePacked(merkleRoot));
        for (uint256 i = 0; i < 32; i++) {
            rawHeader[i + 36] = merkleRootBytes[i];
        }

        // Timestamp (4 bytes) - Convert to LE
        // Note: Even though timestamp is uint32, Bitcoin only uses 4 bytes
        bytes memory timestampBytes = reverseBytes(abi.encodePacked(uint32(blockTimestamp)));
        for (uint256 i = 0; i < 4; i++) {
            rawHeader[i + 68] = timestampBytes[i];
        }

        // Difficulty bits (4 bytes) - Convert to LE
        bytes memory bitsBytes = reverseBytes(abi.encodePacked(difficultyBits));
        for (uint256 i = 0; i < 4; i++) {
            rawHeader[i + 72] = bitsBytes[i];
        }

        // Nonce (4 bytes) - Convert to LE
        bytes memory nonceBytes = reverseBytes(abi.encodePacked(nonce));
        for (uint256 i = 0; i < 4; i++) {
            rawHeader[i + 76] = nonceBytes[i];
        }

        return rawHeader;
    }

    /// @notice Expand compressed difficulty bits to full target
    /// @param bits Compressed difficulty target
    /// @return uint256 Expanded target
    function expandDifficultyBits(uint32 bits) internal pure returns (uint256) {
        uint32 exp = bits >> 24;
        uint32 coef = bits & 0x00ffffff;

        // Add safety checks
        require(exp <= 32, EXPONENT_TOO_LARGE()); // Reasonable limit for Bitcoin

        // Use a safer calculation method
        if (exp <= 3) return coef >> (8 * (3 - exp));
        return coef * (2 ** (8 * (exp - 3)));
    }

    /// @notice Verify the proof of work meets difficulty target
    /// @param blockHash Calculated block hash
    /// @param difficultyBits Compressed difficulty target
    /// @return bool True if proof of work is valid
    function verifyProofOfWork(bytes32 blockHash, uint32 difficultyBits) internal pure returns (bool) {
        // Extract difficulty target from compressed bits
        uint256 target = expandDifficultyBits(difficultyBits);

        // Convert hash to uint256 for comparison
        uint256 hashNum = uint256(blockHash);

        // Valid if hash is less than target
        return hashNum < target;
    }

    /// @notice Verify if a transaction is included in a block using a Merkle proof
    /// @dev All inputs should be in Bitcoin's display format (natural byte order)
    /// @param txId Transaction ID to verify in natural byte order
    /// @param merkleRoot Expected Merkle root in natural byte order
    /// @param proof Array of proof hashes in natural byte order
    /// @param index Index of the transaction in the block (0-based)
    /// @return bool True if the proof is valid
    function verifyTxInclusion(bytes32 txId, bytes32 merkleRoot, bytes32[] memory proof, uint256 index)
        internal
        view
        returns (bool)
    {
        // Keep current hash in Bitcoin's internal byte order (not reversed)
        bytes32 currentHash = txId;

        // For each level of the proof
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            // If the current position (index) is even, the proof element goes on the right
            // If it's odd, it goes on the left
            if (index % 2 == 0) {
                // Current hash should go on the left
                currentHash = hashPair(currentHash, proofElement);
            } else {
                // Current hash should go on the right
                currentHash = hashPair(proofElement, currentHash);
            }

            // Move up to the parent level
            index = index / 2;
        }

        // Compare with the expected merkle root
        return currentHash == merkleRoot;
    }

    /// @notice Generate merkle proof for a transaction in natural byte order
    /// @dev Index is provided as uint but represents binary path in the tree
    ///      The maximum value of the index is checked against array length
    /// @param txIndex Index of the transaction in the block (0-based)
    /// @param txHashes Array of transaction hashes in tree order in natural byte order
    /// @return proof Array of proof hashes in natural byte order
    /// @return index Position of the transaction in the block
    function generateMerkleProof(uint256 txIndex, bytes32[] memory txHashes)
        internal
        view
        returns (bytes32[] memory proof, uint256 index)
    {
        uint256 numLeaves = txHashes.length;
        uint256 proofLength = calculateProofLength(numLeaves);
        proof = new bytes32[](proofLength);

        // Start with the leaf level
        bytes32[] memory currentLevel = txHashes;
        index = txIndex; // Store original index for return
        uint256 currentIndex = txIndex;
        uint256 proofIndex = 0;

        while (currentLevel.length > 1) {
            bytes32[] memory nextLevel = new bytes32[]((currentLevel.length + 1) / 2);

            for (uint256 i = 0; i < currentLevel.length; i += 2) {
                if (i == currentLevel.length - 1) {
                    // Handle odd number of elements
                    nextLevel[i / 2] = currentLevel[i];
                    continue;
                }

                // If this is our path, store the sibling in the proof
                if (i == currentIndex || i + 1 == currentIndex) {
                    proof[proofIndex++] = currentLevel[i + (currentIndex % 2 == 0 ? 1 : 0)];
                }

                // Calculate parent hash
                nextLevel[i / 2] = hashPair(currentLevel[i], currentLevel[i + 1]);
            }

            // Move to next level
            currentLevel = nextLevel;
            currentIndex /= 2;
        }

        return (proof, index);
    }

    ///  @notice Calculate the length of the Merkle proof based on number of leaves
    ///  @param numLeaves Number of leaf nodes
    ///  @return uint256 Length of the proof array
    function calculateProofLength(uint256 numLeaves) internal pure returns (uint256) {
        if (numLeaves <= 1) return 0;
        return 1 + calculateProofLength((numLeaves + 1) / 2);
    }
}
