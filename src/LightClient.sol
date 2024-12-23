// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// import {BitcoinMerkleRoot} from "./BitcoinMerkleRoot.sol";

/**
 * @title BitcoinLightClient
 * @notice A light client implementation for Bitcoin on Ethereum
 * @dev Validates Bitcoin block headers and performs SPV verification
 */
contract BitcoinLightClient {
    // Errors
    error INVALID_HEADER_LENGTH();
    error PREVIOUS_BLOCK_UNKNOWN();
    error INVALID_PROOF_OF_WORK();
    error INVALID_BLOCK_HEADER();
    error INVALID_BLOCK_HASH();
    error SHA256_FAILED();

    // Bitcoin block header is 80 bytes
    uint256 private constant HEADER_LENGTH = 80;

    // Minimum difficulty target
    uint256 private constant LOWEST_DIFFICULTY = 0x1d00ffff;

    // Maximum difficulty target
    uint256 private constant MAXIMUM_DIFFICULTY = 0x00000000ffff0000000000000000000000000000000000000000000000000000;

    // Block header interval for difficulty adjustment
    uint256 private constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

    // Target block time in seconds
    uint256 private constant TARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks

    // TODO: Pack the uints by allowing the max limit for the respective fields
    struct BlockHeader {
        uint256 version; // Block version
        bytes32 prevBlock; // Previous block hash
        bytes32 merkleRoot; // Merkle tree root hash
        uint256 timestamp; // Block timestamp
        uint256 difficultyBits; // Compressed difficulty target
        uint256 nonce; // Nonce used for mining
        uint256 height; // Block height
        bytes32 blockHash; // Temp (Needs to be removed)
    }

    // Mapping of block hash to block header
    mapping(bytes32 => BlockHeader) public headers;

    // Main chain tip
    bytes32 public chainTip;

    // Genesis block header hash
    bytes32 public immutable genesisBlock;

    // Events
    event BlockHeaderSubmitted(bytes32 indexed blockHash, bytes32 indexed prevBlock, uint256 height);
    event ChainReorg(bytes32 indexed oldTip, bytes32 indexed newTip);

    /**
     * @dev Constructor sets the genesis block
     * @param _genesisBlock Hash of the Bitcoin genesis block header
     */
    constructor(bytes32 _genesisBlock) {
        genesisBlock = _genesisBlock;
        chainTip = _genesisBlock;
    }

    /**
     * @notice Submit a new block header
     * @param parsedHeader Bitcoin block header
     */
    function submitBlockHeader(BlockHeader memory parsedHeader) external {
        // require(sha256DoubleHash(blockHeader) == parsedHeader.blockHash, INVALID_BLOCK_HASH());

        // Parse header
        // BlockHeader memory parsedHeader = parseBlockHeader(blockHeader);

        // Calculate block hash
        bytes32 blockHash = parsedHeader.blockHash;

        // Verify the header connects to our chain
        require(
            headers[parsedHeader.prevBlock].timestamp != 0 || parsedHeader.prevBlock == genesisBlock,
            PREVIOUS_BLOCK_UNKNOWN()
        );

        // Verify proof of work
        require(verifyProofOfWork(blockHash, parsedHeader.difficultyBits), INVALID_PROOF_OF_WORK());

        // Verify difficulty target if this is an adjustment block
        if (parsedHeader.height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0) {
            verifyDifficultyTarget(parsedHeader);
        }

        // Set block height
        parsedHeader.height = headers[parsedHeader.prevBlock].height + 1;

        // Store the header
        headers[blockHash] = parsedHeader;

        // Update chain tip if this is the new best chain
        if (parsedHeader.height > headers[chainTip].height) {
            bytes32 oldTip = chainTip;
            chainTip = blockHash;
            emit ChainReorg(oldTip, chainTip);
        }

        emit BlockHeaderSubmitted(blockHash, parsedHeader.prevBlock, parsedHeader.height);
    }

    /**
     * @dev Parse a raw block header (80 bytes) into structured data
     * @param header Raw block header bytes
     * @return BlockHeader Parsed header struct
     */
    // function parseBlockHeader(bytes calldata header) public pure returns (BlockHeader memory) {
    //     require(header.length == HEADER_LENGTH, INVALID_HEADER_LENGTH());

    //     BlockHeader memory parsed;
    //     uint256 version; // Block version
    //     bytes32 prevBlock; // Previous block hash
    //     bytes32 merkleRoot; // Merkle tree root hash
    //     uint256 blockTimestamp; // Block timestamp
    //     uint256 difficultyBits; // Compressed difficulty target
    //     uint256 nonce; // Nonce used for mining

    //     // Extract header fields
    //     assembly {
    //         // Version is first 4 bytes
    //         version := shr(224, calldataload(header.offset))

    //         // Previous block hash is next 32 bytes
    //         prevBlock := calldataload(add(header.offset, 4))

    //         // Merkle root is next 32 bytes
    //         merkleRoot := calldataload(add(header.offset, 36))

    //         // Timestamp is next 4 bytes
    //         blockTimestamp := shr(224, calldataload(add(header.offset, 68)))

    //         // Difficulty bits is next 4 bytes
    //         difficultyBits := shr(224, calldataload(add(header.offset, 72)))

    //         // Nonce is last 4 bytes
    //         nonce := shr(224, calldataload(add(header.offset, 76)))
    //     }

    //     // Assign the correct values
    //     parsed.version = version; // Block version
    //     parsed.prevBlock = prevBlock; // Previous block hash
    //     parsed.merkleRoot = merkleRoot; // Merkle tree root hash
    //     parsed.timestamp = blockTimestamp; // Block timestamp
    //     parsed.difficultyBits = difficultyBits; // Compressed difficulty target
    //     parsed.nonce = nonce;

    //     return parsed;
    // }

    /**
     * @dev Calculate double SHA256 hash of block header
     * @param header Raw block header bytes
     * @return bytes32 Block hash
     */
    // function calculateBlockHash(bytes calldata header) internal pure returns (bytes32) {
    //     return sha256(abi.encodePacked(sha256(header)));
    // }

    /**
     * @dev Verify the proof of work meets difficulty target
     * @param blockHash Calculated block hash
     * @param difficultyBits Compressed difficulty target
     * @return bool True if proof of work is valid
     */
    function verifyProofOfWork(bytes32 blockHash, uint256 difficultyBits) internal pure returns (bool) {
        // Extract difficulty target from compressed bits
        uint256 target = expandDifficultyBits(difficultyBits);

        // Convert hash to uint256 for comparison
        uint256 hashNum = uint256(blockHash);

        // Valid if hash is less than target
        return hashNum < target;
    }

    /**
     * @dev Expand compressed difficulty bits to full target
     * @param bits Compressed difficulty target
     * @return uint256 Expanded target
     */
    function expandDifficultyBits(uint256 bits) internal pure returns (uint256) {
        // Extract exponent and coefficient
        uint256 exp = bits >> 24;
        uint256 coef = bits & 0xffffff;

        // Return expanded difficulty target
        return coef * (2 ** (8 * (exp - 3)));
    }

    // TODO: CORRECT THIS || Should be run off chain ideally (gas intensive to do it for BTC txns)
    /**
     * @dev Calculate merkle root from transaction ids in natural byte order
     * @param txids TXIDs must be in natural byte order
     * @return bytes32 Calculated merkle root
     */
    function calculateMerkleRoot(bytes32[] memory txids) public view returns (bytes32) {
        // Exit condition: if only one hash remains, return it
        if (txids.length == 1) {
            return txids[0];
        }

        // Calculate length of next level
        uint256 nextLevelLength = (txids.length + 1) / 2;
        bytes32[] memory nextLevel = new bytes32[](nextLevelLength);

        // Process pairs and compute parent nodes
        for (uint256 i = 0; i < txids.length; i += 2) {
            uint256 index = i / 2;
            bytes32 left = txids[i];
            bytes32 right = i + 1 < txids.length ? txids[i + 1] : left;

            // Hash the concatenated pair
            nextLevel[index] = hashPair(left, right);
        }

        // Recursive call with the new level
        return calculateMerkleRoot(nextLevel);
    }

    /**
     * @dev Verify difficulty target for adjustment blocks
     * @param header New block header
     */
    function verifyDifficultyTarget(BlockHeader memory header) internal view {
        // Get the last adjustment block
        bytes32 cursor = header.prevBlock;
        for (uint256 i = 0; i < DIFFICULTY_ADJUSTMENT_INTERVAL - 1; i++) {
            cursor = headers[cursor].prevBlock;
        }

        BlockHeader storage lastAdjustment = headers[cursor];

        // Calculate actual timespan
        uint256 actualTimespan = header.timestamp - lastAdjustment.timestamp;

        // Apply bounds of 1/4 and 4x target timespan
        actualTimespan = actualTimespan < TARGET_TIMESPAN / 4 ? TARGET_TIMESPAN / 4 : actualTimespan;
        actualTimespan = actualTimespan > TARGET_TIMESPAN * 4 ? TARGET_TIMESPAN * 4 : actualTimespan;

        // Calculate new target
        uint256 newTarget = expandDifficultyBits(lastAdjustment.difficultyBits);
        newTarget = newTarget * actualTimespan / TARGET_TIMESPAN;

        // Ensure new target is below maximum allowed
        uint256 maxTarget = expandDifficultyBits(LOWEST_DIFFICULTY);
        newTarget = newTarget > maxTarget ? maxTarget : newTarget;

        // Verify header difficulty matches calculated target
        require(expandDifficultyBits(header.difficultyBits) == newTarget, "Invalid difficulty target");
    }

    function hashPair(bytes32 a, bytes32 b) public view returns (bytes32) {
        return sha256DoubleHash(abi.encodePacked(a, b));
    }

    function sha256DoubleHash(bytes memory blockHeader) public view returns (bytes32) {
        require(blockHeader.length == HEADER_LENGTH, INVALID_HEADER_LENGTH());
        // First SHA256
        (bool success1, bytes memory result1) = address(0x2).staticcall(abi.encodePacked(blockHeader));
        require(success1, SHA256_FAILED());

        // Second SHA256
        (bool success2, bytes memory result2) = address(0x2).staticcall(result1);
        require(success2, SHA256_FAILED());

        return bytes32(result2);
    }

    function reverseBytesHash(bytes32 blockHash) public pure returns (bytes32) {
        // Convert the bytes32 to bytes memory for easier manipulation
        bytes memory temp = new bytes(32);

        // Copy the bytes32 into our temporary array
        assembly {
            mstore(add(temp, 32), blockHash)
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

    function getReversedBitcoinBlockHash(bytes memory blockHeader) public view returns (bytes32) {
        // First get the double SHA256 hash
        bytes32 hash = sha256DoubleHash(blockHeader);

        // Then reverse it
        return reverseBytesHash(hash);
    }

    function getReversedMerkleRoot(bytes32[] memory txids) public view returns (bytes32) {
        // First get the double SHA256 hash
        bytes32 hash = calculateMerkleRoot(txids);

        // Then reverse it
        return reverseBytesHash(hash);
    }
}
