// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

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

    // Bitcoin block header is 80 bytes
    uint256 private constant HEADER_LENGTH = 80;

    // Minimum difficulty target
    uint256 private constant LOWEST_DIFFICULTY = 0x1d00ffff;

    // Block header interval for difficulty adjustment
    uint256 private constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

    // Target block time in seconds
    uint256 private constant TARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks

    // TODO: Pack the uints by allowing the max limit for the respective field
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
        // require(header.length == HEADER_LENGTH, INVALID_HEADER_LENGTH()); // Had it been a raw header
        // require(calculatedBlockHash == parsedHeader.blockHash, INVALID_BLOCK_HASH());

        // Parse header
        // BlockHeader memory parsedHeader = parseBlockHeader(header);

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
     * @notice Verify a transaction inclusion proof
     * @param txid Transaction ID
     * @param merkleProof Merkle proof of inclusion
     * @param blockHash Block hash containing the transaction
     * @return bool True if the proof is valid
     */
    function verifyTx(bytes32 txid, bytes32[] calldata merkleProof, bytes32 blockHash) public view returns (bool) {
        BlockHeader storage header = headers[blockHash];
        require(header.timestamp != 0, INVALID_BLOCK_HEADER());

        bytes32 expectedRoot = calculateMerkleRoot(txid, merkleProof);
        return expectedRoot == header.merkleRoot;
    }

    /**
     * @dev Parse a raw block header (80 bytes) into structured data
     * @param header Raw block header bytes
     * @return BlockHeader Parsed header struct
     */
    // function parseBlockHeader(bytes calldata header) internal pure returns (BlockHeader memory) {
    //     require(header.length == HEADER_LENGTH, INVALID_HEADER_LENGTH());

    //     BlockHeader memory parsed;

    //     // Extract header fields
    //     assembly {
    //         // Version is first 4 bytes
    //         parsed.version := shr(224, calldataload(header.offset))

    //         // Previous block hash is next 32 bytes
    //         parsed.prevBlock := calldataload(add(header.offset, 4))

    //         // Merkle root is next 32 bytes
    //         parsed.merkleRoot := calldataload(add(header.offset, 36))

    //         // Timestamp is next 4 bytes
    //         parsed.timestamp := shr(224, calldataload(add(header.offset, 68)))

    //         // Difficulty bits is next 4 bytes
    //         parsed.difficultyBits := shr(224, calldataload(add(header.offset, 72)))

    //         // Nonce is last 4 bytes
    //         parsed.nonce := shr(224, calldataload(add(header.offset, 76)))
    //     }

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

    /**
     * @dev Calculate merkle root from transaction and proof
     * @param txid Transaction ID
     * @param proof Merkle proof nodes
     * @return bytes32 Calculated merkle root
     */
    function calculateMerkleRoot(bytes32 txid, bytes32[] calldata proof) internal pure returns (bytes32) {
        bytes32 current = txid;

        for (uint256 i = 0; i < proof.length; i++) {
            if (uint256(current) < uint256(proof[i])) {
                current = sha256(abi.encodePacked(current, proof[i]));
            } else {
                current = sha256(abi.encodePacked(proof[i], current));
            }
        }

        return current;
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
}
