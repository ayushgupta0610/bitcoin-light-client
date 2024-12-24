// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {BitcoinHeaderParser} from "./BitcoinHeaderParser.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title BitcoinLightClient
 * @notice A light client implementation for Bitcoin on Ethereum
 * @dev Validates Bitcoin block headers and performs SPV verification
 */
contract LightClient is BitcoinHeaderParser, AccessControl {
    // Errors
    error INVALID_HEADER_LENGTH();
    error PREVIOUS_BLOCK_UNKNOWN();
    error INVALID_PROOF_OF_WORK();
    error INVALID_BLOCK_HEADER();
    error INVALID_DIFFICULTY_TARGET();
    error SHA256_FAILED();
    error INVALID_INPUT();

    // Block submitter role
    bytes32 private constant BLOCK_SUBMIT_ROLE = keccak256("BLOCK_SUBMIT_ROLE");

    // Bitcoin block header is 80 bytes
    uint256 private constant HEADER_LENGTH = 80;

    // Minimum difficulty target
    uint256 private constant LOWEST_DIFFICULTY_BITS = 0x1d00ffff;

    // Block header interval for difficulty adjustment
    uint256 private constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

    // Target block time in seconds
    uint256 private constant TARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks

    // Genesis block header hash
    bytes32 public constant GENESIS_BLOCK = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

    // Mapping of block hash to block header
    mapping(bytes32 => BlockHeader) private headers;

    // Main chain tip
    bytes32 public chainTip = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

    // Events
    event BlockHeaderSubmitted(bytes32 indexed blockHash, bytes32 indexed prevBlock, uint256 height);
    event ChainReorg(bytes32 indexed oldTip, bytes32 indexed newTip);

    constructor(address blockSubmitter) {
        // TODO: Add functions who can update / delete / add the roles (this is for illustration purposes)
        _grantRole(BLOCK_SUBMIT_ROLE, blockSubmitter);
        _initialiseGenesisBlock();
    }

    function _initialiseGenesisBlock() private {
        BlockHeader memory blockHeader = BlockHeader({
            version: 0x01,
            prevBlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
            merkleRoot: 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b,
            timestamp: 1231006505,
            difficultyBits: 0x1d00ffff,
            nonce: 0x7c2bac1d,
            height: 0
        });
        headers[GENESIS_BLOCK] = blockHeader;
    }

    /**
     * @notice Submit a new block header
     * @param rawHeader The 80-byte Bitcoin block header
     */
    function submitRawBlockHeader(bytes calldata rawHeader) external onlyRole(BLOCK_SUBMIT_ROLE) {
        require(rawHeader.length == HEADER_LENGTH, INVALID_HEADER_LENGTH());

        // Calculate block hash in reverse byte order
        bytes32 blockHash = getReversedBitcoinBlockHash(rawHeader);

        // Parse header
        BlockHeader memory parsedHeader = parseBlockHeader(rawHeader);

        // Submit block header
        _submitBlockHeader(blockHash, parsedHeader);
    }

    /**
     * @notice Submit a new block header
     * @param blockHash Block hash in reverse byte order
     * @param version Block version
     * @param prevBlock Previous block hash
     * @param merkleRoot Merkle tree root hash
     * @param blockTimestamp  Block timestamp
     * @param difficultyBits Compressed difficulty target
     * @param nonce used for mining
     */
    function submitBlockHeader(
        bytes32 blockHash,
        uint256 version,
        bytes32 prevBlock,
        bytes32 merkleRoot,
        uint256 blockTimestamp,
        uint256 difficultyBits,
        uint256 nonce
    ) external onlyRole(BLOCK_SUBMIT_ROLE) {
        BlockHeader memory blockHeader = BlockHeader({
            version: version, // Block version
            prevBlock: prevBlock,
            merkleRoot: merkleRoot,
            timestamp: blockTimestamp,
            difficultyBits: difficultyBits,
            nonce: nonce, // Nonce used for mining
            height: 0
        });
        _submitBlockHeader(blockHash, blockHeader);
    }

    // This can also be made as verify and submit Block header by verifying if the parsedHeader hashes to blockHash by converting the struct to rawHeader first
    function _submitBlockHeader(bytes32 blockHash, BlockHeader memory parsedHeader) private {
        // Verify the header connects to our chain
        require(
            headers[parsedHeader.prevBlock].timestamp != 0 || parsedHeader.prevBlock == GENESIS_BLOCK,
            PREVIOUS_BLOCK_UNKNOWN()
        );

        // Verify proof of work
        require(verifyProofOfWork(blockHash, parsedHeader.difficultyBits), INVALID_PROOF_OF_WORK());

        // Set block height
        parsedHeader.height = headers[parsedHeader.prevBlock].height + 1;

        // Verify difficulty target if this is an adjustment block
        if (parsedHeader.height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0) {
            verifyDifficultyTarget(parsedHeader);
        }

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

    // TODO: Correct this
    /**
     * @notice Verify a transaction inclusion proofs
     * @param txId Transaction ID
     * @param proofs Merkle proofs of inclusion
     * @param root Block hash containing the transaction
     * @return bool True if the proofs are valid
     */
    function verifyTx(bytes32 txId, bytes32[] calldata proofs, bytes32 root) external view returns (bool) {
        BlockHeader storage header = headers[root];
        require(header.timestamp != 0, INVALID_BLOCK_HEADER());

        for (uint256 i = 0; i < proofs.length; i++) {
            bytes32 proofElement = proofs[i];

            if (txId <= proofElement) {
                // Hash(current computed hash + current element of the proofs)
                txId = keccak256(abi.encodePacked(txId, proofElement));
            } else {
                // Hash(current element of the proofs + current computed hash)
                txId = keccak256(abi.encodePacked(proofElement, txId));
            }
        }

        return txId == root;
    }

    /**
     * @dev Verify the proof of work meets difficulty target
     * @param blockHash Calculated block hash
     * @param difficultyBits Compressed difficulty target
     * @return bool True if proof of work is valid
     */
    function verifyProofOfWork(bytes32 blockHash, uint256 difficultyBits) public pure returns (bool) {
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
    function expandDifficultyBits(uint256 bits) public pure returns (uint256) {
        uint256 exp = bits >> 24;
        uint256 coef = bits & 0x00ffffff;

        // Return expanded difficulty target
        return coef * (2 ** (8 * (exp - 3)));
    }

    /**
     * @dev Calculate merkle root in natural byte order from transaction ids (in natural byte order)
     * @param txids Merkle proof nodes
     * @return bytes32 Calculated merkle root
     */
    function calculateMerkleRoot(bytes32[] memory txids) public view returns (bytes32) {
        require(txids.length == 0, INVALID_INPUT());
        if (txids.length == 1) return txids[0];

        // Create a memory array to store the current level's hashes
        uint256 currentLevelLength = txids.length;
        bytes32[] memory currentLevel = new bytes32[](currentLevelLength);

        // Copy initial txids to currentLevel
        for (uint256 i = 0; i < txids.length; i++) {
            currentLevel[i] = txids[i];
        }

        // Continue until we reach the root
        while (currentLevelLength > 1) {
            // Calculate new level length (round up division)
            uint256 nextLevelLength = (currentLevelLength + 1) / 2;
            bytes32[] memory nextLevel = new bytes32[](nextLevelLength);

            // Process pairs and compute parent nodes
            for (uint256 i = 0; i < currentLevelLength; i += 2) {
                uint256 index = i / 2;
                bytes32 left = currentLevel[i];
                bytes32 right = i + 1 < currentLevelLength ? currentLevel[i + 1] : left;

                // Hash the concatenated pair
                nextLevel[index] = hashPair(left, right);
            }

            // Update currentLevel for next iteration
            currentLevel = nextLevel;
            currentLevelLength = nextLevelLength;
        }

        return currentLevel[0];
    }

    function hashPair(bytes32 a, bytes32 b) internal view returns (bytes32) {
        return sha256DoubleHash(abi.encodePacked(a, b));
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

        BlockHeader memory lastAdjustment = headers[cursor];

        // Calculate actual timespan
        uint256 actualTimespan = header.timestamp - lastAdjustment.timestamp;

        // Apply bounds of 1/4 and 4x target timespan
        actualTimespan = actualTimespan < TARGET_TIMESPAN / 4 ? TARGET_TIMESPAN / 4 : actualTimespan;
        actualTimespan = actualTimespan > TARGET_TIMESPAN * 4 ? TARGET_TIMESPAN * 4 : actualTimespan;

        // Calculate new target
        uint256 newTarget = expandDifficultyBits(lastAdjustment.difficultyBits);
        newTarget = (newTarget * actualTimespan) / TARGET_TIMESPAN;

        // Ensure new target is below maximum allowed
        uint256 maxTarget = expandDifficultyBits(LOWEST_DIFFICULTY_BITS);
        newTarget = newTarget > maxTarget ? maxTarget : newTarget;

        // Verify header difficulty matches calculated target
        require(expandDifficultyBits(header.difficultyBits) == newTarget, INVALID_DIFFICULTY_TARGET());
    }

    function sha256DoubleHash(bytes memory bytesData) internal view returns (bytes32) {
        // First SHA256
        (bool success1, bytes memory result1) = address(0x2).staticcall(abi.encodePacked(bytesData));
        require(success1, SHA256_FAILED());

        // Second SHA256
        (bool success2, bytes memory result2) = address(0x2).staticcall(result1);
        require(success2, SHA256_FAILED());

        return bytes32(result2);
    }

    function reverseBytes32(bytes32 hash) public pure returns (bytes32) {
        // Convert the bytes32 to bytes memory for easier manipulation
        bytes memory temp = new bytes(32);

        // Copy the bytes32 into our temporary array
        assembly {
            mstore(add(temp, 32), hash)
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

    /**
     * @dev Calculate bitcoin block hash in reverse order
     * @param blockHeader Raw block header bytes
     * @return bytes32 Block hash
     */
    function getReversedBitcoinBlockHash(bytes memory blockHeader) public view returns (bytes32) {
        // First get the double SHA256 hash
        bytes32 hash = sha256DoubleHash(blockHeader);

        // Then reverse it
        return reverseBytes32(hash);
    }

    function getReversedMerkleRoot(bytes32[] memory txids) public view returns (bytes32) {
        // First get the double SHA256 hash
        bytes32 hash = calculateMerkleRoot(txids);

        // Then reverse it
        return reverseBytes32(hash);
    }

    function getBlockHeader(bytes32 blockHash) external view returns (BlockHeader memory) {
        return headers[blockHash];
    }

    function getBlockHash(bytes calldata blockHeader) public view returns (bytes32) {
        require(blockHeader.length == HEADER_LENGTH, INVALID_HEADER_LENGTH());
        return sha256DoubleHash(blockHeader);
    }
}
