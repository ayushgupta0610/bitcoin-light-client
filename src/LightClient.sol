// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// import {console} from "forge-std/console.sol";
import {BitcoinUtils} from "./BitcoinUtils.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title BitcoinLightClient
 * @notice A light client implementation for Bitcoin on Ethereum
 * @dev Validates Bitcoin block headers and performs SPV verification
 */
contract LightClient is AccessControl {
    // Errors
    error INVALID_HEADER_LENGTH();
    error PREVIOUS_BLOCK_UNKNOWN();
    error INVALID_PROOF_OF_WORK();
    error INVALID_DIFFICULTY_TARGET();
    error INVALID_INPUT();

    // Block submitter role
    bytes32 private constant BLOCK_SUBMIT_ROLE = keccak256("BLOCK_SUBMIT_ROLE");

    // Bitcoin block header is 80 bytes
    uint8 private constant HEADER_LENGTH = 80;

    // Minimum difficulty bits
    uint32 private constant MINIMUM_DIFFICULTY_BITS = 0x1d00ffff;

    // Block header interval for difficulty adjustment
    uint32 private constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

    // Target block time in seconds
    uint40 private constant TARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks

    // Genesis block header hash
    bytes32 public constant GENESIS_BLOCK = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

    // Last block hash initialised to genesis block
    bytes32 public latestBlockHash = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

    // Mapping of block hash to block header
    mapping(bytes32 => BitcoinUtils.BlockHeader) private headers;

    // Events
    event BlockHeaderSubmitted(bytes32 indexed blockHash, bytes32 indexed prevBlock, uint32 height);
    event ChainReorg(
        uint32 prevBlockHeight, bytes32 indexed prevBlockHash, bytes32 indexed latestBlockHash, uint32 latestBlockHeight
    );

    constructor(address blockSubmitter) {
        // TODO: Add functions who can update / delete / add the roles (this is for illustration purposes)
        _grantRole(BLOCK_SUBMIT_ROLE, blockSubmitter);
        _initialiseGenesisBlock();
    }

    function _initialiseGenesisBlock() private {
        BitcoinUtils.BlockHeader memory blockHeader = BitcoinUtils.BlockHeader({
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
        bytes32 blockHash = getBlockHash(rawHeader);

        // Parse header
        BitcoinUtils.BlockHeader memory parsedHeader = BitcoinUtils.parseBlockHeader(rawHeader);

        // Submit block header
        _submitBlockHeader(blockHash, parsedHeader);
    }

    /**
     * @notice Submit a new block header
     * @param blockHash Block hash in reverse byte order
     * @param version Block version
     * @param blockTimestamp  Block timestamp
     * @param difficultyBits Compressed difficulty target
     * @param nonce used for mining
     * @param prevBlock Previous block hash
     * @param merkleRoot Merkle tree root hash
     */
    function submitBlockHeader(
        bytes32 blockHash,
        uint32 version, // 4 bytes
        uint40 blockTimestamp, // 5 bytes
        uint32 difficultyBits, // 4 bytes
        uint32 nonce, // 4 bytes
        bytes32 prevBlock, // 32 bytes
        bytes32 merkleRoot // 32 bytes
    ) external onlyRole(BLOCK_SUBMIT_ROLE) {
        BitcoinUtils.BlockHeader memory blockHeader = BitcoinUtils.BlockHeader({
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

    // This can also be made as verify and submit Block header by verifying if the blockHeader hashes to blockHash by converting the struct to rawHeader first - Will add to the gas cost!
    function _submitBlockHeader(bytes32 blockHash, BitcoinUtils.BlockHeader memory blockHeader) private {
        // Verify the header connects to our chain
        require(
            headers[blockHeader.prevBlock].timestamp != 0 || blockHeader.prevBlock == GENESIS_BLOCK,
            PREVIOUS_BLOCK_UNKNOWN()
        );

        // Verify proof of work
        require(BitcoinUtils.verifyProofOfWork(blockHash, blockHeader.difficultyBits), INVALID_PROOF_OF_WORK());

        // Set block height
        blockHeader.height = headers[blockHeader.prevBlock].height + 1;

        // Verify difficulty target if this is an adjustment block (This spikes up the gas to in case of blockNo%2016==0)
        // if (blockHeader.height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0) {
        //     verifyDifficultyTarget(blockHeader);
        // }

        // Store the header
        headers[blockHash] = blockHeader;

        // Update latest block hash if this is the new best chain
        if (blockHeader.height > headers[latestBlockHash].height) {
            bytes32 prevBlockHash = latestBlockHash;
            latestBlockHash = blockHash;
            emit ChainReorg(headers[latestBlockHash].height, prevBlockHash, latestBlockHash, blockHeader.height);
        }

        emit BlockHeaderSubmitted(blockHash, blockHeader.prevBlock, blockHeader.height);
    }

    /**
     * @dev Calculate merkle root in natural byte order from transaction ids (in natural byte order)
     * @param txids Merkle proof nodes
     * @return bytes32 Calculated merkle root in natural byte order
     */
    function _calculateMerkleRootInNaturalByteOrder(bytes32[] memory txids) internal view returns (bytes32) {
        require(txids.length != 0, INVALID_INPUT());
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
                nextLevel[index] = BitcoinUtils.hashPair(left, right);
            }

            // Update currentLevel for next iteration
            currentLevel = nextLevel;
            currentLevelLength = nextLevelLength;
        }

        return currentLevel[0];
    }

    /**
     * @dev Verify difficulty target for adjustment blocks
     * @param header New block header
     */
    function verifyDifficultyTarget(BitcoinUtils.BlockHeader memory header) public view {
        // Only adjust difficulty every 2016 blocks
        if (header.height % 2016 != 0) {
            require(
                header.difficultyBits == headers[header.prevBlock].difficultyBits,
                "Difficulty can only change on adjustment blocks"
            );
            return;
        }

        // Calculate the height of the last adjustment block
        // For block 2016, we need block 0
        // For block 4032, we need block 2016
        uint256 lastAdjustmentHeight = (header.height / 2016 - 1) * 2016;

        // Get the last adjustment block by traversing back to that height
        bytes32 cursor = header.prevBlock;
        BitcoinUtils.BlockHeader memory currentBlock;

        do {
            currentBlock = headers[cursor];
            cursor = currentBlock.prevBlock;
        } while (currentBlock.height > lastAdjustmentHeight);

        BitcoinUtils.BlockHeader memory lastAdjustment = headers[cursor];

        // Calculate actual timespan between last adjustment and current block
        uint256 actualTimespan = header.timestamp - lastAdjustment.timestamp;

        // Bound the adjustment factor
        if (actualTimespan < TARGET_TIMESPAN / 4) {
            actualTimespan = TARGET_TIMESPAN / 4;
        }
        if (actualTimespan > TARGET_TIMESPAN * 4) {
            actualTimespan = TARGET_TIMESPAN * 4;
        }

        // Calculate new target
        uint256 oldTarget = BitcoinUtils.expandDifficultyBits(lastAdjustment.difficultyBits);
        uint256 newTarget = (oldTarget * actualTimespan) / TARGET_TIMESPAN;

        // Never exceed the minimum difficulty (maximum target)
        uint256 maxTarget = BitcoinUtils.expandDifficultyBits(MINIMUM_DIFFICULTY_BITS);
        if (newTarget > maxTarget) {
            newTarget = maxTarget;
        }

        // Convert new target to compact format and verify
        uint32 newDifficultyBits = BitcoinUtils.compactDifficultyBits(uint32(newTarget));
        require(header.difficultyBits == newDifficultyBits, "Invalid difficulty target");
    }

    /**
     * @dev Calculate serialized block header from BlockHeader struct
     * @param version Block version
     * @param blockTimestamp  Block timestamp
     * @param difficultyBits Compressed difficulty target
     * @param nonce used for mining
     * @param prevBlock Previous block hash
     * @param merkleRoot Merkle tree root hash
     * @return bytes serialized block header
     */
    function getSeralizedBlockHeader(
        uint32 version, // 4 bytes
        uint40 blockTimestamp, // 5 bytes
        uint32 difficultyBits, // 4 bytes
        uint32 nonce, // 4 bytes
        bytes32 prevBlock, // 32 bytes
        bytes32 merkleRoot // 32 bytes
    ) external pure returns (bytes memory) {
        return BitcoinUtils.serializeBlockHeader(version, blockTimestamp, difficultyBits, nonce, prevBlock, merkleRoot);
    }

    /**
     * @dev Calculate bitcoin block hash in reverse byte order
     * @param blockHeader Raw block header bytes
     * @return bytes32 Block hash in reverse byte order
     */
    function getBlockHash(bytes memory blockHeader) public view returns (bytes32) {
        require(blockHeader.length == HEADER_LENGTH, INVALID_HEADER_LENGTH());
        // First get the double SHA256 hash
        bytes32 hash = BitcoinUtils.sha256DoubleHash(blockHeader);

        // Then reverse it
        return BitcoinUtils.reverseBytes32(hash);
    }

    /**
     * @dev Calculate merkle root in reversed byte order
     * @param txids bytes32 txn ids
     * @return bytes32 merkle root
     */
    function calculateMerkleRoot(bytes32[] memory txids) external view returns (bytes32) {
        bytes32[] memory txIdsInNaturalBytesOrder = BitcoinUtils.reverseBytes32Array(txids);
        // First get the double SHA256 hash
        bytes32 hash = _calculateMerkleRootInNaturalByteOrder(txIdsInNaturalBytesOrder);

        // Then reverse it
        return BitcoinUtils.reverseBytes32(hash);
    }

    /**
     * @dev Get block header struct for a block hash
     * @param blockHash block hash
     * @return BlockHeader block header struct
     */
    function getBlockHeader(bytes32 blockHash) external view returns (BitcoinUtils.BlockHeader memory) {
        return headers[blockHash];
    }
}
