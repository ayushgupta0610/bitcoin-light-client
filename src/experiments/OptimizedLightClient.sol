// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {BitcoinUtils} from "../BitcoinUtils.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract OptimizedLightClient is AccessControl {
    error INVALID_HEADER_LENGTH();
    error INVALID_PROOF_OF_WORK();
    error INVALID_HEADER_CHAIN();
    error CHAIN_NOT_CONNECTED();
    error HEADERS_REQUIRED();

    bytes32 private constant BLOCK_SUBMIT_ROLE = keccak256("BLOCK_SUBMIT_ROLE");
    uint8 private constant HEADER_LENGTH = 80;

    // Latest checkpoint header hash
    bytes32 private latestCheckpointHeaderHash;

    // Mapping of block hash to block header
    mapping(bytes32 => BitcoinUtils.BlockHeader) private headers;

    event BlockHeaderSubmitted(bytes32 indexed blockHash, bytes32 indexed prevBlock, uint32 height);
    event ChainReorg(uint32 prevBlockHeight, bytes32 indexed prevBlockHash, uint32 height, bytes32 indexed blockHash);

    constructor(
        uint32 version, // 4 bytes
        uint32 timestamp, // 4 bytes
        uint32 difficultyBits, // 4 bytes
        uint32 nonce, // 4 bytes
        uint32 height, // 4 bytes
        bytes32 prevBlock, // 32 bytes
        bytes32 merkleRoot // 32 bytes
    ) {
        _grantRole(BLOCK_SUBMIT_ROLE, msg.sender);
        BitcoinUtils.BlockHeader memory header =
            BitcoinUtils.BlockHeader(version, timestamp, difficultyBits, nonce, height, prevBlock, merkleRoot);
        latestCheckpointHeaderHash = BitcoinUtils.getBlockHashFromStruct(header);
        headers[latestCheckpointHeaderHash] = header;
    }

    /**
     * @notice Submit a new block header along with intermediate headers connecting to last checkpoint
     * @param rawHeader bytes header
     * @param intermediateHeaders Array of intermediate headers connecting to last checkpoint (in reverse order)
     * @dev intermediateHeaders should be ordered from newest to oldest (connecting to checkpoint)
     */
    function submitBlockHeader(bytes calldata rawHeader, bytes[] calldata intermediateHeaders)
        external
        onlyRole(BLOCK_SUBMIT_ROLE)
        returns (bool)
    {
        if (rawHeader.length != HEADER_LENGTH) revert INVALID_HEADER_LENGTH();
        bytes32 blockHash = getBlockHash(rawHeader);
        BitcoinUtils.BlockHeader memory header = BitcoinUtils.parseBlockHeader(rawHeader);

        // Verify POW for new header
        if (!BitcoinUtils.verifyProofOfWork(blockHash, header.difficultyBits)) {
            revert INVALID_PROOF_OF_WORK();
        }

        // If there are intermediate headers, verify the chain
        if (intermediateHeaders.length > 0) {
            bool isValid = _verifyHeaderChain(header.prevBlock, intermediateHeaders);
            if (!isValid) revert INVALID_HEADER_CHAIN();
        } else {
            // If no intermediate headers, verify direct connection to checkpoint
            if (header.prevBlock != latestCheckpointHeaderHash) revert CHAIN_NOT_CONNECTED();
        }

        // Update the checkpoint
        uint32 latestHeaderHeight = headers[latestCheckpointHeaderHash].height;
        header.height = latestHeaderHeight + uint32(intermediateHeaders.length) + 1;
        latestCheckpointHeaderHash = blockHash;
        headers[latestCheckpointHeaderHash] = header;

        emit BlockHeaderSubmitted(blockHash, header.prevBlock, header.height);
        return true;
    }

    /**
     * @notice Verify a chain of headers connects properly from latest checkpoint to new block
     * @param currentPrevHash Previous hash of the current header
     * @param intermediateHeaders Array of intermediate headers
     * @return bool True if chain is valid
     */
    function _verifyHeaderChain(bytes32 currentPrevHash, bytes[] calldata intermediateHeaders)
        private
        view
        returns (bool)
    {
        // Verify each intermediate header
        for (uint256 i = 0; i < intermediateHeaders.length; i++) {
            if (intermediateHeaders[i].length != HEADER_LENGTH) revert INVALID_HEADER_LENGTH();

            // Parse and verify the header
            BitcoinUtils.BlockHeader memory intermediateHeader = BitcoinUtils.parseBlockHeader(intermediateHeaders[i]);

            // Calculate hash of this intermediate header
            bytes32 intermediateHash = BitcoinUtils.sha256DoubleHash(intermediateHeaders[i]);
            intermediateHash = BitcoinUtils.reverseBytes32(intermediateHash);

            // Verify the hash chain
            if (currentPrevHash != intermediateHash) revert INVALID_HEADER_CHAIN();

            // Verify POW for intermediate header
            if (!BitcoinUtils.verifyProofOfWork(intermediateHash, intermediateHeader.difficultyBits)) {
                revert INVALID_PROOF_OF_WORK();
            }

            // Move to next header
            currentPrevHash = intermediateHeader.prevBlock;
        }

        // Final verification - connect to checkpoint
        return currentPrevHash == latestCheckpointHeaderHash; // Evaluate till how many blocks does this not return OOG error
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
     * @dev Get blocj header struct for a given block hash
     * @param blockHash bytes32 Block hash in reverse byte order
     * @return BitcoinUtils.BlockHeader Block header struct
     */
    function getHeader(bytes32 blockHash) external view returns (BitcoinUtils.BlockHeader memory) {
        return headers[blockHash];
    }

    /**
     * @dev Get the latest block hash
     * @return bytes32 Latest block hash
     */
    function getLatestHeaderHash() external view returns (bytes32) {
        return latestCheckpointHeaderHash;
    }

    /**
     * @dev Get the latest block header
     * @return BitcoinUtils.BlockHeader Latest block header
     */
    function getLatestCheckpoint() external view returns (BitcoinUtils.BlockHeader memory) {
        return headers[latestCheckpointHeaderHash];
    }
}
