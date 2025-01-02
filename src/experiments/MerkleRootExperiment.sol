// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// import {console} from "forge-std/console.sol";
import {BitcoinUtils} from "../BitcoinUtils.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract MerkleRootExperiment {
    /**
     * @dev Calculate merkle root in reversed byte order
     * @param txids bytes32 txn ids
     * @return bytes32 merkle root
     */
    function calculateMerkleRoot(bytes32[] calldata txids) external view returns (bytes32) {
        bytes32[] memory txIdsInNaturalBytesOrder = BitcoinUtils.reverseBytes32Array(txids);
        // First get the double SHA256 hash
        bytes32 hash = _calculateMerkleRootInNaturalByteOrder(txIdsInNaturalBytesOrder);

        // Then reverse it
        return BitcoinUtils.reverseBytes32(hash);
    }

    /**
     * @dev Calculate merkle root in natural byte order from transaction ids (in natural byte order)
     * @param txids Merkle proof nodes
     * @return bytes32 Calculated merkle root in natural byte order
     */
    function _calculateMerkleRootInNaturalByteOrder(bytes32[] memory txids) internal view returns (bytes32) {
        require(txids.length != 0, "INVALID_INPUT()");
        if (txids.length == 1) return txids[0];

        // Create a memory array to store the current level's hashes
        uint256 currentLevelLength = txids.length;
        bytes32[] memory currentLevel = new bytes32[](currentLevelLength);

        // Copy initial txids to currentLevel
        for (uint256 i = 0; i < currentLevelLength; i++) {
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
     * @notice Generate merkle proof for a transaction using binary index path
     * @dev Index is provided as uint but represents binary path in the tree
     *      The maximum value of the index is checked against array length
     * @param transactions Array of transaction hashes in tree order
     * @param index Binary path index to the target transaction
     * @return proof Array of proof hashes
     * @return directions Array of boolean values indicating left (false) or right (true) placements
     */
    function generateMerkleProof(
        bytes32[] memory transactions, // This should be in natural byte order and so would be the resultant txns
        uint256 index
    ) public view returns (bytes32[] memory proof, bool[] memory directions) {
        // Check if transactions array is empty
        require(transactions.length > 0, "Empty transaction list");

        // Calculate maximum allowed index (number of transactions - 1)
        uint256 maxIndex = transactions.length - 1;
        require(index <= maxIndex, "Index out of bounds");

        // Calculate the number of levels in the tree
        uint256 levels = 0;
        uint256 levelSize = transactions.length;
        while (levelSize > 1) {
            levelSize = (levelSize + 1) >> 1; // Divide by 2 rounding up
            levels++;
        }

        // Initialize proof arrays
        proof = new bytes32[](levels);
        directions = new bool[](levels);

        // Current level's nodes
        bytes32[] memory currentLevel = new bytes32[](transactions.length);
        for (uint256 i = 0; i < transactions.length; i++) {
            currentLevel[i] = transactions[i];
        }

        // Current position being tracked
        uint256 currentIndex = index;

        // Generate proof by moving up the tree
        for (uint256 level = 0; level < levels; level++) {
            uint256 levelLength = currentLevel.length;
            uint256 nextLevelLength = (levelLength + 1) >> 1;
            bytes32[] memory nextLevel = new bytes32[](nextLevelLength);

            // For each pair in current level
            for (uint256 i = 0; i < levelLength; i += 2) {
                uint256 pairIndex = i >> 1;
                bytes32 left = currentLevel[i];
                bytes32 right = (i + 1 < levelLength) ? currentLevel[i + 1] : left;

                // If this pair contains our target index
                if (i <= currentIndex && currentIndex < i + 2) {
                    // Record the sibling as proof
                    if (currentIndex % 2 == 0) {
                        proof[level] = right;
                        directions[level] = true; // Right sibling
                    } else {
                        proof[level] = left;
                        directions[level] = false; // Left sibling
                    }
                }

                // Hash the pair for next level
                nextLevel[pairIndex] = BitcoinUtils.hashPair(left, right);
            }

            // Update for next level
            currentLevel = nextLevel;
            currentIndex = currentIndex >> 1;
        }

        return (proof, directions);
    }

    /**
     * @notice Helper function to verify a generated proof
     * @param txId Transaction hash to verify
     * @param proof Array of proof hashes
     * @param directions Array of proof directions [true for right sibling or 0, false for left sibling or 1]
     * @return bytes32 Computed merkle root
     */
    function verifyGeneratedProof(
        bytes32 txId,
        bytes32[] memory proof,
        bool[] memory directions // should be index ideally
    ) public view returns (bytes32) {
        require(proof.length == directions.length, "Proof and directions length mismatch");

        bytes32 currentHash = txId;

        // Compute root by applying proof elements
        for (uint256 i = 0; i < proof.length; i++) {
            if (directions[i]) {
                // Proof element goes on right
                currentHash = BitcoinUtils.hashPair(currentHash, proof[i]);
            } else {
                // Proof element goes on left
                currentHash = BitcoinUtils.hashPair(proof[i], currentHash);
            }
        }

        return currentHash;
    }

    /**
     * @notice Verify if a transaction is included in a block using a Merkle proof
     * @dev All inputs should be in Bitcoin's display format (reversed byte order)
     * @param txId Transaction ID to verify (in Bitcoin's reversed byte order)
     * @param merkleRoot Expected Merkle root (in Bitcoin's reversed byte order)
     * @param proof Array of proof hashes (in Bitcoin's reversed byte order)
     * @param index Index of the transaction in the block (0-based)
     * @return bool True if the proof is valid
     */
    function verifyTxInclusion(bytes32 txId, bytes32 merkleRoot, bytes32[] calldata proof, uint256 index)
        external
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
                currentHash = BitcoinUtils.hashPair(currentHash, proofElement);
            } else {
                // Current hash should go on the right
                currentHash = BitcoinUtils.hashPair(proofElement, currentHash);
            }

            // Move up to the parent level
            index = index / 2;
        }

        // Compare with the expected merkle root
        return currentHash == merkleRoot;
    }
}
