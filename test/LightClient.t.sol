// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {LightClient} from "../src/LightClient.sol";
import {BitcoinUtils} from "../src/BitcoinUtils.sol";

contract LightClientTest is Test {
    LightClient public lightClient;
    address public blockSubmitter;

    // Genesis block constants
    bytes32 constant GENESIS_BLOCK = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

    // Example Bitcoin block header (block #1)
    bytes constant BLOCK_1_HEADER =
        hex"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    bytes32 constant BLOCK_1_HASH = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
    uint32 private constant TARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks

    function setUp() public {
        blockSubmitter = makeAddr("blockSubmitter");
        lightClient = new LightClient(blockSubmitter);
    }

    function test_InitialState() public {
        assertEq(lightClient.latestBlockHash(), GENESIS_BLOCK);

        BitcoinUtils.BlockHeader memory genesisHeader = lightClient.getBlockHeader(GENESIS_BLOCK);
        assertEq(genesisHeader.version, 1);
        assertEq(genesisHeader.prevBlock, bytes32(0));
        assertEq(genesisHeader.merkleRoot, 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b);
        assertEq(genesisHeader.timestamp, 1231006505);
        assertEq(genesisHeader.difficultyBits, 0x1d00ffff);
        assertEq(genesisHeader.nonce, 0x7c2bac1d);
        assertEq(genesisHeader.height, 0);
    }

    function test_SubmitRawBlockHeader() public {
        vm.startPrank(blockSubmitter);

        // Block #1 header with correct PoW
        bytes memory validHeader =
            hex"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
        bytes32 expectedHash = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;

        lightClient.submitRawBlockHeader(validHeader);

        BitcoinUtils.BlockHeader memory header = lightClient.getBlockHeader(expectedHash);
        assertEq(header.version, 1);
        assertEq(header.prevBlock, GENESIS_BLOCK);
        assertEq(header.height, 1);

        vm.stopPrank();
    }

    function test_RevertWhen_InvalidHeaderLength() public {
        vm.startPrank(blockSubmitter);

        bytes memory invalidHeader = hex"0100000000";
        vm.expectRevert(abi.encodeWithSignature("INVALID_HEADER_LENGTH()"));
        lightClient.submitRawBlockHeader(invalidHeader);

        vm.stopPrank();
    }

    function test_RevertWhen_UnauthorizedSubmitter() public {
        address unauthorized = makeAddr("unauthorized");
        vm.startPrank(unauthorized);

        vm.expectRevert();
        lightClient.submitRawBlockHeader(BLOCK_1_HEADER);

        vm.stopPrank();
    }

    function test_RevertWhen_InconsistentBlockAddition() public {
        vm.startPrank(blockSubmitter);

        vm.expectRevert(LightClient.PREVIOUS_BLOCK_UNKNOWN.selector);
        // Values from Block #2
        lightClient.submitBlockHeader(
            0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd,
            1, // version
            1231489544, // timestamp
            0x1d00ffff, // difficultyBits
            0x61bdd208, // nonce
            0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048, // prevBlock
            0x9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5 // merkleRoot
        );
        vm.stopPrank();
    }

    function test_SubmitBlockHeader() public {
        vm.startPrank(blockSubmitter);

        // Values from Block #1
        lightClient.submitBlockHeader(
            BLOCK_1_HASH,
            1, // version
            1231469665, // timestamp
            0x1d00ffff, // difficultyBits
            0x7c2bac1d, // nonce
            GENESIS_BLOCK, // prevBlock
            0x3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a // merkleRoot
        );

        BitcoinUtils.BlockHeader memory header = lightClient.getBlockHeader(BLOCK_1_HASH);
        assertEq(header.version, 1);
        assertEq(header.prevBlock, GENESIS_BLOCK);
        assertEq(header.height, 1);

        vm.stopPrank();
    }

    function test_VerifyProofOfWork() public pure {
        // Real Bitcoin block #1 values
        bytes32 blockHash = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
        uint32 bits = 0x1d00ffff;

        bool isValid = BitcoinUtils.verifyProofOfWork(blockHash, bits);
        assertTrue(isValid, "Valid PoW should return true");

        // Test with invalid hash (higher than target)
        bytes32 invalidHash = 0x1000000000000000000000000000000000000000000000000000000000000000;
        isValid = BitcoinUtils.verifyProofOfWork(invalidHash, bits);
        assertFalse(isValid, "Invalid PoW should return false");
    }

    function test_ExpandDifficultyBits() public {
        uint256 target = BitcoinUtils.expandDifficultyBits(0x1d00ffff);
        assertTrue(target > 0);

        // Test maximum exponent
        vm.expectRevert(abi.encodeWithSignature("EXPONENT_TOO_LARGE()"));
        BitcoinUtils.expandDifficultyBits(0x2100ffff); // Exponent can't be more than 32
    }

    function test_CalculateMerkleRoot() public view {
        bytes32[] memory txids = new bytes32[](4);
        // Block #100k : https://btcscan.org/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
        txids[0] = 0x8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87;
        txids[1] = 0xfff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4;
        txids[2] = 0x6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4;
        txids[3] = 0xe9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d;

        bytes32 preCalculatedMerkleRoot = 0xf3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766;
        bytes32 merkleRoot = lightClient.calculateMerkleRoot(txids);
        assertEq(merkleRoot, preCalculatedMerkleRoot);
    }

    function test_RevertWhen_EmptyTxids() public {
        bytes32[] memory txids = new bytes32[](0);

        vm.expectRevert(abi.encodeWithSignature("INVALID_INPUT()"));
        lightClient.calculateMerkleRoot(txids);
    }

    function test_GetBlockHash() public view {
        // Block #161,477 header in hex (80 bytes)
        bytes memory header =
            hex"010000005e44c8aec03a71182943739e5c51daa2aa4fe1c12c4a435cbd02000000000000dc915bd7f2e0632276fe8e7c0007669f32299442071bca80f15d53a8a43ec5bff27a0b4fd7690d1ad0f84a11";

        // Known block hash for block #161,477
        bytes32 expectedHash = 0x00000000000006b0ddbf4f481393b896b2a3721ac64bc580b3b89f273000a0f3;

        bytes32 hash = lightClient.getBlockHash(header);
        assertEq(hash, expectedHash, "Block hash calculation mismatch");
    }

    function test_ChainUpdate() public {
        vm.startPrank(blockSubmitter);

        // Real Bitcoin block #1 data
        bytes32 block1Hash = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
        lightClient.submitBlockHeader(
            block1Hash,
            1, // version
            1231469665, // timestamp
            0x1d00ffff, // difficultyBits
            2573394689, // nonce - real nonce from block #1
            GENESIS_BLOCK, // prevBlock
            0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098 // merkleRoot from block #1
        );

        // Submit block #2 with valid PoW
        bytes32 block2Hash = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd;
        lightClient.submitBlockHeader(
            block2Hash,
            1,
            1231469744,
            0x1d00ffff,
            2573394689,
            block1Hash,
            0x9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5
        );

        // Verify the chain is updated
        assertEq(lightClient.latestBlockHash(), block2Hash);
        BitcoinUtils.BlockHeader memory newHead = lightClient.getBlockHeader(block2Hash);
        assertEq(newHead.height, 2);

        vm.stopPrank();
    }

    function test_ChainReorg() public {
        vm.startPrank(blockSubmitter);

        // Block #1 (Main chain)
        bytes32 block1Hash = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
        lightClient.submitBlockHeader(
            block1Hash,
            1,
            1231469665,
            0x1d00ffff,
            0x7c2bac1d,
            GENESIS_BLOCK,
            0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098
        );

        // Block #2 (Main chain)
        bytes32 block2Hash = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd;
        lightClient.submitBlockHeader(
            block2Hash,
            1,
            1231469744,
            0x1d00ffff,
            0x2883949c,
            block1Hash,
            0x9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5
        );

        // Verify current chain state
        assertEq(lightClient.latestBlockHash(), block2Hash);
        assertEq(lightClient.getBlockHeader(block2Hash).height, 2);

        // Now submit a competing chain from block #1
        // Competing Block #2 with same parent but different content
        bytes32 competingBlock2Hash = 0x000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820;

        vm.expectEmit(true, true, true, true);
        emit LightClient.ChainReorg(2, block2Hash, 2, competingBlock2Hash);

        lightClient.submitBlockHeader(
            competingBlock2Hash,
            1,
            1231470173, // Later timestamp
            0x1d00ffff,
            0x1dac2b7c,
            block1Hash, // Same parent as the original block 2
            0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098
        );

        // Verify the chain has been reorganized
        assertEq(lightClient.latestBlockHash(), competingBlock2Hash);
        assertEq(lightClient.getBlockHeader(competingBlock2Hash).height, 2);

        vm.stopPrank();
    }

    // function test_DifficultyTargetAdjustment() public {
    //     vm.startPrank(blockSubmitter);

    //     bytes32 prevHash = GENESIS_BLOCK;
    //     uint32 startTime = 1231006505; // Genesis block timestamp
    //     uint32 INITIAL_BITS = 0x1d00ffff;

    //     // Mock a valid block hash that satisfies PoW requirement
    //     // This is a real Bitcoin block hash that satisfies the initial difficulty
    //     bytes32 VALID_POW_HASH = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;

    //     // (Important: https://bitcoin.stackexchange.com/questions/5838/how-is-difficulty-calculated)
    //     for (uint32 i = 1; i < 2017; i++) {
    //         // Use the same valid PoW hash for all blocks - this is just for testing
    //         _submitTestBlock(
    //             VALID_POW_HASH,
    //             startTime + (i * 600), // 10 minute intervals
    //             INITIAL_BITS,
    //             prevHash,
    //             1
    //         );
    //         prevHash = VALID_POW_HASH;
    //     }

    //     // Test Case 1: Exactly 2 weeks (no change in difficulty)
    //     {
    //         uint32 exactTwoWeeks = startTime + (2017 * 600);
    //         _submitTestBlock(
    //             VALID_POW_HASH,
    //             exactTwoWeeks,
    //             INITIAL_BITS, // Should remain the same
    //             prevHash,
    //             1
    //         );
    //     }

    //     // Test Case 2: Too fast (blocks mined in half the expected time)
    //     {
    //         uint32 oneWeekLater = startTime + (TARGET_TIMESPAN / 2);

    //         vm.expectRevert(abi.encodeWithSignature("INVALID_DIFFICULTY_TARGET()"));
    //         _submitTestBlock(
    //             VALID_POW_HASH,
    //             oneWeekLater,
    //             INITIAL_BITS, // Should fail as difficulty needs to increase
    //             prevHash,
    //             1
    //         );
    //     }

    //     // Test Case 3: Too slow
    //     {
    //         uint32 fourWeeksLater = startTime + (TARGET_TIMESPAN * 2);

    //         vm.expectRevert(abi.encodeWithSignature("INVALID_DIFFICULTY_TARGET()"));
    //         _submitTestBlock(
    //             VALID_POW_HASH,
    //             fourWeeksLater,
    //             INITIAL_BITS, // Should fail as difficulty needs to decrease
    //             prevHash,
    //             1
    //         );
    //     }

    //     vm.stopPrank();
    // }

    // Helper function to submit blocks quickly
    function _submitTestBlock(bytes32 blockHash, uint32 timestamp, uint32 bits, bytes32 prevBlockHash, uint32 nonce)
        internal
    {
        lightClient.submitBlockHeader(
            blockHash,
            1, // version
            timestamp,
            bits,
            nonce,
            prevBlockHash,
            bytes32(0) // merkle root doesn't matter for this test
        );
    }

    // Helper function to create mock block headers
    function _createMockBlockHeader(
        uint32 version,
        bytes32 prevBlock,
        bytes32 merkleRoot,
        uint32 blockTimestamp,
        uint32 difficultyBits,
        uint32 nonce
    ) internal pure returns (bytes memory) {
        bytes memory header = new bytes(80);

        assembly {
            mstore(add(header, 32), version)
            mstore(add(header, 36), prevBlock)
            mstore(add(header, 68), merkleRoot)
            mstore(add(header, 100), blockTimestamp)
            mstore(add(header, 105), difficultyBits)
            mstore(add(header, 109), nonce)
        }

        return header;
    }
}
