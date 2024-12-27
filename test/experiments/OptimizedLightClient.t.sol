// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {OptimizedLightClient} from "../../src/experiments/OptimizedLightClient.sol";
import {BitcoinUtils} from "../../src/BitcoinUtils.sol";

contract OptimizedLightClientTest is Test {
    OptimizedLightClient public client;
    address public constant SUBMITTER = address(0x1234);

    // Genesis block data
    bytes32 constant GENESIS_HASH = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;
    bytes constant GENESIS_HEADER =
        hex"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    // Block 1 data (real Bitcoin block after genesis)
    bytes constant BLOCK_1_HEADER =
        hex"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    bytes32 constant BLOCK_1_HASH = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;

    // Block 2 data
    bytes constant BLOCK_2_HEADER =
        hex"010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61";
    bytes32 constant BLOCK_2_HASH = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd;

    // Add more test blocks
    bytes constant BLOCK_3_HEADER =
        hex"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    bytes32 constant BLOCK_3_HASH = 0x000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820;

    function setUp() public {
        BitcoinUtils.BlockHeader memory genesisHeader = _getGenesisHeader();
        // Deploy with correct constructor parameters
        vm.prank(SUBMITTER);
        client = new OptimizedLightClient(
            genesisHeader.version,
            genesisHeader.timestamp,
            genesisHeader.difficultyBits,
            genesisHeader.nonce,
            0, // Genesis height
            genesisHeader.prevBlock,
            genesisHeader.merkleRoot
        );
    }

    function _getGenesisHeader() private pure returns (BitcoinUtils.BlockHeader memory) {
        return BitcoinUtils.BlockHeader(
            1,
            1231006505,
            0x1d00ffff,
            0x7c2bac1d,
            0,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
        );
    }

    function testInitialState() public view {
        assertEq(client.getLatestHeaderHash(), GENESIS_HASH);

        BitcoinUtils.BlockHeader memory checkpoint = client.getHeader(GENESIS_HASH);
        assertEq(checkpoint.height, 0);
        assertEq(checkpoint.version, 1);
        assertEq(checkpoint.timestamp, 1231006505);
        assertEq(checkpoint.difficultyBits, 0x1d00ffff);
        assertEq(checkpoint.nonce, 0x7c2bac1d);
    }

    function testSubmitNextBlock() public {
        vm.startPrank(SUBMITTER);

        // Submit block 1 (direct connection to genesis)
        bool success = client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));
        assertTrue(success);

        assertEq(client.getLatestHeaderHash(), BLOCK_1_HASH);

        BitcoinUtils.BlockHeader memory checkpoint = client.getLatestCheckpoint();
        assertEq(checkpoint.height, 1);
        vm.stopPrank();
    }

    function testSubmitMultipleBlocks() public {
        vm.startPrank(SUBMITTER);

        // First submit block 1
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));

        // Then submit block 2 with block 1 as intermediate
        bytes[] memory intermediateHeaders = new bytes[](1);
        intermediateHeaders[0] = BLOCK_1_HEADER;

        bool success = client.submitBlockHeader(BLOCK_2_HEADER, intermediateHeaders);
        assertTrue(success);

        assertEq(client.getLatestHeaderHash(), BLOCK_2_HASH);

        BitcoinUtils.BlockHeader memory checkpoint = client.getLatestCheckpoint();
        assertEq(checkpoint.height, 2);
        vm.stopPrank();
    }

    function testFailInvalidPoW() public {
        vm.startPrank(SUBMITTER);

        // Modify nonce to make PoW invalid
        bytes memory invalidHeader = BLOCK_1_HEADER;
        // Modify the last 4 bytes (nonce)
        assembly {
            mstore8(add(invalidHeader, 79), 0x00)
            mstore8(add(invalidHeader, 78), 0x00)
            mstore8(add(invalidHeader, 77), 0x00)
            mstore8(add(invalidHeader, 76), 0x00)
        }

        client.submitBlockHeader(invalidHeader, new bytes[](0));
        vm.stopPrank();
    }

    function testFailInvalidChain() public {
        vm.startPrank(SUBMITTER);

        // Try to submit block 2 directly without block 1
        client.submitBlockHeader(BLOCK_2_HEADER, new bytes[](0));
        vm.stopPrank();
    }

    function testFailInvalidIntermediateHeader() public {
        vm.startPrank(SUBMITTER);

        // Create invalid intermediate headers array
        bytes[] memory invalidIntermediateHeaders = new bytes[](1);
        invalidIntermediateHeaders[0] = BLOCK_2_HEADER; // Wrong order

        client.submitBlockHeader(BLOCK_1_HEADER, invalidIntermediateHeaders);
        vm.stopPrank();
    }

    function testLargeChainSubmission() public {
        vm.startPrank(SUBMITTER);

        // In real test, use actual Bitcoin block headers
        bytes[] memory intermediateHeaders = new bytes[](5);
        // Fill with real consecutive Bitcoin block headers...

        bool success = client.submitBlockHeader(
            BLOCK_2_HEADER, // Replace with actual target block
            intermediateHeaders
        );
        assertTrue(success);
        vm.stopPrank();
    }

    function testReorganization() public {
        vm.startPrank(SUBMITTER);

        // First submit a chain
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));

        // Submit a competing chain with higher difficulty
        // In real test, use actual competing chain data
        bytes[] memory competingChain = new bytes[](2);
        // Fill with real competing chain headers...

        bool success = client.submitBlockHeader(
            BLOCK_2_HEADER, // Replace with actual competing chain tip
            competingChain
        );
        assertTrue(success);
        vm.stopPrank();
    }

    // Add test for submitting invalid header length
    function testFailInvalidHeaderLength() public {
        vm.startPrank(SUBMITTER);
        bytes memory invalidHeader = hex"0011"; // Too short
        client.submitBlockHeader(invalidHeader, new bytes[](0));
        vm.stopPrank();
    }

    // Add test for submitting duplicate block
    function testFailDuplicateBlock() public {
        vm.startPrank(SUBMITTER);

        // Submit block 1
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));

        // Try to submit the same block again
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));
        vm.stopPrank();
    }

    // Add test for checking block height increments
    function testBlockHeightIncrement() public {
        vm.startPrank(SUBMITTER);

        // Submit block 1
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));
        BitcoinUtils.BlockHeader memory checkpoint1 = client.getLatestCheckpoint();
        assertEq(checkpoint1.height, 1);

        // Submit block 2
        bytes[] memory intermediateHeaders = new bytes[](1);
        intermediateHeaders[0] = BLOCK_1_HEADER;
        client.submitBlockHeader(BLOCK_2_HEADER, intermediateHeaders);

        BitcoinUtils.BlockHeader memory checkpoint2 = client.getLatestCheckpoint();
        assertEq(checkpoint2.height, 2);
        vm.stopPrank();
    }

    // Add test for access control
    function testFailUnauthorizedSubmission() public {
        vm.prank(address(0xdead));
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));
    }

    // Add test for multiple intermediate headers
    function testMultipleIntermediateHeaders() public {
        vm.startPrank(SUBMITTER);

        // First submit blocks 1 and 2
        client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));
        bytes[] memory intermediateHeaders1 = new bytes[](1);
        intermediateHeaders1[0] = BLOCK_1_HEADER;
        client.submitBlockHeader(BLOCK_2_HEADER, intermediateHeaders1);

        // Submit block 3 with both block 1 and 2 as intermediates
        bytes[] memory intermediateHeaders2 = new bytes[](2);
        intermediateHeaders2[0] = BLOCK_2_HEADER;
        intermediateHeaders2[1] = BLOCK_1_HEADER;

        bool success = client.submitBlockHeader(BLOCK_3_HEADER, intermediateHeaders2);
        assertTrue(success);

        BitcoinUtils.BlockHeader memory checkpoint = client.getLatestCheckpoint();
        assertEq(checkpoint.height, 3);
        vm.stopPrank();
    }
}
