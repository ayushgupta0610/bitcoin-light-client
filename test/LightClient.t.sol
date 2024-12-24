// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {LightClient} from "../src/LightClient.sol";

contract LightClientTest is Test {
    LightClient public lightClient;
    address blockSubmitter = makeAddr("blockSubmitter");

    // Test data - Bitcoin Mainnet block 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
    bytes constant VALID_BLOCK_HEADER =
        hex"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    bytes32 constant VALID_BLOCK_HASH = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
    bytes32 constant BLOCK_SUBMIT_ROLE = keccak256("BLOCK_SUBMIT_ROLE");

    function setUp() public {
        lightClient = new LightClient(blockSubmitter);
    }

    function testInitialState() public view {
        assertEq(lightClient.latestBlockHash(), lightClient.GENESIS_BLOCK());
        assertTrue(lightClient.hasRole(BLOCK_SUBMIT_ROLE, blockSubmitter));
    }

    function testSubmitRawBlockHeader_InvalidLength() public {
        bytes memory invalidHeader = hex"0000";
        vm.startPrank(blockSubmitter);
        vm.expectRevert(LightClient.INVALID_HEADER_LENGTH.selector);
        lightClient.submitRawBlockHeader(invalidHeader);
        vm.stopPrank();
    }

    function testSubmitRawBlockHeader_UnauthorizedSubmitter() public {
        address unauthorized = address(0x4321);
        vm.startPrank(unauthorized);
        vm.expectRevert();
        lightClient.submitRawBlockHeader(VALID_BLOCK_HEADER);
        vm.stopPrank();
    }

    function testSubmitBlockHeader_Success() public {
        vm.startPrank(blockSubmitter);
        lightClient.submitRawBlockHeader(VALID_BLOCK_HEADER);

        LightClient.BlockHeader memory header = lightClient.getBlockHeader(VALID_BLOCK_HASH);
        assertEq(header.version, 1);
        assertEq(header.prevBlock, 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f);
        assertEq(header.merkleRoot, 0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098);
        assertEq(header.timestamp, 1231469665);
        assertEq(header.difficultyBits, 486604799);
        assertEq(header.nonce, 2573394689);
        assertEq(header.height, 1);
        vm.stopPrank();
    }

    function testVerifyProofOfWork() public {
        // Test with real Bitcoin block data
        bytes32 blockHash = lightClient.getReversedBitcoinBlockHash(VALID_BLOCK_HEADER);
        uint256 difficultyBits = 0x1d00ffff; // Example difficulty bits

        vm.startPrank(blockSubmitter);
        bool isValid = lightClient.verifyProofOfWork(blockHash, difficultyBits);
        assertTrue(isValid);
        vm.stopPrank();
    }

    function testExpandDifficultyBitsOverflow() public {
        // Test known valid cases
        lightClient.expandDifficultyBits(0x1705dd01); // A normal difficulty target
        lightClient.expandDifficultyBits(0x1d00ffff); // Maximum difficulty bits

        // Test edge cases
        uint256 maxExp = 0xff; // Maximum possible exponent (8 bits)
        uint256 maxCoef = 0x00ffffff; // Maximum possible coefficient (24 bits)

        // This should revert due to overflow
        vm.expectRevert();
        lightClient.expandDifficultyBits((maxExp << 24) | maxCoef);
    }

    function testReverseBytes32() public view {
        bytes32 original = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        bytes32 reversed = lightClient.reverseBytes32(original);
        assertNotEq(original, reversed);
        assertEq(lightClient.reverseBytes32(reversed), original);
    }

    function testCalculateMerkleRoot() public view {
        bytes32[] memory txids = new bytes32[](4);
        txids[0] = 0x876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c;
        txids[1] = 0xc40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff;
        txids[2] = 0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963;
        txids[3] = 0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9;

        bytes32 root = lightClient.calculateMerkleRoot(txids);
        bytes32 PRECALCULATED_MERKLE_ROOT = 0x6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3; // (Natural byte order)
        assertTrue(root == PRECALCULATED_MERKLE_ROOT);
    }
}
