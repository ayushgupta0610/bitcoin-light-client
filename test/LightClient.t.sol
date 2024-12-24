// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {LightClient} from "../src/LightClient.sol";

contract LightClientTest is Test {
    LightClient public lightClient;
    address blockSubmitter = makeAddr("blockSubmitter");

    // Test data - Bitcoin Mainnet block 00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04
    bytes constant VALID_BLOCK_HEADER =
        hex"000000020702eb8ad3b2dd0c05ad1beb1d4f09544d4f0f90c7797f000000000000000000f76e228faf0b52da9735d1254a89c612e2f98f96fa2e83e4009b557f99f6e2a3e1068d62ed3e031a10d7c659";
    bytes32 constant VALID_BLOCK_HASH = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
    bytes32 constant BLOCK_SUBMIT_ROLE = keccak256("BLOCK_SUBMIT_ROLE");

    function setUp() public {
        lightClient = new LightClient(blockSubmitter);
    }

    function testInitialState() public {
        assertEq(lightClient.chainTip(), lightClient.GENESIS_BLOCK());
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
        assertEq(header.version, 0x20000000);
        assertEq(header.height, 1);
        vm.stopPrank();
    }

    function testVerifyProofOfWork() public {
        // Test with real Bitcoin block data
        bytes32 blockHash = lightClient.getReversedBitcoinBlockHash(VALID_BLOCK_HEADER);
        uint256 difficultyBits = 0x1a031aed; // Example difficulty bits

        vm.startPrank(blockSubmitter);
        bool isValid = lightClient.verifyProofOfWork(blockHash, difficultyBits);
        assertTrue(isValid);
        vm.stopPrank();
    }

    function testExpandDifficultyBits() public view {
        uint256 bits = 0x1a031aed;
        uint256 target = lightClient.expandDifficultyBits(bits);
        assertTrue(target > 0);
    }

    function testReverseBytes32() public view {
        bytes32 original = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        bytes32 reversed = lightClient.reverseBytes32(original);
        assertNotEq(original, reversed);
        assertEq(lightClient.reverseBytes32(reversed), original);
    }

    function testVerifyTx() public {
        // Setup test data
        bytes32 txId = bytes32(uint256(1));
        bytes32[] memory proofs = new bytes32[](2);
        proofs[0] = bytes32(uint256(2));
        proofs[1] = bytes32(uint256(3));

        vm.startPrank(blockSubmitter);
        lightClient.submitRawBlockHeader(VALID_BLOCK_HEADER);
        bool isValid = lightClient.verifyTx(txId, proofs, VALID_BLOCK_HASH);
        vm.stopPrank();
    }

    function testCalculateMerkleRoot() public view {
        bytes32[] memory txids = new bytes32[](4);
        txids[0] = 0x876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c;
        txids[1] = 0xc40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff;
        txids[2] = 0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963;
        txids[3] = 0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9;

        bytes32 root = lightClient.calculateMerkleRoot(txids);
        assertTrue(root != bytes32(0));
    }

    function testDifficultyAdjustment() public {
        // Create a chain of 2016 blocks to test difficulty adjustment
        vm.startPrank(blockSubmitter);

        bytes memory header = VALID_BLOCK_HEADER;
        for (uint256 i = 0; i < 2016; i++) {
            // Modify header timestamp and nonce for each block
            header = _modifyBlockHeader(header, i);
            lightClient.submitRawBlockHeader(header);
        }

        vm.stopPrank();
    }

    function _modifyBlockHeader(bytes memory header, uint256 index) internal pure returns (bytes memory) {
        bytes memory modified = new bytes(80);
        for (uint256 i = 0; i < 80; i++) {
            if (i >= 68 && i < 72) {
                // Timestamp bytes
                modified[i] = bytes1(uint8(header[i]) + uint8(index & 0xFF));
            } else if (i >= 76 && i < 80) {
                // Nonce bytes
                modified[i] = bytes1(uint8(header[i]) + uint8(index & 0xFF));
            } else {
                modified[i] = header[i];
            }
        }
        return modified;
    }

    // Fuzz testing
    function testFuzz_SubmitBlockHeader(
        uint256 version,
        bytes32 prevBlock,
        bytes32 merkleRoot,
        uint256 timestamp,
        uint256 difficultyBits,
        uint256 nonce
    ) public {
        vm.assume(difficultyBits <= type(uint32).max);
        vm.assume(timestamp <= block.timestamp);
        vm.assume(version <= type(uint32).max);
        vm.assume(nonce <= type(uint32).max);

        vm.startPrank(blockSubmitter);
        lightClient.submitBlockHeader(bytes32(0), version, prevBlock, merkleRoot, timestamp, difficultyBits, nonce);
        vm.stopPrank();
    }
}
