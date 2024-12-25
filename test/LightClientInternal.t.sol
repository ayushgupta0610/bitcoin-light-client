// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {LightClient} from "../src/LightClient.sol";

contract ExposedLightClient is LightClient {
    constructor(address blockSubmitter) LightClient(blockSubmitter) {}

    function exposed_verifyProofOfWork(bytes32 blockHash, uint32 difficultyBits) public pure returns (bool) {
        return verifyProofOfWork(blockHash, difficultyBits);
    }

    function exposed_expandDifficultyBits(uint32 bits) public pure returns (uint256) {
        return expandDifficultyBits(bits);
    }

    function exposed_hashPair(bytes32 a, bytes32 b) public view returns (bytes32) {
        return hashPair(a, b);
    }
}

contract LightClientInternalTest is Test {
    ExposedLightClient public lightClient;
    address blockSubmitter;

    function setUp() public {
        blockSubmitter = address(0x1234);
        lightClient = new ExposedLightClient(blockSubmitter);
    }

    function testInternalVerifyProofOfWork() public view {
        bytes32 blockHash = bytes32(uint256(1));
        uint32 difficultyBits = 0x1d00ffff;
        bool result = lightClient.exposed_verifyProofOfWork(blockHash, difficultyBits);
        assertTrue(result);
    }

    function testInternalExpandDifficultyBits() public view {
        uint32 bits = 0x1d00ffff;
        uint256 target = lightClient.exposed_expandDifficultyBits(bits);
        assertTrue(target > 0);
    }

    function testInternalHashPair() public view {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        bytes32 hash = lightClient.exposed_hashPair(a, b);
        assertTrue(hash != bytes32(0));
    }
}
