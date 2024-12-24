// script/DeployLightClient.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {LightClient} from "../src/LightClient.sol";

contract DeployLightClient is Script {
    function run() external {
        // Start the broadcast to deploy the contract
        vm.startBroadcast();

        // Set the default account as the block submitter
        address blockSubmitter = msg.sender;

        // Deploy the LightClient contract
        LightClient lightClient = new LightClient(blockSubmitter);

        // Log the deployed contract address
        console.log("LightClient deployed to:", address(lightClient));

        // Stop the broadcast
        vm.stopBroadcast();
    }
}
