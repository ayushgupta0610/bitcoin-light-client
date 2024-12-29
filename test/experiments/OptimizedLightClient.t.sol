// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {OptimizedLightClient} from "../../src/experiments/OptimizedLightClient.sol";
import {BitcoinUtils} from "../../src/BitcoinUtils.sol";

contract OptimizedLightClientTest is Test {
    OptimizedLightClient public client;
    address public constant SUBMITTER = address(0x1234);

    // Initial block data
    bytes32 constant INITIAL_HASH = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;
    bytes constant INITIAL_HEADER =
        hex"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    // Block 1 data (real Bitcoin block after initial)
    bytes constant BLOCK_1_HEADER =
        hex"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
    bytes32 constant BLOCK_1_HASH = 0x00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;

    // Block 2 data
    bytes constant BLOCK_2_HEADER =
        hex"010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61";
    bytes32 constant BLOCK_2_HASH = 0x000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd;

    // Block 10 data (real Bitcoin block after initial)
    bytes constant BLOCK_10_HEADER =
        hex"010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565";
    bytes32 constant BLOCK_10_HASH = 0x000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9;

    // Block 11 data (real Bitcoin block after initial)
    bytes constant BLOCK_11_HEADER =
        hex"01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8";
    bytes32 constant BLOCK_11_HASH = 0x0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073;

    // Block 12 data (real Bitcoin block after initial)
    bytes constant BLOCK_12_HEADER =
        hex"010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c";
    bytes32 constant BLOCK_12_HASH = 0x0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e;

    // Block 12 data (real Bitcoin block after initial)
    bytes constant BLOCK_109_HEADER =
        hex"01000000cf247ab093cae5a6698f9f3fa5e9bd885ef6589f2e5e5cdd9dd6af420000000030b2b4faab68a1669e4eda67442919f25561f8df26237de4760425433f7f00a33ec26949ffff001d359e2d4e";
    bytes32 constant BLOCK_109_HASH = 0x000000003f5dccc4e0bdac7081755b9d9ee17e7737316202b900d1c567c5abae;

    function setUp() public {
        BitcoinUtils.BlockHeader memory initialHeader = _getInitialHeader();
        // Deploy with correct constructor parameters
        vm.prank(SUBMITTER);
        client = new OptimizedLightClient(
            initialHeader.version,
            initialHeader.timestamp,
            initialHeader.difficultyBits,
            initialHeader.nonce,
            initialHeader.height,
            initialHeader.prevBlock,
            initialHeader.merkleRoot
        );
    }

    function _getInitialHeader() private pure returns (BitcoinUtils.BlockHeader memory) {
        return BitcoinUtils.BlockHeader(
            1,
            1231473952,
            486604799,
            1709518110,
            10,
            0x000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805,
            0xd3ad39fa52a89997ac7381c95eeffeaf40b66af7a57e9eba144be0a175a12b11
        );
    }

    function testInitialState() public view {
        assertEq(client.getLatestHeaderHash(), BLOCK_10_HASH);

        BitcoinUtils.BlockHeader memory checkpoint = client.getHeader(BLOCK_10_HASH);
        assertEq(checkpoint.height, 10);
        assertEq(checkpoint.version, 1);
        assertEq(checkpoint.timestamp, 1231473952);
        assertEq(checkpoint.difficultyBits, 486604799);
        assertEq(checkpoint.nonce, 1709518110);
    }

    function testSubmitNextBlock() public {
        vm.startPrank(SUBMITTER);

        // Submit block 11 (direct connection to initial)
        bool success = client.submitBlockHeader(BLOCK_11_HEADER, new bytes[](0));
        assertTrue(success);

        assertEq(client.getLatestHeaderHash(), BLOCK_11_HASH);

        BitcoinUtils.BlockHeader memory checkpoint = client.getLatestCheckpoint();
        assertEq(checkpoint.height, 11);
        vm.stopPrank();
    }

    // function testSubmitMultipleBlocks() public {
    //     vm.startPrank(SUBMITTER);

    //     // First submit block 1
    //     client.submitBlockHeader(BLOCK_1_HEADER, new bytes[](0));

    //     // Then submit block 2 with block 1 as intermediate
    //     bytes[] memory intermediateHeaders = new bytes[](1);
    //     intermediateHeaders[0] = BLOCK_1_HEADER;

    //     bool success = client.submitBlockHeader(BLOCK_2_HEADER, intermediateHeaders);
    //     assertTrue(success);

    //     assertEq(client.getLatestHeaderHash(), BLOCK_2_HASH);

    //     BitcoinUtils.BlockHeader memory checkpoint = client.getLatestCheckpoint();
    //     assertEq(checkpoint.height, 2);
    //     vm.stopPrank();
    // }

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

    // TODO: See how the reoorg can be handled best
    function testReorganization() public {
        vm.startPrank(SUBMITTER);

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
    function testSubmitWithIntermediateBlock() public {
        vm.startPrank(SUBMITTER);

        // Submit block 11
        // client.submitBlockHeader(BLOCK_11_HEADER, new bytes[](0));
        // BitcoinUtils.BlockHeader memory checkpoint1 = client.getLatestCheckpoint();
        // assertEq(checkpoint1.height, 11);

        // Submit block 12
        bytes[] memory intermediateHeaders = new bytes[](1);
        intermediateHeaders[0] = BLOCK_11_HEADER;
        client.submitBlockHeader(BLOCK_12_HEADER, intermediateHeaders);

        BitcoinUtils.BlockHeader memory checkpoint2 = client.getLatestCheckpoint();
        assertEq(checkpoint2.height, 12);
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

        bytes[] memory intermediateHeaders = new bytes[](98);
        intermediateHeaders[0] =
            hex"01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8";
        intermediateHeaders[1] =
            hex"010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c";
        intermediateHeaders[2] =
            hex"010000005e2b8043bd9f8db558c284e00ea24f78879736f4acd110258e48c2270000000071b22998921efddf90c75ac3151cacee8f8084d3e9cb64332427ec04c7d562994cd16649ffff001d37d1ae86";
        intermediateHeaders[3] =
            hex"0100000089304d4ba5542a22fb616d1ca019e94222ee45c1ad95a83120de515c00000000560164b8bad7675061aa0f43ced718884bdd8528cae07f24c58bb69592d8afe185d36649ffff001d29cbad24";
        intermediateHeaders[4] =
            hex"01000000378a6f6593e2f0251132d96616e837eb6999bca963f6675a0c7af180000000000d080260d107d269ccba9247cfc64c952f1d13514b49e9f1230b3a197a8b7450fa276849ffff001d38d8fb98";

        // Update indices 5-97 (previously all were index 2)
        intermediateHeaders[5] =
            hex"010000007384231257343f2fa3c55ee69ea9e676a709a06dcfd2f73e8c2c32b300000000442ee91b2b999fb15d61f6a88ecf2988e9c8ed48f002476128e670d3dac19fe706286849ffff001d049e12d6";
        intermediateHeaders[6] =
            hex"01000000f5c46c41c30df6aaff3ae9f74da83e4b1cffdec89c009b39bb254a17000000005d6291c35a88fd9a3aef5843124400936fbf2c9166314addcaf5678e55b7e0a30f2c6849ffff001d07608493";
        intermediateHeaders[7] =
            hex"0100000009f8fd6ba6f0b6d5c207e8fcbcf50f46876a5deffbac4701d7d0f13f0000000023ca63b851cadfd7099ae68eb22147d09394adb72a78e86b69c42deb6df225f92e2e6849ffff001d323741f2";
        intermediateHeaders[8] =
            hex"01000000161126f0d39ec082e51bbd29a1a816984f6298fdb5ccc3f606d5655600000000201e1ad44f0ae957771d2e60fa252594e7fcc75a51db4cdfb5fbaeb38612390490d96849ffff001d06216771";
        intermediateHeaders[9] =
            hex"01000000aa698b967619b95c9181ebd256700651aaa1255fe503f59b391ff0b2000000005a8da000e1a2258630dd6f0286ddc24b7b0ef897f3447138c9a3ccb8b36cfa9e47dc6849ffff001d07e8fbd1";
        intermediateHeaders[10] =
            hex"010000008b52bbd72c2f49569059f559c1b1794de5192e4f7d6d2b03c7482bad0000000083e4f8a9d502ed0c419075c1abb5d56f878a2e9079e5612bfb76a2dc37d9c42741dd6849ffff001d2b909dd6";
        intermediateHeaders[11] =
            hex"01000000f528fac1bcb685d0cd6c792320af0300a5ce15d687c7149548904e31000000004e8985a786d864f21e9cbb7cbdf4bc9265fe681b7a0893ac55a8e919ce035c2f85de6849ffff001d385ccb7c";
        intermediateHeaders[12] =
            hex"0100000050e593d3b22034cfc9884df842e85d398b5c3cfd77b1aa2a86f221ac000000005fafe0e1824bb9995f12eeb4183eaa1fde889f4590191cd63a92a61a1eee9a43f9e16849ffff001d30339e19";
        intermediateHeaders[13] =
            hex"01000000f8000cd0261cdcd7215149ff2f0090c93b0857f0f720d0e8cdee782900000000d9a6665d16cf43ec412e38aef57098c9b5ff613bfefc1ceaa1781e5f087897f6bce46849ffff001d21be2da5";
        intermediateHeaders[14] =
            hex"01000000bb36b800114609bfdd0019c02a411702d019a837402f1d466e00899100000000fa2fb24edda69806924fe1ef06bd073264d8b32f55eeaacab45a156563d0d4dd91e76849ffff001d0195ec60";
        intermediateHeaders[15] =
            hex"010000008ec0e98eaa3378c803880364eb6d696974772bf8d9a9e3a229f4d50200000000f6ef70bb4846dffdefb6daa75c87d7021f01d7ed0590fb9d040993609c9c7bd1d8eb6849ffff001d20e842b0";
        intermediateHeaders[16] =
            hex"01000000817ac590d6cd50e70cf710266e33382088e111e774a86af831455c1a000000008a15f1ddaef05f8acb0db86b2f4534f68d417f05de65a64073c3d0b7e0eded32d4ec6849ffff001d1b6910e0";
        intermediateHeaders[17] =
            hex"01000000896e8271cf721a5db7b1dbae43b40eac2a7b0247870b06f47802968800000000595badffff2bb1453255880ba0f33d7be62a2f55b6f266bc26869d2715974c196aef6849ffff001d2c5bb2b3";
        intermediateHeaders[18] =
            hex"01000000008de6ae7a37b4f26a763f4d65c5bc7feb1ad9e3ce0fff4190c067f0000000000913281db730c5cff987146330508c88cc3e642d1b9f5154854764fd547e0a54eaf26849ffff001d2e4a4c3d";
        intermediateHeaders[19] =
            hex"0100000033aa0fa26441ead7005df4b0ad2e61405e80cb805e3c657f194df3260000000021184d335529aae22259315be42915b0360deeae97ec428a654014a3d2899ca00ff66849ffff001d0948811f";
        intermediateHeaders[20] =
            hex"01000000632dfba41dda58eec7b6db8f75b25a69a38829915c82e6d1001e511c000000004f08f5265053c96c4eb51eac4ad3f5c668323f4b630af32a66915eeee678f9b36bf96849ffff001d399f07f1";
        intermediateHeaders[21] =
            hex"01000000b5969273528cd8cee5b13a095762d731d9c5e30a21b4713ef255c6d600000000f54667bee8511d31bb173bcc6f15b0bf3dc42788a813439bfea9065f90586f3ca6fc6849ffff001d2c950522";
        intermediateHeaders[22] =
            hex"0100000005ba6ff20c063f7f23b49c53d7004941241eb5347616f406333fdefc00000000b57076c0e5f498a6f06ef26c72e224cd7e25784ed6cd569e570988d5e59bdcd36afd6849ffff001d2edcf3b7";
        intermediateHeaders[23] =
            hex"010000005b74dda1cc03078d30fe49722218667eb31524f22c59687ac30fe04e00000000ede29e76449491b0e2b766dc213c0e15bd7ab6eae48a7cb399c22a48621c5219cd016949ffff001d1b8557c3";
        intermediateHeaders[24] =
            hex"0100000083527a686e27387544d284257d9238c5fe3d50fc9e6ceb5b8d8b4346000000000201df27519bd574817d5449758f744e42d648415d1370b17ac6448b6ccc9cfe20036949ffff001d05727a3e";
        intermediateHeaders[25] =
            hex"01000000c0d1e5e651f40fd9b0a4fe024b79f15fa65f1d85bbf265582ccf93f0000000002837870b786929d9e30d651dcda7c3006a04b79d292261031a4235328b0f0fbc5c066949ffff001d1c00dd1d";
        intermediateHeaders[26] =
            hex"01000000917354007e87c5ea0a1bea34d5275718a40d082bdd28717d7075f34f00000000e43721163a2bdbc80493a9e0b65d20b1ce63ec4c5ffadc39ea01e13d4e053596d4096949ffff001d1e2f1812";
        intermediateHeaders[27] =
            hex"01000000f12ee37c151ee80a22be4f6ff155646addc588cf604e3cf354dfb4750000000095ca77f0c5dfd190be1eab32399d93555666cdadb8f44eb0636a608414b10d3c400b6949ffff001d160ab450";
        intermediateHeaders[28] =
            hex"010000004aa5ae0b1842e2daa39a019e1a6cfad2306aae707b035f3ee571710f000000002d00540fb7aa5cf6fefc567912eeef891a19ac2f9fc055eafd229b1a73e1a182470f6949ffff001d02956322";
        intermediateHeaders[29] =
            hex"01000000df2c4d42797dd61991b8df3033716f364b33f87a7cbd3494b8587ac400000000e1fe31bd4e94cd3a004849125ac5951703d34b33f3a90ca1ddc67ae4f8ed6eae2d116949ffff001d37466753";
        intermediateHeaders[30] =
            hex"01000000c49052b367c9cfc10792aac007acdf986aa1e60fdbb87193cbd6732900000000eea3f31766c62e47ca1e9ccd303e37404887a570375079fa030b3e036ce71c7038146949ffff001d0552ee6b";
        intermediateHeaders[31] =
            hex"010000002aa08c1efce70618d7370e0383a0b5801cafc5ecdc8108e34d93fe42000000004f0c28db6791823456c979edc21f8e9615a037c410299a745f2e7af03cf33107c8166949ffff001d22e2cd27";
        intermediateHeaders[32] =
            hex"010000008e6285267ce431a52e3ef3c46eefc4a144f51195f3bf8489c891ffeb00000000a4d66fc5b10430fcfd14558e63d19b649a61ee95b71b1bcce948b1d53583dbebab176949ffff001d4f7aef04";
        intermediateHeaders[33] =
            hex"0100000066184d75b89754b5363036a66b0aa70142ae537e9c2a64c5175f97310000000049935f8c517625d3560f23a3cdf82fef68779c99f4a92931c91d8c11517c5cf137196949ffff001d2dc932c1";
        intermediateHeaders[34] =
            hex"010000005002c9b34042ac70ac8e36b1840672d69cb0ba6ada5effb6477de4aa00000000743a0389e4d8c9f60ad41025b797fd25e228123c4b54b5df20ed02ca97781df03c1b6949ffff001d21537e7a";
        intermediateHeaders[35] =
            hex"010000000d765e68e3487bd6d3372dd9eeca050857cf6c9bdb171fcdbe34d363000000001567e4c48479995636794ce5ec794eb145c1194478f45bb0a45cc11d8cc27fb1581f6949ffff001d28d2dbc1";
        intermediateHeaders[36] =
            hex"010000002bf72d8a5d6ea0889a5b52e19f53268423d644d3d61364174b859ccd00000000be23d982899e45eb4f5095cbc1c43ddc9495e93fd1e4f0bb3a20fd461412c5bd7a216949ffff001d14fc8df0";
        intermediateHeaders[37] =
            hex"010000004c812cdb1077ddb53fa3da180758d29b49262cc37eeaf9ef74a8afbf000000000743ebb1940fb72a15cebc9dbe481ea7625c70790a56bedfb7d74e0ba8227880e3226949ffff001d182b34b3";
        intermediateHeaders[38] =
            hex"0100000039e975250e63187ecb299082518f8da887198ea2b0834a1089cdacdd00000000b87adb107589f869ca344a457dec051371352b2f38be825d914139b568305faa7e256949ffff001d3a42e6fa";
        intermediateHeaders[39] =
            hex"01000000cce04fcc1138bafcf657f97e31c30705b991827071233deb2eae63ba00000000cb9f33326bbf60634a0634c3bce1c4a7e43ac4bd3fe54a654ae35be3f6ac83fdab286949ffff001d2654f246";
        intermediateHeaders[40] =
            hex"010000005714bd772bcbdb97a08d32cc82469cadbf7feb69bb4131a993bc7c7f00000000e19a9f3635b503e037212f13f6dd2b40a6b2d81379b9b341df3e33c14c22a3de8a2b6949ffff001d089368dd";
        intermediateHeaders[41] =
            hex"010000007a127b3a7af982beab22647b6456c8cbe6dc43a290c65d87b2abc08200000000b4ff4753f29de2ec4aefcccbb72b113f820894587fb3b7e0218ca6cb648cb441d02f6949ffff001d39a360d5";
        intermediateHeaders[42] =
            hex"010000005df242b278026fcf51ac4ba5cf5b590e58c2d1d76b2c09b25c52c98e00000000d6be02040ee5f8e52f2e925e6f70c73196064f99f20090bc73ea71516c5472d455336949ffff001d295b06ea";
        intermediateHeaders[43] =
            hex"0100000056d42459d4e316593155b4fad15dd700b93e9d2eb9999490d49e98ec0000000048b6a7bcf2a59e336da83ee70ddd230fc7e2db16c3c2654494c5502dac012538ce356949ffff001d23c2373b";
        intermediateHeaders[44] =
            hex"010000004ee5095194d71ca1b345ee9f27dbb6815ce4d5df9dc2c3c91ba364be0000000026366720a786e6615b3203909f8df77fc2e96d1afe593bd3d9623d19c481c947aa386949ffff001d1e6cbbe9";
        intermediateHeaders[45] =
            hex"010000005878d514861163b782b54b2d4c6f6bbdaf22e41c2401e9f84522515a000000000e7dcba835e4c20485b614f252183b53921a8901049ea6ef22f09a42195601b5203b6949ffff001d22c63213";
        intermediateHeaders[46] =
            hex"01000000ef06fa30dd7275529ae9d2677998c4d507a07517d28b23e6e08ed2e7000000004ca77b8b243eee32a9b06a8bea33abd5cf517bf68eed73e7fa951f4f30d2a17ec6446949ffff001de4acd41c";
        intermediateHeaders[47] =
            hex"010000002f8b9d4d8ea162a1d2e5fe288b110bf80a92b963b2d30f40956c88a2000000002518bddd47990bc127da5579b114cc3976568c7d0fc8f5b7a4b90478076799fba76b6949ffff001d397d4eb2";
        intermediateHeaders[48] =
            hex"010000002100cacac549da7d2a879cfbefc18cac6fbb9931d7da48c3e818e38600000000c654ae2f49a83f60d62dfafca02a221c9cb45ad96a5cb1539b22077bfa87d25e7d6d6949ffff001d32d01813";
        intermediateHeaders[49] =
            hex"010000008fd40a92b8965c798cf25dcdd8395de4ef75f206337de4985a3262be0000000099add42809e35d9c89641de1e9497db2e70bbb283e9b9492599f879533654c5cf86e6949ffff001d30177cef";
        intermediateHeaders[50] =
            hex"0100000086cff19f969df7040f27de690e7355436001cb3e361e7589526a077d00000000be4544845044c67df65f37d0ba8bb323fe457c141abe38eecdc2e530144bfb8103736949ffff001d31852f96";
        intermediateHeaders[51] =
            hex"0100000053514b63574bf6c65d576578f6cb2ad0f6256de1454211ddfa2222160000000073cad1e2d193f0d27471b13eb4b1f356aa63de8dc78a58a9128a2115c6eb1e5647776949ffff001d140de59c";
        intermediateHeaders[52] =
            hex"010000002b120517ca99a3d8361c2a9eef3126fff7c18e3ec365dc2201c315ca000000001d2e4b642f3d14c24f57f237d38acb8e4939855a8ca6ce7dab48e2cd85843d9ad97a6949ffff001d1622692a";
        intermediateHeaders[53] =
            hex"010000004f8dceb614b17b5ac9c9368906ffb338aeb750a1dfe1adaa67eef59500000000b45cf14a7caeeb5fcb286d314ac2fa85f58df3d5156fa95c832f373930de9bc3b37e6949ffff001d36e9e4e2";
        intermediateHeaders[54] =
            hex"01000000d143e6eb3910c5e54f55655e885727810105c04754ae1edeb349992100000000fc2bd82cfc026bb9594f5e92e7aae7f0c5750e6e7d8dd73812bc1fff792d2712aa806949ffff001d1d5b20d8";
        intermediateHeaders[55] =
            hex"0100000053fb045b4d3ca149faca8e7ea53cdb3168bc58b875e47196b3a6b3f100000000406468307c915485a9c9eabe31cc853e68311176e07e71475c3e26888fb7b7ed30846949ffff001d2b740f74";
        intermediateHeaders[56] =
            hex"010000003ce6c27ae14022e4b6ea0a5c3633d156e3e3a47509c1adf085371ba300000000f01258747019514aa5c475cddd59a309347280ead98d19d8df8f9f99eb56757938866949ffff001d25d3778f";
        intermediateHeaders[57] =
            hex"01000000cae10bd8c753c43529191bc15f2956f96c3c2e9498b3ee8dd506a42100000000d8855c4002ac58a052b1ad12af7179fecf988893093528f2a457beb5fb6b715fe1986949ffff001d275a6678";
        intermediateHeaders[58] =
            hex"01000000063f92bbe049395e3bb6d865a6de0a5b26f4b6b01e90f4bfce381bc20000000090162a9c64459060f320a51253378106c6472a23a9dcd90588f0cc09d00d4dcc549c6949ffff001d212e6768";
        intermediateHeaders[59] =
            hex"01000000cc91c80800b3a75d6542b82bc6d8d7024551f9bfb041ee1b0bb8ca0e00000000668b636991dd0638ddb442ee2b10e3184d87e2d059a43076e10512af8814d3d07da06949ffff001d32db67ca";
        intermediateHeaders[60] =
            hex"010000009918d5221408b7a4325c754792ccad2b13e22e9f30dfcc0d965eeda80000000069a57920735cf77470917d6ddb01a83fe26fd9bcd71a360443c08d4d2d59a43372a46949ffff001d31070a95";
        intermediateHeaders[61] =
            hex"0100000095194b8567fe2e8bbda931afd01a7acd399b9325cb54683e64129bcd00000000660802c98f18fd34fd16d61c63cf447568370124ac5f3be626c2e1c3c9f0052d19a76949ffff001d33f3c25d";
        intermediateHeaders[62] =
            hex"010000009a22db7fd25e719abf9e8ccf869fbbc1e22fa71822a37efae054c17b00000000f7a5d0816883ec2f4d237082b47b4d3a6a26549d65ac50d8527b67ab4cb7e6cfadaa6949ffff001d15fa87f6";
        intermediateHeaders[63] =
            hex"0100000084999d1fa0ae9b7eb8b75fa8ad765c6d467a6117015860dce4d89bb600000000ceefaf23adb1009753545c230a374c48851676ccb7d6f004b66dd302ceb5443b4eae6949ffff001d192e9d71";
        intermediateHeaders[64] =
            hex"01000000192f62105285f84e7876b764dde15cc96e3689ccd39ff1131f18041600000000f38b91a939e7f81483f88ffcf3da8607fd928a093746a03b5eb4964ae0a4d2886bb16949ffff001d1541834f";
        intermediateHeaders[65] =
            hex"01000000753fbb8b0a766119fe8e9347b55cf6f977bc961d7dff46b87c050921000000004bb7d646fe8e6678ab8829cc899a89f256b6cf19dbddd494a773b057c374002489b36949ffff001d1766221f";
        intermediateHeaders[66] =
            hex"010000005bbeaaef7d3123d7367e9d68978f0cf8225a2815b3024e0125ef11fb00000000c87ac7e967e3b09e53e4bb31d4d9306465bd8500061c1819b15d451b46bdc95bb7b56949ffff001d2ac2b510";
        intermediateHeaders[67] =
            hex"01000000aeb1c63f4aab6eb66f12f3c64949f43a4bbd1d13ffe777c3015c4d850000000080ee9dbb0f58c4e12269383c9735abb1c6f03065f40d5238ec6c3e5fec3a88189db96949ffff001d00002aa0";
        intermediateHeaders[68] =
            hex"0100000014770aa562d6a32431289058ac1bcfafec815bee4bd2e7eb15197c870000000082232ac15c8d8642df8827fe5e3a297a758447f00c1ee9e51b2e578b22c5e5976dbc6949ffff001d2c5b65bf";
        intermediateHeaders[69] =
            hex"01000000ebf2a13396772607b579e5313855d85deb6c2ff5eb4b896d17b0167e0000000002946a80f855fa6e59264de3b84da0ce975ab6d0806a90288bb2cb7f4e782b2016c06949ffff001d049add3f";
        intermediateHeaders[70] =
            hex"01000000917354007e87c5ea0a1bea34d5275718a40d082bdd28717d7075f34f00000000e43721163a2bdbc80493a9e0b65d20b1ce63ec4c5ffadc39ea01e13d4e053596d4096949ffff001d1e2f1812";
        intermediateHeaders[71] =
            hex"01000000f12ee37c151ee80a22be4f6ff155646addc588cf604e3cf354dfb4750000000095ca77f0c5dfd190be1eab32399d93555666cdadb8f44eb0636a608414b10d3c400b6949ffff001d160ab450";
        intermediateHeaders[72] =
            hex"010000004aa5ae0b1842e2daa39a019e1a6cfad2306aae707b035f3ee571710f000000002d00540fb7aa5cf6fefc567912eeef891a19ac2f9fc055eafd229b1a73e1a182470f6949ffff001d02956322";
        intermediateHeaders[73] =
            hex"01000000df2c4d42797dd61991b8df3033716f364b33f87a7cbd3494b8587ac400000000e1fe31bd4e94cd3a004849125ac5951703d34b33f3a90ca1ddc67ae4f8ed6eae2d116949ffff001d37466753";
        intermediateHeaders[74] =
            hex"01000000c49052b367c9cfc10792aac007acdf986aa1e60fdbb87193cbd6732900000000eea3f31766c62e47ca1e9ccd303e37404887a570375079fa030b3e036ce71c7038146949ffff001d0552ee6b";
        intermediateHeaders[75] =
            hex"010000002aa08c1efce70618d7370e0383a0b5801cafc5ecdc8108e34d93fe42000000004f0c28db6791823456c979edc21f8e9615a037c410299a745f2e7af03cf33107c8166949ffff001d22e2cd27";
        intermediateHeaders[76] =
            hex"010000008e6285267ce431a52e3ef3c46eefc4a144f51195f3bf8489c891ffeb00000000a4d66fc5b10430fcfd14558e63d19b649a61ee95b71b1bcce948b1d53583dbebab176949ffff001d4f7aef04";
        intermediateHeaders[77] =
            hex"0100000066184d75b89754b5363036a66b0aa70142ae537e9c2a64c5175f97310000000049935f8c517625d3560f23a3cdf82fef68779c99f4a92931c91d8c11517c5cf137196949ffff001d2dc932c1";
        intermediateHeaders[78] =
            hex"010000005002c9b34042ac70ac8e36b1840672d69cb0ba6ada5effb6477de4aa00000000743a0389e4d8c9f60ad41025b797fd25e228123c4b54b5df20ed02ca97781df03c1b6949ffff001d21537e7a";
        intermediateHeaders[79] =
            hex"010000000d765e68e3487bd6d3372dd9eeca050857cf6c9bdb171fcdbe34d363000000001567e4c48479995636794ce5ec794eb145c1194478f45bb0a45cc11d8cc27fb1581f6949ffff001d28d2dbc1";
        intermediateHeaders[80] =
            hex"010000002bf72d8a5d6ea0889a5b52e19f53268423d644d3d61364174b859ccd00000000be23d982899e45eb4f5095cbc1c43ddc9495e93fd1e4f0bb3a20fd461412c5bd7a216949ffff001d14fc8df0";
        intermediateHeaders[81] =
            hex"010000004c812cdb1077ddb53fa3da180758d29b49262cc37eeaf9ef74a8afbf000000000743ebb1940fb72a15cebc9dbe481ea7625c70790a56bedfb7d74e0ba8227880e3226949ffff001d182b34b3";
        intermediateHeaders[82] =
            hex"0100000039e975250e63187ecb299082518f8da887198ea2b0834a1089cdacdd00000000b87adb107589f869ca344a457dec051371352b2f38be825d914139b568305faa7e256949ffff001d3a42e6fa";
        intermediateHeaders[83] =
            hex"01000000cce04fcc1138bafcf657f97e31c30705b991827071233deb2eae63ba00000000cb9f33326bbf60634a0634c3bce1c4a7e43ac4bd3fe54a654ae35be3f6ac83fdab286949ffff001d2654f246";
        intermediateHeaders[84] =
            hex"010000005714bd772bcbdb97a08d32cc82469cadbf7feb69bb4131a993bc7c7f00000000e19a9f3635b503e037212f13f6dd2b40a6b2d81379b9b341df3e33c14c22a3de8a2b6949ffff001d089368dd";
        intermediateHeaders[85] =
            hex"010000007a127b3a7af982beab22647b6456c8cbe6dc43a290c65d87b2abc08200000000b4ff4753f29de2ec4aefcccbb72b113f820894587fb3b7e0218ca6cb648cb441d02f6949ffff001d39a360d5";
        intermediateHeaders[86] =
            hex"010000005df242b278026fcf51ac4ba5cf5b590e58c2d1d76b2c09b25c52c98e00000000d6be02040ee5f8e52f2e925e6f70c73196064f99f20090bc73ea71516c5472d455336949ffff001d295b06ea";
        intermediateHeaders[87] =
            hex"0100000056d42459d4e316593155b4fad15dd700b93e9d2eb9999490d49e98ec0000000048b6a7bcf2a59e336da83ee70ddd230fc7e2db16c3c2654494c5502dac012538ce356949ffff001d23c2373b";
        intermediateHeaders[88] =
            hex"010000004ee5095194d71ca1b345ee9f27dbb6815ce4d5df9dc2c3c91ba364be0000000026366720a786e6615b3203909f8df77fc2e96d1afe593bd3d9623d19c481c947aa386949ffff001d1e6cbbe9";
        intermediateHeaders[89] =
            hex"010000005878d514861163b782b54b2d4c6f6bbdaf22e41c2401e9f84522515a000000000e7dcba835e4c20485b614f252183b53921a8901049ea6ef22f09a42195601b5203b6949ffff001d22c63213";
        intermediateHeaders[90] =
            hex"01000000ef06fa30dd7275529ae9d2677998c4d507a07517d28b23e6e08ed2e7000000004ca77b8b243eee32a9b06a8bea33abd5cf517bf68eed73e7fa951f4f30d2a17ec6446949ffff001de4acd41c";
        intermediateHeaders[91] =
            hex"010000002f8b9d4d8ea162a1d2e5fe288b110bf80a92b963b2d30f40956c88a2000000002518bddd47990bc127da5579b114cc3976568c7d0fc8f5b7a4b90478076799fba76b6949ffff001d397d4eb2";
        intermediateHeaders[92] =
            hex"010000002100cacac549da7d2a879cfbefc18cac6fbb9931d7da48c3e818e38600000000c654ae2f49a83f60d62dfafca02a221c9cb45ad96a5cb1539b22077bfa87d25e7d6d6949ffff001d32d01813";
        intermediateHeaders[93] =
            hex"010000008fd40a92b8965c798cf25dcdd8395de4ef75f206337de4985a3262be0000000099add42809e35d9c89641de1e9497db2e70bbb283e9b9492599f879533654c5cf86e6949ffff001d30177cef";
        intermediateHeaders[94] =
            hex"0100000086cff19f969df7040f27de690e7355436001cb3e361e7589526a077d00000000be4544845044c67df65f37d0ba8bb323fe457c141abe38eecdc2e530144bfb8103736949ffff001d31852f96";
        intermediateHeaders[95] =
            hex"0100000053514b63574bf6c65d576578f6cb2ad0f6256de1454211ddfa2222160000000073cad1e2d193f0d27471b13eb4b1f356aa63de8dc78a58a9128a2115c6eb1e5647776949ffff001d140de59c";
        intermediateHeaders[96] =
            hex"010000002b120517ca99a3d8361c2a9eef3126fff7c18e3ec365dc2201c315ca000000001d2e4b642f3d14c24f57f237d38acb8e4939855a8ca6ce7dab48e2cd85843d9ad97a6949ffff001d1622692a";
        intermediateHeaders[97] =
            hex"010000004f8dceb614b17b5ac9c9368906ffb338aeb750a1dfe1adaa67eef59500000000b45cf14a7caeeb5fcb286d314ac2fa85f58df3d5156fa95c832f373930de9bc3b37e6949ffff001d36e9e4e2";

        bool success = client.submitBlockHeader(BLOCK_109_HEADER, intermediateHeaders);
        assertTrue(success);

        BitcoinUtils.BlockHeader memory checkpoint = client.getLatestCheckpoint();
        assertEq(checkpoint.height, 109);
        vm.stopPrank();
    }
}
