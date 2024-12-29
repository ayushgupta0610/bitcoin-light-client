const axios = require("axios");
const fs = require("fs");

// Function to convert hex string to bytes32 format
function toBytes32(hexString) {
  // Remove '0x' if present
  hexString = hexString.replace("0x", "");

  // Pad to 64 characters (32 bytes)
  while (hexString.length < 64) {
    hexString = "0" + hexString;
  }

  return "0x" + hexString;
}

// Helper function to convert number to little-endian hex bytes
function toLeBytes(num, bytes = 4) {
  let hex = num.toString(16).padStart(bytes * 2, "0");
  // Convert to little-endian
  const pairs = hex.match(/.{2}/g) || [];
  return pairs.reverse().join("");
}

// Helper function to reverse bytes of a hex string
function reverseBytes(hexString) {
  // Remove '0x' if present
  hexString = hexString.replace("0x", "");
  // Split into pairs and reverse
  const pairs = hexString.match(/.{2}/g) || [];
  return pairs.reverse().join("");
}

async function getBlockHeaderData(blockHash) {
  const url = "https://docs-demo.btc.quiknode.pro/";

  try {
    const response = await axios.post(
      url,
      {
        method: "getblockheader",
        params: [blockHash],
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    const blockData = response.data.result;

    // Generate raw block header (80 bytes total)
    const versionHex = toLeBytes(blockData.version);
    const prevBlockHex = reverseBytes(blockData.previousblockhash);
    const merkleRootHex = reverseBytes(blockData.merkleroot);
    const timestampHex = toLeBytes(blockData.time);
    const bitsHex = reverseBytes(blockData.bits);
    const nonceHex = toLeBytes(blockData.nonce);

    // Concatenate all parts
    const rawBlockHeader =
      versionHex +
      prevBlockHex +
      merkleRootHex +
      timestampHex +
      bitsHex +
      nonceHex;

    const formattedData = {
      blockHash: toBytes32(blockData.hash),
      version: blockData.version,
      prevBlock: toBytes32(blockData.previousblockhash),
      merkleRoot: toBytes32(blockData.merkleroot),
      blockTimestamp: blockData.time,
      difficultyBits: parseInt(blockData.bits, 16),
      nonce: blockData.nonce,
      rawBlockHeader: "0x" + rawBlockHeader,
    };

    console.log("Block header data: ", blockData);
    console.log("------------------------");
    console.log("Formatted data for submitBlockHeader:");
    console.log("------------------------");
    console.log("Parameter order for function call:");
    console.log(
      "submitBlockHeader(blockHash, version, prevBlock, merkleRoot, blockTimestamp, difficultyBits, nonce, rawBlockHeader)"
    );
    console.log("------------------------");
    console.log("Values to copy into Remix:");
    console.log("blockHash:", formattedData.blockHash);
    console.log("version:", formattedData.version);
    console.log("prevBlock:", formattedData.prevBlock);
    console.log("merkleRoot:", formattedData.merkleRoot);
    console.log("blockTimestamp:", formattedData.blockTimestamp);
    console.log("difficultyBits:", formattedData.difficultyBits);
    console.log("nonce:", formattedData.nonce);
    console.log("rawBlockHeader:", formattedData.rawBlockHeader);

    return formattedData;
  } catch (error) {
    console.error("Error fetching block header:", error);
    throw error;
  }
}

async function processBlockHeadersJson(jsonPath) {
  try {
    // Read and parse JSON file
    const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));

    // Process each block header
    const formattedHeaders = data.map((block) => {
      // Generate raw block header components
      const versionHex = toLeBytes(block.version);
      const prevBlockHex = reverseBytes(block.previousBlock);
      const merkleRootHex = reverseBytes(block.merkleRoot);
      const timestampHex = toLeBytes(block.timestamp);
      const bitsHex = toLeBytes(block.bits);
      const nonceHex = toLeBytes(block.nonce);

      // Concatenate all parts
      const rawBlockHeader =
        versionHex +
        prevBlockHex +
        merkleRootHex +
        timestampHex +
        bitsHex +
        nonceHex;

      return {
        height: block.height,
        formattedData: {
          blockHash: toBytes32(block.hash),
          version: block.version,
          prevBlock: toBytes32(block.previousBlock),
          merkleRoot: toBytes32(block.merkleRoot),
          blockTimestamp: block.timestamp,
          difficultyBits: block.bits,
          nonce: block.nonce,
          rawBlockHeader: "0x" + rawBlockHeader,
        },
      };
    });

    // Output results
    formattedHeaders.forEach(({ height, formattedData }) => {
      console.log(`\nBlock ${height}:`);
      console.log("------------------------");
      console.log("Values for Remix:");
      console.log("blockHash:", formattedData.blockHash);
      console.log("version:", formattedData.version);
      console.log("prevBlock:", formattedData.prevBlock);
      console.log("merkleRoot:", formattedData.merkleRoot);
      console.log("blockTimestamp:", formattedData.blockTimestamp);
      console.log("difficultyBits:", formattedData.difficultyBits);
      console.log("nonce:", formattedData.nonce);
      console.log("rawBlockHeader:", formattedData.rawBlockHeader);
    });

    return formattedHeaders;
  } catch (error) {
    console.error("Error processing block headers:", error);
    throw error;
  }
}

// Execute with the JSON file path
processBlockHeadersJson("./block_headers_2024-12-29T19-42-07-176Z.json");
