const axios = require("axios");

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

    // Format data for submitBlockHeader function
    const formattedData = {
      blockHash: toBytes32(blockData.hash),
      version: blockData.version,
      prevBlock: toBytes32(blockData.previousblockhash),
      merkleRoot: toBytes32(blockData.merkleroot),
      blockTimestamp: blockData.time,
      difficultyBits: parseInt(blockData.bits, 16),
      nonce: blockData.nonce,
    };

    console.log("Formatted data for submitBlockHeader:");
    console.log("------------------------");
    console.log("Parameter order for function call:");
    console.log(
      "submitBlockHeader(blockHash, version, prevBlock, merkleRoot, blockTimestamp, difficultyBits, nonce)"
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

    // Return formatted data in case needed programmatically
    return formattedData;
  } catch (error) {
    console.error("Error fetching block header:", error);
    throw error;
  }
}

// Example usage with the block hash from your example
const blockHash =
  "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
getBlockHeaderData(blockHash);
