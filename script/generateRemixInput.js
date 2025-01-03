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

// Example usage with the block hash from your example
const blockHash =
  "0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073";
getBlockHeaderData(blockHash);
