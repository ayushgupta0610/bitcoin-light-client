const fs = require("fs");

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

async function generateRawHeadersArray(inputPath) {
  try {
    // Read and parse input JSON file
    const data = JSON.parse(fs.readFileSync(inputPath, "utf8"));

    // Process each block header
    const rawHeaders = data.map((block) => {
      // Generate raw block header components
      const versionHex = toLeBytes(block.version);
      const prevBlockHex = reverseBytes(block.previousBlock);
      const merkleRootHex = reverseBytes(block.merkleRoot);
      const timestampHex = toLeBytes(block.timestamp);
      const bitsHex = toLeBytes(block.bits);
      const nonceHex = toLeBytes(block.nonce);

      // Concatenate all parts
      return (
        "0x" +
        versionHex +
        prevBlockHex +
        merkleRootHex +
        timestampHex +
        bitsHex +
        nonceHex
      );
    });

    // Console output for verification
    console.log("Raw Headers Array:");
    console.log(JSON.stringify(rawHeaders, null, 2));

    // Create the JavaScript file content
    const fileContent = `const rawHeaders = ${JSON.stringify(
      rawHeaders,
      null,
      2
    )};\n\nmodule.exports = rawHeaders;`;

    // Write to output file
    fs.writeFileSync("rawHeaders.js", fileContent);
    console.log("\nRaw headers array has been written to rawHeaders.js");

    return rawHeaders;
  } catch (error) {
    console.error("Error generating raw headers:", error);
    throw error;
  }
}

// Execute with input file path
generateRawHeadersArray("./block_headers_2024-12-29T19-42-07-176Z.json");
