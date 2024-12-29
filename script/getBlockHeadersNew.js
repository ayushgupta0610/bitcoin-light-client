const axios = require("axios");
const fs = require("fs").promises;

// Configure axios defaults
const api = axios.create({
  baseURL: "https://blockchain.info",
  timeout: 10000, // 10 seconds timeout
  headers: {
    "Content-Type": "application/json",
  },
});

async function getBlockHeaders(startHeight, count) {
  const headers = [];

  try {
    for (let height = startHeight; height < startHeight + count; height++) {
      try {
        const response = await api.get(`/block-height/${height}?format=json`);
        const block = response.data.blocks[0];

        // Extract and format the block header information
        const header = {
          height: block.height,
          hash: block.hash,
          version: block.ver,
          previousBlock: block.prev_block,
          merkleRoot: block.mrkl_root,
          timestamp: block.time,
          bits: block.bits,
          nonce: block.nonce,
          size: block.size,
          weight: block.weight,
          txCount: block.n_tx,
        };

        headers.push(header);
        console.log(`Successfully fetched block ${height}`);

        // Add delay to avoid rate limiting
        await new Promise((resolve) => setTimeout(resolve, 200));
      } catch (error) {
        console.error(`Error fetching block ${height}:`, error.message);
        // Add a placeholder for failed blocks to maintain sequence
        headers.push({
          height,
          error: error.message,
        });
      }
    }

    return headers;
  } catch (error) {
    console.error("Fatal error in getBlockHeaders:", error.message);
    throw error;
  }
}

async function main() {
  try {
    console.log("Starting to fetch block headers...");
    const headers = await getBlockHeaders(10, 100);

    // Save results to file with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `block_headers_${timestamp}.json`;

    await fs.writeFile(filename, JSON.stringify(headers, null, 2));

    console.log(`Successfully saved ${headers.length} headers to ${filename}`);

    // Print summary
    const successfulBlocks = headers.filter((h) => !h.error).length;
    console.log(`
Summary:
- Total blocks processed: ${headers.length}
- Successful fetches: ${successfulBlocks}
- Failed fetches: ${headers.length - successfulBlocks}
        `);
  } catch (error) {
    console.error("Failed to complete operation:", error.message);
    process.exit(1);
  }
}

// Run the script
main().catch(console.error);
