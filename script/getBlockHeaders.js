// https://blockchain.info/block-height/2?format=json

const axios = require("axios");

async function fetchBlockHeaders(startHeight = 10, endHeight = 55) {
  const headers = [];
  const API_BASE = "https://api.blockcypher.com/v1/btc/main/blocks/";

  // Configure axios with default settings
  const client = axios.create({
    timeout: 10000, // 10 seconds timeout
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
  });

  try {
    for (let height = startHeight; height <= endHeight; height++) {
      console.log(`Fetching block at height ${height}...`);

      try {
        // BlockCypher has rate limits, so we add a small delay
        await new Promise((resolve) => setTimeout(resolve, 200));

        const response = await client.get(`${API_BASE}${height}`);
        const block = response.data;

        headers.push({
          height: block.height,
          hash: block.hash,
          prev_block: block.prev_block,
          time: new Date(block.time).getTime() / 1000,
          bits: block.bits,
          nonce: block.nonce,
          merkle_root: block.mrkl_root,
          version: block.ver,
        });
      } catch (requestError) {
        if (requestError.response) {
          // The request was made and the server responded with a status code
          // that falls out of the range of 2xx
          console.error(`Error fetching block ${height}:`, {
            status: requestError.response.status,
            data: requestError.response.data,
          });
        } else if (requestError.request) {
          // The request was made but no response was received
          console.error(`No response received for block ${height}`);
        } else {
          // Something happened in setting up the request
          console.error(
            `Error setting up request for block ${height}:`,
            requestError.message
          );
        }

        // Add retry logic
        console.log(`Retrying block ${height} after 2 seconds...`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
        height--; // Retry the same height
        continue;
      }
    }

    // Save to file
    const fs = require("fs");
    fs.writeFileSync("block_headers.json", JSON.stringify(headers, null, 2));
    console.log("Block headers saved to block_headers.json");

    return headers;
  } catch (error) {
    console.error("Fatal error fetching block headers:", error);
    throw error;
  }
}

// Execute the script with error handling
fetchBlockHeaders()
  .then((headers) => {
    console.log(`Successfully fetched ${headers.length} block headers`);
    console.log(`First block header:`, headers[0]);
  })
  .catch((error) => {
    console.error("Script failed:", error.message);
    process.exit(1);
  });
