// Helper function to convert hex string to bytes array
function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

// Helper function to convert bytes array to hex string
function bytesToHex(bytes) {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Hash function used in the merkle root function (using crypto-js for SHA256)
function hash256(hex) {
  const crypto = require("crypto");
  const binary = Buffer.from(hex, "hex");
  const hash1 = crypto.createHash("sha256").update(binary).digest();
  const hash2 = crypto.createHash("sha256").update(hash1).digest();
  return hash2.toString("hex");
}

function merkleRoot(txids) {
  // Exit Condition: Stop recursion when we have one hash result left
  if (txids.length === 1) {
    return txids[0];
  }

  // Keep an array of results
  const result = [];

  // 1. Split up array of hashes into pairs
  for (let i = 0; i < txids.length; i += 2) {
    const one = txids[i];
    const two = txids[i + 1];

    // 2a. Concatenate each pair
    // 2b. Concatenate with itself if there is no pair
    const concat = one + (two || one);

    // 3. Hash the concatenated pair and add to results array
    result.push(hash256(concat));
  }

  // Recursion: Do the same thing again for these results
  return merkleRoot(result);
}

// Test (e.g. block 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506)
const txids = [
  "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
  "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
  "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
  "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
];

// TXIDs must be in natural byte order when creating the merkle root
const reversedTxids = txids.map((txid) =>
  txid.match(/.{2}/g).reverse().join("")
);

// Create the merkle root
const result = merkleRoot(reversedTxids);
console.log("Without reversed merkle root: ", result);

// Display the result in reverse byte order
console.log(result.match(/.{2}/g).reverse().join(""));
// => f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766

// // Natural byte order (Reversed txn ids from btcscan) - Block: 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
// [
//   "876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c",
//   "c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff",
//   "c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963",
//   "1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9"
// ]

// Natural byte order
[
  "0x876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c",
  "0xc40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff",
  "0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963",
  "0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9",
];

// Reverse byte order
[
  "0x8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
  "0xfff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
  "0x6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
  "0xe9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
];
