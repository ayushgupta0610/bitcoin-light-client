// TODO: WIP
const crypto = require("crypto");

function doubleSha256(buffer) {
  const firstHash = crypto.createHash("sha256").update(buffer).digest();
  const secondHash = crypto.createHash("sha256").update(firstHash).digest();
  return secondHash;
}

function reverseBuffer(buffer) {
  const reversed = Buffer.from(buffer);
  for (let i = 0; i < Math.floor(buffer.length / 2); i++) {
    const temp = reversed[i];
    reversed[i] = reversed[buffer.length - 1 - i];
    reversed[buffer.length - 1 - i] = temp;
  }
  return reversed;
}

function verifyTx(txid, proofs, merkleRoot) {
  // Convert hex strings to buffers if they aren't already
  let computedHash = Buffer.from(txid.replace("0x", ""), "hex");
  const targetRoot = Buffer.from(merkleRoot.replace("0x", ""), "hex");

  // Process each proof element
  for (const proofHex of proofs) {
    const proofBuffer = Buffer.from(proofHex.replace("0x", ""), "hex");

    // Concatenate and hash the buffers
    const concatenated = Buffer.concat([computedHash, proofBuffer]);
    computedHash = doubleSha256(concatenated);
  }

  // Compare the computed hash with the target merkle root
  return computedHash.equals(targetRoot);
}

// Test values from your example
// const txid = "0xf66f6ab609d242edf26678139ddd614777c4e5080f017d15cb9aa431dda351";
// const merkleRoot =
//   "0x17663ab10c2e13d92dccb4514b05b18815f5f38af1f21e06931c71d62b36d8af";
// const proofs = [
//   "0x50ba87bdd484f07c8c55f76a22982f987c0465fdc345381b4634a70dc0ea0b38",
//   "0x96b8787b1e3abed802cff132c891c2e511edd200b08baa9eb7d8942d7c5423c6",
//   "0x65e5a4862b807c83b588e0f4122d4ca2d46691d17a1ec1ebce4485dccc3380d4",
//   "0x1ee9441ddde02f8ffb910613cd509adbc21282c6e34728599f3ae75e972fb815",
//   "0xec950fc02f71fc06ed71afa4d2c49fcba04777f353a001b0bba9924c63cfe712",
//   "0x5d874040a77de7182f7a68bf47c02898f519cb3b58092b79fa2cff614a0f4d50",
//   "0x0a1c958af3e30ad07f659f44f708f8648452d1427463637b9039e5b721699615",
//   "0xd94d24d2dcaac111f5f638983122b0e55a91aeb999e0e4d58e0952fa346a1711",
//   "0xc4709bc9f860e5dff01b5fc7b53fb9deecc622214aba710d495bccc7f860af4a",
//   "0xd4ed5f5e4334c0a4ccce6f706f3c9139ac0f6d2af3343ad3fae5a02fee8df542",
//   "0xb5aed07505677c8b1c6703742f4558e993d7984dc03d2121d3712d81ee067351",
//   "0xf9a14bf211c857f61ff9a1de95fc902faebff67c5d4898da8f48c9d306f1f80f",
// ];

const txid =
  "0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963";
const merkleRoot =
  "0xf3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766";
const proofs = [
  "0x876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c",
  "0xc40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff",
  "0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963",
  "0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9",
];

// Run the verification
const isValid = verifyTx(txid, proofs, merkleRoot);
console.log("Transaction verification result:", isValid);

// Helper function to inspect intermediate hashes
function debugVerification(txid, proofs, merkleRoot) {
  let computedHash = Buffer.from(txid.replace("0x", ""), "hex");
  console.log("Starting with txid:", computedHash.toString("hex"));

  for (let i = 0; i < proofs.length; i++) {
    const proofBuffer = Buffer.from(proofs[i].replace("0x", ""), "hex");
    const concatenated = Buffer.concat([computedHash, proofBuffer]);
    computedHash = doubleSha256(concatenated);
    console.log(`After proof ${i + 1}:`, computedHash.toString("hex"));
  }

  const targetRoot = Buffer.from(merkleRoot.replace("0x", ""), "hex");
  console.log("Target root:", targetRoot.toString("hex"));
  console.log("Match:", computedHash.equals(targetRoot));
}

// Run debug verification
console.log("\nDebug verification:");
debugVerification(txid, proofs, merkleRoot);
