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

// Natural byte order (Reversed txn ids from btcscan) - Block: 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
[
  "876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c",
  "c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff",
  "c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963",
  "1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9"
]

// Natural byte order
[
  "0x876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c",
  "0xc40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff",
  "0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963",
  "0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9",
];
0x6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3 (Natural byte order)
0xf3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766 (Reverse byte order)

// Reverse byte order
[
  "0x8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
  "0xfff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
  "0x6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
  "0xe9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
];

0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9
0x6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3
["0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963", "0x15b88c5107195bf09eb9da89b83d95b3d070079a3c5c5d3d17d0dcd873fbdacc"]

0xc46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963,0x15b88c5107195bf09eb9da89b83d95b3d070079a3c5c5d3d17d0dcd873fbdacc

["0x1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9","0x15b88c5107195bf09eb9da89b83d95b3d070079a3c5c5d3d17d0dcd873fbdacc"]

// Actual bytes order - ie reversed order transactions
[
  "0xbb28a1a5b3a02e7657a81c38355d56c6f05e80b9219432e3352ddcfc3cb6304c",
  "0xfbde5d03b027d2b9ba4cf5d4fecab9a99864df2637b25ea4cbcb1796ff6550ca",
  "0x8131ffb0a2c945ecaf9b9063e59558784f9c3a74741ce6ae2a18d0571dac15bb",
  "0xd6c7cb254aa7a5fd446e8b48c307890a2d4e426da8ad2e1191cc1d8bbe0677d7",
  "0xce29e5407f5e4c9ad581c337a639f3041b24220d5aa60370d96a39335538810b",
  "0x45a38677e1be28bd38b51bc1a1c0280055375cdf54472e04c590a989ead82515",
  "0xc5abc61566dbb1c4bce5e1fda7b66bed22eb2130cea4b721690bc1488465abc9",
  "0xa71f74ab78b564004fffedb2357fb4059ddfc629cb29ceeb449fafbf272104ca",
  "0xfda204502a3345e08afd6af27377c052e77f1fefeaeb31bdd45f1e1237ca5470",
  "0xd3cd1ee6655097146bdae1c177eb251de92aed9045a0959edc6b91d7d8c1f158",
  "0xcb00f8a0573b18faa8c4f467b049f5d202bf1101d9ef2633bc611be70376a4b4",
  "0x05d07bb2de2bda1115409f99bf6b626d23ecb6bed810d8be263352988e4548cb"
]

0xbb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181 // Natural byte order transaction
0x1959fcdf6c0cff855babb65cb200288e5aaf2de38a398c077ff396f4a51303e4 // Natural bytes order merkle root
["0xd77706be8b1dcc91112eada86d424e2d0a8907c3488b6e44fda5a74a25cbc7d6",
"0xafa23ed68017e1c8c50eee6a651b10de8fc250814727dae01e0ac44fc0bdcd7b",
"0x61a369306834de4b02fb4d697d584b0bf2c7eb37a3954e9a568575f3cb0940e9",
"0x96a785fbf236648423cc0eb63e5233bb967fb753aa49889e13265dfc84886898"]


// Natural order byte transactions
["0x4c30b63cfcdc2d35e3329421b9805ef0c6565d35381ca857762ea0b3a5a128bb",
"0xca5065ff9617cbcba45eb23726df6498a9b9cafed4f54cbab9d227b0035ddefb",
"0xbb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181",
"0xd77706be8b1dcc91112eada86d424e2d0a8907c3488b6e44fda5a74a25cbc7d6",
"0x0b81385533396ad97003a65a0d22241b04f339a637c381d59a4c5e7f40e529ce",
"0x1525d8ea89a990c5042e4754df5c37550028c0a1c11bb538bd28bee17786a345",
"0xc9ab658448c10b6921b7a4ce3021eb22ed6bb6a7fde1e5bcc4b1db6615c6abc5",
"0xca042127bfaf9f44ebce29cb29c6df9d05b47f35b2edff4f0064b578ab741fa7",
"0x7054ca37121e5fd4bd31ebeaef1f7fe752c07773f26afd8ae045332a5004a2fd",
"0x58f1c1d8d7916bdc9e95a04590ed2ae91d25eb77c1e1da6b14975065e61ecdd3",
"0xb4a47603e71b61bc3326efd90111bf02d2f549b067f4c4a8fa183b57a0f800cb",
"0xcb48458e98523326bed810d8beb6ec236d626bbf999f401511da2bdeb27bd005"]


0xbb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181 // Natural byte order transaction index 2
0x6abbb3eb3d733a9fe18967fd7d4c117e4ccbbac5bec4d910d900b3ae0793e77f // Natural byte order merkle root
// Natural byte order proofs generated from Natural order byte transactions
["0xd77706be8b1dcc91112eada86d424e2d0a8907c3488b6e44fda5a74a25cbc7d6",
"0xafa23ed68017e1c8c50eee6a651b10de8fc250814727dae01e0ac44fc0bdcd7b",
"0x61a369306834de4b02fb4d697d584b0bf2c7eb37a3954e9a568575f3cb0940e9",
"0x8276222651209fe1a2c4c0fa1c58510aec8b090dd1eb1f82f9d261b8273b525b"]



// Initialize with real transaction IDs from block #800000
// bytes32[] memory newTransactions = new bytes32[](12);
// newTransactions[0] = 0x4c30b63cfcdc2d35e3329421b9805ef0c6565d35381ca857762ea0b3a5a128bb;
// newTransactions[1] = 0xca5065ff9617cbcba45eb23726df6498a9b9cafed4f54cbab9d227b0035ddefb;
// newTransactions[2] = 0xbb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181;
// newTransactions[3] = 0xd77706be8b1dcc91112eada86d424e2d0a8907c3488b6e44fda5a74a25cbc7d6;
// newTransactions[4] = 0x0b81385533396ad97003a65a0d22241b04f339a637c381d59a4c5e7f40e529ce;
// newTransactions[5] = 0x1525d8ea89a990c5042e4754df5c37550028c0a1c11bb538bd28bee17786a345;
// newTransactions[6] = 0xc9ab658448c10b6921b7a4ce3021eb22ed6bb6a7fde1e5bcc4b1db6615c6abc5;
// newTransactions[7] = 0xca042127bfaf9f44ebce29cb29c6df9d05b47f35b2edff4f0064b578ab741fa7;
// newTransactions[8] = 0x7054ca37121e5fd4bd31ebeaef1f7fe752c07773f26afd8ae045332a5004a2fd;
// newTransactions[9] = 0x58f1c1d8d7916bdc9e95a04590ed2ae91d25eb77c1e1da6b14975065e61ecdd3;
// newTransactions[10] = 0xb4a47603e71b61bc3326efd90111bf02d2f549b067f4c4a8fa183b57a0f800cb;
// newTransactions[11] = 0xcb48458e98523326bed810d8beb6ec236d626bbf999f401511da2bdeb27bd005;

// transactions = newTransactions;