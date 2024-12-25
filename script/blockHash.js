const crypto = require("crypto");

// ------------
// block header (genesis block)
// ------------
const version = "000186A0";

const previousblock =
  "000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250";
const merkleroot =
  "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
    .match(/.{2}/g)
    .reverse()
    .join("");
// "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"; // Check by reversing it as well

const time = "4d1b2237";
const bits = "1b04864c";
const nonce = "10572b0f";

const blockheader = version + previousblock + merkleroot + time + bits + nonce;
console.log("Block header: ", blockheader);

// ---------
// block hash
// ----------

// Convert hexadecimal string to Buffer (equivalent to Ruby's pack("H*"))
const bytes = Buffer.from(
  "02000000bfc3c378eecc0bd2ea14d0c1a36266ba8f50243c1147c60300000000000000004392e2d5edcfe47c5d2546ef5b480f80f0edd921178e1b3d0ef15ce540331010556d5b55f58616187a388289",
  "hex"
);
console.log("blockheader bytes: ", bytes);

// SHA-256 (first round)
const hash1 = crypto.createHash("sha256").update(bytes).digest();
console.log("hash1: ", hash1);

// SHA-256 (second round)
const hash2 = crypto.createHash("sha256").update(hash1).digest();
console.log("hash2: ", hash2);

// Convert Buffer to hexadecimal string (equivalent to Ruby's unpack("H*"))
const blockhash = hash2.toString("hex");

// Print result (natural byte order)
console.log("blockhash: ", blockhash); //=> 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000

// Print result (reverse byte order)
// Split into pairs of characters, reverse the array, and join back together
const reversedBlockhash = blockhash.match(/.{2}/g).reverse().join("");
console.log("reversedBlockhash: ", reversedBlockhash); //=> 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
