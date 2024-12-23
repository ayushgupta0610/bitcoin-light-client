const { sha256 } = require("crypto-js");

class BitcoinDifficultyValidator {
  constructor() {
    this.DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
    this.TARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks in seconds
    this.LOWEST_DIFFICULTY = 0x1d00ffff;
  }

  // Expand compressed difficulty bits to full target
  expandDifficultyBits(bits) {
    const exp = bits >> 24;
    const coef = bits & 0xffffff;
    return coef * Math.pow(2, 8 * (exp - 3));
  }

  // Verify proof of work meets difficulty target
  verifyProofOfWork(blockHash, difficultyBits) {
    const target = this.expandDifficultyBits(difficultyBits);

    // Convert hex hash to decimal for comparison
    const hashNum = BigInt(`0x${blockHash}`);
    const targetNum = BigInt(target);

    return hashNum < targetNum;
  }

  // Verify difficulty target for adjustment blocks
  verifyDifficultyTarget(newHeader, lastAdjustmentHeader) {
    let actualTimespan = newHeader.timestamp - lastAdjustmentHeader.timestamp;

    // Apply bounds of 1/4 and 4x target timespan
    actualTimespan = Math.min(
      Math.max(actualTimespan, this.TARGET_TIMESPAN / 4),
      this.TARGET_TIMESPAN * 4
    );

    // Calculate new target
    const lastTarget = this.expandDifficultyBits(
      lastAdjustmentHeader.difficultyBits
    );
    let newTarget = (lastTarget * actualTimespan) / this.TARGET_TIMESPAN;

    // Ensure new target is below maximum allowed
    const maxTarget = this.expandDifficultyBits(this.LOWEST_DIFFICULTY);
    newTarget = Math.min(newTarget, maxTarget);

    // Compare with header's difficulty
    const headerTarget = this.expandDifficultyBits(newHeader.difficultyBits);
    return headerTarget === newTarget;
  }
}

// Example usage
function runExamples() {
  const validator = new BitcoinDifficultyValidator();

  // Example 1: Verify Proof of Work
  const exampleBlockHash =
    "00000000000000000000943de85f4495f053ff55f27d135edc61c27990c2eec5";
  const exampleDifficultyBits = 0x1d00ffff;

  console.log("\nExample 1: Proof of Work Verification");
  console.log("Block Hash:", exampleBlockHash);
  console.log("Difficulty Bits:", exampleDifficultyBits.toString(16));
  console.log(
    "Is Valid PoW:",
    validator.verifyProofOfWork(exampleBlockHash, exampleDifficultyBits)
  );

  // Example 2: Difficulty Target Verification
  const newHeader = {
    timestamp: 1617040118,
    difficultyBits: 0x1d00ffff,
  };

  const lastAdjustmentHeader = {
    timestamp: 1617040118 - 2 * 24 * 60 * 60, // 2 days earlier
    difficultyBits: 0x1d00ffff,
  };

  console.log("\nExample 2: Difficulty Target Verification");
  console.log("New Header Timestamp:", newHeader.timestamp);
  console.log("Last Adjustment Timestamp:", lastAdjustmentHeader.timestamp);
  console.log(
    "Is Valid Target:",
    validator.verifyDifficultyTarget(newHeader, lastAdjustmentHeader)
  );
}

// Run the examples
runExamples();

module.exports = BitcoinDifficultyValidator;
