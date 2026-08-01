import { prisma } from "../lib/prisma";
import { processAllModsecLandingRecords } from "../services/modsecProcessor";

/**
 * Worker process that runs continuously and processes modsec_landing records
 * Run this as a separate process: npm run worker:modsec
 */
async function worker() {
  const BATCH_SIZE = parseInt(process.env.BATCH_SIZE || "500", 10);
  const POLL_INTERVAL = 5000; // 5 seconds
  const ORGANIZATION_ID = process.env.DEFAULT_ORGANIZATION_ID;

  console.log("🚀 ModSec Landing Processor Worker started");
  console.log(`   Batch size: ${BATCH_SIZE}`);
  console.log(`   Poll interval: ${POLL_INTERVAL}ms`);
  console.log(`   Organization ID: ${ORGANIZATION_ID || "None (will use NULL)"}`);

  while (true) {
    try {
      // The keyset claimer already returns immediately when the queue is
      // empty, avoiding a separate full COUNT scan before every worker poll.
      const result = await processAllModsecLandingRecords(
        ORGANIZATION_ID,
        BATCH_SIZE
      );

      if (result.processed === 0 && result.failed === 0) {
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
        continue;
      }

      console.log(`   ✅ Processed: ${result.processed}`);
      console.log(`   ❌ Failed: ${result.failed}`);

      if (result.errors.length > 0) {
        console.log(`   ⚠️  Errors (showing first 5):`);
        result.errors.slice(0, 5).forEach((error) => {
          console.log(`      - ID ${error.id}: ${error.error}`);
        });
      }

      // If we processed a full batch, there might be more - process immediately
      // Otherwise, wait before next poll
      if (result.processed < BATCH_SIZE) {
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
      }
    } catch (error) {
      console.error("❌ Worker error:", error);
      // Wait before retrying on error
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL * 2));
    }
  }
}

// Handle graceful shutdown
process.on("SIGINT", async () => {
  console.log("\n🛑 Shutting down worker...");
  await prisma.$disconnect();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\n🛑 Shutting down worker...");
  await prisma.$disconnect();
  process.exit(0);
});

// Start the worker
worker().catch(async (error) => {
  console.error("Fatal worker error:", error);
  await prisma.$disconnect();
  process.exit(1);
});

