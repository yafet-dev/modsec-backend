import { PrismaClient } from "@prisma/client";
import { processAllModsecLandingRecords } from "../services/modsecProcessor";

const prisma = new PrismaClient();

/**
 * Script to process all unprocessed modsec_landing records and migrate them to Log table
 * 
 * Usage:
 *   npx ts-node src/scripts/processModsecLanding.ts [organizationId]
 * 
 * If organizationId is not provided, logs will be created without organization association
 */
async function main() {
  const organizationId = process.argv[2] || undefined;

  console.log("🚀 Starting ModSec Landing to Log migration...");
  console.log(
    organizationId
      ? `📋 Organization ID: ${organizationId}`
      : "📋 No organization ID provided (logs will be created without organization)"
  );

  try {
    // Count unprocessed records
    const unprocessedCount = await prisma.modsecLanding.count({
      where: { processed: false },
    });

    console.log(`📊 Found ${unprocessedCount} unprocessed records`);

    if (unprocessedCount === 0) {
      console.log("✅ No records to process");
      return;
    }

    // Process all records
    const result = await processAllModsecLandingRecords(organizationId, 500);

    console.log("\n📈 Processing Results:");
    console.log(`   ✅ Successfully processed: ${result.processed}`);
    console.log(`   ❌ Failed: ${result.failed}`);

    if (result.errors.length > 0) {
      console.log("\n⚠️  Errors encountered:");
      result.errors.slice(0, 10).forEach((error) => {
        console.log(`   - ID: ${error.id}, Error: ${error.error}`);
      });
      if (result.errors.length > 10) {
        console.log(`   ... and ${result.errors.length - 10} more errors`);
      }
    }

    console.log("\n✅ Migration completed!");
  } catch (error) {
    console.error("❌ Error during migration:", error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Run the script
main();

