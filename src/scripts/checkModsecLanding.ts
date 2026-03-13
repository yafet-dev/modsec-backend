import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Script to check if ModsecLanding table exists and verify its structure
 */
async function main() {
  try {
    console.log("🔍 Checking ModsecLanding table...");

    // Try to query the table
    const count = await prisma.modsecLanding.count();
    console.log(`✅ ModsecLanding table exists!`);
    console.log(`📊 Total records: ${count}`);

    // Get a sample record if any exist
    if (count > 0) {
      const sample = await prisma.modsecLanding.findFirst({
        orderBy: { time: "desc" },
      });
      console.log("\n📝 Sample record:");
      console.log(`   ID: ${sample?.id}`);
      console.log(`   Time: ${sample?.time}`);
      console.log(`   Processed: ${sample?.processed}`);
      console.log(`   Has data: ${sample?.data ? "Yes" : "No"}`);
    }

    // Count unprocessed records
    const unprocessed = await prisma.modsecLanding.count({
      where: { processed: false },
    });
    console.log(`\n📋 Unprocessed records: ${unprocessed}`);
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes("does not exist")) {
        console.error("❌ ModsecLanding table does not exist in the database");
        console.log("\n💡 You may need to:");
        console.log("   1. Run: npm run prisma:migrate");
        console.log("   2. Or create the table manually in Supabase");
      } else {
        console.error("❌ Error:", error.message);
      }
    } else {
      console.error("❌ Unknown error:", error);
    }
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();


