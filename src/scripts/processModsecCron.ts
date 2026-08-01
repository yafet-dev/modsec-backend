import { prisma } from "../lib/prisma";
import { processAllModsecLandingRecords } from "../services/modsecProcessor";
import { sendNotificationsForLogs, sendNotificationsForNewLogs } from "../services/notificationService";

/**
 * Cron job script to process modsec_landing records
 * 
 * Usage:
 *   - Add to crontab: Every minute: cd /path/to/project && npm run cron:modsec
 *   - Or use node-cron in Node.js
 *   - Or use systemd timer
 * 
 * Environment variables:
 *   - BATCH_SIZE (default: 500)
 */
async function main() {
  const batchSize = parseInt(process.env.BATCH_SIZE || "500", 10);

  console.log(`🕐 [${new Date().toISOString()}] Starting ModSec processing cron job...`);
  console.log(`   Batch size: ${batchSize}`);

  try {
    // Process records (organization ID will be automatically matched by host domain)
    const result = await processAllModsecLandingRecords(
      undefined,
      batchSize
    );

    if (result.processed === 0 && result.failed === 0) {
      console.log("   ✅ No records to process");
      return;
    }

    console.log(`   ✅ Successfully processed: ${result.processed}`);
    console.log(`   ❌ Failed: ${result.failed}`);
    console.log(`   📋 Debug - result.logIds: ${result.logIds ? result.logIds.length : 'undefined'} log IDs`);

    if (result.errors.length > 0 && result.errors.length <= 10) {
      console.log(`   ⚠️  Errors:`);
      result.errors.forEach((error) => {
        console.log(`      - ID ${error.id}: ${error.error}`);
      });
    } else if (result.errors.length > 10) {
      console.log(`   ⚠️  ${result.errors.length} errors (too many to display)`);
    }

    // Phase 2: Send notifications for newly processed logs
    console.log(`\n   📧 ========================================`);
    console.log(`   📧 NOTIFICATION PHASE`);
    console.log(`   📧 ========================================`);
    console.log(`   📊 Total logs processed: ${result.processed}`);
    console.log(`   📊 Log IDs created: ${result.logIds ? result.logIds.length : 0}`);
    
    if (result.processed > 0) {
      if (result.logIds && result.logIds.length > 0) {
        console.log(`   🔄 Starting notification check for ${result.logIds.length} newly created log(s)...`);
        const notificationResult = await sendNotificationsForLogs(result.logIds);
        console.log(`\n   📧 Notification Summary:`);
        console.log(`      ✅ Successfully sent: ${notificationResult.sent}`);
        console.log(`      ❌ Failed: ${notificationResult.failed}`);
        if (notificationResult.failed > 0) {
          if (notificationResult.errors.length > 0 && notificationResult.errors.length <= 5) {
            console.log(`      ⚠️  Errors:`);
            notificationResult.errors.forEach((err) => {
              console.log(`         - Log ${err.logId}: ${err.error}`);
            });
          }
        }
      } else {
        console.log(`   ⚠️  No log IDs returned from processing, using fallback timestamp method...`);
        // Fallback: use timestamp-based approach - check logs from last 10 minutes
        const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
        console.log(`   🔄 Checking for logs created since: ${tenMinutesAgo.toISOString()}`);
        const notificationResult = await sendNotificationsForNewLogs(tenMinutesAgo);
        console.log(`\n   📧 Notification Summary:`);
        console.log(`      ✅ Successfully sent: ${notificationResult.sent}`);
        console.log(`      ❌ Failed: ${notificationResult.failed}`);
        if (notificationResult.sent === 0 && notificationResult.failed === 0) {
          console.log(`      ℹ️  No logs found matching notification criteria`);
        }
      }
    } else {
      console.log(`   ℹ️  No logs were processed, skipping notification phase`);
    }
    console.log(`   📧 ========================================\n`);

    console.log(`✅ [${new Date().toISOString()}] Cron job completed`);
  } catch (error) {
    console.error(`❌ [${new Date().toISOString()}] Cron job error:`, error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();

