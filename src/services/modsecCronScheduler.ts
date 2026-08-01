import * as cron from "node-cron";
import { processAllModsecLandingRecords } from "./modsecProcessor";
import { sendNotificationsForLogs, sendNotificationsForNewLogs } from "./notificationService";

/**
 * Cron scheduler for processing ModSec landing records
 * 
 * Environment variables:
 *   - ENABLE_MODSEC_CRON: Enable/disable cron (default: "true")
 *   - MODSEC_CRON_SCHEDULE: Cron schedule (default: every minute)
 *   - BATCH_SIZE: Number of records claimed per transaction (default: 500)
 */
class ModsecCronScheduler {
  private task: cron.ScheduledTask | null = null;
  private isRunning = false;

  /**
   * Start the cron scheduler
   */
  start(): void {
    const enabled = process.env.ENABLE_MODSEC_CRON !== "false";
    const schedule = process.env.MODSEC_CRON_SCHEDULE || "* * * * *";

    if (!enabled) {
      console.log("⏸️  ModSec cron scheduler is disabled (ENABLE_MODSEC_CRON=false)");
      return;
    }

    // Validate cron schedule
    if (!cron.validate(schedule)) {
      console.error(`❌ Invalid cron schedule: ${schedule}`);
      return;
    }

    console.log(`⏰ Starting ModSec cron scheduler with schedule: ${schedule}`);

    this.task = cron.schedule(schedule, async () => {
      if (this.isRunning) {
        console.log("⏳ ModSec processing already in progress, skipping this run...");
        return;
      }

      this.isRunning = true;
      const startTime = Date.now();

      try {
        const batchSize = parseInt(process.env.BATCH_SIZE || "500", 10);

        console.log(`🕐 [${new Date().toISOString()}] Starting ModSec processing cron job...`);
        console.log(`   Batch size: ${batchSize}`);

        // Process records (organization ID will be automatically matched by host domain)
        const result = await processAllModsecLandingRecords(
          undefined,
          batchSize
        );

        const duration = Date.now() - startTime;
        if (result.processed === 0 && result.failed === 0) {
          console.log("   ✅ No records to process");
          return;
        }

        console.log(`   ✅ Successfully processed: ${result.processed}`);
        console.log(`   ❌ Failed: ${result.failed}`);
        console.log(`   ⏱️  Duration: ${duration}ms`);

        if (result.errors.length > 0 && result.errors.length <= 10) {
          console.log(`   ⚠️  Errors:`);
          result.errors.forEach((error) => {
            console.log(`      - ID ${error.id}: ${error.error.substring(0, 100)}`);
          });
        } else if (result.errors.length > 10) {
          console.log(`   ⚠️  ${result.errors.length} errors (too many to display)`);
        }

        // Phase 2: Send notifications for newly processed logs
        if (result.processed > 0) {
          console.log(`\n   📧 Starting notification phase...`);
          try {
            if (result.logIds && result.logIds.length > 0) {
              console.log(`   📧 Sending notifications for ${result.logIds.length} newly created log(s)...`);
              const notificationResult = await sendNotificationsForLogs(result.logIds);
              console.log(`   📧 Notifications sent: ${notificationResult.sent}, failed: ${notificationResult.failed}`);
              if (notificationResult.errors.length > 0) {
                notificationResult.errors.forEach((err) => {
                  console.log(`      ⚠️  Log ${err.logId}: ${err.error}`);
                });
              }
            } else {
              console.log(`   📧 No log IDs returned, using fallback timestamp method...`);
              const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
              const notificationResult = await sendNotificationsForNewLogs(tenMinutesAgo);
              console.log(`   📧 Notifications sent: ${notificationResult.sent}, failed: ${notificationResult.failed}`);
            }
          } catch (notifError) {
            console.error(`   ❌ Notification error:`, notifError);
          }
        }

        console.log(`✅ [${new Date().toISOString()}] Cron job completed`);
      } catch (error) {
        const duration = Date.now() - startTime;
        console.error(`❌ [${new Date().toISOString()}] Cron job error (${duration}ms):`, error);
      } finally {
        this.isRunning = false;
      }
    }, {
      timezone: "UTC"
    });

    console.log("✅ ModSec cron scheduler started successfully");
  }

  /**
   * Stop the cron scheduler
   */
  stop(): void {
    if (this.task) {
      this.task.stop();
      this.task = null;
      console.log("⏹️  ModSec cron scheduler stopped");
    }
  }

  /**
   * Get scheduler status
   */
  getStatus(): { running: boolean; isProcessing: boolean } {
    return {
      running: this.task !== null,
      isProcessing: this.isRunning,
    };
  }
}

// Export singleton instance
export const modsecCronScheduler = new ModsecCronScheduler();

