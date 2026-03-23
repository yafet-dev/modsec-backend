import * as cron from "node-cron";
import { runSummaryReportCron } from "./summaryReportJob";

let task: cron.ScheduledTask | null = null;

/**
 * Schedules periodic WAF summary emails (per org / per domain).
 * Env: ENABLE_SUMMARY_REPORT_CRON (default on), SUMMARY_REPORT_CRON_SCHEDULE (default "0 * * * *" = hourly).
 */
export function startSummaryReportCron(): void {
  if (process.env.ENABLE_SUMMARY_REPORT_CRON === "false") {
    console.log("⏸️  Summary report cron disabled (ENABLE_SUMMARY_REPORT_CRON=false)");
    return;
  }

  const schedule = process.env.SUMMARY_REPORT_CRON_SCHEDULE || "0 * * * *";

  if (!cron.validate(schedule)) {
    console.error(`❌ Invalid SUMMARY_REPORT_CRON_SCHEDULE: ${schedule}`);
    return;
  }

  console.log(`📧 Summary report email cron: ${schedule} (UTC)`);

  task = cron.schedule(schedule, async () => {
    try {
      await runSummaryReportCron(new Date());
    } catch (e) {
      console.error("[summary-report cron]", e);
    }
  });
}

export function stopSummaryReportCron(): void {
  if (task) {
    task.stop();
    task = null;
  }
}
