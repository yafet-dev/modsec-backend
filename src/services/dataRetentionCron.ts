import * as cron from "node-cron";
import { isDataRetentionRunning, runDataRetention } from "./dataRetentionJob";

const DEFAULT_SCHEDULE = "30 3 * * *";

let task: cron.ScheduledTask | null = null;

function scheduleFromEnv(): string {
  return process.env.DATA_RETENTION_CRON_SCHEDULE || DEFAULT_SCHEDULE;
}

function enabledFromEnv(): boolean {
  return process.env.ENABLE_DATA_RETENTION_CRON !== "false";
}

/** Reported to the settings page so admins know when cleanup happens. */
export function getDataRetentionSchedule(): {
  enabled: boolean;
  cron: string;
  timezone: "UTC";
} {
  return { enabled: enabledFromEnv(), cron: scheduleFromEnv(), timezone: "UTC" };
}

/**
 * Daily cleanup of logs and raw landing data past each organization's
 * retention.
 * Env: ENABLE_DATA_RETENTION_CRON (default on),
 *      DATA_RETENTION_CRON_SCHEDULE (default "30 3 * * *" = 03:30 UTC daily).
 */
export function startDataRetentionCron(): void {
  if (!enabledFromEnv()) {
    console.log("⏸️  Data retention cron disabled (ENABLE_DATA_RETENTION_CRON=false)");
    return;
  }

  const schedule = scheduleFromEnv();
  if (!cron.validate(schedule)) {
    console.error(`❌ Invalid DATA_RETENTION_CRON_SCHEDULE: ${schedule}`);
    return;
  }

  console.log(`🧹 Data retention cleanup cron: ${schedule} (UTC)`);

  task = cron.schedule(
    schedule,
    async () => {
      if (isDataRetentionRunning()) {
        console.log("[data-retention] Previous cleanup still running, skipping this run");
        return;
      }
      try {
        const result = await runDataRetention(new Date());
        const seconds = (
          (result.finishedAt.getTime() - result.startedAt.getTime()) /
          1000
        ).toFixed(1);
        console.log(
          `[data-retention] Deleted ${result.logsDeleted} logs and ${result.rawDeleted} raw events in ${seconds}s`
        );
        for (const error of result.errors) {
          console.error(`[data-retention] ${error}`);
        }
      } catch (error) {
        console.error("[data-retention]", error);
      }
    },
    { timezone: "UTC" }
  );
}

export function stopDataRetentionCron(): void {
  if (task) {
    task.stop();
    task = null;
  }
}
