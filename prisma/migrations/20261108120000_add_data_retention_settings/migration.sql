-- Per-organization data retention. Defaults keep one month of data.
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "logRetentionDays" INTEGER NOT NULL DEFAULT 30;
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "rawRetentionDays" INTEGER NOT NULL DEFAULT 30;
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "retentionLastRunAt" TIMESTAMP(3);
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "retentionLastLogsDeleted" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "retentionLastRawDeleted" INTEGER NOT NULL DEFAULT 0;

-- Database-level guard rails matching src/services/dataRetentionPolicy.ts.
-- Organized logs: 7 days to 1 year. Raw landing JSON: 7 days to 3 months.
ALTER TABLE "Organization" DROP CONSTRAINT IF EXISTS "Organization_logRetentionDays_range";
ALTER TABLE "Organization"
  ADD CONSTRAINT "Organization_logRetentionDays_range"
  CHECK ("logRetentionDays" BETWEEN 7 AND 365);

ALTER TABLE "Organization" DROP CONSTRAINT IF EXISTS "Organization_rawRetentionDays_range";
ALTER TABLE "Organization"
  ADD CONSTRAINT "Organization_rawRetentionDays_range"
  CHECK ("rawRetentionDays" BETWEEN 7 AND 90);
