-- AlterTable
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "summaryReportFrequency" TEXT NOT NULL DEFAULT 'daily';
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "summaryReportEnabled" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "summaryReportEmails" TEXT[] DEFAULT ARRAY[]::TEXT[];
