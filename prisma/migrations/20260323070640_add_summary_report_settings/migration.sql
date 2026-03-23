-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "summaryReportEmails" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "summaryReportEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "summaryReportFrequency" TEXT NOT NULL DEFAULT 'daily';
