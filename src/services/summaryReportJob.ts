import fs from "fs";
import path from "path";
import type { Organization } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { emailService } from "../lib/email";
import { buildSummaryReportHtml } from "./summaryReportHtml";

const LOGO_CID = "zergaw-summary-logo";

export function getSummaryReportLogoPath(): string {
  const fromEnv = process.env.SUMMARY_REPORT_LOGO_PATH;
  if (fromEnv) return fromEnv;
  return path.join(process.cwd(), "assets", "Logo-blue.png");
}

/** Whether this cron tick should send for the given frequency (UTC). */
export function shouldSendForFrequency(
  now: Date,
  frequency: string
): boolean {
  const h = now.getUTCHours();
  const m = now.getUTCMinutes();
  const dow = now.getUTCDay(); // 0 Sun .. 1 Mon
  const dom = now.getUTCDate();

  if (m !== 0) return false;

  switch (frequency) {
    case "hourly":
      return true;
    case "daily":
      return h === 8;
    case "weekly":
      return dow === 1 && h === 8;
    case "monthly":
      return dom === 1 && h === 8;
    default:
      return h === 8;
  }
}

export function getReportWindow(
  frequency: string,
  now: Date
): { start: Date; end: Date; periodLabel: string } {
  if (frequency === "hourly") {
    const end = new Date(now);
    const start = new Date(end.getTime() - 60 * 60 * 1000);
    return { start, end, periodLabel: "Hourly" };
  }

  if (frequency === "daily") {
    const y = new Date(now);
    y.setUTCDate(y.getUTCDate() - 1);
    const start = new Date(
      Date.UTC(y.getUTCFullYear(), y.getUTCMonth(), y.getUTCDate(), 0, 0, 0, 0)
    );
    const end = new Date(
      Date.UTC(y.getUTCFullYear(), y.getUTCMonth(), y.getUTCDate(), 23, 59, 59, 999)
    );
    return { start, end, periodLabel: "Daily" };
  }

  if (frequency === "weekly") {
    const end = new Date(now);
    end.setUTCDate(end.getUTCDate() - 1);
    end.setUTCHours(23, 59, 59, 999);
    const start = new Date(end);
    start.setUTCDate(start.getUTCDate() - 6);
    start.setUTCHours(0, 0, 0, 0);
    return { start, end, periodLabel: "Weekly" };
  }

  if (frequency === "monthly") {
    const year = now.getUTCFullYear();
    const month = now.getUTCMonth();
    const start = new Date(Date.UTC(year, month - 1, 1, 0, 0, 0, 0));
    const end = new Date(Date.UTC(year, month, 0, 23, 59, 59, 999));
    return { start, end, periodLabel: "Monthly" };
  }

  const y = new Date(now);
  y.setUTCDate(y.getUTCDate() - 1);
  const start = new Date(
    Date.UTC(y.getUTCFullYear(), y.getUTCMonth(), y.getUTCDate(), 0, 0, 0, 0)
  );
  const end = new Date(
    Date.UTC(y.getUTCFullYear(), y.getUTCMonth(), y.getUTCDate(), 23, 59, 59, 999)
  );
  return { start, end, periodLabel: "Daily" };
}

/** Rolling 7-day window ending now (for one-time / sample sends). */
export function getLast7DaysWindow(now: Date = new Date()): {
  start: Date;
  end: Date;
  periodLabel: string;
} {
  const end = new Date(now);
  const start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  return {
    start,
    end,
    periodLabel: "Last 7 days (one-time)",
  };
}

async function fetchLogsForDomain(
  organizationId: string,
  domain: string,
  start: Date,
  end: Date
) {
  return prisma.log.findMany({
    where: {
      organizationId,
      host: domain,
      timestamp: { gte: start, lte: end },
    },
    orderBy: { timestamp: "desc" },
  });
}

/**
 * Send one HTML email per domain to all configured recipients (or optional override list).
 */
export async function sendSummaryReportsForOrganization(
  org: Pick<
    Organization,
    | "id"
    | "name"
    | "domains"
    | "summaryReportEmails"
    | "summaryReportFrequency"
  >,
  window: { start: Date; end: Date; periodLabel: string },
  options?: { recipients?: string[] }
): Promise<{ sent: number; errors: string[] }> {
  const errors: string[] = [];
  let sent = 0;

  if (!emailService.isConfigured()) {
    errors.push("SMTP not configured");
    return { sent: 0, errors };
  }

  const recipients = (options?.recipients ?? org.summaryReportEmails).filter(Boolean);
  if (recipients.length === 0) {
    return { sent: 0, errors: ["No recipient emails"] };
  }

  const logoPath = getSummaryReportLogoPath();
  const useLogo = fs.existsSync(logoPath);

  for (const domain of org.domains) {
    const logs = await fetchLogsForDomain(org.id, domain, window.start, window.end);
    const html = buildSummaryReportHtml({
      domain,
      organizationName: org.name,
      logs,
      startDate: window.start,
      endDate: window.end,
      periodLabel: window.periodLabel,
      logoCid: useLogo ? LOGO_CID : null,
    });

    const subject = `${window.periodLabel} WAF report: ${domain} — ${org.name}`;

    const result = useLogo
      ? await emailService.sendEmailWithInlineImage({
          to: recipients,
          subject,
          html,
          inlineImage: { path: logoPath, cid: LOGO_CID, filename: "Logo-blue.png" },
        })
      : await emailService.sendEmail({ to: recipients, subject, html });

    if (result.success) sent += 1;
    else errors.push(`${domain}: ${result.error || "send failed"}`);
  }

  return { sent, errors };
}

/**
 * Run from cron: process all organizations with summary reports enabled.
 */
export async function runSummaryReportCron(now: Date = new Date()): Promise<void> {
  const orgs = (
    await prisma.organization.findMany({
      where: { summaryReportEnabled: true },
    })
  ).filter((o) => o.summaryReportEmails.length > 0);

  for (const org of orgs) {
    const freq = org.summaryReportFrequency || "daily";
    if (!shouldSendForFrequency(now, freq)) continue;

    const window = getReportWindow(freq, now);
    try {
      const { sent, errors } = await sendSummaryReportsForOrganization(org, window);
      if (sent > 0 || errors.length) {
        console.log(
          `[summary-report] org=${org.name} (${org.id}) sent=${sent} errors=${errors.join("; ") || "none"}`
        );
      }
    } catch (e) {
      console.error(`[summary-report] org ${org.id}:`, e);
    }
  }
}
