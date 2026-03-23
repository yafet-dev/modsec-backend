import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import {
  getLast7DaysWindow,
  sendSummaryReportsForOrganization,
} from "../services/summaryReportJob";

const router = Router();

const ALLOWED_FREQ = new Set(["hourly", "daily", "weekly", "monthly"]);

async function requireOrgAdmin(
  token: string | undefined,
  organizationId: string
): Promise<
  | { ok: true; userId: string }
  | { ok: false; status: number; message: string }
> {
  if (!token) {
    return { ok: false, status: 401, message: "No token provided" };
  }

  const {
    data: { user: supabaseUser },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !supabaseUser) {
    return { ok: false, status: 401, message: "Invalid or expired token" };
  }

  const dbUser = await prisma.user.findUnique({
    where: { email: supabaseUser.email! },
  });

  if (!dbUser) {
    return { ok: false, status: 404, message: "User not found" };
  }

  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId,
      userId: dbUser.id,
      status: "verified",
      role: "admin",
    },
  });

  if (!membership) {
    return {
      ok: false,
      status: 403,
      message: "Only organization admins can manage summary reports",
    };
  }

  return { ok: true, userId: dbUser.id };
}

/**
 * POST /api/organizations/:organizationId/summary-report/send-now
 * One-time 7-day WAF report (one email per domain). Body optional: { emails?: string[] }.
 */
router.post(
  "/:organizationId/summary-report/send-now",
  async (req: Request, res: Response) => {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader?.replace("Bearer ", "");
      const { organizationId } = req.params;

      const auth = await requireOrgAdmin(token, organizationId);
      if (!auth.ok) {
        return res.status(auth.status).json({ message: auth.message });
      }

      const org = await prisma.organization.findUnique({
        where: { id: organizationId },
      });

      if (!org) {
        return res.status(404).json({ message: "Organization not found" });
      }

      const body = req.body as { emails?: string[] } | undefined;
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      let recipients: string[];

      if (body?.emails !== undefined) {
        if (!Array.isArray(body.emails)) {
          return res.status(400).json({ message: "emails must be an array" });
        }
        for (const e of body.emails) {
          if (typeof e !== "string" || !emailRegex.test(e)) {
            return res.status(400).json({ message: "Invalid email in list" });
          }
        }
        recipients = body.emails;
      } else {
        recipients = org.summaryReportEmails.filter(Boolean);
      }

      if (recipients.length === 0) {
        return res.status(400).json({
          message:
            "Add at least one recipient email (save settings or pass emails in the request body)",
        });
      }

      if (org.domains.length === 0) {
        return res.status(400).json({ message: "No domains configured for this organization" });
      }

      const window = getLast7DaysWindow(new Date());
      const { sent, errors } = await sendSummaryReportsForOrganization(org, window, {
        recipients,
      });

      if (sent === 0 && errors.length > 0) {
        return res.status(502).json({
          message: errors.join("; ") || "Failed to send report",
          sent: 0,
        });
      }

      return res.json({
        sent,
        period: {
          start: window.start.toISOString(),
          end: window.end.toISOString(),
          label: window.periodLabel,
        },
        errors: errors.length ? errors : undefined,
      });
    } catch (e: unknown) {
      console.error("POST summary-report/send-now:", e);
      return res.status(500).json({ message: "Failed to send report" });
    }
  }
);

router.patch("/:organizationId/summary-report", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");
    const { organizationId } = req.params;

    const auth = await requireOrgAdmin(token, organizationId);
    if (!auth.ok) {
      return res.status(auth.status).json({ message: auth.message });
    }

    const { enabled, frequency, emails } = req.body as {
      enabled?: boolean;
      frequency?: string;
      emails?: string[];
    };

    if (frequency !== undefined && !ALLOWED_FREQ.has(frequency)) {
      return res.status(400).json({
        message: "frequency must be one of: hourly, daily, weekly, monthly",
      });
    }

    if (emails !== undefined) {
      if (!Array.isArray(emails)) {
        return res.status(400).json({ message: "emails must be an array" });
      }
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      for (const e of emails) {
        if (typeof e !== "string" || !emailRegex.test(e)) {
          return res.status(400).json({ message: "Invalid email in list" });
        }
      }
    }

    if (enabled === true && emails !== undefined && emails.length === 0) {
      return res.status(400).json({
        message: "Add at least one email when enabling summary reports",
      });
    }

    const updated = await prisma.organization.update({
      where: { id: organizationId },
      data: {
        ...(typeof enabled === "boolean" && { summaryReportEnabled: enabled }),
        ...(frequency !== undefined && { summaryReportFrequency: frequency }),
        ...(emails !== undefined && { summaryReportEmails: emails }),
      },
    });

    return res.json({
      summaryReportEnabled: updated.summaryReportEnabled,
      summaryReportFrequency: updated.summaryReportFrequency,
      summaryReportEmails: updated.summaryReportEmails,
    });
  } catch (e: unknown) {
    console.error("PATCH summary-report:", e);
    return res.status(500).json({ message: "Failed to update summary report settings" });
  }
});

export { router as summaryReportRoutes };
