import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import type { Log } from "@prisma/client";

const router = Router();

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * @swagger
 * tags:
 *   name: Notification Settings
 *   description: Notification settings management endpoints
 */

/**
 * Helper function to verify user has access to organization
 */
async function verifyOrganizationAccess(
  userId: string,
  organizationId: string
): Promise<{ hasAccess: boolean; isAdmin: boolean }> {
  // Check if user is super_admin
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { role: true },
  });

  if (user?.role === "super_admin") {
    return { hasAccess: true, isAdmin: true };
  }

  // Check if user is a member of the organization with admin role
  const membership = await prisma.organizationMember.findFirst({
    where: {
      userId,
      organizationId,
      status: "verified",
      role: "admin",
    },
  });

  return {
    hasAccess: !!membership,
    isAdmin: !!membership,
  };
}

/**
 * @swagger
 * /api/organizations/{id}/notification-settings:
 *   get:
 *     summary: Get all notification settings for an organization
 *     tags: [Notification Settings]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *     responses:
 *       200:
 *         description: List of notification settings
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 organizationId:
 *                   type: string
 *                   format: uuid
 *                 settings:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/NotificationSettings'
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 */
router.get("/:id/notification-settings", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;

    // Verify organization exists
    const organization = await prisma.organization.findUnique({
      where: { id },
      select: { id: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    // Verify user has access
    const { hasAccess } = await verifyOrganizationAccess(user.id, id);

    if (!hasAccess) {
      return res.status(403).json({
        message: "You do not have access to this organization",
      });
    }

    // Get all notification settings for the organization
    const settings = await prisma.notificationSettings.findMany({
      where: { organizationId: id },
      orderBy: { createdAt: "desc" },
    });

    return res.json({
      organizationId: id,
      settings,
    });
  } catch (error) {
    console.error("Error fetching notification settings:", error);
    return res.status(500).json({
      message: "Failed to fetch notification settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/notification-settings:
 *   post:
 *     summary: Create or update notification settings
 *     tags: [Notification Settings]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - notificationType
 *               - domainFilter
 *               - severityFilter
 *             properties:
 *               notificationType:
 *                 type: string
 *                 enum: [email, telegram]
 *               emailList:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of email addresses (required if notificationType is email)
 *               telegramChatId:
 *                 type: string
 *                 description: Telegram chat ID (required if notificationType is telegram)
 *               domainFilter:
 *                 type: string
 *                 enum: [all, specific]
 *               selectedDomains:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of domain names (required if domainFilter is specific)
 *               severityFilter:
 *                 type: string
 *                 enum: [all, critical, high, low]
 *               enabled:
 *                 type: boolean
 *                 default: true
 *     responses:
 *       200:
 *         description: Notification settings created/updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/NotificationSettings'
 *       400:
 *         description: Invalid request data
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 */
router.post("/:id/notification-settings", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;
    const {
      notificationType,
      emailList,
      telegramChatId,
      domainFilter,
      selectedDomains: selectedDomainsInput,
      severityFilter,
      enabled = true,
    } = req.body;
    
    // Use a mutable variable for selectedDomains
    let selectedDomains = selectedDomainsInput;

    // Validate required fields
    if (!notificationType || !["email", "telegram"].includes(notificationType)) {
      return res.status(400).json({
        message: "notificationType is required and must be 'email' or 'telegram'",
      });
    }

    if (!domainFilter || !["all", "specific"].includes(domainFilter)) {
      return res.status(400).json({
        message: "domainFilter is required and must be 'all' or 'specific'",
      });
    }

    if (!severityFilter || !["all", "critical", "high", "low"].includes(severityFilter)) {
      return res.status(400).json({
        message: "severityFilter is required and must be 'all', 'critical', 'high', or 'low'",
      });
    }

    // Validate notification type specific fields
    if (notificationType === "email") {
      if (!emailList || !Array.isArray(emailList) || emailList.length === 0) {
        return res.status(400).json({
          message: "emailList is required and must contain at least one email address",
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      for (const email of emailList) {
        if (!emailRegex.test(email)) {
          return res.status(400).json({
            message: `Invalid email format: ${email}`,
          });
        }
      }
    }
    // Telegram: telegramChatId is set via the connect flow, not required in request body

    // Validate domain filter
    if (domainFilter === "specific") {
      if (!selectedDomains || !Array.isArray(selectedDomains) || selectedDomains.length === 0) {
        return res.status(400).json({
          message: "selectedDomains is required and must contain at least one domain when domainFilter is 'specific'",
        });
      }

      // Verify organization exists and get its domains
      const organization = await prisma.organization.findUnique({
        where: { id },
        select: { id: true, domains: true },
      });

      if (!organization) {
        return res.status(404).json({
          message: "Organization not found",
        });
      }

      // Verify user has access
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);

      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to manage notification settings",
        });
      }

      // Validate that selected domains belong to the organization
      const normalizedOrgDomains = organization.domains.map((d) => d.toLowerCase().trim());
      for (const domain of selectedDomains) {
        if (!normalizedOrgDomains.includes(domain.toLowerCase().trim())) {
          return res.status(400).json({
            message: `Domain ${domain} does not belong to this organization`,
          });
        }
      }
    } else {
      // Verify organization exists and get its domains
      const organization = await prisma.organization.findUnique({
        where: { id },
        select: { id: true, domains: true },
      });

      if (!organization) {
        return res.status(404).json({
          message: "Organization not found",
        });
      }

      // Verify user has access
      const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);

      if (!hasAccess || !isAdmin) {
        return res.status(403).json({
          message: "You must be an admin of this organization to manage notification settings",
        });
      }

      // When domainFilter is "all", populate selectedDomains with all organization domains
      if (domainFilter === "all") {
        selectedDomains = organization.domains;
      }
    }

    // Determine final selectedDomains value
    const finalSelectedDomains = domainFilter === "all" 
      ? selectedDomains  // Already populated with all organization domains
      : domainFilter === "specific" 
        ? selectedDomains  // User-selected domains
        : [];  // Fallback (shouldn't happen)

    // For telegram type, carry over chat ID from existing connected setting if not provided
    let finalTelegramChatId: string | null = null;
    let finalTelegramEnabled = false;
    let finalTelegramConnectedAt: Date | null = null;
    if (notificationType === "telegram") {
      if (telegramChatId) {
        finalTelegramChatId = telegramChatId;
        finalTelegramEnabled = true;
        finalTelegramConnectedAt = new Date();
      } else {
        // Check if there's an existing connected telegram setting for this org
        const existingTelegram = await prisma.notificationSettings.findFirst({
          where: {
            organizationId: id,
            notificationType: "telegram",
            telegramEnabled: true,
            telegramChatId: { not: null },
          },
        });
        if (existingTelegram) {
          finalTelegramChatId = existingTelegram.telegramChatId;
          finalTelegramEnabled = true;
          finalTelegramConnectedAt = existingTelegram.telegramConnectedAt;
        }
      }
    }

    // Create notification settings
    const settings = await prisma.notificationSettings.create({
      data: {
        organizationId: id,
        notificationType,
        emailList: notificationType === "email" ? emailList : [],
        telegramChatId: finalTelegramChatId,
        telegramEnabled: finalTelegramEnabled,
        telegramConnectedAt: finalTelegramConnectedAt,
        domainFilter,
        selectedDomains: finalSelectedDomains,
        severityFilter,
        enabled,
      },
    });

    return res.json(settings);
  } catch (error) {
    console.error("Error creating notification settings:", error);
    return res.status(500).json({
      message: "Failed to create notification settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/notification-settings/{settingsId}:
 *   put:
 *     summary: Update notification settings
 *     tags: [Notification Settings]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *       - in: path
 *         name: settingsId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Notification settings ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               notificationType:
 *                 type: string
 *                 enum: [email, telegram]
 *               emailList:
 *                 type: array
 *                 items:
 *                   type: string
 *               telegramChatId:
 *                 type: string
 *               domainFilter:
 *                 type: string
 *                 enum: [all, specific]
 *               selectedDomains:
 *                 type: array
 *                 items:
 *                   type: string
 *               severityFilter:
 *                 type: string
 *                 enum: [all, critical, high, low]
 *               enabled:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Notification settings updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/NotificationSettings'
 *       400:
 *         description: Invalid request data
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Notification settings not found
 */
router.put("/:id/notification-settings/:settingsId", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id, settingsId } = req.params;
    const {
      notificationType,
      emailList,
      telegramChatId,
      domainFilter,
      selectedDomains,
      severityFilter,
      enabled,
    } = req.body;

    // Verify notification settings exist and belong to organization
    const existingSettings = await prisma.notificationSettings.findFirst({
      where: {
        id: settingsId,
        organizationId: id,
      },
    });

    if (!existingSettings) {
      return res.status(404).json({
        message: "Notification settings not found",
      });
    }

    // Verify user has access
    const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);

    if (!hasAccess || !isAdmin) {
      return res.status(403).json({
        message: "You must be an admin of this organization to manage notification settings",
      });
    }

    // Validate fields if provided
    if (notificationType && !["email", "telegram"].includes(notificationType)) {
      return res.status(400).json({
        message: "notificationType must be 'email' or 'telegram'",
      });
    }

    if (domainFilter && !["all", "specific"].includes(domainFilter)) {
      return res.status(400).json({
        message: "domainFilter must be 'all' or 'specific'",
      });
    }

    if (severityFilter && !["all", "critical", "high", "low"].includes(severityFilter)) {
      return res.status(400).json({
        message: "severityFilter must be 'all', 'critical', 'high', or 'low'",
      });
    }

    // Validate notification type specific fields
    const finalNotificationType = notificationType || existingSettings.notificationType;
    if (finalNotificationType === "email") {
      if (emailList !== undefined) {
        if (!Array.isArray(emailList) || emailList.length === 0) {
          return res.status(400).json({
            message: "emailList must contain at least one email address",
          });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        for (const email of emailList) {
          if (!emailRegex.test(email)) {
            return res.status(400).json({
              message: `Invalid email format: ${email}`,
            });
          }
        }
      }
    }
    // Telegram: telegramChatId is set via the connect flow, not validated here

    // Validate domain filter
    const finalDomainFilter = domainFilter || existingSettings.domainFilter;
    let finalSelectedDomains = selectedDomains;
    
    if (finalDomainFilter === "specific") {
      if (selectedDomains !== undefined) {
        if (!Array.isArray(selectedDomains) || selectedDomains.length === 0) {
          return res.status(400).json({
            message: "selectedDomains must contain at least one domain when domainFilter is 'specific'",
          });
        }

        // Get organization domains
        const organization = await prisma.organization.findUnique({
          where: { id },
          select: { domains: true },
        });

        if (organization) {
          const normalizedOrgDomains = organization.domains.map((d) => d.toLowerCase().trim());
          for (const domain of selectedDomains) {
            if (!normalizedOrgDomains.includes(domain.toLowerCase().trim())) {
              return res.status(400).json({
                message: `Domain ${domain} does not belong to this organization`,
              });
            }
          }
        }
      } else {
        // If selectedDomains is not provided but domainFilter is "specific", keep existing
        finalSelectedDomains = existingSettings.selectedDomains;
      }
    } else if (finalDomainFilter === "all") {
      // When domainFilter is "all", populate selectedDomains with all organization domains
      const organization = await prisma.organization.findUnique({
        where: { id },
        select: { domains: true },
      });

      if (organization) {
        finalSelectedDomains = organization.domains;
      } else {
        finalSelectedDomains = [];
      }
    }

    // Update notification settings
    const updatedSettings = await prisma.notificationSettings.update({
      where: { id: settingsId },
      data: {
        ...(notificationType && { notificationType }),
        ...(emailList !== undefined && {
          emailList: finalNotificationType === "email" ? emailList : [],
        }),
        ...(telegramChatId !== undefined && {
          telegramChatId: finalNotificationType === "telegram" ? telegramChatId : null,
        }),
        ...(domainFilter && { domainFilter }),
        ...(finalSelectedDomains !== undefined && {
          selectedDomains: finalSelectedDomains,
        }),
        ...(severityFilter && { severityFilter }),
        ...(enabled !== undefined && { enabled }),
      },
    });

    return res.json(updatedSettings);
  } catch (error) {
    console.error("Error updating notification settings:", error);
    return res.status(500).json({
      message: "Failed to update notification settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/notification-settings/{settingsId}:
 *   delete:
 *     summary: Delete notification settings
 *     tags: [Notification Settings]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *       - in: path
 *         name: settingsId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Notification settings ID
 *     responses:
 *       200:
 *         description: Notification settings deleted successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Notification settings not found
 */
router.delete("/:id/notification-settings/:settingsId", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id, settingsId } = req.params;

    // Verify notification settings exist and belong to organization
    const existingSettings = await prisma.notificationSettings.findFirst({
      where: {
        id: settingsId,
        organizationId: id,
      },
    });

    if (!existingSettings) {
      return res.status(404).json({
        message: "Notification settings not found",
      });
    }

    // Verify user has access
    const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);

    if (!hasAccess || !isAdmin) {
      return res.status(403).json({
        message: "You must be an admin of this organization to manage notification settings",
      });
    }

    // Delete notification settings
    await prisma.notificationSettings.delete({
      where: { id: settingsId },
    });

    return res.json({
      message: "Notification settings deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting notification settings:", error);
    return res.status(500).json({
      message: "Failed to delete notification settings",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

/**
 * @swagger
 * /api/organizations/{id}/notification-settings/send-sample:
 *   post:
 *     summary: Send a sample notification email
 *     tags: [Notification Settings]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Organization ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - notificationType
 *             properties:
 *               notificationType:
 *                 type: string
 *                 enum: [email, telegram]
 *               emailList:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of email addresses (required if notificationType is email)
 *     responses:
 *       200:
 *         description: Sample notification sent successfully
 *       400:
 *         description: Invalid request data
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Organization not found
 */
router.post("/:id/notification-settings/send-sample", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    // Verify token
    const {
      data: { user: supabaseUser },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !supabaseUser) {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: supabaseUser.email! },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const { id } = req.params;
    const { notificationType, emailList } = req.body;

    // Validate notification type
    if (!notificationType || !["email", "telegram"].includes(notificationType)) {
      return res.status(400).json({
        message: "notificationType is required and must be 'email' or 'telegram'",
      });
    }

    // Verify organization exists
    const organization = await prisma.organization.findUnique({
      where: { id },
      select: { id: true, name: true, domains: true },
    });

    if (!organization) {
      return res.status(404).json({
        message: "Organization not found",
      });
    }

    // Verify user has access
    const { hasAccess, isAdmin } = await verifyOrganizationAccess(user.id, id);

    if (!hasAccess || !isAdmin) {
      return res.status(403).json({
        message: "You must be an admin of this organization to send sample notifications",
      });
    }

    // Generate sample log
    const { generateSampleLog, generateAttackNotificationEmail } = await import("../services/notificationService");
    const sampleLog = generateSampleLog(organization);

    // ─── TELEGRAM SAMPLE ───
    if (notificationType === "telegram") {
      // Find connected telegram setting for this org
      const telegramSetting = await prisma.notificationSettings.findFirst({
        where: {
          organizationId: id,
          notificationType: "telegram",
          telegramEnabled: true,
          telegramChatId: { not: null },
        },
      });

      if (!telegramSetting || !telegramSetting.telegramChatId) {
        return res.status(400).json({
          message: "Telegram is not connected. Please connect Telegram first.",
        });
      }

      const { sendTelegramMessage, sendMessageWithInlineKeyboard, generateBanTokenUrl } = await import("../services/telegramService");

      const host = sampleLog.host || "example.com";
      const severity = (sampleLog.severity || "CRITICAL").toUpperCase();
      const action = sampleLog.action === "blocked" ? "🛑 Blocked" : "⚠️ Warning";
      const sampleIp = sampleLog.clientIp || "192.168.1.100";

      // Generate ban token URL for sample
      const banUrl = await generateBanTokenUrl(id, sampleIp, [host]);

      const text = [
        `🚨 <b>[SAMPLE] WAF Alert</b>`,
        ``,
        `<b>Domain:</b> ${escapeHtml(host)}`,
        `<b>Severity:</b> ${severity}`,
        `<b>Action:</b> ${action}`,
        `<b>Rule:</b> ${escapeHtml(sampleLog.ruleId || "N/A")} — ${escapeHtml(sampleLog.rule || "N/A")}`,
        `<b>IP:</b> <code>${escapeHtml(sampleIp)}</code>`,
        `<b>Method:</b> ${escapeHtml(sampleLog.method || "GET")}`,
        `<b>URI:</b> <code>${escapeHtml(sampleLog.requestUrl || "/")}</code>`,
        `<b>Time:</b> ${sampleLog.timestamp ? new Date(sampleLog.timestamp).toISOString() : new Date().toISOString()}`,
        ``,
        `<b>Message:</b> ${escapeHtml(sampleLog.message || "Attack detected")}`,
        ``,
        `<i>This is a sample notification to test your Telegram integration.</i>`,
      ].join("\n");

      try {
        if (banUrl) {
          await sendMessageWithInlineKeyboard(
            telegramSetting.telegramChatId,
            text,
            [{ text: "🚫 Ban IP Address", url: banUrl }]
          );
        } else {
          await sendTelegramMessage(telegramSetting.telegramChatId, text);
        }
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : "Unknown error";
        return res.status(500).json({
          message: "Failed to send sample Telegram notification",
          error: errMsg,
        });
      }

      return res.json({
        message: "Sample Telegram notification sent successfully",
        sentTo: [`telegram:${telegramSetting.telegramChatId}`],
      });
    }

    // ─── EMAIL SAMPLE ───
    // Validate email list
    if (!emailList || !Array.isArray(emailList) || emailList.length === 0) {
      return res.status(400).json({
        message: "emailList is required and must contain at least one email address",
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    for (const email of emailList) {
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          message: `Invalid email format: ${email}`,
        });
      }
    }

    // Check if email service is configured
    const { emailService } = await import("../lib/email");
    if (!emailService.isConfigured()) {
      return res.status(500).json({
        message: "Email service is not configured. Please configure SMTP settings in your environment.",
      });
    }

    // Generate ban token URL for sample
    const { generateBanTokenUrl } = await import("../services/notificationService");
    const sampleIp = sampleLog.clientIp || "192.168.1.100";
    const sampleHost = sampleLog.host || "example.com";
    const banUrl = await generateBanTokenUrl(id, sampleIp, [sampleHost]);

    const html = generateAttackNotificationEmail(sampleLog as Log, organization, banUrl);
    const severity = (sampleLog.severity || "CRITICAL").toUpperCase();
    const subject = `[SAMPLE] 🚨 ${severity} Security Alert: ${sampleLog.rule || "Attack Detected"} on ${sampleHost}`;

    const result = await emailService.sendEmail({
      to: emailList,
      subject,
      html,
    });

    if (!result.success) {
      return res.status(500).json({
        message: "Failed to send sample notification",
        error: result.error,
      });
    }

    return res.json({
      message: "Sample notification sent successfully",
      sentTo: emailList,
    });
  } catch (error) {
    console.error("Error sending sample notification:", error);
    return res.status(500).json({
      message: "Failed to send sample notification",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

export { router as notificationSettingsRoutes };
