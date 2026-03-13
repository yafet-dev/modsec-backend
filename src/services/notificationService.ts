import { prisma } from "../lib/prisma";
import { emailService } from "../lib/email";
import { sendWafAlertToOrganization } from "./telegramService";
import type { Log, NotificationSettings, Organization } from "@prisma/client";
import crypto from "crypto";

/**
 * Generate sample log data for testing
 */
export function generateSampleLog(organization: Pick<Organization, 'id' | 'name' | 'domains'>): Partial<Log> {
  const sampleAttacks = [
    {
      action: "blocked",
      severity: "CRITICAL",
      rule: "SQL Injection Attack",
      ruleId: "942100",
      method: "POST",
      requestUrl: "/api/users/delete",
      message: "SQL Injection detected in POST parameter: id=1' OR '1'='1",
      clientIp: "192.168.1.100",
      clientPort: 54321,
    },
    {
      action: "blocked",
      severity: "HIGH",
      rule: "XSS Attack Detection",
      ruleId: "941100",
      method: "GET",
      requestUrl: "/search?q=<script>alert(1)</script>",
      message: "XSS attack detected in query parameter",
      clientIp: "203.0.113.42",
      clientPort: null,
    },
    {
      action: "warning",
      severity: "MEDIUM",
      rule: "Path Traversal Attempt",
      ruleId: "930100",
      method: "GET",
      requestUrl: "/files/../../../../etc/passwd",
      message: "Path traversal attempt detected",
      clientIp: "10.0.0.45",
      clientPort: null,
    },
  ];

  const sample = sampleAttacks[Math.floor(Math.random() * sampleAttacks.length)];
  const host = organization.domains && organization.domains.length > 0 
    ? organization.domains[0] 
    : "example.com";

  return {
    id: "sample-" + Date.now(),
    organizationId: organization.id,
    action: sample.action,
    severity: sample.severity,
    timestamp: new Date(),
    clientIp: sample.clientIp,
    clientPort: sample.clientPort || null,
    host: host,
    method: sample.method,
    requestUrl: sample.requestUrl,
    rule: sample.rule,
    ruleId: sample.ruleId,
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    message: sample.message,
    httpMethod: "HTTP/1.1",
    responseCode: sample.action === "blocked" ? 403 : 200,
    maturity: 9,
  } as Partial<Log>;
}

/**
 * Generate a temporary ban token and return the ban URL
 */
export async function generateBanTokenUrl(
  organizationId: string,
  ip: string,
  domains: string[]
): Promise<string | null> {
  try {
    // Generate secure random token
    const banToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store token
    await prisma.iPBanToken.create({
      data: {
        organizationId,
        ip,
        domains,
        token: banToken,
        expiresAt,
      },
    });

    // Use PUBLIC_BASE_URL (backend) since the ban endpoint is on the backend
    const publicBaseUrl = process.env.PUBLIC_BASE_URL;
    if (!publicBaseUrl) {
      console.error("PUBLIC_BASE_URL is not set, cannot generate ban URL");
      return null;
    }
    return `${publicBaseUrl.replace(/\/$/, "")}/api/ip-bans/ban?token=${banToken}`;
  } catch (error) {
    console.error("Error generating ban token:", error);
    return null; // Fail silently, don't block notification
  }
}

/**
 * Generate beautiful HTML email template for attack notification
 */
export function generateAttackNotificationEmail(
  log: Log | Partial<Log>,
  organization: Pick<Organization, 'id' | 'name' | 'domains'>,
  banUrl?: string | null
): string {
  const severityColors: Record<string, string> = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#f59e0b",
    LOW: "#84cc16",
  };

  const severityLabels: Record<string, string> = {
    CRITICAL: "Critical",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low",
  };

  const actionLabels: Record<string, string> = {
    blocked: "Blocked",
    warning: "Warning",
    allowed: "Allowed",
  };

  const severity = (log.severity || "LOW").toUpperCase();
  const severityColor = severityColors[severity] || "#6b7280";
  const severityLabel = severityLabels[severity] || severity;
  const actionLabel = actionLabels[log.action || "warning"] || (log.action || "warning");
  const timestamp = log.timestamp ? new Date(log.timestamp).toLocaleString() : new Date().toLocaleString();
  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Alert - ${severityLabel} Attack Detected</title>
  <style>
    /* Buttons are always stacked vertically for better email client compatibility */
  </style>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
  <table role="presentation" style="width: 100%; border-collapse: collapse;">
    <tr>
      <td style="padding: 40px 20px;">
        <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          <!-- Header -->
          <tr>
            <td style="padding: 32px 32px 24px; background: linear-gradient(135deg, #1f2937 0%, #111827 100%); border-radius: 8px 8px 0 0;">
              <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">
                🛡️ Security Alert
              </h1>
              <p style="margin: 8px 0 0; color: #d1d5db; font-size: 14px;">
                Zergaw Cloud Firewall Attack Detection
              </p>
            </td>
          </tr>

          <!-- Alert Badge -->
          <tr>
            <td style="padding: 24px 32px;">
              <div style="display: inline-block; padding: 8px 16px; background-color: ${severityColor}15; border-left: 4px solid ${severityColor}; border-radius: 4px;">
                <span style="color: ${severityColor}; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">
                  ${severityLabel} Severity - ${actionLabel}
                </span>
              </div>
            </td>
          </tr>

          <!-- Attack Details -->
          <tr>
            <td style="padding: 0 32px 24px;">
              <h2 style="margin: 0 0 16px; color: #111827; font-size: 18px; font-weight: 600;">
                Attack Details
              </h2>
              <table role="presentation" style="width: 100%; border-collapse: collapse; background-color: #f9fafb; border-radius: 6px; overflow: hidden;">
                <tr>
                  <td style="padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Domain</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px; font-family: 'Courier New', monospace;">
                      ${log.host}
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Attack Type</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px;">
                      ${log.rule || "Unknown"}
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Rule ID</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px; font-family: 'Courier New', monospace;">
                      ${log.ruleId || "N/A"}
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Request Method</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px; font-family: 'Courier New', monospace;">
                      ${log.method} ${log.requestUrl}
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Source IP</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px; font-family: 'Courier New', monospace;">
                      ${log.clientIp}${log.clientPort ? `:${log.clientPort}` : ""}
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 12px 16px; border-bottom: 1px solid #e5e7eb;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Timestamp</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px;">
                      ${timestamp}
                    </div>
                  </td>
                </tr>
                ${log.message ? `
                <tr>
                  <td style="padding: 12px 16px;">
                    <span style="color: #6b7280; font-size: 13px; font-weight: 500;">Message</span>
                    <div style="color: #111827; font-size: 14px; margin-top: 4px; background-color: #ffffff; padding: 8px; border-radius: 4px; border: 1px solid #e5e7eb; font-family: 'Courier New', monospace; word-break: break-word;">
                      ${log.message}
                    </div>
                  </td>
                </tr>
                ` : ""}
              </table>
            </td>
          </tr>

          <!-- Action Buttons -->
          <tr>
            <td style="padding: 0 32px 32px;">
              <div class="action-buttons-container" style="display: block; width: 100%; box-sizing: border-box;">
                <a href="${frontendUrl}/dashboard/logs" class="action-button" style="display: block; width: 100%; box-sizing: border-box; padding: 18px 32px; background-color: #111827; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 600; text-align: center; margin-bottom: 16px;">
                  View in Dashboard
                </a>
                ${banUrl ? `
                <a href="${banUrl}" class="action-button" style="display: block; width: 100%; box-sizing: border-box; padding: 18px 32px; background-color: #dc2626; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 600; text-align: center;">
                  🚫 Ban IP Address
                </a>
                ` : ""}
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 32px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 8px 8px;">
              <p style="margin: 0; color: #6b7280; font-size: 12px; line-height: 1.5;">
                This is an automated security alert from <strong>${organization.name}</strong>.<br>
                If you believe this is an error, please contact your system administrator.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim();
}

/**
 * Check if log matches notification settings filters
 */
function matchesNotificationFilters(
  log: Log,
  settings: NotificationSettings
): boolean {
  // Check if notifications are enabled
  if (!settings.enabled) {
    return false;
  }

  // Check severity filter
  if (settings.severityFilter !== "all") {
    const logSeverity = log.severity.toUpperCase();
    const filterSeverity = settings.severityFilter.toUpperCase();
    
    if (filterSeverity === "CRITICAL" && logSeverity !== "CRITICAL") {
      return false;
    }
    if (filterSeverity === "HIGH" && !["CRITICAL", "HIGH"].includes(logSeverity)) {
      return false;
    }
    if (filterSeverity === "LOW" && logSeverity === "CRITICAL") {
      return false; // Low filter means only low severity
    }
  }

  // Check domain filter
  if (settings.domainFilter === "specific") {
    if (!settings.selectedDomains || settings.selectedDomains.length === 0) {
      return false;
    }
    const normalizedHost = log.host.toLowerCase().trim();
    const normalizedDomains = settings.selectedDomains.map((d) => d.toLowerCase().trim());
    if (!normalizedDomains.includes(normalizedHost)) {
      return false;
    }
  }
  // If domainFilter is "all", selectedDomains should contain all org domains (already populated)

  return true;
}

/**
 * Send notifications for specific log IDs
 * This is the preferred method - sends notifications for exact logs that were just created
 */
export async function sendNotificationsForLogs(
  logIds: string[]
): Promise<{
  sent: number;
  failed: number;
  errors: Array<{ logId: string; error: string }>;
}> {
  const errors: Array<{ logId: string; error: string }> = [];
  let sent = 0;
  let failed = 0;

  console.log(`   📋 Step 1: Checking email service configuration...`);
  
  // Check if email service is configured
  if (!emailService.isConfigured()) {
    console.error(`   ❌ Email service is NOT configured!`);
    console.error(`   ❌ Please configure SMTP settings in your .env file:`);
    console.error(`      - SMTP_HOST`);
    console.error(`      - SMTP_PORT`);
    console.error(`      - SMTP_USER`);
    console.error(`      - SMTP_PASS`);
    console.error(`      - EMAIL_FROM (optional)`);
    return { sent: 0, failed: 0, errors: [] };
  }
  
  console.log(`   ✅ Email service is configured`);

  if (logIds.length === 0) {
    console.log(`   ℹ️  No log IDs provided, skipping notifications`);
    return { sent: 0, failed: 0, errors: [] };
  }

  console.log(`   📋 Step 2: Fetching ${logIds.length} log(s) from database...`);

  try {
    // Fetch the specific logs by their IDs
    const logs = await prisma.log.findMany({
      where: {
        id: {
          in: logIds,
        },
        organizationId: {
          not: null,
        },
      },
      include: {
        organization: true,
      },
    });

    if (logs.length === 0) {
      console.log(`   ⚠️  No logs found with the provided IDs`);
      return { sent: 0, failed: 0, errors: [] };
    }

    console.log(`   ✅ Found ${logs.length} log(s) in database`);
    console.log(`   📋 Step 3: Checking which organizations have notification settings...`);

    // Group logs by organization
    const logsByOrg = new Map<string, typeof logs>();
    for (const log of logs) {
      if (!log.organizationId || !log.organization) {
        console.log(`   ⚠️  Log ${log.id} has no organization, skipping`);
        continue;
      }
      
      if (!logsByOrg.has(log.organizationId)) {
        logsByOrg.set(log.organizationId, []);
      }
      logsByOrg.get(log.organizationId)!.push(log);
    }

    console.log(`   📊 Processing ${logsByOrg.size} organization(s)`);

    // Process each organization
    for (const [organizationId, orgLogs] of logsByOrg) {
      const organization = orgLogs[0].organization!;
      console.log(`   🔍 Checking organization: ${organization.name} (${organizationId})`);

      // Get all notification settings for this organization (email + telegram)
      const notificationSettings = await prisma.notificationSettings.findMany({
        where: {
          organizationId,
          enabled: true,
        },
      });

      const emailSettings = notificationSettings.filter((s) => s.notificationType === "email");
      const telegramSettings = notificationSettings.filter(
        (s) => s.notificationType === "telegram" && s.telegramEnabled && s.telegramChatId
      );

      console.log(`   📋 Found ${emailSettings.length} email + ${telegramSettings.length} telegram setting(s) for this organization`);

      if (emailSettings.length === 0 && telegramSettings.length === 0) {
        console.log(`   ⚠️  No notification settings found for organization ${organization.name}`);
        continue;
      }

      // Log notification settings details
      for (const setting of emailSettings) {
        console.log(`   📧 Email setting ${setting.id}: ${setting.emailList?.length || 0} email(s), domainFilter: ${setting.domainFilter}, severityFilter: ${setting.severityFilter}`);
      }
      for (const setting of telegramSettings) {
        console.log(`   📲 Telegram setting ${setting.id}: chat=${setting.telegramChatId}, domainFilter: ${setting.domainFilter}, severityFilter: ${setting.severityFilter}`);
      }

      // Process each log
      for (const log of orgLogs) {
        console.log(`   🔎 Processing log ${log.id}: ${log.severity} ${log.action} on ${log.host}`);
        
        // --- EMAIL notifications ---
        const matchingEmailSettings = emailSettings.filter((settings) =>
          matchesNotificationFilters(log, settings)
        );

        if (matchingEmailSettings.length > 0) {
          // Collect all unique email addresses from matching settings
          const emailAddresses = new Set<string>();
          for (const settings of matchingEmailSettings) {
            if (settings.emailList && Array.isArray(settings.emailList) && settings.emailList.length > 0) {
              settings.emailList.forEach((email) => {
                if (email && typeof email === 'string' && email.trim()) {
                  emailAddresses.add(email.trim());
                }
              });
            }
          }

          if (emailAddresses.size > 0) {
            try {
              // Generate ban token URL if we have an IP
              const banUrl = log.clientIp
                ? await generateBanTokenUrl(organizationId, log.clientIp, [log.host || "*"])
                : null;
              
              const html = generateAttackNotificationEmail(log, organization, banUrl);
              const severity = log.severity.toUpperCase();
              const subject = `🚨 ${severity} Security Alert: ${log.rule || "Attack Detected"} on ${log.host}`;

              const emailArray = Array.from(emailAddresses);
              console.log(`   📤 Sending email to: ${emailArray.join(", ")}`);

              const result = await emailService.sendEmail({
                to: emailArray,
                subject,
                html,
              });

              if (result.success) {
                sent++;
                console.log(`   ✅ Email sent for log ${log.id} to ${emailAddresses.size} recipient(s)`);
              } else {
                failed++;
                errors.push({ logId: log.id, error: result.error || "Email send error" });
                console.error(`   ❌ Email failed for log ${log.id}: ${result.error}`);
              }
            } catch (error) {
              failed++;
              const errorMessage = error instanceof Error ? error.message : "Unknown error";
              errors.push({ logId: log.id, error: errorMessage });
              console.error(`   ❌ Email error for log ${log.id}:`, error);
            }
          }
        }

        // --- TELEGRAM notifications ---
        const matchingTelegramSettings = telegramSettings.filter((settings) =>
          matchesNotificationFilters(log, settings)
        );

        if (matchingTelegramSettings.length > 0) {
          try {
            const telegramResult = await sendWafAlertToOrganization(
              organizationId,
              {
                domain: log.host,
                severity: log.severity,
                ruleId: log.ruleId || undefined,
                rule: log.rule || undefined,
                clientIp: log.clientIp,
                requestUrl: log.requestUrl,
                timestamp: log.timestamp,
              }
            );
            if (telegramResult.sent > 0) {
              sent += telegramResult.sent;
              console.log(`   📲 Telegram sent for log ${log.id}: ${telegramResult.sent} message(s)`);
            }
            if (telegramResult.failed > 0) {
              failed += telegramResult.failed;
            }
          } catch (error) {
            console.error(`   ❌ Telegram error for log ${log.id}:`, error);
          }
        }
      }
    }

    return { sent, failed, errors };
  } catch (error) {
    console.error("Error in sendNotificationsForLogs:", error);
    throw error;
  }
}

/**
 * Send notifications for new logs (timestamp-based fallback)
 * This should be called after processing modsec_landing records
 */
export async function sendNotificationsForNewLogs(
  sinceTimestamp?: Date
): Promise<{
  sent: number;
  failed: number;
  errors: Array<{ logId: string; error: string }>;
}> {
  const errors: Array<{ logId: string; error: string }> = [];
  let sent = 0;
  let failed = 0;

  // Check if email service is configured
  if (!emailService.isConfigured()) {
    console.warn("⚠️  Email service not configured. Skipping notifications.");
    return { sent: 0, failed: 0, errors: [] };
  }

  try {
    // Find all logs created since the timestamp (or last 5 minutes if not provided)
    const cutoffTime = sinceTimestamp || new Date(Date.now() - 5 * 60 * 1000);

    const newLogs = await prisma.log.findMany({
      where: {
        createdAt: {
          gte: cutoffTime,
        },
        organizationId: {
          not: null,
        },
      },
      include: {
        organization: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    if (newLogs.length === 0) {
      return { sent: 0, failed: 0, errors: [] };
    }

    console.log(`📧 Found ${newLogs.length} new logs to check for notifications`);

    // Group logs by organization
    const logsByOrg = new Map<string, typeof newLogs>();
    for (const log of newLogs) {
      if (!log.organizationId || !log.organization) {
        console.log(`   ⚠️  Log ${log.id} has no organization, skipping`);
        continue;
      }
      
      if (!logsByOrg.has(log.organizationId)) {
        logsByOrg.set(log.organizationId, []);
      }
      logsByOrg.get(log.organizationId)!.push(log);
    }

    console.log(`   📊 Processing ${logsByOrg.size} organization(s)`);

    // Process each organization
    for (const [organizationId, logs] of logsByOrg) {
      const organization = logs[0].organization!;
      console.log(`   🔍 Checking organization: ${organization.name} (${organizationId})`);

      // Get all notification settings for this organization (email + telegram)
      const allSettings = await prisma.notificationSettings.findMany({
        where: {
          organizationId,
          enabled: true,
        },
      });

      const emailSettings2 = allSettings.filter((s) => s.notificationType === "email");
      const telegramSettings2 = allSettings.filter(
        (s) => s.notificationType === "telegram" && s.telegramEnabled && s.telegramChatId
      );

      console.log(`   📋 Found ${emailSettings2.length} email + ${telegramSettings2.length} telegram setting(s)`);

      if (emailSettings2.length === 0 && telegramSettings2.length === 0) {
        console.log(`   ⚠️  No notification settings found for organization ${organization.name}`);
        continue;
      }

      // Process each log
      for (const log of logs) {
        console.log(`   🔎 Processing log ${log.id}: ${log.severity} ${log.action} on ${log.host}`);

        // --- EMAIL ---
        const matchingEmail2 = emailSettings2.filter((s) => matchesNotificationFilters(log, s));
        if (matchingEmail2.length > 0) {
          const emailAddresses = new Set<string>();
          for (const s of matchingEmail2) {
            if (s.emailList && Array.isArray(s.emailList)) {
              s.emailList.forEach((email) => {
                if (email && typeof email === 'string' && email.trim()) emailAddresses.add(email.trim());
              });
            }
          }
          if (emailAddresses.size > 0) {
            try {
              // Generate ban token URL if we have an IP
              const banUrl = log.clientIp
                ? await generateBanTokenUrl(organizationId, log.clientIp, [log.host || "*"])
                : null;
              
              const html = generateAttackNotificationEmail(log, organization, banUrl);
              const severity = log.severity.toUpperCase();
              const subject = `🚨 ${severity} Security Alert: ${log.rule || "Attack Detected"} on ${log.host}`;
              const emailArray = Array.from(emailAddresses);
              const result = await emailService.sendEmail({ to: emailArray, subject, html });
              if (result.success) {
                sent++;
              } else {
                failed++;
                errors.push({ logId: log.id, error: result.error || "Email send error" });
              }
            } catch (error) {
              failed++;
              errors.push({ logId: log.id, error: error instanceof Error ? error.message : "Unknown error" });
            }
          }
        }

        // --- TELEGRAM ---
        const matchingTelegram2 = telegramSettings2.filter((s) => matchesNotificationFilters(log, s));
        if (matchingTelegram2.length > 0) {
          try {
            const tgResult = await sendWafAlertToOrganization(organizationId, {
              domain: log.host,
              severity: log.severity,
              ruleId: log.ruleId || undefined,
              rule: log.rule || undefined,
              clientIp: log.clientIp,
              requestUrl: log.requestUrl,
              timestamp: log.timestamp,
            });
            sent += tgResult.sent;
            failed += tgResult.failed;
          } catch (error) {
            console.error(`   ❌ Telegram error for log ${log.id}:`, error);
          }
        }
      }
    }

    return { sent, failed, errors };
  } catch (error) {
    console.error("Error in sendNotificationsForNewLogs:", error);
    throw error;
  }
}
