/**
 * Telegram Bot Service
 *
 * Provides helpers for:
 * - sendMessage / answerCallbackQuery / sendMessageWithInlineKeyboard
 * - setWebhook / getWebhookInfo
 * - sendWafAlert (formatted WAF notification)
 *
 * Uses native fetch (Node 18+). Never logs TELEGRAM_BOT_TOKEN.
 */

import { prisma } from "../lib/prisma";
import crypto from "crypto";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
function getBotToken(): string {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) {
    throw new Error("TELEGRAM_BOT_TOKEN is not set in environment");
  }
  return token;
}

function telegramApiUrl(method: string): string {
  return `https://api.telegram.org/bot${getBotToken()}/${method}`;
}

// ---------------------------------------------------------------------------
// Low-level Telegram API helpers
// ---------------------------------------------------------------------------

export async function sendTelegramMessage(
  chatId: string | number,
  text: string,
  extra?: Record<string, unknown>
): Promise<void> {
  const body: Record<string, unknown> = {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    ...extra,
  };

  const res = await fetch(telegramApiUrl("sendMessage"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const json = (await res.json()) as { ok: boolean; description?: string };
  if (!json.ok) {
    throw new Error(
      `Telegram sendMessage failed: ${json.description || res.status}`
    );
  }
}

export async function answerCallbackQuery(
  callbackQueryId: string,
  text?: string
): Promise<void> {
  const body: Record<string, unknown> = {
    callback_query_id: callbackQueryId,
    text: text || "",
  };

  const res = await fetch(telegramApiUrl("answerCallbackQuery"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const json = (await res.json()) as { ok: boolean; description?: string };
  if (!json.ok) {
    console.error(
      `Telegram answerCallbackQuery failed: ${json.description || res.status}`
    );
  }
}

export async function sendMessageWithInlineKeyboard(
  chatId: string | number,
  text: string,
  buttons: Array<{ text: string; callback_data?: string; url?: string }>
): Promise<void> {
  await sendTelegramMessage(chatId, text, {
    reply_markup: {
      inline_keyboard: [buttons],
    },
  });
}

// ---------------------------------------------------------------------------
// Webhook management
// ---------------------------------------------------------------------------

export async function setTelegramWebhook(): Promise<{
  ok: boolean;
  description?: string;
}> {
  const publicBase = process.env.PUBLIC_BASE_URL;
  const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (!publicBase || !secret) {
    throw new Error(
      "PUBLIC_BASE_URL and TELEGRAM_WEBHOOK_SECRET must be set in .env"
    );
  }

  const webhookUrl = `${publicBase.replace(/\/$/, "")}/telegram/webhook/${secret}`;

  console.log(`[Telegram] Setting webhook → ${publicBase}/telegram/webhook/***`);

  const res = await fetch(telegramApiUrl("setWebhook"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: webhookUrl }),
  });

  const json = (await res.json()) as {
    ok: boolean;
    description?: string;
    result?: boolean;
  };
  if (!json.ok) {
    throw new Error(
      `Telegram setWebhook failed: ${json.description || res.status}`
    );
  }

  console.log("[Telegram] Webhook set successfully ✅");
  return json;
}

export async function getTelegramWebhookInfo(): Promise<unknown> {
  const res = await fetch(telegramApiUrl("getWebhookInfo"), {
    method: "GET",
  });
  return res.json();
}

// ---------------------------------------------------------------------------
// WAF Alert formatter + sender
// ---------------------------------------------------------------------------

interface WafAlertPayload {
  domain?: string;
  severity?: string;
  ruleId?: string;
  rule?: string;
  anomalyScore?: number;
  clientIp?: string;
  requestUrl?: string;
  timestamp?: string | Date;
}

function formatWafAlert(payload: WafAlertPayload): string {
  const lines: string[] = [];
  lines.push("🚨 <b>WAF Alert</b>");
  lines.push("");
  if (payload.domain) lines.push(`<b>Domain:</b> ${escapeHtml(payload.domain)}`);
  if (payload.severity)
    lines.push(`<b>Severity:</b> ${escapeHtml(payload.severity)}`);
  if (payload.ruleId) lines.push(`<b>Rule:</b> ${escapeHtml(payload.ruleId)}`);
  if (payload.rule) lines.push(`<b>Description:</b> ${escapeHtml(payload.rule)}`);
  if (payload.anomalyScore !== undefined)
    lines.push(`<b>Score:</b> ${payload.anomalyScore}`);
  if (payload.clientIp)
    lines.push(`<b>IP:</b> <code>${escapeHtml(payload.clientIp)}</code>`);
  if (payload.requestUrl)
    lines.push(`<b>URI:</b> <code>${escapeHtml(payload.requestUrl)}</code>`);
  if (payload.timestamp) {
    const ts =
      payload.timestamp instanceof Date
        ? payload.timestamp.toISOString()
        : payload.timestamp;
    lines.push(`<b>Time:</b> ${ts}`);
  }
  return lines.join("\n");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
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
    const banToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

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
      console.error("[Telegram] PUBLIC_BASE_URL is not set, cannot generate ban URL");
      return null;
    }
    return `${publicBaseUrl.replace(/\/$/, "")}/api/ip-bans/ban?token=${banToken}`;
  } catch (error) {
    console.error("[Telegram] Error generating ban token:", error);
    return null;
  }
}

/**
 * Send a WAF alert to all Telegram-enabled notification settings
 * for a given organization.
 */
export async function sendWafAlertToOrganization(
  organizationId: string,
  payload: WafAlertPayload
): Promise<{ sent: number; failed: number }> {
  let sent = 0;
  let failed = 0;

  try {
    const settings = await prisma.notificationSettings.findMany({
      where: {
        organizationId,
        notificationType: "telegram",
        enabled: true,
        telegramEnabled: true,
        telegramChatId: { not: null },
      },
    });

    if (settings.length === 0) return { sent: 0, failed: 0 };

    // Generate ban URL if we have an IP
    const banUrl = payload.clientIp && payload.domain
      ? await generateBanTokenUrl(organizationId, payload.clientIp, [payload.domain])
      : null;

    const text = formatWafAlert(payload);

    for (const s of settings) {
      try {
        if (banUrl) {
          // Send with inline keyboard button
          await sendMessageWithInlineKeyboard(
            s.telegramChatId!,
            text,
            [{ text: "🚫 Ban IP Address", url: banUrl }]
          );
        } else {
          // Send plain message
          await sendTelegramMessage(s.telegramChatId!, text);
        }
        sent++;
        console.log(
          `   📲 Telegram alert sent for org ${organizationId} to chat ${s.telegramChatId}`
        );
      } catch (err) {
        failed++;
        console.error(
          `   ❌ Telegram send failed for chat ${s.telegramChatId}:`,
          err
        );
      }
    }
  } catch (err) {
    console.error("[Telegram] Error loading notification settings:", err);
  }

  return { sent, failed };
}

/**
 * Send a WAF alert for a specific user (used by the test endpoint).
 */
export async function sendWafAlertToUser(
  userId: string,
  payload: WafAlertPayload
): Promise<{ ok: boolean; error?: string }> {
  try {
    // Find all orgs where user is a member, then find Telegram settings
    const memberships = await prisma.organizationMember.findMany({
      where: { userId, status: "verified" },
      select: { organizationId: true },
    });

    const orgIds = memberships.map((m) => m.organizationId);
    if (orgIds.length === 0) {
      return { ok: false, error: "User has no organizations" };
    }

    const settings = await prisma.notificationSettings.findMany({
      where: {
        organizationId: { in: orgIds },
        notificationType: "telegram",
        enabled: true,
        telegramEnabled: true,
        telegramChatId: { not: null },
      },
    });

    if (settings.length === 0) {
      return { ok: false, error: "Telegram not connected" };
    }

    const text = formatWafAlert(payload);
    for (const s of settings) {
      await sendTelegramMessage(s.telegramChatId!, text);
    }

    return { ok: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return { ok: false, error: msg };
  }
}
