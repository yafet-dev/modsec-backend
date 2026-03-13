/**
 * Telegram Routes
 *
 * - POST /telegram/webhook/:secret        — Telegram webhook receiver
 * - POST /api/telegram/start-link         — Generate connect code (auth required)
 * - POST /api/telegram/test               — Send test message (auth required)
 * - POST /api/telegram/set-webhook        — (Dev) Set Telegram webhook
 * - GET  /api/telegram/webhook-info       — (Dev) Get webhook info
 * - POST /api/telegram/disconnect         — Disconnect Telegram (auth required)
 */

import { Router, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { supabase } from "../lib/supabase";
import crypto from "crypto";
import {
  sendTelegramMessage,
  sendMessageWithInlineKeyboard,
  answerCallbackQuery,
  setTelegramWebhook,
  getTelegramWebhookInfo,
} from "../services/telegramService";

// ---------------------------------------------------------------------------
// Two separate routers:
//   webhookRouter  → mounted at /telegram  (no CORS / no auth)
//   apiRouter      → mounted at /api/telegram (auth required)
// ---------------------------------------------------------------------------

export const telegramWebhookRouter = Router();
export const telegramApiRouter = Router();

// ---------------------------------------------------------------------------
// Auth helper (same pattern as notification-settings.routes.ts)
// ---------------------------------------------------------------------------
async function getAuthenticatedUser(req: Request): Promise<{
  userId: string;
  email: string;
} | null> {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace("Bearer ", "");
  if (!token) return null;

  const {
    data: { user: supabaseUser },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !supabaseUser) return null;

  const user = await prisma.user.findUnique({
    where: { email: supabaseUser.email! },
  });

  if (!user) return null;
  return { userId: user.id, email: user.email };
}

// ---------------------------------------------------------------------------
// Generate connect code
// ---------------------------------------------------------------------------
function generateConnectCode(): string {
  const prefix = "EAG";
  const num = crypto.randomInt(100000, 999999);
  return `${prefix}-${num}`;
}

// ===========================================================================
// WEBHOOK ROUTE — POST /telegram/webhook/:secret
// ===========================================================================
telegramWebhookRouter.post(
  "/webhook/:secret",
  async (req: Request, res: Response) => {
    // Always respond 200 quickly to avoid Telegram retries
    const secret = req.params.secret;
    if (secret !== process.env.TELEGRAM_WEBHOOK_SECRET) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // Acknowledge immediately, handle in background
    res.status(200).json({ ok: true });

    try {
      const update = req.body;

      // Handle /start command
      if (update.message?.text?.startsWith("/start")) {
        await handleStartCommand(update.message);
        return;
      }

      // Handle callback_query (Connect button click)
      if (update.callback_query) {
        await handleCallbackQuery(update.callback_query);
        return;
      }
    } catch (err) {
      console.error("[Telegram Webhook] Error processing update:", err);
    }
  }
);

// ---------------------------------------------------------------------------
// /start handler
// ---------------------------------------------------------------------------
async function handleStartCommand(message: {
  chat: { id: number };
  text: string;
  from?: { id: number; first_name?: string };
}): Promise<void> {
  const chatId = message.chat.id;
  const name = message.from?.first_name || "there";

  // Check if user sent /start with a connect code (deep-link):  /start EAG-123456
  const parts = message.text.trim().split(/\s+/);
  const deepLinkCode = parts.length > 1 ? parts[1] : null;

  if (deepLinkCode) {
    // Attempt to connect directly via deep-link code
    const connected = await attemptConnect(
      chatId,
      message.from?.id,
      deepLinkCode
    );
    if (connected) return; // Already handled
    // If code was invalid / expired, fall through to the welcome message
  }

  // Send welcome with the latest pending connect code (if any)
  // For now, just show a generic welcome; user must generate code from dashboard first
  await sendTelegramMessage(
    chatId,
    `👋 Hi ${escapeHtml(name)}!\n\n` +
      `Welcome to the <b>Zergaw WAF Alert Bot</b>.\n\n` +
      `To connect your account:\n` +
      `1. Open your WAF dashboard\n` +
      `2. Go to Notification Settings → Telegram\n` +
      `3. Click "Connect Telegram"\n` +
      `4. Copy the link and open it here\n\n` +
      `Once connected, you'll receive real-time WAF attack alerts here. 🛡️`
  );
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// Callback query handler (Connect ✅ button)
// ---------------------------------------------------------------------------
async function handleCallbackQuery(callbackQuery: {
  id: string;
  message?: { chat: { id: number } };
  from: { id: number; first_name?: string };
  data?: string;
}): Promise<void> {
  const cbId = callbackQuery.id;
  const chatId = callbackQuery.message?.chat.id;
  const telegramUserId = callbackQuery.from.id;
  const data = callbackQuery.data || "";

  if (!chatId) {
    await answerCallbackQuery(cbId, "❌ Error: no chat context");
    return;
  }

  // Parse callback_data = "connect:<CONNECT_CODE>"
  if (!data.startsWith("connect:")) {
    await answerCallbackQuery(cbId, "❌ Unknown action");
    return;
  }

  const connectCode = data.replace("connect:", "").trim();
  const success = await attemptConnect(chatId, telegramUserId, connectCode);

  if (success) {
    await answerCallbackQuery(cbId, "✅ Connected!");
  } else {
    await answerCallbackQuery(cbId, "❌ Code expired or invalid");
  }
}

// ---------------------------------------------------------------------------
// Shared connect logic
// ---------------------------------------------------------------------------
async function attemptConnect(
  chatId: number,
  telegramUserId: number | undefined,
  connectCode: string
): Promise<boolean> {
  try {
    // Look up the connect request
    const request = await prisma.telegramConnectRequest.findUnique({
      where: { connectCode },
    });

    if (!request) {
      await sendTelegramMessage(
        chatId,
        "❌ Invalid connect code. Please generate a new one from the dashboard."
      );
      return false;
    }

    if (request.usedAt) {
      await sendTelegramMessage(
        chatId,
        "⚠️ This code has already been used. Please generate a new one."
      );
      return false;
    }

    if (new Date() > request.expiresAt) {
      await sendTelegramMessage(
        chatId,
        "⏰ This code has expired. Please generate a new one from the dashboard."
      );
      return false;
    }

    // Find or create notification settings for this org with type = telegram
    let notifSettings = await prisma.notificationSettings.findFirst({
      where: {
        organizationId: request.organizationId,
        notificationType: "telegram",
      },
    });

    if (notifSettings) {
      // Update existing
      notifSettings = await prisma.notificationSettings.update({
        where: { id: notifSettings.id },
        data: {
          telegramChatId: String(chatId),
          telegramUserId: telegramUserId ? String(telegramUserId) : null,
          telegramEnabled: true,
          telegramConnectedAt: new Date(),
          enabled: true,
        },
      });
    } else {
      // Create new
      notifSettings = await prisma.notificationSettings.create({
        data: {
          organizationId: request.organizationId,
          notificationType: "telegram",
          telegramChatId: String(chatId),
          telegramUserId: telegramUserId ? String(telegramUserId) : null,
          telegramEnabled: true,
          telegramConnectedAt: new Date(),
          enabled: true,
        },
      });
    }

    // Mark code as used
    await prisma.telegramConnectRequest.update({
      where: { id: request.id },
      data: { usedAt: new Date() },
    });

    // Send confirmation
    await sendTelegramMessage(
      chatId,
      "✅ <b>Connected successfully!</b>\n\n" +
        "You will now receive WAF attack alerts here.\n" +
        "Manage your settings in the dashboard under Notification Settings."
    );

    console.log(
      `[Telegram] Connected chat ${chatId} to org ${request.organizationId} (user ${request.userId})`
    );
    return true;
  } catch (err) {
    console.error("[Telegram] Error connecting:", err);
    await sendTelegramMessage(
      chatId,
      "❌ Something went wrong. Please try again."
    );
    return false;
  }
}

// ===========================================================================
// API ROUTES (auth required)
// ===========================================================================

// ---------------------------------------------------------------------------
// POST /api/telegram/start-link
// Body: { organizationId: string }
// Returns: { connectCode, botUsername, deepLink, expiresAt }
// ---------------------------------------------------------------------------
telegramApiRouter.post(
  "/start-link",
  async (req: Request, res: Response) => {
    try {
      const auth = await getAuthenticatedUser(req);
      if (!auth) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const { organizationId } = req.body;
      if (!organizationId) {
        return res
          .status(400)
          .json({ message: "organizationId is required" });
      }

      // Verify user is a member of the organization
      const membership = await prisma.organizationMember.findFirst({
        where: {
          userId: auth.userId,
          organizationId,
          status: "verified",
        },
      });

      const user = await prisma.user.findUnique({
        where: { id: auth.userId },
        select: { role: true },
      });

      if (!membership && user?.role !== "super_admin") {
        return res
          .status(403)
          .json({ message: "Not a member of this organization" });
      }

      // Expire any old unused codes for this user+org
      await prisma.telegramConnectRequest.updateMany({
        where: {
          userId: auth.userId,
          organizationId,
          usedAt: null,
        },
        data: { expiresAt: new Date() }, // expire now
      });

      // Generate new code
      const connectCode = generateConnectCode();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      await prisma.telegramConnectRequest.create({
        data: {
          userId: auth.userId,
          organizationId,
          connectCode,
          expiresAt,
        },
      });

      // Build deep-link URL: https://t.me/<bot_username>?start=<connectCode>
      // We need the bot username. Fetch it from Telegram getMe.
      let botUsername = process.env.TELEGRAM_BOT_USERNAME || "";
      if (!botUsername) {
        try {
          const token = process.env.TELEGRAM_BOT_TOKEN;
          if (token) {
            const meRes = await fetch(
              `https://api.telegram.org/bot${token}/getMe`
            );
            const meJson = (await meRes.json()) as {
              ok: boolean;
              result?: { username?: string };
            };
            if (meJson.ok && meJson.result?.username) {
              botUsername = meJson.result.username;
            }
          }
        } catch {
          // ignore, user can still manually use the code
        }
      }

      const deepLink = botUsername
        ? `https://t.me/${botUsername}?start=${connectCode}`
        : null;

      return res.json({
        connectCode,
        deepLink,
        botUsername: botUsername || null,
        expiresAt: expiresAt.toISOString(),
        instructions:
          "Open the deep-link in Telegram, or send /start to the bot and use the connect code.",
      });
    } catch (err) {
      console.error("[Telegram] Error in start-link:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/telegram/disconnect
// Body: { organizationId: string }
// ---------------------------------------------------------------------------
telegramApiRouter.post(
  "/disconnect",
  async (req: Request, res: Response) => {
    try {
      const auth = await getAuthenticatedUser(req);
      if (!auth) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const { organizationId } = req.body;
      if (!organizationId) {
        return res
          .status(400)
          .json({ message: "organizationId is required" });
      }

      // Find and update the telegram notification setting
      const setting = await prisma.notificationSettings.findFirst({
        where: {
          organizationId,
          notificationType: "telegram",
        },
      });

      if (!setting) {
        return res
          .status(404)
          .json({ message: "No Telegram connection found" });
      }

      // Send a goodbye message before disconnecting
      if (setting.telegramChatId) {
        try {
          await sendTelegramMessage(
            setting.telegramChatId,
            "🔌 Telegram notifications have been disconnected from the WAF dashboard.\n" +
              "You will no longer receive alerts here."
          );
        } catch {
          // Ignore send errors during disconnect
        }
      }

      await prisma.notificationSettings.update({
        where: { id: setting.id },
        data: {
          telegramEnabled: false,
          telegramChatId: null,
          telegramUserId: null,
          telegramConnectedAt: null,
        },
      });

      return res.json({ ok: true, message: "Telegram disconnected" });
    } catch (err) {
      console.error("[Telegram] Error in disconnect:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/telegram/test
// Body: { organizationId?: string }  (optional; if not provided, finds first org)
// ---------------------------------------------------------------------------
telegramApiRouter.post("/test", async (req: Request, res: Response) => {
  try {
    const auth = await getAuthenticatedUser(req);
    if (!auth) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Find Telegram settings for the user's organization
    const memberships = await prisma.organizationMember.findMany({
      where: { userId: auth.userId, status: "verified" },
      select: { organizationId: true },
    });

    const user = await prisma.user.findUnique({
      where: { id: auth.userId },
      select: { role: true },
    });

    let orgIds = memberships.map((m) => m.organizationId);

    // Super admin can access any org
    if (user?.role === "super_admin" && req.body.organizationId) {
      orgIds = [req.body.organizationId];
    }

    if (orgIds.length === 0) {
      return res
        .status(404)
        .json({ ok: false, error: "No organizations found" });
    }

    const setting = await prisma.notificationSettings.findFirst({
      where: {
        organizationId: { in: orgIds },
        notificationType: "telegram",
        telegramEnabled: true,
        telegramChatId: { not: null },
      },
    });

    if (!setting || !setting.telegramChatId) {
      return res
        .status(404)
        .json({ ok: false, error: "Telegram not connected" });
    }

    await sendTelegramMessage(
      setting.telegramChatId,
      "✅ <b>Telegram test successful!</b>\n\nYour WAF notifications are working."
    );

    return res.json({ ok: true });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    console.error("[Telegram] Test error:", err);
    return res.status(500).json({ ok: false, error: msg });
  }
});

// ---------------------------------------------------------------------------
// POST /api/telegram/set-webhook  (Dev helper)
// ---------------------------------------------------------------------------
telegramApiRouter.post(
  "/set-webhook",
  async (req: Request, res: Response) => {
    try {
      const auth = await getAuthenticatedUser(req);
      if (!auth) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      // Only super_admin
      const user = await prisma.user.findUnique({
        where: { id: auth.userId },
        select: { role: true },
      });
      if (user?.role !== "super_admin") {
        return res.status(403).json({ message: "Super admin only" });
      }

      const result = await setTelegramWebhook();
      return res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      return res.status(500).json({ ok: false, error: msg });
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/telegram/webhook-info  (Dev helper)
// ---------------------------------------------------------------------------
telegramApiRouter.get(
  "/webhook-info",
  async (req: Request, res: Response) => {
    try {
      const auth = await getAuthenticatedUser(req);
      if (!auth) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const info = await getTelegramWebhookInfo();
      return res.json(info);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      return res.status(500).json({ ok: false, error: msg });
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/telegram/status
// Query: ?organizationId=xxx
// Returns Telegram connection status for the org
// ---------------------------------------------------------------------------
telegramApiRouter.get("/status", async (req: Request, res: Response) => {
  try {
    const auth = await getAuthenticatedUser(req);
    if (!auth) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const organizationId = req.query.organizationId as string;
    if (!organizationId) {
      return res
        .status(400)
        .json({ message: "organizationId query param is required" });
    }

    const setting = await prisma.notificationSettings.findFirst({
      where: {
        organizationId,
        notificationType: "telegram",
      },
    });

    return res.json({
      connected: setting?.telegramEnabled || false,
      telegramChatId: setting?.telegramChatId || null,
      connectedAt: setting?.telegramConnectedAt || null,
    });
  } catch (err) {
    console.error("[Telegram] Status error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});
