/**
 * Dev helper: Set the Telegram bot webhook URL using PUBLIC_BASE_URL.
 *
 * Usage:
 *   npx tsx src/scripts/setTelegramWebhook.ts
 *
 * Re-run this script whenever your ngrok URL changes.
 */

import dotenv from "dotenv";
dotenv.config();

async function main() {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const publicBase = process.env.PUBLIC_BASE_URL;
  const secret = process.env.TELEGRAM_WEBHOOK_SECRET;

  if (!token || !publicBase || !secret) {
    console.error(
      "❌ Missing env vars. Ensure TELEGRAM_BOT_TOKEN, PUBLIC_BASE_URL, and TELEGRAM_WEBHOOK_SECRET are set in .env"
    );
    process.exit(1);
  }

  const webhookUrl = `${publicBase.replace(/\/$/, "")}/telegram/webhook/${secret}`;

  console.log(`\n🔗 Setting Telegram webhook...`);
  console.log(`   URL: ${publicBase}/telegram/webhook/***`);

  // Set webhook
  const setRes = await fetch(
    `https://api.telegram.org/bot${token}/setWebhook`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: webhookUrl }),
    }
  );
  const setJson = (await setRes.json()) as {
    ok: boolean;
    description?: string;
  };

  if (setJson.ok) {
    console.log(`   ✅ Webhook set successfully!`);
  } else {
    console.error(`   ❌ Failed: ${setJson.description}`);
    process.exit(1);
  }

  // Verify with getWebhookInfo
  console.log(`\n📋 Verifying webhook info...`);
  const infoRes = await fetch(
    `https://api.telegram.org/bot${token}/getWebhookInfo`
  );
  const infoJson = (await infoRes.json()) as {
    ok: boolean;
    result?: {
      url: string;
      has_custom_certificate: boolean;
      pending_update_count: number;
      last_error_date?: number;
      last_error_message?: string;
    };
  };

  if (infoJson.ok && infoJson.result) {
    const info = infoJson.result;
    // Mask the secret in the URL for display
    const maskedUrl = info.url.replace(secret, "***");
    console.log(`   URL: ${maskedUrl}`);
    console.log(`   Pending updates: ${info.pending_update_count}`);
    if (info.last_error_message) {
      console.log(
        `   ⚠️  Last error: ${info.last_error_message} (${new Date((info.last_error_date || 0) * 1000).toISOString()})`
      );
    }
  }

  console.log(`\n✅ Done! Your bot is ready to receive updates.\n`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
